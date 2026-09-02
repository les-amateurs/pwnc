"""Synchronous DAP transport with isolated reader, router, and writer lanes.

The public API is deliberately synchronous.  Internally, byte framing, protocol
state, outbound I/O, ordered notifications, and re-entrant callbacks live on
different threads so arbitrary callback code can issue another synchronous DAP
request without capturing the only thread capable of completing it.

``send`` returns a :class:`concurrent.futures.Future` subclass for compatibility:
calling the future's own ``result()`` yields the raw DAP response, while
``DapTransport.result()`` validates that response and returns its ``body``.
Unlike a normal Future, completion callbacks are always scheduled off the
reader/router/writer threads, including callbacks registered after completion.
"""

from __future__ import annotations

import json
import queue
import secrets
import subprocess
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as _FutureTimeout
from dataclasses import dataclass, field
from itertools import count
from typing import Any

from ._console_bridge import _ansi_safe_suffix
from ._process import wait_process

DEFAULT_TIMEOUT = 30.0
CONTROL_TIMEOUT = 5.0
DEFAULT_QUEUE_MESSAGES = 1024
DEFAULT_MAX_FRAME_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_PENDING_REQUESTS = 4096
DEFAULT_MAX_QUEUED_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_CALLBACK_WORKERS = 256
DEFAULT_STDERR_TAIL_BYTES = 1024 * 1024
DEFAULT_ERROR_HISTORY = 256
DEFAULT_STARTUP_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_STARTUP_OUTPUT_BYTES = 8 * 1024 * 1024

_STARTUP_OUTPUT_TRUNCATED = "\x1b[0m[pwnc: earlier startup output was truncated]\n"


class DapError(RuntimeError):
    """A DAP request failed or the transport became unusable."""

    def __init__(self, message, command=None, body=None):
        super().__init__(message)
        self.command = command
        self.body = body


class DapTimeout(DapError):
    """A DAP request did not get a response within the timeout."""


class DapOverload(DapError):
    """A bounded transport or callback queue could not admit more work."""


def _validate_init(init) -> bool:
    if type(init) is not bool:
        raise TypeError("init must be True or False")
    return init


def spawn_argv(gdb_path="gdb", gdb_args=None, *, init=True):
    """Build GDB's argv, optionally suppressing its normal init files."""
    init = _validate_init(init)
    argv = [gdb_path, "-q"]
    if not init:
        argv.append("-nx")
    argv.append("--interpreter=dap")
    if gdb_args:
        argv.extend(gdb_args)
    return argv


@dataclass(frozen=True, slots=True)
class _Inbound:
    kind: str
    value: Any = None


@dataclass(frozen=True, slots=True)
class _Outbound:
    data: bytes
    seq: int
    message_type: str
    command: str | None


@dataclass(frozen=True, slots=True)
class _EventCall:
    handler: Callable[[dict[str, Any]], Any] | None = None
    body: dict[str, Any] = field(default_factory=dict)
    event: str = ""
    barrier: threading.Event | None = None


@dataclass(frozen=True, slots=True)
class _TerminalCall:
    reason: str


class _WakeableQueue:
    """A bounded FIFO with an out-of-band, capacity-independent wake item.

    ``queue.Queue`` cannot wake a blocking ``get()`` when an unrelated stop
    event is set.  Timed gets used to bridge that gap, but make every idle DAP
    session wake periodically.  This small queue retains normal bounded-put
    behavior while allowing shutdown control items to be inserted even when
    the data capacity is saturated.

    Control insertion is only used during terminal shutdown.  It may
    temporarily take the physical queue one item beyond ``maxsize``; ordinary
    producers remain bounded by ``maxsize`` throughout.
    """

    def __init__(self, maxsize=0):
        self.maxsize = maxsize
        self._items = deque()
        self._condition = threading.Condition()

    def qsize(self):
        with self._condition:
            return len(self._items)

    def empty(self):
        with self._condition:
            return not self._items

    def full(self):
        with self._condition:
            return self.maxsize > 0 and len(self._items) >= self.maxsize

    def put(self, item, block=True, timeout=None):
        if timeout is not None and timeout < 0:
            raise ValueError("'timeout' must be a non-negative number")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self.maxsize > 0 and len(self._items) >= self.maxsize:
                if not block:
                    raise queue.Full
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Full
                self._condition.wait(remaining)
            self._items.append(item)
            self._condition.notify()

    def put_nowait(self, item):
        self.put(item, block=False)

    def put_interruptible(self, item, cancelled, timeout=None):
        """Put while bounded, waking promptly when ``cancelled`` becomes true.

        Callers that can change the cancellation predicate must also perform a
        control insertion, which broadcasts this queue's condition.
        """
        if timeout is not None and timeout < 0:
            raise ValueError("'timeout' must be a non-negative number")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self.maxsize > 0 and len(self._items) >= self.maxsize:
                if cancelled():
                    return False
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            if cancelled():
                return False
            self._items.append(item)
            self._condition.notify()
            return True

    def put_control(self, item, *, front=False):
        """Insert a terminal control item without waiting for data capacity."""
        with self._condition:
            if front:
                self._items.appendleft(item)
            else:
                self._items.append(item)
            self._condition.notify_all()

    def get(self, block=True, timeout=None):
        if timeout is not None and timeout < 0:
            raise ValueError("'timeout' must be a non-negative number")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while not self._items:
                if not block:
                    raise queue.Empty
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                self._condition.wait(remaining)
            item = self._items.popleft()
            # A bounded producer may be waiting for this data slot.
            self._condition.notify_all()
            return item

    def get_nowait(self):
        return self.get(block=False)


_ROUTER_STOP = object()
_WRITER_STOP = object()
_EVENT_STOP = object()
_COMPLETION_STOP = object()


class _ControlCell:
    """Small condition result used for router-owned control decisions."""

    def __init__(self):
        self._condition = threading.Condition()
        self._done = False
        self._value = None

    def finish(self, value):
        with self._condition:
            if self._done:
                return
            self._done = True
            self._value = value
            self._condition.notify_all()

    def result(self, timeout):
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._done:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DapTimeout("DAP router did not acknowledge control request")
                self._condition.wait(remaining)
            return self._value


class DapFuture(Future):
    """Future-compatible raw DAP response handle with safe callback affinity."""

    def __init__(self, transport, seq, command, *, capture_startup_result=False):
        super().__init__()
        self._transport = transport
        self._dap_seq = seq
        self._dap_command = command
        self._dap_capture_startup_result = bool(capture_startup_result)
        self._dap_inline_callbacks = []
        self._dap_callback_queue = deque()
        self._dap_callback_delivery_started = False
        self._dap_callback_worker_active = False

    def _invoke_callbacks(self):
        # Future.set_result/set_exception/cancel normally execute callbacks in
        # the completing thread.  That thread is the protocol router here, so
        # doing so would let a synchronous callback capture response routing.
        with self._condition:
            inline_callbacks = list(self._dap_inline_callbacks)
            self._dap_inline_callbacks.clear()
            callbacks = list(self._done_callbacks)
            self._done_callbacks.clear()
            self._dap_callback_delivery_started = True
            self._dap_callback_queue.extend(callbacks)
            schedule = bool(callbacks) and not self._dap_callback_worker_active
            if schedule:
                self._dap_callback_worker_active = True
        # These are transport-internal, nonblocking notification hooks.  They
        # run before the router can accept another frame, which lets protocol
        # consumers publish response state before a following wire event.
        for callback in inline_callbacks:
            try:
                callback(self)
            except BaseException as error:  # noqa: BLE001 - invariant boundary
                self._transport._record_worker_error(error)
        if schedule:
            self._transport._schedule_future_callback_lane(self)

    def _add_inline_done_callback(self, fn):
        """Register a trusted nonblocking completion hook on router affinity."""
        if not callable(fn):
            raise TypeError("inline done callback must be callable")
        with self._condition:
            if not self.done():
                self._dap_inline_callbacks.append(fn)
                return
        # Completion won registration.  The router is no longer relying on this
        # caller to return, so immediate delivery is safe and closes the race.
        fn(self)

    def add_done_callback(self, fn):
        if not callable(fn):
            raise TypeError("done callback must be callable")
        if self._transport._is_current_future_callback(self):
            # Preserve Future's recursive late-registration behavior without
            # involving a protocol or message pump.  This is already a user
            # callback stack, so inline invocation cannot capture the router.
            self._transport._invoke_future_callback(self, fn)
            return
        with self._condition:
            if not self._dap_callback_delivery_started:
                self._done_callbacks.append(fn)
                return
            self._dap_callback_queue.append(fn)
            schedule = not self._dap_callback_worker_active
            if schedule:
                self._dap_callback_worker_active = True
        if schedule:
            self._transport._schedule_future_callback_lane(self)

    def cancel(self):
        if self.cancelled():
            return True
        if self.done():
            return False
        cancelled = self._transport._cancel_future(self)
        # Match concurrent.futures.Future when another caller won the cancel
        # race while our router control message was in flight.
        return cancelled or self.cancelled()

    def _cancel_from_router(self):
        cancelled = Future.cancel(self)
        if cancelled:
            # DapTransport is this Future's executor.  Executors must make the
            # CANCELLED -> CANCELLED_AND_NOTIFIED transition so wait() and
            # as_completed() wake as well as direct result() callers.
            Future.set_running_or_notify_cancel(self)
        return cancelled

    def set_running_or_notify_cancel(self):
        raise RuntimeError("DapFuture execution state is owned by DapTransport")

    def set_result(self, result):
        raise RuntimeError("DapFuture completion is owned by DapTransport")

    def set_exception(self, exception):
        raise RuntimeError("DapFuture completion is owned by DapTransport")

    def _finish_result(self, result):
        Future.set_result(self, result)

    def _finish_exception(self, exception):
        Future.set_exception(self, exception)

    def _run_callback_lane(self):
        while True:
            with self._condition:
                if not self._dap_callback_queue:
                    self._dap_callback_worker_active = False
                    return
                callback = self._dap_callback_queue.popleft()
            self._transport._invoke_future_callback(self, callback)


class DapTransport:
    """Own a GDB DAP subprocess and expose a synchronous request API.

    ``init=True`` uses GDB's normal initialization files; ``init=False`` adds
    ``-nx`` before starting the DAP interpreter.

    The reader only frames bytes and queues them.  The router is the sole owner
    of JSON decoding, response correlation, timeout/cancel selection, and
    terminal failure.  The writer is the sole owner of GDB stdin.  Passive
    event handlers run in one ordered callback lane; handlers explicitly
    registered as ``reentrant=True`` and Future callbacks receive fresh bounded
    OS-thread stacks.
    """

    def __init__(
        self,
        gdb_path="gdb",
        gdb_args=None,
        env=None,
        *,
        init=True,
        queue_messages=DEFAULT_QUEUE_MESSAGES,
        max_frame_bytes=DEFAULT_MAX_FRAME_BYTES,
        max_pending_requests=DEFAULT_MAX_PENDING_REQUESTS,
        max_queued_bytes=DEFAULT_MAX_QUEUED_BYTES,
        max_callback_workers=DEFAULT_MAX_CALLBACK_WORKERS,
        stderr_tail_bytes=DEFAULT_STDERR_TAIL_BYTES,
        error_history=DEFAULT_ERROR_HISTORY,
        startup_output_bytes=DEFAULT_STARTUP_OUTPUT_BYTES,
    ):
        if queue_messages <= 0:
            raise ValueError("queue_messages must be positive")
        if max_frame_bytes <= 0:
            raise ValueError("max_frame_bytes must be positive")
        if max_pending_requests <= 0:
            raise ValueError("max_pending_requests must be positive")
        if max_queued_bytes <= 0:
            raise ValueError("max_queued_bytes must be positive")
        if max_callback_workers <= 0:
            raise ValueError("max_callback_workers must be positive")
        if stderr_tail_bytes < 0:
            raise ValueError("stderr_tail_bytes cannot be negative")
        if error_history <= 0:
            raise ValueError("error_history must be positive")
        if type(startup_output_bytes) is not int or startup_output_bytes < 0:
            raise ValueError("startup_output_bytes must be a non-negative integer")
        if startup_output_bytes > MAX_STARTUP_OUTPUT_BYTES:
            raise ValueError(
                "startup_output_bytes cannot exceed "
                f"{MAX_STARTUP_OUTPUT_BYTES} bytes"
            )

        init = _validate_init(init)
        self.proc = subprocess.Popen(
            spawn_argv(gdb_path, gdb_args, init=init),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0,
        )
        self.init = init
        self._max_frame_bytes = max_frame_bytes
        self._max_pending_requests = max_pending_requests
        self._max_queued_bytes = max_queued_bytes
        self._max_callback_workers = max_callback_workers
        self._stderr_tail_bytes = stderr_tail_bytes
        self._startup_output_limit = startup_output_bytes

        self._inbound = _WakeableQueue(maxsize=queue_messages)
        self._outbound = _WakeableQueue(maxsize=queue_messages)
        self._events = _WakeableQueue(maxsize=queue_messages)
        self._completion_ready = queue.SimpleQueue()
        self._next_seq = 1
        self._queued_outbound_bytes = 0
        self._worker_numbers = count(1)
        self._terminal_listener_numbers = count(1)

        self._state_lock = threading.RLock()
        self._outbound_lock = threading.Lock()
        self._lane_signal_lock = threading.Lock()
        self._worker_condition = threading.Condition(self._state_lock)
        self._startup_output_condition = threading.Condition(self._state_lock)
        self._pending = {}
        self._handlers = {}
        self._late_tombstones = OrderedDict()
        self._late_responses = deque(maxlen=64)
        self._accepting = True
        self._terminal_reason = None
        self._workers_accepting = True
        self._completion_accepting = True
        self._workers = {}
        self._active_workers = 0
        self._active_reentrant_workers = 0
        self._peak_workers = 0
        self._worker_errors = deque(maxlen=error_history)
        self._close_survivors = []
        self._stderr_tail = bytearray()
        # Native GDB DAP redirects fd 1 and fd 2 to an OutputEvent pipe before
        # the client can register handlers.  Retain that early text here so a
        # later secondary CLI UI can begin with the output users would have
        # seen during an ordinary GDB startup.
        self._startup_output = bytearray()
        self._startup_output_truncated = False
        self._startup_output_open = True
        self._startup_barrier_marker = None
        self._startup_completed_marker = None
        self._startup_claim_result = None
        self._startup_stale_markers = set()
        self._terminal_listeners = {}
        self._terminal_delivery_state = "open"
        self._event_lane_stopped = False
        self._router_stop_queued = False
        self._writer_stop_queued = False
        self._event_stop_queued = False
        self._completion_stop_queued = False

        self._initialized = threading.Event()
        self._router_done = threading.Event()
        self._reader_done = threading.Event()
        self._writer_done = threading.Event()
        self._stderr_done = threading.Event()
        self._event_done = threading.Event()
        self._completion_done = threading.Event()
        self._shutdown = threading.Event()
        self._router_stop = threading.Event()
        self._writer_stop = threading.Event()
        self._event_stop = threading.Event()
        self._completion_stop = threading.Event()
        self._close_complete = threading.Event()
        self._close_started = False
        self._close_error = None

        self._reader_thread_id = None
        self._router_thread_id = None
        self._writer_thread_id = None
        self._event_thread_id = None
        self._completion_thread_id = None
        self._callback_local = threading.local()

        self._router = threading.Thread(
            target=self._route_loop,
            name="pwnc-dap-router",
            daemon=True,
        )
        self._writer = threading.Thread(
            target=self._write_loop,
            name="pwnc-dap-writer",
            daemon=True,
        )
        self._reader = threading.Thread(
            target=self._read_loop,
            name="pwnc-dap-reader",
            daemon=True,
        )
        self._stderr_reader = threading.Thread(
            target=self._stderr_loop,
            name="pwnc-dap-stderr",
            daemon=True,
        )
        self._event_worker = threading.Thread(
            target=self._event_loop,
            name="pwnc-dap-events",
            daemon=True,
        )
        self._completion_dispatcher = threading.Thread(
            target=self._completion_loop,
            name="pwnc-dap-completions",
            daemon=True,
        )

        started = []
        try:
            for thread in (
                self._router,
                self._writer,
                self._reader,
                self._stderr_reader,
                self._event_worker,
                self._completion_dispatcher,
            ):
                thread.start()
                started.append(thread)
        except BaseException:
            self._accepting = False
            self._completion_accepting = False
            self._router_stop.set()
            self._shutdown.set()
            self._writer_stop.set()
            self._event_stop.set()
            self._completion_stop.set()
            self._signal_router_stop()
            self._signal_writer_stop()
            self._signal_event_stop()
            self._signal_completion_stop()
            try:
                self.proc.kill()
            except OSError:
                pass
            try:
                wait_process(self.proc, CONTROL_TIMEOUT)
            except subprocess.TimeoutExpired:
                pass
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except (OSError, ValueError):
                    pass
            for thread in started:
                thread.join(CONTROL_TIMEOUT)
            raise

    @property
    def reader_thread_id(self):
        return self._reader_thread_id

    @property
    def router_thread_id(self):
        return self._router_thread_id

    @property
    def writer_thread_id(self):
        return self._writer_thread_id

    @property
    def event_thread_id(self):
        return self._event_thread_id

    @property
    def stderr_tail(self):
        with self._state_lock:
            return bytes(self._stderr_tail)

    @property
    def worker_errors(self):
        with self._state_lock:
            return list(self._worker_errors)

    @property
    def close_survivors(self):
        with self._state_lock:
            return list(self._close_survivors)

    @property
    def pending_count(self):
        with self._state_lock:
            return len(self._pending)

    @property
    def closed(self):
        """Whether the protocol router has observed terminal channel state."""
        return self._router_done.is_set()

    @property
    def terminal_reason(self):
        with self._state_lock:
            return self._terminal_reason

    def wait_closed(self, timeout=None):
        """Wait for the protocol router to reach terminal state.

        This is an event-backed wait: it neither polls nor consumes the
        terminal notification.  ``True`` means the router finished; ``False``
        means a finite *timeout* expired first.
        """
        return self._router_done.wait(timeout)

    def add_terminal_listener(self, callback):
        """Invoke ``callback(reason)`` once when routing becomes terminal.

        Delivery follows passive DAP events already accepted from the wire, so
        a final stop or operation outcome cannot be overtaken by EOF.  A
        listener registered during that ordered handoff joins it; registration
        after delivery has begun runs immediately.  The returned zero-argument
        function unregisters pending delivery and reports whether it won that
        race.  Listener code never runs while the transport state lock is held.
        """
        if not callable(callback):
            raise TypeError("terminal listener must be callable")
        with self._state_lock:
            if (
                self._terminal_reason is None
                or self._terminal_delivery_state == "queued"
            ):
                number = next(self._terminal_listener_numbers)
                self._terminal_listeners[number] = callback
                reason = None
            else:
                number = None
                reason = self._terminal_reason or "transport closed"

        if reason is not None:
            self._invoke_terminal_listener(callback, reason)

        def unsubscribe():
            if number is None:
                return False
            with self._state_lock:
                return self._terminal_listeners.pop(number, None) is not None

        return unsubscribe

    def on(self, event, handler, *, reentrant=False):
        """Register ``handler(body)`` for an event.

        Passive handlers share a serial lane and therefore observe wire order.
        A callback protocol whose parent may synchronously wait for a child must
        opt into ``reentrant=True`` so each invocation receives a fresh stack.
        """
        if not isinstance(event, str):
            raise TypeError("event name must be text")
        if not callable(handler):
            raise TypeError("event handler must be callable")
        with self._state_lock:
            if not self._accepting:
                raise DapError("transport closed")
            self._handlers.setdefault(event, []).append((handler, bool(reentrant)))
        return handler

    def off(self, event, handler):
        """Remove all registrations of *handler* for *event*."""
        with self._state_lock:
            entries = self._handlers.get(event, [])
            kept = [entry for entry in entries if entry[0] is not handler]
            removed = len(entries) - len(kept)
            if kept:
                self._handlers[event] = kept
            else:
                self._handlers.pop(event, None)
            return removed

    def send(self, command, arguments=None):
        """Queue a request without waiting and return a Future-compatible handle."""
        if not isinstance(command, str):
            raise TypeError("DAP command must be text")
        message = {"type": "request", "command": command}
        if arguments is not None:
            message["arguments"] = arguments
        try:
            encoded = self._encode_without_seq(message)
        except (TypeError, ValueError) as error:
            raise DapError(
                f"request is not JSON serializable: {error}",
                command=command,
            ) from error

        with self._outbound_lock, self._state_lock:
            if not self._accepting:
                raise DapError(self._terminal_reason or "transport closed", command=command)
            if len(self._pending) >= self._max_pending_requests:
                raise DapOverload(
                    f"pending request limit {self._max_pending_requests} reached",
                    command=command,
                )
            seq = self._next_seq
            capture_startup_result = (
                command == "evaluate"
                and isinstance(arguments, dict)
                and arguments.get("context") == "repl"
            )
            future = DapFuture(
                self,
                seq,
                command,
                capture_startup_result=capture_startup_result,
            )
            outbound = _Outbound(
                self._checked_frame(seq, encoded, command),
                seq,
                "request",
                command,
            )
            self._pending[seq] = future
            try:
                self._put_outbound_locked(outbound)
            except DapOverload:
                self._pending.pop(seq, None)
                raise
            self._next_seq += 1
        return future

    def result(self, future, timeout=DEFAULT_TIMEOUT):
        """Wait for a raw response Future, validate it, and return its body."""
        command = getattr(future, "_dap_command", None)
        try:
            response = future.result(timeout=timeout)
        except _FutureTimeout:
            if isinstance(future, DapFuture) and future._transport is self:
                if not self._queue_inbound(
                    _Inbound("timeout", future._dap_seq),
                    timeout=CONTROL_TIMEOUT,
                ):
                    raise DapError(
                        "DAP router is unavailable",
                        command=command,
                    )
                try:
                    response = future.result(timeout=CONTROL_TIMEOUT)
                except _FutureTimeout as error:
                    raise DapError(
                        "DAP router did not acknowledge timeout",
                        command=command,
                    ) from error
            else:
                raise DapTimeout(
                    f"timed out waiting for {command!r} response",
                    command=command,
                )
        if not isinstance(response, dict):
            raise DapError("malformed DAP response", command=command, body=response)
        if not response.get("success", False):
            raise DapError(
                response.get("message") or "request failed",
                command=command,
                body=response.get("body"),
            )
        return response.get("body")

    def request(self, command, arguments=None, timeout=DEFAULT_TIMEOUT):
        """Send a request synchronously and return its response body."""
        return self.result(self.send(command, arguments), timeout)

    def claim_startup_output(self, timeout=DEFAULT_TIMEOUT):
        """Close and return the text emitted before a secondary UI exists.

        A marker is written by GDB through the same fd-1 pipe as startup
        output.  Waiting for its OutputEvent makes this a real flush boundary,
        even though GDB's DAP response and output-writer threads are separate.
        The transcript is claimed once; :meth:`restore_startup_output` reopens
        it when attaching the new UI fails and a retry should remain possible.
        """
        if threading.get_ident() == self._router_thread_id:
            raise DapError("cannot claim startup output from the DAP router")
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative or None")
        deadline = None if timeout is None else time.monotonic() + timeout

        def remaining():
            if deadline is None:
                return None
            return max(0.0, deadline - time.monotonic())

        marker = f"__PWNC_STARTUP_OUTPUT_{secrets.token_hex(32)}__"
        with self._startup_output_condition:
            if not self._startup_output_open:
                return ""
            if self._startup_barrier_marker is not None:
                raise DapError("a startup-output claim is already in progress")
            self._startup_barrier_marker = marker
            self._startup_completed_marker = None
            self._startup_claim_result = None

        try:
            self.request(
                "pwncConsoleOutputBarrier",
                {"marker": marker},
                timeout=remaining(),
            )
            with self._startup_output_condition:
                while self._startup_completed_marker != marker:
                    if self._terminal_reason is not None:
                        raise DapError(
                            self._terminal_reason,
                            command="pwncConsoleOutputBarrier",
                        )
                    wait_for = remaining()
                    if wait_for is not None and wait_for <= 0:
                        raise DapTimeout(
                            "timed out flushing GDB startup output",
                            command="pwncConsoleOutputBarrier",
                        )
                    self._startup_output_condition.wait(wait_for)
                result = self._startup_claim_result or ""
                self._startup_completed_marker = None
                self._startup_claim_result = None
                return result
        except BaseException:
            with self._startup_output_condition:
                if self._startup_completed_marker == marker:
                    # The marker won a response/error race.  Put the transcript
                    # back so the caller can retry the console attachment.
                    recovered = self._startup_claim_result or ""
                    self._startup_completed_marker = None
                    self._startup_claim_result = None
                    self._restore_startup_output_locked(recovered)
                elif self._startup_barrier_marker == marker:
                    # A canceled request can still complete late.  Suppress its
                    # random marker if that happens, but let the next claim use
                    # a fresh barrier and retain all ordinary output.
                    self._startup_stale_markers.add(marker)
                    self._startup_barrier_marker = None
                self._startup_output_condition.notify_all()
            raise

    def restore_startup_output(self, output):
        """Restore a claimed transcript after a failed new-UI attachment."""
        if not isinstance(output, str):
            raise TypeError("startup output must be text")
        with self._startup_output_condition:
            self._restore_startup_output_locked(output)
            self._startup_output_condition.notify_all()

    def wait_initialized(self, timeout=DEFAULT_TIMEOUT):
        """Wait until the initialized event and its ordered handlers finish."""
        if not self._initialized.wait(timeout):
            raise DapTimeout("gdb DAP did not send 'initialized'")
        with self._state_lock:
            reason = self._terminal_reason
        if reason is not None:
            raise DapError(reason)

    def drain_events(self, timeout=DEFAULT_TIMEOUT):
        """Wait until passive handlers for all earlier wire events have run.

        ``pwncEventBarrier`` executes on GDB's DAP thread.  Its response is
        ordered after events deferred by the preceding request.  A router-side
        marker then travels through the same FIFO as passive event handlers,
        giving callers a real event-lane barrier without polling.
        """
        if threading.get_ident() == self._event_thread_id:
            raise DapError("cannot drain the DAP event lane from that lane")

        deadline = None if timeout is None else time.monotonic() + timeout

        def remaining():
            if deadline is None:
                return None
            return max(0.0, deadline - time.monotonic())

        delivered = threading.Event()
        delivery_errors = []

        def queue_barrier(_future):
            try:
                self._queue_ordered_event(
                    _EventCall(event="pwncEventBarrier", barrier=delivered)
                )
            except BaseException as error:  # noqa: BLE001 - relay lane failure
                delivery_errors.append(error)
                delivered.set()

        future = self.send("pwncEventBarrier")
        future._add_inline_done_callback(queue_barrier)
        body = self.result(future, timeout=remaining())
        if not delivered.wait(remaining()):
            raise DapTimeout(
                "timed out draining ordered DAP events",
                command="pwncEventBarrier",
            )
        if delivery_errors:
            raise delivery_errors[0]
        return body

    @staticmethod
    def _encode_without_seq(message):
        data = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if not data.startswith(b"{"):
            raise TypeError("DAP message must encode as an object")
        return data

    @staticmethod
    def _frame_encoded(seq, encoded_without_seq):
        body = b'{"seq":' + str(seq).encode("ascii") + b"," + encoded_without_seq[1:]
        return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body

    def _checked_frame(self, seq, encoded_without_seq, command=None):
        body_bytes = len(encoded_without_seq) + len(str(seq)) + 7
        if body_bytes > self._max_frame_bytes:
            raise DapOverload(
                f"DAP frame is {body_bytes} bytes; limit is {self._max_frame_bytes}",
                command=command,
            )
        return self._frame_encoded(seq, encoded_without_seq)

    def _put_outbound_locked(self, outbound):
        size = len(outbound.data)
        if self._queued_outbound_bytes + size > self._max_queued_bytes:
            raise DapOverload(
                f"DAP queued-byte limit {self._max_queued_bytes} reached",
                command=outbound.command,
            )
        try:
            self._outbound.put_nowait(outbound)
        except queue.Full as error:
            raise DapOverload(
                "DAP outbound queue is full",
                command=outbound.command,
            ) from error
        self._queued_outbound_bytes += size

    @staticmethod
    def _write_all(stream, data):
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = stream.write(view[offset:])
            if written is None or written <= 0:
                raise OSError("DAP stream made no progress while writing")
            if written > len(view) - offset:
                raise OSError("DAP stream reported an impossible write length")
            offset += written
        stream.flush()

    @staticmethod
    def _read_exact(stream, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = stream.read(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _signal_router_stop(self):
        with self._lane_signal_lock:
            if self._router_stop_queued:
                return
            self._router_stop_queued = True
            # Explicit close supersedes queued protocol work.  Control
            # insertion bypasses capacity, so a saturated inbound queue cannot
            # strand a router blocked in get().
            self._inbound.put_control(_ROUTER_STOP, front=True)

    def _signal_writer_stop(self):
        with self._lane_signal_lock:
            if self._writer_stop_queued:
                return
            self._writer_stop_queued = True
            # Terminal state makes all remaining outbound requests invalid.
            self._outbound.put_control(_WRITER_STOP, front=True)

    def _signal_event_stop(self):
        with self._lane_signal_lock:
            if self._event_stop_queued:
                return
            self._event_stop_queued = True
            # Ordered handlers already accepted by the router must drain.
            self._events.put_control(_EVENT_STOP)

    def _signal_completion_stop(self):
        with self._lane_signal_lock:
            if self._completion_stop_queued:
                return
            self._completion_stop_queued = True
            # Future callback lanes admitted before close must drain first.
            self._completion_ready.put(_COMPLETION_STOP)

    def _queue_inbound(self, inbound, timeout=None):
        return self._inbound.put_interruptible(
            inbound,
            lambda: (
                self._shutdown.is_set()
                or self._router_stop.is_set()
                or self._router_done.is_set()
            ),
            timeout=timeout,
        )

    def _enqueue_protocol_message(self, message):
        encoded = self._encode_without_seq(message)
        with self._outbound_lock, self._state_lock:
            if not self._accepting:
                return False
            seq = self._next_seq
            outbound = _Outbound(
                self._checked_frame(seq, encoded, message.get("command")),
                seq,
                str(message.get("type")),
                message.get("command"),
            )
            self._put_outbound_locked(outbound)
            self._next_seq += 1
        return True

    def _read_loop(self):
        self._reader_thread_id = threading.get_ident()
        stream = self.proc.stdout
        try:
            if stream is None:
                raise EOFError("GDB stdout is unavailable")
            while not self._shutdown.is_set():
                content_length = None
                header_bytes = 0
                while True:
                    line = stream.readline(8193)
                    if not line:
                        self._queue_inbound(_Inbound("eof", "gdb DAP stream closed"))
                        return
                    header_bytes += len(line)
                    if len(line) > 8192 or header_bytes > 65536:
                        raise ValueError("DAP header is too large")
                    stripped = line.strip()
                    if not stripped:
                        break
                    if b":" not in stripped:
                        continue
                    key, value = stripped.split(b":", 1)
                    if key.strip().lower() == b"content-length":
                        if content_length is not None:
                            raise ValueError("duplicate DAP Content-Length")
                        content_length = int(value.strip())
                if content_length is None:
                    continue
                if content_length <= 0 or content_length > self._max_frame_bytes:
                    raise ValueError(f"invalid DAP Content-Length {content_length}")
                payload = self._read_exact(stream, content_length)
                if payload is None:
                    self._queue_inbound(_Inbound("eof", "gdb DAP stream closed"))
                    return
                if not self._queue_inbound(_Inbound("frame", payload)):
                    return
        except (EOFError, OSError, ValueError) as error:
            self._queue_inbound(
                _Inbound(
                    "reader-error",
                    f"DAP byte reader failed: {type(error).__name__}: {error}",
                )
            )
        finally:
            self._reader_done.set()

    def _write_loop(self):
        self._writer_thread_id = threading.get_ident()
        try:
            while True:
                outbound = self._outbound.get()
                if outbound is _WRITER_STOP:
                    return
                with self._state_lock:
                    self._queued_outbound_bytes -= len(outbound.data)
                stream = self.proc.stdin
                if stream is None:
                    raise OSError("GDB stdin is unavailable")
                self._write_all(stream, outbound.data)
        except BaseException as error:  # noqa: BLE001 - terminal writer guard
            self._queue_inbound(
                _Inbound(
                    "writer-error",
                    f"DAP writer failed: {type(error).__name__}: {error}",
                )
            )
        finally:
            self._writer_done.set()

    def _route_loop(self):
        self._router_thread_id = threading.get_ident()
        try:
            while True:
                inbound = self._inbound.get()
                if inbound is _ROUTER_STOP:
                    self._terminal_failure("transport closed")
                    return
                if inbound.kind == "frame":
                    try:
                        message = json.loads(inbound.value.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        self._terminal_failure(f"invalid DAP JSON: {error}")
                        return
                    try:
                        self._validate_message(message)
                    except (TypeError, ValueError) as error:
                        self._terminal_failure(f"invalid DAP message: {error}")
                        return
                    if self._route_message(message) is False:
                        return
                    continue
                if inbound.kind == "timeout":
                    self._route_timeout(inbound.value)
                    continue
                if inbound.kind == "cancel":
                    future, decision = inbound.value
                    self._route_cancel(future, decision)
                    continue
                if inbound.kind in {
                    "writer-error",
                    "reader-error",
                    "callback-delivery-error",
                    "eof",
                    "close",
                }:
                    self._terminal_failure(str(inbound.value))
                    return
                self._terminal_failure(f"unknown inbound item {inbound.kind!r}")
                return
        except BaseException as error:  # noqa: BLE001 - terminal router guard
            try:
                self._terminal_failure(
                    f"DAP router failed: {type(error).__name__}: {error}"
                )
            except BaseException:  # noqa: BLE001 - emergency terminal guard
                # The pending registry is cleared before terminal callbacks are
                # scheduled, so this fallback can still wake every waiter.
                with self._state_lock:
                    self._accepting = False
                    pending = list(self._pending.values())
                    self._pending.clear()
                    if self._terminal_reason is None:
                        self._terminal_reason = "DAP router failed"
                    effective_reason = self._terminal_reason
                    queue_terminal = self._terminal_delivery_state == "open"
                    if queue_terminal:
                        self._terminal_delivery_state = "queued"
                    self._startup_output_condition.notify_all()
                for future in pending:
                    if not future.done():
                        try:
                            future._finish_exception(DapError(effective_reason))
                        except BaseException as finish_error:  # noqa: BLE001
                            self._record_worker_error(finish_error)
                self._initialized.set()
                if queue_terminal:
                    self._queue_terminal_delivery(effective_reason)
        finally:
            self._router_stop.set()
            self._writer_stop.set()
            self._event_stop.set()
            self._signal_router_stop()
            self._signal_writer_stop()
            self._signal_event_stop()
            self._router_done.set()

    @staticmethod
    def _validate_message(message):
        if not isinstance(message, dict):
            raise TypeError("top-level JSON value is not an object")
        seq = message.get("seq")
        if type(seq) is not int or seq < 0:
            raise ValueError("seq is not a non-negative integer")
        kind = message.get("type")
        if kind not in {"request", "response", "event"}:
            raise ValueError(f"unsupported message type {kind!r}")
        if kind == "response":
            request_seq = message.get("request_seq")
            if type(request_seq) is not int or request_seq < 0:
                raise ValueError("response request_seq is not a non-negative integer")
            if type(message.get("success")) is not bool:
                raise ValueError("response success is not boolean")
            if not isinstance(message.get("command"), str):
                raise ValueError("response command is not text")
        elif kind == "event":
            if not isinstance(message.get("event"), str):
                raise ValueError("event name is not text")
            body = message.get("body")
            if body is not None and not isinstance(body, dict):
                raise ValueError("event body is not an object")
        elif not isinstance(message.get("command"), str):
            raise ValueError("request command is not text")

    def _append_startup_output_locked(self, output):
        if not self._startup_output_open or not output:
            return
        encoded = output.encode("utf-8")
        limit = self._startup_output_limit
        if limit == 0:
            return
        self._startup_output.extend(encoded)
        if len(self._startup_output) > limit:
            self._startup_output[:] = _ansi_safe_suffix(
                self._startup_output,
                limit,
            )
            self._startup_output_truncated = True

    def _take_startup_output_locked(self):
        output = bytes(self._startup_output).decode("utf-8", errors="replace")
        if self._startup_output_truncated:
            output = _STARTUP_OUTPUT_TRUNCATED + output
        self._startup_output.clear()
        self._startup_output_truncated = False
        return output

    def _restore_startup_output_locked(self, output):
        current = ""
        if self._startup_output_open:
            current = self._take_startup_output_locked()
        else:
            self._startup_output.clear()
            self._startup_output_truncated = False
        self._startup_output_open = True
        self._startup_barrier_marker = None
        self._startup_completed_marker = None
        self._startup_claim_result = None
        self._append_startup_output_locked(output)
        self._append_startup_output_locked(current)

    @staticmethod
    def _remove_startup_marker(output, marker):
        index = output.find(marker)
        if index < 0:
            return output, False, "", ""
        prefix = output[:index]
        suffix = output[index + len(marker):]
        if suffix.startswith("\r\n"):
            suffix = suffix[2:]
        elif suffix.startswith("\n"):
            suffix = suffix[1:]
        return prefix + suffix, True, prefix, suffix

    def _capture_startup_output_event(self, body):
        output = body.get("output")
        if not isinstance(output, str):
            return body

        filtered = output
        with self._startup_output_condition:
            # Timed-out barriers can still surface after cancellation.  Their
            # private marker is never user output and must not enter either the
            # transcript or an ordinary output-event handler.
            for stale in tuple(self._startup_stale_markers):
                filtered, found, _prefix, _suffix = self._remove_startup_marker(
                    filtered,
                    stale,
                )
                if found:
                    self._startup_stale_markers.discard(stale)

            marker = self._startup_barrier_marker
            if marker is not None:
                filtered, found, prefix, _suffix = self._remove_startup_marker(
                    filtered,
                    marker,
                )
            else:
                found = False
                prefix = ""

            if found:
                self._append_startup_output_locked(prefix)
                self._startup_claim_result = self._take_startup_output_locked()
                self._startup_output_open = False
                self._startup_barrier_marker = None
                self._startup_completed_marker = marker
                self._startup_output_condition.notify_all()
            else:
                self._append_startup_output_locked(filtered)

        if filtered == output:
            return body
        if not filtered:
            return None
        filtered_body = dict(body)
        filtered_body["output"] = filtered
        return filtered_body

    def _capture_startup_response(self, future, message):
        if not future._dap_capture_startup_result or not message.get("success"):
            return
        body = message.get("body")
        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, str) or not result:
            return
        with self._startup_output_condition:
            self._append_startup_output_locked(result)

    def _route_message(self, message):
        self._assert_router("message routing")
        kind = message["type"]
        if kind == "response":
            seq = message["request_seq"]
            with self._state_lock:
                future = self._pending.get(seq)
                timed_out = seq in self._late_tombstones
            if future is None:
                with self._state_lock:
                    self._late_responses.append(
                        {"requestSeq": seq, "timedOut": timed_out}
                    )
                return
            if message["command"] != future._dap_command:
                self._terminal_failure(
                    "DAP response command mismatch for request "
                    f"{seq}: expected {future._dap_command!r}, "
                    f"got {message['command']!r}"
                )
                return False
            with self._state_lock:
                self._pending.pop(seq, None)
            if not future.done():
                self._capture_startup_response(future, message)
                future._finish_result(message)
            return

        if kind == "event":
            event = message["event"]
            body = message.get("body") or {}
            if event == "output":
                body = self._capture_startup_output_event(body)
                if body is None:
                    return
            with self._state_lock:
                handlers = list(self._handlers.get(event, ()))
            for handler, reentrant in handlers:
                if reentrant:
                    self._spawn_callback_worker(
                        f"event-{event}",
                        handler,
                        body,
                        bounded=True,
                        raise_on_reject=True,
                    )
                else:
                    self._queue_ordered_event(_EventCall(handler, body, event))
            if event == "initialized":
                # Preserve the old observable contract: wait_initialized does
                # not return until prior initialized handlers have run.
                self._queue_ordered_event(
                    _EventCall(event=event, barrier=self._initialized)
                )
            return

        # Adapter reverse request.  Decline through the writer lane so the
        # router never performs pipe I/O or waits for the write lock.
        self._enqueue_protocol_message(
            {
                "type": "response",
                "request_seq": message["seq"],
                "command": message["command"],
                "success": False,
                "message": "not supported",
            }
        )

    def _route_timeout(self, seq):
        self._assert_router("timeout routing")
        with self._state_lock:
            future = self._pending.pop(seq, None)
            if future is not None:
                self._add_tombstone_locked(seq, future._dap_command)
        if future is not None and not future.done():
            cancel_error = None
            try:
                self._enqueue_protocol_message(
                    {
                        "type": "request",
                        "command": "cancel",
                        "arguments": {"requestId": future._dap_seq},
                    }
                )
            except BaseException as error:  # noqa: BLE001 - finish waiter first
                cancel_error = error
            future._finish_exception(
                DapTimeout(
                    f"timed out waiting for {future._dap_command!r} response",
                    command=future._dap_command,
                )
            )
            if cancel_error is not None:
                raise cancel_error

    def _route_cancel(self, future, decision):
        self._assert_router("cancellation routing")
        with self._state_lock:
            current = self._pending.get(future._dap_seq)
            if current is future and not future.done():
                cancelled = future._cancel_from_router()
                if cancelled:
                    self._pending.pop(future._dap_seq, None)
                    self._add_tombstone_locked(
                        future._dap_seq,
                        future._dap_command,
                    )
            else:
                cancelled = False
        if cancelled:
            try:
                self._enqueue_protocol_message(
                    {
                        "type": "request",
                        "command": "cancel",
                        "arguments": {"requestId": future._dap_seq},
                    }
                )
            finally:
                # Do not let an outbound-overload failure strand cancel().
                decision.finish(cancelled)
        else:
            decision.finish(False)

    def _cancel_future(self, future):
        decision = _ControlCell()
        if threading.get_ident() == self._router_thread_id:
            self._route_cancel(future, decision)
        elif not self._queue_inbound(
            _Inbound("cancel", (future, decision)),
            timeout=CONTROL_TIMEOUT,
        ):
            return False
        return bool(decision.result(CONTROL_TIMEOUT))

    def _add_tombstone_locked(self, seq, command):
        self._late_tombstones[seq] = command
        self._late_tombstones.move_to_end(seq)
        while len(self._late_tombstones) > 64:
            self._late_tombstones.popitem(last=False)

    def _terminal_failure(self, reason):
        self._assert_router("terminal failure")
        with self._state_lock:
            self._accepting = False
            pending = list(self._pending.values())
            self._pending.clear()
            if self._terminal_reason is None:
                self._terminal_reason = reason
            effective_reason = self._terminal_reason
            queue_terminal = self._terminal_delivery_state == "open"
            if queue_terminal:
                self._terminal_delivery_state = "queued"
            self._startup_output_condition.notify_all()
        for future in pending:
            if not future.done():
                try:
                    future._finish_exception(
                        DapError(effective_reason, command=future._dap_command)
                    )
                except BaseException as error:  # noqa: BLE001 - notify all waiters
                    self._record_worker_error(error)
        self._initialized.set()
        if queue_terminal:
            self._queue_terminal_delivery(effective_reason)

    def _queue_terminal_delivery(self, reason):
        # Terminal observation is ordered after every passive DAP handler
        # already admitted from the wire.  In particular, a final operation
        # completion event must win over a following EOF.  Control insertion
        # bypasses capacity so saturation cannot drop terminal delivery.
        with self._state_lock:
            event_lane_stopped = self._event_lane_stopped
        if event_lane_stopped:
            self._deliver_terminal_listeners(reason)
        else:
            self._events.put_control(_TerminalCall(str(reason)))

    def _deliver_terminal_listeners(self, reason):
        with self._state_lock:
            if self._terminal_delivery_state != "queued":
                return
            self._terminal_delivery_state = "delivering"
            listeners = list(self._terminal_listeners.values())
            self._terminal_listeners.clear()
        for listener in listeners:
            self._invoke_terminal_listener(listener, reason)
        with self._state_lock:
            self._terminal_delivery_state = "delivered"

    def _invoke_terminal_listener(self, listener, reason):
        try:
            listener(str(reason))
        except BaseException as error:  # noqa: BLE001 - observer isolation
            self._record_worker_error(error)

    def _queue_ordered_event(self, call):
        try:
            self._events.put_nowait(call)
        except queue.Full as error:
            raise DapOverload("DAP ordered event queue is full") from error

    def _event_loop(self):
        self._event_thread_id = threading.get_ident()
        try:
            while True:
                call = self._events.get()
                if call is _EVENT_STOP:
                    return
                if isinstance(call, _TerminalCall):
                    self._deliver_terminal_listeners(call.reason)
                    continue
                if call.barrier is not None:
                    call.barrier.set()
                    continue
                if call.handler is None:
                    continue
                try:
                    call.handler(call.body)
                except BaseException as error:  # noqa: BLE001 - arbitrary handler
                    self._record_worker_error(error)
        finally:
            with self._state_lock:
                self._event_lane_stopped = True
                terminal_reason = self._terminal_reason
                delivery_pending = self._terminal_delivery_state == "queued"
            if delivery_pending:
                self._deliver_terminal_listeners(
                    terminal_reason or "transport closed"
                )
            self._event_done.set()

    def _schedule_future_callback_lane(self, future):
        with self._state_lock:
            if self._completion_accepting:
                self._completion_ready.put(future)
                return

        # Future.add_done_callback() has no rejection channel.  Once explicit
        # close has reaped infrastructure, normal caller-side immediate
        # invocation is both compatible and safe: no router stack can be held.
        if self._safe_inline_callback_caller():
            future._run_callback_lane()
            return
        error = DapError("Future callback delivery infrastructure is closed")
        self._record_worker_error(error)
        raise error

    def _completion_loop(self):
        self._completion_thread_id = threading.get_ident()
        try:
            while True:
                future = self._completion_ready.get()
                if future is _COMPLETION_STOP:
                    return
                try:
                    self._spawn_callback_worker(
                        f"future-{future._dap_seq}",
                        future._run_callback_lane,
                        bounded=False,
                        raise_on_reject=True,
                    )
                except BaseException as error:  # noqa: BLE001 - delivery guard
                    failure = DapError(
                        "could not start Future callback worker: "
                        f"{type(error).__name__}: {error}"
                    )
                    self._record_worker_error(failure)
                    queued = self._queue_inbound(
                        _Inbound("callback-delivery-error", str(failure)),
                        timeout=CONTROL_TIMEOUT,
                    )
                    if queued:
                        self._router_done.wait(CONTROL_TIMEOUT)
                    # Thread creation failure makes normal safe affinity
                    # impossible.  Terminalize routing first, then deliver the
                    # already-accepted callbacks here: re-entry now fails fast
                    # instead of capturing a live protocol stack.
                    future._run_callback_lane()
        finally:
            self._completion_done.set()

    def _invoke_future_callback(self, future, callback):
        previous = getattr(self._callback_local, "future", None)
        self._callback_local.future = future
        try:
            callback(future)
        except BaseException as error:  # noqa: BLE001 - arbitrary callback
            self._record_worker_error(error)
        finally:
            self._callback_local.future = previous

    def _is_current_future_callback(self, future):
        return getattr(self._callback_local, "future", None) is future

    def _safe_inline_callback_caller(self):
        current = threading.current_thread()
        return current not in {
            self._reader,
            self._router,
            self._writer,
            self._completion_dispatcher,
        }

    def _prune_workers_locked(self):
        for number, thread in list(self._workers.items()):
            if not thread.is_alive():
                self._workers.pop(number, None)

    def _spawn_callback_worker(
        self,
        label,
        function,
        *args,
        bounded=True,
        raise_on_reject=False,
    ):
        number = next(self._worker_numbers)

        def run():
            previous_depth = getattr(self._callback_local, "depth", 0)
            self._callback_local.depth = previous_depth + 1
            try:
                with self._worker_condition:
                    self._active_workers += 1
                    self._peak_workers = max(
                        self._peak_workers,
                        self._active_workers,
                    )
                function(*args)
            except BaseException as error:  # noqa: BLE001 - arbitrary callback
                self._record_worker_error(error)
            finally:
                self._callback_local.depth = previous_depth
                with self._worker_condition:
                    self._active_workers -= 1
                    if bounded:
                        self._active_reentrant_workers -= 1
                    self._worker_condition.notify_all()

        with self._worker_condition:
            self._prune_workers_locked()
            if not self._workers_accepting:
                error = DapError("transport no longer accepts callback workers")
                self._worker_errors.append(error)
                if raise_on_reject:
                    raise error
                return None
            if (
                bounded
                and self._active_reentrant_workers >= self._max_callback_workers
            ):
                error = DapOverload(
                    f"callback worker limit {self._max_callback_workers} reached"
                )
                self._worker_errors.append(error)
                if raise_on_reject:
                    raise error
                return None
            try:
                thread = threading.Thread(
                    target=run,
                    name=f"pwnc-dap-{label}-{number}",
                    daemon=True,
                )
            except BaseException as error:
                self._worker_errors.append(error)
                if raise_on_reject:
                    raise
                return None
            self._workers[number] = thread
            if bounded:
                self._active_reentrant_workers += 1
            try:
                # run() takes this same condition before touching counters, so
                # close/wait can never observe an unstarted registered thread.
                thread.start()
            except BaseException as error:
                self._workers.pop(number, None)
                if bounded:
                    self._active_reentrant_workers -= 1
                self._worker_errors.append(error)
                self._worker_condition.notify_all()
                if raise_on_reject:
                    raise
                return None
        return thread

    def _record_worker_error(self, error):
        with self._worker_condition:
            self._worker_errors.append(error)

    def _assert_router(self, action):
        if threading.get_ident() != self._router_thread_id:
            raise AssertionError(f"{action} did not run on the DAP router")

    def _stderr_loop(self):
        stream = self.proc.stderr
        try:
            if stream is None:
                return
            while not self._shutdown.is_set():
                chunk = stream.read(4096)
                if not chunk:
                    return
                with self._startup_output_condition:
                    self._append_startup_output_locked(
                        chunk.decode("utf-8", errors="replace")
                    )
                    if self._stderr_tail_bytes:
                        self._stderr_tail.extend(chunk)
                        excess = len(self._stderr_tail) - self._stderr_tail_bytes
                        if excess > 0:
                            del self._stderr_tail[:excess]
        except (OSError, ValueError):
            pass
        finally:
            self._stderr_done.set()

    @staticmethod
    def _remaining(deadline):
        return max(0.0, deadline - time.monotonic())

    def _wait_callback_workers(self, deadline):
        current = threading.current_thread()
        while True:
            with self._worker_condition:
                self._prune_workers_locked()
                workers = list(self._workers.values())
            for worker in workers:
                if worker is current:
                    continue
                remaining = self._remaining(deadline)
                if remaining <= 0:
                    break
                worker.join(remaining)
            with self._worker_condition:
                self._prune_workers_locked()
                current_survivors = [
                    worker.name
                    for worker in self._workers.values()
                    if worker is current and worker.is_alive()
                ]
                other_survivors = [
                    worker.name
                    for worker in self._workers.values()
                    if worker is not current and worker.is_alive()
                ]
                if not other_survivors:
                    return current_survivors
            if self._remaining(deadline) <= 0:
                return [*current_survivors, *other_survivors]

    def _close_from_callback_context(self):
        return (
            getattr(self._callback_local, "depth", 0) > 0
            or threading.get_ident() == self._event_thread_id
        )

    def _emergency_close(self, deadline):
        """Best-effort reap after an unexpected exception in normal close."""
        self._router_stop.set()
        self._shutdown.set()
        self._writer_stop.set()
        self._event_stop.set()
        self._completion_stop.set()
        self._signal_router_stop()
        self._signal_writer_stop()
        self._signal_event_stop()
        self._signal_completion_stop()
        with self._state_lock:
            self._accepting = False
            self._completion_accepting = False
        with self._worker_condition:
            self._workers_accepting = False
            self._worker_condition.notify_all()
        try:
            if self.proc.poll() is None:
                self.proc.kill()
        except BaseException:  # noqa: BLE001, S110 - cannot mask original cause
            pass
        try:
            wait_process(self.proc, self._remaining(deadline))
        except BaseException:  # noqa: BLE001, S110 - cannot mask original cause
            pass
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except BaseException:  # noqa: BLE001, S110 - cannot mask original cause
                pass
        current = threading.current_thread()
        for thread in (
            self._router,
            self._writer,
            self._reader,
            self._stderr_reader,
            self._event_worker,
            self._completion_dispatcher,
        ):
            try:
                if thread is not current and thread.ident is not None:
                    thread.join(self._remaining(deadline))
            except BaseException:  # noqa: BLE001, S110 - cannot mask original cause
                pass

    def close(self, timeout=CONTROL_TIMEOUT):
        """Boundedly stop GDB and reap transport threads.

        Python cannot forcibly kill a callback blocked in external user code;
        such workers are reported through :attr:`close_survivors`.  GDB and all
        transport infrastructure are nevertheless reaped under one deadline.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        with self._state_lock:
            if self._close_complete.is_set():
                completed_failure = self._close_error
                if completed_failure is not None:
                    raise completed_failure
                return
            if self._close_started:
                wait_for_other = True
            else:
                self._close_started = True
                self._accepting = False
                wait_for_other = False
        if wait_for_other:
            # The close owner eventually joins callback workers.  A callback
            # waiting for that owner would create a bounded wait cycle.
            if self._close_from_callback_context():
                return
            if not self._close_complete.wait(self._remaining(deadline)):
                raise DapError("transport close did not finish before deadline")
            with self._state_lock:
                completed_failure = self._close_error
            if completed_failure is not None:
                raise completed_failure
            return

        failure = None
        try:
            if not self._router_done.is_set():
                self._router_stop.set()
                self._signal_router_stop()
                self._router_done.wait(self._remaining(deadline))

            self._shutdown.set()
            self._writer_stop.set()
            self._event_stop.set()
            self._signal_writer_stop()
            self._signal_event_stop()

            if self.proc.poll() is None:
                try:
                    self.proc.terminate()
                except OSError:
                    pass
                try:
                    wait_process(self.proc, min(0.25, self._remaining(deadline)))
                except subprocess.TimeoutExpired:
                    try:
                        self.proc.kill()
                    except OSError:
                        pass
                    try:
                        wait_process(self.proc, self._remaining(deadline))
                    except subprocess.TimeoutExpired:
                        pass
            else:
                # Reap an exited child as well; poll() does not replace wait().
                try:
                    wait_process(self.proc, self._remaining(deadline))
                except subprocess.TimeoutExpired:
                    pass

            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except (OSError, ValueError):
                    pass

            current = threading.current_thread()
            infrastructure = (
                self._router,
                self._writer,
                self._reader,
                self._stderr_reader,
            )
            for thread in infrastructure:
                if thread is current or thread.ident is None:
                    continue
                thread.join(self._remaining(deadline))

            if self._event_worker is not current and self._event_worker.ident is not None:
                self._event_worker.join(self._remaining(deadline))

            # No more router completions can appear.  Drain every accepted
            # Future callback lane before refusing new callback workers.
            with self._state_lock:
                self._completion_accepting = False
            self._completion_stop.set()
            self._signal_completion_stop()
            if (
                self._completion_dispatcher is not current
                and self._completion_dispatcher.ident is not None
            ):
                self._completion_dispatcher.join(self._remaining(deadline))

            with self._worker_condition:
                self._workers_accepting = False
                self._worker_condition.notify_all()
            worker_survivors = self._wait_callback_workers(deadline)
            infrastructure_survivors = [
                thread.name
                for thread in infrastructure
                if thread is not current and thread.is_alive()
            ]
            if (
                self._completion_dispatcher is not current
                and self._completion_dispatcher.is_alive()
            ):
                infrastructure_survivors.append(
                    self._completion_dispatcher.name
                )
            if self._event_worker is not current and self._event_worker.is_alive():
                worker_survivors.append(self._event_worker.name)
            if current is self._event_worker:
                worker_survivors.append(current.name)
            if current is self._completion_dispatcher:
                worker_survivors.append(current.name)

            with self._state_lock:
                self._close_survivors = list(dict.fromkeys(worker_survivors))

            if self.proc.poll() is None or infrastructure_survivors:
                survivors = list(infrastructure_survivors)
                if self.proc.poll() is None:
                    survivors.insert(0, "gdb-process")
                failure = DapError(
                    "transport close deadline expired with survivors: "
                    + ", ".join(survivors)
                )
        except BaseException as error:  # noqa: BLE001 - preserve and replay close failure
            failure = error
            self._emergency_close(deadline)
        finally:
            with self._state_lock:
                self._close_error = failure
            self._close_complete.set()
        if failure is not None:
            raise failure
