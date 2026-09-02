"""Real-GDB proof for a reader-isolated, synchronous DAP transport.

The transport in this experiment deliberately isolates four execution domains::

    stdout byte reader -> inbound Queue -> router/completion thread
                                           |
                                           +-> fresh user callback workers

    synchronous senders -> ordered outbound Queue -> dedicated byte writer

The byte reader only finds ``Content-Length`` frames and enqueues their raw
payload bytes.  In particular it never decodes JSON, mutates request slots,
sets a ``Future``, or invokes an event/user callback.  The router owns JSON
decoding, response correlation, timeout/close completion, and event fan-out.
Every event handler and response completion callback is scheduled on a fresh
ordinary thread so neither the reader nor router can be captured by sync user
code.  Sequence assignment and outbound enqueue are atomic, and the dedicated
writer performs complete writes without ever occupying the router.

The public request path remains synchronous and uses a small condition-based
response slot rather than ``concurrent.futures.Future``.  Slots support a safe
``add_done_callback`` analogue, but callbacks are *always* scheduled; they are
never called inline by the thread that completes or registers the slot.

Run directly (bata24 GEF is required when ``--require-gef`` is supplied)::

    python3 tests/dap/experiments/routed_transport_probe.py --require-gef

No asyncio, greenlet, fixed worker pool, or recursive message pump is used.
This is intentionally an experiment, not a production transport edit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import shutil
import subprocess
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, field
from itertools import count
from pathlib import Path
from typing import Any

try:
    import pytest
except ImportError:  # Direct execution does not require pytest.
    pytest = None


DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_BATA24_GEF_SHA256 = (
    "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
)
DEFAULT_DEPTH = 8
REQUEST_TIMEOUT = 15.0
DEADLOCK_TIMEOUT = 45.0
CONTROL_TIMEOUT = 5.0
_UNSET = object()


class RoutedDapError(RuntimeError):
    """The DAP channel or a request failed."""

    def __init__(
        self,
        message: str,
        *,
        command: str | None = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.command = command
        self.body = body


class RoutedDapTimeout(RoutedDapError):
    """A response did not arrive before its caller's deadline."""


class _WaitDeadline(Exception):
    pass


@dataclass(frozen=True)
class _Inbound:
    kind: str
    value: Any = None
    producer_thread_id: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _Outbound:
    kind: str
    data: bytes | None = None
    seq: int | None = None
    message_type: str | None = None
    command: str | None = None


class _ResponseSlot:
    """A response cell completed only by the transport router thread."""

    def __init__(
        self,
        transport: RoutedDapTransport,
        seq: int,
        command: str,
    ) -> None:
        self.transport = transport
        self.seq = seq
        self.command = command
        self._condition = threading.Condition()
        self._value: Any = _UNSET
        self._error: BaseException | None = None
        self._callbacks: list[Callable[[_ResponseSlot], Any]] = []

    @property
    def done(self) -> bool:
        with self._condition:
            return self._value is not _UNSET or self._error is not None

    def _finish(
        self,
        *,
        value: Any = _UNSET,
        error: BaseException | None = None,
    ) -> bool:
        """Finish on the router and schedule, rather than invoke, callbacks."""
        self.transport._assert_router("response completion")
        if (value is _UNSET) == (error is None):
            raise AssertionError("slot needs exactly one value or error")
        with self._condition:
            if self._value is not _UNSET or self._error is not None:
                return False
            self._value = value
            self._error = error
            callbacks = list(self._callbacks)
            self._callbacks.clear()
            self._condition.notify_all()
        for callback in callbacks:
            self.transport._spawn_user_worker(
                "completion",
                callback,
                self,
                label=f"seq-{self.seq}",
            )
        return True

    def _wait(self, timeout: float | None) -> Any:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self._value is _UNSET and self._error is None:
                remaining = (
                    None if deadline is None else deadline - time.monotonic()
                )
                if remaining is not None and remaining <= 0:
                    raise _WaitDeadline
                self._condition.wait(remaining)
            if self._error is not None:
                raise self._error
            return self._value

    def add_done_callback(
        self,
        callback: Callable[[_ResponseSlot], Any],
    ) -> None:
        """Schedule *callback* on a worker, even when already complete."""
        with self._condition:
            if self._value is _UNSET and self._error is None:
                self._callbacks.append(callback)
                return
        self.transport._spawn_user_worker(
            "completion",
            callback,
            self,
            label=f"seq-{self.seq}-already-done",
        )

    def result(self, timeout: float | None = REQUEST_TIMEOUT) -> Any:
        return self.transport.result(self, timeout=timeout)


class RoutedDapTransport:
    """Experiment-only DAP transport with a mechanically minimal reader."""

    def __init__(
        self,
        gdb_path: str = "gdb",
        gdb_args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        argv = [gdb_path, "-q", "-nx", "--interpreter=dap"]
        if gdb_args:
            argv.extend(gdb_args)
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0,
        )
        self._next_seq = 1
        self._worker_ids = count(1)
        self._inbound: queue.Queue[_Inbound] = queue.Queue()
        self._outbound: queue.Queue[_Outbound] = queue.Queue()
        self._state_lock = threading.RLock()
        self._outbound_lock = threading.Lock()
        self._worker_condition = threading.Condition(self._state_lock)
        self._pending: dict[int, _ResponseSlot] = {}
        self._handlers: dict[str, list[Callable[[dict[str, Any]], Any]]] = {}
        self._late_tombstones: OrderedDict[int, str] = OrderedDict()
        self._accepting = True
        self._terminal_reason: str | None = None
        self._router_done = threading.Event()
        self._writer_done = threading.Event()
        self._writer_stop_queued = False
        self._initialized = threading.Event()
        self._close_ack = threading.Event()
        self._reader_id: int | None = None
        self._router_id: int | None = None
        self._writer_id: int | None = None
        self._reader_log: list[dict[str, Any]] = []
        self._router_log: list[dict[str, Any]] = []
        self._writer_log: list[dict[str, Any]] = []
        self._worker_log: list[dict[str, Any]] = []
        self._late_responses: list[dict[str, Any]] = []
        self._worker_errors: list[BaseException] = []
        self._workers: dict[int, threading.Thread] = {}
        self._worker_total = 0
        self._workers_accepting = True
        self._active_workers = 0
        self._peak_workers = 0
        self._close_survivors: list[str] = []
        self._stderr_chunks: list[bytes] = []
        self._reader = threading.Thread(
            target=self._read_loop,
            name="routed-dap-byte-reader",
            daemon=True,
        )
        self._router = threading.Thread(
            target=self._route_loop,
            name="routed-dap-router",
            daemon=True,
        )
        self._writer = threading.Thread(
            target=self._write_loop,
            name="routed-dap-writer",
            daemon=True,
        )
        self._stderr_reader = threading.Thread(
            target=self._drain_stderr,
            name="routed-dap-stderr-reader",
            daemon=True,
        )
        self._router.start()
        self._writer.start()
        self._reader.start()
        self._stderr_reader.start()

    @property
    def reader_thread_id(self) -> int | None:
        return self._reader_id

    @property
    def router_thread_id(self) -> int | None:
        return self._router_id

    @property
    def writer_thread_id(self) -> int | None:
        return self._writer_id

    @property
    def reader_log(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return list(self._reader_log)

    @property
    def router_log(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return list(self._router_log)

    @property
    def writer_log(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return list(self._writer_log)

    @property
    def worker_log(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return list(self._worker_log)

    @property
    def late_responses(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return list(self._late_responses)

    @property
    def worker_errors(self) -> list[BaseException]:
        with self._state_lock:
            return list(self._worker_errors)

    def _record_router(self, kind: str, **fields: Any) -> None:
        self._assert_router("router trace")
        with self._state_lock:
            self._router_log.append(
                {
                    "kind": kind,
                    "threadId": threading.get_ident(),
                    **fields,
                }
            )

    def _assert_router(self, action: str) -> None:
        if threading.get_ident() != self._router_id:
            raise AssertionError(f"{action} did not run on the router")

    def _assert_user_worker(self, action: str) -> None:
        infrastructure_threads = {self._reader, self._router, self._writer}
        if threading.current_thread() in infrastructure_threads:
            raise AssertionError(f"{action} ran on a transport infrastructure thread")

    def on(
        self,
        event: str,
        handler: Callable[[dict[str, Any]], Any],
    ) -> None:
        with self._state_lock:
            if not self._accepting:
                raise RoutedDapError("transport closed")
            self._handlers.setdefault(event, []).append(handler)

    def send(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
    ) -> _ResponseSlot:
        message: dict[str, Any] = {
            "type": "request",
            "command": command,
        }
        if arguments is not None:
            message["arguments"] = arguments
        try:
            encoded = self._encode_without_seq(message)
        except (TypeError, ValueError) as error:
            raise RoutedDapError(
                f"request is not JSON serializable: {error}",
                command=command,
            ) from error

        # Sequence assignment, pending registration, and queue insertion share
        # one critical section.  The one writer consumes this FIFO, so DAP seq
        # values and actual wire order cannot diverge under concurrent callers.
        with self._outbound_lock, self._state_lock:
            if not self._accepting:
                raise RoutedDapError("transport closed", command=command)
            seq = self._next_seq
            self._next_seq += 1
            slot = _ResponseSlot(self, seq, command)
            self._pending[seq] = slot
            self._outbound.put(
                _Outbound(
                    "message",
                    self._frame_encoded(seq, encoded),
                    seq=seq,
                    message_type="request",
                    command=command,
                )
            )
        return slot

    def result(
        self,
        slot: _ResponseSlot,
        timeout: float | None = REQUEST_TIMEOUT,
    ) -> Any:
        try:
            response = slot._wait(timeout)
        except _WaitDeadline:
            # Timeout state is also selected by the router.  A response which
            # was already queued first wins; otherwise this installs a bounded
            # tombstone so the eventual response is explicitly classified.
            self._inbound.put(_Inbound("timeout", slot.seq))
            try:
                response = slot._wait(CONTROL_TIMEOUT)
            except _WaitDeadline as error:
                raise RoutedDapError(
                    "router did not acknowledge timeout",
                    command=slot.command,
                ) from error
        if not response.get("success", False):
            raise RoutedDapError(
                response.get("message") or "request failed",
                command=slot.command,
                body=response.get("body"),
            )
        return response.get("body")

    def request(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
    ) -> Any:
        return self.result(self.send(command, arguments), timeout=timeout)

    def wait_initialized(self, timeout: float = REQUEST_TIMEOUT) -> None:
        if not self._initialized.wait(timeout):
            raise RoutedDapTimeout("GDB DAP did not send initialized")

    @staticmethod
    def _encode_without_seq(message: dict[str, Any]) -> bytes:
        data = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if not data.startswith(b"{"):
            raise TypeError("DAP message must encode as an object")
        return data

    @staticmethod
    def _frame_encoded(seq: int, encoded_without_seq: bytes) -> bytes:
        body = b'{"seq":' + str(seq).encode("ascii") + b"," + encoded_without_seq[1:]
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        return header + body

    @staticmethod
    def _write_all(stream: Any, data: bytes) -> None:
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

    def _enqueue_protocol_message(self, message: dict[str, Any]) -> bool:
        """Queue a router-generated message without doing I/O on the router."""
        encoded = self._encode_without_seq(message)
        with self._outbound_lock, self._state_lock:
            if not self._accepting:
                return False
            seq = self._next_seq
            self._next_seq += 1
            self._outbound.put(
                _Outbound(
                    "message",
                    self._frame_encoded(seq, encoded),
                    seq=seq,
                    message_type=str(message.get("type")),
                    command=str(message.get("command")),
                )
            )
        return True

    def _write_loop(self) -> None:
        self._writer_id = threading.get_ident()
        try:
            while True:
                outbound = self._outbound.get()
                if outbound.kind == "stop":
                    return
                if outbound.kind != "message" or outbound.data is None:
                    raise RoutedDapError(
                        f"unknown outbound item {outbound.kind!r}"
                    )
                stream = self.proc.stdin
                if stream is None:
                    raise OSError("GDB stdin is unavailable")
                self._write_all(stream, outbound.data)
                with self._state_lock:
                    self._writer_log.append(
                        {
                            "kind": "message-written",
                            "threadId": threading.get_ident(),
                            "seq": outbound.seq,
                            "messageType": outbound.message_type,
                            "command": outbound.command,
                            "byteCount": len(outbound.data),
                        }
                    )
        except BaseException as error:  # noqa: BLE001 - terminal writer guard
            with self._state_lock:
                self._writer_log.append(
                    {
                        "kind": "writer-error",
                        "threadId": threading.get_ident(),
                        "errorType": type(error).__name__,
                        "errorMessage": str(error),
                    }
                )
            self._inbound.put(
                _Inbound(
                    "writer-error",
                    f"DAP writer failed: {type(error).__name__}: {error}",
                )
            )
        finally:
            self._writer_done.set()

    @staticmethod
    def _read_exact(stream: Any, size: int) -> bytes | None:
        chunks = []
        remaining = size
        while remaining:
            chunk = stream.read(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_loop(self) -> None:
        # Keep this loop mechanically minimal.  Even its diagnostic evidence
        # is carried in queue envelopes and recorded by the router; the reader
        # itself mutates no protocol/completion/handler state.
        reader_thread_id = threading.get_ident()

        def enqueue(kind: str, value: Any = None, **details: Any) -> None:
            self._inbound.put(
                _Inbound(
                    kind,
                    value,
                    producer_thread_id=reader_thread_id,
                    details=details,
                )
            )

        stream = self.proc.stdout
        try:
            if stream is None:
                raise EOFError("GDB stdout is unavailable")
            while True:
                content_length: int | None = None
                while True:
                    line = stream.readline()
                    if not line:
                        enqueue("eof", "GDB DAP stream closed")
                        return
                    stripped = line.strip()
                    if not stripped:
                        break
                    if b":" not in stripped:
                        continue
                    key, value = stripped.split(b":", 1)
                    if key.strip().lower() == b"content-length":
                        content_length = int(value.strip())
                        if content_length < 0:
                            raise ValueError("negative DAP Content-Length")
                if content_length is None:
                    continue
                payload = self._read_exact(stream, content_length)
                if payload is None:
                    enqueue("eof", "GDB DAP stream closed")
                    return
                enqueue("frame", payload, byteCount=len(payload))
        except (EOFError, OSError, ValueError) as error:
            enqueue(
                "reader-error",
                f"DAP byte reader failed: {error}",
                errorType=type(error).__name__,
                errorMessage=str(error),
            )

    def _observe_reader_inbound(self, inbound: _Inbound) -> None:
        """Record reader evidence on the router, never on the reader."""
        self._assert_router("reader observation")
        if inbound.producer_thread_id is None:
            return
        with self._state_lock:
            if self._reader_id is None:
                self._reader_id = inbound.producer_thread_id
            elif self._reader_id != inbound.producer_thread_id:
                raise AssertionError("multiple DAP byte-reader threads observed")
            self._reader_log.append(
                {
                    "kind": f"{inbound.kind}-enqueued",
                    "threadId": inbound.producer_thread_id,
                    "observedByRouterThreadId": threading.get_ident(),
                    **inbound.details,
                }
            )

    def _route_loop(self) -> None:
        self._router_id = threading.get_ident()
        try:
            while True:
                inbound = self._inbound.get()
                self._observe_reader_inbound(inbound)
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
                    self._route_message(message)
                    continue
                if inbound.kind == "timeout":
                    self._route_timeout(int(inbound.value))
                    continue
                if inbound.kind == "send-error":
                    seq, error = inbound.value
                    self._route_send_error(seq, error)
                    continue
                if inbound.kind == "writer-error":
                    self._terminal_failure(str(inbound.value))
                    return
                if inbound.kind == "close":
                    self._terminal_failure(str(inbound.value))
                    return
                if inbound.kind in {"eof", "reader-error"}:
                    self._terminal_failure(str(inbound.value))
                    return
                self._terminal_failure(f"unknown inbound item {inbound.kind!r}")
                return
        except BaseException as error:  # noqa: BLE001 - terminal router guard
            # No router failure may strand synchronous callers.  Keep this
            # guard outside individual message handlers so future routing bugs
            # receive the same terminal cleanup as malformed peer input.
            try:
                self._terminal_failure(
                    f"DAP router failed: {type(error).__name__}: {error}"
                )
            except BaseException:  # noqa: BLE001 - emergency terminal guard
                # _terminal_failure clears the registry before diagnostics or
                # callback scheduling, so even a secondary diagnostics failure
                # cannot leave request slots registered.
                with self._state_lock:
                    self._accepting = False
                    pending = list(self._pending.values())
                    self._pending.clear()
                for slot in pending:
                    try:
                        slot._finish(
                            error=RoutedDapError(
                                "DAP router failed during terminal cleanup",
                                command=slot.command,
                            )
                        )
                    except BaseException as finish_error:  # noqa: BLE001
                        with self._state_lock:
                            self._worker_errors.append(finish_error)
        finally:
            with self._worker_condition:
                self._workers_accepting = False
                self._worker_condition.notify_all()
            self._router_done.set()
            self._close_ack.set()

    @staticmethod
    def _validate_message(message: Any) -> None:
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

    def _route_message(self, message: dict[str, Any]) -> None:
        self._assert_router("message routing")
        kind = message.get("type")
        if kind == "response":
            seq = message.get("request_seq")
            with self._state_lock:
                slot = self._pending.pop(seq, None)
                timeout_command = self._late_tombstones.get(seq)
            if slot is None:
                late = {
                    "requestSeq": seq,
                    "command": message.get("command") or timeout_command,
                    "timedOut": timeout_command is not None,
                }
                with self._state_lock:
                    self._late_responses.append(late)
                self._record_router("late-response", **late)
                return
            self._record_router(
                "response-completed",
                requestSeq=seq,
                command=slot.command,
            )
            slot._finish(value=message)
            return
        if kind == "event":
            event = str(message.get("event"))
            body = message.get("body") or {}
            if event == "initialized":
                self._initialized.set()
            with self._state_lock:
                handlers = list(self._handlers.get(event, ()))
            self._record_router(
                "event-fanout",
                event=event,
                handlerCount=len(handlers),
            )
            for index, handler in enumerate(handlers):
                self._spawn_user_worker(
                    "event",
                    handler,
                    body,
                    label=f"{event}-{index}",
                )
            return
        if kind == "request":
            self._record_router(
                "reverse-request-declined",
                command=message.get("command"),
            )
            self._enqueue_protocol_message(
                {
                    "type": "response",
                    "request_seq": message.get("seq"),
                    "command": message.get("command"),
                    "success": False,
                    "message": "not supported by routed transport probe",
                }
            )
            return
        self._record_router("unknown-message", messageType=kind)

    def _route_timeout(self, seq: int) -> None:
        with self._state_lock:
            slot = self._pending.pop(seq, None)
            if slot is not None:
                self._late_tombstones[seq] = slot.command
                self._late_tombstones.move_to_end(seq)
                while len(self._late_tombstones) > 64:
                    self._late_tombstones.popitem(last=False)
        if slot is None:
            return
        self._record_router("request-timed-out", requestSeq=seq, command=slot.command)
        slot._finish(
            error=RoutedDapTimeout(
                f"timed out waiting for {slot.command!r} response",
                command=slot.command,
            )
        )

    def _route_send_error(self, seq: int, error: BaseException) -> None:
        with self._state_lock:
            slot = self._pending.pop(seq, None)
        if slot is None:
            return
        self._record_router("send-failed", requestSeq=seq, command=slot.command)
        slot._finish(error=error)

    def _terminal_failure(self, reason: str) -> None:
        self._assert_router("terminal failure")
        with self._state_lock:
            self._accepting = False
            pending = list(self._pending.values())
            self._pending.clear()
            first_terminal = self._terminal_reason is None
            if first_terminal:
                self._terminal_reason = reason
        if first_terminal:
            self._record_router("channel-terminal", reason=reason, pending=len(pending))
        for slot in pending:
            slot._finish(error=RoutedDapError(reason, command=slot.command))
        self._initialized.set()

    def _spawn_user_worker(
        self,
        worker_kind: str,
        function: Callable[..., Any],
        *args: Any,
        label: str,
    ) -> threading.Thread | None:
        worker_number = next(self._worker_ids)

        def run() -> None:
            try:
                with self._worker_condition:
                    self._active_workers += 1
                    self._peak_workers = max(self._peak_workers, self._active_workers)
                    self._worker_log.append(
                        {
                            "kind": f"{worker_kind}-enter",
                            "label": label,
                            "threadId": threading.get_ident(),
                            "threadName": threading.current_thread().name,
                        }
                    )
                self._assert_user_worker(f"{worker_kind} callback")
                function(*args)
            except BaseException as error:  # noqa: BLE001 - arbitrary user code
                with self._worker_condition:
                    self._worker_errors.append(error)
            finally:
                with self._worker_condition:
                    self._worker_log.append(
                        {
                            "kind": f"{worker_kind}-return",
                            "label": label,
                            "threadId": threading.get_ident(),
                            "threadName": threading.current_thread().name,
                        }
                    )
                    self._active_workers -= 1
                    self._worker_condition.notify_all()

        thread = threading.Thread(
            target=run,
            name=f"routed-dap-{worker_kind}-{worker_number}",
            daemon=True,
        )
        with self._worker_condition:
            if not self._workers_accepting:
                error = RoutedDapError(
                    f"transport no longer accepts {worker_kind} callbacks"
                )
                self._worker_errors.append(error)
                self._worker_log.append(
                    {
                        "kind": f"{worker_kind}-rejected",
                        "label": label,
                        "threadId": threading.get_ident(),
                        "threadName": threading.current_thread().name,
                    }
                )
                return None
            self._workers[worker_number] = thread
            self._worker_total += 1
            try:
                # Keep the condition lock held until Thread.start has crossed
                # its internal started barrier.  run() blocks on this same lock,
                # so wait_workers can never observe an unstarted Thread.
                self._start_user_worker(thread)
            except BaseException as error:  # noqa: BLE001 - Thread.start guard
                self._workers.pop(worker_number, None)
                self._worker_errors.append(error)
                self._worker_log.append(
                    {
                        "kind": f"{worker_kind}-start-failed",
                        "label": label,
                        "threadId": threading.get_ident(),
                        "threadName": threading.current_thread().name,
                        "errorType": type(error).__name__,
                        "errorMessage": str(error),
                    }
                )
                self._worker_condition.notify_all()
                return None
        return thread

    @staticmethod
    def _start_user_worker(thread: threading.Thread) -> None:
        thread.start()

    def wait_workers(
        self,
        timeout: float = DEADLOCK_TIMEOUT,
        *,
        raise_on_timeout: bool = True,
    ) -> list[str]:
        deadline = time.monotonic() + timeout
        while True:
            with self._worker_condition:
                workers = list(self._workers.items())
            for _worker_number, worker in workers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                worker.join(remaining)
            with self._worker_condition:
                for worker_number, worker in list(self._workers.items()):
                    if not worker.is_alive():
                        self._workers.pop(worker_number, None)
                survivors = [
                    worker.name for worker in self._workers.values() if worker.is_alive()
                ]
                if not survivors and self._active_workers == 0:
                    return []
            if time.monotonic() >= deadline:
                if raise_on_timeout:
                    raise TimeoutError(
                        "transport callback workers did not finish: "
                        + ", ".join(survivors)
                    )
                return survivors

    @staticmethod
    def _remaining(deadline: float) -> float:
        return max(0.0, deadline - time.monotonic())

    def close(self, timeout: float = CONTROL_TIMEOUT) -> None:
        """Close within one shared deadline and report callback survivors."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self._outbound_lock, self._state_lock:
            should_signal_router = not self._router_done.is_set()
            self._accepting = False
            if not self._writer_stop_queued:
                self._writer_stop_queued = True
                self._outbound.put(_Outbound("stop"))
        if should_signal_router:
            self._inbound.put(_Inbound("close", "transport closed"))
            self._router_done.wait(self._remaining(deadline))

        if self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass
            terminate_grace = min(0.25, self._remaining(deadline))
            try:
                self.proc.wait(timeout=terminate_grace)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.kill()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=self._remaining(deadline))
                except subprocess.TimeoutExpired:
                    pass

        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except (OSError, ValueError):
                pass

        infrastructure = (
            self._router,
            self._writer,
            self._reader,
            self._stderr_reader,
        )
        for thread in infrastructure:
            thread.join(self._remaining(deadline))

        with self._worker_condition:
            self._workers_accepting = False
            self._worker_condition.notify_all()
        self._close_survivors = self.wait_workers(
            self._remaining(deadline),
            raise_on_timeout=False,
        )

        infrastructure_survivors = [
            thread.name for thread in infrastructure if thread.is_alive()
        ]
        if self.proc.poll() is None or infrastructure_survivors:
            details = infrastructure_survivors
            if self.proc.poll() is None:
                details = ["gdb-process", *details]
            raise RoutedDapError(
                "transport close deadline expired with survivors: "
                + ", ".join(details)
            )

    def _drain_stderr(self) -> None:
        stream = self.proc.stderr
        if stream is None:
            return
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            with self._state_lock:
                self._stderr_chunks.append(chunk)

    def evidence(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "readerThreadId": self._reader_id,
                "routerThreadId": self._router_id,
                "readerLog": list(self._reader_log),
                "routerLog": list(self._router_log),
                "writerLog": list(self._writer_log),
                "workerLog": list(self._worker_log),
                "lateResponses": list(self._late_responses),
                "workerErrors": [repr(error) for error in self._worker_errors],
                "peakWorkers": self._peak_workers,
                "pendingCount": len(self._pending),
                "workerCount": self._worker_total,
                "liveWorkerCount": len(self._workers),
                "workerSurvivors": list(self._close_survivors),
                "writerThreadId": self._writer_id,
            }


class _SyncCell:
    """Small synchronous cell for operation events (not a Future)."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._value: Any = _UNSET
        self._error: BaseException | None = None

    def finish(self, value: Any = _UNSET, error: BaseException | None = None) -> None:
        if (value is _UNSET) == (error is None):
            raise AssertionError("cell needs exactly one value or error")
        with self._condition:
            if self._value is not _UNSET or self._error is not None:
                return
            self._value = value
            self._error = error
            self._condition.notify_all()

    def result(self, timeout: float = DEADLOCK_TIMEOUT) -> Any:
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._value is _UNSET and self._error is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("operation result timed out")
                self._condition.wait(remaining)
            if self._error is not None:
                raise self._error
            return self._value


class _RecursiveDispatcher:
    """Sync callbacks that recursively call DAP and untouched GEF."""

    def __init__(self, transport: RoutedDapTransport, max_depth: int) -> None:
        self.transport = transport
        self.max_depth = max_depth
        self.lock = threading.RLock()
        self.operations: dict[int, _SyncCell] = {}
        self.early: dict[int, tuple[str, dict[str, Any]]] = {}
        self.callback_entries: list[dict[str, Any]] = []
        self.errors: list[BaseException] = []
        transport.on("rpcProbeCallback", self._callback)
        transport.on("rpcProbeDone", lambda body: self._outcome("done", body))
        transport.on("rpcProbeFailed", lambda body: self._outcome("failed", body))

    def start(
        self,
        depth: int,
        parent_operation_id: int | None = None,
    ) -> tuple[int, _SyncCell]:
        started = self.transport.request(
            "rpcProbeStart",
            {"depth": depth, "parentOperationId": parent_operation_id},
        )
        operation_id = int(started["operationId"])
        cell = _SyncCell()
        with self.lock:
            self.operations[operation_id] = cell
            early = self.early.pop(operation_id, None)
        if early is not None:
            self._finish_cell(cell, *early)
        return operation_id, cell

    @staticmethod
    def _finish_cell(
        cell: _SyncCell,
        outcome: str,
        body: dict[str, Any],
    ) -> None:
        if outcome == "done":
            cell.finish(value=body["result"])
        else:
            cell.finish(error=AssertionError(body["error"]))

    def _outcome(self, outcome: str, body: dict[str, Any]) -> None:
        self.transport._assert_user_worker("operation outcome")
        operation_id = int(body["operationId"])
        with self.lock:
            cell = self.operations.pop(operation_id, None)
            if cell is None:
                self.early[operation_id] = (outcome, body)
                return
        self._finish_cell(cell, outcome, body)

    def _callback(self, body: dict[str, Any]) -> None:
        self.transport._assert_user_worker("host callback")
        entry = {
            "operationId": int(body["operationId"]),
            "callbackId": int(body["callbackId"]),
            "depth": int(body["depth"]),
            "threadId": threading.get_ident(),
            "threadName": threading.current_thread().name,
        }
        with self.lock:
            self.callback_entries.append(entry)
        try:
            depth = entry["depth"]
            # This command belongs to untouched bata24 GEF.  Its invoke body
            # synchronously performs nested gdb.execute("show commands ...").
            gef_result = self.transport.request(
                "evaluate",
                {"expression": "history -n", "context": "repl"},
            )
            if not isinstance(gef_result["result"], str):
                raise TypeError("GEF history result was not text")

            if depth < self.max_depth:
                child_id, child = self.start(depth + 1, entry["operationId"])
                child_result = child.result()
                value = {
                    "fromDepth": depth,
                    "childOperationId": child_id,
                    "nested": child_result,
                }
            else:
                value = {"fromDepth": depth, "leaf": True}
            reply = self.transport.request(
                "rpcProbeReply",
                {
                    "operationId": entry["operationId"],
                    "callbackId": entry["callbackId"],
                    "value": value,
                },
            )
            if reply["status"] != "resume-queued":
                raise AssertionError(f"unexpected callback reply: {reply!r}")
        except Exception as error:  # noqa: BLE001 - propagate arbitrary callback failure
            with self.lock:
                self.errors.append(error)
                cells = list(self.operations.values())
            for cell in cells:
                cell.finish(error=error)


def _source(transport: RoutedDapTransport, path: Path) -> Any:
    # GDB's source command accepts backslash-escaped whitespace, not shell
    # quoting.  These fixtures have simple paths, but keep the helper honest.
    escaped = str(path.resolve()).replace("\\", "\\\\").replace(" ", "\\ ")
    return transport.request(
        "evaluate",
        {"expression": "source " + escaped, "context": "repl"},
        timeout=DEADLOCK_TIMEOUT,
    )


def _initialize(transport: RoutedDapTransport) -> None:
    transport.request(
        "initialize",
        {
            "clientID": "pwnc-routed-transport-probe",
            "adapterID": "gdb",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "pathFormat": "path",
        },
    )
    transport.wait_initialized()


def _assert_nested_result(result: dict[str, Any], max_depth: int) -> list[int]:
    operation_ids = []
    current = result
    for depth in range(max_depth + 1):
        if current["depth"] != depth:
            raise AssertionError(f"bad depth result {current!r}")
        operation_ids.append(int(current["operationId"]))
        callback = current["callbackResult"]
        if callback["fromDepth"] != depth:
            raise AssertionError(f"bad callback result {callback!r}")
        if depth == max_depth:
            if callback != {"fromDepth": depth, "leaf": True}:
                raise AssertionError(f"bad leaf result {callback!r}")
        else:
            if callback["childOperationId"] != callback["nested"]["operationId"]:
                raise AssertionError("nested operation ids disagree")
            current = callback["nested"]
    return operation_ids


def _wait_until(predicate: Callable[[], bool], timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise TimeoutError(f"timed out waiting for {label}")


def _future_inline_hazard() -> dict[str, Any]:
    """Show the stdlib Future callback behavior our slot avoids."""
    future: Future[int] = Future()
    setter_thread = threading.get_ident()
    callback_threads: list[int] = []
    future.add_done_callback(lambda _future: callback_threads.append(threading.get_ident()))
    future.set_result(1)
    if callback_threads != [setter_thread]:
        raise AssertionError("Future callback was not inline in the setter thread")
    late_threads: list[int] = []
    future.add_done_callback(lambda _future: late_threads.append(threading.get_ident()))
    if late_threads != [setter_thread]:
        raise AssertionError("completed Future callback was not inline in caller")
    return {
        "setterThreadId": setter_thread,
        "callbackThreadId": callback_threads[0],
        "lateRegistrationThreadId": late_threads[0],
    }


def run_probe(
    gdb_path: str = "gdb",
    gef_path: Path = DEFAULT_GEF,
    max_depth: int = DEFAULT_DEPTH,
    *,
    require_gef: bool = True,
) -> dict[str, Any]:
    if not shutil.which(gdb_path) and not Path(gdb_path).is_file():
        raise RuntimeError(f"GDB executable was not found: {gdb_path}")
    gef_path = Path(gef_path).resolve()
    if not gef_path.is_file():
        if require_gef:
            raise RuntimeError(f"bata24 GEF source is required: {gef_path}")
        raise RuntimeError("this live probe requires GEF; pass its source path")
    if max_depth < 1:
        raise ValueError("max_depth must be at least one")

    future_hazard = _future_inline_hazard()
    gef_digest_before = hashlib.sha256(gef_path.read_bytes()).hexdigest()
    if gef_digest_before != EXPECTED_BATA24_GEF_SHA256:
        raise RuntimeError(
            "bata24 GEF source digest mismatch: "
            f"expected {EXPECTED_BATA24_GEF_SHA256}, got {gef_digest_before}"
        )
    transport = RoutedDapTransport(gdb_path)
    dispatcher: _RecursiveDispatcher | None = None
    try:
        _initialize(transport)
        _source(transport, gef_path)
        experiments = Path(__file__).resolve().parent
        _source(transport, experiments / "gef_injection_ext.py")
        _source(transport, experiments / "rpc_probe_ext.py")

        # A completion callback registered before completion performs a real
        # nested synchronous request.  If it ran inline on the router, that
        # router would be unable to route the nested response and would hang.
        completion_done = threading.Event()
        completion_evidence: dict[str, Any] = {}
        version_slot = transport.send(
            "evaluate",
            {"expression": "show version", "context": "repl"},
        )

        def nested_completion(slot: _ResponseSlot) -> None:
            transport._assert_user_worker("pre-completion callback")
            completion_evidence["preThreadId"] = threading.get_ident()
            completion_evidence["version"] = slot.result()["result"].splitlines()[0]
            nested = transport.request(
                "evaluate",
                {"expression": "show pagination", "context": "repl"},
            )
            completion_evidence["nested"] = nested["result"].strip()
            completion_done.set()

        version_slot.add_done_callback(nested_completion)
        version_body = version_slot.result()
        if not completion_done.wait(DEADLOCK_TIMEOUT):
            raise TimeoutError("nested completion callback deadlocked")
        if "pagination" not in completion_evidence["nested"].lower():
            raise AssertionError("nested completion request returned wrong output")

        # Registration after completion must also be scheduled, rather than
        # running synchronously in this main/caller thread.
        late_callback_done = threading.Event()

        def late_completion(_slot: _ResponseSlot) -> None:
            transport._assert_user_worker("late completion callback")
            completion_evidence["lateThreadId"] = threading.get_ident()
            late_callback_done.set()

        version_slot.add_done_callback(late_completion)
        if not late_callback_done.wait(DEADLOCK_TIMEOUT):
            raise TimeoutError("late completion callback was not scheduled")

        dispatcher = _RecursiveDispatcher(transport, max_depth)
        outer_id, outer = dispatcher.start(0)
        result = outer.result()
        operation_ids = _assert_nested_result(result, max_depth)
        if operation_ids[0] != outer_id:
            raise AssertionError("outer operation id changed")
        transport.wait_workers()
        if dispatcher.errors:
            raise dispatcher.errors[0]

        rpc_snapshot = transport.request("rpcProbeSnapshot")
        gef_snapshot = transport.request("pwncGefInjectionSnapshot")
        gdb_thread_ids = {
            item["threadId"]
            for item in rpc_snapshot["trace"]
            if item["kind"]
            in {
                "operation-enter",
                "callback-emitted",
                "operation-resumed",
                "operation-done",
            }
        }
        if len(gdb_thread_ids) != 1:
            raise AssertionError(f"GDB work used unexpected threads: {gdb_thread_ids}")

        history_enters = [
            item
            for item in gef_snapshot["events"]
            if item["kind"] == "execute-enter" and item["command"] == "history -n"
        ]
        nested_gef = [
            item
            for item in gef_snapshot["events"]
            if item["kind"] == "execute-enter"
            and item["command"].startswith("show commands ")
        ]
        if len(history_enters) != max_depth + 1:
            raise AssertionError("GEF did not run once per synchronous callback")
        if len(nested_gef) < max_depth + 1:
            raise AssertionError("GEF nested gdb.execute calls were not observed")
        if {item["depth"] for item in history_enters} != {0}:
            raise AssertionError("GEF outer execute nesting was wrong")
        if {item["depth"] for item in nested_gef} != {1}:
            raise AssertionError("GEF inner execute nesting was wrong")
        if {item["threadId"] for item in history_enters + nested_gef} != gdb_thread_ids:
            raise AssertionError("GEF did not stay on the GDB main thread")

        callback_threads = {item["threadId"] for item in dispatcher.callback_entries}
        if len(callback_threads) != max_depth + 1:
            raise AssertionError("nested sync callbacks did not retain distinct stacks")
        if callback_threads & {
            transport.reader_thread_id,
            transport.router_thread_id,
            transport.writer_thread_id,
        }:
            raise AssertionError("callback ran on transport infrastructure")
        if threading.get_ident() in callback_threads:
            raise AssertionError("callback ran on public caller thread")
        if completion_evidence["preThreadId"] in {
            transport.reader_thread_id,
            transport.router_thread_id,
            transport.writer_thread_id,
        }:
            raise AssertionError("completion callback captured transport infrastructure")
        if completion_evidence["lateThreadId"] == threading.get_ident():
            raise AssertionError("late completion callback ran inline")

        # A deliberately slow *real GDB* evaluate times out.  The router owns
        # timeout completion, then classifies the eventual response as late.
        slow = transport.send(
            "evaluate",
            {
                "expression": "python import time; time.sleep(0.30)",
                "context": "repl",
            },
        )
        try:
            slow.result(timeout=0.03)
        except RoutedDapTimeout:
            pass
        else:
            raise AssertionError("slow GDB request did not time out")
        _wait_until(
            lambda: any(
                item["requestSeq"] == slow.seq and item["timedOut"]
                for item in transport.late_responses
            ),
            REQUEST_TIMEOUT,
            "late GDB response",
        )
        recovery = transport.request(
            "evaluate",
            {"expression": "show confirm", "context": "repl"},
        )
        if "confirm" not in recovery["result"].lower():
            raise AssertionError("transport did not recover after late response")

        transport.wait_workers()
        evidence = transport.evidence()
        if evidence["workerErrors"]:
            raise AssertionError(f"callback worker errors: {evidence['workerErrors']}")
        reader_kinds = {item["kind"] for item in evidence["readerLog"]}
        if not reader_kinds <= {
            "frame-enqueued",
            "eof-enqueued",
            "reader-error-enqueued",
        }:
            raise AssertionError(f"reader performed an invalid action: {reader_kinds}")
        if "frame-enqueued" not in reader_kinds:
            raise AssertionError("reader did not frame any DAP input")
        if {
            item["observedByRouterThreadId"] for item in evidence["readerLog"]
        } != {transport.router_thread_id}:
            raise AssertionError("reader evidence was not consumed by the router")
        if {item["threadId"] for item in evidence["readerLog"]} != {
            transport.reader_thread_id
        }:
            raise AssertionError("DAP frames came from multiple byte readers")
        router_completion_threads = {
            item["threadId"]
            for item in evidence["routerLog"]
            if item["kind"]
            in {"response-completed", "request-timed-out", "late-response"}
        }
        if router_completion_threads != {transport.router_thread_id}:
            raise AssertionError("completion routing escaped the router")
        if transport.reader_thread_id == transport.router_thread_id:
            raise AssertionError("reader and router are the same thread")
        infrastructure_ids = {
            transport.reader_thread_id,
            transport.router_thread_id,
            transport.writer_thread_id,
        }
        if None in infrastructure_ids or len(infrastructure_ids) != 3:
            raise AssertionError(
                f"reader/router/writer thread affinity was invalid: {infrastructure_ids}"
            )
        written = [
            item
            for item in evidence["writerLog"]
            if item["kind"] == "message-written"
        ]
        written_sequences = [item["seq"] for item in written]
        if written_sequences != list(range(1, len(written_sequences) + 1)):
            raise AssertionError(
                f"DAP wire sequence was not contiguous: {written_sequences}"
            )
        if {item["threadId"] for item in written} != {
            transport.writer_thread_id
        }:
            raise AssertionError("outbound writes escaped the dedicated writer")
        if evidence["pendingCount"]:
            raise AssertionError("transport leaked pending response slots")
        gdb_version = version_body["result"].splitlines()[0]
    finally:
        try:
            transport.close()
        finally:
            gef_digest_after = hashlib.sha256(gef_path.read_bytes()).hexdigest()
            if gef_digest_after != EXPECTED_BATA24_GEF_SHA256:
                raise AssertionError(
                    "bata24 GEF source bytes changed during the live probe"
                )

    close_evidence = run_close_probe(gdb_path)
    return {
        "callbackWorkers": max_depth + 1,
        "completionCallbackThread": completion_evidence["preThreadId"],
        "futureInlineHazard": future_hazard,
        "gdbMainThread": next(iter(gdb_thread_ids)),
        "gdbVersion": gdb_version,
        "gefNestedExecuteCalls": len(nested_gef),
        "gefSha256": gef_digest_before,
        "gefSourceUnmodified": True,
        "lateResponseCount": len(evidence["lateResponses"]),
        "nestedOperations": len(operation_ids),
        "peakDynamicWorkers": evidence["peakWorkers"],
        "readerActions": sorted(reader_kinds),
        "readerThread": evidence["readerThreadId"],
        "routerThread": evidence["routerThreadId"],
        "writerThread": evidence["writerThreadId"],
        "wireSequenceCount": len(written_sequences),
        "safeLateCompletionThread": completion_evidence["lateThreadId"],
        "transportWorkerCount": evidence["workerCount"],
        "close": close_evidence,
    }


def run_close_probe(gdb_path: str = "gdb") -> dict[str, Any]:
    """Close with a pending real-GDB request and prove router-owned failure."""
    transport = RoutedDapTransport(gdb_path)
    try:
        _initialize(transport)
        pending = transport.send(
            "evaluate",
            {
                "expression": "python import time; time.sleep(10)",
                "context": "repl",
            },
        )
        completion_started = threading.Event()
        completion_done = threading.Event()

        def pending_completion(slot: _ResponseSlot) -> None:
            completion_started.set()
            try:
                slot.result(timeout=CONTROL_TIMEOUT)
            except RoutedDapError as error:
                if "closed" not in str(error).lower():
                    raise AssertionError(
                        f"unexpected completion close error: {error}"
                    ) from error
            else:
                raise AssertionError("close completion callback received success")
            time.sleep(0.03)
            completion_done.set()

        pending.add_done_callback(pending_completion)
        time.sleep(0.03)
        started = time.monotonic()
        transport.close()
        elapsed = time.monotonic() - started
        if elapsed > CONTROL_TIMEOUT:
            raise AssertionError(
                f"transport exceeded its global close deadline: {elapsed:.3f}s"
            )
        if not completion_started.is_set() or not completion_done.is_set():
            raise AssertionError("close did not join the pending completion worker")
        try:
            pending.result(timeout=CONTROL_TIMEOUT)
        except RoutedDapError as error:
            if "closed" not in str(error).lower():
                raise AssertionError(f"unexpected close error: {error}") from error
        else:
            raise AssertionError("pending request survived transport close")
        evidence = transport.evidence()
        terminal = [
            item for item in evidence["routerLog"] if item["kind"] == "channel-terminal"
        ]
        if not terminal or terminal[-1]["threadId"] != transport.router_thread_id:
            raise AssertionError("router did not own close completion")
        if evidence["pendingCount"]:
            raise AssertionError("close leaked pending response slots")
        if transport.proc.poll() is None:
            raise AssertionError("GDB survived transport close")
        infrastructure = (
            transport._router,
            transport._writer,
            transport._reader,
            transport._stderr_reader,
        )
        if any(thread.is_alive() for thread in infrastructure):
            raise AssertionError("transport infrastructure survived close")
        if evidence["liveWorkerCount"] or evidence["workerSurvivors"]:
            raise AssertionError("completion workers survived bounded close")
        if evidence["workerErrors"]:
            raise AssertionError(f"close worker errors: {evidence['workerErrors']}")
        return {
            "cleanupSeconds": round(elapsed, 3),
            "completionWorkerReaped": True,
            "pendingFailedByRouter": True,
            "gdbExited": True,
            "infrastructureReaped": True,
        }
    finally:
        transport.close()


def test_partial_writes_preserve_one_complete_dap_frame() -> None:
    class _ShortStream:
        def __init__(self) -> None:
            self.data = bytearray()
            self.write_calls = 0
            self.flushed = False

        def write(self, data: memoryview) -> int:
            self.write_calls += 1
            count = min(3, len(data))
            self.data.extend(data[:count])
            return count

        def flush(self) -> None:
            self.flushed = True

    message = {"type": "request", "command": "evaluate", "arguments": {"x": 1}}
    encoded = RoutedDapTransport._encode_without_seq(message)
    framed = RoutedDapTransport._frame_encoded(7, encoded)
    stream = _ShortStream()
    RoutedDapTransport._write_all(stream, framed)
    assert bytes(stream.data) == framed
    assert stream.write_calls > 1
    assert stream.flushed is True
    header, body = bytes(stream.data).split(b"\r\n\r\n", 1)
    assert header == f"Content-Length: {len(body)}".encode("ascii")
    assert json.loads(body) == {"seq": 7, **message}


def test_modified_gef_is_rejected_by_exact_digest(tmp_path: Path) -> None:
    modified_gef = tmp_path / "gef.py"
    modified_gef.write_bytes(b"# not the required bata24 GEF source\n")
    try:
        run_probe(gef_path=modified_gef, max_depth=1)
    except RuntimeError as error:
        if "bata24 GEF source digest mismatch" not in str(error):
            raise AssertionError(f"unexpected GEF rejection: {error}") from error
    else:
        raise AssertionError("modified GEF source passed the exact digest guard")


def test_live_concurrent_send_sequence_matches_wire_order() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("live GDB is required")
        return
    transport = RoutedDapTransport("gdb")
    first_inside_put = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()
    second_done = threading.Event()
    slots: dict[str, _ResponseSlot] = {}
    errors: list[BaseException] = []
    original_put = transport._outbound.put
    blocked_once = False

    def blocking_put(item: _Outbound, *args: Any, **kwargs: Any) -> None:
        nonlocal blocked_once
        if item.kind == "message" and not blocked_once:
            blocked_once = True
            first_inside_put.set()
            if not release_first.wait(CONTROL_TIMEOUT):
                raise TimeoutError("concurrent-send test did not release first enqueue")
        original_put(item, *args, **kwargs)

    def send_first() -> None:
        try:
            slots["first"] = transport.send(
                "evaluate",
                {"expression": "show version", "context": "repl"},
            )
        except Exception as error:  # noqa: BLE001 - relay sender failure
            errors.append(error)

    def send_second() -> None:
        second_entered.set()
        try:
            slots["second"] = transport.send(
                "evaluate",
                {"expression": "show pagination", "context": "repl"},
            )
        except Exception as error:  # noqa: BLE001 - relay sender failure
            errors.append(error)
        finally:
            second_done.set()

    first_thread = threading.Thread(target=send_first, daemon=True)
    second_thread = threading.Thread(target=send_second, daemon=True)
    try:
        _initialize(transport)
        transport._outbound.put = blocking_put
        first_thread.start()
        if not first_inside_put.wait(CONTROL_TIMEOUT):
            raise TimeoutError("first sender did not enter its atomic enqueue")
        second_thread.start()
        if not second_entered.wait(CONTROL_TIMEOUT):
            raise TimeoutError("second sender did not start")
        if second_done.wait(0.05):
            raise AssertionError("second sender bypassed the outbound ordering lock")
        release_first.set()
        first_thread.join(CONTROL_TIMEOUT)
        second_thread.join(CONTROL_TIMEOUT)
        if first_thread.is_alive() or second_thread.is_alive():
            raise TimeoutError("concurrent senders did not finish")
        if errors:
            raise errors[0]
        slots["first"].result()
        slots["second"].result()
        first_seq = slots["first"].seq
        second_seq = slots["second"].seq
        if second_seq != first_seq + 1:
            raise AssertionError("concurrent request sequence allocation was not atomic")
        written = [
            item["seq"]
            for item in transport.writer_log
            if item["kind"] == "message-written"
            and item["seq"] in {first_seq, second_seq}
        ]
        if written != [first_seq, second_seq]:
            raise AssertionError(f"wire order diverged from DAP seq order: {written}")
    finally:
        release_first.set()
        transport._outbound.put = original_put
        if first_thread.ident is not None:
            first_thread.join(CONTROL_TIMEOUT)
        if second_thread.ident is not None:
            second_thread.join(CONTROL_TIMEOUT)
        transport.close()


def test_live_invalid_json_object_fails_pending_on_router() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("live GDB is required")
        return
    transport = RoutedDapTransport("gdb")
    try:
        _initialize(transport)
        pending = transport.send(
            "evaluate",
            {
                "expression": "python import time; time.sleep(10)",
                "context": "repl",
            },
        )
        transport._inbound.put(_Inbound("frame", b"[]"))
        if not transport._router_done.wait(CONTROL_TIMEOUT):
            raise TimeoutError("router did not reject non-object JSON")
        try:
            pending.result(timeout=CONTROL_TIMEOUT)
        except RoutedDapError as error:
            if "top-level JSON value is not an object" not in str(error):
                raise AssertionError(f"unexpected protocol error: {error}") from error
        else:
            raise AssertionError("invalid JSON object did not fail pending request")
        evidence = transport.evidence()
        if evidence["pendingCount"]:
            raise AssertionError("invalid JSON object leaked pending requests")
        if transport._accepting:
            raise AssertionError("router continued accepting after protocol failure")
    finally:
        transport.close()


def test_live_writer_failure_fails_pending_on_router() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("live GDB is required")
        return
    transport = RoutedDapTransport("gdb")
    original_write_all = transport._write_all

    def fail_write(_stream: Any, _data: bytes) -> None:
        raise OSError("injected writer failure")

    try:
        _initialize(transport)
        transport._write_all = fail_write
        pending = transport.send(
            "evaluate",
            {"expression": "show version", "context": "repl"},
        )
        if not transport._router_done.wait(CONTROL_TIMEOUT):
            raise TimeoutError("writer failure did not terminate the router")
        try:
            pending.result(timeout=CONTROL_TIMEOUT)
        except RoutedDapError as error:
            if "injected writer failure" not in str(error):
                raise AssertionError(f"unexpected writer error: {error}") from error
        else:
            raise AssertionError("writer failure did not fail pending request")
        evidence = transport.evidence()
        if evidence["pendingCount"]:
            raise AssertionError("writer failure leaked pending requests")
        if transport._accepting:
            raise AssertionError("transport accepted requests after writer failure")
        if not any(
            item["kind"] == "writer-error" for item in evidence["writerLog"]
        ):
            raise AssertionError("writer failure was not recorded")
    finally:
        transport._write_all = original_write_all
        transport.close()


def test_live_close_reports_externally_blocked_completion_worker() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("live GDB is required")
        return
    transport = RoutedDapTransport("gdb")
    callback_entered = threading.Event()
    release_callback = threading.Event()

    def blocked_completion(slot: _ResponseSlot) -> None:
        try:
            slot.result(timeout=CONTROL_TIMEOUT)
        except RoutedDapError:
            pass
        callback_entered.set()
        release_callback.wait(DEADLOCK_TIMEOUT)

    try:
        _initialize(transport)
        pending = transport.send(
            "evaluate",
            {
                "expression": "python import time; time.sleep(10)",
                "context": "repl",
            },
        )
        pending.add_done_callback(blocked_completion)
        transport.close(timeout=0.40)
        if not callback_entered.is_set():
            raise AssertionError("pending completion callback did not start on close")
        survivors = transport.evidence()["workerSurvivors"]
        if not survivors or not any("completion" in name for name in survivors):
            raise AssertionError(
                f"blocked completion worker was not reported: {survivors}"
            )
        if transport.proc.poll() is None:
            raise AssertionError("GDB survived close with a callback survivor")
    finally:
        release_callback.set()
        transport.wait_workers(CONTROL_TIMEOUT, raise_on_timeout=False)
        transport.close()


def test_live_worker_start_failure_does_not_capture_router() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("live GDB is required")
        return
    transport = RoutedDapTransport("gdb")
    callback_ran = threading.Event()
    original_start = transport._start_user_worker

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("injected worker start failure")

    try:
        _initialize(transport)
        slot = transport.send(
            "evaluate",
            {
                "expression": "python import time; time.sleep(0.10)",
                "context": "repl",
            },
        )
        transport._start_user_worker = fail_start
        slot.add_done_callback(lambda _slot: callback_ran.set())
        body = slot.result()
        transport._start_user_worker = original_start
        if "result" not in body:
            raise AssertionError("evaluate response was malformed")
        if callback_ran.is_set():
            raise AssertionError("callback ran despite injected start failure")
        if not any(
            "injected worker start failure" in repr(error)
            for error in transport.worker_errors
        ):
            raise AssertionError("worker start failure was not recorded")
        recovery = transport.request(
            "evaluate",
            {"expression": "show confirm", "context": "repl"},
        )
        if "confirm" not in recovery["result"].lower():
            raise AssertionError("router did not recover from worker start failure")
        if transport._router_done.is_set():
            raise AssertionError("worker start failure terminated the router")
        transport.wait_workers()
        if transport.evidence()["liveWorkerCount"]:
            raise AssertionError("failed worker start leaked worker accounting")
    finally:
        transport._start_user_worker = original_start
        transport.close()


def test_live_reader_isolated_routed_transport() -> None:
    if not shutil.which("gdb") or not DEFAULT_GEF.is_file():
        if pytest is not None:
            pytest.skip("live GDB and bata24 GEF are required")
        return
    evidence = run_probe(max_depth=DEFAULT_DEPTH)
    assert evidence["nestedOperations"] == DEFAULT_DEPTH + 1
    assert evidence["readerThread"] != evidence["routerThread"]
    assert evidence["close"]["pendingFailedByRouter"] is True


def test_live_gdb_matrix_from_environment() -> None:
    raw_matrix = os.environ.get("PWNC_ROUTED_GDB_MATRIX_JSON")
    if not raw_matrix:
        if pytest is not None:
            pytest.skip("PWNC_ROUTED_GDB_MATRIX_JSON is not configured")
        return
    matrix = json.loads(raw_matrix)
    if not isinstance(matrix, dict) or not matrix:
        raise ValueError("PWNC_ROUTED_GDB_MATRIX_JSON must be a non-empty object")
    for expected_version, gdb_path in matrix.items():
        evidence = run_probe(str(gdb_path), max_depth=2)
        if str(expected_version) not in evidence["gdbVersion"]:
            raise AssertionError(
                f"expected GDB {expected_version}, got {evidence['gdbVersion']}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    parser.add_argument("--require-gef", action="store_true")
    arguments = parser.parse_args()
    evidence = run_probe(
        arguments.gdb,
        arguments.gef,
        arguments.depth,
        require_gef=arguments.require_gef,
    )
    print("PASS reader-isolated synchronous DAP transport probe")
    for key in sorted(evidence):
        print(f"{key}: {evidence[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
