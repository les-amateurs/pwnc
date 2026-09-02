"""A persistent terminal viewer which can switch between owned GDB consoles.

The standalone :mod:`._console_bridge` connects to this router as its viewer.
The router presents the bridge protocol downstream and acts as a bridge client
to one owned :class:`~pwnc.gdb.dap.console.Console` endpoint upstream.  Changing
the upstream therefore never replaces the terminal process, toggles terminal
mode, or exposes per-GDB broker credentials to the terminal child.

All production waiting is event driven: sockets are handled by one selector,
host commands use a wake pipe, and public synchronization uses Events and the
owned broker's Condition.  There is no periodic polling loop.
"""

from __future__ import annotations

import errno
import json
import math
import operator
import os
import queue
import secrets
import selectors
import socket
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from itertools import count
from typing import Callable

from ._process import wait_process
from .discovery import _os_error_reason
from .console import (
    _DEFAULT_BACKLOG_BYTES,
    _FRAME_CLOSE,
    _FRAME_DETACH,
    _FRAME_EPOCH_INPUT,
    _FRAME_EPOCH_RESIZE,
    _FRAME_HELLO,
    _FRAME_HELLO_ACK,
    _FRAME_INPUT,
    _FRAME_OUTPUT,
    _FRAME_RESIZE,
    _FRAME_SWITCH_PAUSE,
    _FRAME_SWITCH_PAUSED,
    _FRAME_SWITCH_RESUME,
    _FRAME_SWITCH_RESUMED,
    _MAX_FRAME_BYTES,
    _MAX_LIVE_QUEUE_BYTES,
    _PROTOCOL_VERSION,
    _ansi_safe_suffix,
    ArgvTerminalLauncher,
    ConsoleMode,
    ViewerConfig,
    ViewerMode,
    _extract_frames,
    _pack_frame,
    _set_winsize,
    _spawn_terminal_bridge,
    _terminal_argv,
)

_HELLO_TIMEOUT = 5.0
_EPOCH = struct.Struct("!Q")
_SWITCH = struct.Struct("!QQ")
_ROLLBACK_TIMEOUT = 1.0
_RELEASE_TIMEOUT = 1.0
_CLOSE = object()
_LOSS_STOP = object()
_ENDPOINT_LOSS = object()
_CONNECTION_CHANGE = object()


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("timed out switching the GDB console viewer")
    return remaining


def _wait_deadline(timeout) -> float | None:
    if timeout is None:
        return None
    if isinstance(timeout, bool):
        raise TypeError("timeout must be a nonnegative real number or None")
    try:
        timeout = float(timeout)
    except (TypeError, ValueError) as error:
        raise TypeError("timeout must be a nonnegative real number or None") from error
    if timeout < 0:
        raise ValueError("timeout cannot be negative")
    if not math.isfinite(timeout):
        raise ValueError("timeout must be finite; use None for no deadline")
    return time.monotonic() + timeout


def _wait_remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("timed out waiting for the console viewer")
    return remaining


@dataclass(slots=True)
class _Switch:
    endpoint: object
    deadline: float
    hello_sent: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    cancelled: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None
    result: int | None = None
    lane: "_Lane | None" = None
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    authenticated: threading.Event = field(default_factory=threading.Event)
    epoch: int | None = None
    old_epoch: int | None = None
    switch_id: int | None = None
    phase: str = "connecting"
    rollback_deadline: float | None = None
    old_endpoint: object | None = None


@dataclass(slots=True)
class _Lane:
    endpoint: object
    sock: socket.socket
    command: _Switch | None
    connecting: bool
    incoming: bytearray = field(default_factory=bytearray)
    outgoing: bytearray = field(default_factory=bytearray)
    staged_output: bytearray = field(default_factory=bytearray)
    hello_complete: bool = False
    authenticated: bool = False


class ViewerRouter:
    """Keep one terminal viewer alive while selecting owned console endpoints.

    With a :class:`ViewerConfig`, ``start()`` launches the configured terminal
    bridge and waits for it to connect.  With ``viewer=None``, ``start()`` only
    starts the listener and returns immediately; an independently launched
    bridge may connect, disconnect, and reconnect through the same socket.
    ``switch(endpoint)`` transactionally connects an owned console endpoint and
    returns only after that endpoint has the viewer geometry synchronously
    applied.  A failed candidate leaves the previous endpoint selected.

    Endpoint loss is deliberately not inferred from terminal bytes (including
    ``^C``).  It is observed from the upstream broker's CLOSE/EOF.  Pool code
    should additionally use the GDB transport terminal listener as the primary
    process-death signal and may use :meth:`add_loss_listener` as a fallback.
    """

    def __init__(self, viewer: ViewerConfig | None = None, *, socket_path=None, listener=None):
        if viewer is not None and not isinstance(viewer, ViewerConfig):
            raise TypeError("viewer must be a ViewerConfig or None")
        if socket_path is not None:
            try:
                socket_path = os.fspath(socket_path)
            except TypeError as error:
                raise TypeError("socket_path must be a filesystem path or None") from error
            if not socket_path:
                raise ValueError("socket_path cannot be empty")
        if listener is not None:
            if not isinstance(listener, socket.socket):
                raise TypeError("listener must be a socket.socket or None")
            if listener.family != socket.AF_UNIX or not (listener.type & socket.SOCK_STREAM):
                raise ValueError("listener must be an AF_UNIX stream socket")
            try:
                if not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                    raise ValueError("listener socket must already be listening")
                bound_path = listener.getsockname()
            except OSError as error:
                raise RuntimeError(
                    f"could not inspect the supplied viewer listener: "
                    f"{_os_error_reason(error)}"
                ) from error
            if not bound_path:
                raise ValueError("listener socket must have a filesystem path")
            if socket_path is None:
                socket_path = bound_path
            elif os.fsencode(socket_path) != os.fsencode(bound_path):
                raise ValueError("socket_path does not match the bound listener")
        self.viewer = viewer
        self.proc = None
        self._requested_socket_path = socket_path
        # A discovery lease passes a duplicate here.  The router owns and closes
        # that descriptor, but the lease remains the sole owner of its pathname.
        self._listener = listener

        self._condition = threading.Condition()
        self._switch_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._listener_lock = threading.Lock()
        self._listeners: dict[int, Callable[[object, str, int], None]] = {}
        self._connection_listeners: dict[int, Callable[[bool, str | None], None]] = {}
        self._listener_numbers = count(1)
        self._losses: queue.SimpleQueue = queue.SimpleQueue()
        self._loss_thread = None

        self._commands: queue.SimpleQueue = queue.SimpleQueue()
        self._wake_r = -1
        self._wake_w = -1
        self._thread = None
        self._router_done = threading.Event()
        self._closed = False
        self._started = False
        self._error: BaseException | None = None

        self._tmpdir = None
        self.socket_path = socket_path
        self._owns_socket_path = socket_path is None

        self._downstream = None
        self._downstream_authenticated = False
        self._downstream_reconnect = False
        self._downstream_close_reason = None
        self._downstream_deadline = None
        self._downstream_in = bytearray()
        self._downstream_out = bytearray()
        self._viewer_backlog = bytearray()
        self._viewer_backlog_truncated = False
        self._geometry = (24, 80)
        self._geometry_generation = 0
        # Managed bridge input is epoch tagged.  Switching first pauses terminal
        # reads and waits for a barrier ACK ordered after every old input frame;
        # a matching RESUME then changes the epoch.  Timeouts before the barrier
        # resume the old epoch, so cancellation cannot strand or retarget input.
        self._active_epoch = 0
        self._next_epoch = 1
        self._next_switch_id = 1
        self._pending_switch: _Switch | None = None

        self._active: _Lane | None = None
        self._candidate: _Lane | None = None
        self._current = None
        self._generation = 0

        self._terminal_state = None
        self._terminal_monitor = None

    @property
    def current(self):
        with self._condition:
            return self._current

    @property
    def generation(self) -> int:
        with self._condition:
            return self._generation

    @property
    def viewer_process(self):
        return self.proc

    @property
    def viewer_connected(self) -> bool:
        with self._condition:
            return self._downstream_authenticated

    @property
    def viewer_reconnect(self) -> bool:
        """Whether the connected viewer opted into pool failover."""
        with self._condition:
            return self._downstream_authenticated and self._downstream_reconnect

    def wait_viewer_connected(self, timeout=None) -> bool:
        """Wait eventfully until a protocol-compatible viewer is connected."""
        deadline = _wait_deadline(timeout)
        with self._condition:
            while not self._downstream_authenticated:
                if self._closed:
                    raise RuntimeError("viewer router closed while waiting for a viewer")
                if self._error is not None:
                    raise RuntimeError("viewer router failed while waiting for a viewer") from self._error
                if not self._started:
                    raise RuntimeError("viewer router is not running")
                self._condition.wait(_wait_remaining(deadline))
            return True

    def wait_viewer_disconnected(self, timeout=None) -> bool:
        """Wait eventfully until the current viewer has disconnected."""
        deadline = _wait_deadline(timeout)
        with self._condition:
            while self._downstream_authenticated:
                self._condition.wait(_wait_remaining(deadline))
            return True

    def close_viewer(self, reason="selected GDB exited") -> bool:
        """Close only the connected bridge while retaining the router listener."""
        with self._condition:
            if not self._started or self._closed or not self._downstream_authenticated:
                return False
        self._commands.put(("close-viewer", str(reason)))
        self._wake()
        return True

    @property
    def viewer_alive(self) -> bool:
        if self.viewer_connected:
            return True
        if self.viewer is None:
            return False
        proc = self.proc
        return proc is not None and proc.poll() is None

    @property
    def alive(self) -> bool:
        with self._condition:
            return self._started and not self._closed and self._error is None

    def add_loss_listener(self, callback):
        """Register ``callback(endpoint, reason, generation)``.

        Callbacks run on a dedicated notification lane, never the selector
        thread, so a pool callback may synchronously select a replacement.
        The returned function removes a listener which has not been captured
        for delivery yet.
        """
        if not callable(callback):
            raise TypeError("loss listener must be callable")
        with self._listener_lock:
            number = next(self._listener_numbers)
            self._listeners[number] = callback

        def unsubscribe():
            with self._listener_lock:
                return self._listeners.pop(number, None) is not None

        return unsubscribe

    def add_connection_listener(self, callback):
        """Register ``callback(connected, reason)`` for viewer transitions.

        ``reason`` is ``None`` for a successful connection and a descriptive
        string for a disconnect.  Only a validated protocol connection
        produces a disconnect event; malformed pre-handshake peers are silent.
        Callbacks share the endpoint-loss notification lane and therefore never
        run on the selector thread.  The returned function removes a callback
        which has not already been captured for delivery.
        """
        if not callable(callback):
            raise TypeError("connection listener must be callable")
        with self._listener_lock:
            number = next(self._listener_numbers)
            self._connection_listeners[number] = callback

        def unsubscribe():
            with self._listener_lock:
                return self._connection_listeners.pop(number, None) is not None

        return unsubscribe

    def _bridge_argv(self) -> list[str]:
        bridge = os.path.join(os.path.dirname(__file__), "_console_bridge.py")
        argv = [
            sys.executable,
            bridge,
            self.socket_path,
        ]
        if self.viewer.keep_open:
            argv.append("--keep-open")
        if self.viewer.reconnect:
            argv.append("--reconnect")
        return argv

    def _spawn_viewer(self):
        if self.viewer is None:
            raise RuntimeError("a detached viewer router does not spawn a bridge")
        argv = self._bridge_argv()
        snapshot = None
        if self.viewer.mode in (ViewerMode.CURRENT, ViewerMode.TARGET):
            proc, snapshot = _spawn_terminal_bridge(argv, self.viewer)
        else:
            launcher = self.viewer.launcher
            if launcher is None:
                launcher = ArgvTerminalLauncher(_terminal_argv(None))
            elif isinstance(launcher, (str, list, tuple)):
                launcher = ArgvTerminalLauncher(launcher)
            if hasattr(launcher, "spawn"):
                proc = launcher.spawn(argv)
            elif callable(launcher):
                proc = launcher(argv)
            else:
                raise TypeError("terminal launcher must be argv, callable, or have spawn()")
        if proc is None or not hasattr(proc, "poll") or not hasattr(proc, "wait"):
            if snapshot is not None:
                snapshot.restore()
            raise TypeError("terminal launcher did not return a Popen-like process")
        self.proc = proc
        if snapshot is not None:
            self._terminal_state = (proc, snapshot)
        monitor = threading.Thread(
            target=self._monitor_viewer,
            args=(proc,),
            name="pwnc-viewer-terminal-restore",
            daemon=True,
        )
        self._terminal_monitor = monitor
        try:
            monitor.start()
        except BaseException:
            # Bounded explicit shutdown still owns the restoration snapshot.
            self._terminal_monitor = None

    def _monitor_viewer(self, proc) -> None:
        try:
            proc.wait()
        except Exception:
            pass
        finally:
            self._restore_terminal(proc)
            with self._condition:
                self._condition.notify_all()

    def _restore_terminal(self, proc=None) -> None:
        with self._condition:
            state = self._terminal_state
            if state is None or (proc is not None and state[0] is not proc):
                return
            self._terminal_state = None
            _proc, snapshot = state
            # A monitor and synchronous close may both observe process exit.
            # Keep claiming the snapshot and restoring it atomic to callers so
            # close cannot return while the terminal is still raw/nonblocking.
            snapshot.restore()

    def start(self, timeout=10) -> "ViewerRouter":
        timeout = float(timeout)
        if timeout < 0:
            raise ValueError("timeout cannot be negative")
        deadline = time.monotonic() + timeout
        stage = "initialize the viewer router"
        try:
            with self._condition:
                if self._closed:
                    raise RuntimeError("viewer router is closed")
                if self._started:
                    return self

                stage = "create the viewer-router wake channel"
                self._wake_r, self._wake_w = os.pipe()
                os.set_blocking(self._wake_r, False)
                os.set_blocking(self._wake_w, False)
                listener = self._listener
                if listener is None:
                    if self._requested_socket_path is None:
                        stage = "create the private viewer runtime directory"
                        self._tmpdir = tempfile.mkdtemp(prefix="pwnc-viewer-")
                        os.chmod(self._tmpdir, 0o700)
                        self.socket_path = os.path.join(self._tmpdir, "bridge.sock")
                    else:
                        self.socket_path = self._requested_socket_path
                    stage = "create the viewer Unix listener"
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    stage = f"bind the viewer Unix listener at {self.socket_path}"
                    listener.bind(self.socket_path)
                    stage = f"restrict viewer socket permissions at {self.socket_path}"
                    os.chmod(self.socket_path, 0o600)
                    stage = f"listen on the viewer Unix socket at {self.socket_path}"
                    listener.listen(4)
                stage = "configure the viewer Unix listener"
                listener.setblocking(False)
                self._listener = listener
                self._started = True
                self._thread = threading.Thread(
                    target=self._run,
                    name="pwnc-viewer-router",
                    daemon=True,
                )
                self._loss_thread = threading.Thread(
                    target=self._loss_loop,
                    name="pwnc-viewer-losses",
                    daemon=True,
                )
                self._thread.start()
                self._loss_thread.start()
                if self.viewer is None:
                    return self
                stage = "start the configured terminal viewer"
                self._spawn_viewer()

                while not self._downstream_authenticated:
                    if self._error is not None:
                        raise RuntimeError("viewer router failed") from self._error
                    if self.proc is not None and self.proc.poll() is not None:
                        raise RuntimeError("console viewer exited before connecting")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("console viewer did not connect within %.1fs" % timeout)
                    self._condition.wait(remaining)
        except BaseException as error:
            # Startup can fail after the router and callback threads exist.
            # Route every partial construction through the normal bounded
            # shutdown path instead of closing descriptors under a selector.
            self.close()
            if isinstance(error, OSError):
                raise RuntimeError(
                    f"could not {stage}: {_os_error_reason(error)}"
                ) from error
            raise
        return self

    def switch(self, endpoint, timeout=10):
        """Atomically display *endpoint* without replacing the viewer process."""
        timeout = float(timeout)
        if timeout < 0:
            raise ValueError("timeout cannot be negative")
        if not math.isfinite(timeout):
            raise ValueError("timeout must be finite")
        if getattr(endpoint, "mode", None) is not ConsoleMode.OWNED:
            raise ValueError("viewer routing requires an owned console endpoint")
        broker = getattr(endpoint, "_broker", None)
        if broker is None or not broker.alive:
            raise RuntimeError("console endpoint is closed")

        with self._switch_lock:
            deadline = time.monotonic() + timeout
            with self._condition:
                if not self._started or self._closed:
                    raise RuntimeError("viewer router is not running")
                if self._current is endpoint and self._active is not None:
                    return endpoint
            if broker.connected:
                # Closing an old upstream socket and the broker observing its
                # EOF happen on different selector threads.  Treat that small
                # release interval as part of this operation so an immediate
                # A -> B -> A switch cannot spuriously report that A is still
                # leased.  A genuinely independent viewer remains connected
                # and produces the same error once the caller's deadline wins.
                try:
                    broker.wait_disconnected(_remaining(deadline))
                except TimeoutError:
                    raise RuntimeError("console endpoint already has a viewer") from None

            command = _Switch(endpoint, deadline)
            self._commands.put(("prepare", command))
            self._wake()
            try:
                if not command.hello_sent.wait(_remaining(deadline)):
                    raise TimeoutError("timed out connecting the console endpoint")
                if command.error is not None:
                    raise command.error
                if not command.authenticated.wait(_remaining(deadline)):
                    raise TimeoutError("timed out authenticating the console endpoint")
                if command.error is not None:
                    raise command.error

                # Keep applying until no resize raced the synchronous DAP
                # request.  The remaining operation deadline covers both lock
                # acquisition and the request itself.
                while True:
                    geometry_generation, rows, cols = self._geometry_snapshot()
                    _set_winsize(broker.master_fd, rows, cols)
                    with broker._condition:
                        broker._current_size = (rows, cols)
                    endpoint._resize_worker.apply_sync(
                        rows,
                        cols,
                        timeout=_remaining(deadline),
                    )
                    with self._condition:
                        if geometry_generation == self._geometry_generation:
                            break

                self._commands.put(("commit", command))
                self._wake()
                try:
                    completed = command.done.wait(_remaining(deadline))
                except TimeoutError:
                    completed = False
                if not completed:
                    # The selector owns the commit/cancel decision.  Request a
                    # timeout transition and wait for its bounded rollback so a
                    # caller never observes a half-switched input epoch.
                    self._commands.put(("timeout", command))
                    self._wake()
                    command.done.wait(_ROLLBACK_TIMEOUT + 0.5)
                if not command.done.is_set():
                    raise TimeoutError("timed out restoring the console switch")
                if command.error is not None:
                    raise command.error
                old_endpoint = command.old_endpoint
                if old_endpoint is not None:
                    old_broker = getattr(old_endpoint, "_broker", None)
                    if old_broker is not None:
                        try:
                            old_broker.wait_disconnected(_RELEASE_TIMEOUT)
                        except TimeoutError:
                            # The new endpoint is already committed.  A delayed
                            # broker EOF must not turn success into a reported
                            # failure; its connection nonce still prevents a
                            # premature switch back from stealing the lease.
                            pass
                return endpoint
            except BaseException:
                command.cancelled.set()
                self._commands.put(("cancel", command))
                self._wake()
                # Do not release the per-router switch lane while a candidate
                # from this operation is still registered.  This bounded wait
                # makes a timed-out prepare/authentication immediately
                # reusable instead of making the next call race selector-side
                # cleanup.  Pending epoch transactions already completed (or
                # dropped the ambiguous viewer) in the main path above.
                command.done.wait(_ROLLBACK_TIMEOUT + 0.5)
                raise

    def _geometry_snapshot(self) -> tuple[int, int, int]:
        with self._condition:
            return self._geometry_generation, *self._geometry

    def _wake(self) -> None:
        try:
            os.write(self._wake_w, b"x")
        except (BlockingIOError, OSError):
            pass

    def _loss_loop(self) -> None:
        while True:
            item = self._losses.get()
            if item is _LOSS_STOP:
                return
            kind, arguments = item
            with self._listener_lock:
                if kind is _ENDPOINT_LOSS:
                    listeners = list(self._listeners.values())
                else:
                    listeners = list(self._connection_listeners.values())
            for listener in listeners:
                try:
                    listener(*arguments)
                except BaseException:
                    # Lifecycle observers are isolated from routing.
                    pass

    def _notify_loss(self, endpoint, reason: str, generation: int) -> None:
        self._losses.put(
            (
                _ENDPOINT_LOSS,
                (endpoint, str(reason), int(generation)),
            )
        )

    def _notify_connection(self, connected: bool, reason: str | None) -> None:
        self._losses.put(
            (
                _CONNECTION_CHANGE,
                (bool(connected), None if connected else str(reason or "viewer disconnected")),
            )
        )

    def _selector_timeout(self) -> float | None:
        deadlines = []
        if (
            self._downstream is not None
            and not self._downstream_authenticated
            and self._downstream_deadline is not None
        ):
            deadlines.append(self._downstream_deadline)
        command = self._pending_switch
        if command is None and self._candidate is not None:
            command = self._candidate.command
        if command is not None and not command.done.is_set():
            if command.phase == "resuming-old" and command.rollback_deadline is not None:
                deadlines.append(command.rollback_deadline)
            else:
                deadlines.append(command.deadline)
        if not deadlines:
            return None
        return max(0.0, min(deadlines) - time.monotonic())

    def _set_events(self, selector, fileobj, events, data) -> None:
        try:
            selector.modify(fileobj, events, data)
        except KeyError:
            selector.register(fileobj, events, data)

    def _downstream_events(self, selector) -> None:
        if self._downstream is None:
            return
        events = selectors.EVENT_READ
        if self._downstream_out:
            events |= selectors.EVENT_WRITE
        try:
            self._set_events(selector, self._downstream, events, "downstream")
        except (OSError, ValueError):
            self._drop_downstream(selector)

    def _lane_events(self, selector, lane: _Lane) -> None:
        events = selectors.EVENT_READ
        if lane.connecting or lane.outgoing:
            events |= selectors.EVENT_WRITE
        try:
            self._set_events(selector, lane.sock, events, lane)
        except (OSError, ValueError):
            self._lose_lane(selector, lane, "endpoint socket closed")

    def _accept_downstream(self, selector) -> None:
        try:
            conn, _address = self._listener.accept()
        except BlockingIOError:
            return
        conn.setblocking(False)
        if self._downstream is not None:
            conn.close()
            return
        self._downstream = conn
        self._downstream_authenticated = False
        self._downstream_reconnect = False
        self._downstream_close_reason = None
        self._downstream_deadline = time.monotonic() + _HELLO_TIMEOUT
        self._downstream_in.clear()
        self._downstream_out.clear()
        selector.register(conn, selectors.EVENT_READ, "downstream")

    def _handle_downstream_hello(self, payload, selector) -> bool:
        try:
            hello = json.loads(payload.decode("utf-8"))
            if not isinstance(hello, dict):
                raise ValueError
            version = hello.get("version")
            if isinstance(version, bool) or version != _PROTOCOL_VERSION:
                raise ValueError
            reconnect = hello.get("reconnect", False)
            if not isinstance(reconnect, bool):
                raise ValueError
            has_rows, has_cols = "rows" in hello, "cols" in hello
            if has_rows != has_cols:
                raise ValueError
            if has_rows:
                rows, cols = hello["rows"], hello["cols"]
                if isinstance(rows, bool) or isinstance(cols, bool):
                    raise ValueError
                rows, cols = operator.index(rows), operator.index(cols)
                if not (0 < rows <= 0xFFFF and 0 < cols <= 0xFFFF):
                    raise ValueError
                with self._condition:
                    self._geometry = (rows, cols)
                    self._geometry_generation += 1
        except (
            UnicodeDecodeError,
            ValueError,
            TypeError,
            RecursionError,
            OverflowError,
        ):
            self._drop_downstream(selector)
            return False
        with self._condition:
            self._downstream_authenticated = True
            self._downstream_reconnect = reconnect
            self._downstream_deadline = None
            self._condition.notify_all()
        # A fresh bridge starts with terminal input disabled.  Publish the
        # current epoch before replaying output or accepting input so a viewer
        # can reconnect to an already-selected endpoint without another switch.
        self._queue_downstream_frame(
            _FRAME_HELLO_ACK,
            _EPOCH.pack(self._active_epoch),
            selector,
        )
        self._notify_connection(True, None)
        if self._viewer_backlog or self._viewer_backlog_truncated:
            backlog = bytes(self._viewer_backlog)
            if self._viewer_backlog_truncated:
                backlog = b"\x1b[0m" + backlog
            self._queue_downstream_output(backlog, selector)
            self._viewer_backlog.clear()
            self._viewer_backlog_truncated = False
        self._forward_resize_to_lanes(selector)
        return True

    def _handle_downstream_frame(self, frame_type, payload, selector) -> bool:
        if not self._downstream_authenticated:
            return frame_type == _FRAME_HELLO and self._handle_downstream_hello(payload, selector)
        if frame_type == _FRAME_INPUT:
            # Untagged input belongs to the bridge's pre-router epoch and is
            # never forwarded to a selected GDB.
            return True
        if frame_type == _FRAME_EPOCH_INPUT:
            if len(payload) < _EPOCH.size:
                self._drop_downstream(selector, "invalid viewer input frame")
                return False
            epoch = _EPOCH.unpack(payload[: _EPOCH.size])[0]
            lane = self._active
            if lane is not None and epoch == self._active_epoch:
                self._queue_lane(
                    lane,
                    _FRAME_INPUT,
                    payload[_EPOCH.size :],
                    selector,
                )
            return True
        if frame_type == _FRAME_RESIZE:
            try:
                size = json.loads(payload.decode("ascii"))
                rows, cols = int(size["rows"]), int(size["cols"])
                if not (0 < rows <= 0xFFFF and 0 < cols <= 0xFFFF):
                    raise ValueError
            except (
                KeyError,
                UnicodeDecodeError,
                ValueError,
                TypeError,
                RecursionError,
                OverflowError,
            ):
                self._drop_downstream(selector, "invalid viewer resize frame")
                return False
            with self._condition:
                self._geometry = (rows, cols)
                self._geometry_generation += 1
            self._forward_resize_to_lanes(selector, payload=payload)
            return True
        if frame_type == _FRAME_EPOCH_RESIZE:
            if len(payload) <= _EPOCH.size:
                self._drop_downstream(selector)
                return False
            epoch = _EPOCH.unpack(payload[: _EPOCH.size])[0]
            if epoch != self._active_epoch:
                return True
            resize_payload = payload[_EPOCH.size :]
            try:
                size = json.loads(resize_payload.decode("ascii"))
                rows, cols = int(size["rows"]), int(size["cols"])
                if not (0 < rows <= 0xFFFF and 0 < cols <= 0xFFFF):
                    raise ValueError
            except (
                KeyError,
                UnicodeDecodeError,
                ValueError,
                TypeError,
                RecursionError,
                OverflowError,
            ):
                self._drop_downstream(selector)
                return False
            with self._condition:
                self._geometry = (rows, cols)
                self._geometry_generation += 1
            self._forward_resize_to_lanes(selector, payload=resize_payload)
            return True
        if frame_type in (_FRAME_SWITCH_PAUSED, _FRAME_SWITCH_RESUMED):
            if len(payload) != _SWITCH.size:
                self._drop_downstream(selector)
                return False
            switch_id, epoch = _SWITCH.unpack(payload)
            command = self._pending_switch
            # A late ACK from a transaction which timed out and completed its
            # rollback is harmless.  It must never tear down the stable viewer.
            if command is None or command.switch_id != switch_id:
                return True
            if frame_type == _FRAME_SWITCH_PAUSED:
                if command.epoch == epoch:
                    self._switch_paused(selector, command)
            else:
                self._switch_resumed(selector, command, epoch)
            return True
        if frame_type in (_FRAME_DETACH, _FRAME_CLOSE):
            reason = "viewer detached" if frame_type == _FRAME_DETACH else "viewer closed"
            self._drop_downstream(selector, reason)
            return False
        self._drop_downstream(selector)
        return False

    def _read_downstream(self, selector) -> None:
        try:
            data = self._downstream.recv(65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            self._drop_downstream(selector, "viewer socket EOF")
            return
        self._downstream_in.extend(data)
        try:
            frames = list(_extract_frames(self._downstream_in))
        except ValueError:
            self._drop_downstream(selector)
            return
        for frame_type, payload in frames:
            if self._downstream is None:
                return
            if not self._handle_downstream_frame(frame_type, payload, selector):
                return

    def _write_downstream(self, selector) -> None:
        if not self._downstream_out:
            self._downstream_events(selector)
            return
        try:
            count = self._downstream.send(self._downstream_out)
        except BlockingIOError:
            return
        except OSError:
            self._drop_downstream(selector, "viewer socket write failed")
            return
        if count <= 0:
            self._drop_downstream(selector, "viewer socket write returned EOF")
            return
        del self._downstream_out[:count]
        if not self._downstream_out and self._downstream_close_reason is not None:
            reason = self._downstream_close_reason
            self._drop_downstream(selector, reason)
            return
        self._downstream_events(selector)

    def _close_downstream(self, selector, reason: str) -> None:
        """Send a normal close frame without tearing down the durable listener."""
        if self._downstream is None:
            return
        self._downstream_close_reason = str(reason)
        # Keep every output frame already accepted from the endpoint ahead of
        # CLOSE. The terminal bridge drains those bytes before it exits.
        self._downstream_out.extend(_pack_frame(_FRAME_CLOSE))
        self._downstream_events(selector)

    def _remember_viewer(self, payload: bytes) -> None:
        self._viewer_backlog.extend(payload)
        if len(self._viewer_backlog) > _DEFAULT_BACKLOG_BYTES:
            self._viewer_backlog[:] = _ansi_safe_suffix(
                self._viewer_backlog,
                _DEFAULT_BACKLOG_BYTES,
            )
            self._viewer_backlog_truncated = True

    def _queue_downstream_output(self, payload: bytes, selector) -> None:
        if self._downstream_close_reason is not None:
            # A lane event already selected in the same selector batch may
            # arrive just after close was requested. Preserve it if the CLOSE
            # frame is still wholly queued; once any CLOSE byte is on the wire,
            # accepting later output would violate protocol ordering.
            close_frame = _pack_frame(_FRAME_CLOSE)
            if self._downstream_out.endswith(close_frame):
                frame = _pack_frame(_FRAME_OUTPUT, payload)
                if len(self._downstream_out) + len(frame) > _MAX_LIVE_QUEUE_BYTES:
                    self._remember_viewer(payload)
                    return
                self._downstream_out[-len(close_frame) :] = frame + close_frame
                self._downstream_events(selector)
            return
        if not self._downstream_authenticated:
            self._remember_viewer(payload)
            return
        frame = _pack_frame(_FRAME_OUTPUT, payload)
        if len(self._downstream_out) + len(frame) > _MAX_LIVE_QUEUE_BYTES:
            self._remember_viewer(payload)
            self._drop_downstream(selector, "viewer output queue overflow")
            return
        self._downstream_out.extend(frame)
        self._downstream_events(selector)

    def _queue_downstream_frame(self, frame_type: int, payload: bytes, selector) -> None:
        if self._downstream_close_reason is not None:
            raise RuntimeError("console viewer is closing")
        if not self._downstream_authenticated:
            raise RuntimeError("console viewer disconnected during switch")
        frame = _pack_frame(frame_type, payload)
        if len(self._downstream_out) + len(frame) > _MAX_LIVE_QUEUE_BYTES:
            self._drop_downstream(selector, "viewer control queue overflow")
            raise BufferError("console viewer control queue overflow")
        self._downstream_out.extend(frame)
        self._downstream_events(selector)

    def _drop_downstream(self, selector, reason="viewer disconnected") -> None:
        conn, self._downstream = self._downstream, None
        with self._condition:
            was_connected = self._downstream_authenticated
            self._downstream_authenticated = False
            self._downstream_reconnect = False
            self._downstream_deadline = None
            self._condition.notify_all()
        if was_connected:
            self._notify_connection(False, str(reason))
        self._downstream_in.clear()
        self._downstream_out.clear()
        self._downstream_close_reason = None
        if conn is not None:
            try:
                selector.unregister(conn)
            except Exception:
                pass
            try:
                conn.close()
            except OSError:
                pass
        command, self._pending_switch = self._pending_switch, None
        if command is None and self._candidate is not None:
            # A candidate exists before the epoch transaction begins while its
            # broker authenticates and while the caller synchronously applies
            # viewer geometry.  Viewer EOF must cancel that phase too; waiting
            # only on _pending_switch strands the public call until its full
            # operation timeout and leaves the candidate broker leased.
            command = self._candidate.command
        if command is not None and command.result is None:
            lane = command.lane
            if lane is not None and lane is self._candidate:
                self._candidate = None
                self._close_lane(selector, lane)
            if command.error is None:
                command.error = RuntimeError("console viewer disconnected during console switch")
            command.phase = "cancelled"
            command.hello_sent.set()
            command.authenticated.set()
            command.done.set()

    def _forward_resize_to_lanes(self, selector, payload=None) -> None:
        if payload is None:
            _generation, rows, cols = self._geometry_snapshot()
            payload = json.dumps({"rows": rows, "cols": cols}, separators=(",", ":")).encode("ascii")
        for lane in (self._active, self._candidate):
            if lane is not None and lane.hello_complete:
                self._queue_lane(lane, _FRAME_RESIZE, payload, selector)

    def _queue_lane(self, lane, frame_type, payload, selector) -> None:
        frame = _pack_frame(frame_type, payload)
        if len(lane.outgoing) + len(frame) > _MAX_LIVE_QUEUE_BYTES:
            self._lose_lane(selector, lane, "endpoint input queue overflow")
            return
        lane.outgoing.extend(frame)
        self._lane_events(selector, lane)

    def _prepare(self, selector, command: _Switch) -> None:
        if command.cancelled.is_set():
            command.error = TimeoutError("console switch was cancelled")
            command.hello_sent.set()
            command.done.set()
            return
        if self._candidate is not None:
            command.error = RuntimeError("another console switch is in progress")
            command.hello_sent.set()
            command.done.set()
            return
        broker = getattr(command.endpoint, "_broker", None)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.setblocking(False)
            result = sock.connect_ex(broker.socket_path)
            connected = result in (0, errno.EISCONN)
            if not connected and result not in (
                errno.EINPROGRESS,
                errno.EALREADY,
                errno.EAGAIN,
                errno.EWOULDBLOCK,
            ):
                raise OSError(result, os.strerror(result))
            _generation, rows, cols = self._geometry_snapshot()
            hello = json.dumps(
                {
                    "version": _PROTOCOL_VERSION,
                    "token": broker.token,
                    "session": broker.session_id,
                    "nonce": command.nonce,
                    "rows": rows,
                    "cols": cols,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            lane = _Lane(command.endpoint, sock, command, not connected)
            lane.outgoing.extend(_pack_frame(_FRAME_HELLO, hello))
            command.lane = lane
            self._candidate = lane
            selector.register(sock, selectors.EVENT_READ | selectors.EVENT_WRITE, lane)
        except BaseException as error:
            try:
                sock.close()
            except (NameError, OSError):
                pass
            if isinstance(error, OSError):
                command.error = RuntimeError(
                    f"could not connect the viewer router to GDB console endpoint "
                    f"{broker.socket_path}: {_os_error_reason(error)}"
                )
                command.error.__cause__ = error
            else:
                command.error = error
            command.hello_sent.set()
            command.done.set()

    def _finish_connect(self, selector, lane) -> bool:
        if not lane.connecting:
            return True
        try:
            error = lane.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        except OSError as failure:
            self._lose_lane(
                selector,
                lane,
                f"could not inspect the connection to {lane.endpoint._broker.socket_path}: "
                f"{_os_error_reason(failure)}",
            )
            return False
        if error:
            self._lose_lane(
                selector,
                lane,
                f"could not connect to {lane.endpoint._broker.socket_path}: "
                f"{_os_error_reason(OSError(error, os.strerror(error)))}",
            )
            return False
        lane.connecting = False
        return True

    def _write_lane(self, selector, lane) -> None:
        if not self._finish_connect(selector, lane):
            return
        if lane.outgoing:
            try:
                count = lane.sock.send(lane.outgoing)
            except BlockingIOError:
                return
            except OSError as error:
                self._lose_lane(
                    selector,
                    lane,
                    f"could not write to {lane.endpoint._broker.socket_path}: "
                    f"{_os_error_reason(error)}",
                )
                return
            if count <= 0:
                self._lose_lane(selector, lane, "endpoint socket closed")
                return
            del lane.outgoing[:count]
        if not lane.hello_complete and not lane.outgoing:
            lane.hello_complete = True
            if lane.command is not None:
                lane.command.hello_sent.set()
        self._lane_events(selector, lane)

    def _read_lane(self, selector, lane) -> None:
        try:
            data = lane.sock.recv(65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            self._lose_lane(selector, lane, "endpoint EOF")
            return
        lane.incoming.extend(data)
        try:
            frames = list(_extract_frames(lane.incoming))
        except ValueError:
            self._lose_lane(selector, lane, "invalid endpoint frame")
            return
        for frame_type, payload in frames:
            if frame_type == _FRAME_HELLO_ACK:
                command = lane.command
                if (
                    lane is not self._candidate
                    or command is None
                    or lane.authenticated
                    or not secrets.compare_digest(payload.decode("utf-8", "replace"), command.nonce)
                ):
                    self._lose_lane(selector, lane, "invalid endpoint authentication ACK")
                    return
                lane.authenticated = True
                command.authenticated.set()
            elif frame_type == _FRAME_OUTPUT:
                if not lane.authenticated and lane is self._candidate:
                    self._lose_lane(selector, lane, "endpoint output preceded authentication")
                    return
                if lane is self._candidate:
                    if len(lane.staged_output) + len(payload) > _MAX_LIVE_QUEUE_BYTES:
                        self._lose_lane(selector, lane, "candidate output queue overflow")
                        return
                    lane.staged_output.extend(payload)
                elif lane is self._active:
                    self._queue_downstream_output(payload, selector)
            elif frame_type == _FRAME_CLOSE:
                self._lose_lane(selector, lane, "endpoint closed")
                return
            else:
                self._lose_lane(selector, lane, "invalid endpoint frame")
                return

    def _close_lane(self, selector, lane) -> None:
        try:
            selector.unregister(lane.sock)
        except Exception:
            pass
        try:
            lane.sock.close()
        except OSError:
            pass
        lane.outgoing.clear()
        lane.incoming.clear()
        lane.staged_output.clear()

    def _lose_lane(self, selector, lane, reason: str) -> None:
        self._close_lane(selector, lane)
        if lane is self._candidate:
            command = lane.command
            error = RuntimeError("console endpoint failed while switching: " + str(reason))
            if command is not None and self._pending_switch is command:
                # The transaction, not this now-closed socket, keeps rollback
                # alive.  Leaving a dead lane in _candidate lets a concurrent
                # resize try to re-register its invalid file descriptor.
                self._candidate = None
                self._begin_rollback(selector, command, error)
            else:
                self._candidate = None
                if command is not None:
                    command.error = error
                    command.phase = "cancelled"
                    command.hello_sent.set()
                    command.authenticated.set()
                    command.done.set()
            return
        if lane is self._active:
            endpoint = lane.endpoint
            with self._condition:
                lost_generation = self._generation
                self._active = None
                self._current = None
                self._generation += 1
                self._condition.notify_all()
            self._notify_loss(endpoint, reason, lost_generation)

    def _commit(self, selector, command: _Switch) -> None:
        lane = command.lane
        if (
            command.cancelled.is_set()
            or lane is None
            or lane is not self._candidate
            or not lane.authenticated
            or command.error is not None
            or self._pending_switch is not None
            or not self._downstream_authenticated
        ):
            if command.error is None:
                command.error = RuntimeError("console switch was cancelled")
            command.done.set()
            return
        command.epoch = self._next_epoch
        self._next_epoch += 1
        if self._next_epoch > 0xFFFFFFFFFFFFFFFF:
            self._next_epoch = 1
        command.old_epoch = self._active_epoch
        command.switch_id = self._next_switch_id
        self._next_switch_id += 1
        if self._next_switch_id > 0xFFFFFFFFFFFFFFFF:
            self._next_switch_id = 1
        command.phase = "pausing"
        self._pending_switch = command
        try:
            self._queue_downstream_frame(
                _FRAME_SWITCH_PAUSE,
                _SWITCH.pack(command.switch_id, command.epoch),
                selector,
            )
        except (BufferError, RuntimeError) as error:
            if not command.done.is_set():
                self._pending_switch = None
                self._candidate = None
                self._close_lane(selector, lane)
                command.error = error
                command.phase = "cancelled"
                command.done.set()

    def _switch_paused(self, selector, command: _Switch) -> None:
        if command is not self._pending_switch:
            return
        if command.phase == "resuming-old":
            return
        if command.phase != "pausing":
            return
        if command.cancelled.is_set() or time.monotonic() >= command.deadline:
            self._begin_rollback(
                selector,
                command,
                TimeoutError("timed out committing the console switch"),
            )
            return
        command.phase = "resuming-new"
        try:
            self._queue_downstream_frame(
                _FRAME_SWITCH_RESUME,
                _SWITCH.pack(command.switch_id, command.epoch),
                selector,
            )
        except (BufferError, RuntimeError) as error:
            if not command.done.is_set():
                self._begin_rollback(selector, command, error)

    def _switch_resumed(self, selector, command: _Switch, epoch: int) -> None:
        if command is not self._pending_switch:
            return
        if command.phase == "resuming-new" and epoch == command.epoch:
            self._finish_commit(selector, command)
        elif command.phase == "resuming-old" and epoch == command.old_epoch:
            self._finish_rollback(selector, command)

    def _finish_commit(self, selector, command: _Switch) -> None:
        lane = command.lane
        if command is not self._pending_switch or lane is None or lane is not self._candidate or command.epoch is None:
            return
        self._pending_switch = None
        old = self._active
        command.old_endpoint = None if old is None else old.endpoint
        if old is not None:
            self._close_lane(selector, old)
        self._active = lane
        self._active_epoch = command.epoch
        self._candidate = None
        lane.command = None
        with self._condition:
            self._current = lane.endpoint
            self._generation += 1
            command.result = self._generation
            self._condition.notify_all()
        if lane.staged_output:
            # A candidate can receive several individually valid frames before
            # commit.  Preserve their byte order without combining them into a
            # frame larger than the protocol maximum.
            while lane.staged_output:
                payload = bytes(lane.staged_output[:_MAX_FRAME_BYTES])
                del lane.staged_output[: len(payload)]
                self._queue_downstream_output(payload, selector)
            lane.staged_output.clear()
        command.phase = "committed"
        command.done.set()
        self._lane_events(selector, lane)

    def _begin_rollback(
        self,
        selector,
        command: _Switch,
        error: BaseException | None = None,
    ) -> None:
        if command.result is not None or command.done.is_set():
            return
        if error is not None and command.error is None:
            command.error = error
        if self._pending_switch is not command or command.switch_id is None:
            self._finish_rollback(selector, command)
            return
        if command.phase == "resuming-old":
            return
        command.phase = "resuming-old"
        command.rollback_deadline = time.monotonic() + _ROLLBACK_TIMEOUT
        try:
            self._queue_downstream_frame(
                _FRAME_SWITCH_RESUME,
                _SWITCH.pack(command.switch_id, command.old_epoch),
                selector,
            )
        except (BufferError, RuntimeError):
            if not command.done.is_set():
                self._drop_downstream(selector)

    def _finish_rollback(self, selector, command: _Switch) -> None:
        if self._pending_switch is command:
            self._pending_switch = None
        lane = command.lane
        if lane is not None and lane is self._candidate:
            self._candidate = None
            self._close_lane(selector, lane)
        if command.error is None:
            command.error = TimeoutError("console switch was cancelled")
        command.phase = "cancelled"
        command.hello_sent.set()
        command.authenticated.set()
        command.done.set()

    def _cancel(self, selector, command: _Switch) -> None:
        if self._pending_switch is command:
            self._begin_rollback(selector, command)
            return
        lane = command.lane
        if lane is not None and lane is self._candidate:
            self._candidate = None
            self._close_lane(selector, lane)
        if command.error is None:
            command.error = TimeoutError("console switch was cancelled")
        command.hello_sent.set()
        command.authenticated.set()
        command.done.set()

    def _timeout_switch(self, selector, command: _Switch) -> None:
        if command.done.is_set():
            return
        error = TimeoutError("timed out committing the console switch")
        if self._pending_switch is command:
            self._begin_rollback(selector, command, error)
            return
        if command.error is None:
            command.error = error
        self._cancel(selector, command)

    def _drain_wake(self) -> None:
        try:
            while os.read(self._wake_r, 4096):
                pass
        except (BlockingIOError, OSError):
            pass

    def _commands_ready(self, selector) -> bool:
        self._drain_wake()
        while True:
            try:
                kind, value = self._commands.get_nowait()
            except queue.Empty:
                return True
            if kind == "prepare":
                self._prepare(selector, value)
            elif kind == "commit":
                self._commit(selector, value)
            elif kind == "cancel":
                self._cancel(selector, value)
            elif kind == "timeout":
                self._timeout_switch(selector, value)
            elif kind == "close-viewer":
                self._close_downstream(selector, value)
            elif kind == "close":
                return False

    def _expire(self, selector) -> None:
        now = time.monotonic()
        if (
            self._downstream is not None
            and not self._downstream_authenticated
            and self._downstream_deadline is not None
            and now >= self._downstream_deadline
        ):
            self._drop_downstream(selector)
        command = self._pending_switch
        if command is None and self._candidate is not None:
            command = self._candidate.command
        if command is None or command.done.is_set():
            return
        if command.phase == "resuming-old":
            if command.rollback_deadline is not None and now >= command.rollback_deadline:
                # The bridge did not acknowledge restoration.  Closing that
                # ambiguous viewer guarantees no future byte can reach the
                # wrong GDB; the old upstream lane remains selected.
                self._drop_downstream(selector)
            return
        if now >= command.deadline:
            self._timeout_switch(selector, command)

    def _run(self) -> None:
        selector = selectors.DefaultSelector()
        failure = None
        try:
            selector.register(self._listener, selectors.EVENT_READ, "listener")
            selector.register(self._wake_r, selectors.EVENT_READ, "wake")
            running = True
            while running:
                self._expire(selector)
                ready = selector.select(self._selector_timeout())
                self._expire(selector)
                for key, mask in ready:
                    if key.data == "wake":
                        running = self._commands_ready(selector)
                    elif key.data == "listener":
                        self._accept_downstream(selector)
                    elif key.data == "downstream" and self._downstream is not None:
                        if mask & selectors.EVENT_READ:
                            self._read_downstream(selector)
                        if mask & selectors.EVENT_WRITE and self._downstream is not None:
                            self._write_downstream(selector)
                    elif isinstance(key.data, _Lane):
                        lane = key.data
                        if lane is not self._active and lane is not self._candidate:
                            continue
                        if mask & selectors.EVENT_READ:
                            self._read_lane(selector, lane)
                        if mask & selectors.EVENT_WRITE and (lane is self._active or lane is self._candidate):
                            self._write_lane(selector, lane)
                    if not running:
                        break
        except BaseException as error:
            failure = error
        finally:
            candidate, self._candidate = self._candidate, None
            active, self._active = self._active, None
            if candidate is not None:
                command = candidate.command
                self._close_lane(selector, candidate)
                if command is not None:
                    command.error = failure or RuntimeError("viewer router closed")
                    command.hello_sent.set()
                    command.authenticated.set()
                    command.done.set()
            if active is not None:
                self._close_lane(selector, active)
            if self._downstream is not None:
                try:
                    self._downstream.setblocking(True)
                    self._downstream.settimeout(0.2)
                    pending = bytes(self._downstream_out)
                    self._downstream_out.clear()
                    self._downstream.sendall(pending + _pack_frame(_FRAME_CLOSE))
                except OSError:
                    pass
                self._drop_downstream(selector, "viewer router closed")
            selector.close()
            with self._condition:
                self._current = None
                self._error = failure
                self._closed = True
                self._condition.notify_all()
            self._router_done.set()

    def _stop_viewer(self) -> None:
        proc = self.proc
        if proc is None:
            self._restore_terminal()
            return
        if self.viewer.keep_open:
            self._restore_terminal(proc)
            return
        if proc.poll() is None:
            try:
                wait_process(proc, 0.5)
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass
                try:
                    wait_process(proc, 2.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        wait_process(proc, 2.0)
                    except Exception:
                        pass
        self._restore_terminal(proc)

    def _cleanup_files(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        for name in ("_wake_r", "_wake_w"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)
        if self._owns_socket_path and self.socket_path is not None:
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        if self._tmpdir is not None:
            try:
                os.rmdir(self._tmpdir)
            except OSError:
                pass

    def close(self) -> None:
        with self._close_lock:
            self._close_locked()

    def _close_locked(self) -> None:
        never_started = False
        with self._condition:
            if not self._started:
                self._closed = True
                never_started = True
            else:
                already_closed = self._closed
        if never_started:
            self._restore_terminal()
            self._cleanup_files()
            return
        if not already_closed:
            self._commands.put(("close", _CLOSE))
            self._wake()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread() and thread.ident is not None:
            thread.join(timeout=3.0)
        self._stop_viewer()
        self._cleanup_files()
        self._losses.put(_LOSS_STOP)
        loss_thread = self._loss_thread
        if loss_thread is not None and loss_thread is not threading.current_thread() and loss_thread.ident is not None:
            loss_thread.join(timeout=2.0)

    def __enter__(self):
        return self.start()

    def __exit__(self, _type, _value, _traceback):
        self.close()


__all__ = ["ViewerRouter"]
