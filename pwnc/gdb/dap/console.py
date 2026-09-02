"""Interactive console endpoints for a synchronous GDB DAP session.

The console endpoint and the program displaying it are deliberately separate:

``none``
    Do not allocate or attach a terminal.
``current``
    Borrow the caller's current terminal and attach GDB directly to it.
``target``
    Borrow an explicitly supplied terminal path or file descriptor.
``owned``
    Allocate a stable PTY for GDB and proxy its master through a reconnectable
    Unix-socket broker.  A small standalone bridge can display that endpoint in
    the current terminal or in any caller-provided terminal launcher.

The public API is synchronous.  PTY draining and resize forwarding use bounded
background threads so an unattached or slow viewer cannot block GDB.
"""

from __future__ import annotations

import errno
import fcntl
import json
import operator
import os
import pty
import secrets
import select
import selectors
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Protocol, Sequence

from ._console_bridge import _ansi_safe_suffix
from ._process import wait_process

_PROTOCOL_VERSION = 2
_FRAME_HEADER = struct.Struct("!BI")
_FRAME_HELLO = 1
_FRAME_OUTPUT = 2
_FRAME_INPUT = 3
_FRAME_RESIZE = 4
_FRAME_DETACH = 5
_FRAME_CLOSE = 6
_FRAME_HELLO_ACK = 7
_FRAME_SWITCH_PAUSE = 8
_FRAME_SWITCH_PAUSED = 9
_FRAME_EPOCH_INPUT = 10
_FRAME_EPOCH_RESIZE = 11
_FRAME_SWITCH_RESUME = 12
_FRAME_SWITCH_RESUMED = 13
_MAX_FRAME_BYTES = 4 * 1024 * 1024
_DEFAULT_BACKLOG_BYTES = 1024 * 1024
# Live flow-control is deliberately independent from retained history.  A
# caller asking for a one-byte reconnect backlog must still be able to type a
# command or receive a normal (including maximum-sized) protocol frame.
_MAX_LIVE_QUEUE_BYTES = 2 * _MAX_FRAME_BYTES + _FRAME_HEADER.size


class ConsoleMode(str, Enum):
    NONE = "none"
    CURRENT = "current"
    TARGET = "target"
    OWNED = "owned"


class ViewerMode(str, Enum):
    CURRENT = "current"
    TARGET = "target"
    EXTERNAL = "external"


class TerminalLauncher(Protocol):
    """Spawn a terminal-like program around the supplied bridge argv."""

    def spawn(self, bridge_argv: Sequence[str]) -> subprocess.Popen: ...


@dataclass(frozen=True, slots=True)
class ArgvTerminalLauncher:
    """Shell-free terminal launcher.

    An exact ``"{command}"`` item splices the bridge argv at that position.  If
    omitted, the bridge argv is appended, preserving the historical
    ``[terminal, ..., -e] + child_argv`` convention.
    """

    argv: tuple[str, ...]

    def __init__(self, argv: str | Sequence[str]):
        values = shlex.split(argv) if isinstance(argv, str) else list(argv)
        if not values:
            raise ValueError("terminal launcher argv cannot be empty")
        object.__setattr__(self, "argv", tuple(os.fspath(value) for value in values))

    def command(self, bridge_argv: Sequence[str]) -> list[str]:
        child = [os.fspath(value) for value in bridge_argv]
        count = self.argv.count("{command}")
        if count > 1:
            raise ValueError("terminal launcher may contain at most one {command} item")
        if not count:
            return [*self.argv, *child]
        result: list[str] = []
        for item in self.argv:
            result.extend(child if item == "{command}" else [item])
        return result

    def spawn(self, bridge_argv: Sequence[str]) -> subprocess.Popen:
        return subprocess.Popen(self.command(bridge_argv))


@dataclass(frozen=True, slots=True)
class ViewerConfig:
    mode: ViewerMode
    launcher: object | None = None
    keep_open: bool = False
    tty: str | bytes | os.PathLike[str] | os.PathLike[bytes] | int | None = None
    reconnect: bool = False

    def __post_init__(self):
        object.__setattr__(self, "mode", ViewerMode(self.mode))
        if self.mode is ViewerMode.CURRENT:
            if self.launcher is not None or self.tty is not None:
                raise ValueError("a current-terminal viewer cannot have a launcher or target tty")
            return
        if self.mode is ViewerMode.TARGET:
            if self.launcher is not None:
                raise ValueError("a target-terminal viewer cannot have a launcher")
            if self.tty is None:
                raise ValueError("a target-terminal viewer requires a tty path or fd")
            value = self.tty
            if isinstance(value, bool):
                raise TypeError("viewer target tty must be a path or file descriptor")
            try:
                normalized = int(operator.index(value))
            except TypeError:
                try:
                    normalized = os.fspath(value)
                except TypeError as error:
                    raise TypeError("viewer target tty must be a path or file descriptor") from error
                if not normalized:
                    raise ValueError("viewer target tty path cannot be empty")
            object.__setattr__(self, "tty", normalized)
            return
        if self.tty is not None:
            raise ValueError("a custom external viewer cannot have a target tty")

    @classmethod
    def current(
        cls,
        *,
        keep_open: bool = False,
        reconnect: bool = False,
    ) -> "ViewerConfig":
        return cls(ViewerMode.CURRENT, keep_open=keep_open, reconnect=reconnect)

    @classmethod
    def target(
        cls,
        tty: str | bytes | os.PathLike[str] | os.PathLike[bytes] | int,
        *,
        keep_open: bool = False,
        reconnect: bool = False,
    ) -> "ViewerConfig":
        return cls(
            ViewerMode.TARGET,
            keep_open=keep_open,
            reconnect=reconnect,
            tty=tty,
        )

    @classmethod
    def external(
        cls,
        launcher: object | None = None,
        *,
        keep_open: bool = False,
        reconnect: bool = False,
    ) -> "ViewerConfig":
        return cls(
            ViewerMode.EXTERNAL,
            launcher=launcher,
            keep_open=keep_open,
            reconnect=reconnect,
        )


@dataclass(frozen=True, slots=True)
class ConsoleConfig:
    mode: ConsoleMode
    tty: str | os.PathLike[str] | int | None = None
    viewer: ViewerConfig | None = None
    save_history: bool = True
    initial_rows: int = 24
    initial_cols: int = 80
    backlog_bytes: int = _DEFAULT_BACKLOG_BYTES

    def __post_init__(self):
        object.__setattr__(self, "mode", ConsoleMode(self.mode))
        if self.mode in (ConsoleMode.CURRENT, ConsoleMode.TARGET):
            if self.mode is ConsoleMode.CURRENT and self.tty is None:
                object.__setattr__(self, "tty", 0)
            if self.tty is None:
                raise ValueError("target console mode requires a tty path or fd")
            if self.viewer is not None:
                raise ValueError("borrowed console modes cannot have a bridge viewer")
        elif self.tty is not None:
            raise ValueError("tty is only valid for current or target console modes")
        if self.mode is not ConsoleMode.OWNED and self.viewer is not None:
            raise ValueError("viewer is only valid for owned console mode")
        for field_name in ("initial_rows", "initial_cols", "backlog_bytes"):
            value = getattr(self, field_name)
            if isinstance(value, bool):
                raise TypeError(f"{field_name} must be an integer")
            try:
                value = operator.index(value)
            except TypeError as error:
                raise TypeError(f"{field_name} must be an integer") from error
            object.__setattr__(self, field_name, value)
        if not 0 < self.initial_rows <= 0xFFFF:
            raise ValueError("initial_rows must be between 1 and 65535")
        if not 0 < self.initial_cols <= 0xFFFF:
            raise ValueError("initial_cols must be between 1 and 65535")
        if not 0 < self.backlog_bytes <= _MAX_FRAME_BYTES:
            raise ValueError("backlog_bytes must be between 1 and %d" % _MAX_FRAME_BYTES)

    @classmethod
    def none(cls) -> "ConsoleConfig":
        return cls(ConsoleMode.NONE)

    @classmethod
    def current(cls, fd: int = 0, *, save_history: bool = True) -> "ConsoleConfig":
        return cls(ConsoleMode.CURRENT, tty=fd, save_history=save_history)

    @classmethod
    def target(cls, tty: str | os.PathLike[str] | int, *, save_history: bool = True) -> "ConsoleConfig":
        return cls(ConsoleMode.TARGET, tty=tty, save_history=save_history)

    @classmethod
    def owned(
        cls,
        *,
        viewer: ViewerConfig | None = None,
        save_history: bool = True,
        initial_size: tuple[int, int] = (24, 80),
        backlog_bytes: int = _DEFAULT_BACKLOG_BYTES,
    ) -> "ConsoleConfig":
        rows, cols = initial_size
        return cls(
            ConsoleMode.OWNED,
            viewer=viewer,
            save_history=save_history,
            initial_rows=rows,
            initial_cols=cols,
            backlog_bytes=backlog_bytes,
        )


# These are compatibility discovery adapters, not a preferred terminal.  New
# callers should supply a launcher or use ViewerConfig.current().
_FALLBACK_TERMINALS = [
    ["x-terminal-emulator", "-e"],
    ["xterm", "-e"],
    ["gnome-terminal", "--"],
    ["konsole", "-e"],
    ["kitty", "-e"],
]


def _terminal_argv(terminal):
    """Resolve the historical terminal-prefix argument without invoking a shell."""
    if terminal:
        return shlex.split(terminal) if isinstance(terminal, str) else list(terminal)
    for variable in ("PWNC_DAP_TERMINAL", "TERMINAL"):
        value = os.environ.get(variable)
        if value:
            return shlex.split(value)
    for candidate in _FALLBACK_TERMINALS:
        if shutil.which(candidate[0]):
            return candidate
    raise RuntimeError(
        "no terminal launcher found; supply ViewerConfig.current(), an explicit launcher, or set $PWNC_DAP_TERMINAL"
    )


def _pack_frame(frame_type: int, payload: bytes = b"") -> bytes:
    if len(payload) > _MAX_FRAME_BYTES:
        raise ValueError("console bridge frame is too large")
    return _FRAME_HEADER.pack(frame_type, len(payload)) + payload


def _extract_frames(buffer: bytearray):
    while len(buffer) >= _FRAME_HEADER.size:
        frame_type, length = _FRAME_HEADER.unpack(buffer[: _FRAME_HEADER.size])
        if length > _MAX_FRAME_BYTES:
            raise ValueError("console bridge frame is too large")
        end = _FRAME_HEADER.size + length
        if len(buffer) < end:
            return
        payload = bytes(buffer[_FRAME_HEADER.size : end])
        del buffer[:end]
        yield frame_type, payload


def _winsize(fd: int) -> tuple[int, int]:
    try:
        raw = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, _xp, _yp = struct.unpack("HHHH", raw)
        return int(rows), int(cols)
    except OSError:
        return 0, 0


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _resolve_tty(value) -> tuple[str, int]:
    """Validate a borrowed tty and return its canonical name plus a private fd."""
    if isinstance(value, int):
        fd = os.dup(value)
    else:
        flags = os.O_RDWR | os.O_NOCTTY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(os.fspath(value), flags)
    try:
        if not os.isatty(fd):
            raise ValueError("console target is not a tty")
        st = os.fstat(fd)
        if not stat.S_ISCHR(st.st_mode):
            raise ValueError("console target is not a character device")
        return os.ttyname(fd), fd
    except BaseException:
        os.close(fd)
        raise


class _LatestResizeWorker:
    def __init__(self, gdb):
        self._gdb = gdb
        self._condition = threading.Condition()
        self._pending: tuple[int, tuple[int, int]] | None = None
        self._last: tuple[int, int] | None = None
        self._generation = 0
        self._request_lock = threading.Lock()
        self._closed = False
        self._thread = threading.Thread(target=self._run, name="pwnc-console-resize", daemon=True)
        self._thread.start()

    def submit(self, rows: int, cols: int) -> None:
        size = (int(rows), int(cols))
        if not (0 < size[0] <= 0xFFFF and 0 < size[1] <= 0xFFFF):
            return
        with self._condition:
            if self._closed or (size == self._last and self._pending is None):
                return
            self._generation += 1
            self._pending = (self._generation, size)
            self._condition.notify()

    def _run(self) -> None:
        while True:
            with self._condition:
                while self._pending is None and not self._closed:
                    self._condition.wait()
                if self._closed:
                    return
                generation, size = self._pending
                self._pending = None
            try:
                self._apply(size, generation)
            except Exception:
                return

    def apply_sync(self, rows: int, cols: int, *, timeout: float | None = None) -> None:
        """Apply a size before returning, coalescing with the async lane."""
        size = (int(rows), int(cols))
        if not (0 < size[0] <= 0xFFFF and 0 < size[1] <= 0xFFFF):
            raise ValueError("console dimensions must be between 1 and 65535")
        with self._condition:
            if self._closed:
                raise RuntimeError("console resize worker is closed")
            # Invalidate any older async item, including one which has already
            # been dequeued but has not acquired the request lane yet.
            self._generation += 1
            generation = self._generation
            self._pending = None
        self._apply(size, generation, timeout=timeout)

    def _apply(
        self,
        size: tuple[int, int],
        generation: int,
        *,
        timeout: float | None = None,
    ) -> None:
        deadline = None if timeout is None else time.monotonic() + float(timeout)
        if deadline is None:
            acquired = self._request_lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            acquired = remaining > 0 and self._request_lock.acquire(timeout=remaining)
        if not acquired:
            raise TimeoutError("timed out waiting for the console resize lane")
        try:
            with self._condition:
                if self._closed:
                    raise RuntimeError("console resize worker is closed")
                if generation != self._generation:
                    return
                if size == self._last:
                    return
            arguments = {"rows": size[0], "cols": size[1]}
            if deadline is None:
                self._gdb.transport.request("pwncSetWinsize", arguments)
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out applying the console size")
                self._gdb.transport.request(
                    "pwncSetWinsize",
                    arguments,
                    timeout=remaining,
                )
            with self._condition:
                self._last = size
        finally:
            self._request_lock.release()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._pending = None
            self._condition.notify_all()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)


class _SigwinchRelay:
    """Share process-wide SIGWINCH delivery without stealing existing handlers.

    Python only permits installing signal handlers from its main thread.  The
    first foreground-terminal watcher therefore installs this relay there;
    subsequent watchers may subscribe from any thread.  A handler which was
    present first is invoked after all resize notifications and restored when
    the last watcher is removed from the main thread.

    If the final removal happens elsewhere, the inert relay remains installed
    and continues chaining the original handler.  Python offers no safe way to
    run ``signal.signal`` synchronously on the main thread from an arbitrary
    worker.  Keeping an empty, event-driven relay is preferable to generating a
    synthetic signal or replacing somebody else's newer handler.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._listeners: tuple[Callable[[], None], ...] = ()
        self._previous = None
        self._installed = False
        # Bound-method identity is not stable across attribute accesses.  Keep
        # the exact callable used with signal.signal for identity checks.
        self._handler = self._dispatch

    def subscribe(self, listener: Callable[[], None]) -> bool:
        with self._lock:
            if listener in self._listeners:
                return True
            if self._installed and signal.getsignal(signal.SIGWINCH) is not self._handler:
                if self._listeners:
                    # Existing subscribers have been displaced too; do not
                    # disturb the newer owner or promise delivery to another.
                    return False
                self._installed = False
                self._previous = None
            if not self._installed:
                if threading.current_thread() is not threading.main_thread():
                    return False
                previous = signal.getsignal(signal.SIGWINCH)
                try:
                    signal.signal(signal.SIGWINCH, self._handler)
                except (OSError, ValueError):
                    return False
                self._previous = previous
                self._installed = True
            self._listeners = (*self._listeners, listener)
            return True

    def unsubscribe(self, listener: Callable[[], None]) -> None:
        with self._lock:
            self._listeners = tuple(candidate for candidate in self._listeners if candidate is not listener)
            if self._listeners or not self._installed:
                return
            if threading.current_thread() is not threading.main_thread():
                return
            # Never clobber a handler installed after ours.
            if signal.getsignal(signal.SIGWINCH) is self._handler:
                try:
                    signal.signal(signal.SIGWINCH, self._previous)
                except (OSError, ValueError):
                    return
            self._installed = False
            self._previous = None

    def _dispatch(self, signum, frame) -> None:
        # Tuple replacement makes dispatch lock-free.  A listener concurrently
        # removed may receive one harmless final wake; its nonblocking pipe
        # write tolerates a descriptor which has already closed.
        for listener in self._listeners:
            try:
                listener()
            except BaseException:
                pass
        previous = self._previous
        if callable(previous) and previous is not self._handler:
            previous(signum, frame)


_SIGWINCH_RELAY = _SigwinchRelay()


def _is_foreground_process_tty(fd: int) -> bool:
    """Whether resizing *fd* causes the kernel to SIGWINCH this process."""
    try:
        return os.tcgetpgrp(fd) == os.getpgrp()
    except (AttributeError, OSError):
        return False


class _SigwinchUnavailable(RuntimeError):
    pass


class _CurrentResizeWatcher:
    """Event-driven resize and hangup watcher for the controlling terminal."""

    def __init__(
        self,
        fd: int,
        sink: Callable[[int, int], None],
        lost_sink: Callable[[], None],
    ):
        self._fd = fd
        self._sink = sink
        self._lost_sink = lost_sink
        self._stop = threading.Event()
        self._previous = _winsize(fd)
        self._wake_r = self._wake_w = -1
        self._signal_notify = self._wake
        self._subscribed = False
        self._thread = threading.Thread(target=self._run, name="pwnc-console-winsize", daemon=True)
        try:
            self._wake_r, self._wake_w = os.pipe()
            os.set_blocking(self._wake_r, False)
            os.set_blocking(self._wake_w, False)
            if not _SIGWINCH_RELAY.subscribe(self._signal_notify):
                raise _SigwinchUnavailable("SIGWINCH relay cannot be installed from this thread")
            self._subscribed = True
            self._thread.start()
        except BaseException:
            if self._subscribed:
                _SIGWINCH_RELAY.unsubscribe(self._signal_notify)
                self._subscribed = False
            # Ownership of the caller's tty fd transfers only after successful
            # construction.  Leave it for open_console's fallback/cleanup.
            self._close_fds(close_tty=False)
            raise

    def _wake(self) -> None:
        try:
            os.write(self._wake_w, b"x")
        except (BlockingIOError, OSError):
            pass

    def _run(self) -> None:
        previous = self._previous
        poller = select.poll()
        poller.register(
            self._fd,
            select.POLLHUP | select.POLLERR | getattr(select, "POLLNVAL", 0),
        )
        poller.register(self._wake_r, select.POLLIN)
        while not self._stop.is_set():
            events = poller.poll()
            terminal_lost = False
            resize = False
            for fd, flags in events:
                if fd == self._wake_r:
                    resize = True
                    try:
                        while os.read(self._wake_r, 4096):
                            pass
                    except (BlockingIOError, OSError):
                        pass
                elif flags & (select.POLLHUP | select.POLLERR | getattr(select, "POLLNVAL", 0)):
                    terminal_lost = True
            if self._stop.is_set():
                return
            if terminal_lost:
                self._lost_sink()
                return
            if resize:
                size = _winsize(self._fd)
                if size != previous and all(size):
                    self._sink(*size)
                    previous = size

    def _close_fds(self, *, close_tty: bool = True) -> None:
        names = ("_fd", "_wake_r", "_wake_w") if close_tty else ("_wake_r", "_wake_w")
        for name in names:
            fd = getattr(self, name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)

    def close(self) -> None:
        self._stop.set()
        if self._subscribed:
            _SIGWINCH_RELAY.unsubscribe(self._signal_notify)
            self._subscribed = False
        self._wake()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._close_fds()


class _BorrowedResizeWatcher:
    """Event-driven resize/loss watcher for a target or non-controlling TTY.

    TTY geometry changes do not make the device fd readable.  A tiny helper
    therefore joins the target's foreground process group when it belongs to
    our session, or claims an otherwise unowned PTY, and relays kernel
    ``SIGWINCH`` delivery through a pipe.  A process-wide explicit SIGWINCH
    relay is also used when it can be installed.  Unrelated sessions cannot be
    safely joined or have their controlling terminal stolen; those targets
    retain event-driven hangup detection and their initial size, and may opt in
    to later size updates by signaling the host process.
    """

    def __init__(
        self,
        fd: int,
        sink: Callable[[int, int], None],
        lost_sink: Callable[[], None],
    ):
        self._fd = fd
        self._sink = sink
        self._lost_sink = lost_sink
        self._stop = threading.Event()
        self._previous = _winsize(fd)
        self._wake_r = self._wake_w = -1
        self._notify_r = self._notify_w = -1
        self._helper = None
        self._helper_reaped = False
        self._helper_ready = threading.Event()
        self._resize_supported = None
        self._helper_error = None
        self._signal_notify = self._signal_wake
        self._subscribed = False
        self._thread = threading.Thread(target=self._run, name="pwnc-console-winsize", daemon=True)
        try:
            self._wake_r, self._wake_w = os.pipe()
            self._notify_r, self._notify_w = os.pipe()
            for pipe_fd in (self._wake_r, self._wake_w, self._notify_r):
                os.set_blocking(pipe_fd, False)
            helper = os.path.join(os.path.dirname(__file__), "_tty_resize_bridge.py")
            self._helper = subprocess.Popen(
                [sys.executable, helper, str(fd), str(self._notify_w)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(fd, self._notify_w),
            )
            os.close(self._notify_w)
            self._notify_w = -1
            self._subscribed = _SIGWINCH_RELAY.subscribe(self._signal_notify)
            self._thread.start()
            # Construction is the publication barrier: once the watcher is
            # returned, a target resize must not race helper foreground setup.
            # This is one bounded event wait, not a periodic geometry scan.  A
            # helper which reports neither R nor U is a failed construction;
            # returning it would silently reintroduce the startup race.
            if not self._helper_ready.wait(2.0):
                raise RuntimeError("target TTY resize helper did not become ready")
            if self._helper_error is not None:
                raise self._helper_error
        except BaseException:
            # The readiness barrier can fail after the watcher thread has
            # started. Stop and join it before closing descriptors or reaping
            # the helper so failed construction cannot leave a polling thread
            # blocked on invalid/reused fd numbers.
            self._stop.set()
            if self._subscribed:
                _SIGWINCH_RELAY.unsubscribe(self._signal_notify)
                self._subscribed = False
            self._write_wake(b"q")
            if self._thread.ident is not None and self._thread is not threading.current_thread():
                self._thread.join(timeout=2.0)
            self._stop_helper()
            # Ownership of the caller's tty fd transfers only after successful
            # construction, matching _CurrentResizeWatcher's unwind contract.
            self._close_fds(close_tty=False)
            raise

    def _write_wake(self, value: bytes) -> None:
        try:
            os.write(self._wake_w, value)
        except (BlockingIOError, OSError):
            pass

    def _signal_wake(self) -> None:
        self._write_wake(b"r")

    def _resize(self) -> None:
        size = _winsize(self._fd)
        if size != self._previous and all(size):
            self._sink(*size)
            self._previous = size

    @staticmethod
    def _drain(fd: int) -> bytes:
        output = bytearray()
        try:
            while True:
                data = os.read(fd, 4096)
                if not data:
                    break
                output.extend(data)
        except (BlockingIOError, OSError):
            pass
        return bytes(output)

    def _reap_helper(self) -> None:
        helper = self._helper
        if helper is None or self._helper_reaped:
            return
        # Pipe HUP is emitted only after our helper has closed its inherited
        # notification fd on exit, so this is an event-ordered reap rather than
        # a timed process-status probe.
        helper.wait()
        self._helper_reaped = True

    def _run(self) -> None:
        poller = select.poll()
        poller.register(
            self._fd,
            select.POLLHUP | select.POLLERR | getattr(select, "POLLNVAL", 0),
        )
        poller.register(self._wake_r, select.POLLIN)
        poller.register(
            self._notify_r,
            select.POLLIN | select.POLLHUP | select.POLLERR,
        )
        notify_registered = True
        while not self._stop.is_set():
            events = poller.poll()
            terminal_lost = False
            resize = False
            for ready_fd, flags in events:
                if ready_fd == self._fd:
                    if flags & (select.POLLHUP | select.POLLERR | getattr(select, "POLLNVAL", 0)):
                        terminal_lost = True
                elif ready_fd == self._wake_r:
                    resize = b"r" in self._drain(self._wake_r)
                elif ready_fd == self._notify_r:
                    notifications = self._drain(self._notify_r)
                    resize = resize or b"W" in notifications
                    if b"R" in notifications:
                        self._resize_supported = True
                        self._helper_ready.set()
                    elif b"U" in notifications:
                        self._resize_supported = False
                        self._helper_ready.set()
                    if flags & (select.POLLHUP | select.POLLERR):
                        if notify_registered:
                            try:
                                poller.unregister(self._notify_r)
                            except (KeyError, OSError):
                                pass
                            notify_registered = False
                        if not self._helper_ready.is_set():
                            self._helper_error = RuntimeError(
                                "target TTY resize helper exited before reporting readiness"
                            )
                            self._helper_ready.set()
                        self._reap_helper()
            if self._stop.is_set():
                return
            if terminal_lost:
                self._lost_sink()
                return
            if resize:
                self._resize()

    def _stop_helper(self) -> None:
        helper = self._helper
        if helper is None or self._helper_reaped:
            return
        if helper.poll() is None:
            try:
                helper.terminate()
            except OSError:
                pass
            try:
                wait_process(helper, 1.0)
            except subprocess.TimeoutExpired:
                try:
                    helper.kill()
                except OSError:
                    pass
                try:
                    wait_process(helper, 1.0)
                except subprocess.TimeoutExpired:
                    return
        self._helper_reaped = True

    def _close_fds(self, *, close_tty: bool = True) -> None:
        names = (
            ("_fd", "_wake_r", "_wake_w", "_notify_r", "_notify_w")
            if close_tty
            else ("_wake_r", "_wake_w", "_notify_r", "_notify_w")
        )
        for name in names:
            fd = getattr(self, name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)

    def close(self) -> None:
        self._stop.set()
        if self._subscribed:
            _SIGWINCH_RELAY.unsubscribe(self._signal_notify)
            self._subscribed = False
        self._write_wake(b"q")
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._stop_helper()
        self._close_fds()


class _TerminalSnapshot:
    """Restorable termios and file-status state for an inherited viewer TTY.

    The standalone bridge makes fd 0 and fd 1 nonblocking as well as placing
    fd 0 in raw mode.  Duplicates keep the original open-file descriptions
    reachable even if the caller later replaces its numeric standard fds.
    """

    def __init__(self, stdin_fd: int = 0, stdout_fd: int = 1):
        self._lock = threading.Lock()
        self._fds: list[int] = []
        self._blocking: list[tuple[int, bool]] = []
        self._termios = None
        try:
            for index, source_fd in enumerate((stdin_fd, stdout_fd)):
                try:
                    fd = os.dup(source_fd)
                except OSError:
                    continue
                self._fds.append(fd)
                try:
                    self._blocking.append((fd, os.get_blocking(fd)))
                except OSError:
                    pass
                if index == 0 and os.isatty(fd):
                    try:
                        self._termios = (fd, termios.tcgetattr(fd))
                    except termios.error:
                        pass
        except BaseException:
            self.restore()
            raise

    def restore(self) -> None:
        with self._lock:
            fds, self._fds = self._fds, []
            blocking, self._blocking = self._blocking, []
            terminal, self._termios = self._termios, None
        if terminal is not None:
            fd, attributes = terminal
            try:
                termios.tcsetattr(fd, termios.TCSANOW, attributes)
            except (OSError, termios.error):
                pass
        for fd, value in blocking:
            try:
                os.set_blocking(fd, value)
            except OSError:
                pass
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


def _spawn_terminal_bridge(argv: Sequence[str], viewer: ViewerConfig):
    """Spawn *argv* in the current or an explicitly targeted terminal.

    The target path/fd is opened or duplicated privately, validated as a TTY,
    and attached directly to all three standard streams.  No shell or ambient
    terminal launcher participates.  The returned snapshot is a parent-side
    fallback which restores raw/nonblocking terminal state even if the bridge
    is killed before its own ``finally`` block can run.
    """

    if viewer.mode not in (ViewerMode.CURRENT, ViewerMode.TARGET):
        raise ValueError("terminal bridge spawning requires current or target viewer mode")
    snapshot = None
    target_fd = -1
    try:
        command = list(argv)
        # The public standalone viewer is a supervisor so it can recover from a
        # bridge-child SIGKILL.  Tell the bridge which parent it belongs to as
        # well: on Linux it arms PR_SET_PDEATHSIG, allowing the child to run its
        # own terminal-restoration finally block if the supervisor is SIGKILLed.
        command.extend(("--supervisor-pid", str(os.getpid())))
        if viewer.mode is ViewerMode.CURRENT:
            snapshot = _TerminalSnapshot()
            proc = subprocess.Popen(command)
        else:
            _tty_path, target_fd = _resolve_tty(viewer.tty)
            snapshot = _TerminalSnapshot(target_fd, target_fd)
            command.append("--target-tty")
            proc = subprocess.Popen(
                command,
                stdin=target_fd,
                stdout=target_fd,
                stderr=target_fd,
                close_fds=True,
            )
        return proc, snapshot
    except BaseException:
        if snapshot is not None:
            snapshot.restore()
        raise
    finally:
        if target_fd >= 0:
            try:
                os.close(target_fd)
            except OSError:
                pass


class _OwnedPtyBroker:
    """Own and continuously drain one PTY master; accept reconnecting viewers."""

    def __init__(
        self,
        resize_sink: Callable[[int, int], None],
        *,
        initial_size: tuple[int, int],
        backlog_bytes: int,
    ):
        # Establish a fully inert object first so any failure after allocating
        # the PTY can be unwound locally.  A failed ``__init__`` is never handed
        # back to ``open_console``, so relying on its normal close path would
        # leak the master/slave (and possibly pipe/socket) descriptors.
        self.master_fd = -1
        self._slave_fd = -1
        self._wake_r = -1
        self._wake_w = -1
        self._listener = None
        self._tmpdir = None
        self.socket_path = None
        self.session_id = uuid.uuid4().hex
        self.token = secrets.token_urlsafe(32)
        self._resize_sink = resize_sink
        self._backlog_limit = int(backlog_bytes)
        self._live_queue_limit = _MAX_LIVE_QUEUE_BYTES
        self._backlog = bytearray()
        self._backlog_truncated = False
        self._master_out = bytearray()
        self._client = None
        self._client_authenticated = False
        self._client_in = bytearray()
        self._client_out = bytearray()
        self._client_deadline = None
        self._disconnect_requested = False
        self._condition = threading.Condition()
        self._connected = False
        self._current_size = tuple(initial_size)
        self._closed = False
        self._error = None
        self._thread = None
        self._stop = threading.Event()
        try:
            self.master_fd, self._slave_fd = pty.openpty()
            os.set_blocking(self.master_fd, False)
            _set_winsize(self.master_fd, *initial_size)
            self.tty = os.ttyname(self._slave_fd)

            self._wake_r, self._wake_w = os.pipe()
            os.set_blocking(self._wake_r, False)
            os.set_blocking(self._wake_w, False)

            self._tmpdir = tempfile.mkdtemp(prefix="pwnc-console-")
            os.chmod(self._tmpdir, 0o700)
            self.socket_path = os.path.join(self._tmpdir, "bridge.sock")
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener.bind(self.socket_path)
            os.chmod(self.socket_path, 0o600)
            self._listener.listen(4)
            self._listener.setblocking(False)
        except BaseException:
            if self._listener is not None:
                try:
                    self._listener.close()
                except OSError:
                    pass
            for fd_name in ("master_fd", "_slave_fd", "_wake_r", "_wake_w"):
                fd = getattr(self, fd_name)
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    setattr(self, fd_name, -1)
            if self.socket_path is not None:
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass
            if self._tmpdir is not None:
                try:
                    os.rmdir(self._tmpdir)
                except OSError:
                    pass
            raise

    def start(self) -> None:
        if self._thread is not None:
            return
        thread = threading.Thread(target=self._run, name="pwnc-console-broker", daemon=True)
        self._thread = thread
        try:
            thread.start()
        except BaseException:
            # ``Thread.join`` rejects a never-started thread.  Clear it before
            # cleanup so the original startup failure is never masked.
            self._thread = None
            self._cleanup()
            raise

    def release_slave(self) -> None:
        fd, self._slave_fd = self._slave_fd, -1
        if fd >= 0:
            os.close(fd)

    @property
    def connected(self) -> bool:
        with self._condition:
            return self._connected

    @property
    def current_size(self) -> tuple[int, int]:
        with self._condition:
            return self._current_size

    @property
    def alive(self) -> bool:
        with self._condition:
            return not self._closed

    def wait_connected(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._connected:
                if self._closed:
                    if self._error is not None:
                        raise RuntimeError("console PTY broker failed") from self._error
                    raise RuntimeError("console PTY broker closed before viewer connected")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("console bridge did not connect within %.1fs" % timeout)
                self._condition.wait(remaining)

    def wait_disconnected(self, timeout: float) -> None:
        """Wait eventfully until the current broker-authenticated viewer is gone."""
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._connected and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("console bridge did not disconnect within %.1fs" % timeout)
                self._condition.wait(remaining)

    def _wake(self) -> None:
        try:
            os.write(self._wake_w, b"x")
        except OSError:
            pass

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
        self._stop.set()
        self._wake()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread() and thread.ident is not None:
            thread.join(timeout=3.0)
        if thread is None or thread.ident is None or thread.is_alive():
            self._cleanup()

    def detach_client(self, timeout: float = 3.0) -> None:
        """Disconnect the current viewer while retaining the owned PTY."""
        deadline = time.monotonic() + timeout
        with self._condition:
            if self._closed or not self._connected:
                return
            self._disconnect_requested = True
        self._wake()
        with self._condition:
            while self._connected and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("console viewer did not detach within %.1fs" % timeout)
                self._condition.wait(remaining)

    def _remember(self, data: bytes) -> None:
        self._backlog.extend(data)
        if len(self._backlog) > self._backlog_limit:
            self._backlog[:] = _ansi_safe_suffix(
                self._backlog,
                self._backlog_limit,
            )
            self._backlog_truncated = True

    def _set_connected(self, value: bool) -> None:
        with self._condition:
            self._connected = value
            self._condition.notify_all()

    def _drop_client(self, selector: selectors.BaseSelector) -> None:
        client, self._client = self._client, None
        self._client_authenticated = False
        self._client_in.clear()
        self._client_out.clear()
        self._client_deadline = None
        with self._condition:
            self._disconnect_requested = False
        self._set_connected(False)
        if client is not None:
            try:
                selector.unregister(client)
            except Exception:
                pass
            try:
                client.close()
            except OSError:
                pass

    def _client_events(self, selector: selectors.BaseSelector) -> None:
        if self._client is None:
            return
        events = selectors.EVENT_READ
        if self._client_out:
            events |= selectors.EVENT_WRITE
        try:
            selector.modify(self._client, events, "client")
        except (KeyError, ValueError, OSError):
            self._drop_client(selector)

    def _master_events(self, selector: selectors.BaseSelector) -> None:
        events = selectors.EVENT_READ
        if self._master_out:
            events |= selectors.EVENT_WRITE
        try:
            selector.modify(self.master_fd, events, "master")
        except (KeyError, ValueError, OSError):
            pass

    def _queue_client(self, frame_type: int, payload: bytes = b"") -> None:
        self._client_out.extend(_pack_frame(frame_type, payload))

    def _accept(self, selector: selectors.BaseSelector) -> None:
        try:
            conn, _addr = self._listener.accept()
        except BlockingIOError:
            return
        conn.setblocking(False)
        if self._client is not None:
            conn.close()
            return
        self._client = conn
        self._client_deadline = time.monotonic() + 5.0
        selector.register(conn, selectors.EVENT_READ, "client")

    def _handle_hello(self, payload: bytes, selector: selectors.BaseSelector) -> bool:
        try:
            hello = json.loads(payload.decode("utf-8"))
            if not isinstance(hello, dict):
                raise ValueError
            nonce = hello.get("nonce")
            nonce_bytes = None
            if nonce is not None:
                if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
                    raise ValueError
                nonce_bytes = nonce.encode("utf-8")
                if len(nonce_bytes) > 256:
                    raise ValueError
            if not secrets.compare_digest(str(hello.get("token", "")), self.token):
                raise ValueError
            if hello.get("version") != _PROTOCOL_VERSION:
                raise ValueError
            if hello.get("session") != self.session_id:
                raise ValueError
        except (
            UnicodeDecodeError,
            UnicodeEncodeError,
            ValueError,
            TypeError,
            RecursionError,
            OverflowError,
        ):
            self._drop_client(selector)
            return False
        try:
            has_rows = "rows" in hello
            has_cols = "cols" in hello
            if has_rows != has_cols:
                raise ValueError
            if has_rows:
                rows = hello["rows"]
                cols = hello["cols"]
                if isinstance(rows, bool) or isinstance(cols, bool):
                    raise ValueError
                rows = operator.index(rows)
                cols = operator.index(cols)
                if not (0 < rows <= 0xFFFF and 0 < cols <= 0xFFFF):
                    raise ValueError
                _set_winsize(self.master_fd, rows, cols)
                with self._condition:
                    self._current_size = (rows, cols)
                # Queue the ordinary resize lane for clients which connect to
                # the broker directly.  attach_viewer additionally performs a
                # synchronous application before it returns.
                self._resize_sink(rows, cols)
        except (OSError, TypeError, ValueError, OverflowError):
            self._drop_client(selector)
            return False
        self._client_authenticated = True
        self._client_deadline = None
        self._set_connected(True)
        # Routers include a connection nonce.  Echoing it proves that their
        # exact socket, rather than a racing viewer, owns this broker lease.
        # Ordinary standalone bridges omit the nonce and retain protocol-v1
        # behavior without seeing an unfamiliar frame.
        if nonce_bytes is not None:
            self._queue_client(_FRAME_HELLO_ACK, nonce_bytes)
        if self._backlog or self._backlog_truncated:
            backlog = bytes(self._backlog)
            if self._backlog_truncated:
                # A retained suffix cannot reproduce terminal attributes set
                # by discarded history.  Reset first so reconnect starts from
                # a deterministic ground state.
                backlog = b"\x1b[0m" + backlog
            self._queue_client(_FRAME_OUTPUT, backlog)
            self._backlog.clear()
            self._backlog_truncated = False
        self._client_events(selector)
        return True

    def _handle_client_frame(self, frame_type: int, payload: bytes, selector: selectors.BaseSelector) -> bool:
        if not self._client_authenticated:
            return frame_type == _FRAME_HELLO and self._handle_hello(payload, selector)
        if frame_type == _FRAME_INPUT:
            if len(self._master_out) + len(payload) > self._live_queue_limit:
                self._drop_client(selector)
                return False
            self._master_out.extend(payload)
            self._master_events(selector)
            return True
        if frame_type == _FRAME_RESIZE:
            try:
                size = json.loads(payload.decode("ascii"))
                rows, cols = int(size["rows"]), int(size["cols"])
                if not (0 < rows <= 0xFFFF and 0 < cols <= 0xFFFF):
                    raise ValueError
                _set_winsize(self.master_fd, rows, cols)
                with self._condition:
                    self._current_size = (rows, cols)
                self._resize_sink(rows, cols)
            except (
                KeyError,
                OSError,
                UnicodeDecodeError,
                ValueError,
                TypeError,
                RecursionError,
                OverflowError,
            ):
                self._drop_client(selector)
                return False
            return True
        if frame_type in (_FRAME_DETACH, _FRAME_CLOSE):
            self._drop_client(selector)
            return False
        self._drop_client(selector)
        return False

    def _read_client(self, selector: selectors.BaseSelector) -> None:
        try:
            data = self._client.recv(65536)
        except BlockingIOError:
            return
        except OSError:
            self._drop_client(selector)
            return
        if not data:
            self._drop_client(selector)
            return
        self._client_in.extend(data)
        try:
            frames = list(_extract_frames(self._client_in))
        except ValueError:
            self._drop_client(selector)
            return
        for frame_type, payload in frames:
            if self._client is None:
                return
            if not self._handle_client_frame(frame_type, payload, selector):
                return

    def _write_client(self, selector: selectors.BaseSelector) -> None:
        if not self._client_out:
            self._client_events(selector)
            return
        try:
            written = self._client.send(self._client_out)
        except BlockingIOError:
            return
        except OSError:
            self._drop_client(selector)
            return
        if written <= 0:
            self._drop_client(selector)
            return
        del self._client_out[:written]
        self._client_events(selector)

    def _close_client(self, selector: selectors.BaseSelector) -> None:
        if self._client is not None:
            try:
                self._client.setblocking(True)
                self._client.settimeout(0.2)
                pending = bytes(self._client_out)
                self._client_out.clear()
                self._client.sendall(pending + _pack_frame(_FRAME_CLOSE))
            except OSError:
                pass
        self._drop_client(selector)

    def _forward_master_output(self, data, selector):
        """Route PTY bytes whose trailing ANSI sequence is known complete."""
        if not data:
            return
        if self._client_authenticated:
            frame = _pack_frame(_FRAME_OUTPUT, data)
            if len(self._client_out) + len(frame) > self._live_queue_limit:
                self._remember(data)
                self._drop_client(selector)
            else:
                self._client_out.extend(frame)
                self._client_events(selector)
        else:
            self._remember(data)

    def _read_master(self, selector: selectors.BaseSelector) -> bool:
        try:
            data = os.read(self.master_fd, 65536)
        except BlockingIOError:
            return True
        except OSError as error:
            if error.errno == errno.EIO:
                return False
            raise
        if not data:
            return False
        # PTYs and terminals are ordered byte streams.  Forward every read
        # immediately; an escape sequence may span any number of reads, socket
        # frames, or terminal writes without requiring application buffering.
        self._forward_master_output(data, selector)
        return True

    def _write_master(self, selector: selectors.BaseSelector) -> None:
        if not self._master_out:
            self._master_events(selector)
            return
        try:
            written = os.write(self.master_fd, self._master_out)
        except BlockingIOError:
            return
        if written > 0:
            del self._master_out[:written]
        self._master_events(selector)

    def _authentication_timeout(self) -> float | None:
        """Return the sole broker selector deadline, if one is active."""
        if self._client is None or self._client_authenticated or self._client_deadline is None:
            return None
        return max(0.0, self._client_deadline - time.monotonic())

    def _expire_unauthenticated_client(self, selector: selectors.BaseSelector) -> None:
        if (
            self._client is not None
            and not self._client_authenticated
            and self._client_deadline is not None
            and time.monotonic() >= self._client_deadline
        ):
            self._drop_client(selector)

    def _run(self) -> None:
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.master_fd, selectors.EVENT_READ, "master")
            selector.register(self._listener, selectors.EVENT_READ, "listener")
            selector.register(self._wake_r, selectors.EVENT_READ, "wake")
            running = True
            while running and not self._stop.is_set():
                self._expire_unauthenticated_client(selector)
                timeout = self._authentication_timeout()
                ready = selector.select(timeout)
                # If the authentication deadline and socket readiness race,
                # the deadline wins.  Any selected key for the dropped client
                # is harmlessly ignored below.
                self._expire_unauthenticated_client(selector)
                for key, mask in ready:
                    if key.data == "wake":
                        try:
                            while os.read(self._wake_r, 4096):
                                pass
                        except (BlockingIOError, OSError):
                            pass
                        with self._condition:
                            disconnect = self._disconnect_requested
                        if disconnect:
                            self._close_client(selector)
                    elif key.data == "listener":
                        self._accept(selector)
                    elif key.data == "master":
                        if mask & selectors.EVENT_READ:
                            running = self._read_master(selector)
                        if running and mask & selectors.EVENT_WRITE:
                            self._write_master(selector)
                    elif key.data == "client" and self._client is not None:
                        if mask & selectors.EVENT_READ:
                            self._read_client(selector)
                        if mask & selectors.EVENT_WRITE and self._client is not None:
                            self._write_client(selector)
                    if not running or self._stop.is_set():
                        break
        except BaseException as error:
            self._error = error
        finally:
            if self._client is not None:
                self._close_client(selector)
            selector.close()
            self._cleanup()

    def _cleanup(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._connected = False
            self._condition.notify_all()
        for obj in (self._listener, self._client):
            if obj is not None:
                try:
                    obj.close()
                except OSError:
                    pass
        self._client = None
        for fd_name in ("master_fd", "_slave_fd", "_wake_r", "_wake_w"):
            fd = getattr(self, fd_name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_name, -1)
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        try:
            os.rmdir(self._tmpdir)
        except OSError:
            pass


class Console:
    """Lifecycle handle for one attached GDB console UI."""

    def __init__(
        self,
        *,
        mode: ConsoleMode,
        tty: str,
        gdb,
        config: ConsoleConfig,
        resize_worker: _LatestResizeWorker,
        broker: _OwnedPtyBroker | None = None,
        watcher: _BorrowedResizeWatcher | _CurrentResizeWatcher | None = None,
        borrowed_lost: threading.Event | None = None,
    ):
        self.mode = mode
        self.tty = tty
        self.session_id = broker.session_id if broker is not None else None
        self.proc = None  # legacy alias for an externally spawned viewer
        self.keep_open = False
        self._gdb = gdb
        self._config = config
        self._resize_worker = resize_worker
        self._broker = broker
        self._watcher = watcher
        self._borrowed_lost = borrowed_lost
        self._closed = False
        self._viewer_config: ViewerConfig | None = None
        self._viewer_terminal_state = None
        self._lock = threading.RLock()

    @property
    def detachable(self) -> bool:
        return self.mode is ConsoleMode.OWNED

    @property
    def endpoint_alive(self) -> bool:
        if self.mode is ConsoleMode.OWNED:
            return self._broker is not None and self._broker.alive
        # GDB has no API for deleting a secondary CLI UI.  Releasing pwnc's
        # resize watcher therefore does not detach a borrowed current/target
        # terminal; keep representing that UI until the whole session closes.
        return not getattr(self._gdb, "_closed", False) and (
            self._borrowed_lost is None or not self._borrowed_lost.is_set()
        )

    @property
    def viewer_connected(self) -> bool:
        return self._broker is not None and self._broker.connected

    @property
    def viewer_process(self):
        return self.proc

    @property
    def viewer_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def alive(self):
        """Compatibility predicate used by the existing ``Gdb.console`` API."""
        return self.endpoint_alive

    def _same_tty(self, value) -> bool:
        try:
            if isinstance(value, int):
                candidate = os.ttyname(value)
            else:
                candidate = os.fspath(value)
            return os.path.samefile(self.tty, candidate)
        except (OSError, TypeError, ValueError):
            return False

    def _check_explicit_config(self, config: ConsoleConfig) -> None:
        if config.mode is ConsoleMode.NONE:
            raise ValueError("cannot replace a live console endpoint with none mode")
        if config.mode is not self.mode:
            raise ValueError("console endpoint already uses %s mode, not %s" % (self.mode.value, config.mode.value))
        if config.save_history != self._config.save_history:
            raise ValueError("console endpoint save_history setting cannot be changed")
        if self.mode in (ConsoleMode.CURRENT, ConsoleMode.TARGET):
            if not self._same_tty(config.tty):
                raise ValueError("console endpoint is attached to a different tty")
            return
        existing = self._config
        if (
            config.initial_rows != existing.initial_rows
            or config.initial_cols != existing.initial_cols
            or config.backlog_bytes != existing.backlog_bytes
        ):
            raise ValueError("owned console endpoint geometry/backlog cannot be reconfigured in place")

    def reuse(
        self,
        terminal=None,
        *,
        timeout: float = 10.0,
        keep_open: bool = False,
    ) -> "Console":
        """Validate a repeated public request and reconnect its viewer if needed."""
        explicit = isinstance(terminal, ConsoleConfig)
        if explicit:
            config = terminal
            self._check_explicit_config(config)
            viewer = config.viewer
        else:
            if self.mode is not ConsoleMode.OWNED:
                if terminal is not None or keep_open:
                    raise ValueError("a borrowed console endpoint cannot be replaced by a viewer")
                return self
            viewer = ViewerConfig.external(terminal, keep_open=keep_open)

        if self.mode is not ConsoleMode.OWNED or viewer is None:
            return self
        if self.viewer_connected:
            # A no-argument compatibility call is an idempotent lookup.  An
            # explicit replacement request while connected is an error rather
            # than silently ignoring a materially different terminal.
            replacing = explicit or terminal is not None or keep_open
            if replacing and viewer != self._viewer_config:
                raise ValueError("a different console viewer is already connected")
            return self
        self.attach_viewer(viewer, timeout=timeout)
        return self

    def _bridge_argv(self, viewer: ViewerConfig) -> list[str]:
        bridge = os.path.join(os.path.dirname(__file__), "_console_bridge.py")
        argv = [
            sys.executable,
            bridge,
            self._broker.socket_path,
            # URL-safe tokens may begin with ``-``; use --name=value so
            # argparse never mistakes the value for another option.
            "--token=" + self._broker.token,
            "--session=" + self._broker.session_id,
        ]
        if viewer.keep_open:
            argv.append("--keep-open")
        return argv

    def attach_viewer(self, viewer: ViewerConfig, *, timeout: float = 10.0):
        if self.mode is not ConsoleMode.OWNED or self._broker is None:
            raise RuntimeError("only owned console endpoints support bridge viewers")
        if not isinstance(viewer, ViewerConfig):
            raise TypeError("viewer must be a ViewerConfig")
        with self._lock:
            if self._closed:
                raise RuntimeError("console endpoint is closed")
            if self._broker.connected:
                return self.proc
            if self.viewer_alive:
                raise RuntimeError("a console viewer is already starting")
            # Restore an uncleanly exited inherited viewer before taking the
            # next baseline.  Otherwise a reconnect could remember
            # raw/nonblocking state as the state it should restore later.
            self._restore_viewer_terminal(self.proc)
            argv = self._bridge_argv(viewer)
            if viewer.mode in (ViewerMode.CURRENT, ViewerMode.TARGET):
                proc, terminal_snapshot = _spawn_terminal_bridge(argv, viewer)
            else:
                terminal_snapshot = None
                launcher = viewer.launcher
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
                if terminal_snapshot is not None:
                    terminal_snapshot.restore()
                raise TypeError("terminal launcher did not return a Popen-like process")
            self.proc = proc
            self.keep_open = viewer.keep_open
            self._viewer_config = viewer
            if terminal_snapshot is not None:
                self._viewer_terminal_state = (proc, terminal_snapshot)
                monitor = threading.Thread(
                    target=self._monitor_viewer_terminal,
                    args=(proc,),
                    name="pwnc-console-terminal-restore",
                    daemon=True,
                )
                try:
                    monitor.start()
                except BaseException:
                    # Detach and endpoint cleanup retain the snapshot, so a
                    # convenience-monitor startup failure is still recoverable.
                    pass
        try:
            self._broker.wait_connected(float(timeout))
            rows, cols = self._broker.current_size
            # HELLO geometry is committed by the broker before it marks the
            # connection live.  Apply it synchronously so reconnect callers do
            # not observe a stale GDB width/height after attach_viewer returns.
            self._resize_worker.apply_sync(rows, cols)
        except BaseException:
            self._stop_viewer(proc, timeout=2.0)
            with self._lock:
                if self.proc is proc:
                    self.proc = None
                    self._viewer_config = None
            raise
        return proc

    def _monitor_viewer_terminal(self, proc) -> None:
        try:
            proc.wait()
        except Exception:
            pass
        finally:
            self._restore_viewer_terminal(proc)

    def _restore_viewer_terminal(self, proc=None) -> None:
        with self._lock:
            state = self._viewer_terminal_state
            if state is None or (proc is not None and state[0] is not proc):
                return
            self._viewer_terminal_state = None
            _state_proc, snapshot = state
            # Publication of the cleared state and completion of restoration
            # are one lifecycle transition.  A process-monitor thread may race
            # close()/dispose_endpoint() here; keeping the lock until restore
            # finishes prevents the synchronous caller from observing ``None``
            # and returning while terminal flags are still raw/nonblocking.
            snapshot.restore()

    def _stop_viewer(self, proc, *, timeout: float = 2.0) -> None:
        """Give the bridge a cleanup signal before using SIGKILL as fallback."""
        if proc is None:
            self._restore_viewer_terminal(proc)
            return
        if proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                wait_process(proc, timeout)
            except Exception:
                pass
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                wait_process(proc, timeout)
            except Exception:
                pass
        self._restore_viewer_terminal(proc)

    def detach_viewer(self, *, timeout: float = 3.0) -> None:
        """Close the displayed viewer while retaining GDB's owned PTY/UI."""
        if self.mode is not ConsoleMode.OWNED or self._broker is None:
            raise RuntimeError("a borrowed GDB console UI cannot be detached")
        with self._lock:
            if self._closed:
                return
            proc = self.proc
        first_error = None
        try:
            self._broker.detach_client(timeout=timeout)
        except BaseException as error:
            first_error = error
        # Sever the protocol lane first, then stop the launcher.  The bridge
        # gets a normal CLOSE/signal cleanup path; SIGKILL is only a bounded
        # fallback and the parent snapshot covers even that case.
        self._stop_viewer(proc, timeout=min(2.0, timeout))
        if first_error is not None:
            raise first_error

    def close(self):
        """Close an owned viewer; borrowed UIs remain monitored until GDB exits.

        An owned PTY remains attached and drained until GDB exits because GDB
        persists real CLI history only when an interactive UI still exists at
        quit.  Current/target UIs cannot be detached, and their watcher must
        remain alive to detect a later external terminal hangup truthfully.
        """
        if self.mode is ConsoleMode.OWNED:
            self.detach_viewer()
        return

    def _dispose_resources(self, *, force_viewer: bool) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            proc = self.proc
        first_error = None
        for resource in (self._watcher, self._broker, self._resize_worker):
            if resource is None:
                continue
            try:
                resource.close()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if proc is not None and (force_viewer or not self.keep_open):
            self._stop_viewer(proc, timeout=2.0)
        else:
            self._restore_viewer_terminal(proc)
        if first_error is not None:
            raise first_error

    def dispose_endpoint(self):
        if not self.detachable:
            raise RuntimeError("GDB cannot detach a borrowed console UI")
        self._dispose_resources(force_viewer=False)

    def _abort(self) -> None:
        """Construction/session-race cleanup which never honors keep_open."""
        self._dispose_resources(force_viewer=True)

    def kill(self):
        """Force the current viewer down while retaining an owned endpoint."""
        proc = self.proc
        self.detach_viewer(timeout=2.0)
        self._stop_viewer(proc, timeout=2.0)


def _attach_new_ui(gdb, tty, save_history, timeout):
    """Claim early output and transactionally attach one secondary GDB UI."""
    transport = gdb.transport
    claim = getattr(transport, "claim_startup_output", None)
    restore = getattr(transport, "restore_startup_output", None)
    claimed = callable(claim)
    startup_output = claim(timeout=timeout) if claimed else ""
    arguments = {"tty": tty, "save_history": save_history}
    if startup_output:
        arguments["startup_output"] = startup_output
    try:
        return transport.request("pwncNewUI", arguments)
    except BaseException as attach_error:
        if claimed and callable(restore):
            try:
                restore(startup_output)
            except BaseException as restore_error:  # noqa: BLE001 - preserve attach error
                add_note = getattr(attach_error, "add_note", None)
                if callable(add_note):
                    add_note(
                        "also failed to restore GDB startup output: "
                        f"{type(restore_error).__name__}: {restore_error}"
                    )
        raise


def open_console(gdb, config: ConsoleConfig, *, timeout: float = 10.0):
    """Attach the console described by *config* to *gdb*."""
    if not isinstance(config, ConsoleConfig):
        raise TypeError("config must be a ConsoleConfig")
    if config.mode is ConsoleMode.NONE:
        return None

    resize_worker = _LatestResizeWorker(gdb)
    if config.mode in (ConsoleMode.CURRENT, ConsoleMode.TARGET):
        watcher = None
        borrowed_lost = threading.Event()
        try:
            tty_path, tty_fd = _resolve_tty(config.tty)
            rows, cols = _winsize(tty_fd)
            if rows and cols:
                resize_worker.apply_sync(rows, cols)
            _attach_new_ui(
                gdb,
                tty_path,
                config.save_history,
                timeout,
            )
            handle = Console(
                mode=config.mode,
                tty=tty_path,
                gdb=gdb,
                config=config,
                resize_worker=resize_worker,
                borrowed_lost=borrowed_lost,
            )
            if config.mode is ConsoleMode.CURRENT and _is_foreground_process_tty(tty_fd):
                try:
                    watcher = _CurrentResizeWatcher(
                        tty_fd,
                        resize_worker.submit,
                        borrowed_lost.set,
                    )
                except _SigwinchUnavailable:
                    # A current console may be opened before the main thread
                    # has installed the shared relay, or another component may
                    # replace it later.  Use the event-driven borrowed helper.
                    watcher = None
            if watcher is None:
                watcher = _BorrowedResizeWatcher(
                    tty_fd,
                    resize_worker.submit,
                    borrowed_lost.set,
                )
            handle._watcher = watcher
            return handle
        except BaseException:
            if watcher is not None:
                watcher.close()
            else:
                try:
                    os.close(tty_fd)
                except (NameError, OSError):
                    pass
            resize_worker.close()
            raise

    broker = None
    handle = None
    try:
        broker = _OwnedPtyBroker(
            resize_worker.submit,
            initial_size=(config.initial_rows, config.initial_cols),
            backlog_bytes=config.backlog_bytes,
        )
        # GDB may render an arbitrarily large prompt as part of ``new-ui``
        # (GEF and other plugins install prompt hooks).  Drain the PTY before
        # asking GDB to open its slave, while our retained slave descriptor
        # keeps the master from observing a premature EIO.  Starting after the
        # synchronous request would let a prompt larger than the kernel PTY
        # buffer block GDB's main thread before it can send the DAP response.
        broker.start()
        handle = Console(
            mode=config.mode,
            tty=broker.tty,
            gdb=gdb,
            config=config,
            resize_worker=resize_worker,
            broker=broker,
        )
        if config.viewer is not None:
            # Start the viewer first: its authenticated HELLO carries the real
            # terminal geometry, which attach_viewer applies synchronously.
            handle.attach_viewer(config.viewer, timeout=timeout)
        else:
            resize_worker.apply_sync(config.initial_rows, config.initial_cols)
        _attach_new_ui(
            gdb,
            broker.tty,
            config.save_history,
            timeout,
        )
        broker.release_slave()
        return handle
    except BaseException:
        if handle is not None:
            handle._abort()
        elif broker is not None:
            broker.close()
            resize_worker.close()
        else:
            resize_worker.close()
        raise


def start_console(gdb, terminal=None, timeout=10, keep_open=False):
    """Compatibility entry point plus explicit-config dispatch.

    Passing a :class:`ConsoleConfig` selects the new API.  Historical string or
    argv values still mean "owned PTY displayed in an external terminal".
    """
    if isinstance(terminal, ConsoleConfig):
        return open_console(gdb, terminal, timeout=timeout)
    viewer = ViewerConfig.external(terminal, keep_open=keep_open)
    return open_console(gdb, ConsoleConfig.owned(viewer=viewer), timeout=timeout)


__all__ = [
    "ArgvTerminalLauncher",
    "Console",
    "ConsoleConfig",
    "ConsoleMode",
    "TerminalLauncher",
    "ViewerConfig",
    "ViewerMode",
    "open_console",
    "start_console",
]
