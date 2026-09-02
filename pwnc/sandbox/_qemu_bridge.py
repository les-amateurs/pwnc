"""Private, event-driven bridge for a qemu-user guest GDB stub.

QEMU's user-mode ``-g`` option accepts an AF_UNIX pathname.  The sandbox
mounts a fresh per-instance directory at ``/run/pwnc/debug`` and keeps that
socket private, while this bridge publishes one atomically reserved loopback
TCP endpoint for host GDB.  No container TCP listener or readiness polling is
needed.
"""

from __future__ import annotations

import ctypes
import errno
import os
import selectors
import shutil
import socket
import stat
import struct
import threading
from pathlib import Path

from .errors import SandboxBackendError

_IN_ATTRIB = 0x00000004
_IN_CLOSE_WRITE = 0x00000008
_IN_MOVED_TO = 0x00000080
_IN_CREATE = 0x00000100
_IN_DELETE = 0x00000200
_IN_DELETE_SELF = 0x00000400
_IN_MOVE_SELF = 0x00000800
_WATCH_MASK = _IN_ATTRIB | _IN_CLOSE_WRITE | _IN_MOVED_TO | _IN_CREATE | _IN_DELETE | _IN_DELETE_SELF | _IN_MOVE_SELF
_INOTIFY_EVENT = struct.Struct("iIII")


def _make_owned_tree_removable(directory: Path) -> None:
    """Restore owner traversal without following guest-created symlinks."""

    try:
        directory.chmod(0o700)
    except FileNotFoundError:
        return
    for root, directories, _files in os.walk(directory, topdown=True, followlinks=False):
        for name in directories:
            candidate = Path(root, name)
            try:
                mode = candidate.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(mode):
                candidate.chmod(0o700)


def _retry_owned_remove(function, path: str, exception) -> None:
    """Retry only permission-failed unlink/rmdir operations in the owned tree."""

    error = exception[1]
    if not isinstance(error, PermissionError) or function not in {os.unlink, os.rmdir}:
        raise error
    candidate = Path(path)
    mode = candidate.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise error
    candidate.chmod(0o700 if stat.S_ISDIR(mode) else 0o600)
    function(path)


def _libc_function(name: str, argtypes, restype):
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, name, None)
    if function is None:
        raise SandboxBackendError(f"Linux {name} is unavailable; qemu-user sandbox debugging requires inotify")
    function.argtypes = argtypes
    function.restype = restype
    return function


class _DirectoryWatch:
    """Own one inotify watch established before QEMU can create its socket."""

    def __init__(self, directory: Path):
        init = _libc_function("inotify_init1", [ctypes.c_int], ctypes.c_int)
        add = _libc_function("inotify_add_watch", [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32], ctypes.c_int)
        descriptor = init(os.O_CLOEXEC | os.O_NONBLOCK)
        if descriptor < 0:
            number = ctypes.get_errno()
            raise SandboxBackendError(f"cannot create qemu GDB socket watch: {os.strerror(number)}")
        try:
            encoded = os.fsencode(directory)
            if add(descriptor, encoded, _WATCH_MASK) < 0:
                number = ctypes.get_errno()
                raise SandboxBackendError(f"cannot watch qemu GDB socket directory: {os.strerror(number)}")
        except BaseException:
            os.close(descriptor)
            raise
        self.descriptor = descriptor

    def fileno(self) -> int:
        return self.descriptor

    def drain(self) -> None:
        while True:
            try:
                data = os.read(self.descriptor, 64 * 1024)
            except BlockingIOError:
                return
            if not data:
                return
            cursor = 0
            while cursor + _INOTIFY_EVENT.size <= len(data):
                _watch, _mask, _cookie, name_length = _INOTIFY_EVENT.unpack_from(data, cursor)
                cursor += _INOTIFY_EVENT.size + name_length

    def close(self) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


class QemuGdbBridge:
    """Bridge a loopback TCP listener to one exact QEMU AF_UNIX stub."""

    BUFFER_SIZE = 64 * 1024

    def __init__(self, directory: Path, *, host: str = "127.0.0.1", host_port: int | None = None):
        self.directory = Path(directory).absolute()
        try:
            self.directory.mkdir(mode=0o700)
        except FileExistsError as error:
            raise SandboxBackendError(f"qemu GDB runtime directory already exists: {self.directory}") from error
        os.chmod(self.directory, 0o700)
        self.socket_path = self.directory / "gdb.sock"

        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((host, host_port or 0))
            listener.listen(1)
        except BaseException:
            listener.close()
            self.directory.rmdir()
            raise

        self.host = host
        self.host_port = int(listener.getsockname()[1])
        self._listener = listener
        try:
            self._watch = _DirectoryWatch(self.directory)
            self._wake_r, self._wake_w = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except BaseException:
            listener.close()
            watch = getattr(self, "_watch", None)
            if watch is not None:
                watch.close()
            self.directory.rmdir()
            raise
        self._condition = threading.Condition(threading.RLock())
        self._close_lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._thread: threading.Thread | None = None
        self._expected_pid: int | None = None
        self._ready = False
        self._closing = False
        self._closed = False
        self._error: BaseException | None = None

    @property
    def error(self) -> BaseException | None:
        with self._condition:
            return self._error

    @property
    def ready(self) -> bool:
        with self._condition:
            return self._ready

    def authorize(self, expected_pid: int) -> None:
        if isinstance(expected_pid, bool) or not isinstance(expected_pid, int) or expected_pid <= 0:
            raise ValueError("expected QEMU PID must be a positive integer")
        with self._condition:
            if self._closing or self._closed:
                raise SandboxBackendError("qemu GDB bridge is closed")
            if self._thread is not None:
                raise SandboxBackendError("qemu GDB bridge is already authorized")
            self._expected_pid = expected_pid
            thread = threading.Thread(target=self._run, name=f"pwnc-qemu-gdb-{self.host_port}", daemon=True)
            self._thread = thread
            thread.start()

    def wait_ready(self, timeout: float | None, *, cancelled=None) -> None:
        if cancelled is not None and not callable(cancelled):
            raise TypeError("cancelled must be callable or None")
        with self._condition:
            available = self._condition.wait_for(
                lambda: (
                    self._ready
                    or self._error is not None
                    or self._closing
                    or self._closed
                    or (cancelled is not None and cancelled())
                ),
                timeout,
            )
            if not available:
                raise TimeoutError("timed out waiting for qemu-user GDB stub")
            if self._error is not None:
                raise SandboxBackendError(f"qemu-user GDB bridge failed: {self._error}") from self._error
            if cancelled is not None and cancelled():
                raise SandboxBackendError("qemu-user exited before its GDB stub became ready")
            if not self._ready:
                raise SandboxBackendError("qemu-user GDB bridge closed before its stub became ready")

    def wake_waiters(self) -> None:
        """Re-evaluate owner-side terminal/cancellation state without polling."""

        with self._condition:
            self._condition.notify_all()

    def _socket_exists(self) -> bool:
        try:
            mode = self.socket_path.lstat().st_mode
        except FileNotFoundError:
            return False
        if not stat.S_ISSOCK(mode):
            raise SandboxBackendError(f"qemu GDB endpoint is not a Unix socket: {self.socket_path}")
        return True

    @staticmethod
    def _shutdown(endpoint: socket.socket, how: int = socket.SHUT_RDWR) -> None:
        try:
            endpoint.shutdown(how)
        except OSError:
            pass

    def _track(self, endpoint: socket.socket) -> None:
        with self._condition:
            if self._closing:
                endpoint.close()
                raise SandboxBackendError("qemu GDB bridge is closing")
            self._connections.add(endpoint)

    def _untrack_close(self, endpoint: socket.socket) -> None:
        self._shutdown(endpoint)
        try:
            endpoint.close()
        finally:
            with self._condition:
                self._connections.discard(endpoint)

    def _connect_stub(self) -> socket.socket:
        option = getattr(socket, "SO_PEERCRED", None)
        if option is None:
            raise SandboxBackendError("Linux SO_PEERCRED is unavailable; cannot verify qemu GDB peer identity")
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._track(upstream)
        try:
            upstream.connect(os.fspath(self.socket_path))
            credentials = upstream.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", credentials)
            if pid != self._expected_pid or uid != os.getuid():
                raise SandboxBackendError(
                    "qemu GDB Unix peer identity mismatch: "
                    f"peer={pid}:{uid}, expected={self._expected_pid}:{os.getuid()}"
                )
            return upstream
        except BaseException:
            self._untrack_close(upstream)
            raise

    def _pump(self, source: socket.socket, destination: socket.socket) -> None:
        try:
            while True:
                data = source.recv(self.BUFFER_SIZE)
                if not data:
                    self._shutdown(destination, socket.SHUT_WR)
                    return
                destination.sendall(data)
        except OSError:
            self._shutdown(source)
            self._shutdown(destination)

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        workers = (
            threading.Thread(target=self._pump, args=(client, upstream), name="pwnc-qemu-gdb-upload", daemon=True),
            threading.Thread(target=self._pump, args=(upstream, client), name="pwnc-qemu-gdb-download", daemon=True),
        )
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

    def _run(self) -> None:
        selector = selectors.DefaultSelector()
        try:
            self._listener.setblocking(False)
            self._wake_r.setblocking(False)
            selector.register(self._listener, selectors.EVENT_READ, "listener")
            selector.register(self._watch, selectors.EVENT_READ, "watch")
            selector.register(self._wake_r, selectors.EVENT_READ, "wake")
            if self._socket_exists():
                with self._condition:
                    self._ready = True
                    self._condition.notify_all()
            while True:
                for key, _events in selector.select():
                    if key.data == "wake":
                        return
                    if key.data == "watch":
                        self._watch.drain()
                        exists = self._socket_exists()
                        with self._condition:
                            self._ready = exists
                            self._condition.notify_all()
                        continue
                    if key.data != "listener":
                        continue
                    client, _address = self._listener.accept()
                    self._track(client)
                    try:
                        if not self._socket_exists():
                            # GDB connected before QEMU bound its endpoint.
                            # Wait on inotify rather than retrying or sleeping.
                            while not self._socket_exists():
                                events = selector.select()
                                if any(event_key.data == "wake" for event_key, _mask in events):
                                    return
                                if any(event_key.data == "watch" for event_key, _mask in events):
                                    self._watch.drain()
                        with self._condition:
                            self._ready = True
                            self._condition.notify_all()
                        upstream = self._connect_stub()
                        try:
                            self._relay(client, upstream)
                        finally:
                            self._untrack_close(upstream)
                    finally:
                        self._untrack_close(client)
        except BaseException as error:  # noqa: BLE001 - publish to owner
            with self._condition:
                if not self._closing:
                    self._error = error
                    self._condition.notify_all()
        finally:
            selector.close()

    def close(self) -> None:
        with self._close_lock:
            with self._condition:
                if self._closed:
                    return
                self._closing = True
                connections = tuple(self._connections)
                thread = self._thread
                self._condition.notify_all()
            self._shutdown(self._wake_w)
            self._shutdown(self._listener)
            self._listener.close()
            for endpoint in connections:
                self._untrack_close(endpoint)
            if thread is not None and thread is not threading.current_thread():
                thread.join()
            self._watch.close()
            for endpoint in (self._wake_r, self._wake_w):
                try:
                    endpoint.close()
                except OSError:
                    pass
            try:
                # This directory is freshly and exclusively created by the
                # bridge, but must be writable by QEMU inside the container.
                # Remove the complete owned tree so guest-created debris
                # cannot make lifecycle cleanup permanently fail.  On Linux,
                # shutil uses fd-relative traversal and does not follow
                # attacker-controlled symlinks out of this directory.
                _make_owned_tree_removable(self.directory)
                shutil.rmtree(self.directory, onerror=_retry_owned_remove)
            except FileNotFoundError:
                pass
            with self._condition:
                self._closed = True
                self._condition.notify_all()


__all__ = ["QemuGdbBridge"]
