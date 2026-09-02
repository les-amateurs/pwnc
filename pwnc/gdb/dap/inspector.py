"""Event-driven JSON publisher for the standalone native runtime viewer."""

from __future__ import annotations

import errno
import json
import os
import select
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .discovery import _os_error_reason
from .history import RuntimeEvent, RuntimeSnapshot


PROTOCOL_NAME = "pwnc-runtime"
PROTOCOL_VERSION = 1
DEFAULT_QUEUE_MESSAGES = 256
MAX_MESSAGE_BYTES = 16 * 1024 * 1024


class ViewerConnectionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ViewerStats:
    connected: bool
    queued: int
    dropped_events: int
    dropped_snapshots: int
    sent_messages: int
    send_failures: int


@dataclass(frozen=True, slots=True)
class _OutboundItem:
    kind: str
    value: object


class _OutboundQueue:
    """Bounded condition queue that preserves newest snapshots under pressure."""

    def __init__(self, limit: int):
        if limit <= 0:
            raise ValueError("viewer queue limit must be positive")
        self._limit = limit
        self._condition = threading.Condition()
        self._items: deque[_OutboundItem] = deque()
        self._closed = False
        self._dropped_events = 0
        self._dropped_snapshots = 0

    def put(self, item: _OutboundItem, *, first: bool = False) -> bool:
        with self._condition:
            if self._closed:
                return False
            if len(self._items) >= self._limit:
                if item.kind == "event":
                    self._dropped_events += 1
                    return False
                removed = self._remove_first("event")
                if removed:
                    self._dropped_events += 1
                elif item.kind == "snapshot" and self._remove_first("snapshot"):
                    self._dropped_snapshots += 1
                elif item.kind == "hello" and self._remove_first("hello"):
                    pass
                elif item.kind == "hello" and self._remove_first("snapshot"):
                    self._dropped_snapshots += 1
                else:
                    if item.kind == "snapshot":
                        self._dropped_snapshots += 1
                    return False
            (self._items.appendleft if first else self._items.append)(item)
            self._condition.notify()
            return True

    def _remove_first(self, kind: str) -> bool:
        for index, queued in enumerate(self._items):
            if queued.kind == kind:
                del self._items[index]
                return True
        return False

    def get(self) -> _OutboundItem | None:
        with self._condition:
            self._condition.wait_for(lambda: self._items or self._closed)
            if not self._items:
                return None
            return self._items.popleft()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    @property
    def size(self) -> int:
        with self._condition:
            return len(self._items)

    @property
    def dropped_events(self) -> int:
        with self._condition:
            return self._dropped_events

    @property
    def dropped_snapshots(self) -> int:
        with self._condition:
            return self._dropped_snapshots


class RuntimeViewer:
    """Publish one GDB runtime session without blocking its DAP reader."""

    def __init__(self, runtime, *, queue_messages: int = DEFAULT_QUEUE_MESSAGES):
        self._runtime = runtime
        self._session_id = str(uuid.uuid4())
        self._queue = _OutboundQueue(queue_messages)
        self._socket_lock = threading.Lock()
        self._socket: socket.socket | None = None
        self._socket_epoch = 0
        self._connected = threading.Event()
        self._start_lock = threading.Lock()
        self._closed = False
        self._unsubscribe = None
        self._worker: threading.Thread | None = None
        self._sent_messages = 0
        self._send_failures = 0
        self._previous_snapshot: RuntimeSnapshot | None = None
        self._announced_epoch = -1
        self._viewer_process: subprocess.Popen | None = None
        self._owned_socket_directory: str | None = None
        self._socket_path: str | None = None

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    @property
    def stats(self) -> ViewerStats:
        return ViewerStats(
            self.connected,
            self._queue.size,
            self._queue.dropped_events,
            self._queue.dropped_snapshots,
            self._sent_messages,
            self._send_failures,
        )

    def connect(self, socket_path=None, *, capture: bool = True) -> "RuntimeViewer":
        if self._closed:
            raise ViewerConnectionError("runtime viewer publisher is closed")
        path, source = _resolve_viewer_socket(socket_path)
        self._ensure_started()
        connection = None
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.connect(path)
        except OSError as error:
            if connection is not None:
                connection.close()
            reasons = {
                errno.ENOENT: (
                    "no viewer socket exists there; start one with viewer.open(), "
                    "run pwnc-runtime-viewer, or correct the socket setting"
                ),
                errno.ECONNREFUSED: (
                    "the socket refused the connection; it may be stale or the "
                    "native viewer may have exited"
                ),
                errno.EACCES: "permission was denied; check the socket and parent-directory permissions",
                errno.EPERM: "the operation was not permitted; check the socket permissions",
                errno.ENOTSOCK: "the endpoint exists but is not a Unix socket",
                errno.ETIMEDOUT: "the connection timed out while waiting for the native viewer",
            }
            reason = reasons.get(error.errno)
            if reason is None:
                reason = _os_error_reason(error)
            raise ViewerConnectionError(
                f"cannot connect to native runtime viewer at {path!r} "
                f"(resolved from {source}): {reason}"
            ) from error
        with self._socket_lock:
            previous, self._socket = self._socket, connection
            self._socket_epoch += 1
            self._socket_path = path
            self._connected.set()
        if previous is not None:
            try:
                previous.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            previous.close()
        self._queue.put(_OutboundItem("hello", None), first=True)
        for snapshot in self._runtime.history:
            self._queue.put(_OutboundItem("snapshot", snapshot))
        if capture:
            self._runtime.history.snapshot("viewer-connect")
        return self

    def reconnect(self, socket_path=None, *, capture: bool = False) -> "RuntimeViewer":
        return self.connect(self._socket_path if socket_path is None else socket_path, capture=capture)

    def disconnect(self) -> None:
        """Disconnect without discarding session identity or retained history."""

        self._disconnect_socket()

    def open(
        self,
        executable=None,
        *,
        socket_path=None,
        timeout: float = 10.0,
        capture: bool = True,
    ) -> "RuntimeViewer":
        if self.connected:
            return self
        executable = _viewer_executable(executable)
        if socket_path is None:
            directory = tempfile.mkdtemp(prefix="pwnc-runtime-viewer-")
            self._owned_socket_directory = directory
            socket_path = os.path.join(directory, "viewer.sock")
        else:
            socket_path = os.path.abspath(os.fsdecode(socket_path))
        ready_read, ready_write = os.pipe()
        try:
            process = subprocess.Popen(
                [executable, "--socket", socket_path, "--ready-fd", str(ready_write)],
                close_fds=True,
                pass_fds=(ready_write,),
            )
            self._viewer_process = process
        except BaseException:
            os.close(ready_read)
            os.close(ready_write)
            self._cleanup_owned_directory()
            raise
        os.close(ready_write)
        try:
            readable, _, _ = select.select([ready_read], [], [], timeout)
            if not readable or os.read(ready_read, 1) != b"R":
                status = process.poll()
                reason = "exited" if status is not None else "did not signal readiness"
                if status is None:
                    process.terminate()
                    try:
                        process.wait(3.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                self._viewer_process = None
                self._cleanup_owned_directory()
                raise ViewerConnectionError(f"native viewer {reason} before its socket became ready")
        finally:
            os.close(ready_read)
        try:
            return self.connect(socket_path, capture=capture)
        except BaseException:
            self.stop_viewer()
            raise

    def publish(self, snapshot: RuntimeSnapshot | None = None, *, name: str | None = None, **capture_options):
        if snapshot is None:
            snapshot = self._runtime.history.snapshot(name, **capture_options)
        elif not isinstance(snapshot, RuntimeSnapshot):
            raise TypeError("publish() requires a RuntimeSnapshot or capture options")
        else:
            self._queue.put(_OutboundItem("snapshot", snapshot))
        return snapshot

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._unsubscribe is not None:
                self._unsubscribe()
        except Exception:
            pass
        self._queue.close()
        self._disconnect_socket()
        self._connected.set()
        if self._worker is not None:
            self._worker.join(1.0)

    def stop_viewer(self) -> None:
        """Terminate only the viewer process started by this publisher."""
        process = self._viewer_process
        self._viewer_process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(3.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self._cleanup_owned_directory()

    def _cleanup_owned_directory(self) -> None:
        directory, self._owned_socket_directory = self._owned_socket_directory, None
        if directory is None:
            return
        socket_path = os.path.join(directory, "viewer.sock")
        try:
            if stat.S_ISSOCK(os.lstat(socket_path).st_mode):
                os.unlink(socket_path)
        except FileNotFoundError:
            pass
        try:
            os.rmdir(directory)
        except OSError:
            pass

    def _on_history(self, kind: str, value) -> None:
        if not self._closed:
            self._queue.put(_OutboundItem(kind, value))

    def _ensure_started(self) -> None:
        with self._start_lock:
            if self._worker is not None:
                return
            self._unsubscribe = self._runtime.history.subscribe(self._on_history)
            self._worker = threading.Thread(
                target=self._send_loop,
                name=f"pwnc-viewer-{self._session_id[:8]}",
                daemon=True,
            )
            self._worker.start()

    def _send_loop(self) -> None:
        while True:
            self._connected.wait()
            if self._closed:
                return
            item = self._queue.get()
            if item is None:
                return
            try:
                connection, epoch = self._current_socket()
                if connection is None:
                    self._queue.put(item, first=True)
                    self._connected.clear()
                    continue
                # A replacement socket can become visible after this worker
                # has already dequeued older runtime data.  Announce each
                # socket epoch here, on the sole writer thread, so no event or
                # snapshot can overtake its hello during reconnect.
                if self._announced_epoch != epoch:
                    hello = self._encode(_OutboundItem("hello", None))
                    if len(hello) > MAX_MESSAGE_BYTES:
                        raise ViewerConnectionError(
                            f"viewer hello is {len(hello)} bytes; limit is {MAX_MESSAGE_BYTES}"
                        )
                    connection.sendall(hello)
                    self._sent_messages += 1
                    self._announced_epoch = epoch
                if item.kind == "hello":
                    continue
                encoded = self._encode(item)
                if len(encoded) > MAX_MESSAGE_BYTES:
                    raise ViewerConnectionError(
                        f"viewer message is {len(encoded)} bytes; limit is {MAX_MESSAGE_BYTES}"
                    )
                connection.sendall(encoded)
                self._sent_messages += 1
            except ViewerConnectionError:
                self._send_failures += 1
            except OSError:
                self._send_failures += 1
                self._queue.put(item, first=True)
                self._disconnect_socket(connection)

    def _current_socket(self) -> tuple[socket.socket | None, int]:
        with self._socket_lock:
            return self._socket, self._socket_epoch

    def _disconnect_socket(self, expected: socket.socket | None = None) -> None:
        with self._socket_lock:
            if expected is not None and self._socket is not expected:
                connection = expected
            else:
                connection, self._socket = self._socket, None
                self._connected.clear()
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    def _encode(self, item: _OutboundItem) -> bytes:
        message = {
            "protocol": PROTOCOL_NAME,
            "version": PROTOCOL_VERSION,
            "type": item.kind,
            "session_id": self._session_id,
        }
        if item.kind == "hello":
            self._previous_snapshot = None
            message["session"] = self._session_json()
        elif item.kind == "event":
            if not isinstance(item.value, RuntimeEvent):
                raise ViewerConnectionError("event queue contained a non-event value")
            message["event"] = item.value.to_json()
        elif item.kind == "snapshot":
            if not isinstance(item.value, RuntimeSnapshot):
                raise ViewerConnectionError("snapshot queue contained a non-snapshot value")
            snapshot = item.value
            message["snapshot"] = snapshot.to_json()
            if self._previous_snapshot is not None and self._previous_snapshot.sequence != snapshot.sequence:
                message["diff_from_previous"] = self._previous_snapshot.diff(snapshot).to_json()
            self._previous_snapshot = snapshot
        elif item.kind != "goodbye":
            raise ViewerConnectionError(f"unsupported viewer message kind {item.kind!r}")
        return (json.dumps(message, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )

    def _session_json(self) -> dict:
        info = self._runtime._info()
        main = self._runtime.main
        inferior = info.get("inferior") or {}
        return {
            "id": self._session_id,
            "pid": inferior.get("pid"),
            "inferior": inferior.get("number"),
            "architecture": info.get("architecture"),
            "main": None
            if main is None
            else {"id": main.id, "path": main.path, "build_id": main.build_id, "load_bias": main.load_bias},
            "bata24": info.get("bata24") or {},
        }


def _resolve_viewer_socket(value=None) -> tuple[str, str]:
    source = "the explicit socket_path argument"
    if value is None:
        value = os.environ.get("PWNC_RUNTIME_VIEWER_SOCKET")
        source = "$PWNC_RUNTIME_VIEWER_SOCKET"
    if value is None:
        runtime = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
        value = os.path.join(runtime, f"pwnc-runtime-viewer-{os.getuid()}.sock")
        source = "the default per-user runtime socket"
    try:
        path = os.path.abspath(os.fsdecode(value))
        encoded = os.fsencode(path)
    except OSError as error:
        raise ViewerConnectionError(
            f"cannot resolve the native runtime viewer socket from {source}: "
            f"{_os_error_reason(error)}"
        ) from error
    except (TypeError, ValueError) as error:
        raise ViewerConnectionError(
            f"cannot resolve the native runtime viewer socket from {source}: {error}"
        ) from error
    if len(encoded) >= 104:
        raise ViewerConnectionError(
            f"native runtime viewer socket from {source} is too long for a Unix socket: {path}"
        )
    return path, source


def _viewer_socket_path(value=None) -> str:
    return _resolve_viewer_socket(value)[0]


def _viewer_executable(value=None) -> str:
    if value is None:
        value = os.environ.get("PWNC_RUNTIME_VIEWER")
    if value is None:
        bundled = Path(__file__).resolve().parents[3] / "native" / "runtime_viewer" / "build" / "pwnc-runtime-viewer"
        value = bundled if os.access(bundled, os.X_OK) else shutil.which("pwnc-runtime-viewer")
    if value is None:
        raise ViewerConnectionError(
            "native viewer is not built and pwnc-runtime-viewer is not on PATH; "
            "set PWNC_RUNTIME_VIEWER to its executable"
        )
    path = os.path.abspath(os.fsdecode(value))
    if not os.access(path, os.X_OK):
        raise ViewerConnectionError(f"native viewer executable is not built or executable: {path}")
    return path


__all__ = [
    "DEFAULT_QUEUE_MESSAGES",
    "MAX_MESSAGE_BYTES",
    "PROTOCOL_NAME",
    "PROTOCOL_VERSION",
    "RuntimeViewer",
    "ViewerConnectionError",
    "ViewerStats",
]
