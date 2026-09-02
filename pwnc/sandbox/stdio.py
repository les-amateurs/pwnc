"""Reconnectable, event-driven stdio bridge for manager-owned challenges."""

from __future__ import annotations

import errno
import os
import selectors
import socket
import stat
import threading
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from pwnlib.tubes.sock import sock as PwntoolsSocketTube

from .errors import SandboxBackendError
from .protocol import require_same_uid

DEFAULT_BACKLOG_BYTES = 8 * 1024 * 1024
DEFAULT_INPUT_BYTES = 2 * 1024 * 1024
_CHUNK = 64 * 1024


def _nonblocking(fd: int) -> None:
    os.set_blocking(fd, False)


def _fd(value: int | BinaryIO, label: str) -> int:
    descriptor = value if isinstance(value, int) else value.fileno()
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise ValueError(f"{label} is not an open file descriptor")
    return descriptor


def _private_socket_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode):
        raise SandboxBackendError(f"stdio endpoint exists and is not a socket: {path}")
    path.unlink()


class StdioBroker:
    """Drain target output continuously and lend one raw stream at a time.

    The manager owns the target descriptors and this broker for the complete
    sandbox lifetime.  Clients may disconnect without closing target stdin;
    output produced while no client is present remains in bounded backlog.
    Once that backlog is full, normal pipe/PTY backpressure is intentional.
    """

    def __init__(
        self,
        path,
        *,
        input_fd: int | BinaryIO,
        output_fd: int | BinaryIO,
        backlog_bytes: int = DEFAULT_BACKLOG_BYTES,
        input_bytes: int = DEFAULT_INPUT_BYTES,
        on_disconnect: Callable[[str], object] | None = None,
    ):
        self.path = Path(path).absolute()
        self.input_fd = _fd(input_fd, "target input")
        self.output_fd = _fd(output_fd, "target output")
        if isinstance(backlog_bytes, bool) or not isinstance(backlog_bytes, int) or backlog_bytes <= 0:
            raise ValueError("backlog_bytes must be a positive integer")
        if isinstance(input_bytes, bool) or not isinstance(input_bytes, int) or input_bytes <= 0:
            raise ValueError("input_bytes must be a positive integer")
        if on_disconnect is not None and not callable(on_disconnect):
            raise TypeError("on_disconnect must be callable or None")
        self.backlog_bytes = backlog_bytes
        self.input_bytes = input_bytes
        self.on_disconnect = on_disconnect

        self._condition = threading.Condition(threading.RLock())
        self._close_lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._client: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._wake_r: int | None = None
        self._wake_w: int | None = None
        self._started = False
        self._closing = False
        self._closed = False
        self._worker_done = False
        self._terminal = False
        self._error: BaseException | None = None
        self._output = deque()
        self._output_size = 0
        self._input = bytearray()

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    @property
    def connected(self) -> bool:
        with self._condition:
            return self._client is not None

    @property
    def terminal(self) -> bool:
        with self._condition:
            return self._terminal

    @property
    def error(self) -> BaseException | None:
        with self._condition:
            return self._error

    def start(self) -> StdioBroker:
        try:
            return self._start_once()
        except BaseException as error:
            # Startup can fail after listener, wake pipe, or worker creation.
            # Close outside _condition so even a partially started worker can
            # acquire the condition and observe the explicit wake event.
            try:
                self.close()
            except BaseException as cleanup_error:  # noqa: BLE001
                error.add_note(f"stdio broker rollback also failed: {cleanup_error}")
            raise

    def _start_once(self) -> StdioBroker:
        with self._condition:
            if self._closed or self._closing:
                raise SandboxBackendError("stdio broker is closed")
            if self._started:
                return self
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent = self.path.parent.stat()
            if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
                raise PermissionError(f"stdio runtime directory must be private: {self.path.parent}")
            _private_socket_path(self.path)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.setblocking(False)
            try:
                listener.bind(os.fspath(self.path))
                os.chmod(self.path, 0o600)
                listener.listen(4)
                self._wake_r, self._wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
                _nonblocking(self.input_fd)
                _nonblocking(self.output_fd)
            except BaseException:
                listener.close()
                _private_socket_path(self.path)
                raise
            self._listener = listener
            self._started = True
            self._thread = threading.Thread(
                target=self._run,
                name=f"pwnc-sandbox-stdio-{self.path.stem}",
                daemon=True,
            )
            self._thread.start()
            return self

    def _wake(self) -> None:
        descriptor = self._wake_w
        if descriptor is None:
            return
        try:
            os.write(descriptor, b"x")
        except BlockingIOError:
            pass
        except OSError:
            # A retained descriptor which cannot carry the wake event is a
            # cleanup failure.  Suppressing EBADF here could make close()
            # wait forever for a worker whose selector was never woken.
            raise

    def _set_terminal(self) -> None:
        with self._condition:
            self._terminal = True
            self._condition.notify_all()

    def _drop_client(self, selector: selectors.BaseSelector, reason: str) -> None:
        with self._condition:
            client, self._client = self._client, None
            # Bytes already accepted from a client belong to the target even
            # when that client closes immediately after send().  Retain and
            # drain them before accepting later input; otherwise a normal
            # send-then-close loses the tail nondeterministically.
            self._condition.notify_all()
        if client is not None:
            try:
                selector.unregister(client)
            except Exception:  # noqa: BLE001,S110 - selector may already have removed it
                pass
            try:
                client.close()
            except OSError:
                pass
        if self.on_disconnect is not None:
            try:
                self.on_disconnect(reason)
            except Exception:  # noqa: BLE001,S110 - lifecycle notification is advisory
                pass

    def _accept(self, selector: selectors.BaseSelector) -> None:
        listener = self._listener
        if listener is None:
            return
        try:
            client, _ = listener.accept()
        except BlockingIOError:
            return
        client.setblocking(False)
        with self._condition:
            occupied = self._client is not None
            if not occupied:
                self._client = client
                self._condition.notify_all()
        if occupied:
            try:
                client.sendall(b"pwnc sandbox stdio is already attached\n")
            except OSError:
                pass
            client.close()
            return
        selector.register(client, selectors.EVENT_READ, "client")

    def _read_target(self) -> None:
        try:
            data = os.read(self.output_fd, _CHUNK)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno in {errno.EIO, errno.EBADF}:
                data = b""
            else:
                raise
        if not data:
            self._set_terminal()
            return
        self._output.append(memoryview(data))
        self._output_size += len(data)

    def _write_client(self, selector: selectors.BaseSelector) -> None:
        client = self._client
        if client is None or not self._output:
            return
        view = self._output[0]
        try:
            sent = client.send(view)
        except BlockingIOError:
            return
        except OSError:
            self._drop_client(selector, "stdio client disconnected")
            return
        if sent <= 0:
            self._drop_client(selector, "stdio client disconnected")
            return
        self._output_size -= sent
        if sent == len(view):
            self._output.popleft()
        else:
            self._output[0] = view[sent:]

    def _read_client(self, selector: selectors.BaseSelector) -> None:
        client = self._client
        if client is None:
            return
        try:
            data = client.recv(min(_CHUNK, self.input_bytes - len(self._input)))
        except BlockingIOError:
            return
        except OSError:
            self._drop_client(selector, "stdio client disconnected")
            return
        if not data:
            self._drop_client(selector, "stdio client disconnected")
            return
        self._input.extend(data)

    def _write_target(self) -> None:
        if not self._input:
            return
        try:
            written = os.write(self.input_fd, self._input)
        except BlockingIOError:
            return
        except BrokenPipeError:
            self._input.clear()
            return
        except OSError as error:
            if error.errno in {errno.EIO, errno.EBADF}:
                self._input.clear()
                return
            raise
        if written:
            del self._input[:written]

    def _events(self, selector: selectors.BaseSelector) -> None:
        client = self._client
        if client is not None:
            mask = 0
            if len(self._input) < self.input_bytes and not self._terminal:
                mask |= selectors.EVENT_READ
            if self._output:
                mask |= selectors.EVENT_WRITE
            if mask:
                selector.modify(client, mask, "client")
        target_mask = 0
        if not self._terminal and self._output_size < self.backlog_bytes:
            target_mask |= selectors.EVENT_READ
        try:
            selector.modify(self.output_fd, target_mask or selectors.EVENT_READ, "output")
        except KeyError:
            pass
        # Registering EVENT_READ while the backlog is full would defeat
        # backpressure. Unregister until a client drains bytes instead.
        if not target_mask:
            try:
                selector.unregister(self.output_fd)
            except KeyError:
                pass
        elif self.output_fd not in selector.get_map():
            selector.register(self.output_fd, selectors.EVENT_READ, "output")

        input_mask = selectors.EVENT_WRITE if self._input else 0
        if input_mask:
            if self.input_fd in selector.get_map():
                selector.modify(self.input_fd, input_mask, "input")
            else:
                selector.register(self.input_fd, input_mask, "input")
        else:
            try:
                selector.unregister(self.input_fd)
            except KeyError:
                pass

    def _run(self) -> None:
        selector = selectors.DefaultSelector()
        try:
            selector.register(self._listener, selectors.EVENT_READ, "listener")
            selector.register(self._wake_r, selectors.EVENT_READ, "wake")
            selector.register(self.output_fd, selectors.EVENT_READ, "output")
            while True:
                with self._condition:
                    if self._closing:
                        return
                self._events(selector)
                for key, mask in selector.select():
                    if key.data == "wake":
                        try:
                            os.read(self._wake_r, _CHUNK)
                        except BlockingIOError:
                            pass
                    elif key.data == "listener":
                        self._accept(selector)
                    elif key.data == "output" and mask & selectors.EVENT_READ:
                        self._read_target()
                    elif key.data == "input" and mask & selectors.EVENT_WRITE:
                        self._write_target()
                    elif key.data == "client":
                        if mask & selectors.EVENT_READ:
                            self._read_client(selector)
                        if mask & selectors.EVENT_WRITE:
                            self._write_client(selector)
                if self._terminal and not self._output and self._client is not None:
                    try:
                        self._client.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
        except BaseException as error:  # noqa: BLE001 - publish worker failure to waiters
            with self._condition:
                self._error = error
                self._condition.notify_all()
        finally:
            self._drop_client(selector, "stdio broker closed")
            selector.close()
            with self._condition:
                self._worker_done = True
                self._condition.notify_all()

    def wait_connected(self, timeout=None) -> bool:
        with self._condition:
            return (
                self._condition.wait_for(
                    lambda: self._client is not None or self._closing or self._closed or self._error is not None,
                    timeout,
                )
                and self._client is not None
            )

    def wait_disconnected(self, timeout=None) -> bool:
        with self._condition:
            return (
                self._condition.wait_for(
                    lambda: self._client is None or self._closed or self._error is not None,
                    timeout,
                )
                and self._client is None
            )

    def wait_terminal(self, timeout=None) -> bool:
        with self._condition:
            return (
                self._condition.wait_for(
                    lambda: self._terminal or self._closing or self._closed or self._error is not None,
                    timeout,
                )
                and self._terminal
            )

    def close(self) -> None:
        with self._condition:
            if self._thread is threading.current_thread():
                # An on_disconnect callback can run on the broker worker.
                # Taking _close_lock there could deadlock an external closer
                # which already holds it while joining this exact thread.
                self._closing = True
                self._condition.notify_all()
                raise SandboxBackendError("stdio broker close must finish outside its worker thread")
        with self._close_lock:
            with self._condition:
                if self._closed:
                    return
                self._closing = True
                thread = self._thread
                self._condition.notify_all()

            failures: list[BaseException] = []
            wake_failed = False
            try:
                self._wake()
            except BaseException as error:  # noqa: BLE001 - retain exact wake descriptor for retry
                failures.append(error)
                wake_failed = True

            if thread is not None:
                if thread.is_alive() and not wake_failed:
                    # _wake() makes the selector observe _closing.  Once that
                    # explicit event is delivered, retain ownership until the
                    # worker has actually completed instead of abandoning it
                    # at an arbitrary deadline.
                    thread.join()
                if thread.is_alive():
                    if not wake_failed:
                        failures.append(SandboxBackendError("stdio broker worker did not stop after wake"))
                else:
                    self._thread = None

            if self._thread is None:
                for descriptor_name in ("_wake_r", "_wake_w"):
                    descriptor = getattr(self, descriptor_name)
                    if descriptor is None:
                        continue
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            failures.append(error)
                            continue
                    setattr(self, descriptor_name, None)

                client = self._client
                if client is not None:
                    try:
                        client.close()
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            failures.append(error)
                        else:
                            self._client = None
                    else:
                        self._client = None

                listener = self._listener
                if listener is not None:
                    try:
                        listener.close()
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            failures.append(error)
                        else:
                            self._listener = None
                    else:
                        self._listener = None

                if self._started and self._listener is None:
                    try:
                        _private_socket_path(self.path)
                    except BaseException as error:  # noqa: BLE001 - endpoint remains owned for retry
                        failures.append(error)

            endpoint_remains = self._started and (self.path.exists() or self.path.is_symlink())
            resources_remain = (
                any(
                    resource is not None
                    for resource in (
                        self._thread,
                        self._wake_r,
                        self._wake_w,
                        self._listener,
                        self._client,
                    )
                )
                or endpoint_remains
            )
            cleanup_complete = not failures and not resources_remain
            with self._condition:
                self._closed = cleanup_complete
                self._condition.notify_all()
            if failures:
                error = SandboxBackendError(f"stdio broker cleanup failed ({len(failures)} error(s))")
                for failure in failures:
                    error.add_note(str(failure))
                raise error from failures[0]
            if not cleanup_complete:
                raise SandboxBackendError("stdio broker cleanup left owned resources")

    def __enter__(self):
        return self.start()

    def __exit__(self, _type, _value, _traceback):
        self.close()


def connect_stdio(path, *, timeout=None):
    """Return a pwntools tube connected to a manager-owned stdio broker."""
    endpoint = os.fspath(path)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if timeout is not None:
        connection.settimeout(timeout)
    try:
        connection.connect(endpoint)
        require_same_uid(connection)
    except BaseException:
        connection.close()
        raise
    tube = PwntoolsSocketTube()
    tube.sock = connection
    tube.family = connection.family
    tube.type = connection.type
    tube.proto = connection.proto
    tube.rhost = endpoint
    tube.rport = None
    tube.lhost = "unix"
    tube.lport = None
    tube.settimeout(timeout)
    return tube


__all__ = ["StdioBroker", "connect_stdio"]
