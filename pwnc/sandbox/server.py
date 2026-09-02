"""Event-driven Unix-socket server for a persistent :class:`SandboxManager`."""

from __future__ import annotations

import selectors
import socket
import threading

from .protocol import (
    failure,
    parse_request,
    receive_message,
    require_same_uid,
    send_message,
    success,
)


class SandboxServer:
    """Serve one manager over its exclusively leased Unix socket."""

    def __init__(self, manager, lease):
        if not hasattr(manager, "dispatch") or not hasattr(manager, "close"):
            raise TypeError("manager must provide dispatch() and close()")
        self.manager = manager
        self.lease = lease
        self.address = lease.address
        self._listener = lease.duplicate_socket()
        self._listener.setblocking(False)
        self._wake_r, self._wake_w = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)
        self._condition = threading.Condition(threading.RLock())
        self._workers: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()
        self._receiving: set[socket.socket] = set()
        self._thread: threading.Thread | None = None
        self._started = False
        self._closing = False
        self._closed = False
        self._error: BaseException | None = None

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    @property
    def error(self) -> BaseException | None:
        with self._condition:
            return self._error

    def _wake(self) -> None:
        try:
            self._wake_w.send(b"x")
        except (BlockingIOError, BrokenPipeError, OSError):
            pass

    def start(self) -> SandboxServer:
        with self._condition:
            if self._closed or self._closing:
                raise RuntimeError("sandbox server is closed")
            if self._started:
                return self
            self._started = True
            self._thread = threading.Thread(
                target=self.serve_forever,
                name="pwnc-sandbox-manager-server",
                daemon=True,
            )
            self._thread.start()
            return self

    def _worker_done(self, worker: threading.Thread, connection: socket.socket) -> None:
        with self._condition:
            self._workers.discard(worker)
            self._connections.discard(connection)
            self._receiving.discard(connection)
            self._condition.notify_all()

    def _handle(self, connection: socket.socket) -> None:
        worker = threading.current_thread()
        shutdown = False
        try:
            require_same_uid(connection)
            operation, arguments = parse_request(receive_message(connection))
            with self._condition:
                self._receiving.discard(connection)
            result = self.manager.dispatch(operation, arguments)
            send_message(connection, success(result))
            shutdown = operation == "shutdown"
        except BaseException as error:  # noqa: BLE001 - remote typed diagnostic
            try:
                send_message(connection, failure(error))
            except Exception:  # noqa: BLE001,S110 - peer may already be gone
                pass
        finally:
            try:
                connection.close()
            finally:
                self._worker_done(worker, connection)
        if shutdown:
            self.close()

    def _accept(self) -> None:
        try:
            connection, _ = self._listener.accept()
        except BlockingIOError:
            return
        connection.setblocking(True)
        worker = threading.Thread(
            target=self._handle,
            args=(connection,),
            name="pwnc-sandbox-manager-request",
            daemon=True,
        )
        with self._condition:
            if self._closing:
                connection.close()
                return
            self._workers.add(worker)
            self._connections.add(connection)
            self._receiving.add(connection)
        try:
            worker.start()
        except BaseException:
            with self._condition:
                self._workers.discard(worker)
                self._connections.discard(connection)
                self._receiving.discard(connection)
            connection.close()
            raise

    def serve_forever(self) -> None:
        selector = selectors.DefaultSelector()
        try:
            with self._condition:
                if self._closed:
                    raise RuntimeError("sandbox server is closed")
                self._started = True
            selector.register(self._listener, selectors.EVENT_READ, "listener")
            selector.register(self._wake_r, selectors.EVENT_READ, "wake")
            while True:
                for key, _mask in selector.select():
                    if key.data == "wake":
                        try:
                            self._wake_r.recv(4096)
                        except BlockingIOError:
                            pass
                        with self._condition:
                            if self._closing:
                                return
                    elif key.data == "listener":
                        self._accept()
        except BaseException as error:  # noqa: BLE001 - preserve server failure for caller
            with self._condition:
                if not self._closing:
                    self._error = error
        finally:
            selector.close()
            self._finish_close()

    def _finish_close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closing = True
            connections = tuple(self._connections)
        try:
            self._listener.close()
        except OSError:
            pass
        # Interrupt both incomplete request reads and responses whose peer has
        # stopped reading.  ``manager.close()`` below separately wakes any
        # lifecycle operation which is still executing in a request worker.
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            self.manager.close()
        except BaseException as error:  # noqa: BLE001 - expose through server.error
            with self._condition:
                if self._error is None:
                    self._error = error
        finally:
            with self._condition:
                # manager.close() wakes lifecycle operations.  Keep owning the
                # lease and every worker until those events are observed; a
                # shorter server timeout would orphan live request threads.
                self._condition.wait_for(lambda: not self._workers)
            for endpoint in (self._wake_r, self._wake_w):
                try:
                    endpoint.close()
                except OSError:
                    pass
            try:
                self.lease.close()
            finally:
                with self._condition:
                    self._closed = True
                    self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            if self._closing:
                if self._thread is threading.current_thread():
                    return
                self._condition.wait_for(lambda: self._closed)
                return
            self._closing = True
            self._condition.notify_all()
        self._wake()
        thread = self._thread
        if thread is None:
            # A never-started server has no accept loop whose ``finally`` can
            # release the manager and lease.  ``serve_forever()`` itself sets
            # ``_started`` before blocking, including when it runs directly
            # on the caller's thread.
            with self._condition:
                never_started = not self._started
            if never_started:
                self._finish_close()
            return
        if thread is not threading.current_thread():
            thread.join()

    def wait_closed(self, timeout=None) -> bool:
        with self._condition:
            return self._condition.wait_for(lambda: self._closed, timeout)

    def __enter__(self):
        return self.start()

    def __exit__(self, _type, _value, _traceback):
        self.close()


__all__ = ["SandboxServer"]
