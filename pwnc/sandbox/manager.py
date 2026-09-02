"""Persistent, event-driven ownership of local challenge sandboxes."""

from __future__ import annotations

import errno
import math
import os
import selectors
import shutil
import signal
import socket
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path

from ._shim import (
    CommandKind,
    ErrorStage,
    EventKind,
    ShimConnection,
    ShimEvent,
    ShimListener,
    ShimProtocolError,
    ShimRemoteError,
    build_shim,
)
from .config import SandboxProjectConfig, load_project_config
from .errors import (
    SandboxBackendError,
    SandboxCapabilityError,
    SandboxConfigError,
    SandboxNotFoundError,
    SandboxProtocolError,
)
from .model import SandboxSnapshot, SandboxSpec, SandboxState, SandboxStdio
from .protocol import PROTOCOL_VERSION
from .stdio import StdioBroker

_TERMINAL_STATES = frozenset({SandboxState.EXITED, SandboxState.FAILED, SandboxState.CLOSED})


def _duration(value, label: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if value is None or isinstance(value, bool):
        suffix = " or None" if optional else ""
        raise TypeError(f"{label} must be a nonnegative finite number{suffix}")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise TypeError(f"{label} must be a nonnegative finite number") from error
    if result < 0 or not math.isfinite(result):
        raise ValueError(f"{label} must be nonnegative and finite")
    return result


def _deadline(timeout: float | None) -> float | None:
    return None if timeout is None else time.monotonic() + timeout


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("sandbox operation timed out")
    return remaining


def _target_credentials(pid: int) -> tuple[int, int]:
    """Verify every host-namespace credential for one pidfd-identified target."""

    try:
        lines = Path(f"/proc/{pid}/status").read_text().splitlines()
    except OSError as error:
        raise SandboxCapabilityError(f"cannot verify sandbox target credentials for PID {pid}: {error}") from error
    values: dict[str, tuple[int, int, int, int]] = {}
    for line in lines:
        name, separator, value = line.partition(":")
        if separator and name in {"Uid", "Gid"}:
            fields = value.split()
            if len(fields) != 4:
                raise SandboxCapabilityError(
                    f"cannot verify sandbox target credentials for PID {pid}: malformed {name} field"
                )
            try:
                values[name] = tuple(int(field) for field in fields)
            except ValueError as error:
                raise SandboxCapabilityError(
                    f"cannot verify sandbox target credentials for PID {pid}: malformed {name} field"
                ) from error
    if set(values) != {"Uid", "Gid"}:
        raise SandboxCapabilityError(f"cannot verify sandbox target credentials for PID {pid}")
    expected_uid, expected_gid = os.getuid(), os.getgid()
    if any(value != expected_uid for value in values["Uid"]) or any(value != expected_gid for value in values["Gid"]):
        raise SandboxCapabilityError(
            "sandbox target host credentials do not match the invoking user: "
            f"target-uids={values['Uid']}, target-gids={values['Gid']}, "
            f"host={expected_uid}:{expected_gid}"
        )
    return expected_uid, expected_gid


def _container_path(pid: int, path: str) -> str:
    """Map a container path through the exact target's mount namespace."""

    if path.startswith("/"):
        return f"/proc/{pid}/root/{path.lstrip('/')}"
    return f"/proc/{pid}/cwd/{path}"


class _ShimController:
    """Serialize v3 shim commands while one reader owns ``recvmsg``."""

    def __init__(
        self,
        connection: ShimConnection,
        on_event: Callable[[ShimEvent], object],
        on_terminal: Callable[[BaseException], object],
    ) -> None:
        self.connection = connection
        self._on_event = on_event
        self._on_terminal = on_terminal
        self._condition = threading.Condition(threading.RLock())
        self._command_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._ready: ShimEvent | None = None
        self._exit: ShimEvent | None = None
        self._acks: list[ShimEvent] = []
        self._errors: list[ShimRemoteError] = []
        self._terminal_error: BaseException | None = None
        self._closing = False
        self._closed = False
        self._close_complete = False
        self._thread = threading.Thread(
            target=self._read,
            name="pwnc-sandbox-shim-events",
            daemon=True,
        )

    @property
    def host_pid(self) -> int | None:
        return self.connection.host_pid

    @property
    def exit_event(self) -> ShimEvent | None:
        with self._condition:
            return self._exit

    def start(self) -> _ShimController:
        self._thread.start()
        return self

    def _publish_terminal(self, error: BaseException) -> None:
        notify = False
        with self._condition:
            if self._terminal_error is None and self._exit is None and not self._closing:
                self._terminal_error = error
                notify = True
            self._closed = True
            self._condition.notify_all()
        if notify:
            self._on_terminal(error)

    def _read(self) -> None:
        try:
            while True:
                event = self.connection.recv()
                protocol_error: BaseException | None = None
                with self._condition:
                    if event.kind is EventKind.READY:
                        if self._ready is not None:
                            protocol_error = ShimProtocolError("sandbox shim sent READY more than once")
                        else:
                            self._ready = event
                    elif event.kind is EventKind.EXIT:
                        if self._exit is not None:
                            protocol_error = ShimProtocolError("sandbox shim sent EXIT more than once")
                        else:
                            self._exit = event
                    elif event.kind is EventKind.ACK:
                        self._acks.append(event)
                    elif event.kind is EventKind.ERROR:
                        self._errors.append(ShimRemoteError(event))
                    elif event.kind is EventKind.HELLO:
                        protocol_error = ShimProtocolError("sandbox shim sent HELLO after the pre-exec handshake")
                    self._condition.notify_all()
                if protocol_error is not None:
                    raise protocol_error
                self._on_event(event)
                if event.kind is EventKind.EXIT:
                    return
        except EOFError:
            self._publish_terminal(SandboxBackendError("sandbox shim disconnected before reporting target exit"))
        except BaseException as error:  # noqa: BLE001 - replay through session state
            self._publish_terminal(error)
        finally:
            with self._condition:
                self._closed = True
                self._condition.notify_all()

    def wake_waiters(self) -> None:
        with self._condition:
            self._condition.notify_all()

    @staticmethod
    def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
        if cancelled is not None and cancelled():
            raise SandboxBackendError("sandbox start cancelled because manager is closing")

    def wait_ready(
        self,
        timeout: float | None,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> ShimEvent:
        deadline = _deadline(timeout)
        with self._condition:
            while self._ready is None:
                self._check_cancelled(cancelled)
                if self._errors:
                    raise self._errors[0]
                if self._terminal_error is not None:
                    raise self._terminal_error
                if self._exit is not None:
                    raise SandboxBackendError("sandbox target exited before its READY event")
                self._condition.wait(_remaining(deadline))
            self._check_cancelled(cancelled)
            return self._ready

    def _command(
        self,
        kind: CommandKind,
        sender: Callable[[], object],
        *,
        expected_signal: int,
        timeout: float | None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ShimEvent:
        deadline = _deadline(timeout)
        with self._command_lock:
            with self._condition:
                self._check_cancelled(cancelled)
                if self._exit is not None:
                    raise SandboxBackendError("sandbox target has already exited")
                if self._terminal_error is not None:
                    raise self._terminal_error
                ack_index = len(self._acks)
                error_index = len(self._errors)
            sender()
            with self._condition:
                while len(self._acks) == ack_index:
                    self._check_cancelled(cancelled)
                    if len(self._errors) > error_index:
                        raise self._errors[error_index]
                    if self._terminal_error is not None:
                        raise self._terminal_error
                    if self._exit is not None:
                        raise SandboxBackendError("sandbox target exited before acknowledging command")
                    self._condition.wait(_remaining(deadline))
                self._check_cancelled(cancelled)
                event = self._acks[ack_index]
            if event.value != int(kind) or event.detail != expected_signal:
                raise ShimProtocolError(
                    f"unexpected shim ACK ({event.value:#x}, {event.detail}); "
                    f"expected ({int(kind):#x}, {expected_signal})"
                )
            return event

    def continue_(self, timeout: float | None) -> ShimEvent:
        return self._command(
            CommandKind.CONTINUE,
            self.connection.continue_,
            expected_signal=signal.SIGCONT,
            timeout=timeout,
        )

    def signal(self, number: int, timeout: float | None) -> ShimEvent:
        return self._command(
            CommandKind.SIGNAL,
            lambda: self.connection.signal(number),
            expected_signal=number,
            timeout=timeout,
        )

    def kill(self, timeout: float | None) -> ShimEvent:
        return self._command(
            CommandKind.KILL,
            self.connection.kill,
            expected_signal=signal.SIGKILL,
            timeout=timeout,
        )

    def acknowledge_ready(
        self,
        timeout: float | None,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> ShimEvent:
        return self._command(
            CommandKind.READY_ACK,
            self.connection.acknowledge_ready,
            expected_signal=0,
            timeout=timeout,
            cancelled=cancelled,
        )

    def close(self) -> None:
        with self._close_lock:
            with self._condition:
                if self._close_complete:
                    return
                self._closing = True
                self._condition.notify_all()
            self.connection.close()
            if self._thread is not threading.current_thread():
                # ShimConnection.close() performs shutdown(2), so the reader
                # stops via an event rather than a status loop or timeout.
                self._thread.join()
            if self._thread.is_alive():
                raise SandboxBackendError("sandbox shim reader did not stop")
            with self._condition:
                self._closed = True
                self._close_complete = True
                self._condition.notify_all()


class _SandboxSession:
    def __init__(
        self,
        sandbox_id: str,
        spec: SandboxSpec,
        runtime_dir: Path,
        *,
        shim_path: Path,
        backend_factory,
        startup_timeout: float,
        operation_timeout: float,
    ) -> None:
        self.id = sandbox_id
        self.spec = spec
        self.runtime_dir = runtime_dir
        self.created_at = time.time()
        self.shim_path = shim_path
        self.backend_factory = backend_factory
        self.startup_timeout = startup_timeout
        self.operation_timeout = operation_timeout

        self._condition = threading.Condition(threading.RLock())
        self._operation_lock = threading.RLock()
        self._state = SandboxState.STARTING
        self._paused = False
        self._host_pid: int | None = None
        self._exit_code: int | None = None
        self._error: str | None = None
        self._closing = False
        self._closed = False
        self._start_cancelled = False
        self._start_finished = threading.Event()
        self._ready_ack_pending = False
        # This is deliberately an exact PID rather than another pause flag.
        # Only the stop established by the shim immediately after exec may be
        # handed to GDB; a later user-requested SIGSTOP must not recreate that
        # capability.
        self._exec_stop_pid: int | None = None
        self._qemu_stub_pid: int | None = None

        self.listener: ShimListener | None = None
        self.controller: _ShimController | None = None
        self.backend = None
        self.instance = None
        self.broker: StdioBroker | None = None
        self._stdio_fds: list[int] = []
        self._backend_exit: int | None = None
        self._backend_error: BaseException | None = None
        self._backend_thread: threading.Thread | None = None
        self._wake_r: socket.socket | None
        self._wake_w: socket.socket | None
        self._wake_r, self._wake_w = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)

    def _wake(self) -> None:
        endpoint = self._wake_w
        if endpoint is None:
            return
        try:
            endpoint.send(b"x")
        except (BlockingIOError, BrokenPipeError, OSError):
            pass

    def _backend_wait(self, instance) -> None:
        try:
            code = instance.wait()
        except BaseException as error:  # noqa: BLE001 - publish to startup/lifecycle
            with self._condition:
                self._backend_error = error
                self._condition.notify_all()
        else:
            with self._condition:
                self._backend_exit = code
                self._condition.notify_all()
        finally:
            self._wake()

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    @property
    def start_finished(self) -> bool:
        return self._start_finished.is_set()

    def _is_start_cancelled(self) -> bool:
        with self._condition:
            return self._start_cancelled

    def _check_start_cancelled(self) -> None:
        if self._is_start_cancelled():
            raise SandboxBackendError("sandbox start cancelled because manager is closing")

    def cancel_start(self) -> None:
        with self._condition:
            if self._start_finished.is_set():
                return
            self._start_cancelled = True
            controller = self.controller
            self._condition.notify_all()
        self._wake()
        if controller is not None:
            controller.wake_waiters()

    def _start_stdio(self) -> None:
        if self.spec.stdio is SandboxStdio.NONE:
            return
        attach = self.instance.attach
        if attach is None:
            raise SandboxBackendError("Docker did not create the requested stdio attachment")
        if self.spec.stdio is SandboxStdio.PTY:
            if attach.master_fd is None:
                raise SandboxBackendError("Docker PTY attachment has no master descriptor")
            input_fd = os.dup(attach.master_fd)
            self._stdio_fds.append(input_fd)
            output_fd = os.dup(attach.master_fd)
        else:
            if attach.stdin is None or attach.stdout is None:
                raise SandboxBackendError("Docker pipe attachment is missing stdin or stdout")
            input_fd = os.dup(attach.stdin.fileno())
            self._stdio_fds.append(input_fd)
            output_fd = os.dup(attach.stdout.fileno())
        self._stdio_fds.append(output_fd)
        broker = StdioBroker(
            self.runtime_dir / "i",
            input_fd=input_fd,
            output_fd=output_fd,
        )
        self.broker = broker
        broker.start()

    def _accept_control(self, timeout: float) -> ShimConnection:
        assert self.listener is not None
        assert self._wake_r is not None
        deadline = _deadline(timeout)
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.listener, selectors.EVENT_READ, "listener")
            selector.register(self._wake_r, selectors.EVENT_READ, "backend")
            while True:
                self._check_start_cancelled()
                events = selector.select(_remaining(deadline))
                if not events:
                    raise TimeoutError("timed out waiting for sandbox shim connection")
                # A connected Unix socket remains readable in the listener
                # queue even if the short-lived container has already exited.
                # Always prefer it over the docker-wait notification.
                if any(key.data == "listener" for key, _mask in events):
                    return self.listener.accept(timeout=0)
                if any(key.data == "backend" for key, _mask in events):
                    try:
                        self._wake_r.recv(4096)
                    except BlockingIOError:
                        pass
                    self._check_start_cancelled()
                    immediately_ready = selector.select(0)
                    if any(key.data == "listener" for key, _mask in immediately_ready):
                        return self.listener.accept(timeout=0)
                    with self._condition:
                        if self._backend_error is not None:
                            raise SandboxBackendError(
                                "Docker container failed before shim connection"
                            ) from self._backend_error
                        raise SandboxBackendError(
                            f"Docker container exited with status {self._backend_exit} before shim connection"
                        )
        finally:
            selector.close()

    def _handshake_control(self, connection: ShimConnection, timeout: float) -> None:
        """Verify the supervisor's host identity before it may fork the target."""

        assert self._wake_r is not None
        deadline = _deadline(timeout)
        selector = selectors.DefaultSelector()
        try:
            selector.register(connection, selectors.EVENT_READ, "control")
            selector.register(self._wake_r, selectors.EVENT_READ, "backend")
            while True:
                self._check_start_cancelled()
                events = selector.select(_remaining(deadline))
                if not events:
                    raise TimeoutError("timed out waiting for sandbox shim pre-exec handshake")
                if any(key.data == "control" for key, _mask in events):
                    hello = connection.recv(timeout=0, raise_remote=True)
                    break
                if any(key.data == "backend" for key, _mask in events):
                    try:
                        self._wake_r.recv(4096)
                    except BlockingIOError:
                        pass
                    self._check_start_cancelled()
                    immediately_ready = selector.select(0)
                    if any(key.data == "control" for key, _mask in immediately_ready):
                        hello = connection.recv(timeout=0, raise_remote=True)
                        break
                    with self._condition:
                        if self._backend_error is not None:
                            raise SandboxBackendError(
                                "Docker container failed before the shim pre-exec handshake"
                            ) from self._backend_error
                        raise SandboxBackendError(
                            "Docker container exited before the shim pre-exec handshake "
                            f"with status {self._backend_exit}"
                        )
        finally:
            selector.close()

        if (
            hello.kind is not EventKind.HELLO
            or hello.pid != 0
            or hello.value != 0
            or hello.detail != 0
            or hello.flags != 0
            or hello.pidfd is not None
        ):
            raise ShimProtocolError("sandbox shim did not begin with a valid HELLO frame")

        peer_pid, peer_uid, peer_gid = connection.peer_credentials()
        expected_uid, expected_gid = os.getuid(), os.getgid()
        if peer_uid != expected_uid or peer_gid != expected_gid:
            raise SandboxCapabilityError(
                "sandbox shim host credentials do not match the invoking user: "
                f"shim={peer_uid}:{peer_gid}, host={expected_uid}:{expected_gid}"
            )
        # SO_PEERCRED covers the effective IDs.  Verify real, effective, saved,
        # and filesystem IDs while the trusted supervisor is blocked before
        # fork; its child inherits these exact credentials and clears every
        # capability before exec.
        _target_credentials(peer_pid)
        self._check_start_cancelled()
        connection.acknowledge_hello()

    def start(self) -> SandboxSnapshot:
        with self._operation_lock:
            try:
                self._check_start_cancelled()
                self.runtime_dir.mkdir(mode=0o700)
                self._check_start_cancelled()
                self.listener = ShimListener(self.runtime_dir / "c")
                self._check_start_cancelled()
                self.backend = self.backend_factory(
                    session_id=self.id,
                    shim_path=self.shim_path,
                    control_socket=self.listener.path,
                )
                self._check_start_cancelled()
                self.instance = self.backend.spawn(self.spec)
                self._check_start_cancelled()
                self._start_stdio()
                self._check_start_cancelled()
                instance = self.instance
                self._backend_thread = threading.Thread(
                    target=self._backend_wait,
                    args=(instance,),
                    name=f"pwnc-sandbox-docker-wait-{self.id}",
                    daemon=True,
                )
                self._backend_thread.start()
                connection = self._accept_control(self.startup_timeout)
                try:
                    self._handshake_control(connection, self.startup_timeout)
                except BaseException:
                    connection.close()
                    raise
                controller = _ShimController(
                    connection,
                    self._on_shim_event,
                    self._on_shim_terminal,
                )
                self.controller = controller
                controller.start()
                try:
                    ready = self.controller.wait_ready(
                        self.startup_timeout,
                        cancelled=self._is_start_cancelled,
                    )
                except ShimRemoteError as error:
                    event = error.event
                    if (
                        self.spec.qemu is not None
                        and event.detail == ErrorStage.CHILD_EXEC
                        and event.value in {errno.ENOENT, errno.ENOEXEC, errno.EACCES}
                    ):
                        qemu = self.spec.qemu
                        requested = qemu.binary or f"qemu-{qemu.architecture}"
                        raise SandboxCapabilityError(
                            f"cannot execute {qemu.source} QEMU emulator {requested!r}: {os.strerror(event.value)}; "
                            "install it in the image or select a host qemu-user-static source"
                        ) from error
                    raise
                host_pid = self.controller.host_pid
                if host_pid is None:
                    raise SandboxCapabilityError("kernel did not expose the target PID through its pidfd")
                _target_credentials(host_pid)
                self._check_start_cancelled()
                if not ready.paused:
                    with self._condition:
                        self._ready_ack_pending = True
                    self.controller.acknowledge_ready(
                        self.startup_timeout,
                        cancelled=self._is_start_cancelled,
                    )
                    with self._condition:
                        self._ready_ack_pending = False
                self._check_start_cancelled()
                try:
                    self.instance.target_host_pid = host_pid
                except (AttributeError, TypeError):
                    pass
                authorize_debugger = getattr(self.instance, "authorize_debugger", None)
                if callable(authorize_debugger):
                    authorize_debugger(host_pid)
                wait_debugger_ready = getattr(self.instance, "wait_debugger_ready", None)
                if callable(wait_debugger_ready) and self.spec.qemu is not None and self.spec.pause_at_exec:
                    wait_debugger_ready(
                        self.startup_timeout,
                        cancelled=lambda: self._state in _TERMINAL_STATES or self._is_start_cancelled(),
                    )
                # The one accepted seqpacket connection remains valid after
                # the filesystem socket is removed; no second supervisor
                # belongs to this session.
                self.listener.close()
                self.listener = None
                with self._condition:
                    self._check_start_cancelled()
                    self._host_pid = host_pid
                    qemu_paused = self.spec.qemu is not None and self.spec.pause_at_exec
                    if self._state not in _TERMINAL_STATES:
                        self._paused = ready.paused or qemu_paused
                        self._state = SandboxState.PAUSED if self._paused else SandboxState.RUNNING
                    self._exec_stop_pid = host_pid if ready.paused else None
                    self._qemu_stub_pid = host_pid if qemu_paused else None
                    self._condition.notify_all()
                    return self._snapshot_locked()
            except BaseException as error:
                with self._condition:
                    self._closing = True
                    self._error = str(error)
                    self._state = SandboxState.FAILED
                    self._paused = False
                    self._condition.notify_all()
                try:
                    self._cleanup(mark_closed=True)
                except BaseException as cleanup_error:  # noqa: BLE001 - retain exact resources for retry
                    error.add_note(f"sandbox cleanup also failed: {cleanup_error}")
                finally:
                    with self._condition:
                        self._closing = False
                        self._condition.notify_all()
                if isinstance(error, (ShimProtocolError, ShimRemoteError)):
                    raise SandboxBackendError(str(error)) from error
                raise
            finally:
                self._start_finished.set()
                with self._condition:
                    self._condition.notify_all()

    def _on_shim_event(self, event: ShimEvent) -> None:
        with self._condition:
            if self._closing:
                return
            if event.kind is EventKind.READY:
                self._host_pid = self.controller.host_pid if self.controller is not None else None
                self._paused = event.paused
                self._state = SandboxState.PAUSED if event.paused else SandboxState.RUNNING
            elif event.kind is EventKind.EXIT:
                self._exit_code = event.returncode
                self._paused = False
                self._state = SandboxState.EXITED
                self._exec_stop_pid = None
                self._qemu_stub_pid = None
            elif event.kind is EventKind.ERROR and event.flags:
                self._error = str(ShimRemoteError(event))
                self._qemu_stub_pid = None
                if self._state is SandboxState.STARTING:
                    self._state = SandboxState.FAILED
            self._condition.notify_all()
        instance = self.instance
        wake_debugger = None if instance is None else getattr(instance, "wake_debugger_waiters", None)
        if callable(wake_debugger):
            wake_debugger()

    def _on_shim_terminal(self, error: BaseException) -> None:
        with self._condition:
            if self._closing or self._state in _TERMINAL_STATES:
                return
            self._state = SandboxState.FAILED
            self._paused = False
            self._exec_stop_pid = None
            self._qemu_stub_pid = None
            self._error = str(error)
            self._condition.notify_all()

    def _snapshot_locked(self) -> SandboxSnapshot:
        instance = self.instance
        ports = () if instance is None else tuple(instance.ports)
        container_id = None if instance is None else instance.container_id
        stdio_socket = None
        snapshot_error = self._error
        if self.broker is not None:
            broker_error = self.broker.error
            if broker_error is None and not self.broker.closed and not self._closed:
                stdio_socket = os.fspath(self.broker.path)
            elif broker_error is not None:
                description = f"stdio broker failed: {broker_error}"
                snapshot_error = description if snapshot_error is None else f"{snapshot_error}; {description}"
        return SandboxSnapshot(
            id=self.id,
            profile=self.spec.profile,
            backend=self.spec.backend,
            state=self._state,
            created_at=self.created_at,
            host_pid=self._host_pid,
            container_id=container_id,
            stdio=self.spec.stdio,
            stdio_socket=stdio_socket,
            ports=ports,
            paused=self._paused,
            exit_code=self._exit_code,
            error=snapshot_error,
            debug=None if instance is None else getattr(instance, "debug", None),
        )

    def snapshot(self) -> SandboxSnapshot:
        with self._condition:
            return self._snapshot_locked()

    def resume(self) -> SandboxSnapshot:
        with self._operation_lock:
            with self._condition:
                if self._state is not SandboxState.PAUSED:
                    raise SandboxBackendError(f"sandbox {self.id!r} is not paused")
                if self.spec.qemu is not None and self.spec.pause_at_exec:
                    raise SandboxCapabilityError(
                        "a QEMU guest paused before its first instruction must be continued through GDB"
                    )
                # Once a continuation is attempted, an eventual PAUSED state
                # can no longer be proven to be the original post-exec stop.
                self._exec_stop_pid = None
            assert self.controller is not None
            self.controller.continue_(self.operation_timeout)
            with self._condition:
                if self._state is SandboxState.PAUSED:
                    self._state = SandboxState.RUNNING
                    self._paused = False
                self._condition.notify_all()
                return self._snapshot_locked()

    def send_signal(self, number: int) -> SandboxSnapshot:
        if isinstance(number, bool) or not isinstance(number, int):
            raise TypeError("signal must be an integer")
        if number <= 0 or number >= signal.NSIG:
            raise ValueError(f"signal must be between 1 and {signal.NSIG - 1}")
        with self._operation_lock:
            with self._condition:
                if self._state in _TERMINAL_STATES:
                    raise SandboxBackendError(f"sandbox {self.id!r} is not running")
                if self.spec.qemu is not None and self.spec.pause_at_exec and number == signal.SIGCONT:
                    raise SandboxCapabilityError(
                        "a QEMU guest paused before its first instruction must be continued through GDB"
                    )
                # Signals can continue, terminate, or replace the initial
                # group stop.  Never restore this token when SIGSTOP is ACKed.
                self._exec_stop_pid = None
                self._qemu_stub_pid = None
            assert self.controller is not None
            self.controller.signal(number, self.operation_timeout)
            with self._condition:
                if number == signal.SIGSTOP:
                    self._state = SandboxState.PAUSED
                    self._paused = True
                elif number == signal.SIGCONT and self._state is SandboxState.PAUSED:
                    self._state = SandboxState.RUNNING
                    self._paused = False
                self._condition.notify_all()
                return self._snapshot_locked()

    def kill(self) -> SandboxSnapshot:
        with self._operation_lock:
            with self._condition:
                if self._state in _TERMINAL_STATES:
                    return self._snapshot_locked()
                self._exec_stop_pid = None
                self._qemu_stub_pid = None
            assert self.controller is not None
            self.controller.kill(self.operation_timeout)
            return self.snapshot()

    def attach_at_exec(self, callback: Callable[[int], object]) -> object:
        """Invoke ``callback`` for the exact, still-owned post-exec stop.

        The callback runs while the lifecycle operation lock is held.  Thus a
        manager resume or close is ordered wholly before or wholly after the
        GDB attachment, rather than invalidating the numeric PID between the
        state check and ``gdb.attach``.
        """

        if not callable(callback):
            raise TypeError("GDB attach callback must be callable")
        with self._operation_lock:
            with self._condition:
                host_pid = self._host_pid
                controller = self.controller
                eligible = (
                    self._state is SandboxState.PAUSED
                    and self._paused
                    and not self._closing
                    and not self._closed
                    and host_pid is not None
                    and self._exec_stop_pid == host_pid
                    and controller is not None
                )
            if not eligible:
                raise SandboxCapabilityError("GDB attach requires the original post-exec stop")

            assert host_pid is not None
            assert controller is not None
            # Resolve the retained pidfd again under the same lifecycle lock.
            # A stale numeric PID is never passed to GDB after the exact target
            # exited and its PID was reused.
            if controller.host_pid != host_pid:
                with self._condition:
                    self._exec_stop_pid = None
                raise SandboxCapabilityError("sandbox post-exec target identity is no longer valid")
            _target_credentials(host_pid)

            with self._condition:
                if (
                    self._state is not SandboxState.PAUSED
                    or not self._paused
                    or self._closing
                    or self._closed
                    or self.controller is not controller
                    or self._host_pid != host_pid
                    or self._exec_stop_pid != host_pid
                ):
                    self._exec_stop_pid = None
                    raise SandboxCapabilityError("GDB attach requires the original post-exec stop")

            result = callback(host_pid)
            with self._condition:
                # GDB now owns the debugger state.  The manager cannot prove
                # that a future pause is still the pristine shim exec stop.
                self._exec_stop_pid = None
            return result

    def attach_qemu(self, callback: Callable[[int, object], object]) -> object:
        """Attach one selected GDB to this session's exact QEMU guest stub."""

        if not callable(callback):
            raise TypeError("QEMU GDB attach callback must be callable")
        with self._operation_lock:
            with self._condition:
                host_pid = self._host_pid
                controller = self.controller
                instance = self.instance
                debug = None if instance is None else getattr(instance, "debug", None)
                eligible = (
                    self.spec.qemu is not None
                    and debug is not None
                    and self._state is SandboxState.PAUSED
                    and self._paused
                    and not self._closing
                    and not self._closed
                    and host_pid is not None
                    and self._qemu_stub_pid == host_pid
                    and controller is not None
                )
            if not eligible:
                raise SandboxCapabilityError("QEMU GDB attach requires the original guest-stub pause")
            assert host_pid is not None
            assert controller is not None
            if controller.host_pid != host_pid:
                with self._condition:
                    self._qemu_stub_pid = None
                raise SandboxCapabilityError("sandbox QEMU target identity is no longer valid")
            _target_credentials(host_pid)
            with self._condition:
                if (
                    self._state is not SandboxState.PAUSED
                    or not self._paused
                    or self._closing
                    or self._closed
                    or self.controller is not controller
                    or self._host_pid != host_pid
                    or self._qemu_stub_pid != host_pid
                    or controller.host_pid != host_pid
                ):
                    self._qemu_stub_pid = None
                    raise SandboxCapabilityError("QEMU GDB attach requires the original guest-stub pause")
            result = callback(host_pid, debug)
            with self._condition:
                self._qemu_stub_pid = None
            return result

    def resize(self, rows: int, columns: int) -> SandboxSnapshot:
        with self._operation_lock:
            if self.instance is None:
                raise SandboxBackendError("sandbox backend is not ready")
            self.instance.resize(rows, columns)
            return self.snapshot()

    def wait(self, timeout: float | None = None) -> SandboxSnapshot:
        timeout = _duration(timeout, "wait timeout", optional=True)
        with self._condition:
            ready = self._condition.wait_for(lambda: self._state in _TERMINAL_STATES, timeout)
            if not ready:
                raise TimeoutError(f"timed out waiting for sandbox {self.id!r}")
            return self._snapshot_locked()

    def _cleanup(self, *, mark_closed: bool) -> None:
        failures: list[BaseException] = []
        with self._condition:
            self._exec_stop_pid = None
            self._qemu_stub_pid = None

        broker = self.broker
        if broker is not None:
            try:
                broker.close()
            except BaseException as error:  # noqa: BLE001 - continue exact cleanup
                failures.append(error)
            else:
                if not broker.closed:
                    failures.append(SandboxBackendError("stdio broker did not finish closing"))
                else:
                    try:
                        broker.path.unlink()
                    except FileNotFoundError:
                        self.broker = None
                    except BaseException as error:  # noqa: BLE001
                        failures.append(error)
                    else:
                        self.broker = None

        controller = self.controller
        if controller is not None:
            with self._condition:
                ready_ack_pending = self._ready_ack_pending
            if controller.exit_event is None and not ready_ack_pending:
                try:
                    controller.kill(self.operation_timeout)
                except BaseException:  # noqa: BLE001,S110 - exact backend close is authoritative
                    # Closing the exact instance below is the authoritative
                    # fallback and remains retryable if Docker reports an
                    # error.
                    pass
            try:
                controller.close()
            except BaseException as error:  # noqa: BLE001
                failures.append(error)
            else:
                self.controller = None
                with self._condition:
                    self._ready_ack_pending = False

        listener = self.listener
        if listener is not None:
            try:
                listener.close()
            except BaseException as error:  # noqa: BLE001
                failures.append(error)
            else:
                try:
                    listener.path.unlink()
                except FileNotFoundError:
                    self.listener = None
                except BaseException as error:  # noqa: BLE001
                    failures.append(error)
                else:
                    self.listener = None

        instance = self.instance
        if instance is not None:
            try:
                instance.close()
            except BaseException as error:  # noqa: BLE001
                failures.append(error)
            else:
                self.instance = None
        backend = self.backend
        if backend is not None:
            try:
                backend.close()
            except BaseException as error:  # noqa: BLE001
                failures.append(error)
            else:
                self.backend = None

        thread = self._backend_thread
        if thread is not None:
            if not thread.is_alive():
                self._backend_thread = None
            elif self.instance is None and thread is not threading.current_thread():
                # Successful exact-instance removal wakes Docker wait.  Keep
                # the worker owned until that event is observed.
                thread.join()
                self._backend_thread = None
            elif not failures:
                failures.append(SandboxBackendError("Docker wait worker is still owned by a live instance"))

        if self.broker is None:
            remaining_descriptors: list[int] = []
            for descriptor in self._stdio_fds:
                try:
                    os.close(descriptor)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        failures.append(error)
                        remaining_descriptors.append(descriptor)
            self._stdio_fds = remaining_descriptors

        if self._backend_thread is None:
            for name in ("_wake_r", "_wake_w"):
                endpoint = getattr(self, name)
                if endpoint is None:
                    continue
                try:
                    endpoint.close()
                except OSError as error:
                    if error.errno != errno.EBADF:
                        failures.append(error)
                        continue
                setattr(self, name, None)

        resources_remain = any(
            resource is not None
            for resource in (
                self.broker,
                self.controller,
                self.listener,
                self.instance,
                self.backend,
                self._backend_thread,
                self._wake_r,
                self._wake_w,
            )
        ) or bool(self._stdio_fds)
        if not resources_remain:
            try:
                shutil.rmtree(self.runtime_dir)
            except FileNotFoundError:
                pass
            except BaseException as error:  # noqa: BLE001
                failures.append(error)

        cleanup_complete = not failures and not resources_remain and not self.runtime_dir.exists()
        with self._condition:
            self._closed = bool(mark_closed and cleanup_complete)
            if self._closed:
                self._state = SandboxState.CLOSED
                self._paused = False
            elif failures:
                self._state = SandboxState.FAILED
                self._paused = False
                if self._error is None:
                    self._error = "sandbox cleanup failed"
            self._condition.notify_all()
        if failures:
            error = SandboxBackendError(f"sandbox cleanup failed ({len(failures)} error(s))")
            for failure in failures:
                error.add_note(str(failure))
            raise error from failures[0]
        if not cleanup_complete:
            raise SandboxBackendError("sandbox cleanup left owned resources")

    def close(self) -> SandboxSnapshot:
        with self._operation_lock:
            with self._condition:
                if self._closed:
                    return self._snapshot_locked()
                self._closing = True
                self._exec_stop_pid = None
            try:
                self._cleanup(mark_closed=True)
            finally:
                with self._condition:
                    self._closing = False
                    self._condition.notify_all()
            return self.snapshot()


class SandboxManager:
    """Own all Docker and debugger resources for one project manager."""

    def __init__(
        self,
        project_config: SandboxProjectConfig,
        *,
        runtime_dir=None,
        backend_factory=None,
        shim_builder=build_shim,
        startup_timeout=30.0,
        operation_timeout=30.0,
        gdb_pool=None,
        gdb_console=None,
    ) -> None:
        if not isinstance(project_config, SandboxProjectConfig):
            raise TypeError("project_config must be a SandboxProjectConfig")
        if backend_factory is None:
            from .docker import DockerBackend

            backend_factory = DockerBackend
        if not callable(backend_factory):
            raise TypeError("backend_factory must be callable")
        if not callable(shim_builder):
            raise TypeError("shim_builder must be callable")
        self.project_config = project_config
        self.backend_factory = backend_factory
        self.shim_builder = shim_builder
        self.startup_timeout = _duration(startup_timeout, "startup timeout")
        self.operation_timeout = _duration(operation_timeout, "operation timeout")
        self.gdb_pool = gdb_pool
        self.gdb_console = gdb_console

        preferred = (
            Path(runtime_dir) if runtime_dir is not None else Path(tempfile.gettempdir()) / f"pwnc-{os.getuid()}"
        )
        preferred = preferred.expanduser().absolute()
        suffix_budget = len(os.fsencode("/.s-00000000/s-" + "0" * 16 + "/c"))
        if len(os.fsencode(preferred)) + suffix_budget > 103:
            base = Path(tempfile.gettempdir()) / f"pwnc-{os.getuid()}"
        else:
            base = preferred
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        if base.stat().st_uid != os.getuid():
            raise PermissionError(f"sandbox runtime parent must be owned by this uid: {base}")
        # Long project/test paths transparently fall back to the same short,
        # private runtime used by discovery. The unpredictable child created
        # by mkdtemp is mode 0700 and owns all shim/stdin sockets.
        self.runtime_dir = Path(tempfile.mkdtemp(prefix=".s-", dir=base))
        self.runtime_dir.chmod(0o700)
        self._condition = threading.Condition(threading.RLock())
        self._shim_lock = threading.Lock()
        self._attach_lock = threading.Lock()
        self._shim_path: Path | None = None
        self._sessions: dict[str, _SandboxSession] = {}
        self._starting: dict[str, _SandboxSession] = {}
        self._reserved_ids: set[str] = set()
        self._start_calls = 0
        self._close_requested = False
        self._closing = False
        self._closed = False

    def _build_shim(self) -> Path:
        with self._shim_lock:
            if self._shim_path is None:
                self._shim_path = Path(self.shim_builder()).absolute()
            return self._shim_path

    def _new_id(self) -> str:
        with self._condition:
            if self._closed:
                raise SandboxBackendError("sandbox manager is closed")
            if self._close_requested:
                raise SandboxBackendError("sandbox manager is closing")
            while True:
                sandbox_id = f"s-{uuid.uuid4().hex[:16]}"
                if (
                    sandbox_id not in self._sessions
                    and sandbox_id not in self._starting
                    and sandbox_id not in self._reserved_ids
                ):
                    self._reserved_ids.add(sandbox_id)
                    self._start_calls += 1
                    return sandbox_id

    @staticmethod
    def _configure(
        spec: SandboxSpec,
        *,
        command=None,
        env=None,
        stdio=None,
        paused=None,
    ) -> SandboxSpec:
        changes = {}
        if command is not None:
            changes["command"] = command
        if env is not None:
            if not isinstance(env, Mapping):
                raise TypeError("environment override must be a mapping")
            changes["env"] = {**spec.env, **dict(env)}
        if stdio is not None:
            changes["stdio"] = stdio
        if paused is not None:
            if type(paused) is not bool:
                raise TypeError("paused override must be true or false")
            changes["pause_at_exec"] = paused
        try:
            return spec.configured(**changes)
        except (TypeError, ValueError) as error:
            raise SandboxConfigError(str(error)) from error

    def start(self, profile=None, *, command=None, env=None, stdio=None, paused=None) -> SandboxSnapshot:
        with self._condition:
            if self._closed:
                raise SandboxBackendError("sandbox manager is closed")
            if self._close_requested:
                raise SandboxBackendError("sandbox manager is closing")
        spec = self.project_config.profile(profile)
        spec = self._configure(spec, command=command, env=env, stdio=stdio, paused=paused)
        sandbox_id = self._new_id()
        session: _SandboxSession | None = None
        try:
            shim_path = self._build_shim()
            with self._condition:
                if self._close_requested:
                    raise SandboxBackendError("sandbox manager closed while preparing target")
                # Construction and publication are atomic with manager close;
                # from this point onward shutdown owns a concrete cancellable
                # session rather than only an identifier.
                session = _SandboxSession(
                    sandbox_id,
                    spec,
                    self.runtime_dir / sandbox_id,
                    shim_path=shim_path,
                    backend_factory=self.backend_factory,
                    startup_timeout=self.startup_timeout,
                    operation_timeout=self.operation_timeout,
                )
                self._starting[sandbox_id] = session
                self._condition.notify_all()
            snapshot = session.start()
            with self._condition:
                if self._close_requested:
                    raise SandboxBackendError("sandbox manager closed while starting target")
                if self._starting.get(sandbox_id) is session:
                    del self._starting[sandbox_id]
                self._sessions[sandbox_id] = session
                self._condition.notify_all()
            return snapshot
        finally:
            with self._condition:
                if session is not None and session.closed and self._starting.get(sandbox_id) is session:
                    del self._starting[sandbox_id]
                self._reserved_ids.discard(sandbox_id)
                self._start_calls -= 1
                self._condition.notify_all()

    def _session(self, sandbox_id) -> _SandboxSession:
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxProtocolError("sandbox_id must be nonempty text")
        with self._condition:
            try:
                return self._sessions[sandbox_id]
            except KeyError as error:
                raise SandboxNotFoundError(f"sandbox {sandbox_id!r} does not exist") from error

    def list(self) -> tuple[SandboxSnapshot, ...]:
        with self._condition:
            sessions = tuple(self._sessions.values())
        return tuple(sorted((session.snapshot() for session in sessions), key=lambda item: item.created_at))

    def get(self, sandbox_id) -> SandboxSnapshot:
        return self._session(sandbox_id).snapshot()

    def close_sandbox(self, sandbox_id) -> SandboxSnapshot:
        session = self._session(sandbox_id)
        snapshot = session.close()
        with self._condition:
            if self._sessions.get(sandbox_id) is session:
                del self._sessions[sandbox_id]
            self._condition.notify_all()
        return snapshot

    def attach(self, sandbox_id) -> dict:
        session = self._session(sandbox_id)

        def selected_gdb():
            pool = self.gdb_pool
            if pool is None:
                raise SandboxCapabilityError("sandbox manager was started without a GDB pool")
            selection = getattr(self.gdb_console, "selection", None)
            gdb = getattr(selection, "gdb", None)
            generation = getattr(selection, "generation", None)
            if gdb is None:
                gdb = getattr(pool, "current", None)
            if gdb is None:
                raise SandboxCapabilityError("connect a viewer before attaching the selected prepared GDB")
            configured = gdb.use(timeout=self.operation_timeout) if callable(getattr(gdb, "use", None)) else gdb
            return configured, generation

        def attach_selected(host_pid: int) -> dict:
            with self._attach_lock:
                configured, generation = selected_gdb()
                # GDB runs on the host while the inferior lives in Docker's
                # mount namespace. Prefix absolute shared-library paths with
                # the exact inferior root, not an unrelated host libc.
                configured.execute(f"set sysroot /proc/{host_pid}/root")
                configured.attach(host_pid, program=f"/proc/{host_pid}/exe")
                return {
                    "sandbox_id": sandbox_id,
                    "host_pid": host_pid,
                    "generation": generation,
                }

        def connect_selected(host_pid: int, debug) -> dict:
            with self._attach_lock:
                configured, generation = selected_gdb()
                guest_program = session.spec.command[0]
                program = _container_path(host_pid, guest_program)
                qemu = session.spec.qemu
                assert qemu is not None
                sysroot = _container_path(host_pid, "/")
                if qemu.sysroot is not None:
                    sysroot = _container_path(host_pid, qemu.sysroot)
                target = f"{debug.host}:{debug.port}"
                try:
                    configured.connect(
                        target,
                        program=program,
                        sysroot=sysroot,
                        qemu_user=True,
                    )
                except TypeError as error:
                    # A mixed checkout with an older DAP controller must fail
                    # explicitly rather than silently skipping strict rebasing.
                    raise SandboxCapabilityError(
                        "selected GDB does not support QEMU-user remote options"
                    ) from error
                return {
                    "sandbox_id": sandbox_id,
                    "host_pid": host_pid,
                    "generation": generation,
                    "transport": "qemu-gdb",
                    "target": target,
                    "architecture": debug.architecture,
                }

        if session.spec.qemu is not None:
            return session.attach_qemu(connect_selected)
        return session.attach_at_exec(attach_selected)

    @staticmethod
    def _exact(arguments: Mapping, allowed: set[str], required: set[str] = frozenset()) -> None:
        unknown = sorted(set(arguments) - allowed)
        missing = sorted(required - set(arguments))
        if unknown:
            raise SandboxProtocolError(f"unknown request argument(s): {', '.join(unknown)}")
        if missing:
            raise SandboxProtocolError(f"missing request argument(s): {', '.join(missing)}")

    def dispatch(self, operation: str, arguments: Mapping):
        if not isinstance(operation, str) or not isinstance(arguments, Mapping):
            raise SandboxProtocolError("invalid manager operation")
        with self._condition:
            if self._closed:
                raise SandboxBackendError("sandbox manager is closed")
            if self._close_requested:
                raise SandboxBackendError("sandbox manager is closing")
        if operation == "ping":
            self._exact(arguments, set())
            with self._condition:
                count = len(self._sessions)
            return {
                "backend": "docker",
                "version": PROTOCOL_VERSION,
                "manager_pid": os.getpid(),
                "project": os.fspath(self.project_config.path),
                "sessions": count,
                "gdb_pool": self.gdb_pool is not None,
            }
        if operation == "start":
            allowed = {"profile", "command", "env", "stdio", "paused"}
            self._exact(arguments, allowed)
            return self.start(**dict(arguments)).to_wire()
        if operation == "list":
            self._exact(arguments, set())
            return [snapshot.to_wire() for snapshot in self.list()]
        if operation == "get":
            self._exact(arguments, {"sandbox_id"}, {"sandbox_id"})
            return self.get(arguments["sandbox_id"]).to_wire()
        if operation in {"resume", "signal", "kill", "resize", "wait", "close", "attach"}:
            required = {"sandbox_id"}
            allowed = set(required)
            if operation == "signal":
                required.add("signal")
                allowed.add("signal")
            elif operation == "resize":
                required.update(("rows", "columns"))
                allowed.update(("rows", "columns"))
            elif operation == "wait":
                allowed.add("wait_timeout")
            self._exact(arguments, allowed, required)
            sandbox_id = arguments["sandbox_id"]
            if operation == "resume":
                result = self._session(sandbox_id).resume()
            elif operation == "signal":
                result = self._session(sandbox_id).send_signal(arguments["signal"])
            elif operation == "kill":
                result = self._session(sandbox_id).kill()
            elif operation == "resize":
                result = self._session(sandbox_id).resize(arguments["rows"], arguments["columns"])
            elif operation == "wait":
                result = self._session(sandbox_id).wait(arguments.get("wait_timeout"))
            elif operation == "close":
                result = self.close_sandbox(sandbox_id)
            else:
                return self.attach(sandbox_id)
            return result.to_wire()
        if operation == "shutdown":
            self._exact(arguments, set())
            return None
        raise SandboxProtocolError(f"unknown sandbox operation {operation!r}")

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._close_requested = True
            while self._closing:
                self._condition.wait()
                if self._closed:
                    return
            self._closing = True
            starting = tuple(self._starting.values())

        # Cancellation is separate from close() so it can wake startup's
        # selector/condition while start() retains the operation lock.
        for session in starting:
            session.cancel_start()

        with self._condition:
            self._condition.wait_for(lambda: self._start_calls == 0)
            owned = (
                *((sandbox_id, session, self._starting) for sandbox_id, session in self._starting.items()),
                *((sandbox_id, session, self._sessions) for sandbox_id, session in self._sessions.items()),
            )

        failures: list[BaseException] = []
        for sandbox_id, session, collection in owned:
            try:
                session.close()
            except BaseException as error:  # noqa: BLE001 - close every exact session
                failures.append(error)
            else:
                with self._condition:
                    if collection.get(sandbox_id) is session:
                        del collection[sandbox_id]

        pool = self.gdb_pool
        if pool is not None:
            try:
                pool.close()
            except BaseException as error:  # noqa: BLE001
                failures.append(error)
            else:
                self.gdb_pool = None
                self.gdb_console = None

        with self._condition:
            resources_remain = bool(self._starting or self._sessions) or self.gdb_pool is not None
        if not resources_remain:
            try:
                shutil.rmtree(self.runtime_dir)
            except FileNotFoundError:
                pass
            except BaseException as error:  # noqa: BLE001
                failures.append(error)

        cleanup_complete = not failures and not resources_remain and not self.runtime_dir.exists()
        with self._condition:
            self._closing = False
            self._closed = cleanup_complete
            self._condition.notify_all()
        if failures:
            error = SandboxBackendError(f"sandbox manager cleanup failed ({len(failures)} error(s))")
            for failure in failures:
                error.add_note(str(failure))
            raise error from failures[0]
        if not cleanup_complete:
            raise SandboxBackendError("sandbox manager cleanup left owned resources")

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()


def run_manager(
    name="default",
    *,
    socket_path=None,
    config_path=None,
    gdb_pool_size=0,
    gdb_name="default",
    gdb_init=True,
    gdb_setup=None,
    gdb_path="gdb",
    runtime_dir=None,
    backend_factory=None,
    shim_builder=build_shim,
    startup_timeout=30.0,
) -> None:
    """Run one discoverable manager in the foreground until shutdown."""

    if isinstance(gdb_pool_size, bool) or not isinstance(gdb_pool_size, int) or gdb_pool_size < 0:
        raise ValueError("gdb_pool_size must be a nonnegative integer")
    if type(gdb_init) is not bool:
        raise TypeError("gdb_init must be true or false")
    from .discovery import acquire_manager_socket, discover_manager
    from .server import SandboxServer

    address = discover_manager(
        name,
        socket_path=socket_path,
        config_path=config_path,
    )
    project = load_project_config(config_path=address.config_path or config_path)
    lease = acquire_manager_socket(address)
    pool = None
    console = None
    manager = None
    server = None
    previous_handlers: dict[int, object] = {}
    try:
        if gdb_pool_size:
            from pwnc.gdb.dap.pool import GdbPool

            if gdb_path == "gdb" and any(spec.qemu is not None for spec in project.profiles.values()):
                gdb_path = shutil.which("gdb-multiarch") or gdb_path
            pool = GdbPool(
                gdb_pool_size,
                setup=gdb_setup,
                gdb_path=gdb_path,
                init=gdb_init,
            )
            pool.start()
            console = pool.serve(
                gdb_name,
                config_path=project.path,
            )
        manager = SandboxManager(
            project,
            runtime_dir=runtime_dir or address.runtime_dir or address.path.parent,
            backend_factory=backend_factory,
            shim_builder=shim_builder,
            startup_timeout=startup_timeout,
            gdb_pool=pool,
            gdb_console=console,
        )
        pool = None  # manager owns it
        server = SandboxServer(manager, lease)
        lease = None  # server owns it

        if threading.current_thread() is threading.main_thread():

            def request_shutdown(_number, _frame):
                server.close()

            for number in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", None)):
                if number is None:
                    continue
                previous_handlers[number] = signal.getsignal(number)
                signal.signal(number, request_shutdown)
        server.serve_forever()
        if server.error is not None:
            raise server.error
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        if server is not None and not server.closed:
            server.close()
        elif manager is not None:
            manager.close()
        if pool is not None:
            pool.close()
        if lease is not None:
            lease.close()


__all__ = ["SandboxManager", "run_manager"]
