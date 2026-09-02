from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import pty
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import tty
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import pwnc.sandbox.manager as manager_module
from pwnc.sandbox._shim import build_shim, shim_argv
from pwnc.sandbox.config import SandboxProjectConfig
from pwnc.sandbox.errors import (
    SandboxBackendError,
    SandboxCapabilityError,
    SandboxConfigError,
    SandboxNotFoundError,
    SandboxProtocolError,
)
from pwnc.sandbox.manager import SandboxManager
from pwnc.sandbox.model import (
    DockerSpec,
    QemuSpec,
    SandboxBackend,
    SandboxDebug,
    SandboxPortBinding,
    SandboxSnapshot,
    SandboxSpec,
    SandboxState,
    SandboxStdio,
)
from pwnc.sandbox.stdio import StdioBroker, connect_stdio

TIMEOUT = 10.0


def _snapshot(manager: SandboxManager, operation: str, **arguments) -> SandboxSnapshot:
    return SandboxSnapshot.from_wire(manager.dispatch(operation, arguments))


def _python(source: str, *arguments: object) -> list[str]:
    return [sys.executable, "-c", source, *[os.fspath(argument) for argument in arguments]]


@dataclass(slots=True)
class _NativeAttach:
    process: subprocess.Popen[bytes]
    mode: SandboxStdio
    stdin: object | None = None
    stdout: object | None = None
    stderr: object | None = None
    master_fd: int | None = None
    resizes: list[tuple[int, int]] = field(default_factory=list)
    closed: bool = False

    def fileno(self) -> int:
        if self.master_fd is not None:
            return self.master_fd
        assert self.stdout is not None
        return self.stdout.fileno()

    def resize(self, rows: int, columns: int) -> None:
        if self.master_fd is None:
            raise SandboxCapabilityError("terminal resize requires PTY stdio")
        self.resizes.append((rows, columns))
        fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        seen: set[int] = set()
        for stream in (self.stdin, self.stdout, self.stderr):
            if stream is None or id(stream) in seen:
                continue
            seen.add(id(stream))
            try:
                stream.close()
            except OSError:
                pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None


class _NativeInstance:
    """DockerInstance-compatible host fixture backed by the real native shim."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        spec: SandboxSpec,
        attach: _NativeAttach | None,
        token: int,
    ) -> None:
        self.process = process
        self.container_id = f"native-{token}"
        # This is intentionally the supervisor PID.  The manager must replace
        # it with the target PID received through the shim's pidfd.
        self.host_pid = process.pid
        self.target_host_pid = None
        self.ports = ()
        self.stdio = spec.stdio
        self.attach = attach
        self.paused = spec.pause_at_exec
        self.debug = (
            SandboxDebug("tcp", spec.qemu.architecture, "/usr/bin/qemu-fixture", "127.0.0.1", 43210)
            if spec.qemu is not None and spec.pause_at_exec
            else None
        )
        self.debug_authorized_pid = None
        self.shim_control_socket = None
        self.closed = False
        self.killed = False
        self._done = threading.Event()
        self._returncode: int | None = None
        self._wait_error: BaseException | None = None
        self._reaper = threading.Thread(target=self._reap, name=f"native-shim-reaper-{token}", daemon=True)
        self._reaper.start()

    @property
    def exit_code(self) -> int | None:
        return self._returncode

    def _reap(self) -> None:
        try:
            self._returncode = self.process.wait()
        except BaseException as error:  # noqa: BLE001 - replay from wait()
            self._wait_error = error
        finally:
            self._done.set()

    def wait(self, timeout: float | None = None) -> int:
        if not self._done.wait(timeout):
            raise subprocess.TimeoutExpired(self.process.args, timeout)
        if self._wait_error is not None:
            raise self._wait_error
        assert self._returncode is not None
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        if not self._done.is_set():
            try:
                self.process.kill()
            except ProcessLookupError:
                pass

    def authorize_debugger(self, target_host_pid: int) -> None:
        self.debug_authorized_pid = target_host_pid

    def wait_debugger_ready(self, _timeout, *, cancelled=None) -> None:
        assert cancelled is None or not cancelled()

    def wake_debugger_waiters(self) -> None:
        pass

    def resize(self, rows: int, columns: int) -> None:
        if self.attach is None:
            raise SandboxCapabilityError("terminal resize requires PTY stdio")
        self.attach.resize(rows, columns)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if not self._done.is_set():
            try:
                self.process.terminate()
            except ProcessLookupError:
                pass
            if not self._done.wait(2.0):
                try:
                    self.process.kill()
                except ProcessLookupError:
                    pass
                assert self._done.wait(TIMEOUT)
        if self.attach is not None:
            self.attach.close()


class _NativeBackend:
    def __init__(self, owner: _NativeBackendFactory, **options) -> None:
        self.owner = owner
        self.session_id = options.get("session_id")
        self.shim_path = Path(options["shim_path"])
        self.control_socket = Path(options["control_socket"])
        self.instances: list[_NativeInstance] = []
        self.closed = False

    def spawn(self, spec: SandboxSpec) -> _NativeInstance:
        self.owner.specs.append(spec)
        argv = shim_argv(
            self.control_socket,
            spec.command[0],
            spec.command[1:],
            pause=spec.pause_at_exec and spec.qemu is None,
            host_aslr=spec.host_aslr,
            shim=self.shim_path,
        )
        environment = os.environ.copy()
        environment.update(spec.env)
        attach = None
        if spec.stdio is SandboxStdio.PIPE:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
                close_fds=True,
            )
            attach = _NativeAttach(
                process,
                spec.stdio,
                stdin=process.stdin,
                stdout=process.stdout,
            )
        elif spec.stdio is SandboxStdio.PTY:
            master, slave = pty.openpty()
            try:
                tty.setraw(slave)
                process = subprocess.Popen(
                    argv,
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    env=environment,
                    close_fds=True,
                    start_new_session=True,
                )
            finally:
                os.close(slave)
            attach = _NativeAttach(process, spec.stdio, master_fd=master)
        else:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                close_fds=True,
            )
        instance = _NativeInstance(process, spec, attach, len(self.owner.instances) + 1)
        self.instances.append(instance)
        self.owner.instances.append(instance)
        return instance

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        failures = []
        for instance in tuple(self.instances):
            try:
                instance.close()
            except BaseException as error:  # noqa: BLE001 - finish fixture cleanup
                failures.append(error)
        if failures:
            raise failures[0]


class _NativeBackendFactory:
    def __init__(self) -> None:
        self.backends: list[_NativeBackend] = []
        self.instances: list[_NativeInstance] = []
        self.specs: list[SandboxSpec] = []

    def __call__(self, *args, **options) -> _NativeBackend:
        # Keep positional support in the fixture so the test describes the
        # backend contract, rather than constraining a private call style.
        if args:
            names = ("session_id", "shim_path", "control_socket")
            if len(args) > len(names):
                raise TypeError("too many backend factory arguments")
            options = {**dict(zip(names, args, strict=False)), **options}
        assert {"session_id", "shim_path", "control_socket"} <= options.keys()
        backend = _NativeBackend(self, **options)
        self.backends.append(backend)
        return backend


def _build_native_shim(tmp_path_factory) -> Path:
    if sys.platform != "linux":
        pytest.skip("native sandbox shim requires Linux")
    if shutil.which("zig") is None:
        pytest.skip("native sandbox manager tests require zig")
    return build_shim(cache_root=tmp_path_factory.getbasetemp() / "manager-shim-cache")


@pytest.fixture(scope="session")
def native_shim(tmp_path_factory) -> Path:
    return _build_native_shim(tmp_path_factory)


def _project(tmp_path: Path, command: list[str], *, stdio="pipe", paused=False, env=None, qemu=None):
    spec = SandboxSpec(
        profile="default",
        command=tuple(command),
        docker=DockerSpec(image="unused-by-native-fixture"),
        stdio=stdio,
        pause_at_exec=paused,
        env={} if env is None else env,
        qemu=qemu,
    )
    return SandboxProjectConfig(
        path=tmp_path / "pwnc.toml",
        default_profile="default",
        socket=None,
        profiles={"default": spec},
    )


def _manager(tmp_path: Path, project, native_shim: Path, factory=None, **options):
    factory = _NativeBackendFactory() if factory is None else factory
    manager = SandboxManager(
        project,
        runtime_dir=_runtime_base(tmp_path),
        backend_factory=factory,
        shim_builder=lambda: native_shim,
        startup_timeout=TIMEOUT,
        **options,
    )
    return manager, factory


def _runtime_base(tmp_path: Path) -> Path:
    # AF_UNIX filesystem paths are limited to roughly 108 bytes on Linux.
    # Keep the fixture base short while leaving it under pytest's owned tree.
    digest = hashlib.sha256(os.fsencode(tmp_path)).hexdigest()[:10]
    return tmp_path.parent / f"r-{digest}"


def test_target_credentials_require_matching_real_effective_saved_and_fs_ids(monkeypatch):
    uid, gid = os.getuid(), os.getgid()
    status = ""

    def read_status(_path, *_args, **_kwargs):
        return status

    monkeypatch.setattr(manager_module.Path, "read_text", read_status)
    status = f"Name:\ttarget\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
    assert manager_module._target_credentials(4242) == (uid, gid)

    for identity_field, expected in (("Uid", uid), ("Gid", gid)):
        for index in range(4):
            values = [expected] * 4
            values[index] += 1
            uid_values = values if identity_field == "Uid" else [uid] * 4
            gid_values = values if identity_field == "Gid" else [gid] * 4
            uid_text = "\t".join(map(str, uid_values))
            gid_text = "\t".join(map(str, gid_values))
            status = f"Uid:\t{uid_text}\nGid:\t{gid_text}\n"
            with pytest.raises(SandboxCapabilityError, match="credentials do not match"):
                manager_module._target_credentials(4242)


def test_mismatched_supervisor_credentials_fail_before_nonpaused_target_exec(tmp_path, native_shim, monkeypatch):
    marker = tmp_path / "target-ran"
    command = _python("from pathlib import Path; import sys; Path(sys.argv[1]).touch()", marker)
    manager, factory = _manager(tmp_path, _project(tmp_path, command, paused=False), native_shim)

    def reject_credentials(_pid):
        raise SandboxCapabilityError("synthetic remapped supervisor credentials")

    monkeypatch.setattr(manager_module, "_target_credentials", reject_credentials)
    try:
        with pytest.raises(SandboxCapabilityError, match="remapped supervisor"):
            manager.start()
        assert not marker.exists()
        assert len(factory.instances) == 1
        assert factory.instances[0].closed
        assert manager.list() == ()
    finally:
        manager.close()


def test_paused_start_publishes_exact_target_pid_before_any_target_code_runs(tmp_path, native_shim):
    marker = tmp_path / "constructor-equivalent-marker"
    command = _python(
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran'); "
        "print('TARGET-RAN', flush=True); sys.stdin.buffer.read(1); raise SystemExit(23)",
        marker,
    )
    manager, factory = _manager(tmp_path, _project(tmp_path, command, paused=True), native_shim)
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        assert started.state is SandboxState.PAUSED
        assert started.paused
        assert started.host_pid is not None
        assert started.host_pid != factory.instances[0].process.pid
        assert factory.instances[0].target_host_pid == started.host_pid
        assert Path(f"/proc/{started.host_pid}").is_dir()
        assert not marker.exists()

        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        try:
            resumed = _snapshot(manager, "resume", sandbox_id=started.id)
            assert resumed.state is SandboxState.RUNNING
            assert not resumed.paused
            assert tube.recvline(timeout=TIMEOUT) == b"TARGET-RAN\n"
            assert marker.read_text() == "ran"
            tube.send(b"x")
        finally:
            tube.close()
        exited = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
        assert exited.state is SandboxState.EXITED
        assert exited.exit_code == 23
    finally:
        manager.close()


def test_running_pipe_stdio_is_binary_clean_and_wait_records_normal_exit(tmp_path, native_shim):
    command = _python(
        "import sys; data=sys.stdin.buffer.readline(); sys.stdout.buffer.write(b'REPLY\\x00'+data); "
        "sys.stdout.buffer.flush(); raise SystemExit(7)"
    )
    manager, factory = _manager(tmp_path, _project(tmp_path, command), native_shim)
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        assert started.state is SandboxState.RUNNING
        assert not started.paused
        assert started.stdio is SandboxStdio.PIPE
        assert started.stdio_socket is not None
        assert started.host_pid != factory.instances[0].process.pid

        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        try:
            tube.send(b"hello\xff\n")
            assert tube.recvn(len(b"REPLY\x00hello\xff\n"), timeout=TIMEOUT) == b"REPLY\x00hello\xff\n"
        finally:
            tube.close()
        exited = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
        assert exited.state is SandboxState.EXITED
        assert exited.exit_code == 7
        assert exited.host_pid == started.host_pid
    finally:
        manager.close()


def test_short_lived_running_target_is_published_and_reaped_without_pidfd_race(tmp_path, native_shim):
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, ["/bin/true"], stdio="none"),
        native_shim,
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        assert started.host_pid is not None
        assert factory.instances[0].target_host_pid == started.host_pid
        assert started.state in {SandboxState.RUNNING, SandboxState.EXITED}

        exited = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
        assert exited.state is SandboxState.EXITED
        assert exited.exit_code == 0
    finally:
        manager.close()


def test_pipe_stdio_merges_and_drains_stderr_without_pipe_deadlock(tmp_path, native_shim):
    count = 1024 * 1024
    command = _python(
        "import sys; n=int(sys.argv[1]); sys.stderr.buffer.write(b'E'*n); sys.stderr.buffer.flush(); "
        "sys.stdout.buffer.write(b'OUT\\n'); sys.stdout.buffer.flush()",
        str(count),
    )
    manager, _factory = _manager(tmp_path, _project(tmp_path, command), native_shim)
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        try:
            assert tube.recvn(count, timeout=TIMEOUT) == b"E" * count
            assert tube.recvline(timeout=TIMEOUT) == b"OUT\n"
        finally:
            tube.close()
        exited = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
        assert exited.state is SandboxState.EXITED
        assert exited.exit_code == 0
    finally:
        manager.close()


def test_signal_kill_and_concurrent_waiters_are_event_driven(tmp_path, native_shim):
    command = _python(
        "import signal,sys; "
        "signal.signal(signal.SIGUSR1, lambda *_: (sys.stdout.write('USR1\\n'), sys.stdout.flush())); "
        "print('READY', flush=True); "
        "signal.pause(); signal.pause()"
    )
    manager, _factory = _manager(tmp_path, _project(tmp_path, command), native_shim)
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        try:
            assert tube.recvline(timeout=TIMEOUT) == b"READY\n"
            signalled = _snapshot(manager, "signal", sandbox_id=started.id, signal=signal.SIGUSR1)
            assert signalled.state is SandboxState.RUNNING
            assert tube.recvline(timeout=TIMEOUT) == b"USR1\n"

            session = manager._session(started.id)
            entered = threading.Condition()
            entered_count = 0
            original_wait_for = session._condition.wait_for

            def observed_wait_for(predicate, timeout=None):
                nonlocal entered_count
                with entered:
                    entered_count += 1
                    entered.notify_all()
                return original_wait_for(predicate, timeout)

            session._condition.wait_for = observed_wait_for
            results: list[SandboxSnapshot] = []
            failures: list[BaseException] = []
            lock = threading.Lock()

            def wait_for_exit() -> None:
                try:
                    result = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
                except BaseException as error:  # noqa: BLE001 - report thread failure in parent
                    with lock:
                        failures.append(error)
                else:
                    with lock:
                        results.append(result)

            waiters = [threading.Thread(target=wait_for_exit) for _ in range(2)]
            for waiter in waiters:
                waiter.start()
            with entered:
                assert entered.wait_for(lambda: entered_count == 2, TIMEOUT)
            killed = _snapshot(manager, "kill", sandbox_id=started.id)
            assert killed.state in {SandboxState.RUNNING, SandboxState.EXITED}
            for waiter in waiters:
                waiter.join(TIMEOUT)
            assert all(not waiter.is_alive() for waiter in waiters)
            assert not failures
            assert len(results) == 2
            assert all(result.state is SandboxState.EXITED for result in results)
            assert all(result.exit_code == -signal.SIGKILL for result in results)
        finally:
            tube.close()
    finally:
        manager.close()


def test_finite_wait_timeout_does_not_change_live_session_state(tmp_path, native_shim):
    manager, _factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; print('READY', flush=True); signal.pause()")),
        native_shim,
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        try:
            assert tube.recvline(timeout=TIMEOUT) == b"READY\n"
            with pytest.raises(TimeoutError, match="timed out"):
                manager.dispatch("wait", {"sandbox_id": started.id, "wait_timeout": 0.0})
            live = _snapshot(manager, "get", sandbox_id=started.id)
            assert live.state is SandboxState.RUNNING
            assert live.exit_code is None
            _snapshot(manager, "kill", sandbox_id=started.id)
            assert _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT).exit_code == -signal.SIGKILL
        finally:
            tube.close()
    finally:
        manager.close()


def test_pty_stdio_and_resize_reach_the_backend(tmp_path, native_shim):
    command = _python(
        "import os,sys; print('TTY='+str(os.isatty(0)), flush=True); "
        "data=sys.stdin.buffer.readline(); sys.stdout.buffer.write(b'PTY:'+data); sys.stdout.buffer.flush()"
    )
    manager, factory = _manager(tmp_path, _project(tmp_path, command, stdio="pty"), native_shim)
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        assert started.stdio is SandboxStdio.PTY
        resized = _snapshot(manager, "resize", sandbox_id=started.id, rows=41, columns=132)
        assert resized.state is SandboxState.RUNNING
        assert factory.instances[0].attach.resizes == [(41, 132)]

        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        try:
            assert tube.recvline(timeout=TIMEOUT) == b"TTY=True\n"
            tube.send(b"dimensions\n")
            assert tube.recvline(timeout=TIMEOUT) == b"PTY:dimensions\n"
        finally:
            tube.close()
        assert _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT).exit_code == 0
    finally:
        manager.close()


def test_start_overrides_are_explicit_validated_and_do_not_mutate_profile(tmp_path, native_shim):
    original = _python("raise SystemExit(99)")
    project = _project(tmp_path, original, env={"OLD": "configured"})
    manager, factory = _manager(tmp_path, project, native_shim)
    try:
        replacement = _python("import os; raise SystemExit(4 if os.environ['NEW']=='override' else 5)")
        started = _snapshot(
            manager,
            "start",
            profile="default",
            command=replacement,
            env={"NEW": "override"},
            stdio="none",
            paused=False,
        )
        assert _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT).exit_code == 4
        actual = factory.specs[0]
        assert actual.command == tuple(replacement)
        assert dict(actual.env) == {"OLD": "configured", "NEW": "override"}
        assert actual.stdio is SandboxStdio.NONE
        assert project.profile().command == tuple(original)
        assert dict(project.profile().env) == {"OLD": "configured"}

        invalid = [
            ({"command": []}, "command"),
            ({"command": "not-an-argv"}, "command"),
            ({"env": []}, "environment"),
            ({"stdio": "terminal-ish"}, "stdio"),
            ({"paused": "yes"}, "paused"),
        ]
        for override, match in invalid:
            arguments = {"profile": None, "command": None, "env": None, "stdio": None, "paused": None}
            arguments.update(override)
            with pytest.raises((SandboxConfigError, TypeError, ValueError), match=match):
                manager.dispatch("start", arguments)
    finally:
        manager.close()


class _FailingBackend:
    def __init__(self, owner, **_options):
        self.owner = owner
        self.closed = False

    def spawn(self, _spec):
        raise SandboxBackendError("deliberate spawn failure")

    def close(self):
        self.closed = True
        self.owner.closed.set()


class _FailingFactory:
    def __init__(self):
        self.backends = []
        self.closed = threading.Event()

    def __call__(self, *args, **kwargs):
        backend = _FailingBackend(self, **kwargs)
        self.backends.append(backend)
        return backend


class _RetryingFailingBackend(_FailingBackend):
    def close(self):
        self.owner.close_attempts += 1
        if self.owner.close_attempts == 1:
            raise SandboxBackendError("deliberate first cleanup failure")
        super().close()


class _RetryingFailingFactory(_FailingFactory):
    def __init__(self):
        super().__init__()
        self.close_attempts = 0

    def __call__(self, *args, **kwargs):
        backend = _RetryingFailingBackend(self, **kwargs)
        self.backends.append(backend)
        return backend


def test_failed_start_is_transactional_and_removes_private_session_state(tmp_path, native_shim):
    factory = _FailingFactory()
    runtime = _runtime_base(tmp_path)
    manager = SandboxManager(
        _project(tmp_path, ["/does/not/matter"]),
        runtime_dir=runtime,
        backend_factory=factory,
        shim_builder=lambda: native_shim,
        startup_timeout=TIMEOUT,
    )
    try:
        with pytest.raises(SandboxBackendError, match="deliberate spawn failure"):
            manager.dispatch(
                "start",
                {"profile": None, "command": None, "env": None, "stdio": None, "paused": None},
            )
        assert factory.closed.wait(TIMEOUT)
        assert manager.dispatch("list", {}) == []
        assert not list(manager.runtime_dir.glob("s-*"))
    finally:
        manager.close()


def test_failed_start_cleanup_is_retained_by_manager_and_retried(tmp_path, native_shim):
    factory = _RetryingFailingFactory()
    manager = SandboxManager(
        _project(tmp_path, ["/does/not/matter"]),
        runtime_dir=_runtime_base(tmp_path),
        backend_factory=factory,
        shim_builder=lambda: native_shim,
        startup_timeout=TIMEOUT,
    )
    with pytest.raises(SandboxBackendError, match="deliberate spawn failure"):
        manager.start()

    with manager._condition:
        assert manager._start_calls == 0
        assert len(manager._starting) == 1
        session = next(iter(manager._starting.values()))
    assert session.backend is factory.backends[0]
    assert not session.closed
    assert session.runtime_dir.is_dir()

    manager.close()
    assert factory.close_attempts == 2
    assert factory.closed.is_set()
    assert not manager.runtime_dir.exists()


def test_stdio_worker_start_failure_remains_session_owned_and_rolls_back(
    tmp_path,
    native_shim,
    monkeypatch,
):
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()")),
        native_shim,
    )
    brokers: list[StdioBroker] = []
    original_broker_start = StdioBroker.start
    original_thread_start = threading.Thread.start

    def observe_broker_start(broker):
        brokers.append(broker)
        return original_broker_start(broker)

    def fail_broker_worker_start(thread):
        if thread.name.startswith("pwnc-sandbox-stdio-"):
            raise RuntimeError("injected stdio worker start failure")
        return original_thread_start(thread)

    monkeypatch.setattr(StdioBroker, "start", observe_broker_start)
    monkeypatch.setattr(threading.Thread, "start", fail_broker_worker_start)
    try:
        with pytest.raises(RuntimeError, match="injected stdio worker start failure"):
            manager.start()
        assert len(brokers) == 1
        broker = brokers[0]
        assert broker.closed
        assert broker._thread is None
        assert broker._listener is None
        assert broker._wake_r is None
        assert broker._wake_w is None
        assert not broker.path.exists()
        with manager._condition:
            assert not manager._starting
            assert manager._start_calls == 0
        assert factory.instances[0].closed
        assert not list(manager.runtime_dir.glob("s-*"))
    finally:
        manager.close()


class _SilentInstance:
    container_id = "silent-container"
    host_pid = os.getpid()
    target_host_pid = None
    ports = ()
    stdio = SandboxStdio.NONE
    attach = None
    paused = False
    shim_control_socket = None

    def __init__(self) -> None:
        self.closed = False
        self._done = threading.Event()

    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise subprocess.TimeoutExpired("silent", timeout)
        return 137

    def kill(self):
        self.close()

    def resize(self, _rows, _columns):
        raise SandboxCapabilityError("terminal resize requires PTY stdio")

    def close(self):
        self.closed = True
        self._done.set()


class _SilentBackend:
    def __init__(self, owner, **_options):
        self.owner = owner
        self.instance = _SilentInstance()
        self.closed = False

    def spawn(self, _spec):
        self.owner.instance = self.instance
        return self.instance

    def close(self):
        self.closed = True
        self.instance.close()
        self.owner.closed.set()


class _SilentFactory:
    def __init__(self):
        self.instance = None
        self.closed = threading.Event()

    def __call__(self, *args, **kwargs):
        return _SilentBackend(self, **kwargs)


class _ConnectedSilentBackend(_SilentBackend):
    def __init__(self, owner, **options):
        super().__init__(owner, **options)
        self.control_socket = Path(options["control_socket"])
        self.connection = None

    def spawn(self, spec):
        instance = super().spawn(spec)
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.connection.connect(os.fspath(self.control_socket))
        self.owner.connected.set()
        return instance

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        super().close()


class _ConnectedSilentFactory(_SilentFactory):
    def __init__(self):
        super().__init__()
        self.connected = threading.Event()

    def __call__(self, *args, **kwargs):
        return _ConnectedSilentBackend(self, **kwargs)


class _BlockingSpawnBackend(_SilentBackend):
    def spawn(self, _spec):
        self.owner.spawn_entered.set()
        if not self.owner.release_spawn.wait(TIMEOUT):
            raise SandboxBackendError("test did not release blocked spawn")
        self.owner.instance = self.instance
        return self.instance


class _BlockingSpawnFactory(_SilentFactory):
    def __init__(self):
        super().__init__()
        self.spawn_entered = threading.Event()
        self.release_spawn = threading.Event()
        self.backend = None

    def __call__(self, *args, **kwargs):
        self.backend = _BlockingSpawnBackend(self, **kwargs)
        return self.backend


def test_manager_owns_preconstruction_start_while_shim_build_is_blocked(
    tmp_path,
    native_shim,
    monkeypatch,
):
    build_entered = threading.Event()
    release_build = threading.Event()

    def blocking_builder():
        build_entered.set()
        assert release_build.wait(TIMEOUT)
        return native_shim

    manager = SandboxManager(
        _project(tmp_path, ["/does/not/matter"], stdio="none"),
        runtime_dir=_runtime_base(tmp_path),
        backend_factory=_SilentFactory(),
        shim_builder=blocking_builder,
        startup_timeout=TIMEOUT,
    )
    start_errors: list[BaseException] = []
    close_errors: list[BaseException] = []
    close_done = threading.Event()
    close_waiting = threading.Event()

    def start_target():
        try:
            manager.start()
        except BaseException as error:  # noqa: BLE001 - assert exact thread outcome below
            start_errors.append(error)

    original_wait_for = manager._condition.wait_for

    def observed_wait_for(predicate, timeout=None):
        if not predicate():
            close_waiting.set()
        return original_wait_for(predicate, timeout)

    monkeypatch.setattr(manager._condition, "wait_for", observed_wait_for)

    def close_manager():
        try:
            manager.close()
        except BaseException as error:  # noqa: BLE001
            close_errors.append(error)
        finally:
            close_done.set()

    starter = threading.Thread(target=start_target)
    closer = threading.Thread(target=close_manager)
    starter.start()
    assert build_entered.wait(TIMEOUT)
    with manager._condition:
        assert manager._start_calls == 1
        assert not manager._starting
    closer.start()
    assert close_waiting.wait(TIMEOUT)
    assert not close_done.is_set()
    assert manager.runtime_dir.is_dir()

    release_build.set()
    starter.join(TIMEOUT)
    closer.join(TIMEOUT)
    assert not starter.is_alive()
    assert not closer.is_alive()
    assert len(start_errors) == 1
    assert isinstance(start_errors[0], SandboxBackendError)
    assert not close_errors
    assert not manager.runtime_dir.exists()


def test_manager_cancels_and_waits_for_concrete_starting_session(tmp_path, native_shim):
    factory = _BlockingSpawnFactory()
    manager = SandboxManager(
        _project(tmp_path, ["/does/not/matter"], stdio="none"),
        runtime_dir=_runtime_base(tmp_path),
        backend_factory=factory,
        shim_builder=lambda: native_shim,
        startup_timeout=TIMEOUT,
    )
    start_errors: list[BaseException] = []
    close_errors: list[BaseException] = []
    close_done = threading.Event()

    def start_target():
        try:
            manager.start()
        except BaseException as error:  # noqa: BLE001
            start_errors.append(error)

    def close_manager():
        try:
            manager.close()
        except BaseException as error:  # noqa: BLE001
            close_errors.append(error)
        finally:
            close_done.set()

    starter = threading.Thread(target=start_target)
    closer = threading.Thread(target=close_manager)
    starter.start()
    assert factory.spawn_entered.wait(TIMEOUT)
    with manager._condition:
        assert manager._start_calls == 1
        assert len(manager._starting) == 1
        session = next(iter(manager._starting.values()))
    closer.start()
    with session._condition:
        assert session._condition.wait_for(lambda: session._start_cancelled, TIMEOUT)
    assert not close_done.is_set()
    assert manager.runtime_dir.is_dir()

    factory.release_spawn.set()
    starter.join(TIMEOUT)
    closer.join(TIMEOUT)
    assert not starter.is_alive()
    assert not closer.is_alive()
    assert len(start_errors) == 1
    assert "cancelled" in str(start_errors[0])
    assert not close_errors
    assert factory.instance.closed
    assert factory.backend.closed
    assert not manager.runtime_dir.exists()


def test_shutdown_during_ready_ack_closes_v3_channel_without_sending_wrong_command(
    tmp_path,
    native_shim,
    monkeypatch,
):
    ack_entered = threading.Event()
    release_ack = threading.Event()
    kill_command_sent = threading.Event()
    original_ack = manager_module._ShimController.acknowledge_ready
    original_kill = manager_module._ShimController.kill

    def blocked_ack(controller, *args, **kwargs):
        ack_entered.set()
        assert release_ack.wait(TIMEOUT)
        return original_ack(controller, *args, **kwargs)

    def observed_kill(controller, *args, **kwargs):
        kill_command_sent.set()
        return original_kill(controller, *args, **kwargs)

    monkeypatch.setattr(manager_module._ShimController, "acknowledge_ready", blocked_ack)
    monkeypatch.setattr(manager_module._ShimController, "kill", observed_kill)
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()"), stdio="none"),
        native_shim,
    )
    start_errors: list[BaseException] = []
    close_errors: list[BaseException] = []
    close_done = threading.Event()

    def start_target():
        try:
            manager.start()
        except BaseException as error:  # noqa: BLE001
            start_errors.append(error)

    def close_manager():
        try:
            manager.close()
        except BaseException as error:  # noqa: BLE001
            close_errors.append(error)
        finally:
            close_done.set()

    starter = threading.Thread(target=start_target)
    closer = threading.Thread(target=close_manager)
    starter.start()
    assert ack_entered.wait(TIMEOUT)
    with manager._condition:
        session = next(iter(manager._starting.values()))
    with session._condition:
        assert session._ready_ack_pending
    closer.start()
    with session._condition:
        assert session._condition.wait_for(lambda: session._start_cancelled, TIMEOUT)
    assert not close_done.is_set()

    release_ack.set()
    starter.join(TIMEOUT)
    closer.join(TIMEOUT)
    assert not starter.is_alive()
    assert not closer.is_alive()
    assert len(start_errors) == 1
    assert "cancelled" in str(start_errors[0])
    assert not close_errors
    assert not kill_command_sent.is_set()
    assert factory.instances[0].closed
    assert factory.instances[0]._done.is_set()
    assert not manager.runtime_dir.exists()


def test_shim_handshake_timeout_rolls_back_started_backend_and_listener(tmp_path, native_shim):
    factory = _SilentFactory()
    runtime = _runtime_base(tmp_path)
    manager = SandboxManager(
        _project(tmp_path, ["/does/not/matter"], stdio="none"),
        runtime_dir=runtime,
        backend_factory=factory,
        shim_builder=lambda: native_shim,
        startup_timeout=0.05,
    )
    try:
        with pytest.raises((SandboxBackendError, TimeoutError), match="shim|timed out"):
            manager.dispatch(
                "start",
                {"profile": None, "command": None, "env": None, "stdio": None, "paused": None},
            )
        assert factory.closed.wait(TIMEOUT)
        assert factory.instance.closed
        assert manager.dispatch("list", {}) == []
        assert not list(manager.runtime_dir.glob("s-*"))
    finally:
        manager.close()


def test_manager_close_eventfully_cancels_connected_preexec_handshake(tmp_path, native_shim, monkeypatch):
    factory = _ConnectedSilentFactory()
    manager = SandboxManager(
        _project(tmp_path, ["/does/not/matter"], stdio="none"),
        runtime_dir=_runtime_base(tmp_path),
        backend_factory=factory,
        shim_builder=lambda: native_shim,
        startup_timeout=TIMEOUT,
    )
    handshake_entered = threading.Event()
    original_handshake = manager_module._SandboxSession._handshake_control

    def observed_handshake(session, connection, timeout):
        handshake_entered.set()
        return original_handshake(session, connection, timeout)

    monkeypatch.setattr(manager_module._SandboxSession, "_handshake_control", observed_handshake)
    start_errors: list[BaseException] = []
    close_errors: list[BaseException] = []

    def start_target():
        try:
            manager.start()
        except BaseException as error:  # noqa: BLE001 - asserted below
            start_errors.append(error)

    def close_manager():
        try:
            manager.close()
        except BaseException as error:  # noqa: BLE001 - asserted below
            close_errors.append(error)

    starter = threading.Thread(target=start_target)
    closer = threading.Thread(target=close_manager)
    starter.start()
    assert factory.connected.wait(TIMEOUT), start_errors
    assert handshake_entered.wait(TIMEOUT)

    closer.start()
    starter.join(TIMEOUT)
    closer.join(TIMEOUT)
    assert not starter.is_alive()
    assert not closer.is_alive()
    assert len(start_errors) == 1
    assert "cancelled" in str(start_errors[0])
    assert close_errors == []
    assert factory.instance.closed
    assert not manager.runtime_dir.exists()


def test_exec_failure_after_backend_spawn_is_transactional(tmp_path, native_shim):
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, ["/pwnc-test/definitely-not-an-executable"], stdio="none"),
        native_shim,
    )
    try:
        with pytest.raises((SandboxBackendError, OSError), match="exec|shim|executable"):
            manager.dispatch(
                "start",
                {"profile": None, "command": None, "env": None, "stdio": None, "paused": None},
            )
        assert factory.backends
        assert all(backend.closed for backend in factory.backends)
        assert manager.dispatch("list", {}) == []
        assert not list(manager.runtime_dir.glob("s-*"))
    finally:
        manager.close()


def test_unexpected_shim_disconnect_marks_session_failed_and_wakes_wait(tmp_path, native_shim):
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; print('READY', flush=True); signal.pause()")),
        native_shim,
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        try:
            assert tube.recvline(timeout=TIMEOUT) == b"READY\n"
            os.kill(factory.instances[0].process.pid, signal.SIGKILL)
            failed = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
            assert failed.state is SandboxState.FAILED
            assert failed.exit_code is None
            assert "disconnected" in failed.error
        finally:
            tube.close()
    finally:
        manager.close()


class _FakeGdb:
    def __init__(self) -> None:
        self.calls = []
        self.execute_calls = []
        self.connect_calls = []

    def execute(self, command):
        self.execute_calls.append(command)

    def attach(self, pid, program=None):
        self.calls.append((pid, program))

    def connect(self, target, program=None, sysroot=None, qemu_user=False):
        self.connect_calls.append((target, program, sysroot, qemu_user))


class _BlockingFakeGdb(_FakeGdb):
    def __init__(self) -> None:
        super().__init__()
        self.attach_entered = threading.Event()
        self.release_attach = threading.Event()

    def attach(self, pid, program=None):
        self.attach_entered.set()
        assert self.release_attach.wait(TIMEOUT)
        super().attach(pid, program=program)


class _FakeGdbPool:
    def __init__(self, current=None) -> None:
        self.current = current
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_gdb_pool_attach_uses_exact_pid_and_never_resumes_target(tmp_path, native_shim):
    marker = tmp_path / "must-remain-absent"
    command = _python("from pathlib import Path; import sys; Path(sys.argv[1]).touch()", marker)
    fake_gdb = _FakeGdb()
    pool = _FakeGdbPool(fake_gdb)
    manager, _factory = _manager(
        tmp_path,
        _project(tmp_path, command, paused=True),
        native_shim,
        gdb_pool=pool,
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        attached = manager.dispatch("attach", {"sandbox_id": started.id})
        assert attached["sandbox_id"] == started.id
        assert attached["host_pid"] == started.host_pid
        assert fake_gdb.execute_calls == [f"set sysroot /proc/{started.host_pid}/root"]
        assert fake_gdb.calls == [(started.host_pid, f"/proc/{started.host_pid}/exe")]
        assert not marker.exists()
        refreshed = _snapshot(manager, "get", sandbox_id=started.id)
        assert refreshed.state is SandboxState.PAUSED
        assert refreshed.paused
        with pytest.raises(SandboxCapabilityError, match="original post-exec stop"):
            manager.dispatch("attach", {"sandbox_id": started.id})

        _snapshot(manager, "kill", sandbox_id=started.id)
        _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
    finally:
        manager.close()
    assert pool.closed


@pytest.mark.parametrize(
    ("configured_sysroot", "proc_anchor"),
    [("/guest-root", "root/guest-root"), ("guest-root", "cwd/guest-root")],
)
def test_qemu_pool_connects_guest_stub_with_container_program_and_sysroot(
    tmp_path, native_shim, configured_sysroot, proc_anchor
):
    command = _python("import signal; signal.pause()")
    fake_gdb = _FakeGdb()
    pool = _FakeGdbPool(fake_gdb)
    qemu = QemuSpec("aarch64", source="image", sysroot=configured_sysroot, guest_aslr=False)
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, command, paused=True, qemu=qemu),
        native_shim,
        gdb_pool=pool,
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        assert started.state is SandboxState.PAUSED
        assert started.paused
        assert started.debug is not None
        assert started.debug.transport == "tcp"
        assert factory.instances[0].debug_authorized_pid == started.host_pid

        attached = manager.dispatch("attach", {"sandbox_id": started.id})
        assert attached == {
            "sandbox_id": started.id,
            "host_pid": started.host_pid,
            "generation": None,
            "transport": "qemu-gdb",
            "target": "127.0.0.1:43210",
            "architecture": "aarch64",
        }
        root = f"/proc/{started.host_pid}/root"
        assert fake_gdb.connect_calls == [
            (
                "127.0.0.1:43210",
                root + command[0],
                f"/proc/{started.host_pid}/{proc_anchor}",
                True,
            )
        ]
        assert fake_gdb.calls == []
        assert fake_gdb.execute_calls == []
        with pytest.raises(SandboxCapabilityError, match="continued through GDB"):
            manager.dispatch("resume", {"sandbox_id": started.id})
        with pytest.raises(SandboxCapabilityError, match="continued through GDB"):
            manager.dispatch("signal", {"sandbox_id": started.id, "signal": signal.SIGCONT})
        with pytest.raises(SandboxCapabilityError, match="original guest-stub pause"):
            manager.dispatch("attach", {"sandbox_id": started.id})
    finally:
        manager.close()
    assert pool.closed


def test_gdb_attach_rejects_a_later_user_sigstop(tmp_path, native_shim):
    fake_gdb = _FakeGdb()
    manager, _factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()"), paused=True),
        native_shim,
        gdb_pool=_FakeGdbPool(fake_gdb),
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        _snapshot(manager, "resume", sandbox_id=started.id)
        stopped = _snapshot(manager, "signal", sandbox_id=started.id, signal=signal.SIGSTOP)
        assert stopped.state is SandboxState.PAUSED
        assert stopped.paused

        with pytest.raises(SandboxCapabilityError, match="original post-exec stop"):
            manager.dispatch("attach", {"sandbox_id": started.id})
        assert fake_gdb.execute_calls == []
        assert fake_gdb.calls == []
    finally:
        manager.close()


def test_gdb_attach_revalidates_the_retained_pidfd_identity(tmp_path, native_shim, monkeypatch):
    fake_gdb = _FakeGdb()
    manager, _factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()"), paused=True),
        native_shim,
        gdb_pool=_FakeGdbPool(fake_gdb),
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        assert started.host_pid is not None
        monkeypatch.setattr(
            manager_module._ShimController,
            "host_pid",
            property(lambda _controller: started.host_pid + 1),
        )

        with pytest.raises(SandboxCapabilityError, match="identity is no longer valid"):
            manager.dispatch("attach", {"sandbox_id": started.id})
        assert fake_gdb.execute_calls == []
        assert fake_gdb.calls == []
    finally:
        manager.close()


@pytest.mark.parametrize("operation", ["resume", "close"])
def test_gdb_attach_serializes_lifecycle_operations(tmp_path, native_shim, operation):
    marker = tmp_path / f"target-ran-{operation}"
    command = _python(
        "from pathlib import Path; import signal, sys; Path(sys.argv[1]).touch(); signal.pause()",
        marker,
    )
    fake_gdb = _BlockingFakeGdb()
    manager, _factory = _manager(
        tmp_path,
        _project(tmp_path, command, paused=True),
        native_shim,
        gdb_pool=_FakeGdbPool(fake_gdb),
    )
    attach_results: list[dict] = []
    attach_errors: list[BaseException] = []
    lifecycle_errors: list[BaseException] = []
    lifecycle_entered = threading.Event()
    lifecycle_finished = threading.Event()
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        session = manager._session(started.id)

        def attach_target():
            try:
                attach_results.append(manager.dispatch("attach", {"sandbox_id": started.id}))
            except BaseException as error:  # noqa: BLE001 - asserted after joining
                attach_errors.append(error)

        original_operation = getattr(session, operation)

        def observed_operation():
            lifecycle_entered.set()
            return original_operation()

        setattr(session, operation, observed_operation)

        def change_lifecycle():
            try:
                manager.dispatch(operation, {"sandbox_id": started.id})
            except BaseException as error:  # noqa: BLE001 - asserted after joining
                lifecycle_errors.append(error)
            finally:
                lifecycle_finished.set()

        attach_thread = threading.Thread(target=attach_target, name=f"test-sandbox-attach-{operation}")
        attach_thread.start()
        assert fake_gdb.attach_entered.wait(TIMEOUT)
        assert not marker.exists()
        # The callback itself, not merely the preceding state check, owns the
        # exact session lifecycle lock.
        assert not session._operation_lock.acquire(blocking=False)

        lifecycle_thread = threading.Thread(target=change_lifecycle, name=f"test-sandbox-{operation}")
        lifecycle_thread.start()
        assert lifecycle_entered.wait(TIMEOUT)
        assert not lifecycle_finished.is_set()
        assert not marker.exists()

        fake_gdb.release_attach.set()
        attach_thread.join(TIMEOUT)
        lifecycle_thread.join(TIMEOUT)
        assert not attach_thread.is_alive()
        assert not lifecycle_thread.is_alive()
        assert attach_errors == []
        assert lifecycle_errors == []
        assert attach_results == [
            {
                "sandbox_id": started.id,
                "host_pid": started.host_pid,
                "generation": None,
            }
        ]
    finally:
        fake_gdb.release_attach.set()
        manager.close()


def test_attach_requires_a_selected_gdb_and_lifecycle_errors_are_typed(tmp_path, native_shim):
    manager, _factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()"), paused=True),
        native_shim,
        gdb_pool=_FakeGdbPool(),
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        with pytest.raises(SandboxCapabilityError, match="GDB|gdb|selected"):
            manager.dispatch("attach", {"sandbox_id": started.id})
        with pytest.raises(SandboxNotFoundError, match="missing"):
            manager.dispatch("get", {"sandbox_id": "missing"})
        with pytest.raises(SandboxConfigError, match="profile"):
            manager.dispatch(
                "start",
                {"profile": "missing", "command": None, "env": None, "stdio": None, "paused": None},
            )
        with pytest.raises(SandboxProtocolError, match="operation"):
            manager.dispatch("not-an-operation", {})

        closed = _snapshot(manager, "close", sandbox_id=started.id)
        assert closed.state is SandboxState.CLOSED
        with pytest.raises(SandboxNotFoundError):
            manager.dispatch("get", {"sandbox_id": started.id})
    finally:
        manager.close()


def test_manager_close_is_idempotent_kills_children_and_cleans_runtime(tmp_path, native_shim):
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()")),
        native_shim,
    )
    stdio_socket = None
    manager_runtime = manager.runtime_dir
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        stdio_socket = Path(started.stdio_socket)
        assert stdio_socket.is_socket()
        manager.close()
        manager.close()

        assert factory.instances[0]._done.wait(TIMEOUT)
        assert factory.instances[0].closed
        assert all(backend.closed for backend in factory.backends)
        assert not stdio_socket.exists()
        assert not manager_runtime.exists()
        with pytest.raises(SandboxBackendError, match="closed"):
            manager.dispatch(
                "start",
                {"profile": None, "command": None, "env": None, "stdio": None, "paused": None},
            )
    finally:
        manager.close()


def test_manager_close_retains_exact_failed_resources_for_retry(tmp_path, native_shim):
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()"), stdio="none"),
        native_shim,
    )
    started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
    session = manager._session(started.id)
    instance = factory.instances[0]
    backend = factory.backends[0]
    instance_close = instance.close
    backend_close = backend.close
    instance_attempts = 0
    backend_attempts = 0

    def retry_instance_close():
        nonlocal instance_attempts
        instance_attempts += 1
        if instance_attempts == 1:
            raise SandboxBackendError("first exact instance close failed")
        return instance_close()

    def retry_backend_close():
        nonlocal backend_attempts
        backend_attempts += 1
        if backend_attempts == 1:
            raise SandboxBackendError("first backend close failed")
        return backend_close()

    instance.close = retry_instance_close
    backend.close = retry_backend_close
    with pytest.raises(SandboxBackendError, match="manager cleanup failed"):
        manager.close()

    with manager._condition:
        assert manager._sessions[started.id] is session
        assert not manager._closed
    assert not session.closed
    assert session.instance is instance
    assert session.backend is backend
    assert session.snapshot().container_id == started.container_id
    assert manager.runtime_dir.is_dir()

    manager.close()
    # The session retries the exact instance, then the backend verifies its
    # own exact-instance registry while completing session-level cleanup.
    assert instance_attempts == 3
    assert backend_attempts == 2
    assert instance.closed
    assert backend.closed
    assert not manager.runtime_dir.exists()


class _FailOnceClose:
    error = None

    def __init__(self, *, path=None) -> None:
        self.path = path
        self.attempts = 0
        self.closed = False

    def close(self):
        self.attempts += 1
        if self.attempts == 1:
            raise SandboxBackendError("injected resource close failure")
        self.closed = True


def test_dead_stdio_broker_is_not_advertised_and_keeps_target_usable(tmp_path, native_shim, monkeypatch):
    worker_entered = threading.Event()

    def fail_worker_events(_broker, _selector):
        worker_entered.set()
        raise OSError("injected stdio selector failure")

    monkeypatch.setattr(StdioBroker, "_events", fail_worker_events)
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()")),
        native_shim,
    )
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        assert worker_entered.wait(TIMEOUT)
        session = manager._session(started.id)
        assert session.broker is not None
        with session.broker._condition:
            assert session.broker._condition.wait_for(lambda: session.broker.error is not None, TIMEOUT)

        binding = SandboxPortBinding(
            name="challenge",
            internal_port=31337,
            host="127.0.0.1",
            host_port=43137,
        )
        factory.instances[0].ports = (binding,)
        snapshot = _snapshot(manager, "get", sandbox_id=started.id)

        assert snapshot.state is SandboxState.RUNNING
        assert snapshot.stdio_socket is None
        assert snapshot.ports == (binding,)
        assert snapshot.error == "stdio broker failed: injected stdio selector failure"
    finally:
        manager.close()


class _FailOnceController(_FailOnceClose):
    exit_event = object()


class _FailOnceInstance(_FailOnceClose):
    container_id = "exact-container-id"
    ports = ()


def test_session_cleanup_retries_every_failed_resource_before_marking_closed(tmp_path, native_shim):
    runtime = tmp_path / "owned-session"
    runtime.mkdir()
    broker_path = runtime / "stdio.sock"
    listener_path = runtime / "control.sock"
    broker_path.touch()
    listener_path.touch()
    session = manager_module._SandboxSession(
        "s-owned-resources",
        _project(tmp_path, ["/does/not/matter"], stdio="none").profile(),
        runtime,
        shim_path=native_shim,
        backend_factory=_SilentFactory(),
        startup_timeout=TIMEOUT,
        operation_timeout=TIMEOUT,
    )
    broker = _FailOnceClose(path=broker_path)
    controller = _FailOnceController()
    listener = _FailOnceClose(path=listener_path)
    instance = _FailOnceInstance()
    backend = _FailOnceClose()
    session.broker = broker
    session.controller = controller
    session.listener = listener
    session.instance = instance
    session.backend = backend
    read_fd, write_fd = os.pipe()
    session._stdio_fds.extend((read_fd, write_fd))

    assert session.snapshot().container_id == "exact-container-id"
    with pytest.raises(SandboxBackendError, match="cleanup failed"):
        session.close()
    assert not session.closed
    assert session.snapshot().state is SandboxState.FAILED
    assert session.snapshot().container_id == "exact-container-id"
    assert session.broker is broker
    assert session.controller is controller
    assert session.listener is listener
    assert session.instance is instance
    assert session.backend is backend
    assert runtime.is_dir()

    closed = session.close()
    assert closed.state is SandboxState.CLOSED
    assert session.closed
    assert all(resource.attempts == 2 for resource in (broker, controller, listener, instance, backend))
    assert all(resource.closed for resource in (broker, controller, listener, instance, backend))
    assert not runtime.exists()
    for descriptor in (read_fd, write_fd):
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


def test_manager_close_wakes_an_already_blocked_waiter(tmp_path, native_shim):
    manager, _factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; print('READY', flush=True); signal.pause()")),
        native_shim,
    )
    tube = None
    waiter = None
    try:
        started = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        assert tube.recvline(timeout=TIMEOUT) == b"READY\n"
        session = manager._session(started.id)
        entered = threading.Event()
        original_wait_for = session._condition.wait_for

        def observed_wait_for(predicate, timeout=None):
            entered.set()
            return original_wait_for(predicate, timeout)

        session._condition.wait_for = observed_wait_for
        result = []
        errors = []

        def wait_for_close() -> None:
            try:
                result.append(_snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=None))
            except BaseException as error:  # noqa: BLE001 - surface thread failure below
                errors.append(error)

        waiter = threading.Thread(target=wait_for_close)
        waiter.start()
        assert entered.wait(TIMEOUT)
        manager.close()
        waiter.join(TIMEOUT)
        assert not waiter.is_alive()
        assert not errors
        assert len(result) == 1
        assert result[0].state in {SandboxState.EXITED, SandboxState.CLOSED}
    finally:
        if tube is not None:
            tube.close()
        manager.close()
        if waiter is not None:
            waiter.join(TIMEOUT)


def test_ping_and_list_snapshots_are_stable_and_close_is_exact(tmp_path, native_shim):
    manager, factory = _manager(
        tmp_path,
        _project(tmp_path, _python("import signal; signal.pause()")),
        native_shim,
    )
    try:
        ping = manager.dispatch("ping", {})
        assert ping["backend"] == SandboxBackend.DOCKER.value
        assert isinstance(ping["version"], int)
        first = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        second = _snapshot(manager, "start", profile=None, command=None, env=None, stdio=None, paused=None)
        listed = tuple(SandboxSnapshot.from_wire(item) for item in manager.dispatch("list", {}))
        assert {item.id for item in listed} == {first.id, second.id}
        assert len({first.id, second.id}) == 2

        closed = _snapshot(manager, "close", sandbox_id=first.id)
        assert closed.id == first.id
        assert closed.state is SandboxState.CLOSED
        assert factory.instances[0].closed
        assert not factory.instances[1].closed
        remaining = tuple(SandboxSnapshot.from_wire(item) for item in manager.dispatch("list", {}))
        assert [item.id for item in remaining] == [second.id]
    finally:
        manager.close()
