from __future__ import annotations

import json
import signal
import socket
import threading
from pathlib import Path

import pytest

from pwnc.sandbox.client import SandboxClient
from pwnc.sandbox.discovery import SandboxManagerAddress, acquire_manager_socket
from pwnc.sandbox.errors import (
    SandboxCapabilityError,
    SandboxConfigError,
    SandboxNotFoundError,
    SandboxProtocolError,
)
from pwnc.sandbox.model import SandboxState, SandboxStdio
from pwnc.sandbox.protocol import request_message, send_message
from pwnc.sandbox.server import SandboxServer
from tests.sandbox.test_manager import (
    TIMEOUT,
    _build_native_shim,
    _FakeGdb,
    _FakeGdbPool,
    _manager,
    _project,
    _python,
)


@pytest.fixture(scope="session")
def native_shim(tmp_path_factory) -> Path:
    return _build_native_shim(tmp_path_factory)


def _serve(tmp_path, native_shim, command, *, stdio="pipe", paused=False, gdb_pool=None):
    project = _project(tmp_path, command, stdio=stdio, paused=paused)
    manager, factory = _manager(tmp_path, project, native_shim, gdb_pool=gdb_pool)
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    try:
        lease = acquire_manager_socket(address)
    except BaseException:
        manager.close()
        raise
    try:
        server = SandboxServer(manager, lease).start()
    except BaseException:
        lease.close()
        manager.close()
        raise
    client = SandboxClient(address.path, default_timeout=TIMEOUT, address=address)
    return server, client, manager, factory


def test_public_client_round_trip_pause_attach_stdio_wait_and_close(tmp_path, native_shim):
    fake_gdb = _FakeGdb()
    pool = _FakeGdbPool(fake_gdb)
    command = _python(
        "import sys; print('READY', flush=True); data=sys.stdin.buffer.readline(); "
        "sys.stdout.buffer.write(b'ECHO:'+data); sys.stdout.buffer.flush(); raise SystemExit(11)"
    )
    server, client, _manager_instance, _factory = _serve(
        tmp_path,
        native_shim,
        command,
        paused=True,
        gdb_pool=pool,
    )
    try:
        ping = client.ping()
        assert ping["backend"] == "docker"
        remote = client.start()
        assert remote.state is SandboxState.PAUSED
        assert remote.paused
        assert remote.host_pid is not None
        assert [item.id for item in client.list()] == [remote.id]
        assert client.get(remote.id).snapshot == remote.snapshot

        attached = remote.attach()
        assert attached["host_pid"] == remote.host_pid
        assert fake_gdb.calls == [(remote.host_pid, f"/proc/{remote.host_pid}/exe")]
        assert remote.refresh().state is SandboxState.PAUSED

        tube = remote.stdio(timeout=TIMEOUT)
        try:
            assert remote.resume().state is SandboxState.RUNNING
            assert tube.recvline(timeout=TIMEOUT) == b"READY\n"
            tube.send(b"client-bytes\xff\n")
            assert tube.recvline(timeout=TIMEOUT) == b"ECHO:client-bytes\xff\n"
        finally:
            tube.close()
        exited = remote.wait(TIMEOUT)
        assert exited.state is SandboxState.EXITED
        assert exited.exit_code == 11

        closed = remote.close()
        assert closed.state is SandboxState.CLOSED
        assert client.list() == ()
    finally:
        server.close()
    assert server.wait_closed(TIMEOUT)
    assert not (tmp_path / "manager.sock").exists()


def test_remote_errors_keep_types_and_client_side_validation_is_local(tmp_path, native_shim):
    command = _python("import signal; signal.pause()")
    server, client, _manager_instance, _factory = _serve(tmp_path, native_shim, command, stdio="none")
    try:
        with pytest.raises(SandboxNotFoundError, match="missing"):
            client.get("missing")
        with pytest.raises(SandboxProtocolError, match="operation"):
            client._request("definitely-unknown")
        with pytest.raises(SandboxConfigError, match="stdio"):
            client.start(stdio="not-a-mode")

        remote = client.start()
        assert remote.snapshot.stdio is SandboxStdio.NONE
        with pytest.raises(SandboxNotFoundError, match="no stdio"):
            remote.stdio()
        with pytest.raises(ValueError, match="port name"):
            remote.connect()
        with pytest.raises(TypeError, match="signal"):
            remote.signal("SIGTERM")
        with pytest.raises(ValueError, match="rows"):
            remote.resize(0, 80)
        with pytest.raises(SandboxCapabilityError, match="PTY"):
            remote.resize(24, 80)
        with pytest.raises(TimeoutError, match="timed out"):
            remote.wait(0.0)
        assert remote.refresh().state is SandboxState.RUNNING
        remote.kill()
        assert remote.wait(TIMEOUT).exit_code == -signal.SIGKILL
    finally:
        server.close()


class _WaitObservedManager:
    def __init__(self, manager) -> None:
        self.manager = manager
        self.wait_entered = threading.Event()
        self.release_wait = threading.Event()

    def dispatch(self, operation, arguments):
        if operation == "wait":
            self.wait_entered.set()
            self.release_wait.wait()
        return self.manager.dispatch(operation, arguments)

    def close(self):
        return self.manager.close()


def test_blocked_wait_request_does_not_block_ping_or_other_clients(tmp_path, native_shim):
    command = _python("import signal; print('READY', flush=True); signal.pause()")
    project = _project(tmp_path, command)
    manager, _factory = _manager(tmp_path, project, native_shim)
    observed = _WaitObservedManager(manager)
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    server = SandboxServer(observed, acquire_manager_socket(address)).start()
    first = SandboxClient(address.path, default_timeout=TIMEOUT)
    second = SandboxClient(address.path, default_timeout=TIMEOUT)
    try:
        remote = first.start()
        tube = remote.stdio(timeout=TIMEOUT)
        try:
            assert tube.recvline(timeout=TIMEOUT) == b"READY\n"
            result = []
            errors = []

            def wait_remote() -> None:
                try:
                    result.append(remote.wait(TIMEOUT))
                except BaseException as error:  # noqa: BLE001 - surface thread error below
                    errors.append(error)

            waiter = threading.Thread(target=wait_remote)
            waiter.start()
            assert observed.wait_entered.wait(TIMEOUT)
            assert second.ping()["backend"] == "docker"
            assert second.get(remote.id).state is SandboxState.RUNNING
            observed.release_wait.set()
            second.get(remote.id).kill()
            waiter.join(TIMEOUT)
            assert not waiter.is_alive()
            assert not errors
            assert len(result) == 1
            assert result[0].state is SandboxState.EXITED
        finally:
            observed.release_wait.set()
            tube.close()
    finally:
        server.close()


class _BlockingRequestManager:
    def __init__(self) -> None:
        self.dispatch_entered = threading.Event()
        self.release_dispatch = threading.Event()
        self.close_called = threading.Event()

    def dispatch(self, operation, arguments):
        assert operation == "ping"
        assert arguments == {}
        self.dispatch_entered.set()
        assert self.release_dispatch.wait(TIMEOUT)
        return {"finished": True}

    def close(self):
        self.close_called.set()


def test_server_keeps_lease_until_all_request_workers_finish(tmp_path, monkeypatch):
    manager = _BlockingRequestManager()
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    server = SandboxServer(manager, acquire_manager_socket(address)).start()
    client = SandboxClient(address.path, default_timeout=TIMEOUT)
    results: list[dict] = []
    request_errors: list[BaseException] = []
    close_errors: list[BaseException] = []
    close_done = threading.Event()
    worker_waiting = threading.Event()

    def request():
        try:
            results.append(client.ping())
        except BaseException as error:  # noqa: BLE001
            request_errors.append(error)

    original_wait_for = server._condition.wait_for

    def observed_wait_for(predicate, timeout=None):
        if timeout is None and not predicate():
            worker_waiting.set()
        return original_wait_for(predicate, timeout)

    monkeypatch.setattr(server._condition, "wait_for", observed_wait_for)

    def close_server():
        try:
            server.close()
        except BaseException as error:  # noqa: BLE001
            close_errors.append(error)
        finally:
            close_done.set()

    requester = threading.Thread(target=request)
    closer = threading.Thread(target=close_server)
    requester.start()
    assert manager.dispatch_entered.wait(TIMEOUT)
    closer.start()
    assert manager.close_called.wait(TIMEOUT)
    assert worker_waiting.wait(TIMEOUT)
    assert not close_done.is_set()
    assert address.path.exists()
    with server._condition:
        assert server._workers

    manager.release_dispatch.set()
    requester.join(TIMEOUT)
    closer.join(TIMEOUT)
    assert not requester.is_alive()
    assert not closer.is_alive()
    assert request_errors
    assert not results
    assert not close_errors
    assert not address.path.exists()
    with server._condition:
        assert not server._workers


def test_server_close_interrupts_worker_blocked_sending_response(tmp_path, monkeypatch):
    import pwnc.sandbox.server as server_module

    manager = _BlockingRequestManager()
    manager.release_dispatch.set()
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    server = SandboxServer(manager, acquire_manager_socket(address)).start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    send_blocked = threading.Event()
    send_returned = threading.Event()
    real_send_message = server_module.send_message

    def block_while_sending(connection, value):
        if value.get("ok") is not True:
            return real_send_message(connection, value)
        payload = b"x" * (8 * 1024 * 1024)
        connection.setblocking(False)
        sent = 0
        try:
            while sent < len(payload):
                try:
                    sent += connection.send(payload[sent:])
                except BlockingIOError:
                    break
            assert sent < len(payload)
            connection.setblocking(True)
            send_blocked.set()
            connection.sendall(payload[sent:])
        finally:
            send_returned.set()

    monkeypatch.setattr(server_module, "send_message", block_while_sending)
    try:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        client.connect(str(address.path))
        send_message(client, request_message("ping"))
        assert manager.dispatch_entered.wait(TIMEOUT)
        assert send_blocked.wait(TIMEOUT)

        server.close()

        assert send_returned.wait(TIMEOUT)
        assert server.closed
        with server._condition:
            assert not server._workers
            assert not server._connections
    finally:
        client.close()
        server.close()


def test_shutdown_acknowledges_then_closes_manager_socket_and_live_targets(tmp_path, native_shim):
    command = _python("import signal; signal.pause()")
    server, client, _manager_instance, factory = _serve(tmp_path, native_shim, command)
    try:
        remote = client.start()
        assert remote.state is SandboxState.RUNNING

        client.shutdown()
        assert server.wait_closed(TIMEOUT)
        assert server.closed
        assert server.error is None
        assert factory.instances[0]._done.wait(TIMEOUT)
        assert factory.instances[0].closed
        assert not Path(client.socket_path).exists()
    finally:
        server.close()


def test_never_started_server_close_releases_manager_and_socket(tmp_path, native_shim):
    command = _python("import signal; signal.pause()")
    config = _project(tmp_path, command)
    manager, _factory = _manager(tmp_path, config, native_shim)
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    lease = acquire_manager_socket(address)
    runtime = manager.runtime_dir
    server = SandboxServer(manager, lease)

    server.close()

    assert server.closed
    assert server.error is None
    assert not address.path.exists()
    assert not runtime.exists()


def test_server_close_wakes_blocked_remote_wait_and_leaves_no_request_worker(tmp_path, native_shim):
    command = _python("import signal; print('READY', flush=True); signal.pause()")
    server, client, manager, _factory = _serve(tmp_path, native_shim, command)
    tube = None
    waiter = None
    try:
        remote = client.start()
        tube = remote.stdio(timeout=TIMEOUT)
        assert tube.recvline(timeout=TIMEOUT) == b"READY\n"
        session = manager._session(remote.id)
        entered = threading.Event()
        original_wait_for = session._condition.wait_for

        def observed_wait_for(predicate, timeout=None):
            entered.set()
            return original_wait_for(predicate, timeout)

        session._condition.wait_for = observed_wait_for
        results = []
        errors = []

        def wait_remote() -> None:
            try:
                results.append(remote.wait())
            except BaseException as error:  # noqa: BLE001 - surface thread failure below
                errors.append(error)

        waiter = threading.Thread(target=wait_remote)
        waiter.start()
        assert entered.wait(TIMEOUT)
        server.close()
        waiter.join(TIMEOUT)
        assert not waiter.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], EOFError)
        assert not results
        with server._condition:
            assert not server._workers
    finally:
        if tube is not None:
            tube.close()
        server.close()
        if waiter is not None:
            waiter.join(TIMEOUT)


def test_run_manager_owns_persistent_server_until_remote_shutdown(tmp_path, native_shim, monkeypatch):
    import pwnc.sandbox.discovery as discovery_module
    import pwnc.sandbox.manager as manager_module

    config_path = tmp_path / "project" / "pwnc.toml"
    config_path.parent.mkdir()
    config_path.write_text(
        "\n".join(
            (
                "[sandbox]",
                'default-profile = "default"',
                "",
                "[sandbox.default]",
                f"command = {json.dumps(_python('raise SystemExit(99)'))}",
                'stdio = "none"',
                "",
                "[sandbox.default.docker]",
                'image = "unused-by-native-fixture"',
                "",
            )
        )
    )
    socket_path = tmp_path / "persistent-manager.sock"
    # Importing the shared fixture class here keeps this test focused on the
    # public persistent entry point rather than Docker availability.
    from tests.sandbox.test_manager import _NativeBackendFactory

    factory = _NativeBackendFactory()
    acquired = threading.Event()
    real_acquire = discovery_module.acquire_manager_socket

    def observed_acquire(*args, **kwargs):
        lease = real_acquire(*args, **kwargs)
        acquired.set()
        return lease

    monkeypatch.setattr(discovery_module, "acquire_manager_socket", observed_acquire)
    results = []
    errors = []

    def serve() -> None:
        try:
            results.append(
                manager_module.run_manager(
                    socket_path=socket_path,
                    config_path=config_path,
                    runtime_dir=tmp_path / "runtime",
                    backend_factory=factory,
                    shim_builder=lambda: native_shim,
                    startup_timeout=TIMEOUT,
                )
            )
        except BaseException as error:  # noqa: BLE001 - surface thread error below
            errors.append(error)

    thread = threading.Thread(target=serve, name="run-manager-test")
    thread.start()
    assert acquired.wait(TIMEOUT)
    client = SandboxClient(socket_path, default_timeout=TIMEOUT)
    assert client.ping()["backend"] == "docker"
    target = client.start(
        command=_python("import sys; raise SystemExit(6)"),
        stdio=SandboxStdio.NONE,
        paused=False,
    )
    assert target.wait(TIMEOUT).exit_code == 6
    client.shutdown()
    thread.join(TIMEOUT)
    assert not thread.is_alive()
    assert not errors
    assert len(results) == 1
    assert not socket_path.exists()
