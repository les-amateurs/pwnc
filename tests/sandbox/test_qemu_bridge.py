from __future__ import annotations

import os
import socket
import threading

import pytest

import pwnc.sandbox._qemu_bridge as bridge_module
from pwnc.sandbox._qemu_bridge import QemuGdbBridge

TIMEOUT = 5.0


def _unix_echo(path, ready: threading.Event, release: threading.Event, errors: list[BaseException]) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(os.fspath(path))
        server.listen(1)
        ready.set()
        assert release.wait(TIMEOUT)
        connection, _ = server.accept()
        with connection:
            data = connection.recv(4096)
            connection.sendall(data[::-1])
    except BaseException as error:  # noqa: BLE001 - replay in test thread
        errors.append(error)
        ready.set()
    finally:
        server.close()


def test_bridge_reserves_loopback_port_and_relays_to_verified_unix_peer(tmp_path):
    bridge = QemuGdbBridge(tmp_path / "debug")
    ready = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    server = threading.Thread(target=_unix_echo, args=(bridge.socket_path, ready, release, errors), daemon=True)
    try:
        bridge.authorize(os.getpid())
        server.start()
        assert ready.wait(TIMEOUT)
        bridge.wait_ready(TIMEOUT)
        release.set()
        with socket.create_connection((bridge.host, bridge.host_port), timeout=TIMEOUT) as client:
            client.sendall(b"abcdef")
            assert client.recv(6) == b"fedcba"
        server.join(TIMEOUT)
        assert not server.is_alive()
        assert errors == []
        assert bridge.error is None
    finally:
        release.set()
        bridge.close()


def test_client_may_arrive_before_qemu_socket_without_polling(tmp_path):
    bridge = QemuGdbBridge(tmp_path / "debug")
    connected = threading.Event()
    result: list[bytes] = []
    errors: list[BaseException] = []

    def client() -> None:
        try:
            with socket.create_connection((bridge.host, bridge.host_port), timeout=TIMEOUT) as connection:
                connected.set()
                connection.sendall(b"early")
                result.append(connection.recv(5))
        except BaseException as error:  # noqa: BLE001
            errors.append(error)
            connected.set()

    bridge.authorize(os.getpid())
    client_thread = threading.Thread(target=client, daemon=True)
    client_thread.start()
    assert connected.wait(TIMEOUT)

    unix_ready = threading.Event()
    release = threading.Event()
    server = threading.Thread(target=_unix_echo, args=(bridge.socket_path, unix_ready, release, errors), daemon=True)
    try:
        server.start()
        assert unix_ready.wait(TIMEOUT)
        bridge.wait_ready(TIMEOUT)
        release.set()
        client_thread.join(TIMEOUT)
        server.join(TIMEOUT)
        assert result == [b"ylrae"]
        assert errors == []
    finally:
        release.set()
        bridge.close()


def test_bridge_rejects_a_unix_peer_with_the_wrong_pid(tmp_path):
    bridge = QemuGdbBridge(tmp_path / "debug")
    ready = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    server = threading.Thread(target=_unix_echo, args=(bridge.socket_path, ready, release, errors), daemon=True)
    try:
        bridge.authorize(os.getpid() + 1_000_000)
        server.start()
        assert ready.wait(TIMEOUT)
        bridge.wait_ready(TIMEOUT)
        release.set()
        with socket.create_connection((bridge.host, bridge.host_port), timeout=TIMEOUT):
            pass
        with bridge._condition:
            assert bridge._condition.wait_for(lambda: bridge.error is not None, TIMEOUT)
        assert "identity mismatch" in str(bridge.error)
    finally:
        release.set()
        bridge.close()
        server.join(TIMEOUT)


def test_bridge_requires_a_fresh_private_runtime_directory(tmp_path):
    directory = tmp_path / "debug"
    directory.mkdir()
    with pytest.raises(Exception, match="already exists"):
        QemuGdbBridge(directory)


def test_bridge_constructor_closes_watch_when_wake_socket_setup_fails(tmp_path, monkeypatch):
    closed = threading.Event()

    class Watch:
        def __init__(self, _directory):
            pass

        def close(self):
            closed.set()

    def fail_socketpair(*_arguments):
        raise OSError("injected socketpair failure")

    monkeypatch.setattr(bridge_module, "_DirectoryWatch", Watch)
    monkeypatch.setattr(socket, "socketpair", fail_socketpair)
    directory = tmp_path / "debug"

    with pytest.raises(OSError, match="injected socketpair failure"):
        QemuGdbBridge(directory)

    assert closed.is_set()
    assert not directory.exists()


def test_bridge_fails_closed_when_unix_peer_credentials_are_unavailable(tmp_path, monkeypatch):
    bridge = QemuGdbBridge(tmp_path / "debug")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(os.fspath(bridge.socket_path))
        server.listen(1)
        bridge.authorize(os.getpid())
        bridge.wait_ready(TIMEOUT)
        monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)

        with socket.create_connection((bridge.host, bridge.host_port), timeout=TIMEOUT):
            pass
        with bridge._condition:
            assert bridge._condition.wait_for(lambda: bridge.error is not None, TIMEOUT)
        assert "SO_PEERCRED is unavailable" in str(bridge.error)
    finally:
        server.close()
        bridge.close()


def test_bridge_cleanup_removes_guest_debris_without_following_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "must-survive"
    sentinel.write_bytes(b"host data")
    bridge = QemuGdbBridge(tmp_path / "debug")
    nested = bridge.directory / "guest" / "nested"
    nested.mkdir(parents=True)
    (nested / "junk").write_bytes(b"junk")
    (bridge.directory / "outside-link").symlink_to(outside, target_is_directory=True)
    nested.chmod(0)
    bridge.directory.chmod(0)

    bridge.close()

    assert not bridge.directory.exists()
    assert sentinel.read_bytes() == b"host data"
