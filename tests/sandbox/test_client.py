from __future__ import annotations

import signal
import socket
import struct

import pytest

import pwnc.sandbox.client as client_module
from pwnc.sandbox.client import RemoteSandbox, SandboxClient
from pwnc.sandbox.model import (
    SandboxBackend,
    SandboxPortBinding,
    SandboxSnapshot,
    SandboxState,
    SandboxStdio,
)


def test_remote_handle_uses_client_default_timeout_and_preserves_explicit_none(monkeypatch):
    monkeypatch.setattr(
        client_module.socket,
        "SO_PEERCRED",
        getattr(client_module.socket, "SO_PEERCRED", 17),
        raising=False,
    )
    snapshot = SandboxSnapshot(
        id="s-timeout",
        profile="default",
        backend=SandboxBackend.DOCKER,
        state=SandboxState.RUNNING,
        created_at=1.0,
        stdio=SandboxStdio.PIPE,
        stdio_socket="/tmp/stdio.sock",
        ports=(SandboxPortBinding("pwn", 31337, "127.0.0.1", 41001),),
    )
    unset = object()
    sockets = []
    requests = []
    stdio_connections = []
    network_connections = []

    class Socket:
        def __init__(self):
            self.timeout = unset
            self.connected = None
            self.closed = False
            self.peer_checks = 0

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, path):
            self.connected = path

        def getsockopt(self, level, option, size):
            assert level == socket.SOL_SOCKET
            assert option == socket.SO_PEERCRED
            assert size == struct.calcsize("3i")
            self.peer_checks += 1
            return struct.pack("3i", 1234, client_module.os.getuid(), client_module.os.getgid())

        def close(self):
            self.closed = True

    def make_socket(*_args):
        connection = Socket()
        sockets.append(connection)
        return connection

    def send_message(_connection, request):
        requests.append(request)

    def parse_response(_response):
        if requests[-1]["operation"] == "attach":
            return {"generation": 1}
        return snapshot.to_wire()

    monkeypatch.setattr(client_module.socket, "socket", make_socket)
    monkeypatch.setattr(client_module, "send_message", send_message)
    monkeypatch.setattr(client_module, "receive_message", lambda _connection: {})
    monkeypatch.setattr(client_module, "parse_response", parse_response)
    monkeypatch.setattr(
        client_module,
        "connect_stdio",
        lambda path, *, timeout: stdio_connections.append((path, timeout)) or object(),
    )
    monkeypatch.setattr(
        client_module,
        "remote",
        lambda host, port, *, typ, timeout: network_connections.append((host, port, typ, timeout)) or object(),
    )

    client = SandboxClient("/tmp/manager.sock", default_timeout=5.0)
    remote = RemoteSandbox(client, snapshot)
    remote.refresh()
    remote.stdio()
    remote.connect()
    remote.resume()
    remote.signal(signal.SIGTERM)
    remote.kill()
    remote.resize(24, 80)
    assert remote.attach() == {"generation": 1}
    remote.wait()
    remote.close()

    assert [connection.timeout for connection in sockets] == [5.0] * 8 + [6.0, 5.0]
    assert stdio_connections == [("/tmp/stdio.sock", 5.0)]
    assert network_connections == [("127.0.0.1", 41001, "tcp", 5.0)]
    wait_request = next(request for request in requests if request["operation"] == "wait")
    assert wait_request["arguments"]["wait_timeout"] == 5.0
    assert all(connection.connected == "/tmp/manager.sock" for connection in sockets)
    assert all(connection.peer_checks == 1 for connection in sockets)
    assert all(connection.closed for connection in sockets)

    first_unbounded = len(sockets)
    remote.refresh(timeout=None)
    remote.stdio(timeout=None)
    remote.connect(timeout=None)
    remote.wait(None)
    remote.close(timeout=None)

    assert all(connection.timeout is unset for connection in sockets[first_unbounded:])
    assert stdio_connections[-1] == ("/tmp/stdio.sock", None)
    assert network_connections[-1] == ("127.0.0.1", 41001, "tcp", None)
    assert requests[-2]["operation"] == "wait"
    assert requests[-2]["arguments"]["wait_timeout"] is None
    assert all(connection.peer_checks == 1 for connection in sockets)


def test_control_connection_rejects_unverified_peer_before_sending(monkeypatch):
    events = []

    class Socket:
        def settimeout(self, timeout):
            events.append(("timeout", timeout))

        def connect(self, path):
            events.append(("connect", path))

        def close(self):
            events.append(("close", None))

    connection = Socket()
    monkeypatch.setattr(client_module.socket, "socket", lambda *_args: connection)

    def reject_peer(actual):
        assert actual is connection
        events.append(("verify", None))
        raise PermissionError("wrong peer")

    monkeypatch.setattr(client_module, "require_same_uid", reject_peer)
    monkeypatch.setattr(
        client_module,
        "send_message",
        lambda *_args: events.append(("send", None)),
    )

    with pytest.raises(PermissionError, match="wrong peer"):
        SandboxClient("/tmp/manager.sock", default_timeout=2).ping()

    assert events == [
        ("timeout", 2),
        ("connect", "/tmp/manager.sock"),
        ("verify", None),
        ("close", None),
    ]
