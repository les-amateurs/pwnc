import errno
import os
import socket
import threading

import pytest

import pwnc.sandbox.stdio as stdio_module
from pwnc.sandbox.errors import SandboxBackendError
from pwnc.sandbox.stdio import StdioBroker, connect_stdio


def _pipes():
    target_input, broker_input = os.pipe()
    broker_output, target_output = os.pipe()
    return target_input, broker_input, broker_output, target_output


def _close_all(*descriptors):
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


def test_stdio_broker_is_binary_exact_and_reconnectable(tmp_path):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    target_input, broker_input, broker_output, target_output = _pipes()
    broker = StdioBroker(
        runtime / "stdio.sock",
        input_fd=broker_input,
        output_fd=broker_output,
    ).start()
    first = None
    second = None
    try:
        first = connect_stdio(broker.path, timeout=2)
        assert broker.wait_connected(2)

        output = b"\x00\n\r\xfftarget"
        os.write(target_output, output)
        assert first.recvn(len(output), timeout=2) == output

        sent = b"\xff\x00client\n"
        first.send(sent)
        assert os.read(target_input, len(sent)) == sent

        first.close()
        first = None
        assert broker.wait_disconnected(2)
        backlog = b"produced while detached"
        os.write(target_output, backlog)

        second = connect_stdio(broker.path, timeout=2)
        assert broker.wait_connected(2)
        assert second.recvn(len(backlog), timeout=2) == backlog
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()
        broker.close()
        _close_all(target_input, broker_input, broker_output, target_output)


def test_stdio_broker_rejects_a_second_simultaneous_client(tmp_path):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    target_input, broker_input, broker_output, target_output = _pipes()
    broker = StdioBroker(
        runtime / "stdio.sock",
        input_fd=broker_input,
        output_fd=broker_output,
    ).start()
    first = connect_stdio(broker.path, timeout=2)
    second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    second.settimeout(2)
    try:
        assert broker.wait_connected(2)
        second.connect(os.fspath(broker.path))
        assert b"already attached" in second.recv(128)
    finally:
        second.close()
        first.close()
        broker.close()
        _close_all(target_input, broker_input, broker_output, target_output)


def test_connect_stdio_rejects_unverified_peer_before_returning_tube(monkeypatch):
    events = []

    class Socket:
        family = socket.AF_UNIX
        type = socket.SOCK_STREAM
        proto = 0

        def settimeout(self, timeout):
            events.append(("timeout", timeout))

        def connect(self, path):
            events.append(("connect", path))

        def close(self):
            events.append(("close", None))

    connection = Socket()
    monkeypatch.setattr(stdio_module.socket, "socket", lambda *_args: connection)

    def reject_peer(actual):
        assert actual is connection
        events.append(("verify", None))
        raise PermissionError("wrong stdio peer")

    monkeypatch.setattr(stdio_module, "require_same_uid", reject_peer)

    with pytest.raises(PermissionError, match="wrong stdio peer"):
        connect_stdio("/tmp/stdio.sock", timeout=2)

    assert events == [
        ("timeout", 2),
        ("connect", "/tmp/stdio.sock"),
        ("verify", None),
        ("close", None),
    ]


def test_stdio_close_wakes_and_joins_worker_without_timeout(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    target_input, broker_input, broker_output, target_output = _pipes()
    broker = StdioBroker(
        runtime / "stdio.sock",
        input_fd=broker_input,
        output_fd=broker_output,
    ).start()
    worker = broker._thread
    joined = threading.Event()
    original_join = threading.Thread.join

    def observed_join(thread, timeout=None):
        if thread is worker:
            assert timeout is None
            joined.set()
        return original_join(thread, timeout)

    monkeypatch.setattr(threading.Thread, "join", observed_join)
    try:
        broker.close()
        assert joined.is_set()
        assert broker.closed
        assert broker._thread is None
        assert broker._wake_r is None
        assert broker._wake_w is None
        assert broker._listener is None
        assert not broker.path.exists()
    finally:
        broker.close()
        _close_all(target_input, broker_input, broker_output, target_output)


def test_stdio_close_retains_failed_descriptor_and_retries_exact_cleanup(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    target_input, broker_input, broker_output, target_output = _pipes()
    broker = StdioBroker(
        runtime / "stdio.sock",
        input_fd=broker_input,
        output_fd=broker_output,
    ).start()
    failed_descriptor = broker._wake_r
    attempts = 0
    path_attempts = 0
    original_close = stdio_module.os.close
    original_remove_path = stdio_module._private_socket_path

    def fail_once(descriptor):
        nonlocal attempts
        if descriptor == failed_descriptor:
            attempts += 1
            if attempts == 1:
                raise OSError(errno.EIO, "injected close failure")
        return original_close(descriptor)

    def fail_path_once(path):
        nonlocal path_attempts
        if path == broker.path:
            path_attempts += 1
            if path_attempts == 1:
                raise OSError(errno.EIO, "injected endpoint unlink failure")
        return original_remove_path(path)

    monkeypatch.setattr(stdio_module.os, "close", fail_once)
    monkeypatch.setattr(stdio_module, "_private_socket_path", fail_path_once)
    try:
        with pytest.raises(SandboxBackendError, match="stdio broker cleanup failed"):
            broker.close()
        assert not broker.closed
        assert broker._wake_r == failed_descriptor
        assert broker._thread is None
        assert broker._listener is None
        assert broker.path.exists()

        broker.close()
        assert attempts == 2
        assert path_attempts == 2
        assert broker.closed
        assert broker._wake_r is None
        assert not broker.path.exists()
    finally:
        broker.close()
        _close_all(target_input, broker_input, broker_output, target_output)
