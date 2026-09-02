import errno
import os
import socket
import struct

import pytest

from pwnc.sandbox.errors import SandboxConfigError, SandboxProtocolError
from pwnc.sandbox.model import SandboxDebug, SandboxSnapshot
from pwnc.sandbox.protocol import (
    MAX_MESSAGE_BYTES,
    failure,
    parse_request,
    parse_response,
    receive_message,
    request_message,
    require_same_uid,
    send_message,
    success,
)


def test_protocol_round_trip_over_stream_socketpair():
    left, right = socket.socketpair()
    try:
        request = request_message("start", profile="default", paused=True)
        send_message(left, request)
        assert receive_message(right) == request
        send_message(right, success({"id": "s-1"}))
        assert parse_response(receive_message(left)) == {"id": "s-1"}
    finally:
        left.close()
        right.close()


def test_snapshot_debug_descriptor_round_trips_through_protocol_with_legacy_default():
    snapshot = SandboxSnapshot(
        id="s-debug",
        profile="qemu",
        backend="docker",
        state="paused",
        created_at=1.0,
        debug=SandboxDebug(
            transport="tcp",
            architecture="aarch64",
            emulator="/usr/bin/qemu-aarch64",
            host="127.0.0.1",
            port=41234,
        ),
    )
    left, right = socket.socketpair()
    try:
        send_message(left, success(snapshot.to_wire()))
        result = SandboxSnapshot.from_wire(parse_response(receive_message(right)))
        assert result == snapshot

        legacy = snapshot.to_wire()
        legacy.pop("debug")
        send_message(left, success(legacy))
        assert SandboxSnapshot.from_wire(parse_response(receive_message(right))).debug is None
    finally:
        left.close()
        right.close()


def test_remote_typed_error_is_reconstructed():
    with pytest.raises(SandboxConfigError, match="broken profile"):
        parse_response(failure(SandboxConfigError("broken profile")))


def test_invalid_version_and_oversized_frame_are_rejected():
    with pytest.raises(SandboxProtocolError, match="version"):
        parse_request({"version": 999, "operation": "ping", "arguments": {}})
    left, right = socket.socketpair()
    try:
        left.sendall((MAX_MESSAGE_BYTES + 1).to_bytes(4, "big"))
        with pytest.raises(SandboxProtocolError, match="size"):
            receive_message(right)
    finally:
        left.close()
        right.close()


def test_same_uid_check_accepts_local_peer_and_rejects_other_uid(monkeypatch):
    option = getattr(socket, "SO_PEERCRED", 17)
    monkeypatch.setattr(socket, "SO_PEERCRED", option, raising=False)
    calls = []

    class Connection:
        def __init__(self, uid):
            self.uid = uid

        def getsockopt(self, level, requested_option, size):
            calls.append((level, requested_option, size))
            return struct.pack("3i", 1234, self.uid, 5678)

    require_same_uid(Connection(os.getuid()))
    with pytest.raises(PermissionError, match=r"sandbox peer uid .* does not match local uid"):
        require_same_uid(Connection(os.getuid() + 1))

    assert calls == [(socket.SOL_SOCKET, option, struct.calcsize("3i"))] * 2


def test_same_uid_check_fails_closed_when_peer_credentials_are_unavailable(monkeypatch):
    option = getattr(socket, "SO_PEERCRED", 17)
    monkeypatch.setattr(socket, "SO_PEERCRED", option, raising=False)

    class Connection:
        def getsockopt(self, _level, _option, _size):
            raise OSError(errno.ENOPROTOOPT, "peer credentials unavailable")

    with pytest.raises(OSError, match="peer credentials unavailable"):
        require_same_uid(Connection())


def test_same_uid_check_is_portable_when_so_peercred_is_not_exposed(monkeypatch):
    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)

    class Connection:
        def getsockopt(self, *_args):
            raise AssertionError("getsockopt must not be called without SO_PEERCRED")

    require_same_uid(Connection())
