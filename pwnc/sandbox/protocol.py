"""Small request/response protocol for the persistent sandbox manager."""

from __future__ import annotations

import json
import os
import socket
import struct
from collections.abc import Mapping

from .errors import (
    SandboxBackendError,
    SandboxCapabilityError,
    SandboxConfigError,
    SandboxError,
    SandboxNotFoundError,
    SandboxProtocolError,
)

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
_LENGTH = struct.Struct("!I")


_REMOTE_ERRORS = {
    cls.__name__: cls
    for cls in (
        SandboxError,
        SandboxBackendError,
        SandboxCapabilityError,
        SandboxConfigError,
        SandboxNotFoundError,
        SandboxProtocolError,
    )
}
_REMOTE_ERRORS["TimeoutError"] = TimeoutError


def _read_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EOFError("sandbox manager connection closed mid-message")
        result.extend(chunk)
    return bytes(result)


def receive_message(connection: socket.socket) -> dict:
    try:
        (size,) = _LENGTH.unpack(_read_exact(connection, _LENGTH.size))
    except struct.error as error:
        raise SandboxProtocolError("invalid sandbox protocol frame") from error
    if size <= 0 or size > MAX_MESSAGE_BYTES:
        raise SandboxProtocolError(f"sandbox protocol message size is invalid: {size}")
    try:
        value = json.loads(_read_exact(connection, size))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SandboxProtocolError("sandbox protocol message is not valid JSON") from error
    if not isinstance(value, dict):
        raise SandboxProtocolError("sandbox protocol message must be an object")
    return value


def send_message(connection: socket.socket, value: Mapping) -> None:
    if not isinstance(value, Mapping):
        raise TypeError("sandbox protocol message must be a mapping")
    try:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError) as error:
        raise SandboxProtocolError("sandbox protocol value is not JSON serializable") from error
    if not encoded or len(encoded) > MAX_MESSAGE_BYTES:
        raise SandboxProtocolError("sandbox protocol message is too large")
    connection.sendall(_LENGTH.pack(len(encoded)) + encoded)


def request_message(operation: str, **arguments) -> dict:
    if not isinstance(operation, str) or not operation or "\0" in operation:
        raise ValueError("sandbox operation must be nonempty text without NUL")
    return {
        "version": PROTOCOL_VERSION,
        "operation": operation,
        "arguments": arguments,
    }


def success(value=None) -> dict:
    return {"version": PROTOCOL_VERSION, "ok": True, "result": value}


def failure(error: BaseException) -> dict:
    return {
        "version": PROTOCOL_VERSION,
        "ok": False,
        "error": {
            "type": type(error).__name__,
            "message": str(error),
        },
    }


def parse_request(value: Mapping) -> tuple[str, dict]:
    if value.get("version") != PROTOCOL_VERSION:
        raise SandboxProtocolError("sandbox protocol version mismatch")
    operation = value.get("operation")
    arguments = value.get("arguments", {})
    if not isinstance(operation, str) or not operation:
        raise SandboxProtocolError("sandbox request has no operation")
    if not isinstance(arguments, dict):
        raise SandboxProtocolError("sandbox request arguments must be an object")
    return operation, arguments


def parse_response(value: Mapping):
    if value.get("version") != PROTOCOL_VERSION:
        raise SandboxProtocolError("sandbox protocol version mismatch")
    if value.get("ok") is True:
        return value.get("result")
    description = value.get("error")
    if not isinstance(description, dict):
        raise SandboxProtocolError("sandbox manager returned an invalid error")
    name = description.get("type", "SandboxError")
    message = description.get("message", "sandbox manager operation failed")
    if not isinstance(name, str) or not isinstance(message, str):
        raise SandboxProtocolError("sandbox manager returned an invalid error")
    error_type = _REMOTE_ERRORS.get(name, SandboxError)
    raise error_type(message)


def require_same_uid(connection: socket.socket) -> None:
    """Reject a Unix peer outside this process's uid when SO_PEERCRED exists."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return
    credentials = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    local_uid = os.getuid()
    if uid != local_uid:
        raise PermissionError(f"sandbox peer uid {uid} does not match local uid {local_uid}")


__all__ = [
    "MAX_MESSAGE_BYTES",
    "PROTOCOL_VERSION",
    "failure",
    "parse_request",
    "parse_response",
    "receive_message",
    "request_message",
    "require_same_uid",
    "send_message",
    "success",
]
