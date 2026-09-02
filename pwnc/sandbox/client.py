"""Blocking client and remote handles for a persistent sandbox manager."""

from __future__ import annotations

import os
import signal as signal_module
import socket
import threading
from types import MappingProxyType

from pwnlib.tubes.remote import remote

from .errors import SandboxDiscoveryError, SandboxNotFoundError
from .model import SandboxSnapshot, SandboxStdio
from .protocol import parse_response, receive_message, request_message, require_same_uid, send_message
from .stdio import connect_stdio

_DEFAULT_TIMEOUT = object()


class SandboxClient:
    """One-shot request client for a discoverable manager control socket."""

    def __init__(self, socket_path, *, default_timeout=30.0, address=None):
        self.socket_path = os.fspath(socket_path)
        self.default_timeout = default_timeout
        self.address = address

    @classmethod
    def discover(
        cls,
        name="default",
        *,
        socket_path=None,
        config_path=None,
        start=None,
        runtime_dir=None,
        default_timeout=30.0,
    ) -> SandboxClient:
        from .discovery import discover_client

        address = discover_client(
            name,
            socket_path=socket_path,
            config_path=config_path,
            start=start,
            runtime_dir=runtime_dir,
        )
        return cls(address.path, default_timeout=default_timeout, address=address)

    def _request(self, operation, *, timeout=_DEFAULT_TIMEOUT, **arguments):
        if timeout is _DEFAULT_TIMEOUT:
            timeout = self.default_timeout
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if timeout is not None:
            connection.settimeout(timeout)
        try:
            connection.connect(self.socket_path)
            require_same_uid(connection)
            send_message(connection, request_message(operation, **arguments))
            return parse_response(receive_message(connection))
        except (FileNotFoundError, ConnectionRefusedError) as error:
            raise SandboxDiscoveryError(f"sandbox manager is not available: {self.socket_path}") from error
        finally:
            connection.close()

    def ping(self, *, timeout=_DEFAULT_TIMEOUT) -> dict:
        return self._request("ping", timeout=timeout)

    def start(
        self,
        profile=None,
        *,
        command=None,
        env=None,
        stdio=None,
        paused=None,
        timeout=_DEFAULT_TIMEOUT,
    ) -> RemoteSandbox:
        if command is not None:
            command = [os.fsdecode(item) for item in command]
        if stdio is not None:
            stdio = stdio.value if isinstance(stdio, SandboxStdio) else str(stdio)
        result = self._request(
            "start",
            timeout=timeout,
            profile=profile,
            command=command,
            env=env,
            stdio=stdio,
            paused=paused,
        )
        return RemoteSandbox(self, SandboxSnapshot.from_wire(result))

    def list(self, *, timeout=_DEFAULT_TIMEOUT) -> tuple[SandboxSnapshot, ...]:
        result = self._request("list", timeout=timeout)
        return tuple(SandboxSnapshot.from_wire(item) for item in result)

    def get(self, sandbox_id, *, timeout=_DEFAULT_TIMEOUT) -> RemoteSandbox:
        result = self._request("get", timeout=timeout, sandbox_id=sandbox_id)
        return RemoteSandbox(self, SandboxSnapshot.from_wire(result))

    def close_sandbox(self, sandbox_id, *, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        result = self._request("close", timeout=timeout, sandbox_id=sandbox_id)
        return SandboxSnapshot.from_wire(result)

    def shutdown(self, *, timeout=_DEFAULT_TIMEOUT) -> None:
        self._request("shutdown", timeout=timeout)


class RemoteSandbox:
    """A manager-owned sandbox whose local handle may be discarded safely."""

    def __init__(self, client: SandboxClient, snapshot: SandboxSnapshot):
        self.client = client
        self._snapshot = snapshot
        self._lock = threading.RLock()

    @property
    def snapshot(self) -> SandboxSnapshot:
        with self._lock:
            return self._snapshot

    @property
    def id(self) -> str:
        return self.snapshot.id

    @property
    def state(self):
        return self.snapshot.state

    @property
    def host_pid(self):
        return self.snapshot.host_pid

    @property
    def paused(self) -> bool:
        return self.snapshot.paused

    @property
    def ports(self):
        return MappingProxyType({binding.name: binding for binding in self.snapshot.ports})

    @property
    def debug(self):
        return self.snapshot.debug

    def _replace(self, value) -> SandboxSnapshot:
        snapshot = value if isinstance(value, SandboxSnapshot) else SandboxSnapshot.from_wire(value)
        with self._lock:
            self._snapshot = snapshot
        return snapshot

    def _resolve_timeout(self, timeout):
        return self.client.default_timeout if timeout is _DEFAULT_TIMEOUT else timeout

    def refresh(self, *, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        timeout = self._resolve_timeout(timeout)
        value = self.client._request("get", timeout=timeout, sandbox_id=self.id)
        return self._replace(value)

    def stdio(self, *, timeout=_DEFAULT_TIMEOUT):
        timeout = self._resolve_timeout(timeout)
        snapshot = self.refresh(timeout=timeout)
        if snapshot.stdio is SandboxStdio.NONE or snapshot.stdio_socket is None:
            raise SandboxNotFoundError(f"sandbox {self.id!r} has no stdio endpoint")
        return connect_stdio(snapshot.stdio_socket, timeout=timeout)

    @property
    def tube(self):
        return self.stdio()

    def connect(self, name=None, *, timeout=_DEFAULT_TIMEOUT):
        timeout = self._resolve_timeout(timeout)
        snapshot = self.refresh(timeout=timeout)
        bindings = {binding.name: binding for binding in snapshot.ports}
        if name is None:
            if len(bindings) != 1:
                raise ValueError("port name is required unless the sandbox exposes exactly one port")
            binding = next(iter(bindings.values()))
        else:
            try:
                binding = bindings[name]
            except KeyError as error:
                raise SandboxNotFoundError(f"sandbox {self.id!r} has no port {name!r}") from error
        return remote(
            binding.host,
            binding.host_port,
            typ=binding.protocol,
            timeout=timeout,
        )

    def resume(self, *, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        timeout = self._resolve_timeout(timeout)
        value = self.client._request("resume", timeout=timeout, sandbox_id=self.id)
        return self._replace(value)

    def signal(self, signum, *, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        if isinstance(signum, signal_module.Signals):
            signum = signum.value
        if isinstance(signum, bool) or not isinstance(signum, int):
            raise TypeError("signal must be an integer or signal.Signals value")
        timeout = self._resolve_timeout(timeout)
        value = self.client._request("signal", timeout=timeout, sandbox_id=self.id, signal=signum)
        return self._replace(value)

    def kill(self, *, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        timeout = self._resolve_timeout(timeout)
        value = self.client._request("kill", timeout=timeout, sandbox_id=self.id)
        return self._replace(value)

    def resize(self, rows, columns, *, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        for value, label in ((rows, "rows"), (columns, "columns")):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        timeout = self._resolve_timeout(timeout)
        value = self.client._request(
            "resize",
            timeout=timeout,
            sandbox_id=self.id,
            rows=rows,
            columns=columns,
        )
        return self._replace(value)

    def attach(self, *, timeout=_DEFAULT_TIMEOUT) -> dict:
        """Attach the manager's selected prepared GDB without resuming."""
        timeout = self._resolve_timeout(timeout)
        return self.client._request("attach", timeout=timeout, sandbox_id=self.id)

    def wait(self, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        # The server performs an event-driven wait. Give the transport a small
        # allowance over a finite manager-side deadline for response framing.
        timeout = self._resolve_timeout(timeout)
        transport_timeout = None if timeout is None else float(timeout) + 1.0
        value = self.client._request(
            "wait",
            timeout=transport_timeout,
            sandbox_id=self.id,
            wait_timeout=timeout,
        )
        return self._replace(value)

    def close(self, *, timeout=_DEFAULT_TIMEOUT) -> SandboxSnapshot:
        timeout = self._resolve_timeout(timeout)
        value = self.client._request("close", timeout=timeout, sandbox_id=self.id)
        return self._replace(value)

    def __repr__(self) -> str:
        return f"<RemoteSandbox {self.id!r} state={self.state.value!r}>"


__all__ = ["RemoteSandbox", "SandboxClient"]
