"""Public immutable descriptions and snapshots for challenge sandboxes."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from types import MappingProxyType

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class SandboxBackend(str, Enum):
    DOCKER = "docker"


class SandboxStdio(str, Enum):
    PIPE = "pipe"
    PTY = "pty"
    NONE = "none"


class SandboxState(str, Enum):
    STARTING = "starting"
    PAUSED = "paused"
    RUNNING = "running"
    EXITED = "exited"
    FAILED = "failed"
    CLOSED = "closed"


def _name(value: object, label: str = "name") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not _NAME.fullmatch(value):
        raise ValueError(f"{label} must match {_NAME.pattern!r}")
    return value


def _port(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if not 1 <= value <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")
    return value


def _text(value: object, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if "\0" in value:
        raise ValueError(f"{label} cannot contain NUL")
    if not empty and not value:
        raise ValueError(f"{label} cannot be empty")
    return value


def _string_tuple(values: Sequence[object], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise TypeError(f"{label} must be a sequence of arguments")
    return tuple(_text(value, f"{label} item") for value in values)


def _environment(values: Mapping[object, object]) -> MappingProxyType:
    if not isinstance(values, Mapping):
        raise TypeError("environment must be a mapping")
    result: dict[str, str] = {}
    for raw_key, raw_value in values.items():
        key = _text(raw_key, "environment key")
        if "=" in key:
            raise ValueError(f"environment key cannot contain '=': {key!r}")
        value = _text(raw_value, f"environment value for {key!r}", empty=True)
        result[key] = value
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class SandboxPort:
    """One TCP/UDP service exposed from a sandbox on the local host."""

    name: str
    internal_port: int
    protocol: str = "tcp"
    bind_host: str = "127.0.0.1"
    host_port: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _name(self.name, "port name"))
        object.__setattr__(self, "internal_port", _port(self.internal_port, "internal port"))
        protocol = _text(self.protocol, "port protocol").lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("port protocol must be 'tcp' or 'udp'")
        object.__setattr__(self, "protocol", protocol)
        bind_host = _text(self.bind_host, "port bind host")
        if bind_host not in {"127.0.0.1", "::1"}:
            raise ValueError("sandbox ports may only bind to loopback (127.0.0.1 or ::1)")
        object.__setattr__(self, "bind_host", bind_host)
        if self.host_port is not None:
            object.__setattr__(self, "host_port", _port(self.host_port, "host port"))


@dataclass(frozen=True, slots=True)
class SandboxPortBinding:
    name: str
    internal_port: int
    host: str
    host_port: int
    protocol: str = "tcp"

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _name(self.name, "port binding name"))
        object.__setattr__(self, "internal_port", _port(self.internal_port, "internal port"))
        object.__setattr__(self, "host_port", _port(self.host_port, "host port"))
        object.__setattr__(self, "host", _text(self.host, "binding host"))
        protocol = _text(self.protocol, "binding protocol").lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("binding protocol must be 'tcp' or 'udp'")
        object.__setattr__(self, "protocol", protocol)

    def to_wire(self) -> dict:
        return {
            "name": self.name,
            "internal_port": self.internal_port,
            "host": self.host,
            "host_port": self.host_port,
            "protocol": self.protocol,
        }

    @classmethod
    def from_wire(cls, value: Mapping) -> SandboxPortBinding:
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class SandboxMount:
    source: Path
    target: str
    read_only: bool = True

    def __post_init__(self) -> None:
        source = Path(os.fsdecode(os.fspath(self.source))).expanduser().absolute()
        object.__setattr__(self, "source", source)
        target = _text(self.target, "mount target")
        if not target.startswith("/"):
            raise ValueError("mount target must be an absolute container path")
        object.__setattr__(self, "target", target)
        if type(self.read_only) is not bool:
            raise TypeError("mount read_only must be a bool")


@dataclass(frozen=True, slots=True)
class DockerSpec:
    """Docker image/build inputs owned by the Docker backend."""

    image: str | None = None
    build_context: Path | None = None
    dockerfile: Path | None = None
    pull: str = "never"
    platform: str | None = None
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (self.image is None) == (self.build_context is None):
            raise ValueError("DockerSpec requires exactly one of image or build_context")
        if self.image is not None:
            object.__setattr__(self, "image", _text(self.image, "Docker image"))
        if self.build_context is not None:
            context = Path(os.fsdecode(os.fspath(self.build_context))).expanduser().absolute()
            object.__setattr__(self, "build_context", context)
        if self.dockerfile is not None:
            dockerfile = Path(os.fsdecode(os.fspath(self.dockerfile))).expanduser().absolute()
            object.__setattr__(self, "dockerfile", dockerfile)
        pull = _text(self.pull, "Docker pull policy").lower()
        if pull not in {"never", "missing", "always"}:
            raise ValueError("Docker pull policy must be never, missing, or always")
        object.__setattr__(self, "pull", pull)
        if self.platform is not None:
            object.__setattr__(self, "platform", _text(self.platform, "Docker platform"))
        object.__setattr__(self, "extra_args", _string_tuple(self.extra_args, "Docker extra_args"))


@dataclass(frozen=True, slots=True)
class QemuSpec:
    """Backend-neutral QEMU user-mode wrapping configuration.

    ``source`` selects an emulator supplied by the image, a statically linked
    host executable, or the backend's image-first automatic resolution.  An
    omitted ASLR value means that the backend should preserve its normal
    default rather than forcing either state.
    """

    architecture: str
    source: str = "auto"
    binary: str | None = None
    sysroot: str | None = None
    guest_aslr: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "architecture", _name(self.architecture, "QEMU architecture"))
        source = _text(self.source, "QEMU source").lower()
        if source not in {"auto", "host", "image"}:
            raise ValueError("QEMU source must be auto, host, or image")
        object.__setattr__(self, "source", source)
        if self.binary is not None:
            binary = _text(self.binary, "QEMU binary")
            if source == "image" and not binary.startswith("/"):
                raise ValueError("an image QEMU binary must be an absolute container path")
            object.__setattr__(self, "binary", binary)
        if self.sysroot is not None:
            object.__setattr__(self, "sysroot", _text(self.sysroot, "QEMU sysroot"))
        if self.guest_aslr is not None and type(self.guest_aslr) is not bool:
            raise TypeError("guest_aslr must be a bool or None")


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    """Complete backend-neutral definition of one challenge instance."""

    command: tuple[str, ...]
    docker: DockerSpec
    backend: SandboxBackend = SandboxBackend.DOCKER
    stdio: SandboxStdio = SandboxStdio.PIPE
    ports: tuple[SandboxPort, ...] = ()
    mounts: tuple[SandboxMount, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
    pause_at_exec: bool = False
    allow_egress: bool = False
    read_only_root: bool = False
    profile: str = "default"
    qemu: QemuSpec | None = None
    host_aslr: bool | None = None

    def __post_init__(self) -> None:
        try:
            backend = self.backend if isinstance(self.backend, SandboxBackend) else SandboxBackend(self.backend)
        except ValueError as error:
            raise ValueError(f"unsupported sandbox backend: {self.backend!r}") from error
        object.__setattr__(self, "backend", backend)
        if not isinstance(self.docker, DockerSpec):
            raise TypeError("docker must be a DockerSpec")
        command = _string_tuple(self.command, "command")
        if not command:
            raise ValueError("sandbox command cannot be empty")
        object.__setattr__(self, "command", command)
        try:
            stdio = self.stdio if isinstance(self.stdio, SandboxStdio) else SandboxStdio(self.stdio)
        except ValueError as error:
            raise ValueError(f"unsupported sandbox stdio mode: {self.stdio!r}") from error
        object.__setattr__(self, "stdio", stdio)
        ports = tuple(self.ports)
        if any(not isinstance(port, SandboxPort) for port in ports):
            raise TypeError("ports must contain SandboxPort values")
        names = [port.name for port in ports]
        if len(names) != len(set(names)):
            raise ValueError("sandbox port names must be unique")
        object.__setattr__(self, "ports", ports)
        mounts = tuple(self.mounts)
        if any(not isinstance(mount, SandboxMount) for mount in mounts):
            raise TypeError("mounts must contain SandboxMount values")
        targets = [mount.target for mount in mounts]
        if len(targets) != len(set(targets)):
            raise ValueError("sandbox mount targets must be unique")
        object.__setattr__(self, "mounts", mounts)
        object.__setattr__(self, "env", _environment(self.env))
        if self.cwd is not None:
            cwd = _text(self.cwd, "sandbox cwd")
            if not cwd.startswith("/"):
                raise ValueError("sandbox cwd must be an absolute container path")
            object.__setattr__(self, "cwd", cwd)
        for name in ("pause_at_exec", "allow_egress", "read_only_root"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a bool")
        object.__setattr__(self, "profile", _name(self.profile, "sandbox profile"))
        if self.qemu is not None and not isinstance(self.qemu, QemuSpec):
            raise TypeError("qemu must be a QemuSpec or None")
        if self.host_aslr is not None and type(self.host_aslr) is not bool:
            raise TypeError("host_aslr must be a bool or None")

    def configured(self, **changes) -> SandboxSpec:
        return replace(self, **changes)


@dataclass(frozen=True, slots=True)
class SandboxDebug:
    """One debugger endpoint published by a sandbox backend."""

    transport: str
    architecture: str
    emulator: str
    host: str
    port: int

    def __post_init__(self) -> None:
        transport = _text(self.transport, "debug transport").lower()
        object.__setattr__(self, "transport", transport)
        object.__setattr__(self, "architecture", _name(self.architecture, "debug architecture"))
        object.__setattr__(self, "emulator", _text(self.emulator, "debug emulator"))
        object.__setattr__(self, "host", _text(self.host, "debug host"))
        object.__setattr__(self, "port", _port(self.port, "debug port"))

    def to_wire(self) -> dict:
        return {
            "transport": self.transport,
            "architecture": self.architecture,
            "emulator": self.emulator,
            "host": self.host,
            "port": self.port,
        }

    @classmethod
    def from_wire(cls, value: Mapping) -> SandboxDebug:
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class SandboxSnapshot:
    """Serializable public state for a manager-owned sandbox."""

    id: str
    profile: str
    backend: SandboxBackend
    state: SandboxState
    created_at: float
    host_pid: int | None = None
    container_id: str | None = None
    stdio: SandboxStdio = SandboxStdio.NONE
    stdio_socket: str | None = None
    ports: tuple[SandboxPortBinding, ...] = ()
    paused: bool = False
    exit_code: int | None = None
    error: str | None = None
    debug: SandboxDebug | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _name(self.id, "sandbox id"))
        object.__setattr__(self, "profile", _name(self.profile, "sandbox profile"))
        if not isinstance(self.backend, SandboxBackend):
            object.__setattr__(self, "backend", SandboxBackend(self.backend))
        if not isinstance(self.state, SandboxState):
            object.__setattr__(self, "state", SandboxState(self.state))
        if not isinstance(self.stdio, SandboxStdio):
            object.__setattr__(self, "stdio", SandboxStdio(self.stdio))
        object.__setattr__(self, "ports", tuple(self.ports))
        if self.debug is not None and not isinstance(self.debug, SandboxDebug):
            raise TypeError("debug must be a SandboxDebug or None")

    @property
    def bindings(self) -> Mapping[str, SandboxPortBinding]:
        return MappingProxyType({binding.name: binding for binding in self.ports})

    def to_wire(self) -> dict:
        return {
            "id": self.id,
            "profile": self.profile,
            "backend": self.backend.value,
            "state": self.state.value,
            "created_at": self.created_at,
            "host_pid": self.host_pid,
            "container_id": self.container_id,
            "stdio": self.stdio.value,
            "stdio_socket": self.stdio_socket,
            "ports": [binding.to_wire() for binding in self.ports],
            "paused": self.paused,
            "exit_code": self.exit_code,
            "error": self.error,
            "debug": None if self.debug is None else self.debug.to_wire(),
        }

    @classmethod
    def from_wire(cls, value: Mapping) -> SandboxSnapshot:
        data = dict(value)
        data["ports"] = tuple(SandboxPortBinding.from_wire(item) for item in data.get("ports", ()))
        debug = data.get("debug")
        data["debug"] = None if debug is None else SandboxDebug.from_wire(debug)
        return cls(**data)


__all__ = [
    "DockerSpec",
    "QemuSpec",
    "SandboxBackend",
    "SandboxDebug",
    "SandboxMount",
    "SandboxPort",
    "SandboxPortBinding",
    "SandboxSnapshot",
    "SandboxSpec",
    "SandboxState",
    "SandboxStdio",
]
