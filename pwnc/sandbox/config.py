"""Project-local configuration for challenge sandboxes.

Sandbox configuration is deliberately lazy and project-only.  Importing this
module neither searches for nor creates ``pwnc.toml``; callers opt into a read
when they load a project or profile.  Global pwnc configuration is never used
as a fallback because relative build inputs and mounts belong to one concrete
challenge directory.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .. import config as _project_config
from .errors import SandboxConfigError
from .model import DockerSpec, QemuSpec, SandboxMount, SandboxPort, SandboxSpec

_SANDBOX_SETTINGS = frozenset({"default-profile", "socket"})
_PROFILE_KEYS = frozenset(
    {
        "backend",
        "command",
        "stdio",
        "ports",
        "mounts",
        "env",
        "cwd",
        "pause-at-exec",
        "allow-egress",
        "read-only-root",
        "host-aslr",
        "docker",
        "qemu",
    }
)
_DOCKER_KEYS = frozenset(
    {
        "image",
        "build",
        "dockerfile",
        "pull",
        "platform",
        "extra-args",
    }
)
_PORT_KEYS = frozenset({"name", "internal", "protocol", "bind", "host-port"})
_MOUNT_KEYS = frozenset({"source", "target", "read-only"})
_QEMU_KEYS = frozenset({"source", "architecture", "binary", "sysroot", "guest-aslr"})


def _error(location: str, message: str) -> SandboxConfigError:
    return SandboxConfigError(f"{location}: {message}")


def _table(value: object, location: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise _error(location, "must be a TOML table")
    return value


def _array(value: object, location: str) -> list:
    if not isinstance(value, list):
        raise _error(location, "must be a TOML array")
    return value


def _text(value: object, location: str, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise _error(location, "must be text")
    if "\0" in value:
        raise _error(location, "cannot contain NUL")
    if not empty and not value:
        raise _error(location, "cannot be empty")
    return value


def _boolean(value: object, location: str) -> bool:
    if type(value) is not bool:
        raise _error(location, "must be true or false")
    return value


def _unknown(table: Mapping, allowed: frozenset[str], location: str) -> None:
    names = sorted(key for key in table if key not in allowed)
    if not names:
        return
    rendered = ", ".join(repr(name) for name in names)
    raise _error(location, f"unknown key(s): {rendered}")


def _required(table: Mapping, key: str, location: str):
    if key not in table:
        raise _error(location, f"missing required key {key!r}")
    return table[key]


def _path(value: object, location: str, base: Path) -> Path:
    text = _text(value, location)
    try:
        result = Path(os.fsdecode(os.fspath(text))).expanduser()
    except (TypeError, ValueError) as error:
        raise _error(location, "must be a filesystem path") from error
    if not result.is_absolute():
        result = base / result
    try:
        return result.resolve(strict=False)
    except OSError as error:
        raise _error(location, f"cannot resolve path: {error}") from error


def resolve_project_config(config_path=None, *, start=None) -> Path:
    """Resolve one existing project ``pwnc.toml`` without global fallback.

    ``config_path`` may name the file or its containing directory.  With no
    explicit path, the nearest file at or above *start* (or the current working
    directory) is selected.  This function never creates a file or seed.
    """

    if config_path is not None:
        if isinstance(config_path, bool):
            raise TypeError("config_path must be path-like")
        try:
            candidate = Path(os.fsdecode(os.fspath(config_path))).expanduser()
        except TypeError as error:
            raise TypeError("config_path must be path-like") from error
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if candidate.is_dir():
            candidate /= _project_config.CONFIG_FILE
    else:
        candidate = _project_config.find_config(start)
        if candidate is None:
            origin = Path.cwd() if start is None else Path(start)
            raise SandboxConfigError(f"could not find {_project_config.CONFIG_FILE} at or above {origin}")

    try:
        candidate = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise SandboxConfigError(f"project config does not exist: {candidate}") from error
    except OSError as error:
        raise SandboxConfigError(f"cannot resolve project config {candidate}: {error}") from error
    if candidate.name != _project_config.CONFIG_FILE:
        raise SandboxConfigError(f"project config must be named {_project_config.CONFIG_FILE}: {candidate}")
    if not candidate.is_file():
        raise SandboxConfigError(f"project config is not a regular file: {candidate}")
    return candidate


def _sandbox_table(data: Mapping, *, required: bool) -> Mapping:
    root = _table(data, "project config")
    value = root.get("sandbox")
    if value is None:
        if required:
            raise _error("[sandbox]", "table is missing")
        return {}
    return _table(value, "[sandbox]")


def configured_socket(data: Mapping, config_path: Path) -> Path | None:
    """Return the config-relative ``[sandbox].socket`` override, if any.

    This narrow helper intentionally does not validate or require profiles; it
    is used by discovery before a challenge is selected.
    """

    sandbox = _sandbox_table(data, required=False)
    value = sandbox.get("socket")
    if value is None:
        return None
    return _path(value, "[sandbox].socket", config_path.parent)


def _docker_spec(value: object, location: str, base: Path) -> DockerSpec:
    table = _table(value, location)
    _unknown(table, _DOCKER_KEYS, location)

    image = table.get("image")
    if image is not None:
        image = _text(image, f"{location}.image")
    build = table.get("build")
    build_context = None if build is None else _path(build, f"{location}.build", base)
    dockerfile_value = table.get("dockerfile")
    dockerfile = None if dockerfile_value is None else _path(dockerfile_value, f"{location}.dockerfile", base)
    if dockerfile is not None and build_context is None:
        raise _error(location, "dockerfile requires a build context in 'build'")

    extra_args = table.get("extra-args", [])
    extra_args = _array(extra_args, f"{location}.extra-args")
    for index, argument in enumerate(extra_args):
        _text(argument, f"{location}.extra-args[{index}]")

    try:
        return DockerSpec(
            image=image,
            build_context=build_context,
            dockerfile=dockerfile,
            pull=table.get("pull", "never"),
            platform=table.get("platform"),
            extra_args=tuple(extra_args),
        )
    except (TypeError, ValueError) as error:
        raise _error(location, str(error)) from error


def _port(value: object, location: str) -> SandboxPort:
    table = _table(value, location)
    _unknown(table, _PORT_KEYS, location)
    try:
        return SandboxPort(
            name=_required(table, "name", location),
            internal_port=_required(table, "internal", location),
            protocol=table.get("protocol", "tcp"),
            bind_host=table.get("bind", "127.0.0.1"),
            host_port=table.get("host-port"),
        )
    except SandboxConfigError:
        raise
    except (TypeError, ValueError) as error:
        raise _error(location, str(error)) from error


def _mount(value: object, location: str, base: Path) -> SandboxMount:
    table = _table(value, location)
    _unknown(table, _MOUNT_KEYS, location)
    source = _path(_required(table, "source", location), f"{location}.source", base)
    try:
        return SandboxMount(
            source=source,
            target=_required(table, "target", location),
            read_only=table.get("read-only", True),
        )
    except SandboxConfigError:
        raise
    except (TypeError, ValueError) as error:
        raise _error(location, str(error)) from error


def _qemu_spec(value: object, location: str) -> QemuSpec:
    table = _table(value, location)
    _unknown(table, _QEMU_KEYS, location)
    if "guest-aslr" in table:
        _boolean(table["guest-aslr"], f"{location}.guest-aslr")
    try:
        return QemuSpec(
            architecture=_required(table, "architecture", location),
            source=table.get("source", "auto"),
            binary=table.get("binary"),
            sysroot=table.get("sysroot"),
            guest_aslr=table.get("guest-aslr"),
        )
    except SandboxConfigError:
        raise
    except (TypeError, ValueError) as error:
        raise _error(location, str(error)) from error


def _profile(name: str, value: object, base: Path) -> SandboxSpec:
    location = f"[sandbox.{name}]"
    table = _table(value, location)
    _unknown(table, _PROFILE_KEYS, location)

    command = _array(_required(table, "command", location), f"{location}.command")
    for index, argument in enumerate(command):
        _text(argument, f"{location}.command[{index}]")

    environment = table.get("env", {})
    environment = _table(environment, f"{location}.env")
    for key, env_value in environment.items():
        _text(key, f"{location}.env key")
        _text(env_value, f"{location}.env.{key}", empty=True)

    ports_value = _array(table.get("ports", []), f"{location}.ports")
    ports = tuple(_port(item, f"{location}.ports[{index}]") for index, item in enumerate(ports_value))
    mounts_value = _array(table.get("mounts", []), f"{location}.mounts")
    mounts = tuple(_mount(item, f"{location}.mounts[{index}]", base) for index, item in enumerate(mounts_value))

    docker = _docker_spec(
        _required(table, "docker", location),
        f"{location}.docker",
        base,
    )
    qemu = None
    if "qemu" in table:
        qemu = _qemu_spec(table["qemu"], f"{location}.qemu")
    for key in ("pause-at-exec", "allow-egress", "read-only-root", "host-aslr"):
        if key in table:
            _boolean(table[key], f"{location}.{key}")

    try:
        return SandboxSpec(
            profile=name,
            backend=table.get("backend", "docker"),
            command=tuple(command),
            docker=docker,
            stdio=table.get("stdio", "pipe"),
            ports=ports,
            mounts=mounts,
            env=dict(environment),
            cwd=table.get("cwd"),
            pause_at_exec=table.get("pause-at-exec", False),
            allow_egress=table.get("allow-egress", False),
            read_only_root=table.get("read-only-root", False),
            qemu=qemu,
            host_aslr=table.get("host-aslr"),
        )
    except SandboxConfigError as error:
        raise _error(location, str(error)) from error
    except (TypeError, ValueError) as error:
        raise _error(location, str(error)) from error


@dataclass(frozen=True, slots=True)
class SandboxProjectConfig:
    """Parsed sandbox profiles tied to one exact local project file."""

    path: Path
    default_profile: str
    socket: Path | None
    profiles: Mapping[str, SandboxSpec]

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path).resolve(strict=False))
        object.__setattr__(self, "profiles", MappingProxyType(dict(self.profiles)))

    def profile(self, name: str | None = None) -> SandboxSpec:
        selected = self.default_profile if name is None else name
        if not isinstance(selected, str) or not selected:
            raise SandboxConfigError("sandbox profile name must be nonempty text")
        try:
            return self.profiles[selected]
        except KeyError as error:
            available = ", ".join(sorted(self.profiles)) or "(none)"
            raise SandboxConfigError(
                f"sandbox profile {selected!r} does not exist; available profiles: {available}"
            ) from error


def parse_project_config(data: Mapping, config_path) -> SandboxProjectConfig:
    """Parse already-loaded TOML data into immutable sandbox specifications."""

    try:
        path = Path(os.fsdecode(os.fspath(config_path))).expanduser().resolve(strict=False)
    except (TypeError, ValueError, OSError) as error:
        raise TypeError("config_path must be path-like") from error
    sandbox = _sandbox_table(data, required=True)

    for key, value in sandbox.items():
        if key in _SANDBOX_SETTINGS:
            continue
        if not isinstance(value, Mapping):
            raise _error(
                "[sandbox]",
                f"unknown setting {key!r}; profiles must be TOML tables",
            )

    default_profile = sandbox.get("default-profile", "default")
    default_profile = _text(default_profile, "[sandbox].default-profile")
    socket = configured_socket(data, path)
    profiles = {
        name: _profile(name, value, path.parent) for name, value in sandbox.items() if name not in _SANDBOX_SETTINGS
    }
    if not profiles:
        raise _error("[sandbox]", "must define at least one [sandbox.<profile>] table")
    if default_profile not in profiles:
        available = ", ".join(sorted(profiles))
        raise _error(
            "[sandbox].default-profile",
            f"profile {default_profile!r} does not exist; available profiles: {available}",
        )
    return SandboxProjectConfig(path, default_profile, socket, profiles)


def load_project_config(config_path=None, *, start=None) -> SandboxProjectConfig:
    """Read and parse the nearest or explicitly selected local project file."""

    path = resolve_project_config(config_path, start=start)
    try:
        data = _project_config.load_project_config(path)
    except (OSError, TypeError, ValueError) as error:
        raise SandboxConfigError(f"could not read project config {path}: {error}") from error
    return parse_project_config(data, path)


def load_profile(name: str | None = None, *, config_path=None, start=None) -> SandboxSpec:
    """Load one profile, selecting ``[sandbox].default-profile`` when omitted."""

    return load_project_config(config_path, start=start).profile(name)


__all__ = [
    "SandboxProjectConfig",
    "configured_socket",
    "load_profile",
    "load_project_config",
    "parse_project_config",
    "resolve_project_config",
]
