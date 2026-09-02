"""Project-scoped Unix-socket discovery for the sandbox manager.

The project seed is a stable rendezvous input, not an authentication secret.
The boundary is a unique Unix socket in a same-UID, mode-0700 runtime directory;
the socket and its lifetime lock are mode 0600.  Manager lookup may initialize
the seed.  Client lookup is strictly read-only.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import operator
import os
import socket
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from .. import config as _project_config
from .config import configured_socket
from .errors import (
    SandboxAlreadyRunningError,
    SandboxConfigError,
    SandboxDiscoveryError,
)

DISCOVERY_NAMESPACE = "pwnc.sandbox.manager"
DISCOVERY_VERSION = 1
MAX_UNIX_SOCKET_PATH_BYTES = 103
DEFAULT_MANAGER_NAME = "default"


def _manager_name(value) -> str:
    if not isinstance(value, str):
        raise TypeError("manager name must be text")
    if not value:
        raise ValueError("manager name cannot be empty")
    if "\0" in value:
        raise ValueError("manager name cannot contain NUL")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("manager name must be valid UTF-8 text") from error
    if len(encoded) > 256:
        raise ValueError("manager name cannot exceed 256 UTF-8 bytes")
    return value


def _path(value, *, base: Path | None = None) -> Path:
    if isinstance(value, bool):
        raise TypeError("socket path must be path-like")
    try:
        result = Path(os.fsdecode(os.fspath(value))).expanduser()
    except TypeError as error:
        raise TypeError("socket path must be path-like") from error
    if not result.is_absolute():
        result = (Path.cwd() if base is None else base) / result
    return result.absolute()


def _validate_socket_path(path: Path) -> Path:
    encoded = os.fsencode(path)
    if b"\0" in encoded:
        raise ValueError("Unix socket path cannot contain NUL")
    if len(encoded) > MAX_UNIX_SOCKET_PATH_BYTES:
        raise ValueError(
            f"Unix socket path is {len(encoded)} bytes; portable limit is {MAX_UNIX_SOCKET_PATH_BYTES}: {path}"
        )
    return path


def _config_path(config_path, start, *, manager: bool) -> Path:
    if config_path is not None:
        if isinstance(config_path, bool):
            raise TypeError("config_path must be path-like")
        try:
            candidate = Path(os.fsdecode(os.fspath(config_path))).expanduser()
        except TypeError as error:
            raise TypeError("config_path must be path-like") from error
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if candidate.exists() and candidate.is_dir():
            candidate /= _project_config.CONFIG_FILE
        candidate = candidate.resolve(strict=False)
        if candidate.name != _project_config.CONFIG_FILE:
            raise ValueError(f"project config must be named {_project_config.CONFIG_FILE}")
        if not manager and not candidate.is_file():
            raise SandboxDiscoveryError(f"project config does not exist: {candidate}")
        return candidate

    found = _project_config.find_config(start)
    if found is not None:
        return found.resolve(strict=True)
    if not manager:
        raise SandboxDiscoveryError(
            f"could not find {_project_config.CONFIG_FILE}; pass config_path or start the sandbox manager first"
        )

    if start is None:
        root = Path.cwd()
    else:
        if isinstance(start, bool):
            raise TypeError("start must be path-like")
        try:
            root = Path(os.fsdecode(os.fspath(start))).expanduser()
        except TypeError as error:
            raise TypeError("start must be path-like") from error
        if not root.is_absolute():
            root = Path.cwd() / root
        if root.exists() and root.is_file():
            root = root.parent
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise SandboxDiscoveryError(f"project start does not exist: {root}") from error
    if not root.is_dir():
        raise SandboxDiscoveryError(f"project start is not a directory: {root}")
    return root / _project_config.CONFIG_FILE


def _load_project(path: Path) -> dict:
    try:
        data = _project_config.load_project_config(path)
    except (OSError, TypeError, ValueError) as error:
        raise SandboxDiscoveryError(f"could not read project config: {path}") from error
    if not isinstance(data, dict):
        raise SandboxDiscoveryError(f"project config root must be a TOML table: {path}")
    return data


def _seed(data: dict) -> str:
    table = data.get("pwnc")
    if not isinstance(table, dict) or "seed" not in table:
        raise SandboxDiscoveryError("local pwnc.toml has no [pwnc].seed; start the sandbox manager first")
    try:
        return _project_config.validate_project_seed(table["seed"])
    except (TypeError, ValueError) as error:
        raise SandboxDiscoveryError("local [pwnc].seed is invalid") from error


def _configured_socket(data: dict, path: Path) -> Path | None:
    try:
        configured = configured_socket(data, path)
    except SandboxConfigError as error:
        raise SandboxDiscoveryError(str(error)) from error
    if configured is None:
        return None
    return _validate_socket_path(configured)


def _directory_is_private(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700


def _ensure_private_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if not _directory_is_private(path):
        raise SandboxDiscoveryError(f"runtime directory must be owned by this uid with mode 0700: {path}")
    return path


def _derived_filename(seed: str, config_path: Path, name: str) -> str:
    digest = hashlib.sha256()
    digest.update(DISCOVERY_NAMESPACE.encode("ascii"))
    digest.update(b"\0")
    digest.update(str(DISCOVERY_VERSION).encode("ascii"))
    digest.update(b"\0")
    digest.update(bytes.fromhex(seed))
    digest.update(b"\0")
    digest.update(os.fsencode(config_path))
    digest.update(b"\0")
    digest.update(name.encode("utf-8"))
    encoded = base64.urlsafe_b64encode(digest.digest()[:16]).rstrip(b"=").decode("ascii")
    return f"s-{encoded}.sock"


def _runtime_socket(filename: str, *, manager: bool, runtime_dir=None) -> tuple[Path, Path]:
    directory = _path(runtime_dir) if runtime_dir is not None else Path("/tmp") / f"pwnc-{os.getuid()}"
    path = _validate_socket_path(directory / filename)
    if manager:
        _ensure_private_directory(directory)
    elif directory.exists() and not _directory_is_private(directory):
        raise SandboxDiscoveryError(f"runtime directory must be owned by this uid with mode 0700: {directory}")
    return directory, path


@dataclass(frozen=True, slots=True)
class SandboxManagerAddress:
    """Resolved rendezvous address for one project's sandbox manager."""

    path: Path
    source: str
    name: str = DEFAULT_MANAGER_NAME
    config_path: Path | None = None
    project_root: Path | None = None
    seed: str | None = None
    runtime_dir: Path | None = None

    @property
    def socket_path(self) -> Path:
        return self.path

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.lock")


def _discover(
    name=DEFAULT_MANAGER_NAME,
    *,
    socket_path=None,
    config_path=None,
    start=None,
    runtime_dir=None,
    manager: bool,
) -> SandboxManagerAddress:
    name = _manager_name(name)
    if socket_path is not None:
        path = _validate_socket_path(_path(socket_path))
        return SandboxManagerAddress(path, "explicit", name=name)

    path = _config_path(config_path, start, manager=manager)
    if manager:
        try:
            _project_config.ensure_project_seed(path)
        except (OSError, TypeError, ValueError) as error:
            raise SandboxDiscoveryError(f"could not initialize project discovery config: {path}") from error
    data = _load_project(path)

    configured = _configured_socket(data, path)
    if configured is not None:
        return SandboxManagerAddress(
            configured,
            "config",
            name=name,
            config_path=path,
            project_root=path.parent,
        )

    seed = _seed(data)
    filename = _derived_filename(seed, path, name)
    runtime, derived = _runtime_socket(
        filename,
        manager=manager,
        runtime_dir=runtime_dir,
    )
    return SandboxManagerAddress(
        derived,
        "derived",
        name=name,
        config_path=path,
        project_root=path.parent,
        seed=seed,
        runtime_dir=runtime,
    )


def discover_manager(
    name=DEFAULT_MANAGER_NAME,
    *,
    socket_path=None,
    config_path=None,
    start=None,
    runtime_dir=None,
) -> SandboxManagerAddress:
    """Resolve a manager address, initializing its local project seed if needed."""

    return _discover(
        name,
        socket_path=socket_path,
        config_path=config_path,
        start=start,
        runtime_dir=runtime_dir,
        manager=True,
    )


def discover_client(
    name=DEFAULT_MANAGER_NAME,
    *,
    socket_path=None,
    config_path=None,
    start=None,
    runtime_dir=None,
) -> SandboxManagerAddress:
    """Resolve an existing manager address without changing project state."""

    return _discover(
        name,
        socket_path=socket_path,
        config_path=config_path,
        start=start,
        runtime_dir=runtime_dir,
        manager=False,
    )


def _backlog(value) -> int:
    if isinstance(value, bool):
        raise TypeError("listen backlog must be a positive integer")
    try:
        value = operator.index(value)
    except TypeError as error:
        raise TypeError("listen backlog must be a positive integer") from error
    if value <= 0:
        raise ValueError("listen backlog must be positive")
    return value


def _unlink_socket_identity(path: Path, identity) -> bool:
    if identity is None:
        return False
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != identity:
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


class SandboxManagerSocketLease:
    """Exclusive lifetime claim and already-bound manager listener."""

    def __init__(self, address: SandboxManagerAddress, listener: socket.socket, lock_fd: int, identity):
        self.address = address
        self._socket = listener
        self._lock_fd = lock_fd
        self._identity = identity
        self._closed = False
        self._close_lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self.address.path

    @property
    def socket(self) -> socket.socket:
        if self._closed:
            raise SandboxDiscoveryError("sandbox manager socket lease is closed")
        return self._socket

    @property
    def closed(self) -> bool:
        return self._closed

    def duplicate_socket(self) -> socket.socket:
        """Duplicate the listener for a server which is owned by this lease."""

        with self._close_lock:
            if self._closed:
                raise SandboxDiscoveryError("sandbox manager socket lease is closed")
            duplicate = self._socket.dup()
            duplicate.set_inheritable(False)
            return duplicate

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._socket.close()
            finally:
                try:
                    _unlink_socket_identity(self.path, self._identity)
                finally:
                    try:
                        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(self._lock_fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def acquire_manager_socket(
    address: SandboxManagerAddress,
    *,
    backlog=16,
) -> SandboxManagerSocketLease:
    """Atomically claim *address* and return its bound Unix listener."""

    if not isinstance(address, SandboxManagerAddress):
        raise TypeError("address must be a SandboxManagerAddress")
    backlog = _backlog(backlog)
    path = _validate_socket_path(address.path)
    parent = path.parent
    if not parent.is_dir():
        raise SandboxDiscoveryError(f"Unix socket parent directory does not exist: {parent}")

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(address.lock_path, flags, 0o600)
    except OSError as error:
        raise SandboxDiscoveryError(f"could not open manager namespace lock: {address.lock_path}") from error
    listener = None
    identity = None
    try:
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != os.getuid()
            or stat.S_IMODE(lock_info.st_mode) & 0o077
        ):
            raise SandboxDiscoveryError("manager namespace lock must be a private regular file owned by this uid")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise SandboxAlreadyRunningError(f"sandbox manager already owns {path}") from error
            raise

        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
                raise SandboxDiscoveryError(f"refusing to replace non-owned socket path: {path}")
            path.unlink()

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.set_inheritable(False)
        listener.bind(os.fspath(path))
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise SandboxDiscoveryError(f"bound manager path is not an owned Unix socket: {path}")
        identity = (info.st_dev, info.st_ino)
        os.chmod(path, 0o600)
        listener.listen(backlog)
        return SandboxManagerSocketLease(address, listener, lock_fd, identity)
    except BaseException:
        if listener is not None:
            listener.close()
        _unlink_socket_identity(path, identity)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
        raise


# Short aliases are useful to backend code while the qualified names remain
# self-documenting at the public package boundary.
ManagerAddress = SandboxManagerAddress
ManagerSocketLease = SandboxManagerSocketLease


__all__ = [
    "DEFAULT_MANAGER_NAME",
    "DISCOVERY_NAMESPACE",
    "DISCOVERY_VERSION",
    "MAX_UNIX_SOCKET_PATH_BYTES",
    "ManagerAddress",
    "ManagerSocketLease",
    "SandboxManagerAddress",
    "SandboxManagerSocketLease",
    "acquire_manager_socket",
    "discover_client",
    "discover_manager",
]
