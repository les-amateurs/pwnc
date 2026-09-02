"""Deterministic, project-scoped Unix-socket discovery for GDB pools.

Manager discovery is the only mutating lookup: when no explicit socket is
given it creates the nearest/current ``pwnc.toml`` seed immediately.  Viewer
discovery reads the same local file without creating or rewriting anything.

The project seed is an identifier, not an authentication secret.  The unique
socket path and its private per-user runtime directory are the rendezvous
boundary; downstream viewers are not given a reusable protocol credential.
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

from ... import config as _config


DISCOVERY_NAMESPACE = "pwnc.gdb.dap.pool"
DISCOVERY_VERSION = 1
# Darwin's sockaddr_un.sun_path is 104 bytes including its terminating NUL;
# Linux permits a few more.  This conservative portable ceiling is checked on
# encoded filesystem bytes, not Python characters.
MAX_UNIX_SOCKET_PATH_BYTES = 103
DEFAULT_POOL_NAME = "default"


class PoolDiscoveryError(RuntimeError):
    """A pool rendezvous address could not be resolved or safely claimed."""


class PoolAlreadyRunningError(PoolDiscoveryError):
    """Another manager currently owns the same project/pool rendezvous."""


def _os_error_reason(error: OSError) -> str:
    """Turn an errno into a short explanation suitable for public errors."""
    reasons = {
        errno.ENOENT: "the path does not exist",
        errno.ENOTDIR: "a path component is not a directory",
        errno.EACCES: "permission was denied",
        errno.EPERM: "the operation was not permitted",
        errno.EROFS: "the filesystem is read-only",
        errno.ENOSPC: "the filesystem has no space available",
        errno.EMFILE: "this process has too many open files",
        errno.ENFILE: "the system has too many open files",
        errno.ENAMETOOLONG: "the path is too long for the operating system",
        errno.EADDRINUSE: "the socket address is already in use",
    }
    known = reasons.get(error.errno)
    if known is not None:
        return known
    if error.strerror:
        return str(error.strerror).rstrip(".")
    if error.args:
        return str(error.args[-1]).rstrip(".")
    return type(error).__name__


def _discovery_origin(*, socket_path=None, config_path=None, start=None) -> str:
    """Describe the caller's lookup root without performing another lookup."""
    value = socket_path if socket_path is not None else config_path
    if value is not None:
        try:
            return os.fsdecode(os.fspath(value))
        except (TypeError, ValueError):
            return repr(value)
    if start is not None:
        try:
            return os.fsdecode(os.fspath(start))
        except (TypeError, ValueError):
            return repr(start)
    try:
        return os.getcwd()
    except OSError:
        return "the current working directory"


@dataclass(frozen=True, slots=True)
class PoolAddress:
    """Resolved Unix-socket rendezvous for one logical project pool."""

    name: str
    path: Path
    source: str
    config_path: Path | None = None
    project_root: Path | None = None
    seed: str | None = None
    runtime_dir: Path | None = None

    @property
    def socket_path(self) -> Path:
        """Compatibility-friendly alias for :attr:`path`."""
        return self.path

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.lock")


def _pool_name(name) -> str:
    if not isinstance(name, str):
        raise TypeError("pool name must be text")
    if not name:
        raise ValueError("pool name cannot be empty")
    if "\0" in name:
        raise ValueError("pool name cannot contain NUL")
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("pool name must be valid UTF-8 text") from error
    if len(encoded) > 256:
        raise ValueError("pool name cannot exceed 256 UTF-8 bytes")
    return name


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
            f"Unix socket path is {len(encoded)} bytes; portable limit is "
            f"{MAX_UNIX_SOCKET_PATH_BYTES}: {path}"
        )
    return path


def _config_path(config_path, start, *, manager: bool) -> Path:
    if config_path is not None:
        candidate = Path(os.fsdecode(os.fspath(config_path))).expanduser()
        if candidate.exists() and candidate.is_dir():
            candidate = candidate / _config.CONFIG_FILE
        elif not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        candidate = candidate.resolve(strict=False)
        if candidate.name != _config.CONFIG_FILE:
            raise ValueError(f"project config must be named {_config.CONFIG_FILE}")
        if not manager and not candidate.is_file():
            raise PoolDiscoveryError(f"project config does not exist: {candidate}")
        return candidate

    found = _config.find_config(start)
    if found is not None:
        return found.resolve(strict=True)
    if not manager:
        raise PoolDiscoveryError(
            f"could not find pwnc.toml while discovering a GDB pool from "
            f"{_discovery_origin(start=start)}; pass config_path, pass an explicit "
            "socket, or start the pool manager in the intended project first"
        )

    if start is None:
        root = Path.cwd()
    else:
        root = Path(os.fsdecode(os.fspath(start))).expanduser()
        if not root.is_absolute():
            root = Path.cwd() / root
        if root.exists() and root.is_file():
            root = root.parent
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise PoolDiscoveryError(f"project start is not a directory: {root}")
    return root / _config.CONFIG_FILE


def _local_socket(data, config_path: Path) -> Path | None:
    try:
        gdb = data.get("gdb", {})
        if not isinstance(gdb, dict):
            raise TypeError("[gdb] must be a TOML table")
        pool = gdb.get("pool", {})
        if not isinstance(pool, dict):
            raise TypeError("[gdb.pool] must be a TOML table")
        value = pool.get("socket")
    except AttributeError as error:
        raise TypeError("project config root must be a TOML table") from error
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise TypeError("[gdb.pool].socket must be a nonempty path string")
    # Config-relative paths remain stable when manager/viewer use different
    # working directories beneath the same project.
    return _validate_socket_path(_path(value, base=config_path.parent.resolve()))


def _seed(data) -> str:
    try:
        table = data.get("pwnc")
    except AttributeError as error:
        raise TypeError("project config root must be a TOML table") from error
    if not isinstance(table, dict) or "seed" not in table:
        raise PoolDiscoveryError("local pwnc.toml has no [pwnc].seed; start the pool manager first")
    try:
        return _config.validate_project_seed(table["seed"])
    except (TypeError, ValueError) as error:
        raise PoolDiscoveryError("local [pwnc].seed is invalid") from error


def _directory_is_private(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def _ensure_private_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if not _directory_is_private(path):
        raise PoolDiscoveryError(f"runtime directory must be owned by this uid with mode 0700: {path}")
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
    # Preserve 128 bits of collision resistance while keeping deeply nested
    # XDG runtime paths below sockaddr_un's portable byte ceiling.
    encoded = base64.urlsafe_b64encode(digest.digest()[:16]).rstrip(b"=").decode("ascii")
    return f"p-{encoded}.sock"


def _runtime_candidates(runtime_dir) -> tuple[tuple[Path, bool], ...]:
    if runtime_dir is not None:
        candidate = _path(runtime_dir)
        return ((candidate, True),)

    # The default must be identical for independently launched manager/viewer
    # processes.  XDG_RUNTIME_DIR is intentionally excluded because a service,
    # shell, and terminal emulator can legitimately inherit different values.
    return ((Path("/tmp") / f"pwnc-{os.getuid()}", False),)


def _runtime_socket(filename: str, *, manager: bool, runtime_dir=None) -> tuple[Path, Path]:
    failures = []
    for directory, explicit in _runtime_candidates(runtime_dir):
        try:
            candidate = directory / filename
            _validate_socket_path(candidate)
            if manager:
                _ensure_private_directory(directory)
            elif directory.exists() and not _directory_is_private(directory):
                raise PoolDiscoveryError(
                    f"runtime directory must be owned by this uid with mode 0700: {directory}"
                )
            return directory, candidate
        except (OSError, PoolDiscoveryError, ValueError) as error:
            failures.append(error)
            if explicit:
                raise
    failure = failures[-1]
    if isinstance(failure, OSError):
        detail = _os_error_reason(failure)
    else:
        detail = str(failure)
    raise PoolDiscoveryError(
        f"no secure, portable runtime directory is available: {detail}"
    ) from failure


def _discover(
    name=DEFAULT_POOL_NAME,
    *,
    socket_path=None,
    config_path=None,
    start=None,
    runtime_dir=None,
    manager: bool,
) -> PoolAddress:
    name = _pool_name(name)
    # A manual API path is a complete override.  In particular manager lookup
    # must not create pwnc.toml merely because this feature was imported.
    if socket_path is not None:
        path = _validate_socket_path(_path(socket_path))
        return PoolAddress(name, path, "explicit")

    path = _config_path(config_path, start, manager=manager)
    if manager:
        try:
            _config.ensure_project_seed(path)
        except OSError as error:
            raise PoolDiscoveryError(
                f"could not initialize project discovery config {path}: "
                f"{_os_error_reason(error)}"
            ) from error
        except (TypeError, ValueError) as error:
            raise PoolDiscoveryError(
                f"could not initialize project discovery config {path}: {error}"
            ) from error
    try:
        data = _config.load_project_config(path)
    except OSError as error:
        raise PoolDiscoveryError(
            f"could not read project config {path}: {_os_error_reason(error)}"
        ) from error
    except (TypeError, ValueError) as error:
        raise PoolDiscoveryError(f"could not read project config {path}: {error}") from error

    configured = _local_socket(data, path)
    if configured is not None:
        return PoolAddress(
            name,
            configured,
            "config",
            config_path=path,
            project_root=path.parent,
        )

    try:
        seed = _seed(data)
    except PoolDiscoveryError as error:
        raise PoolDiscoveryError(f"{error} (project config: {path})") from error
    filename = _derived_filename(seed, path, name)
    runtime, socket_path = _runtime_socket(filename, manager=manager, runtime_dir=runtime_dir)
    return PoolAddress(
        name,
        socket_path,
        "derived",
        config_path=path,
        project_root=path.parent,
        seed=seed,
        runtime_dir=runtime,
    )


def discover_manager(
    name=DEFAULT_POOL_NAME,
    *,
    socket_path=None,
    config_path=None,
    start=None,
    runtime_dir=None,
) -> PoolAddress:
    """Resolve a manager address, atomically creating its local seed if needed."""
    try:
        return _discover(
            name,
            socket_path=socket_path,
            config_path=config_path,
            start=start,
            runtime_dir=runtime_dir,
            manager=True,
        )
    except (PoolDiscoveryError, TypeError, ValueError):
        raise
    except OSError as error:
        origin = _discovery_origin(
            socket_path=socket_path,
            config_path=config_path,
            start=start,
        )
        raise PoolDiscoveryError(
            f"could not prepare discovery for GDB pool {name!r} from {origin}: "
            f"{_os_error_reason(error)}"
        ) from error


def discover_viewer(
    name=DEFAULT_POOL_NAME,
    *,
    socket_path=None,
    config_path=None,
    start=None,
    runtime_dir=None,
) -> PoolAddress:
    """Read-only resolution of the address previously published by a manager."""
    try:
        return _discover(
            name,
            socket_path=socket_path,
            config_path=config_path,
            start=start,
            runtime_dir=runtime_dir,
            manager=False,
        )
    except (PoolDiscoveryError, TypeError, ValueError):
        raise
    except OSError as error:
        origin = _discovery_origin(
            socket_path=socket_path,
            config_path=config_path,
            start=start,
        )
        raise PoolDiscoveryError(
            f"could not discover GDB pool {name!r} from {origin}: "
            f"{_os_error_reason(error)}"
        ) from error


class PoolSocketLease:
    """Exclusive lifetime claim plus an already-bound listening Unix socket."""

    def __init__(self, address: PoolAddress, listener: socket.socket, lock_fd: int, identity):
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
            raise PoolDiscoveryError("pool socket lease is closed")
        return self._socket

    @property
    def closed(self) -> bool:
        return self._closed

    def duplicate_socket(self) -> socket.socket:
        """Return a listener duplicate owned by the caller.

        The lease must outlive every duplicate.  A router should close its
        duplicate before the manager closes this lease and releases discovery.
        """
        with self._close_lock:
            if self._closed:
                raise PoolDiscoveryError("pool socket lease is closed")
            duplicate = None
            try:
                duplicate = self._socket.dup()
                duplicate.set_inheritable(False)
                return duplicate
            except OSError as error:
                if duplicate is not None:
                    duplicate.close()
                raise PoolDiscoveryError(
                    f"could not duplicate the listener for GDB pool "
                    f"{self.address.name!r} at {self.path}: {_os_error_reason(error)}"
                ) from error

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

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()


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
    """Unlink *path* only while it still names the socket we created."""
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


def acquire_pool_socket(address: PoolAddress, *, backlog=1) -> PoolSocketLease:
    """Exclusively claim *address* and return its bound/listening socket.

    The namespace flock is acquired before examining or removing an old socket
    node and remains held by the returned lease.  Consequently a socket is only
    ever treated as stale by the one manager entitled to bind its replacement.
    """
    if not isinstance(address, PoolAddress):
        raise TypeError("address must be a PoolAddress")
    backlog = _backlog(backlog)
    path = _validate_socket_path(address.path)
    parent = path.parent
    try:
        parent_info = parent.stat()
    except FileNotFoundError as error:
        raise PoolDiscoveryError(f"Unix socket parent directory does not exist: {parent}")
    except OSError as error:
        raise PoolDiscoveryError(
            f"could not inspect Unix socket parent directory {parent}: "
            f"{_os_error_reason(error)}"
        ) from error
    if not stat.S_ISDIR(parent_info.st_mode):
        raise PoolDiscoveryError(f"Unix socket parent path is not a directory: {parent}")

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    stage = f"open namespace lock {address.lock_path}"
    try:
        lock_fd = os.open(address.lock_path, flags, 0o600)
    except OSError as error:
        raise PoolDiscoveryError(
            f"could not {stage} for GDB pool {address.name!r}: "
            f"{_os_error_reason(error)}"
        ) from error
    listener = None
    identity = None
    try:
        stage = f"inspect namespace lock {address.lock_path}"
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != os.getuid()
            or stat.S_IMODE(lock_info.st_mode) & 0o077
        ):
            raise PoolDiscoveryError(
                "pool namespace lock must be a private regular file owned by this uid"
            )
        stage = f"lock namespace {address.lock_path}"
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise PoolAlreadyRunningError(
                    f"pool manager already owns {address.name!r} at {path}"
                ) from error
            raise

        stage = f"inspect existing socket {path}"
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid():
                raise PoolDiscoveryError(f"refusing to replace non-owned socket path: {path}")
            stage = f"remove stale socket {path}"
            path.unlink()

        stage = "create the Unix listener"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.set_inheritable(False)
        stage = f"bind Unix listener {path}"
        listener.bind(os.fspath(path))
        stage = f"verify bound Unix listener {path}"
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise PoolDiscoveryError(f"bound pool path is not an owned Unix socket: {path}")
        identity = (info.st_dev, info.st_ino)
        stage = f"restrict Unix listener permissions at {path}"
        os.chmod(path, 0o600)
        stage = f"listen on Unix socket {path}"
        listener.listen(backlog)
        return PoolSocketLease(address, listener, lock_fd, identity)
    except BaseException as error:
        if listener is not None:
            listener.close()
        _unlink_socket_identity(path, identity)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
        if isinstance(error, OSError):
            raise PoolDiscoveryError(
                f"could not {stage} for GDB pool {address.name!r}: "
                f"{_os_error_reason(error)}"
            ) from error
        raise


__all__ = [
    "DEFAULT_POOL_NAME",
    "DISCOVERY_NAMESPACE",
    "DISCOVERY_VERSION",
    "MAX_UNIX_SOCKET_PATH_BYTES",
    "PoolAddress",
    "PoolAlreadyRunningError",
    "PoolDiscoveryError",
    "PoolSocketLease",
    "acquire_pool_socket",
    "discover_manager",
    "discover_viewer",
]
