"""Build and control the native Linux challenge supervisor.

The shim talks over an ``AF_UNIX/SOCK_SEQPACKET`` socket instead of an
inherited descriptor.  A host listener can therefore be bind-mounted into a
Docker container without giving the challenge protocol access to its stdio.
"""

from __future__ import annotations

import array
import fcntl
import hashlib
import os
import platform
import selectors
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from pathlib import Path
from typing import Self

MAGIC = 0x50574E53
VERSION = 3
FRAME = struct.Struct("!8I")


class EventKind(IntEnum):
    READY = 1
    EXIT = 2
    ERROR = 3
    ACK = 4
    HELLO = 5


class CommandKind(IntEnum):
    CONTINUE = 0x101
    SIGNAL = 0x102
    KILL = 0x103
    READY_ACK = 0x104
    HELLO_ACK = 0x105


class ReadyFlags(IntFlag):
    PAUSED = 1 << 0
    PIDFD = 1 << 1


class ExitFlags(IntFlag):
    NORMAL = 1 << 0
    SIGNAL = 1 << 1
    CORE = 1 << 2


class ErrorFlags(IntFlag):
    FATAL = 1 << 0


class ErrorStage(IntEnum):
    ARGUMENTS = 1
    CONTROL_CONNECT = 2
    SIGNAL_SETUP = 3
    FORK = 4
    CHILD_PDEATHSIG = 5
    CHILD_DUMPABLE = 6
    CHILD_PTRACER = 7
    CHILD_SIGNAL_RESET = 8
    CHILD_GATE = 9
    CHILD_EXEC = 10
    PTRACE_SEIZE = 11
    PTRACE_EXEC_WAIT = 12
    PTRACE_DETACH = 13
    GROUP_STOP = 14
    PIDFD = 15
    PROTOCOL = 16
    SIGNAL = 17
    WAIT = 18
    CHILD_CAPABILITIES = 19
    CHILD_NO_NEW_PRIVS = 20
    CHILD_ASLR = 21


class ShimError(RuntimeError):
    """Base error raised by the native shim integration."""


class ShimBuildError(ShimError):
    """The static native helper could not be built."""


class ShimProtocolError(ShimError):
    """The control peer sent a malformed or unexpected frame."""


class ShimRemoteError(ShimError):
    """The native supervisor reported an operation failure."""

    def __init__(self, event: ShimEvent) -> None:
        self.event = event
        try:
            stage = ErrorStage(event.detail).name.lower()
        except ValueError:
            stage = f"stage-{event.detail}"
        try:
            description = os.strerror(event.value)
        except ValueError:
            description = "unknown error"
        super().__init__(f"sandbox shim {stage} failed: [errno {event.value}] {description}")


def _signed32(value: int) -> int:
    return value - (1 << 32) if value & (1 << 31) else value


@dataclass(frozen=True, slots=True)
class ShimEvent:
    kind: EventKind
    pid: int
    value: int
    detail: int
    flags: int
    pidfd: int | None = None

    @property
    def paused(self) -> bool:
        return self.kind is EventKind.READY and bool(self.flags & ReadyFlags.PAUSED)

    @property
    def returncode(self) -> int:
        if self.kind is not EventKind.EXIT:
            raise ValueError("returncode is defined only for EXIT events")
        if self.flags & ExitFlags.NORMAL:
            return self.value
        if self.flags & ExitFlags.SIGNAL:
            return -self.value
        raise ShimProtocolError(f"EXIT frame has invalid flags {self.flags:#x}")


def _default_cache_root() -> Path:
    configured = os.environ.get("XDG_CACHE_HOME")
    root = Path(configured) if configured else Path.home() / ".cache"
    return root / "pwnc" / "sandbox" / "shim"


def _native_zig_target() -> str:
    machine = platform.machine().lower()
    targets = {
        "x86_64": "x86_64-linux-musl",
        "amd64": "x86_64-linux-musl",
        "aarch64": "aarch64-linux-musl",
        "arm64": "aarch64-linux-musl",
        "i386": "x86-linux-musl",
        "i486": "x86-linux-musl",
        "i586": "x86-linux-musl",
        "i686": "x86-linux-musl",
        "riscv64": "riscv64-linux-musl",
        "ppc64le": "powerpc64le-linux-musl",
    }
    try:
        return targets[machine]
    except KeyError as error:
        raise ShimBuildError(f"unsupported native Linux architecture: {machine}") from error


def _mkdir_private(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except PermissionError:
        pass


def _valid_cached_binary(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not path.is_symlink()
        and bool(metadata.st_mode & stat.S_IXUSR)
    )


def build_shim(*, cache_root: str | os.PathLike[str] | None = None, zig: str | None = None) -> Path:
    """Return a cached, static native build of :mod:`shim.c`.

    The content key includes the source, Zig version, target, and complete
    compiler argument set.  A per-key advisory lock and atomic rename make
    concurrent builders safe.
    """

    if platform.system() != "Linux":
        raise ShimBuildError("the sandbox shim requires Linux")
    compiler = zig or shutil.which("zig")
    if not compiler:
        raise ShimBuildError("zig was not found in PATH")
    compiler = os.fspath(Path(compiler).resolve())
    try:
        version_result = subprocess.run(
            [compiler, "version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ShimBuildError(f"cannot query Zig compiler {compiler!r}: {error}") from error

    source = Path(__file__).with_name("shim.c")
    source_bytes = source.read_bytes()
    target = _native_zig_target()
    compiler_arguments = ("cc", "-target", target, "-static", "-O2", "-std=c11")
    digest = hashlib.sha256()
    for component in (
        b"pwnc-sandbox-shim-v3\0",
        source_bytes,
        os.fsencode(compiler),
        version_result.stdout.strip().encode("utf-8", "surrogateescape"),
        *[argument.encode("ascii") for argument in compiler_arguments],
    ):
        digest.update(struct.pack("!Q", len(component)))
        digest.update(component)

    root = Path(cache_root) if cache_root is not None else _default_cache_root()
    _mkdir_private(root)
    entry = root / digest.hexdigest()
    _mkdir_private(entry)
    output = entry / "pwnc-sandbox-shim"
    lock_path = entry / ".build.lock"
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        if _valid_cached_binary(output):
            return output

        temporary_descriptor, temporary_name = tempfile.mkstemp(prefix=".shim-", dir=entry)
        os.close(temporary_descriptor)
        temporary = Path(temporary_name)
        try:
            command = [compiler, *compiler_arguments, os.fspath(source), "-o", os.fspath(temporary)]
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            if result.returncode != 0:
                diagnostics = (result.stderr or result.stdout).strip()
                raise ShimBuildError(f"zig cc failed ({result.returncode}): {diagnostics}")
            # The cache directory is private, while the file itself must be
            # executable after a bind mount into a container whose configured
            # user may not be the host user.
            temporary.chmod(0o755)
            os.replace(temporary, output)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return output
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def shim_argv(
    control_path: str | os.PathLike[str],
    program: str | os.PathLike[str],
    arguments: Sequence[str | os.PathLike[str]] = (),
    *,
    pause: bool = True,
    host_aslr: bool | None = None,
    fallback_executable: str | os.PathLike[str] | None = None,
    shim: str | os.PathLike[str] | None = None,
) -> list[str]:
    """Construct the shim argv without shell parsing or argument rewriting."""

    executable = Path(shim) if shim is not None else build_shim()
    result = [
        os.fspath(executable),
        "--control",
        os.fspath(control_path),
        "--pause" if pause else "--no-pause",
    ]
    if host_aslr is not None and type(host_aslr) is not bool:
        raise TypeError("host_aslr must be a bool or None")
    if host_aslr is not None:
        result.extend(("--host-aslr", "on" if host_aslr else "off"))
    if fallback_executable is not None:
        result.extend(("--fallback-executable", os.fspath(fallback_executable)))
    result.extend(("--", os.fspath(program), *[os.fspath(argument) for argument in arguments]))
    return result


class ShimConnection:
    """One connected native supervisor control channel."""

    def __init__(self, connection: socket.socket) -> None:
        self._socket = connection
        self._pidfd: int | None = None
        self._closed = False

    @property
    def pidfd(self) -> int | None:
        return self._pidfd

    @property
    def host_pid(self) -> int | None:
        """Resolve the target PID in this process' PID namespace."""

        if self._pidfd is None:
            return None
        fdinfo = Path(f"/proc/self/fdinfo/{self._pidfd}")
        try:
            lines = fdinfo.read_text().splitlines()
        except OSError:
            return None
        for line in lines:
            if line.startswith("Pid:"):
                value = line.partition(":")[2].strip()
                try:
                    pid = int(value)
                except ValueError:
                    return None
                return pid if pid > 0 else None
        return None

    def fileno(self) -> int:
        return self._socket.fileno()

    def peer_credentials(self) -> tuple[int, int, int]:
        """Return the supervisor's host-namespace ``(pid, uid, gid)``.

        Sandbox launch is Linux-only, so silently proceeding without
        ``SO_PEERCRED`` would defeat the pre-exec identity handoff.
        """

        option = getattr(socket, "SO_PEERCRED", None)
        if option is None:
            raise ShimProtocolError("Linux SO_PEERCRED is unavailable for the sandbox shim")
        try:
            credentials = self._socket.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        except OSError as error:
            raise ShimProtocolError(f"cannot read sandbox shim peer credentials: {error}") from error
        pid, uid, gid = struct.unpack("3i", credentials)
        if pid <= 0 or uid < 0 or gid < 0:
            raise ShimProtocolError("sandbox shim returned invalid peer credentials")
        return pid, uid, gid

    def _wait_readable(self, timeout: float | None) -> None:
        if timeout is None:
            return
        selector = selectors.DefaultSelector()
        try:
            selector.register(self._socket, selectors.EVENT_READ)
            if not selector.select(max(0.0, float(timeout))):
                raise TimeoutError("timed out waiting for sandbox shim event")
        finally:
            selector.close()

    def recv(self, timeout: float | None = None, *, raise_remote: bool = False) -> ShimEvent:
        """Receive one complete event, including a READY pidfd when present."""

        self._wait_readable(timeout)
        fd_array = array.array("i")
        try:
            payload, ancillary, message_flags, _address = self._socket.recvmsg(
                FRAME.size,
                socket.CMSG_SPACE(fd_array.itemsize),
                getattr(socket, "MSG_CMSG_CLOEXEC", 0),
            )
        except OSError as error:
            raise ShimProtocolError(f"cannot receive shim frame: {error}") from error
        if not payload:
            raise EOFError("sandbox shim closed its control socket")
        if message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise ShimProtocolError("truncated sandbox shim frame")
        if len(payload) != FRAME.size:
            raise ShimProtocolError(f"sandbox shim frame is {len(payload)} bytes, expected {FRAME.size}")

        received_fds: list[int] = []
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                usable = len(data) - (len(data) % fd_array.itemsize)
                fd_array.frombytes(data[:usable])
                received_fds.extend(fd_array)
                del fd_array[:]
        try:
            magic, version, raw_kind, pid, raw_value, detail, flags, reserved = FRAME.unpack(payload)
            if magic != MAGIC or version != VERSION or reserved != 0:
                raise ShimProtocolError("invalid sandbox shim frame header")
            try:
                event_kind = EventKind(raw_kind)
            except ValueError as error:
                raise ShimProtocolError(f"unexpected sandbox shim event kind {raw_kind:#x}") from error
            if len(received_fds) > 1:
                raise ShimProtocolError("sandbox shim sent more than one descriptor")
            received_pidfd = received_fds[0] if received_fds else None
            expects_pidfd = event_kind is EventKind.READY and bool(flags & ReadyFlags.PIDFD)
            if expects_pidfd != (received_pidfd is not None):
                raise ShimProtocolError("READY pidfd flag and descriptor disagree")
            if received_pidfd is not None:
                descriptor_flags = fcntl.fcntl(received_pidfd, fcntl.F_GETFD)
                fcntl.fcntl(received_pidfd, fcntl.F_SETFD, descriptor_flags | fcntl.FD_CLOEXEC)
                if self._pidfd is not None:
                    os.close(self._pidfd)
                self._pidfd = received_pidfd
                received_fds.clear()
            event = ShimEvent(event_kind, pid, _signed32(raw_value), detail, flags, received_pidfd)
            if raise_remote and event.kind is EventKind.ERROR:
                raise ShimRemoteError(event)
            return event
        finally:
            for descriptor in received_fds:
                os.close(descriptor)

    def _command(self, kind: CommandKind, value: int = 0) -> None:
        if self._closed:
            raise ShimProtocolError("sandbox shim connection is closed")
        payload = FRAME.pack(MAGIC, VERSION, int(kind), 0, value & 0xFFFFFFFF, 0, 0, 0)
        try:
            sent = self._socket.send(payload)
        except OSError as error:
            raise ShimProtocolError(f"cannot send shim command: {error}") from error
        if sent != len(payload):
            raise ShimProtocolError("short sandbox shim command write")

    def continue_(self) -> None:
        self._command(CommandKind.CONTINUE)

    def signal(self, number: int) -> None:
        if number <= 0:
            raise ValueError("signal number must be positive")
        self._command(CommandKind.SIGNAL, int(number))

    def kill(self) -> None:
        self._command(CommandKind.KILL)

    def acknowledge_ready(self) -> None:
        """Allow a non-paused supervisor to reap its target after READY."""
        self._command(CommandKind.READY_ACK)

    def acknowledge_hello(self) -> None:
        """Release a verified supervisor to fork and exec the target."""
        self._command(CommandKind.HELLO_ACK)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            # A manager owns a dedicated reader thread for this connection.
            # shutdown() wakes a blocking recvmsg() before the descriptor is
            # closed; close() alone is not guaranteed to interrupt another
            # thread on every supported kernel.
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._socket.close()
        finally:
            if self._pidfd is not None:
                os.close(self._pidfd)
                self._pidfd = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class ShimListener:
    """Host-side listener suitable for bind-mounting into a container."""

    def __init__(self, socket_path: str | os.PathLike[str]) -> None:
        self.path = Path(socket_path).resolve(strict=False)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            raise FileExistsError(self.path)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        try:
            self._socket.bind(os.fspath(self.path))
            os.chmod(self.path, 0o600)
            self._socket.listen(1)
        except BaseException:
            self._socket.close()
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            raise
        self._closed = False

    @property
    def mount_directory(self) -> Path:
        return self.path.parent

    def fileno(self) -> int:
        """Expose listener readiness without accepting or polling."""

        return self._socket.fileno()

    def container_path(self, mount_point: str | os.PathLike[str]) -> Path:
        return Path(mount_point) / self.path.name

    def accept(self, timeout: float | None = None) -> ShimConnection:
        if timeout is not None:
            selector = selectors.DefaultSelector()
            try:
                selector.register(self._socket, selectors.EVENT_READ)
                if not selector.select(max(0.0, float(timeout))):
                    raise TimeoutError("timed out waiting for sandbox shim connection")
            finally:
                selector.close()
        connection, _address = self._socket.accept()
        return ShimConnection(connection)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._socket.close()
        finally:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


__all__ = [
    "CommandKind",
    "ErrorFlags",
    "ErrorStage",
    "EventKind",
    "ExitFlags",
    "ReadyFlags",
    "ShimBuildError",
    "ShimConnection",
    "ShimError",
    "ShimEvent",
    "ShimListener",
    "ShimProtocolError",
    "ShimRemoteError",
    "build_shim",
    "shim_argv",
]
