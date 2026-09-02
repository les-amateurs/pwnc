"""GDB commands for loading and live-refreshing Teemo DWARF generations."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import socket
import stat
import sys
import tempfile
import threading
import time
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import gdb  # type: ignore  # noqa: E402

from loader_core import (  # noqa: E402
    ET_EXEC,
    ElfImage,
    LoaderError,
    LoaderManifest,
    add_symbol_file_command,
    architecture_matches,
    compute_load_bias,
    find_manifest,
    parse_proc_maps,
    read_elf,
    remove_symbol_file_command,
)


@dataclass(slots=True)
class LoadedGeneration:
    manifest: LoaderManifest
    bias: int
    add_command: str
    lease: Path


_loaded: dict[int, LoadedGeneration] = {}
_watchers: dict[int, "ManifestWatcher"] = {}

SUBSCRIBER_SCHEMA = "pwnc.teemo.subscriber"
SUBSCRIBER_VERSION = 1
NOTIFICATION_SCHEMA = "pwnc.teemo.notification"
NOTIFICATION_VERSION = 1


def refresh(
    manifest_path: str | Path | None = None,
    *,
    target_path: str | Path | None = None,
    bias: int | None = None,
    force: bool = False,
    allow_identity_mismatch: bool = False,
) -> LoadedGeneration:
    """Atomically replace Teemo symbols for the current GDB program space."""

    manual_selection = allow_identity_mismatch or target_path is not None
    program = _optional_program_path() if manual_selection else _program_path()
    target = (
        Path(target_path).expanduser().resolve(strict=False)
        if target_path is not None
        else None
    )
    target_image = read_elf(target) if target is not None else None
    if manifest_path is None:
        if target is not None:
            manifest_path = find_manifest(
                _state_root(),
                target,
                build_id=target_image.build_id,
            )
        else:
            configured = os.environ.get("TEEMO_MANIFEST")
            if configured:
                manifest_path = configured
            else:
                assert program is not None
                manifest_path = find_manifest(
                    _state_root(),
                    program,
                    build_id=_main_objfile_build_id(program),
                )
    manifest = LoaderManifest.load(manifest_path)
    if target is not None:
        assert target_image is not None
        _validate_target_identity(manifest, target, target_image.build_id)
    if not manual_selection:
        assert program is not None
        _validate_identity(manifest, program)
    _validate_architecture(manifest)
    if bias is None:
        if manual_selection:
            bias = _manual_bias(manifest, program, target, target_image)
        else:
            assert program is not None
            bias = _runtime_bias(manifest, program)

    key = _progspace_key()
    previous = _loaded.get(key)
    if (
        not force
        and previous is not None
        and previous.manifest.view_id == manifest.view_id
        and previous.manifest.epoch == manifest.epoch
        and previous.bias == bias
    ):
        return previous

    try:
        pending_lease, lease = _prepare_lease(manifest)
    except OSError as error:
        raise LoaderError(f"cannot create a retention lease for epoch {manifest.epoch}: {error}") from error

    add_command = add_symbol_file_command(manifest, bias)
    removed_previous = False
    if previous is not None:
        try:
            gdb.execute(remove_symbol_file_command(previous.manifest, previous.bias), from_tty=False, to_string=True)
            removed_previous = True
        except gdb.error as error:
            pending_lease.unlink(missing_ok=True)
            raise LoaderError(
                f"could not remove prior Teemo generation; keeping epoch "
                f"{previous.manifest.epoch} active: {error}"
            ) from error
    try:
        gdb.execute(add_command, from_tty=False, to_string=True)
    except gdb.error as error:
        pending_lease.unlink(missing_ok=True)
        if removed_previous and previous is not None:
            try:
                gdb.execute(previous.add_command, from_tty=False, to_string=True)
                _loaded[key] = previous
                _write("warning: restored the prior Teemo generation after refresh failure\n", gdb.STDERR)
            except gdb.error as restore_error:
                _loaded.pop(key, None)
                _write(f"warning: could not restore prior Teemo symbols: {restore_error}\n", gdb.STDERR)
        raise LoaderError(f"GDB rejected {manifest.debug_object}: {error}") from error

    try:
        os.replace(pending_lease, lease)
    except OSError as error:
        pending_lease.unlink(missing_ok=True)
        try:
            gdb.execute(remove_symbol_file_command(manifest, bias), from_tty=False, to_string=True)
        except gdb.error as remove_error:
            _loaded.pop(key, None)
            raise LoaderError(
                f"could not commit the epoch {manifest.epoch} lease ({error}) and could not "
                f"roll back its symbols ({remove_error})"
            ) from error
        if previous is not None:
            try:
                gdb.execute(previous.add_command, from_tty=False, to_string=True)
                _loaded[key] = previous
            except gdb.error as restore_error:
                _loaded.pop(key, None)
                raise LoaderError(
                    f"could not commit the epoch {manifest.epoch} lease ({error}) and could not "
                    f"restore epoch {previous.manifest.epoch} ({restore_error})"
                ) from error
        else:
            _loaded.pop(key, None)
        raise LoaderError(f"could not commit a retention lease for epoch {manifest.epoch}: {error}") from error

    loaded = LoadedGeneration(manifest, bias, add_command, lease)
    _loaded[key] = loaded
    if previous is not None and previous.lease != lease:
        previous.lease.unlink(missing_ok=True)
    _write(
        f"Teemo: loaded epoch {manifest.epoch} for {manifest.binary_filename} "
        f"(bias {bias:#x}) from {manifest.debug_object}\n"
    )
    return loaded


def unload() -> None:
    """Remove Teemo symbols and the retention lease for this program space."""

    key = _progspace_key()
    previous = _loaded.get(key)
    if previous is None:
        return
    try:
        gdb.execute(remove_symbol_file_command(previous.manifest, previous.bias), from_tty=False, to_string=True)
    except gdb.error as error:
        raise LoaderError(
            f"could not unload Teemo epoch {previous.manifest.epoch}; symbols and lease remain active: {error}"
        ) from error
    _loaded.pop(key, None)
    previous.lease.unlink(missing_ok=True)


def _runtime_bias(manifest: LoaderManifest, program: Path) -> int:
    image = read_elf(program)
    inferior = gdb.selected_inferior()
    pid = int(getattr(inferior, "pid", 0) or 0)
    maps_path = Path(f"/proc/{pid}/maps")
    connection = getattr(inferior, "connection", None)
    connection_type = str(getattr(connection, "type", "native" if connection is None else ""))
    local_inferior = connection_type in {"", "native"}
    if local_inferior and pid > 0 and maps_path.is_file():
        try:
            mappings = parse_proc_maps(maps_path.read_text(encoding="utf-8", errors="replace"))
            return compute_load_bias(program, image, mappings)
        except (OSError, LoaderError) as error:
            _write(f"warning: process-map rebasing failed, trying GDB section data: {error}\n", gdb.STDERR)
    runtime_available = pid > 0 or (connection is not None and not local_inferior)
    runtime_entry = _gdb_runtime_entry() if runtime_available else None
    if runtime_entry is not None:
        bias = runtime_entry - manifest.entry_point
        if bias >= 0:
            return bias
    if image.object_type == ET_EXEC:
        return 0
    raise LoaderError("cannot determine PIE load bias; stop a running inferior or pass --bias ADDRESS")


def _manual_bias(
    manifest: LoaderManifest,
    program: Path | None,
    target: Path | None,
    target_image: ElfImage | None,
) -> int:
    """Derive a bias only when the explicitly selected image makes it safe."""

    if program is not None:
        try:
            _validate_identity(manifest, program)
        except LoaderError:
            pass
        else:
            return _runtime_bias(manifest, program)

    binary = target or manifest.binary_path
    try:
        image = target_image if target_image is not None else read_elf(binary)
    except LoaderError as error:
        raise LoaderError(
            "cannot determine the load bias for the manually selected target; "
            f"pass --bias ADDRESS ({error})"
        ) from error
    if image.object_type == ET_EXEC:
        return 0
    raise LoaderError(
        f"manually selected PIE target {binary} requires --bias ADDRESS"
    )


def _gdb_runtime_entry() -> int | None:
    try:
        output = gdb.execute("info files", from_tty=False, to_string=True)
    except gdb.error:
        return None
    match = re.search(r"^\s*Entry point:\s*(0x[0-9a-fA-F]+)", output, flags=re.MULTILINE)
    return int(match.group(1), 16) if match else None


def _validate_identity(manifest: LoaderManifest, program: Path) -> None:
    exact = _same_path(program, manifest.binary_path)
    build_id = _main_objfile_build_id(program)
    if manifest.build_id and build_id:
        if manifest.build_id.lower() != build_id.lower():
            raise LoaderError(
                f"manifest build id {manifest.build_id} does not match inferior build id {build_id}"
            )
        return
    if not exact:
        raise LoaderError(
            f"manifest belongs to {manifest.binary_path}, but GDB is debugging {program}; "
            "matching build ids are required when paths differ"
        )


def _validate_target_identity(
    manifest: LoaderManifest,
    target: Path,
    target_build_id: str | None,
) -> None:
    """Ensure target-based discovery did not select stale or unrelated data."""

    exact = _same_path(target, manifest.binary_path)
    if manifest.build_id and target_build_id:
        if manifest.build_id.lower() != target_build_id.lower():
            raise LoaderError(
                f"manifest build id {manifest.build_id} does not match target build id "
                f"{target_build_id} for {target}"
            )
        return
    if not exact:
        raise LoaderError(
            f"manifest belongs to {manifest.binary_path}, but --target selected {target}; "
            "matching build ids are required when paths differ"
        )


def _validate_architecture(manifest: LoaderManifest) -> None:
    try:
        architecture = gdb.selected_inferior().architecture().name()
    except (AttributeError, gdb.error):
        return
    if not architecture_matches(manifest.architecture, architecture):
        raise LoaderError(
            f"manifest architecture {manifest.architecture!r} does not match GDB architecture {architecture!r}"
        )


def _main_objfile_build_id(program: Path) -> str | None:
    for objfile in gdb.current_progspace().objfiles():
        filename = getattr(objfile, "filename", None)
        if filename and _same_path(program, filename):
            value = getattr(objfile, "build_id", None)
            return str(value) if value else None
    return None


def _program_path() -> Path:
    filename = getattr(gdb.current_progspace(), "filename", None)
    if not filename:
        raise LoaderError("GDB has no current executable; use the file command first")
    return Path(filename).expanduser().resolve(strict=False)


def _optional_program_path() -> Path | None:
    try:
        return _program_path()
    except LoaderError:
        return None


def _state_root() -> Path:
    configured = os.environ.get("TEEMO_STATE_DIR")
    if configured:
        return Path(configured).expanduser().resolve(strict=False)
    return Path.home() / ".cache" / "pwnc-teemo"


def _progspace_key() -> int:
    return id(gdb.current_progspace())


def _same_path(first: str | Path, second: str | Path) -> bool:
    try:
        return Path(first).samefile(second)
    except OSError:
        return Path(first).resolve(strict=False) == Path(second).resolve(strict=False)


def _prepare_lease(manifest: LoaderManifest) -> tuple[Path, Path]:
    """Write a provisional lease that pins the candidate until symbol commit."""

    view_root = _view_root_for_manifest(manifest.path)
    leases = view_root / "leases"
    leases.mkdir(mode=0o700, exist_ok=True)
    lease = leases / f"gdb-{os.getpid()}-{_progspace_key():x}.json"
    value: dict[str, Any] = {
        "schema": "pwnc.teemo.lease",
        "version": 1,
        "pid": os.getpid(),
        "epoch": manifest.epoch,
        "view_id": manifest.view_id,
        "debug_object": str(manifest.debug_object),
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=".lease-", dir=leases)
    temporary = Path(temporary_name)
    pending = Path(f"{temporary_name}.json")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        # Retention cleanup sees only the complete JSON name, never the
        # partially written staging file.
        os.replace(temporary, pending)
    except Exception:
        temporary.unlink(missing_ok=True)
        pending.unlink(missing_ok=True)
        raise
    return pending, lease


def _view_root_for_manifest(path: Path) -> Path:
    """Return the per-view state root for current or immutable manifests."""

    path = path.resolve(strict=False)
    parent = path.parent
    if path.name == "manifest.json" and parent.name.isdecimal() and parent.parent.name == "generations":
        return parent.parent.parent
    return parent


def _current_manifest_for(manifest: LoaderManifest) -> Path:
    candidate = _view_root_for_manifest(manifest.path) / "current.json"
    return candidate if candidate.is_file() else manifest.path


def _notification_runtime_dir() -> Path:
    configured = os.environ.get("TEEMO_RUNTIME_DIR")
    if configured:
        return Path(configured).expanduser().resolve(strict=False)
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        candidate = Path(runtime).expanduser().resolve(strict=False) / "pwnc-teemo"
        if len(os.fsencode(candidate / "gdb-000000-0000000000000000.sock")) < 108:
            return candidate
    return Path("/tmp") / f"pwnc-teemo-{os.getuid()}"


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LoaderError(f"cannot inspect Teemo runtime directory {path}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise LoaderError(f"Teemo runtime directory is not private to this user: {path}")
    if metadata.st_mode & 0o077:
        try:
            path.chmod(0o700)
        except OSError as error:
            raise LoaderError(f"cannot secure Teemo runtime directory {path}: {error}") from error


def _process_start_ticks(pid: int) -> int | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = value[value.rindex(")") + 2 :].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def _atomic_descriptor(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".subscriber-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class ManifestWatcher:
    """Receive manifest wakeups over a selected Unix datagram socket."""

    def __init__(
        self,
        manifest_path: Path,
        bias: int | None,
        view_id: str,
        *,
        target_path: Path | None,
        allow_identity_mismatch: bool,
    ) -> None:
        self.manifest_path = manifest_path
        self.bias = bias
        self.view_id = view_id
        self.target_path = target_path
        self.allow_identity_mismatch = allow_identity_mismatch
        self.key = _progspace_key()
        self._lock = threading.Lock()
        self._stopping = False
        self._started = False
        self._posted = False
        self._pending_epoch: int | None = None
        self._token = secrets.token_hex(8)
        self._runtime_dir = _notification_runtime_dir()
        self.socket_path = self._runtime_dir / f"gdb-{os.getpid()}-{self._token}.sock"
        view_root = _view_root_for_manifest(manifest_path)
        self._subscribers = view_root / "subscribers"
        self.descriptor_path = (
            self._subscribers
            / f"gdb-{os.getpid()}-{self.key:x}-{self._token}.json"
        )
        self._notification_socket: socket.socket | None = None
        self._control_reader: socket.socket | None = None
        self._control_writer: socket.socket | None = None
        self._thread = threading.Thread(target=self._run, name="teemo-gdb-live", daemon=True)

    def start(self) -> None:
        if self._started:
            raise LoaderError("Teemo live notification watcher is already started")
        _ensure_private_directory(self._runtime_dir)
        _ensure_private_directory(self._subscribers)
        if len(os.fsencode(self.socket_path)) >= 108:
            raise LoaderError(f"Unix notification socket path is too long: {self.socket_path}")

        notification_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        control_reader, control_writer = socket.socketpair()
        bound = False
        try:
            notification_socket.bind(os.fspath(self.socket_path))
            bound = True
            os.chmod(self.socket_path, 0o600)
            notification_socket.setblocking(False)
            control_reader.setblocking(False)
            control_writer.setblocking(False)
            start_ticks = _process_start_ticks(os.getpid())
            if start_ticks is None:
                raise LoaderError("cannot identify the GDB process for live notifications")
            _atomic_descriptor(
                self.descriptor_path,
                {
                    "schema": SUBSCRIBER_SCHEMA,
                    "version": SUBSCRIBER_VERSION,
                    "pid": os.getpid(),
                    "uid": os.getuid(),
                    "process_start_ticks": start_ticks,
                    "view_id": self.view_id,
                    "socket_path": str(self.socket_path),
                    "created_ns": time.time_ns(),
                },
            )
            self._notification_socket = notification_socket
            self._control_reader = control_reader
            self._control_writer = control_writer
            self._thread.start()
            self._started = True
        except Exception as error:
            notification_socket.close()
            control_reader.close()
            control_writer.close()
            self.descriptor_path.unlink(missing_ok=True)
            if bound:
                self.socket_path.unlink(missing_ok=True)
            if isinstance(error, LoaderError):
                raise
            raise LoaderError(f"cannot start Teemo live notification socket: {error}") from error

    def stop(self) -> None:
        with self._lock:
            if self._stopping:
                return
            self._stopping = True
        if self._control_writer is not None:
            try:
                self._control_writer.send(b"x")
            except (BlockingIOError, OSError):
                pass
        if self._started:
            self._thread.join(timeout=2)
        for value in (
            self._notification_socket,
            self._control_reader,
            self._control_writer,
        ):
            if value is not None:
                value.close()
        self.descriptor_path.unlink(missing_ok=True)
        self.socket_path.unlink(missing_ok=True)
        try:
            self._runtime_dir.rmdir()
        except OSError:
            pass

    def _run(self) -> None:
        assert self._notification_socket is not None
        assert self._control_reader is not None
        while True:
            try:
                readable, _writable, _exceptional = select.select(
                    [self._notification_socket, self._control_reader], [], []
                )
            except (OSError, ValueError):
                return
            if self._control_reader in readable:
                return
            if self._notification_socket not in readable:
                continue
            while True:
                try:
                    payload = self._notification_socket.recv(65536)
                except BlockingIOError:
                    break
                except OSError:
                    return
                self._queue(payload)

    def _queue(self, payload: bytes) -> None:
        try:
            raw = json.loads(payload.decode("utf-8"))
            if (
                raw.get("schema") != NOTIFICATION_SCHEMA
                or raw.get("version") != NOTIFICATION_VERSION
                or raw.get("view_id") != self.view_id
            ):
                return
            epoch = int(raw["epoch"])
            if epoch < 1:
                return
        except (UnicodeDecodeError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return

        current = _loaded.get(self.key)
        if (
            current is not None
            and current.manifest.view_id == self.view_id
            and current.manifest.epoch >= epoch
        ):
            return
        should_post = False
        with self._lock:
            if self._stopping:
                return
            self._pending_epoch = max(epoch, self._pending_epoch or 0)
            if not self._posted:
                self._posted = True
                should_post = True
        if should_post:
            try:
                gdb.post_event(self._apply)
            except Exception:
                with self._lock:
                    self._posted = False

    def _apply(self) -> None:
        with self._lock:
            if self._stopping:
                self._posted = False
                return
            self._pending_epoch = None
        try:
            refresh(
                self.manifest_path,
                target_path=self.target_path,
                bias=self.bias,
                allow_identity_mismatch=self.allow_identity_mismatch,
            )
        except (LoaderError, gdb.error) as error:
            _write(f"Teemo live refresh failed: {error}\n", gdb.STDERR)
        finally:
            should_post = False
            with self._lock:
                self._posted = False
                pending = self._pending_epoch
                current = _loaded.get(self.key)
                current_epoch = (
                    current.manifest.epoch
                    if current is not None and current.manifest.view_id == self.view_id
                    else 0
                )
                if not self._stopping and pending is not None and pending > current_epoch:
                    self._posted = True
                    should_post = True
                elif pending is not None and pending <= current_epoch:
                    self._pending_epoch = None
            if should_post:
                try:
                    gdb.post_event(self._apply)
                except Exception:
                    with self._lock:
                        self._posted = False


class TeemoRefreshCommand(gdb.Command):
    """Load or transactionally refresh Teemo-generated debug information."""

    def __init__(self) -> None:
        super().__init__("teemo-refresh", gdb.COMMAND_FILES)

    def invoke(self, argument: str, from_tty: bool) -> None:
        try:
            manifest, target, bias, force = _parse_refresh_arguments(argument)
            manual_selection = manifest is not None or target is not None
            refresh(
                manifest,
                target_path=target,
                bias=bias,
                force=force,
                allow_identity_mismatch=manual_selection,
            )
        except LoaderError as error:
            raise gdb.GdbError(str(error)) from error


class TeemoUnloadCommand(gdb.Command):
    """Unload Teemo-generated debug information for the current program space."""

    def __init__(self) -> None:
        super().__init__("teemo-unload", gdb.COMMAND_FILES)

    def invoke(self, argument: str, from_tty: bool) -> None:
        if argument.strip():
            raise gdb.GdbError("usage: teemo-unload")
        try:
            unload()
        except LoaderError as error:
            raise gdb.GdbError(str(error)) from error


class TeemoStatusCommand(gdb.Command):
    """Show the loaded Teemo generation and live-refresh state."""

    def __init__(self) -> None:
        super().__init__("teemo-status", gdb.COMMAND_STATUS)

    def invoke(self, argument: str, from_tty: bool) -> None:
        if argument.strip():
            raise gdb.GdbError("usage: teemo-status")
        loaded = _loaded.get(_progspace_key())
        watcher = _watchers.get(_progspace_key())
        if loaded is None:
            _write("Teemo: no generated debug information is loaded\n")
        else:
            _write(
                f"Teemo: epoch {loaded.manifest.epoch}, view {loaded.manifest.view_id}, "
                f"bias {loaded.bias:#x}, {loaded.manifest.debug_object}\n"
            )
        _write(f"Teemo live refresh: {'on' if watcher else 'off'}\n")


class TeemoLiveCommand(gdb.Command):
    """Enable or disable live refresh of an atomic Teemo manifest."""

    def __init__(self) -> None:
        super().__init__("teemo-live", gdb.COMMAND_FILES)

    def invoke(self, argument: str, from_tty: bool) -> None:
        try:
            arguments = shlex.split(argument)
            if not arguments or arguments[0] not in {"on", "off"}:
                raise LoaderError(
                    "usage: teemo-live on [MANIFEST | --target FILE] "
                    "[--bias ADDRESS] [--force] | teemo-live off"
                )
            key = _progspace_key()
            if arguments[0] == "off":
                if len(arguments) != 1:
                    raise LoaderError("usage: teemo-live off")
                watcher = _watchers.pop(key, None)
                if watcher:
                    watcher.stop()
                _write("Teemo live refresh disabled\n")
                return
            manifest_arg, target, bias, force = _parse_refresh_arguments(
                " ".join(shlex.quote(value) for value in arguments[1:])
            )
            manual_selection = manifest_arg is not None or target is not None
            loaded = refresh(
                manifest_arg,
                target_path=target,
                bias=bias,
                force=force,
                allow_identity_mismatch=manual_selection,
            )
            old = _watchers.pop(key, None)
            if old:
                old.stop()
            manifest_path = _current_manifest_for(loaded.manifest)
            watcher = ManifestWatcher(
                manifest_path,
                bias,
                loaded.manifest.view_id,
                target_path=target,
                allow_identity_mismatch=manual_selection,
            )
            try:
                watcher.start()
                # Close the refresh/register race. A publication before the
                # descriptor was visible is found here; one after it sends a
                # datagram that remains queued until the watcher drains it.
                refresh(
                    manifest_path,
                    target_path=target,
                    bias=bias,
                    allow_identity_mismatch=manual_selection,
                )
            except Exception:
                watcher.stop()
                raise
            _watchers[key] = watcher
            _write(
                f"Teemo live refresh subscribed to {manifest_path} "
                f"via {watcher.socket_path}\n"
            )
        except LoaderError as error:
            raise gdb.GdbError(str(error)) from error


def _parse_refresh_arguments(
    argument: str,
) -> tuple[Path | None, Path | None, int | None, bool]:
    arguments = shlex.split(argument)
    manifest = None
    target = None
    bias = None
    force = False
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value == "--force":
            force = True
        elif value == "--target":
            index += 1
            if index >= len(arguments):
                raise LoaderError("--target requires an ELF path")
            if target is not None:
                raise LoaderError("--target may only be specified once")
            target = Path(arguments[index])
        elif value == "--bias":
            index += 1
            if index >= len(arguments):
                raise LoaderError("--bias requires an address")
            try:
                bias = int(arguments[index], 0)
            except ValueError as error:
                raise LoaderError(f"invalid load bias {arguments[index]!r}") from error
            if bias < 0:
                raise LoaderError("load bias must not be negative")
        elif value.startswith("-"):
            raise LoaderError(f"unknown option {value!r}")
        elif manifest is None:
            manifest = Path(value)
        else:
            raise LoaderError(
                "usage: teemo-refresh [MANIFEST | --target FILE] "
                "[--bias ADDRESS] [--force]"
            )
        index += 1
    if manifest is not None and target is not None:
        raise LoaderError("MANIFEST and --target are mutually exclusive")
    return manifest, target, bias, force


def _write(message: str, stream: Any = None) -> None:
    gdb.write(message, stream or gdb.STDOUT)


def _on_gdb_exit(_event: Any) -> None:
    # Inferior exit is not a progspace exit, so leave symbols loaded for reruns.
    # Leases are cleaned at process shutdown by the atexit handler below.
    return


def _cleanup() -> None:
    for watcher in list(_watchers.values()):
        watcher.stop()
    for loaded in list(_loaded.values()):
        loaded.lease.unlink(missing_ok=True)


import atexit  # noqa: E402

atexit.register(_cleanup)
gdb.events.exited.connect(_on_gdb_exit)
TeemoRefreshCommand()
TeemoUnloadCommand()
TeemoStatusCommand()
TeemoLiveCommand()
_write("Teemo GDB commands loaded: teemo-refresh, teemo-live, teemo-status, teemo-unload\n")
