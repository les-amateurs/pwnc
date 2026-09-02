"""Atomic, per-view artifact publication for Binary Ninja and GDB."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from typing import Callable, Iterator, MutableMapping

from .ir import Document


MANIFEST_SCHEMA = "pwnc.teemo.manifest"
MANIFEST_VERSION = 1
SUBSCRIBER_SCHEMA = "pwnc.teemo.subscriber"
SUBSCRIBER_VERSION = 1
NOTIFICATION_SCHEMA = "pwnc.teemo.notification"
NOTIFICATION_VERSION = 1


class ArtifactError(RuntimeError):
    """Raised when a debug generation cannot be published safely."""


@dataclass(frozen=True, slots=True)
class ManifestSection:
    name: str
    address: int
    size: int
    executable: bool
    writable: bool


@dataclass(frozen=True, slots=True)
class Manifest:
    schema: str
    version: int
    epoch: int
    view_id: str
    created_ns: int
    binary_path: str
    binary_filename: str
    build_id: str | None
    architecture: str
    image_base: int
    entry_point: int
    debug_object: str
    ir: str
    source_root: str
    primary_section: str
    sections: tuple[ManifestSection, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def load(cls, path: str | Path) -> Manifest:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if raw.get("schema") != MANIFEST_SCHEMA or raw.get("version") != MANIFEST_VERSION:
            raise ArtifactError(f"unsupported Teemo manifest at {path}")
        raw["sections"] = tuple(ManifestSection(**section) for section in raw["sections"])
        manifest = cls(**raw)
        manifest.validate()
        return manifest

    def validate(self) -> None:
        if self.epoch < 1 or not self.view_id:
            raise ArtifactError("manifest has an invalid epoch or view id")
        if not self.sections:
            raise ArtifactError("manifest contains no target sections")
        names = {section.name for section in self.sections}
        if self.primary_section not in names:
            raise ArtifactError(f"manifest primary section {self.primary_section!r} is absent")
        if any(section.size <= 0 or section.address < 0 for section in self.sections):
            raise ArtifactError("manifest contains an invalid section range")
        for artifact in (self.debug_object, self.ir, self.source_root):
            if not Path(artifact).is_absolute():
                raise ArtifactError(f"manifest artifact path is not absolute: {artifact!r}")


Emitter = Callable[[Path, Path], None]


class ArtifactStore:
    """Publish immutable generations and one atomic ``current.json`` pointer."""

    def __init__(
        self,
        state_root: str | Path | None = None,
        *,
        emitter: str | Path | Emitter | None = None,
        retain_generations: int = 3,
    ) -> None:
        configured = os.environ.get("TEEMO_STATE_DIR")
        self.state_root = Path(state_root or configured or (Path.home() / ".cache" / "pwnc-teemo"))
        self.emitter = emitter
        if retain_generations < 2:
            raise ValueError("retain_generations must be at least two so GDB never observes a deleted active file")
        self.retain_generations = retain_generations

    def publish(
        self,
        document: Document,
        binary_path: str | Path,
        *,
        timings: MutableMapping[str, float] | None = None,
    ) -> Manifest:
        started = time.perf_counter()

        def record(name: str, phase_started: float) -> None:
            if timings is not None:
                timings[name] = time.perf_counter() - phase_started

        try:
            prepare_started = time.perf_counter()
            document.validate()
            serialized_document = document.dumps(validate=False) + "\n"
            binary_path = Path(binary_path).expanduser().resolve(strict=False)
            view_id = view_identifier(document, binary_path)
            view_root = self.state_root / view_id
            generations = view_root / "generations"
            record("prepare", prepare_started)

            generations.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(view_root, 0o700)
                os.chmod(generations, 0o700)
            except OSError:
                pass

            lock_started = time.perf_counter()
            with self._lock(view_root):
                record("lock_wait", lock_started)
                self._remove_stale_staging(view_root)
                epoch = self._next_epoch(view_root)
                staging = Path(tempfile.mkdtemp(prefix=f".staging-{epoch}-", dir=view_root))
                final = generations / str(epoch)
                generation_created = False
                committed = False
                try:
                    stage_started = time.perf_counter()
                    ir_path = staging / "teemo-ir.json"
                    ir_path.write_text(serialized_document, encoding="utf-8")
                    record("stage", stage_started)

                    emit_started = time.perf_counter()
                    debug_path = staging / "teemo.debug"
                    self._emit(
                        ir_path,
                        debug_path,
                        source_reference_root=final / "teemo.sources",
                    )
                    if not debug_path.is_file() or debug_path.stat().st_size == 0:
                        raise ArtifactError("DWARF emitter did not produce a non-empty debug object")
                    source_root = staging / "teemo.sources"
                    if not source_root.is_dir():
                        raise ArtifactError("DWARF emitter did not materialize the generated source tree")
                    record("emit", emit_started)

                    final_manifest = self._manifest(
                        document,
                        binary_path,
                        view_id,
                        epoch,
                        final,
                    )
                    durability_started = time.perf_counter()
                    (staging / "manifest.json").write_text(
                        json.dumps(final_manifest.to_dict(), indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    _sync_tree(staging)
                    os.rename(staging, final)
                    generation_created = True
                    _sync_directory(generations)
                    _atomic_json(view_root / "current.json", final_manifest.to_dict())
                    committed = True
                    record("durability", durability_started)

                    notification_started = time.perf_counter()
                    try:
                        _notify_subscribers(view_root, final_manifest)
                    except Exception:
                        # Notifications are non-authoritative hints and must
                        # never turn a committed publication into a failure.
                        pass
                    record("notification", notification_started)

                    cleanup_started = time.perf_counter()
                    self._cleanup(generations, epoch)
                    record("cleanup", cleanup_started)
                    return final_manifest
                except Exception:
                    shutil.rmtree(staging, ignore_errors=True)
                    if generation_created and not committed:
                        shutil.rmtree(final, ignore_errors=True)
                    raise
        finally:
            record("total", started)

    def current_path(self, document: Document, binary_path: str | Path) -> Path:
        return self.state_root / view_identifier(document, Path(binary_path)) / "current.json"

    def _manifest(
        self,
        document: Document,
        binary_path: Path,
        view_id: str,
        epoch: int,
        generation: Path,
    ) -> Manifest:
        primary = next((section for section in document.sections if section.name == ".text"), None)
        primary = primary or next((section for section in document.sections if section.executable), document.sections[0])
        return Manifest(
            schema=MANIFEST_SCHEMA,
            version=MANIFEST_VERSION,
            epoch=epoch,
            view_id=view_id,
            created_ns=time.time_ns(),
            binary_path=str(binary_path),
            binary_filename=document.binary.filename,
            build_id=document.binary.build_id,
            architecture=document.binary.architecture.value,
            image_base=document.binary.image_base,
            entry_point=document.binary.entry_point,
            debug_object=str((generation / "teemo.debug").resolve(strict=False)),
            ir=str((generation / "teemo-ir.json").resolve(strict=False)),
            source_root=str((generation / "teemo.sources").resolve(strict=False)),
            primary_section=primary.name,
            sections=tuple(
                ManifestSection(
                    section.name,
                    section.address,
                    section.size,
                    section.executable,
                    section.writable,
                )
                for section in document.sections
            ),
        )

    def _emit(
        self,
        ir_path: Path,
        output: Path,
        *,
        source_reference_root: Path,
    ) -> None:
        if callable(self.emitter):
            self.emitter(ir_path, output)
            return
        executable = resolve_emitter(self.emitter)
        process = subprocess.run(
            [
                str(executable),
                "emit",
                str(ir_path),
                str(output),
                "--source-reference-root",
                str(source_reference_root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
            check=False,
        )
        if process.returncode != 0:
            detail = process.stderr.strip() or process.stdout.strip() or f"exit status {process.returncode}"
            raise ArtifactError(f"DWARF emitter failed: {detail}")

    def _next_epoch(self, view_root: Path) -> int:
        current = view_root / "current.json"
        current_epoch = 0
        try:
            if current.is_file():
                current_epoch = Manifest.load(current).epoch
        except (ArtifactError, OSError, ValueError, TypeError, json.JSONDecodeError):
            current_epoch = 0
        existing = [
            int(path.name)
            for path in (view_root / "generations").iterdir()
            if path.is_dir() and path.name.isdecimal()
        ]
        return max(current_epoch, *existing, 0) + 1

    def _remove_stale_staging(self, view_root: Path) -> None:
        """Remove abandoned pre-publication directories while holding the view lock."""

        for path in view_root.glob(".staging-*"):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)

    def _cleanup(self, generations: Path, current_epoch: int) -> None:
        try:
            existing = sorted(
                (
                    (int(path.name), path)
                    for path in generations.iterdir()
                    if path.is_dir() and path.name.isdecimal()
                ),
                reverse=True,
            )
        except OSError:
            return
        keep = {epoch for epoch, _ in existing[: self.retain_generations]}
        keep.add(current_epoch)
        keep.update(_leased_epochs(generations.parent))
        for epoch, path in existing:
            if epoch not in keep:
                shutil.rmtree(path, ignore_errors=True)

    @contextmanager
    def _lock(self, view_root: Path) -> Iterator[None]:
        lock_path = view_root / ".publish.lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def view_identifier(document: Document, binary_path: str | Path) -> str:
    path = Path(binary_path).expanduser().resolve(strict=False)
    identity = "\0".join(
        (
            str(path),
            document.binary.filename,
            document.binary.architecture.value,
            document.binary.build_id or "",
        )
    )
    return hashlib.sha256(identity.encode("utf-8", errors="surrogateescape")).hexdigest()[:24]


def resolve_emitter(configured: str | Path | None = None) -> Path:
    candidates = []
    if configured:
        candidates.append(Path(configured))
    if environment := os.environ.get("TEEMO_DWARF"):
        candidates.append(Path(environment))
    plugin_root = Path(__file__).resolve().parents[1]
    repository = Path(__file__).resolve().parents[2]
    candidates.extend(
        (
            plugin_root / "bin" / "teemo-dwarf",
            repository / "emitter" / "target" / "release" / "teemo-dwarf",
            repository / "emitter" / "target" / "debug" / "teemo-dwarf",
        )
    )
    if executable := shutil.which("teemo-dwarf"):
        candidates.append(Path(executable))
    for candidate in candidates:
        candidate = candidate.expanduser().resolve(strict=False)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise ArtifactError(
        "cannot find teemo-dwarf; build dwarf/emitter with cargo or set TEEMO_DWARF"
    )


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _sync_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            with path.open("rb") as value:
                os.fsync(value.fileno())
    for directory, _subdirectories, _files in os.walk(root, topdown=False):
        _sync_directory(Path(directory))


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _leased_epochs(view_root: Path) -> set[int]:
    result = set()
    leases = view_root / "leases"
    if not leases.is_dir():
        return result
    for path in leases.glob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("schema") != "pwnc.teemo.lease" or value.get("version") != 1:
                raise ValueError("unknown lease")
            pid = int(value["pid"])
            epoch = int(value["epoch"])
            if pid <= 0 or not Path(f"/proc/{pid}").exists():
                path.unlink(missing_ok=True)
                continue
            result.add(epoch)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            path.unlink(missing_ok=True)
    return result


def _notify_subscribers(view_root: Path, manifest: Manifest) -> None:
    """Wake live GDB consumers after ``current.json`` is durably published.

    Notifications are deliberately only hints. Consumers always reload the
    authoritative atomic manifest, and a stale or malformed subscriber must
    never make artifact publication fail.
    """

    subscribers = view_root / "subscribers"
    if not subscribers.is_dir():
        return
    payload = json.dumps(
        {
            "schema": NOTIFICATION_SCHEMA,
            "version": NOTIFICATION_VERSION,
            "view_id": manifest.view_id,
            "epoch": manifest.epoch,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
        notifier.setblocking(False)
        for descriptor in subscribers.glob("*.json"):
            socket_path: Path | None = None
            owned_socket = False
            try:
                value = json.loads(descriptor.read_text(encoding="utf-8"))
                if (
                    value.get("schema") != SUBSCRIBER_SCHEMA
                    or value.get("version") != SUBSCRIBER_VERSION
                    or value.get("view_id") != manifest.view_id
                ):
                    raise ValueError("invalid subscriber descriptor")
                pid = int(value["pid"])
                uid = int(value["uid"])
                start_ticks = int(value["process_start_ticks"])
                if pid <= 0 or uid != os.getuid():
                    raise ValueError("subscriber identity does not match publisher")
                socket_path = Path(str(value["socket_path"]))
                if not socket_path.is_absolute():
                    raise ValueError("subscriber socket path is not absolute")
                socket_stat = socket_path.lstat()
                if (
                    not stat.S_ISSOCK(socket_stat.st_mode)
                    or socket_stat.st_uid != uid
                ):
                    raise ValueError("unsafe subscriber socket")
                owned_socket = True
                if _process_start_ticks(pid) != start_ticks:
                    raise ProcessLookupError(pid)
                notifier.sendto(payload, os.fspath(socket_path))
            except BlockingIOError:
                # A full receiver queue already contains a wakeup. Dropping a
                # redundant hint is safe because current.json is authoritative.
                continue
            except (
                ProcessLookupError,
                FileNotFoundError,
                ValueError,
                TypeError,
                KeyError,
                json.JSONDecodeError,
            ):
                descriptor.unlink(missing_ok=True)
                if owned_socket and socket_path is not None:
                    socket_path.unlink(missing_ok=True)
            except OSError as error:
                if error.errno in {
                    errno.ECONNREFUSED,
                    errno.ENOENT,
                    errno.ENOTSOCK,
                    errno.ESRCH,
                }:
                    descriptor.unlink(missing_ok=True)
                    if owned_socket and socket_path is not None:
                        socket_path.unlink(missing_ok=True)


def _process_start_ticks(pid: int) -> int | None:
    """Read Linux's stable process start time for PID-reuse protection."""

    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = value[value.rindex(")") + 2 :].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None
