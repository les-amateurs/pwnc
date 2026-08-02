"""Pinned glibc sysroots for native and qemu-user integration tests.

The normal unit suite only parses and validates the manifest.  Downloading is
explicit: callers choose a cache directory and call :func:`provision_sysroot`.
Artifacts are content-addressed by their checked-in SHA-256 digest, while an
extracted root is keyed by every execution-relevant field in its specification.
"""

from __future__ import annotations

import fcntl
import hashlib
import inspect
import json
import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType, TracebackType
from typing import Any

from payloads.target import SUPPORTED_TARGETS, Target, resolve_target

DEFAULT_GLIBC_LANE = "glibc-2.39"
_MANIFEST_PATH = Path(__file__).with_name("glibc_sysroots.json")
_BUFFER_SIZE = 1024 * 1024
_TARGETS_BY_NAME = {target.name: target for target in SUPPORTED_TARGETS}


class SysrootError(RuntimeError):
    """A manifest, download, extraction, or artifact validation failed."""


class UnsupportedSysrootError(SysrootError):
    """The requested target deliberately has no glibc runtime artifact."""


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    """One immutable input archive."""

    name: str
    url: str
    sha256: str
    kind: str

    @property
    def cache_suffix(self) -> str:
        if self.name.endswith(".tar.xz"):
            return ".tar.xz"
        if self.name.endswith(".tar.bz2"):
            return ".tar.bz2"
        return Path(self.name).suffix


@dataclass(frozen=True, slots=True)
class ElfIdentity:
    """ELF header properties which distinguish the catalog ABI."""

    elf_class: int
    endian: str
    machine: int
    flags_mask: int = 0
    flags_value: int = 0


@dataclass(frozen=True, slots=True)
class CompilerSpec:
    kind: str
    target: str | None = None
    argv: tuple[str, ...] = ()
    driver: str | None = None


@dataclass(frozen=True, slots=True)
class SysrootSpec:
    """A glibc root shared by one or more catalog targets."""

    id: str
    lane: str
    glibc_version: str
    targets: tuple[str, ...]
    source: str
    artifacts: tuple[ArtifactSpec, ...]
    extraction_kind: str
    extraction_top: str | None
    sysroot_subdir: str | None
    compiler: CompilerSpec
    qemu: str
    interpreter: str | None
    loader: str
    libc: str
    elf: ElfIdentity
    version_marker: str

    @property
    def fingerprint(self) -> str:
        value = {
            "id": self.id,
            "lane": self.lane,
            "glibc_version": self.glibc_version,
            "targets": self.targets,
            "source": self.source,
            "artifacts": [
                {"name": item.name, "url": item.url, "sha256": item.sha256, "kind": item.kind}
                for item in self.artifacts
            ],
            "extraction_kind": self.extraction_kind,
            "extraction_top": self.extraction_top,
            "sysroot_subdir": self.sysroot_subdir,
            "compiler": {
                "kind": self.compiler.kind,
                "target": self.compiler.target,
                "argv": self.compiler.argv,
            },
            "qemu": self.qemu,
            "loader": self.loader,
            "libc": self.libc,
            "elf": {
                "class": self.elf.elf_class,
                "endian": self.elf.endian,
                "machine": self.elf.machine,
                "flags_mask": self.elf.flags_mask,
                "flags_value": self.elf.flags_value,
            },
            "version_marker": self.version_marker,
        }
        if self.interpreter is not None:
            value["interpreter"] = self.interpreter
        if self.compiler.driver is not None:
            value["compiler"]["driver"] = self.compiler.driver
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class UnsupportedRecord:
    target: str
    reason: str
    upstream_glibc: bool


@dataclass(frozen=True, slots=True)
class SysrootManifest:
    schema_version: int
    default_lane: str
    sysroots: tuple[SysrootSpec, ...]
    unsupported: Mapping[str, UnsupportedRecord]
    by_lane_target: Mapping[tuple[str, str], SysrootSpec]

    @property
    def lanes(self) -> frozenset[str]:
        return frozenset(item.lane for item in self.sysroots)

    def resolve(self, target: Target | str, lane: str | None = None) -> SysrootSpec:
        resolved = _resolve_catalog_target(target)
        selected_lane = lane or self.default_lane
        unsupported = self.unsupported.get(resolved.name)
        if unsupported is not None:
            raise UnsupportedSysrootError(f"{resolved.name}: {unsupported.reason}")
        try:
            return self.by_lane_target[(selected_lane, resolved.name)]
        except KeyError as exc:
            raise UnsupportedSysrootError(f"no {selected_lane} runtime sysroot is pinned for {resolved.name}") from exc


@dataclass(frozen=True, slots=True)
class ProvisionedSysroot:
    """Concrete paths and commands produced from a :class:`SysrootSpec`."""

    spec: SysrootSpec
    root: Path
    sysroot: Path
    libc: Path
    loader: Path
    bootlin_compiler: Path | None = None

    @property
    def qemu(self) -> str:
        return self.spec.qemu

    def resolve_guest_path(self, guest_path: str | os.PathLike[str]) -> Path:
        """Resolve guest-absolute symlinks beneath this sysroot.

        Host :class:`Path` resolution is wrong for links such as
        ``/lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.23.so``:
        the absolute target belongs to the guest root, not the host root.
        """

        value = PurePosixPath(os.fspath(guest_path))
        parts = value.parts[1:] if value.is_absolute() else value.parts
        if not parts or ".." in parts:
            raise SysrootError(f"{self.spec.id}: unsafe guest path {os.fspath(guest_path)!r}")
        return _resolve_guest_path(self.sysroot, PurePosixPath(*parts).as_posix())

    def qemu_argv(
        self,
        executable: str | os.PathLike[str],
        *arguments: str,
    ) -> tuple[str, ...]:
        """Invoke the pinned loader and library directory under qemu-user.

        ``--inhibit-cache`` prevents the guest loader from consulting the host
        ``ld.so.cache`` and ``--library-path`` gives the provisioned libraries
        precedence.  Loader fallback paths are still not a chroot.  The live
        fixture separately uses ``samefile`` on the loader-reported libc path
        to prove that the exact provisioned libc was loaded.
        """

        qemu = shutil.which(self.qemu)
        if qemu is None:
            raise SysrootError(f"required qemu-user binary is unavailable: {self.qemu}")
        return (
            qemu,
            str(self.loader),
            "--inhibit-cache",
            "--library-path",
            str(self.libc.parent),
            str(Path(executable).resolve()),
            *arguments,
        )

    @property
    def compiler_argv(self) -> tuple[str, ...]:
        compiler = self.spec.compiler
        if compiler.kind == "bootlin":
            if self.bootlin_compiler is None:
                raise SysrootError(f"{self.spec.id}: Bootlin compiler was not discovered")
            return (str(self.bootlin_compiler),)
        if compiler.kind == "zig":
            zig = shutil.which("zig")
            if zig is None:
                raise SysrootError("Zig is required to compile this runtime fixture")
            if compiler.target is None:
                raise SysrootError(f"{self.spec.id}: Zig compiler target is missing")
            return (zig, "cc", "-target", compiler.target, "--sysroot", str(self.sysroot))
        if compiler.kind == "bundled-gcc":
            driver = _bundled_gcc_driver(self)
            bundled_bin = self.root / "usr/bin"
            host_libraries = self.root / "usr/lib/x86_64-linux-gnu"
            if not bundled_bin.is_dir() or not host_libraries.is_dir():
                raise SysrootError(f"{self.spec.id}: bundled GCC runtime directories are missing")
            arguments = tuple(
                argument.replace("{root}", str(self.root)).replace("{sysroot}", str(self.sysroot))
                for argument in compiler.argv
            )
            return (
                "/usr/bin/env",
                f"PATH={bundled_bin}",
                f"LD_LIBRARY_PATH={host_libraries}",
                str(driver),
                *arguments,
            )
        if compiler.kind == "system":
            if not compiler.argv:
                raise SysrootError(f"{self.spec.id}: system compiler argv is empty")
            executable = shutil.which(compiler.argv[0])
            if executable is None:
                raise SysrootError(f"required cross compiler is unavailable: {compiler.argv[0]}")
            arguments = tuple(
                argument.replace("{root}", str(self.root)).replace("{sysroot}", str(self.sysroot))
                for argument in compiler.argv[1:]
            )
            return (executable, *arguments, f"--sysroot={self.sysroot}")
        raise SysrootError(f"{self.spec.id}: unknown compiler kind {compiler.kind!r}")


_manifest_cache: dict[Path, SysrootManifest] = {}


def load_manifest(path: str | os.PathLike[str] | None = None) -> SysrootManifest:
    """Load and strictly validate the pinned sysroot manifest."""

    manifest_path = Path(path).resolve() if path is not None else _MANIFEST_PATH.resolve()
    cached = _manifest_cache.get(manifest_path)
    if cached is not None:
        return cached
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SysrootError(f"cannot load sysroot manifest {manifest_path}: {exc}") from exc
    manifest = _parse_manifest(raw)
    _manifest_cache[manifest_path] = manifest
    return manifest


def resolve_sysroot(target: Target | str, lane: str = DEFAULT_GLIBC_LANE) -> SysrootSpec:
    """Resolve one catalog target without downloading anything."""

    return load_manifest().resolve(target, lane)


def provision_sysroot(
    spec_or_target: SysrootSpec | Target | str,
    cache_dir: str | os.PathLike[str],
    *,
    lane: str = DEFAULT_GLIBC_LANE,
) -> ProvisionedSysroot:
    """Download, extract, relocate, and validate one exact libc root."""

    spec = spec_or_target if isinstance(spec_or_target, SysrootSpec) else resolve_sysroot(spec_or_target, lane)
    cache = Path(cache_dir).resolve()
    artifact_dir = cache / "artifacts"
    roots_dir = cache / "roots"
    locks_dir = cache / "locks"
    for directory in (artifact_dir, roots_dir, locks_dir):
        directory.mkdir(parents=True, exist_ok=True)

    final = roots_dir / f"{spec.id}-{spec.fingerprint}"
    lock_path = locks_dir / f"root-{spec.id}-{spec.fingerprint}.lock"
    with _exclusive_lock(lock_path):
        cached = _validated_cached_sysroot(final, spec)
        if cached is not None:
            return cached
        if final.exists():
            _remove_generated_tree(final, roots_dir)

        artifacts = tuple(_materialize_artifact(item, artifact_dir, locks_dir) for item in spec.artifacts)
        staging = Path(tempfile.mkdtemp(prefix=f".{spec.id}-", dir=roots_dir))
        try:
            _extract(spec, artifacts, staging)
            os.replace(staging, final)
            _relocate_bootlin_sdk(spec, final)
            provisioned = _paths_from_root(spec, final)
            validate_provisioned_sysroot(provisioned)
            _write_completion_marker(final, spec, provisioned)
            return provisioned
        except Exception:
            if staging.exists():
                _remove_generated_tree(staging, roots_dir)
            if final.exists():
                _remove_generated_tree(final, roots_dir)
            raise


def validate_provisioned_sysroot(provisioned: ProvisionedSysroot) -> None:
    """Reject the wrong libc, byte order, ELF class, machine, or PPC64 ABI."""

    spec = provisioned.spec
    libc = _resolve_guest_path(provisioned.sysroot, spec.libc)
    loader = _resolve_guest_path(provisioned.sysroot, spec.loader)
    for label, path in (("libc", libc), ("loader", loader)):
        if not path.is_file():
            raise SysrootError(f"{spec.id}: expected {label} does not exist: {path}")
        _validate_elf(path, spec.elf, f"{spec.id} {label}")
    if spec.version_marker.encode() not in libc.read_bytes():
        raise SysrootError(f"{spec.id}: libc does not contain version marker {spec.version_marker!r}")


def _parse_manifest(raw: Any) -> SysrootManifest:
    if not isinstance(raw, dict) or raw.get("schema_version") != 2:
        raise SysrootError("sysroot manifest schema_version must be 2")
    default_lane = _required_string(raw, "default_lane")
    bootlin = raw.get("bootlin_releases")
    packages = raw.get("packages")
    roots = raw.get("sysroots")
    unsupported_raw = raw.get("unsupported")
    if not isinstance(bootlin, dict) or not isinstance(packages, dict) or not isinstance(roots, list):
        raise SysrootError("manifest releases, packages, and sysroots have invalid types")
    if not isinstance(unsupported_raw, list):
        raise SysrootError("manifest unsupported records must be a list")

    package_specs: dict[str, ArtifactSpec] = {}
    for package_id, value in packages.items():
        if not isinstance(value, dict):
            raise SysrootError(f"package {package_id!r} is not an object")
        package_specs[package_id] = _artifact_from_raw(value, expected_kind="deb")

    specs: list[SysrootSpec] = []
    by_lane_target: dict[tuple[str, str], SysrootSpec] = {}
    ids: set[str] = set()
    for value in roots:
        if not isinstance(value, dict):
            raise SysrootError("sysroot entries must be objects")
        spec = _parse_sysroot(value, bootlin, package_specs)
        if spec.id in ids:
            raise SysrootError(f"duplicate sysroot id {spec.id!r}")
        ids.add(spec.id)
        for target_name in spec.targets:
            resolved = _resolve_catalog_target(target_name)
            if resolved.name != target_name:
                raise SysrootError(f"sysroot target is not canonical: {target_name!r}")
            key = (spec.lane, target_name)
            if key in by_lane_target:
                raise SysrootError(f"duplicate sysroot mapping for {spec.lane}/{target_name}")
            by_lane_target[key] = spec
        specs.append(spec)

    unsupported: dict[str, UnsupportedRecord] = {}
    for value in unsupported_raw:
        if not isinstance(value, dict):
            raise SysrootError("unsupported records must be objects")
        target_name = _required_string(value, "target")
        resolved = _resolve_catalog_target(target_name)
        if resolved.name != target_name:
            raise SysrootError(f"unsupported target is not canonical: {target_name!r}")
        if target_name in unsupported:
            raise SysrootError(f"duplicate unsupported target {target_name}")
        reason = _required_string(value, "reason")
        upstream = value.get("upstream_glibc")
        if not isinstance(upstream, bool):
            raise SysrootError(f"{target_name}: upstream_glibc must be boolean")
        unsupported[target_name] = UnsupportedRecord(target_name, reason, upstream)

    if default_lane not in {item.lane for item in specs}:
        raise SysrootError(f"default lane does not exist: {default_lane}")
    return SysrootManifest(
        schema_version=2,
        default_lane=default_lane,
        sysroots=tuple(specs),
        unsupported=MappingProxyType(unsupported),
        by_lane_target=MappingProxyType(by_lane_target),
    )


def _parse_sysroot(
    raw: dict[str, Any],
    bootlin: dict[str, Any],
    packages: dict[str, ArtifactSpec],
) -> SysrootSpec:
    spec_id = _required_string(raw, "id")
    lane = _required_string(raw, "lane")
    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw or not all(isinstance(item, str) for item in targets_raw):
        raise SysrootError(f"{spec_id}: targets must be a nonempty string list")

    source_raw = raw.get("source")
    if not isinstance(source_raw, dict):
        raise SysrootError(f"{spec_id}: source must be an object")
    source_kind = _required_string(source_raw, "kind")
    extraction_top: str | None = None
    if source_kind == "bootlin":
        release_id = _required_string(source_raw, "release")
        slug = _required_string(source_raw, "slug")
        release = bootlin.get(release_id)
        if not isinstance(release, dict):
            raise SysrootError(f"{spec_id}: unknown Bootlin release {release_id!r}")
        hashes = release.get("sha256")
        if not isinstance(hashes, dict) or not isinstance(hashes.get(slug), str):
            raise SysrootError(f"{spec_id}: no checksum for Bootlin slug {slug!r}")
        release_name = _required_string(release, "artifact_release")
        suffix = _required_string(release, "archive_suffix")
        archive_stem = f"{slug}--glibc--stable-{release_name}"
        archive_top_template = release.get("archive_top_template")
        if archive_top_template is None:
            extraction_top = archive_stem
        elif (
            not isinstance(archive_top_template, str)
            or archive_top_template.count("{slug}") != 1
            or "{" in archive_top_template.replace("{slug}", "")
            or "}" in archive_top_template.replace("{slug}", "")
        ):
            raise SysrootError(f"{spec_id}: invalid Bootlin archive_top_template")
        else:
            extraction_top = archive_top_template.replace("{slug}", slug)
        if len(PurePosixPath(extraction_top).parts) != 1 or extraction_top in {".", ".."}:
            raise SysrootError(f"{spec_id}: Bootlin archive top must be one safe path component")
        name = f"{archive_stem}{suffix}"
        url = f"https://toolchains.bootlin.com/downloads/releases/toolchains/{slug}/tarballs/{name}"
        artifacts = (ArtifactSpec(name, url, _validate_sha256(hashes[slug], spec_id), "tar"),)
        glibc_version = _required_string(release, "glibc_version")
        source = f"Bootlin Buildroot SDK {extraction_top}"
        extraction_kind = "bootlin-sdk"
    elif source_kind == "packages":
        package_ids = source_raw.get("packages")
        if (
            not isinstance(package_ids, list)
            or not package_ids
            or not all(isinstance(item, str) for item in package_ids)
        ):
            raise SysrootError(f"{spec_id}: package source needs package ids")
        try:
            artifacts = tuple(packages[item] for item in package_ids)
        except KeyError as exc:
            raise SysrootError(f"{spec_id}: unknown package artifact {exc.args[0]!r}") from exc
        glibc_version = _required_string(raw, "glibc_version")
        source = _required_string(source_raw, "description")
        extraction_kind = "debs"
    else:
        raise SysrootError(f"{spec_id}: unknown source kind {source_kind!r}")

    compiler_raw = raw.get("compiler")
    if not isinstance(compiler_raw, dict):
        raise SysrootError(f"{spec_id}: compiler must be an object")
    compiler_kind = _required_string(compiler_raw, "kind")
    target = compiler_raw.get("target")
    if target is not None and not isinstance(target, str):
        raise SysrootError(f"{spec_id}: compiler target must be a string")
    argv_raw = compiler_raw.get("argv", [])
    if not isinstance(argv_raw, list) or not all(isinstance(item, str) for item in argv_raw):
        raise SysrootError(f"{spec_id}: compiler argv must be a string list")
    for argument in argv_raw:
        remainder = argument.replace("{root}", "").replace("{sysroot}", "")
        if "{" in remainder or "}" in remainder:
            raise SysrootError(f"{spec_id}: unsupported compiler argv template {argument!r}")
    driver_raw = compiler_raw.get("driver")
    if compiler_kind == "bundled-gcc":
        if not isinstance(driver_raw, str) or not driver_raw:
            raise SysrootError(f"{spec_id}: bundled-gcc compiler needs a driver path")
        driver = _normalize_guest_path(driver_raw, f"{spec_id} compiler driver")
    elif driver_raw is not None:
        raise SysrootError(f"{spec_id}: compiler driver is only valid for bundled-gcc")
    else:
        driver = None

    elf_raw = raw.get("elf")
    if not isinstance(elf_raw, dict):
        raise SysrootError(f"{spec_id}: elf identity must be an object")
    elf_class = elf_raw.get("class")
    endian = elf_raw.get("endian")
    machine = elf_raw.get("machine")
    if elf_class not in {32, 64} or endian not in {"little", "big"} or not isinstance(machine, int):
        raise SysrootError(f"{spec_id}: invalid ELF identity")
    flags_mask = elf_raw.get("flags_mask", 0)
    flags_value = elf_raw.get("flags_value", 0)
    if not isinstance(flags_mask, int) or not isinstance(flags_value, int) or flags_value & ~flags_mask:
        raise SysrootError(f"{spec_id}: invalid ELF flag constraint")

    sysroot_subdir = raw.get("sysroot_subdir")
    if sysroot_subdir is not None and not isinstance(sysroot_subdir, str):
        raise SysrootError(f"{spec_id}: sysroot_subdir must be a string")
    loader = _normalize_guest_path(_required_string(raw, "loader"), spec_id)
    interpreter_raw = raw.get("interpreter")
    if interpreter_raw is not None and (not isinstance(interpreter_raw, str) or not interpreter_raw):
        raise SysrootError(f"{spec_id}: interpreter must be a nonempty string when specified")
    return SysrootSpec(
        id=spec_id,
        lane=lane,
        glibc_version=glibc_version,
        targets=tuple(targets_raw),
        source=source,
        artifacts=artifacts,
        extraction_kind=extraction_kind,
        extraction_top=extraction_top,
        sysroot_subdir=sysroot_subdir,
        compiler=CompilerSpec(compiler_kind, target, tuple(argv_raw), driver),
        qemu=_required_string(raw, "qemu"),
        interpreter=_normalize_guest_path(interpreter_raw, spec_id) if interpreter_raw is not None else None,
        loader=loader,
        libc=_normalize_guest_path(_required_string(raw, "libc"), spec_id),
        elf=ElfIdentity(elf_class, endian, machine, flags_mask, flags_value),
        version_marker=_required_string(raw, "version_marker"),
    )


def _artifact_from_raw(raw: dict[str, Any], *, expected_kind: str) -> ArtifactSpec:
    name = _required_string(raw, "name")
    url = _required_string(raw, "url")
    sha256 = _validate_sha256(_required_string(raw, "sha256"), name)
    if not url.startswith("https://"):
        raise SysrootError(f"artifact URL is not HTTPS: {url}")
    return ArtifactSpec(name=name, url=url, sha256=sha256, kind=expected_kind)


def _validate_sha256(value: str, label: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise SysrootError(f"{label}: invalid SHA-256 digest")
    return value


def _required_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise SysrootError(f"manifest field {key!r} must be a nonempty string")
    return value


def _normalize_guest_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value in {"", "."}:
        raise SysrootError(f"{label}: unsafe guest path {value!r}")
    return path.as_posix()


class _exclusive_lock:
    def __init__(self, path: Path):
        self.path = path
        self._file: Any = None

    def __enter__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a+")
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._file is not None:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            self._file.close()


def _materialize_artifact(spec: ArtifactSpec, artifact_dir: Path, locks_dir: Path) -> Path:
    destination = artifact_dir / f"{spec.sha256}{spec.cache_suffix}"
    with _exclusive_lock(locks_dir / f"artifact-{spec.sha256}.lock"):
        if destination.is_file() and _sha256_file(destination) == spec.sha256:
            return destination
        request = urllib.request.Request(spec.url, headers={"User-Agent": "pwnc-runtime-tests/1"})
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{spec.sha256}-", dir=artifact_dir)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            digest = hashlib.sha256()
            with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
                while chunk := response.read(_BUFFER_SIZE):
                    output.write(chunk)
                    digest.update(chunk)
            if digest.hexdigest() != spec.sha256:
                raise SysrootError(f"checksum mismatch for {spec.name}")
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
    return destination


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_BUFFER_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(spec: SysrootSpec, artifacts: Sequence[Path], staging: Path) -> None:
    if spec.extraction_kind == "bootlin-sdk":
        if len(artifacts) != 1:
            raise SysrootError(f"{spec.id}: Bootlin SDK needs exactly one archive")
        with tarfile.open(artifacts[0], mode="r:*") as archive:
            _safe_extract_tar(archive, staging)
        if spec.extraction_top is None or not (staging / spec.extraction_top).is_dir():
            raise SysrootError(f"{spec.id}: archive top-level directory is wrong")
        return
    if spec.extraction_kind == "debs":
        dpkg_deb = shutil.which("dpkg-deb")
        if dpkg_deb is None:
            raise SysrootError("dpkg-deb is required to extract Ubuntu sysroot packages")
        for artifact in artifacts:
            try:
                subprocess.run(
                    [dpkg_deb, "-x", str(artifact), str(staging)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as exc:
                raise SysrootError(f"{spec.id}: cannot extract {artifact.name}: {exc.stderr.strip()}") from exc
        return
    raise SysrootError(f"{spec.id}: unknown extraction kind {spec.extraction_kind!r}")


def _relocate_bootlin_sdk(spec: SysrootSpec, final: Path) -> None:
    if spec.extraction_kind != "bootlin-sdk":
        return
    if spec.extraction_top is None:
        raise SysrootError(f"{spec.id}: missing Bootlin top-level directory")
    script = final / spec.extraction_top / "relocate-sdk.sh"
    if not script.exists():
        return
    try:
        subprocess.run(["/bin/sh", str(script)], cwd=script.parent, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        raise SysrootError(f"{spec.id}: SDK relocation failed: {exc.stderr.strip()}") from exc


def _safe_extract_tar(archive: tarfile.TarFile, destination: Path) -> None:
    """Use the stdlib data filter, with an equivalent Python 3.11 fallback."""

    data_filter = getattr(tarfile, "data_filter", None)
    if data_filter is not None:
        archive.extractall(destination, filter="data")
        return
    members = archive.getmembers()
    for member in members:
        member_path = PurePosixPath(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise SysrootError(f"unsafe archive member path: {member.name!r}")
        if member.ischr() or member.isblk() or member.isfifo():
            raise SysrootError(f"special archive member is forbidden: {member.name!r}")
        if member.issym() or member.islnk():
            link = PurePosixPath(member.linkname)
            # Symbolic link targets are relative to the link's parent.  POSIX
            # tar hard-link targets are relative to the archive root.
            combined = member_path.parent / link if member.issym() else link
            if link.is_absolute() or not _posix_path_stays_beneath_root(combined):
                raise SysrootError(f"unsafe archive link: {member.name!r} -> {member.linkname!r}")

    # A lexical pass is insufficient: an earlier member can create a symlink
    # which changes the effective parent of a later member.  Resolve every
    # destination and link target immediately before extraction so the 3.11
    # fallback cannot write through an archive-created symlink outside root.
    destination.mkdir(parents=True, exist_ok=True)
    extraction_root = destination.resolve()
    extract_filter = {"filter": "fully_trusted"} if "filter" in inspect.signature(archive.extract).parameters else {}
    for member in members:
        member_path = PurePosixPath(member.name)
        target = destination.joinpath(*member_path.parts)
        _require_path_beneath_root(target, extraction_root, member.name)
        if member.issym():
            link_target = target.parent.resolve(strict=False) / member.linkname
            _require_path_beneath_root(link_target, extraction_root, member.name)
        elif member.islnk():
            link_target = destination.joinpath(*PurePosixPath(member.linkname).parts)
            _require_path_beneath_root(link_target, extraction_root, member.name)
        archive.extract(member, destination, **extract_filter)


def _require_path_beneath_root(path: Path, root: Path, member_name: str) -> None:
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SysrootError(f"cannot safely resolve archive member {member_name!r}: {exc}") from exc
    if not _is_relative_to(resolved, root):
        raise SysrootError(f"archive member resolves outside destination: {member_name!r}")


def _paths_from_root(spec: SysrootSpec, final: Path) -> ProvisionedSysroot:
    compiler: Path | None = None
    if spec.extraction_kind == "bootlin-sdk":
        if spec.extraction_top is None:
            raise SysrootError(f"{spec.id}: missing Bootlin top-level directory")
        root = final / spec.extraction_top
        compiler = _find_bootlin_compiler(root)
        try:
            result = subprocess.run(
                [str(compiler), "-print-sysroot"],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise SysrootError(f"{spec.id}: compiler cannot report its sysroot: {exc.stderr.strip()}") from exc
        sysroot = Path(result.stdout.strip()).resolve()
        if not _is_relative_to(sysroot, root.resolve()):
            raise SysrootError(f"{spec.id}: compiler sysroot escapes its SDK: {sysroot}")
    else:
        root = final
        if spec.sysroot_subdir is None:
            raise SysrootError(f"{spec.id}: package sysroot_subdir is missing")
        sysroot = (final / spec.sysroot_subdir).resolve()
        if not _is_relative_to(sysroot, final.resolve()):
            raise SysrootError(f"{spec.id}: package sysroot escapes its extraction root")
    provisioned = ProvisionedSysroot(
        spec=spec,
        root=root,
        sysroot=sysroot,
        libc=_resolve_guest_path(sysroot, spec.libc),
        loader=_resolve_guest_path(sysroot, spec.loader),
        bootlin_compiler=compiler,
    )
    if spec.compiler.kind == "bundled-gcc":
        _bundled_gcc_driver(provisioned)
    return provisioned


def _bundled_gcc_driver(provisioned: ProvisionedSysroot) -> Path:
    driver_path = provisioned.spec.compiler.driver
    if driver_path is None:  # pragma: no cover - manifest parser invariant
        raise SysrootError(f"{provisioned.spec.id}: bundled GCC driver is unspecified")
    candidate = provisioned.root.joinpath(*PurePosixPath(driver_path).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SysrootError(f"{provisioned.spec.id}: bundled GCC driver is missing: {candidate}") from exc
    if not _is_relative_to(resolved, provisioned.root.resolve()):
        raise SysrootError(f"{provisioned.spec.id}: bundled GCC driver escapes its extraction root")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SysrootError(f"{provisioned.spec.id}: bundled GCC driver is not executable: {candidate}")
    # Preserve the installed path rather than its resolved target.  Like the
    # Bootlin wrapper, GCC derives its relocatable prefix from argv[0].
    return candidate.absolute()


def _find_bootlin_compiler(root: Path) -> Path:
    aliases = sorted(root.glob("bin/*-linux-gcc"), key=lambda item: (len(item.name), item.name))
    if aliases:
        # The Buildroot wrapper selects ``<argv[0]>.br_real``.  Resolving its
        # public symlink changes argv[0] and therefore breaks that lookup.
        return aliases[0].absolute()
    compilers = sorted(root.glob("bin/*-gcc"), key=lambda item: (len(item.name), item.name))
    if not compilers:
        raise SysrootError(f"no GCC driver found in Bootlin SDK {root}")
    return compilers[0].absolute()


def _resolve_guest_path(sysroot: Path, guest_path: str) -> Path:
    current = sysroot.resolve()
    parts = list(PurePosixPath(guest_path).parts)
    traversals = 0
    while parts:
        part = parts.pop(0)
        candidate = current / part
        if candidate.is_symlink():
            traversals += 1
            if traversals > 40:
                raise SysrootError(f"too many symlinks while resolving {guest_path}")
            target = PurePosixPath(os.readlink(candidate))
            if target.is_absolute():
                current = sysroot.resolve()
                parts = [*target.parts[1:], *parts]
            else:
                parts = [*target.parts, *parts]
            continue
        if part == "..":
            current = current.parent
        elif part != ".":
            current = candidate
        if not _is_relative_to(current.resolve(strict=False), sysroot.resolve()):
            raise SysrootError(f"guest path escapes sysroot: {guest_path}")
    return current


def _validate_elf(path: Path, expected: ElfIdentity, label: str) -> None:
    header = path.read_bytes()[:64]
    if len(header) < 52 or header[:4] != b"\x7fELF":
        raise SysrootError(f"{label}: not an ELF file")
    elf_class = {1: 32, 2: 64}.get(header[4])
    endian = {1: "little", 2: "big"}.get(header[5])
    if elf_class != expected.elf_class or endian != expected.endian:
        raise SysrootError(f"{label}: expected ELF{expected.elf_class} {expected.endian}, got ELF{elf_class} {endian}")
    order = "<" if endian == "little" else ">"
    machine = struct.unpack_from(f"{order}H", header, 18)[0]
    flags_offset = 36 if elf_class == 32 else 48
    flags = struct.unpack_from(f"{order}I", header, flags_offset)[0]
    if machine != expected.machine:
        raise SysrootError(f"{label}: expected e_machine {expected.machine}, got {machine}")
    if flags & expected.flags_mask != expected.flags_value:
        raise SysrootError(
            f"{label}: e_flags {flags:#x} does not match mask {expected.flags_mask:#x}/value {expected.flags_value:#x}"
        )


def _validated_cached_sysroot(final: Path, spec: SysrootSpec) -> ProvisionedSysroot | None:
    marker = final / ".complete.json"
    if not marker.is_file():
        return None
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    expected_artifacts = [artifact.sha256 for artifact in spec.artifacts]
    if (
        value.get("schema_version") != 1
        or value.get("id") != spec.id
        or value.get("fingerprint") != spec.fingerprint
        or value.get("artifacts") != expected_artifacts
    ):
        return None
    try:
        provisioned = _paths_from_root(spec, final)
        validate_provisioned_sysroot(provisioned)
        actual_files = _provisioned_file_integrity(final, provisioned)
    except (OSError, SysrootError):
        return None
    return provisioned if value.get("files") == actual_files else None


def _write_completion_marker(final: Path, spec: SysrootSpec, provisioned: ProvisionedSysroot) -> None:
    marker = {
        "schema_version": 1,
        "id": spec.id,
        "fingerprint": spec.fingerprint,
        "artifacts": [artifact.sha256 for artifact in spec.artifacts],
        "files": _provisioned_file_integrity(final, provisioned),
    }
    (final / ".complete.json").write_text(
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _provisioned_file_integrity(final: Path, provisioned: ProvisionedSysroot) -> dict[str, dict[str, str | None]]:
    root = final.resolve()
    records: dict[str, dict[str, str | None]] = {}
    paths = [("libc", provisioned.libc), ("loader", provisioned.loader)]
    if provisioned.spec.compiler.kind == "bundled-gcc":
        paths.append(("compiler", _bundled_gcc_driver(provisioned)))
    for label, path in paths:
        resolved = path.resolve(strict=True)
        if not _is_relative_to(resolved, root):
            raise SysrootError(f"{provisioned.spec.id}: cached {label} escapes its extraction root")
        data = resolved.read_bytes()
        records[label] = {
            "path": resolved.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "build_id": _elf_build_id(data),
        }
    return records


def _elf_build_id(data: bytes) -> str | None:
    """Read a unique GNU build ID from ELF PT_NOTE records, if present."""

    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    elf_class = data[4]
    byte_order = {1: "<", 2: ">"}.get(data[5])
    if byte_order is None:
        return None
    try:
        if elf_class == 1:
            program_offset = struct.unpack_from(f"{byte_order}I", data, 28)[0]
            entry_size = struct.unpack_from(f"{byte_order}H", data, 42)[0]
            entry_count = struct.unpack_from(f"{byte_order}H", data, 44)[0]
            minimum_size = 20
            offset_field, size_field, word_format = 4, 16, "I"
        elif elf_class == 2 and len(data) >= 64:
            program_offset = struct.unpack_from(f"{byte_order}Q", data, 32)[0]
            entry_size = struct.unpack_from(f"{byte_order}H", data, 54)[0]
            entry_count = struct.unpack_from(f"{byte_order}H", data, 56)[0]
            minimum_size = 40
            offset_field, size_field, word_format = 8, 32, "Q"
        else:
            return None
        if entry_size < minimum_size or program_offset + entry_size * entry_count > len(data):
            return None

        candidates: set[str] = set()
        for index in range(entry_count):
            entry = program_offset + index * entry_size
            if struct.unpack_from(f"{byte_order}I", data, entry)[0] != 4:  # PT_NOTE
                continue
            note_offset = struct.unpack_from(f"{byte_order}{word_format}", data, entry + offset_field)[0]
            note_size = struct.unpack_from(f"{byte_order}{word_format}", data, entry + size_field)[0]
            note_end = note_offset + note_size
            if note_end > len(data):
                return None
            cursor = note_offset
            while cursor + 12 <= note_end:
                name_size, description_size, note_type = struct.unpack_from(f"{byte_order}III", data, cursor)
                cursor += 12
                name_end = cursor + name_size
                description_start = (name_end + 3) & ~3
                description_end = description_start + description_size
                next_note = (description_end + 3) & ~3
                if name_end > note_end or description_end > note_end or next_note > note_end:
                    return None
                name = data[cursor:name_end].rstrip(b"\0")
                if note_type == 3 and name == b"GNU":  # NT_GNU_BUILD_ID
                    candidates.add(data[description_start:description_end].hex())
                cursor = next_note
        return next(iter(candidates)) if len(candidates) == 1 else None
    except (OverflowError, struct.error):
        return None


def _remove_generated_tree(path: Path, expected_parent: Path) -> None:
    resolved_parent = expected_parent.resolve()
    if path.parent.resolve() != resolved_parent or not path.name:
        raise SysrootError(f"refusing to remove path outside sysroot cache: {path}")
    shutil.rmtree(path)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _posix_path_stays_beneath_root(path: PurePosixPath) -> bool:
    depth = 0
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if depth == 0:
                return False
            depth -= 1
        else:
            depth += 1
    return True


def _resolve_catalog_target(target: Target | str) -> Target:
    if isinstance(target, Target):
        return target
    canonical = _TARGETS_BY_NAME.get(target)
    return canonical if canonical is not None else resolve_target(target)
