"""Immutable LiveCTF source and release-handout fixtures.

Normal tests only parse the checked-in manifest and exercise extraction with
synthetic archives.  Network access is explicit through :func:`provision_all`
and is enabled by the test suite only when ``PWNC_LIVECTF_TESTS=1``.

Downloaded archives are content-addressed by SHA-256.  Extraction accepts only
regular files, directories, and in-tree relative symlinks; handouts extract
only their attested ELF files.  Mutable Docker rebuild observations are kept in
the manifest model but deliberately have no provisioning API.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import posixpath
import re
import shutil
import tarfile
import tempfile
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, BinaryIO, Self
from urllib.parse import urlsplit

_MANIFEST_PATH = Path(__file__).with_name("livectf_artifacts.json")
_BUFFER_SIZE = 1024 * 1024
_HEX = frozenset("0123456789abcdef")
_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_OFFSET_RE = re.compile(r"0x[0-9a-f]+\Z")
_MARKER = ".pwnc-livectf.json"


class LiveCTFArtifactError(RuntimeError):
    """A manifest, download, extraction, or identity check failed."""


@dataclass(frozen=True, slots=True)
class ArchiveIdentity:
    name: str
    url: str
    size: int
    sha256: str

    @property
    def cache_suffix(self) -> str:
        if self.name.endswith(".tar.gz"):
            return ".tar.gz"
        if self.name.endswith(".tar.xz"):
            return ".tar.xz"
        return Path(self.name).suffix


@dataclass(frozen=True, slots=True)
class MemberIdentity:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ElfIdentity(MemberIdentity):
    elf_build_id: str


@dataclass(frozen=True, slots=True)
class LicenseIdentity(MemberIdentity):
    spdx: str


@dataclass(frozen=True, slots=True)
class Provenance:
    license_name: str
    spdx: str
    license_url: str


@dataclass(frozen=True, slots=True)
class SourceSpec:
    id: str
    event: str
    repository: str
    commit: str
    archive_root: str
    archive: ArchiveIdentity
    license: LicenseIdentity
    critical_members: tuple[MemberIdentity, ...]

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "id": self.id,
                "commit": self.commit,
                "archive": self.archive.sha256,
                "license": self.license.sha256,
                "critical_members": [(item.path, item.sha256) for item in self.critical_members],
            }
        )


@dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    tag: str
    name: str


@dataclass(frozen=True, slots=True)
class NestedArchiveIdentity(MemberIdentity):
    pass


@dataclass(frozen=True, slots=True)
class HandoutSpec:
    id: str
    source_id: str
    release: ReleaseIdentity
    outer_archive: ArchiveIdentity
    nested_archive: NestedArchiveIdentity | None
    files: tuple[ElfIdentity, ...]

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            {
                "id": self.id,
                "source_id": self.source_id,
                "release": self.release.tag,
                "outer_archive": self.outer_archive.sha256,
                "nested_archive": None if self.nested_archive is None else self.nested_archive.sha256,
                "files": [(item.path, item.sha256, item.elf_build_id) for item in self.files],
            }
        )


@dataclass(frozen=True, slots=True)
class BaseImageObservation:
    reference: str
    resolved_digest: str
    config_digest: str
    created: str
    os: str
    architecture: str


@dataclass(frozen=True, slots=True)
class BootstrapObservation:
    executions: int
    invalid_address: int
    result_classification: str
    stable_offset: str
    immutable_contract: bool


@dataclass(frozen=True, slots=True)
class MutableBuildObservation:
    id: str
    source_id: str
    observed_at: str
    reproducible: bool
    reason: str
    base_image: BaseImageObservation
    files: tuple[ElfIdentity, ...]
    bootstrap_observation: BootstrapObservation


@dataclass(frozen=True, slots=True)
class LiveCTFManifest:
    schema_version: int
    provenance: Provenance
    sources: tuple[SourceSpec, ...]
    handouts: tuple[HandoutSpec, ...]
    observations: tuple[MutableBuildObservation, ...]
    sources_by_id: Mapping[str, SourceSpec]
    handouts_by_id: Mapping[str, HandoutSpec]


@dataclass(frozen=True, slots=True)
class ProvisionedSource:
    spec: SourceSpec
    root: Path


@dataclass(frozen=True, slots=True)
class ProvisionedHandout:
    spec: HandoutSpec
    root: Path
    files: Mapping[str, Path]


@dataclass(frozen=True, slots=True)
class ProvisionedLiveCTF:
    sources: Mapping[str, ProvisionedSource]
    handouts: Mapping[str, ProvisionedHandout]


def load_manifest(path: str | os.PathLike[str] | None = None) -> LiveCTFManifest:
    """Read and strictly validate the immutable LiveCTF catalog without I/O beyond the JSON file."""

    manifest_path = Path(path).resolve() if path is not None else _MANIFEST_PATH.resolve()
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveCTFArtifactError(f"cannot load LiveCTF manifest {manifest_path}: {exc}") from exc
    return _parse_manifest(raw)


def provision_all(
    cache_dir: str | os.PathLike[str],
    *,
    manifest: LiveCTFManifest | None = None,
) -> ProvisionedLiveCTF:
    """Download, safely extract, and validate every immutable source and handout fixture."""

    selected = manifest or load_manifest()
    sources = {spec.id: provision_source(spec, cache_dir) for spec in selected.sources}
    handouts = {spec.id: provision_handout(spec, cache_dir) for spec in selected.handouts}
    return ProvisionedLiveCTF(MappingProxyType(sources), MappingProxyType(handouts))


def provision_source(spec: SourceSpec, cache_dir: str | os.PathLike[str]) -> ProvisionedSource:
    """Provision one commit-pinned source archive into a content-derived root."""

    cache, artifacts, roots, locks = _cache_directories(cache_dir)
    del cache
    archive = _materialize_archive(spec.archive, artifacts, locks)
    final = roots / f"source-{spec.id}-{spec.fingerprint}"
    with _FileLock(locks / f"root-source-{spec.fingerprint}.lock"):
        existing = ProvisionedSource(spec, final)
        if final.exists():
            try:
                validate_provisioned_source(existing)
                return existing
            except LiveCTFArtifactError:
                _remove_generated_root(final, roots)

        staging = Path(tempfile.mkdtemp(prefix=f".{final.name}-", dir=roots))
        try:
            with tarfile.open(archive, mode="r:*") as source_tar:
                _safe_extract_source(source_tar, staging, spec.archive_root)
            provisioned = ProvisionedSource(spec, staging)
            _write_marker(staging, "source", spec.id, spec.fingerprint)
            validate_provisioned_source(provisioned)
            os.replace(staging, final)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    return ProvisionedSource(spec, final)


def provision_handout(spec: HandoutSpec, cache_dir: str | os.PathLike[str]) -> ProvisionedHandout:
    """Provision one exact release handout, extracting only its attested ELF files."""

    cache, artifacts, roots, locks = _cache_directories(cache_dir)
    del cache
    outer = _materialize_archive(spec.outer_archive, artifacts, locks)
    archive = outer
    if spec.nested_archive is not None:
        archive = _materialize_nested_archive(outer, spec.nested_archive, artifacts, locks)

    final = roots / f"handout-{spec.id}-{spec.fingerprint}"
    with _FileLock(locks / f"root-handout-{spec.fingerprint}.lock"):
        existing = _provisioned_handout(spec, final)
        if final.exists():
            try:
                validate_provisioned_handout(existing)
                return existing
            except LiveCTFArtifactError:
                _remove_generated_root(final, roots)

        staging = Path(tempfile.mkdtemp(prefix=f".{final.name}-", dir=roots))
        try:
            with tarfile.open(archive, mode="r:*") as handout_tar:
                _safe_extract_selected(handout_tar, staging, tuple(item.path for item in spec.files))
            provisioned = _provisioned_handout(spec, staging)
            _write_marker(staging, "handout", spec.id, spec.fingerprint)
            validate_provisioned_handout(provisioned)
            os.replace(staging, final)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    return _provisioned_handout(spec, final)


def validate_provisioned_source(provisioned: ProvisionedSource) -> None:
    """Verify the completion marker, license, and challenge-critical source members."""

    _validate_marker(provisioned.root, "source", provisioned.spec.id, provisioned.spec.fingerprint)
    _validate_member(provisioned.root, provisioned.spec.license)
    for identity in provisioned.spec.critical_members:
        _validate_member(provisioned.root, identity)


def validate_provisioned_handout(provisioned: ProvisionedHandout) -> None:
    """Verify exact file digests and GNU build IDs without executing any artifact."""

    from payloads.elf import ELFInspectionError, inspect_elf

    _validate_marker(provisioned.root, "handout", provisioned.spec.id, provisioned.spec.fingerprint)
    for identity in provisioned.spec.files:
        path = provisioned.files[identity.path]
        _validate_file(path, identity.size, identity.sha256, identity.path)
        try:
            profile = inspect_elf(path)
        except (ELFInspectionError, OSError) as exc:
            raise LiveCTFArtifactError(f"{provisioned.spec.id}: cannot inspect {identity.path}: {exc}") from exc
        if profile.build_id != identity.elf_build_id:
            raise LiveCTFArtifactError(
                f"{provisioned.spec.id}: {identity.path} build ID {profile.build_id!r} "
                f"does not match {identity.elf_build_id!r}"
            )


def _parse_manifest(raw: Any) -> LiveCTFManifest:
    data = _mapping(raw, "manifest")
    _keys(data, {"schema_version", "provenance", "sources", "handouts", "observations"}, "manifest")
    schema_version = _integer(data["schema_version"], "manifest.schema_version", minimum=1)
    if schema_version != 1:
        raise LiveCTFArtifactError(f"unsupported LiveCTF manifest schema {schema_version}")

    provenance = _parse_provenance(data["provenance"])
    source_values = _sequence(data["sources"], "manifest.sources")
    handout_values = _sequence(data["handouts"], "manifest.handouts")
    observation_values = _sequence(data["observations"], "manifest.observations")
    sources = tuple(_parse_source(value, provenance) for value in source_values)
    source_map = _unique_map(sources, "source")
    handouts = tuple(_parse_handout(value, source_map) for value in handout_values)
    handout_map = _unique_map(handouts, "handout")
    observations = tuple(_parse_observation(value, source_map) for value in observation_values)
    _unique_map(observations, "observation")

    all_ids = [item.id for item in (*sources, *handouts, *observations)]
    if len(set(all_ids)) != len(all_ids):
        raise LiveCTFArtifactError("source, handout, and observation IDs must be globally unique")
    if len(sources) != 4:
        raise LiveCTFArtifactError("schema 1 requires exactly the four DEF CON 30-33 source snapshots")
    return LiveCTFManifest(
        schema_version,
        provenance,
        sources,
        handouts,
        observations,
        MappingProxyType(source_map),
        MappingProxyType(handout_map),
    )


def _parse_provenance(raw: Any) -> Provenance:
    data = _mapping(raw, "manifest.provenance")
    _keys(data, {"license_name", "spdx", "license_url"}, "manifest.provenance")
    license_name = _string(data["license_name"], "manifest.provenance.license_name")
    spdx = _string(data["spdx"], "manifest.provenance.spdx")
    license_url = _https(data["license_url"], "manifest.provenance.license_url")
    if spdx != "Apache-2.0" or license_name != "Apache License 2.0":
        raise LiveCTFArtifactError("LiveCTF fixture provenance must remain Apache-2.0")
    return Provenance(license_name, spdx, license_url)


def _parse_source(raw: Any, provenance: Provenance) -> SourceSpec:
    data = _mapping(raw, "source")
    _keys(
        data,
        {"id", "event", "repository", "commit", "archive_root", "archive", "license", "critical_members"},
        "source",
    )
    source_id = _identifier(data["id"], "source.id")
    event = _string(data["event"], f"source {source_id}.event")
    repository = _https(data["repository"], f"source {source_id}.repository")
    commit = _string(data["commit"], f"source {source_id}.commit")
    if _COMMIT_RE.fullmatch(commit) is None:
        raise LiveCTFArtifactError(f"source {source_id}.commit must be a lowercase 40-digit Git object ID")
    archive_root = _safe_path(data["archive_root"], f"source {source_id}.archive_root", single=True)
    archive = _parse_archive(data["archive"], f"source {source_id}.archive")
    if urlsplit(archive.url).path.rstrip("/").rsplit("/", 1)[-1] != commit:
        raise LiveCTFArtifactError(f"source {source_id} archive URL does not end in its pinned commit")
    if commit not in archive.name or commit not in archive_root:
        raise LiveCTFArtifactError(f"source {source_id} archive name/root do not encode its pinned commit")
    license_identity = _parse_license(data["license"], f"source {source_id}.license")
    if license_identity.spdx != provenance.spdx:
        raise LiveCTFArtifactError(f"source {source_id} license does not match catalog provenance")
    critical = tuple(
        _parse_member(value, f"source {source_id}.critical_members[{index}]")
        for index, value in enumerate(_sequence(data["critical_members"], f"source {source_id}.critical_members"))
    )
    if not critical:
        raise LiveCTFArtifactError(f"source {source_id} must attest at least one critical member")
    _unique_paths((license_identity, *critical), f"source {source_id}")
    return SourceSpec(source_id, event, repository, commit, archive_root, archive, license_identity, critical)


def _parse_handout(raw: Any, sources: Mapping[str, SourceSpec]) -> HandoutSpec:
    data = _mapping(raw, "handout")
    _keys(data, {"id", "source_id", "release", "outer_archive", "nested_archive", "files"}, "handout")
    handout_id = _identifier(data["id"], "handout.id")
    source_id = _identifier(data["source_id"], f"handout {handout_id}.source_id")
    if source_id not in sources:
        raise LiveCTFArtifactError(f"handout {handout_id} refers to unknown source {source_id!r}")
    release_data = _mapping(data["release"], f"handout {handout_id}.release")
    _keys(release_data, {"tag", "name"}, f"handout {handout_id}.release")
    release = ReleaseIdentity(
        _string(release_data["tag"], f"handout {handout_id}.release.tag"),
        _string(release_data["name"], f"handout {handout_id}.release.name"),
    )
    outer = _parse_archive(data["outer_archive"], f"handout {handout_id}.outer_archive")
    if f"/download/{release.tag}/" not in urlsplit(outer.url).path:
        raise LiveCTFArtifactError(f"handout {handout_id} release URL does not encode tag {release.tag!r}")
    nested = None
    if data["nested_archive"] is not None:
        member = _parse_member(data["nested_archive"], f"handout {handout_id}.nested_archive")
        nested = NestedArchiveIdentity(member.path, member.size, member.sha256)
    files = tuple(
        _parse_elf(value, f"handout {handout_id}.files[{index}]")
        for index, value in enumerate(_sequence(data["files"], f"handout {handout_id}.files"))
    )
    if not files:
        raise LiveCTFArtifactError(f"handout {handout_id} must attest at least one ELF")
    _unique_paths(files, f"handout {handout_id}")
    return HandoutSpec(handout_id, source_id, release, outer, nested, files)


def _parse_observation(raw: Any, sources: Mapping[str, SourceSpec]) -> MutableBuildObservation:
    data = _mapping(raw, "observation")
    _keys(
        data,
        {
            "id",
            "source_id",
            "observed_at",
            "reproducible",
            "reason",
            "base_image",
            "files",
            "bootstrap_observation",
        },
        "observation",
    )
    observation_id = _identifier(data["id"], "observation.id")
    source_id = _identifier(data["source_id"], f"observation {observation_id}.source_id")
    if source_id not in sources:
        raise LiveCTFArtifactError(f"observation {observation_id} refers to unknown source {source_id!r}")
    observed_at = _string(data["observed_at"], f"observation {observation_id}.observed_at")
    try:
        date.fromisoformat(observed_at)
    except ValueError as exc:
        raise LiveCTFArtifactError(f"observation {observation_id}.observed_at must be an ISO date") from exc
    if data["reproducible"] is not False:
        raise LiveCTFArtifactError(f"observation {observation_id} is mutable and must never be marked reproducible")
    reason = _string(data["reason"], f"observation {observation_id}.reason")

    base_data = _mapping(data["base_image"], f"observation {observation_id}.base_image")
    _keys(
        base_data,
        {"reference", "resolved_digest", "config_digest", "created", "os", "architecture"},
        f"observation {observation_id}.base_image",
    )
    resolved_digest = _string(base_data["resolved_digest"], f"observation {observation_id}.resolved_digest")
    config_digest = _string(base_data["config_digest"], f"observation {observation_id}.config_digest")
    if _IMAGE_DIGEST_RE.fullmatch(resolved_digest) is None or _IMAGE_DIGEST_RE.fullmatch(config_digest) is None:
        raise LiveCTFArtifactError(f"observation {observation_id} contains an invalid container digest")
    base = BaseImageObservation(
        _string(base_data["reference"], f"observation {observation_id}.reference"),
        resolved_digest,
        config_digest,
        _string(base_data["created"], f"observation {observation_id}.created"),
        _string(base_data["os"], f"observation {observation_id}.os"),
        _string(base_data["architecture"], f"observation {observation_id}.architecture"),
    )

    files = tuple(
        _parse_elf(value, f"observation {observation_id}.files[{index}]")
        for index, value in enumerate(_sequence(data["files"], f"observation {observation_id}.files"))
    )
    _unique_paths(files, f"observation {observation_id}")
    bootstrap_data = _mapping(data["bootstrap_observation"], f"observation {observation_id}.bootstrap_observation")
    _keys(
        bootstrap_data,
        {"executions", "invalid_address", "result_classification", "stable_offset", "immutable_contract"},
        f"observation {observation_id}.bootstrap_observation",
    )
    stable_offset = _string(bootstrap_data["stable_offset"], f"observation {observation_id}.stable_offset")
    if _HEX_OFFSET_RE.fullmatch(stable_offset) is None:
        raise LiveCTFArtifactError(f"observation {observation_id}.stable_offset must be lowercase hexadecimal")
    if bootstrap_data["immutable_contract"] is not False:
        raise LiveCTFArtifactError(f"observation {observation_id} bootstrap result must not be an immutable contract")
    bootstrap = BootstrapObservation(
        _integer(bootstrap_data["executions"], f"observation {observation_id}.executions", minimum=1),
        _integer(bootstrap_data["invalid_address"], f"observation {observation_id}.invalid_address", minimum=0),
        _string(bootstrap_data["result_classification"], f"observation {observation_id}.result_classification"),
        stable_offset,
        False,
    )
    return MutableBuildObservation(observation_id, source_id, observed_at, False, reason, base, files, bootstrap)


def _parse_archive(raw: Any, context: str) -> ArchiveIdentity:
    data = _mapping(raw, context)
    _keys(data, {"name", "url", "size", "sha256"}, context)
    name = _safe_path(data["name"], f"{context}.name", single=True)
    if not name.endswith((".tar.gz", ".tar.xz", ".tar.bz2")):
        raise LiveCTFArtifactError(f"{context}.name is not a supported tar archive")
    return ArchiveIdentity(
        name,
        _https(data["url"], f"{context}.url"),
        _integer(data["size"], f"{context}.size", minimum=1),
        _sha256(data["sha256"], f"{context}.sha256"),
    )


def _parse_member(raw: Any, context: str) -> MemberIdentity:
    data = _mapping(raw, context)
    _keys(data, {"path", "size", "sha256"}, context)
    return MemberIdentity(
        _safe_path(data["path"], f"{context}.path"),
        _integer(data["size"], f"{context}.size", minimum=1),
        _sha256(data["sha256"], f"{context}.sha256"),
    )


def _parse_license(raw: Any, context: str) -> LicenseIdentity:
    data = _mapping(raw, context)
    _keys(data, {"spdx", "path", "size", "sha256"}, context)
    return LicenseIdentity(
        _safe_path(data["path"], f"{context}.path"),
        _integer(data["size"], f"{context}.size", minimum=1),
        _sha256(data["sha256"], f"{context}.sha256"),
        _string(data["spdx"], f"{context}.spdx"),
    )


def _parse_elf(raw: Any, context: str) -> ElfIdentity:
    data = _mapping(raw, context)
    _keys(data, {"path", "size", "sha256", "elf_build_id"}, context)
    build_id = _string(data["elf_build_id"], f"{context}.elf_build_id")
    if len(build_id) % 2 or any(character not in _HEX for character in build_id):
        raise LiveCTFArtifactError(f"{context}.elf_build_id must be an even-length lowercase hexadecimal string")
    return ElfIdentity(
        _safe_path(data["path"], f"{context}.path"),
        _integer(data["size"], f"{context}.size", minimum=1),
        _sha256(data["sha256"], f"{context}.sha256"),
        build_id,
    )


def _cache_directories(cache_dir: str | os.PathLike[str]) -> tuple[Path, Path, Path, Path]:
    cache = Path(cache_dir).resolve()
    artifacts = cache / "artifacts"
    roots = cache / "roots"
    locks = cache / "locks"
    for directory in (artifacts, roots, locks):
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise LiveCTFArtifactError(f"unsafe LiveCTF cache directory: {directory}")
    return cache, artifacts, roots, locks


def _materialize_archive(spec: ArchiveIdentity, artifacts: Path, locks: Path) -> Path:
    destination = artifacts / f"{spec.sha256}{spec.cache_suffix}"
    with _FileLock(locks / f"artifact-{spec.sha256}.lock"):
        if destination.exists():
            try:
                _validate_file(destination, spec.size, spec.sha256, spec.name)
                return destination
            except LiveCTFArtifactError:
                if destination.is_symlink() or not destination.is_file():
                    raise
                destination.unlink()

        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{spec.sha256}-", dir=artifacts)
        temporary = Path(temporary_name)
        try:
            digest = hashlib.sha256()
            size = 0
            request = urllib.request.Request(spec.url, headers={"User-Agent": "pwnc-live-ctf-fixture/1"})
            with os.fdopen(descriptor, "wb") as output, urllib.request.urlopen(request, timeout=60) as response:
                while chunk := response.read(_BUFFER_SIZE):
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                    if size > spec.size:
                        raise LiveCTFArtifactError(f"{spec.name}: download exceeds pinned size {spec.size}")
                output.flush()
                os.fsync(output.fileno())
            if size != spec.size or digest.hexdigest() != spec.sha256:
                raise LiveCTFArtifactError(
                    f"{spec.name}: downloaded identity mismatch (size={size}, sha256={digest.hexdigest()})"
                )
            os.replace(temporary, destination)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            raise
    return destination


def _materialize_nested_archive(
    outer: Path,
    spec: NestedArchiveIdentity,
    artifacts: Path,
    locks: Path,
) -> Path:
    suffix = ".tar.gz" if spec.path.endswith(".tar.gz") else Path(spec.path).suffix
    destination = artifacts / f"{spec.sha256}{suffix}"
    with _FileLock(locks / f"artifact-{spec.sha256}.lock"):
        if destination.exists():
            try:
                _validate_file(destination, spec.size, spec.sha256, spec.path)
                return destination
            except LiveCTFArtifactError:
                if destination.is_symlink() or not destination.is_file():
                    raise
                destination.unlink()

        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{spec.sha256}-", dir=artifacts)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output, tarfile.open(outer, mode="r:*") as archive:
                member = _find_unique_regular_member(archive, spec.path)
                source = archive.extractfile(member)
                if source is None:
                    raise LiveCTFArtifactError(f"cannot read nested archive {spec.path}")
                _copy_stream(source, output)
                output.flush()
                os.fsync(output.fileno())
            _validate_file(temporary, spec.size, spec.sha256, spec.path)
            os.replace(temporary, destination)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            raise
    return destination


def _safe_extract_source(archive: tarfile.TarFile, destination: Path, archive_root: str) -> None:
    """Extract one GitHub source tar safely, stripping its exact top-level directory."""

    planned: list[tuple[tarfile.TarInfo, str]] = []
    seen: set[str] = set()
    for member in archive.getmembers():
        normalized = _normalize_tar_path(member.name)
        if normalized == archive_root:
            if not member.isdir():
                raise LiveCTFArtifactError(f"archive root {archive_root!r} is not a directory")
            continue
        prefix = f"{archive_root}/"
        if not normalized.startswith(prefix):
            raise LiveCTFArtifactError(f"archive member is outside expected root {archive_root!r}: {member.name!r}")
        relative = normalized.removeprefix(prefix)
        _safe_path(relative, f"archive member {member.name!r}")
        if relative in seen:
            raise LiveCTFArtifactError(f"duplicate archive member {relative!r}")
        seen.add(relative)
        if not (member.isdir() or member.isreg() or member.issym()):
            raise LiveCTFArtifactError(f"unsupported archive member type for {member.name!r}")
        planned.append((member, relative))

    # Symlinks are created last so no later regular member can traverse one.
    for member, relative in planned:
        if member.issym():
            continue
        target = _destination_path(destination, relative)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(member.mode & 0o777)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise LiveCTFArtifactError(f"cannot read archive member {member.name!r}")
            with target.open("xb") as output:
                _copy_stream(source, output)
            target.chmod(member.mode & 0o777)
    for member, relative in planned:
        if not member.issym():
            continue
        _validate_relative_link(relative, member.linkname)
        target = _destination_path(destination, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(member.linkname)


def _safe_extract_selected(archive: tarfile.TarFile, destination: Path, paths: Sequence[str]) -> None:
    """Extract exact regular-file members, rejecting aliases and duplicates."""

    for path in paths:
        normalized = _safe_path(path, f"selected member {path!r}")
        member = _find_unique_regular_member(archive, normalized)
        target = _destination_path(destination, normalized)
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise LiveCTFArtifactError(f"cannot read selected member {normalized!r}")
        with target.open("xb") as output:
            _copy_stream(source, output)
        target.chmod(member.mode & 0o777)


def _find_unique_regular_member(archive: tarfile.TarFile, path: str) -> tarfile.TarInfo:
    matches = [member for member in archive.getmembers() if _normalize_tar_path(member.name) == path]
    if len(matches) != 1:
        raise LiveCTFArtifactError(f"expected exactly one archive member {path!r}, found {len(matches)}")
    member = matches[0]
    if not member.isreg():
        raise LiveCTFArtifactError(f"archive member {path!r} is not a regular file")
    return member


def _normalize_tar_path(value: str) -> str:
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    # Many hand-created release archives contain a harmless leading ``./``
    # directory entry.  It is never a selectable file, but should not prevent
    # finding a separately attested member.
    if value in {"", "."}:
        return "."
    return _safe_path(value, f"archive member {value!r}")


def _destination_path(root: Path, relative: str) -> Path:
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise LiveCTFArtifactError(f"archive destination escapes extraction root: {relative!r}") from exc
    return path


def _validate_relative_link(relative: str, linkname: str) -> None:
    if not linkname or linkname.startswith("/") or "\\" in linkname:
        raise LiveCTFArtifactError(f"unsafe symlink target {linkname!r} for {relative!r}")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), linkname))
    if resolved == ".." or resolved.startswith(("../", "/")):
        raise LiveCTFArtifactError(f"symlink target escapes extraction root: {relative!r} -> {linkname!r}")


def _provisioned_handout(spec: HandoutSpec, root: Path) -> ProvisionedHandout:
    return ProvisionedHandout(
        spec,
        root,
        MappingProxyType({identity.path: _destination_path(root, identity.path) for identity in spec.files}),
    )


def _validate_member(root: Path, identity: MemberIdentity) -> None:
    _validate_file(_destination_path(root, identity.path), identity.size, identity.sha256, identity.path)


def _validate_file(path: Path, size: int, sha256: str, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise LiveCTFArtifactError(f"{label}: expected a non-symlink regular file at {path}")
    stat = path.stat()
    if stat.st_size != size:
        raise LiveCTFArtifactError(f"{label}: size {stat.st_size} does not match pinned size {size}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_BUFFER_SIZE):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != sha256:
        raise LiveCTFArtifactError(f"{label}: SHA-256 {actual} does not match {sha256}")


def _write_marker(root: Path, kind: str, item_id: str, fingerprint: str) -> None:
    marker = root / _MARKER
    marker.write_text(
        json.dumps(
            {"schema_version": 1, "kind": kind, "id": item_id, "fingerprint": fingerprint},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def _validate_marker(root: Path, kind: str, item_id: str, fingerprint: str) -> None:
    marker = root / _MARKER
    if marker.is_symlink() or not marker.is_file():
        raise LiveCTFArtifactError(f"{item_id}: missing safe completion marker")
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveCTFArtifactError(f"{item_id}: invalid completion marker: {exc}") from exc
    expected = {"schema_version": 1, "kind": kind, "id": item_id, "fingerprint": fingerprint}
    if value != expected:
        raise LiveCTFArtifactError(f"{item_id}: completion marker does not match the selected fixture")


def _remove_generated_root(path: Path, roots: Path) -> None:
    if path.parent != roots or path.is_symlink() or not path.is_dir():
        raise LiveCTFArtifactError(f"refusing to replace unsafe generated root {path}")
    shutil.rmtree(path)


def _copy_stream(source: BinaryIO, output: BinaryIO) -> None:
    while chunk := source.read(_BUFFER_SIZE):
        output.write(chunk)


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def _mapping(raw: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(raw, dict):
        raise LiveCTFArtifactError(f"{context} must be an object")
    return raw


def _sequence(raw: Any, context: str) -> Sequence[Any]:
    if not isinstance(raw, list):
        raise LiveCTFArtifactError(f"{context} must be an array")
    return raw


def _keys(data: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(data)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise LiveCTFArtifactError(f"{context} keys differ (missing={missing}, unknown={unknown})")


def _string(raw: Any, context: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise LiveCTFArtifactError(f"{context} must be a non-empty string")
    return raw


def _integer(raw: Any, context: str, *, minimum: int) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < minimum:
        raise LiveCTFArtifactError(f"{context} must be an integer >= {minimum}")
    return raw


def _identifier(raw: Any, context: str) -> str:
    value = _string(raw, context)
    if _ID_RE.fullmatch(value) is None:
        raise LiveCTFArtifactError(f"{context} must be a lowercase kebab-case identifier")
    return value


def _sha256(raw: Any, context: str) -> str:
    value = _string(raw, context)
    if len(value) != 64 or any(character not in _HEX for character in value):
        raise LiveCTFArtifactError(f"{context} must be exactly 64 lowercase hexadecimal characters")
    return value


def _https(raw: Any, context: str) -> str:
    value = _string(raw, context)
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise LiveCTFArtifactError(f"{context} must be an HTTPS URL without credentials or a fragment")
    return value


def _safe_path(raw: Any, context: str, *, single: bool = False) -> str:
    value = _string(raw, context)
    if value.startswith("/") or "\\" in value:
        raise LiveCTFArtifactError(f"{context} is an unsafe archive-relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts) or (single and len(parts) != 1):
        raise LiveCTFArtifactError(f"{context} is an unsafe archive-relative path")
    return value


def _unique_map(items: Sequence[Any], context: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in items:
        if item.id in result:
            raise LiveCTFArtifactError(f"duplicate {context} ID {item.id!r}")
        result[item.id] = item
    return result


def _unique_paths(items: Sequence[MemberIdentity], context: str) -> None:
    paths = [item.path for item in items]
    if len(paths) != len(set(paths)):
        raise LiveCTFArtifactError(f"{context} contains duplicate member paths")


class _FileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def __enter__(self) -> Self:
        self._descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self._descriptor, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._descriptor is not None:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            os.close(self._descriptor)
            self._descriptor = None


__all__ = [
    "ArchiveIdentity",
    "BaseImageObservation",
    "BootstrapObservation",
    "ElfIdentity",
    "HandoutSpec",
    "LicenseIdentity",
    "LiveCTFArtifactError",
    "LiveCTFManifest",
    "MemberIdentity",
    "MutableBuildObservation",
    "NestedArchiveIdentity",
    "Provenance",
    "ProvisionedHandout",
    "ProvisionedLiveCTF",
    "ProvisionedSource",
    "ReleaseIdentity",
    "SourceSpec",
    "load_manifest",
    "provision_all",
    "provision_handout",
    "provision_source",
    "validate_provisioned_handout",
    "validate_provisioned_source",
]
