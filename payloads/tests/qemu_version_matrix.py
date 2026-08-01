"""Pinned QEMU linux-user releases used by execute-permission probes.

The ordinary QEMU tests intentionally use whichever emulator is installed on
the host.  This module is different: it models an exact upstream source
release on each side of the linux-user execute-permission fix and refuses to
turn an unversioned binary into version-bound evidence.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlparse

import tomllib

from payloads import ExecutionPolicy

_MANIFEST_PATH = Path(__file__).with_name("qemu_versions.toml")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")
_VERSION = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
_BANNER_VERSION = re.compile(r"(?:QEMU emulator|qemu-[A-Za-z0-9_.+-]+) version ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|\Z)")
_ENVIRONMENT_NAME = re.compile(r"\APWNC_QEMU_[A-Z0-9_]+\Z")
_EXEC_PERMISSION_FIX = "cdf7130851318004e6512dbfdb73156fe59c7a59"


class QemuVersionMatrixError(ValueError):
    """A pinned release, binary, or runtime observation is invalid."""


@dataclass(frozen=True, slots=True)
class QemuRelease:
    """One exact upstream QEMU release and its expected observed policy."""

    id: str
    version: str
    source_url: str
    source_sha256: str
    source_directory: str
    execution_policy: ExecutionPolicy
    contains_exec_permission_fix: bool
    binary_environment: str

    def __post_init__(self) -> None:
        if not self.id or self.id != f"qemu-{self.version}":
            raise QemuVersionMatrixError("release id must be qemu-<exact version>")
        if _VERSION.fullmatch(self.version) is None:
            raise QemuVersionMatrixError(f"invalid exact QEMU version {self.version!r}")
        if _SHA256.fullmatch(self.source_sha256) is None:
            raise QemuVersionMatrixError(f"invalid source SHA-256 for {self.id}")
        parsed = urlparse(self.source_url)
        expected_archive = f"qemu-{self.version}.tar.xz"
        if parsed.scheme != "https" or parsed.hostname != "download.qemu.org":
            raise QemuVersionMatrixError(f"{self.id} source must use the official HTTPS download host")
        if Path(parsed.path).name != expected_archive:
            raise QemuVersionMatrixError(f"{self.id} source URL must end in {expected_archive}")
        if self.source_directory != f"qemu-{self.version}" or "/" in self.source_directory:
            raise QemuVersionMatrixError(f"invalid source directory for {self.id}")
        if _ENVIRONMENT_NAME.fullmatch(self.binary_environment) is None:
            raise QemuVersionMatrixError(f"invalid binary environment name for {self.id}")
        if not isinstance(self.contains_exec_permission_fix, bool):
            raise QemuVersionMatrixError("contains_exec_permission_fix must be bool")
        expected = (
            ExecutionPolicy.QEMU_ELF_PERMISSIONS
            if self.contains_exec_permission_fix
            else ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE
        )
        if self.execution_policy is not expected:
            raise QemuVersionMatrixError(
                f"{self.id} fix membership conflicts with execution policy {self.execution_policy.value}"
            )

    @property
    def archive_name(self) -> str:
        return f"qemu-{self.version}.tar.xz"


@dataclass(frozen=True, slots=True)
class QemuVersionManifest:
    """The exact architecture and releases defining the policy boundary."""

    schema_version: int
    architecture: str
    emulator: str
    target_list: str
    exec_permission_fix: str
    build_container_image: str
    releases: tuple[QemuRelease, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise QemuVersionMatrixError(f"unsupported QEMU version manifest schema {self.schema_version!r}")
        if (self.architecture, self.emulator, self.target_list) != (
            "aarch64",
            "qemu-aarch64",
            "aarch64-linux-user",
        ):
            raise QemuVersionMatrixError("the execute-permission boundary probe must use AArch64 linux-user")
        if _COMMIT.fullmatch(self.exec_permission_fix) is None:
            raise QemuVersionMatrixError("exec_permission_fix must be a full Git commit hash")
        if self.exec_permission_fix != _EXEC_PERMISSION_FIX:
            raise QemuVersionMatrixError("the manifest names an unexpected execute-permission fix")
        if not self.build_container_image.startswith("docker.io/library/ubuntu:22.04@sha256:"):
            raise QemuVersionMatrixError("the old-QEMU builder must pin the Ubuntu 22.04 image by digest")
        image_digest = self.build_container_image.rsplit(":", 1)[-1]
        if _SHA256.fullmatch(image_digest) is None:
            raise QemuVersionMatrixError("the QEMU build container image needs a full SHA-256 digest")
        if len(self.releases) < 2:
            raise QemuVersionMatrixError("the manifest needs releases on both sides of the policy boundary")
        ids = [release.id for release in self.releases]
        if len(ids) != len(set(ids)):
            raise QemuVersionMatrixError("release ids must be unique")
        environments = [release.binary_environment for release in self.releases]
        if len(environments) != len(set(environments)):
            raise QemuVersionMatrixError("release binary environments must be unique")
        policies = {release.execution_policy for release in self.releases}
        if policies != {
            ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE,
            ExecutionPolicy.QEMU_ELF_PERMISSIONS,
        }:
            raise QemuVersionMatrixError("the manifest must cover both legacy and enforced execution policies")

    def release(self, release_id: str) -> QemuRelease:
        matches = [release for release in self.releases if release.id == release_id]
        if len(matches) != 1:
            raise QemuVersionMatrixError(f"unknown pinned QEMU release {release_id!r}")
        return matches[0]


@dataclass(frozen=True, slots=True)
class QemuBinaryAttestation:
    """Host-side identity recorded before a binary may supply test evidence."""

    release: QemuRelease
    path: Path
    sha256: str
    banner: str
    observed_version: str

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "release": self.release.id,
            "path": str(self.path),
            "binary_sha256": self.sha256,
            "banner": self.banner,
            "observed_version": self.observed_version,
            "execution_policy": self.release.execution_policy.value,
            "contains_exec_permission_fix": self.release.contains_exec_permission_fix,
        }


def _release(record: object) -> QemuRelease:
    if not isinstance(record, dict):
        raise QemuVersionMatrixError("every release entry must be a TOML table")
    required = {
        "id",
        "version",
        "source_url",
        "source_sha256",
        "source_directory",
        "execution_policy",
        "contains_exec_permission_fix",
        "binary_environment",
    }
    if set(record) != required:
        raise QemuVersionMatrixError(
            f"release fields must be exact; missing={required - set(record)!r}, extra={set(record) - required!r}"
        )
    try:
        policy = ExecutionPolicy(str(record["execution_policy"]))
    except ValueError as exc:
        raise QemuVersionMatrixError(f"invalid execution policy {record['execution_policy']!r}") from exc
    return QemuRelease(
        id=str(record["id"]),
        version=str(record["version"]),
        source_url=str(record["source_url"]),
        source_sha256=str(record["source_sha256"]),
        source_directory=str(record["source_directory"]),
        execution_policy=policy,
        contains_exec_permission_fix=record["contains_exec_permission_fix"],
        binary_environment=str(record["binary_environment"]),
    )


def load_qemu_version_manifest(path: str | Path = _MANIFEST_PATH) -> QemuVersionManifest:
    """Parse and validate the pinned version matrix."""

    manifest_path = Path(path)
    try:
        data = tomllib.loads(manifest_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise QemuVersionMatrixError(f"cannot read QEMU version manifest {manifest_path}: {exc}") from exc
    required = {
        "schema_version",
        "architecture",
        "emulator",
        "target_list",
        "exec_permission_fix",
        "build_container_image",
        "release",
    }
    if set(data) != required:
        raise QemuVersionMatrixError(
            f"manifest fields must be exact; missing={required - set(data)!r}, extra={set(data) - required!r}"
        )
    release_records = data["release"]
    if not isinstance(release_records, list):
        raise QemuVersionMatrixError("release must be an array of tables")
    return QemuVersionManifest(
        schema_version=data["schema_version"],
        architecture=str(data["architecture"]),
        emulator=str(data["emulator"]),
        target_list=str(data["target_list"]),
        exec_permission_fix=str(data["exec_permission_fix"]),
        build_container_image=str(data["build_container_image"]),
        releases=tuple(_release(record) for record in release_records),
    )


def qemu_test_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a loader- and QEMU-prefix-clean environment for a test process."""

    sanitized = dict(os.environ if environment is None else environment)
    for name in tuple(sanitized):
        if name.startswith("QEMU_"):
            sanitized.pop(name)
    for name in (
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
    ):
        sanitized.pop(name, None)
    return sanitized


def resolve_qemu_binary(
    manifest: QemuVersionManifest,
    release: QemuRelease,
    *,
    root: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Resolve an explicit binary override or a provisioned matrix root."""

    values = MappingProxyType(dict(os.environ if environment is None else environment))
    override = values.get(release.binary_environment)
    if override:
        candidate = Path(override)
    else:
        selected_root = root or values.get("PWNC_QEMU_VERSION_ROOT")
        if selected_root is None:
            raise QemuVersionMatrixError(f"set {release.binary_environment} or PWNC_QEMU_VERSION_ROOT for {release.id}")
        candidate = Path(selected_root) / release.id / "bin" / manifest.emulator
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise QemuVersionMatrixError(f"QEMU binary for {release.id} does not exist: {candidate}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise QemuVersionMatrixError(f"QEMU binary for {release.id} is not an executable file: {resolved}")
    return resolved


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def attest_qemu_binary(
    release: QemuRelease,
    binary: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> QemuBinaryAttestation:
    """Hash a binary and require its reported version to match the pin."""

    path = Path(binary).resolve(strict=True)
    process = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=qemu_test_environment(environment),
    )
    if process.returncode:
        diagnostics = process.stderr.strip() or process.stdout.strip() or "no diagnostics"
        raise QemuVersionMatrixError(f"{path} --version exited {process.returncode}: {diagnostics}")
    lines = process.stdout.splitlines()
    if not lines:
        raise QemuVersionMatrixError(f"{path} --version produced no banner")
    banner = lines[0].strip()
    match = _BANNER_VERSION.search(banner)
    if match is None:
        raise QemuVersionMatrixError(f"cannot parse QEMU version from {banner!r}")
    observed = match.group(1)
    if observed != release.version:
        raise QemuVersionMatrixError(
            f"{path} reports QEMU {observed}, but {release.binary_environment} is pinned to {release.version}"
        )
    return QemuBinaryAttestation(release, path, _file_sha256(path), banner, observed)


__all__ = [
    "QemuBinaryAttestation",
    "QemuRelease",
    "QemuVersionManifest",
    "QemuVersionMatrixError",
    "attest_qemu_binary",
    "load_qemu_version_manifest",
    "qemu_test_environment",
    "resolve_qemu_binary",
]
