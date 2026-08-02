"""Download, verify, and build the pinned QEMU execute-policy matrix.

This helper is intentionally explicit and is never run by ordinary tests::

    python3 -m payloads.tests.provision_qemu_versions --root /tmp/pwnc-qemu

The result can be selected with ``PWNC_QEMU_VERSION_ROOT=/tmp/pwnc-qemu``.
Only the AArch64 linux-user binary is built from each SHA-256-pinned official
source archive.  The default build uses the manifest's digest-pinned Ubuntu
22.04 container because QEMU 7.2 does not compile against current Ubuntu 24.04
kernel headers; ``--native-build`` is an explicit compatibility escape hatch.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import inspect
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import NoReturn
from urllib.error import URLError

from .qemu_version_matrix import (
    QemuBinaryAttestation,
    QemuRelease,
    QemuVersionManifest,
    attest_provisioned_qemu_binary,
    attest_qemu_binary,
    load_qemu_version_manifest,
    qemu_build_identity,
    qemu_configure_arguments,
    qemu_provenance_path,
)

_BUILDER_DOCKERFILE = Path(__file__).with_name("fixtures") / "qemu_version_builder.Dockerfile"
_SOURCE_MARKER = ".pwnc-source-provenance.json"
_BUILD_MARKER = ".pwnc-build-provenance.json"
_PROVENANCE_SCHEMA_VERSION = 1
_BUILDER_LABEL = "org.pwnc.qemu-builder.identity"
_SOURCE_SAFE_BUILD_ENVIRONMENT = {"PYTHONDONTWRITEBYTECODE": "1"}


class ProvisionError(RuntimeError):
    """Provisioning could not produce an attested QEMU binary."""


def _fail(message: str) -> NoReturn:
    raise ProvisionError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _download(release: QemuRelease, downloads: Path) -> Path:
    downloads.mkdir(parents=True, exist_ok=True)
    destination = downloads / release.archive_name
    if destination.is_file():
        observed = _sha256(destination)
        if observed == release.source_sha256:
            return destination
        _fail(
            f"cached archive {destination} has SHA-256 {observed}, expected {release.source_sha256}; "
            "remove that exact file before retrying"
        )

    partial = destination.with_suffix(destination.suffix + ".partial")
    request = urllib.request.Request(release.source_url, headers={"User-Agent": "pwnc-qemu-provision/1"})
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
            while block := response.read(1024 * 1024):
                digest.update(block)
                output.write(block)
    except (OSError, URLError) as exc:
        raise ProvisionError(f"failed to download {release.source_url}: {exc}") from exc
    observed = digest.hexdigest()
    if observed != release.source_sha256:
        _fail(f"downloaded {release.id} SHA-256 {observed}, expected {release.source_sha256}; partial={partial}")
    os.replace(partial, destination)
    return destination


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _archive_relative_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        _fail(f"archive member escapes extraction root: {name!r}")
    return path


def _normalized_link_path(parent: PurePosixPath, linkname: str) -> PurePosixPath:
    link = PurePosixPath(linkname)
    if link.is_absolute():
        _fail(f"archive link has an absolute target: {linkname!r}")
    parts: list[str] = []
    for part in (parent / link).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                _fail(f"archive link target escapes extraction root: {linkname!r}")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        _fail(f"archive link has an empty target: {linkname!r}")
    return PurePosixPath(*parts)


def _require_inside(root: Path, path: Path, member_name: str) -> None:
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ProvisionError(f"cannot safely resolve archive member {member_name!r}: {exc}") from exc
    if not _inside(root, resolved):
        _fail(f"archive member resolves outside extraction root: {member_name!r}")


def _require_no_symlink_parent(root: Path, relative: PurePosixPath, member_name: str) -> None:
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            _fail(f"archive member traverses an earlier symbolic link: {member_name!r}")


def _safe_extract_archive(archive: tarfile.TarFile, destination: Path) -> None:
    """Extract one checked member at a time, including on Python 3.11.

    Checking the whole member list before ``extractall`` is insufficient: an
    earlier member can create a symlink which changes the effective parent of
    a later member.  This routine resolves every destination immediately
    before that individual extraction and never writes through a symlink made
    by the archive.
    """

    destination.mkdir(parents=True, exist_ok=True)
    extraction_root = destination.resolve(strict=True)
    supports_filter = "filter" in inspect.signature(archive.extract).parameters
    for member in archive:
        relative = _archive_relative_path(member.name)
        target = destination.joinpath(*relative.parts)
        _require_no_symlink_parent(destination, relative, member.name)
        _require_inside(extraction_root, target, member.name)
        if target.is_symlink():
            _fail(f"archive member would replace an earlier symbolic link: {member.name!r}")
        if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
            _fail(f"archive member has a forbidden special type: {member.name!r}")
        if member.issym():
            link = PurePosixPath(member.linkname)
            if link.is_absolute():
                # Official QEMU archives contain an irrelevant X11 include
                # convenience link to /opt/X11.  Do not materialize absolute
                # host links in the source cache.
                continue
            normalized_link = _normalized_link_path(relative.parent, member.linkname)
            link_target = destination.joinpath(*normalized_link.parts)
            _require_inside(extraction_root, link_target, member.name)
        elif member.islnk():
            link = _normalized_link_path(PurePosixPath(), member.linkname)
            link_target = destination.joinpath(*link.parts)
            _require_inside(extraction_root, link_target, member.name)
            if not link_target.is_file() or link_target.is_symlink():
                _fail(f"archive hard link target is not an earlier regular file: {member.name!r}")
        arguments = {"filter": "data"} if supports_filter else {}
        try:
            archive.extract(member, destination, **arguments)
        except (OSError, tarfile.TarError) as exc:
            raise ProvisionError(f"cannot safely extract archive member {member.name!r}: {exc}") from exc


def _write_json(path: Path, record: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_json(path: Path, context: str) -> object:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisionError(f"cannot read {context} {path}: {exc}") from exc


def _digest_field(digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _source_tree_sha256(root: Path) -> str:
    """Hash source paths, types, modes, contents, and link targets."""

    digest = hashlib.sha256()

    def visit(directory: Path, relative: PurePosixPath) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        except OSError as exc:
            raise ProvisionError(f"cannot enumerate source tree {directory}: {exc}") from exc
        for entry in entries:
            child_relative = relative / entry.name
            if child_relative == PurePosixPath(_SOURCE_MARKER):
                continue
            path_bytes = os.fsencode(child_relative.as_posix())
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ProvisionError(f"cannot inspect source tree entry {entry.path}: {exc}") from exc
            mode = stat.S_IMODE(metadata.st_mode).to_bytes(4, "big")
            if entry.is_symlink():
                kind = b"symlink"
                payload = os.fsencode(os.readlink(entry.path))
            elif entry.is_dir(follow_symlinks=False):
                kind = b"directory"
                payload = b""
            elif entry.is_file(follow_symlinks=False):
                kind = b"file"
                file_digest = hashlib.sha256()
                try:
                    with open(entry.path, "rb") as stream:
                        while block := stream.read(1024 * 1024):
                            file_digest.update(block)
                except OSError as exc:
                    raise ProvisionError(f"cannot hash source tree entry {entry.path}: {exc}") from exc
                payload = file_digest.digest()
            else:
                _fail(f"source tree contains a forbidden special file: {entry.path}")
            for field in (path_bytes, kind, mode, payload):
                _digest_field(digest, field)
            if kind == b"directory":
                visit(Path(entry.path), child_relative)

    visit(root, PurePosixPath())
    return digest.hexdigest()


def _source_record(release: QemuRelease, tree_sha256: str) -> dict[str, object]:
    return {
        "schema_version": _PROVENANCE_SCHEMA_VERSION,
        "release": release.id,
        "source_url": release.source_url,
        "source_sha256": release.source_sha256,
        "archive_name": release.archive_name,
        "source_directory": release.source_directory,
        "tree_sha256": tree_sha256,
    }


def _validate_source_cache(release: QemuRelease, destination: Path) -> Path:
    marker = destination / _SOURCE_MARKER
    observed = _read_json(marker, "source provenance")
    if not isinstance(observed, dict) or set(observed) != set(_source_record(release, "")):
        _fail(f"source provenance fields for {release.id} are invalid")
    tree_sha256 = observed.get("tree_sha256")
    if not isinstance(tree_sha256, str) or len(tree_sha256) != 64:
        _fail(f"source provenance tree digest for {release.id} is invalid")
    if observed != _source_record(release, tree_sha256):
        _fail(f"source provenance for {release.id} does not match the pinned archive")
    actual_tree_sha256 = _source_tree_sha256(destination)
    if actual_tree_sha256 != tree_sha256:
        _fail(f"cached source tree for {release.id} has SHA-256 {actual_tree_sha256}, expected {tree_sha256}")
    try:
        version = (destination / "VERSION").read_text().strip()
    except OSError as exc:
        raise ProvisionError(f"cannot validate cached source VERSION for {release.id}: {exc}") from exc
    if version != release.version or not (destination / "configure").is_file():
        _fail(f"cached source for {release.id} is incomplete or reports VERSION={version!r}")
    return destination


def _validated_source_tree_sha256(release: QemuRelease, source: Path) -> str:
    _validate_source_cache(release, source)
    record = _read_json(source / _SOURCE_MARKER, "source provenance")
    assert isinstance(record, dict)
    tree_sha256 = record["tree_sha256"]
    assert isinstance(tree_sha256, str)
    return tree_sha256


def _extract(release: QemuRelease, archive_path: Path, sources: Path) -> Path:
    observed_archive = _sha256(archive_path)
    if observed_archive != release.source_sha256:
        _fail(f"source archive {archive_path} has SHA-256 {observed_archive}, expected {release.source_sha256}")
    destination = sources / release.source_directory
    if destination.is_dir():
        return _validate_source_cache(release, destination)
    if destination.exists():
        _fail(f"source cache destination is not a directory: {destination}")
    sources.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{release.id}-", dir=sources) as temporary:
        temporary_root = Path(temporary)
        try:
            with tarfile.open(archive_path, mode="r:xz") as archive:
                _safe_extract_archive(archive, temporary_root)
        except (OSError, tarfile.TarError) as exc:
            raise ProvisionError(f"cannot extract {archive_path}: {exc}") from exc
        extracted = temporary_root / release.source_directory
        if not extracted.is_dir():
            _fail(f"{archive_path} did not contain {release.source_directory}/")
        _write_json(extracted / _SOURCE_MARKER, _source_record(release, _source_tree_sha256(extracted)))
        _validate_source_cache(release, extracted)
        try:
            extracted.rename(destination)
        except OSError as exc:
            raise ProvisionError(f"cannot install extracted source at {destination}: {exc}") from exc
    return destination


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> None:
    process = subprocess.run(command, cwd=cwd, text=True, check=False, env=environment)
    if process.returncode:
        _fail(f"command exited {process.returncode}: {command!r}")


def _command_identity(command: list[str], *, environment: dict[str, str] | None = None) -> str:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=environment,
        )
    except OSError as exc:
        raise ProvisionError(f"cannot identify build tool {command[0]!r}: {exc}") from exc
    if process.returncode:
        diagnostics = process.stderr.strip() or process.stdout.strip() or "no diagnostics"
        _fail(f"build tool identity command exited {process.returncode}: {command!r}: {diagnostics}")
    output = process.stdout.strip() or process.stderr.strip()
    if not output:
        _fail(f"build tool identity command produced no output: {command!r}")
    return output.splitlines()[0]


def _native_toolchain(source: Path, environment: dict[str, str]) -> dict[str, dict[str, str]]:
    paths: dict[str, Path] = {}
    for tool in ("cc", "make", "ninja", "pkg-config", "python3"):
        executable = shutil.which(tool, path=environment["PATH"])
        if executable is None:
            _fail(f"native QEMU builds require {tool!r} on PATH")
        paths[tool] = Path(executable).resolve(strict=True)
    try:
        meson = (source / "meson" / "meson.py").resolve(strict=True)
    except OSError as exc:
        raise ProvisionError(f"cannot identify the vendored Meson entry point in {source}: {exc}") from exc
    commands = {
        "cc": [str(paths["cc"]), "--version"],
        "make": [str(paths["make"]), "--version"],
        "meson": [str(paths["python3"]), "-B", str(meson), "--version"],
        "ninja": [str(paths["ninja"]), "--version"],
        "pkg-config": [str(paths["pkg-config"]), "--version"],
        "python3": [str(paths["python3"]), "--version"],
    }
    return {
        name: {
            "path": str(meson if name == "meson" else paths[name]),
            "version": _command_identity(command, environment=environment),
        }
        for name, command in commands.items()
    }


def _native_build_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environment is None else environment
    path = values.get("PATH")
    if not path:
        _fail("native QEMU builds require an explicit PATH")
    # Do not let ambient CC/CFLAGS/LDFLAGS, pkg-config paths, preload hooks,
    # or QEMU variables silently alter a cache identity.  Resolved tools and
    # their versions are separately bound by ``_native_toolchain``.
    return {
        "HOME": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": path,
        **_SOURCE_SAFE_BUILD_ENVIRONMENT,
    }


@dataclasses.dataclass(frozen=True, slots=True)
class _BuilderImage:
    tag: str
    image_id: str
    recipe_sha256: str


def _build_record(
    manifest: QemuVersionManifest,
    release: QemuRelease,
    *,
    build_mode: str,
    source_tree_sha256: str,
    builder_recipe_sha256: str | None,
    builder_image_id: str | None,
    native_toolchain: dict[str, dict[str, str]] | None,
) -> dict[str, object]:
    identity = qemu_build_identity(
        manifest,
        release,
        build_mode=build_mode,
        source_tree_sha256=source_tree_sha256,
        builder_recipe_sha256=builder_recipe_sha256,
        builder_image_id=builder_image_id,
        native_toolchain=native_toolchain,
    )
    return {
        "mode": build_mode,
        "source_tree_sha256": source_tree_sha256,
        "container_image": manifest.build_container_image if build_mode == "container" else None,
        "builder_recipe_sha256": builder_recipe_sha256,
        "builder_image_id": builder_image_id,
        "native_toolchain": native_toolchain,
        "identity": identity,
    }


def _build_cache_record(release: QemuRelease, build_record: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": _PROVENANCE_SCHEMA_VERSION,
        "release": release.id,
        "source_sha256": release.source_sha256,
        "build": build_record,
    }


def _prepare_build_directory(root: Path, release: QemuRelease, build_record: dict[str, object]) -> Path:
    identity = build_record["identity"]
    assert isinstance(identity, str)
    build = root / "build" / f"{release.id}-{identity[:16]}"
    marker = build / _BUILD_MARKER
    expected = _build_cache_record(release, build_record)
    if build.is_dir():
        if _read_json(marker, "build provenance") != expected:
            _fail(f"build cache provenance for {release.id} does not match the requested build identity")
        _fail(
            f"refusing to reuse preexisting build cache {build} without its installed attested binary; "
            "remove that exact build directory before rebuilding"
        )
    if build.exists():
        _fail(f"build cache destination is not a directory: {build}")
    build.mkdir(parents=True)
    _write_json(marker, expected)
    return build


def _provenance_record(
    manifest: QemuVersionManifest,
    release: QemuRelease,
    attestation: QemuBinaryAttestation,
    build_record: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": _PROVENANCE_SCHEMA_VERSION,
        "origin": "provisioned",
        "release": release.id,
        "architecture": manifest.architecture,
        "emulator": manifest.emulator,
        "execution_policy": release.execution_policy.value,
        "contains_exec_permission_fix": release.contains_exec_permission_fix,
        "exec_permission_fix": manifest.exec_permission_fix,
        "binary": {
            "name": manifest.emulator,
            "sha256": attestation.sha256,
            "banner": attestation.banner,
            "observed_version": attestation.observed_version,
        },
        "source": {
            "url": release.source_url,
            "sha256": release.source_sha256,
            "archive_name": release.archive_name,
            "directory": release.source_directory,
            "tree_sha256": build_record["source_tree_sha256"],
        },
        "configure": {
            "target_list": manifest.target_list,
            "arguments": list(qemu_configure_arguments(manifest.target_list)),
        },
        "build": build_record,
    }


def _reuse_installed_binary(
    manifest: QemuVersionManifest,
    release: QemuRelease,
    destination: Path,
    build_record: dict[str, object],
) -> Path | None:
    sidecar = qemu_provenance_path(destination)
    if not destination.exists() and not sidecar.exists():
        return None
    if not destination.is_file() or not os.access(destination, os.X_OK) or not sidecar.is_file():
        _fail(
            f"preexisting installed QEMU for {release.id} lacks a complete executable/provenance pair; "
            f"remove {destination} and {sidecar} before retrying"
        )
    validated = attest_provisioned_qemu_binary(manifest, release, destination)
    if validated.build_identity != build_record["identity"]:
        _fail(
            f"installed {release.id} was built with {validated.build_mode}/{validated.build_identity}, "
            f"not requested {build_record['mode']}/{build_record['identity']}"
        )
    return destination


def _install_built_binary(
    manifest: QemuVersionManifest,
    release: QemuRelease,
    built: Path,
    destination: Path,
    build_record: dict[str, object],
) -> Path:
    if not built.is_file():
        _fail(f"the {release.id} build did not produce {built}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".partial")
    shutil.copy2(built, temporary)
    temporary.chmod(temporary.stat().st_mode | 0o111)
    os.replace(temporary, destination)
    attestation = attest_qemu_binary(release, destination)
    _write_json(
        qemu_provenance_path(destination),
        _provenance_record(manifest, release, attestation, build_record),
    )
    attest_provisioned_qemu_binary(manifest, release, destination)
    return destination


def _build_native(
    manifest: QemuVersionManifest,
    release: QemuRelease,
    source: Path,
    root: Path,
    jobs: int,
    emulator: str,
    target_list: str,
) -> Path:
    source_tree_sha256 = _validated_source_tree_sha256(release, source)
    build_environment = _native_build_environment()
    toolchain = _native_toolchain(source, build_environment)
    build_record = _build_record(
        manifest,
        release,
        build_mode="native",
        source_tree_sha256=source_tree_sha256,
        builder_recipe_sha256=None,
        builder_image_id=None,
        native_toolchain=toolchain,
    )
    destination = root / release.id / "bin" / emulator
    reused = _reuse_installed_binary(manifest, release, destination, build_record)
    if reused is not None:
        return reused
    build = _prepare_build_directory(root, release, build_record)
    if not (build / "build.ninja").is_file():
        _run(
            [
                str(source / "configure"),
                *qemu_configure_arguments(target_list),
            ],
            cwd=build,
            environment=build_environment,
        )
    _run(
        ["ninja", "-C", str(build), f"-j{jobs}", emulator],
        environment=build_environment,
    )
    _validated_source_tree_sha256(release, source)
    return _install_built_binary(manifest, release, build / emulator, destination, build_record)


def _container_engine(requested: str | None) -> str:
    candidates = (requested,) if requested else ("docker", "podman")
    for candidate in candidates:
        if candidate and shutil.which(candidate) is not None:
            return candidate
    detail = requested or "docker or podman"
    _fail(f"the pinned Ubuntu 22.04 QEMU build requires {detail} on PATH; use --native-build only on a compatible host")


def _inspect_builder_image(engine: str, tag: str, expected_identity: str) -> _BuilderImage | None:
    inspected = subprocess.run([engine, "image", "inspect", tag], capture_output=True, text=True, check=False)
    if inspected.returncode:
        return None
    try:
        records = json.loads(inspected.stdout)
        record = records[0]
        image_id = str(record["Id"])
        labels = record["Config"]["Labels"] or {}
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProvisionError(f"cannot parse {engine} image identity for {tag}: {exc}") from exc
    if labels.get(_BUILDER_LABEL) != expected_identity:
        _fail(f"preexisting builder image {tag} lacks the expected provenance label")
    if not image_id.startswith("sha256:") or len(image_id) != len("sha256:") + 64:
        _fail(f"builder image {tag} reports an invalid image ID {image_id!r}")
    return _BuilderImage(tag, image_id, _sha256(_BUILDER_DOCKERFILE))


def _builder_image(engine: str, base: str) -> _BuilderImage:
    recipe = _BUILDER_DOCKERFILE.read_bytes()
    identity = hashlib.sha256(b"pwnc-qemu-builder-v2\0" + base.encode() + b"\0" + recipe).hexdigest()
    tag = f"pwnc-qemu-version-builder:{identity[:16]}"
    existing = _inspect_builder_image(engine, tag, identity)
    if existing is not None:
        return existing
    _run(
        [
            engine,
            "build",
            "--build-arg",
            f"BUILD_BASE={base}",
            "--label",
            f"{_BUILDER_LABEL}={identity}",
            "--file",
            str(_BUILDER_DOCKERFILE),
            "--tag",
            tag,
            str(_BUILDER_DOCKERFILE.parent),
        ]
    )
    built = _inspect_builder_image(engine, tag, identity)
    if built is None:
        _fail(f"{engine} did not install the expected builder image {tag}")
    return built


def _build_containerized(
    manifest: QemuVersionManifest,
    release: QemuRelease,
    root: Path,
    jobs: int,
    emulator: str,
    target_list: str,
    *,
    engine: str,
    builder_image: _BuilderImage,
) -> Path:
    source = root / "sources" / release.source_directory
    source_tree_sha256 = _validated_source_tree_sha256(release, source)
    build_record = _build_record(
        manifest,
        release,
        build_mode="container",
        source_tree_sha256=source_tree_sha256,
        builder_recipe_sha256=builder_image.recipe_sha256,
        builder_image_id=builder_image.image_id,
        native_toolchain=None,
    )
    destination = root / release.id / "bin" / emulator
    reused = _reuse_installed_binary(manifest, release, destination, build_record)
    if reused is not None:
        return reused
    build = _prepare_build_directory(root, release, build_record)
    source_in_container = f"/work/sources/{release.source_directory}"
    build_in_container = f"/work/build/{build.name}"
    configure = f"{source_in_container}/configure {' '.join(qemu_configure_arguments(target_list))}"
    command = (
        f"test -f {build_in_container}/build.ninja || "
        f"(cd {build_in_container} && {configure}); "
        f"ninja -C {build_in_container} -j{jobs} {emulator}"
    )
    run = [engine, "run", "--rm", "--platform", "linux/amd64"]
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        run.extend(("--user", f"{os.getuid()}:{os.getgid()}"))
    run.extend(
        (
            "--env",
            "HOME=/tmp",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--volume",
            f"{root}:/work",
            "--volume",
            f"{source}:{source_in_container}:ro",
            "--workdir",
            "/work",
            builder_image.tag,
            "sh",
            "-ec",
            command,
        )
    )
    _run(run)
    _validated_source_tree_sha256(release, source)
    return _install_built_binary(manifest, release, build / emulator, destination, build_record)


def provision(
    root: Path,
    release_ids: tuple[str, ...],
    jobs: int,
    *,
    download_only: bool = False,
    native_build: bool = False,
    container_engine: str | None = None,
) -> None:
    """Provision selected releases below one explicit cache root."""

    selected_root = root.resolve(strict=False)
    if selected_root == Path(selected_root.anchor):
        _fail("refusing to use a filesystem root as the QEMU version cache")
    if jobs <= 0:
        _fail("jobs must be positive")
    manifest = load_qemu_version_manifest()
    releases = manifest.releases if not release_ids else tuple(manifest.release(item) for item in release_ids)
    attestations: list[dict[str, object]] = []
    engine = None if download_only or native_build else _container_engine(container_engine)
    image = None if engine is None else _builder_image(engine, manifest.build_container_image)
    for release in releases:
        archive = _download(release, selected_root / "downloads")
        if download_only:
            continue
        source = _extract(release, archive, selected_root / "sources")
        if native_build:
            binary = _build_native(
                manifest,
                release,
                source,
                selected_root,
                jobs,
                manifest.emulator,
                manifest.target_list,
            )
        else:
            assert engine is not None and image is not None
            binary = _build_containerized(
                manifest,
                release,
                selected_root,
                jobs,
                manifest.emulator,
                manifest.target_list,
                engine=engine,
                builder_image=image,
            )
        validated = attest_provisioned_qemu_binary(manifest, release, binary)
        record = _read_json(validated.provenance_path, "installed QEMU provenance")
        assert isinstance(record, dict)
        attestations.append(record)
    if not download_only:
        report = {
            "schema_version": manifest.schema_version,
            "architecture": manifest.architecture,
            "emulator": manifest.emulator,
            "build_container_image": None if native_build else manifest.build_container_image,
            "releases": attestations,
        }
        _write_json(selected_root / "attestation.json", report)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="explicit cache/install root")
    parser.add_argument("--release", action="append", default=[], help="release id; repeat to select a subset")
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1), help="parallel Ninja jobs")
    parser.add_argument("--download-only", action="store_true", help="verify and cache source archives only")
    parser.add_argument(
        "--native-build",
        action="store_true",
        help="build on the host instead of the digest-pinned Ubuntu 22.04 container",
    )
    parser.add_argument("--container-engine", choices=("docker", "podman"), help="container CLI; auto-detected")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        provision(
            arguments.root,
            tuple(arguments.release),
            arguments.jobs,
            download_only=arguments.download_only,
            native_build=arguments.native_build,
            container_engine=arguments.container_engine,
        )
    except (ProvisionError, ValueError) as exc:
        print(f"error: {exc}")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a CLI
    raise SystemExit(main())
