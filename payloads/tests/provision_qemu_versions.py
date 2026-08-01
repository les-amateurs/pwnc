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
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import NoReturn
from urllib.error import URLError

from .qemu_version_matrix import QemuRelease, attest_qemu_binary, load_qemu_version_manifest

_BUILDER_DOCKERFILE = Path(__file__).with_name("fixtures") / "qemu_version_builder.Dockerfile"


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


def _safe_archive_members(archive: tarfile.TarFile, destination: Path) -> tuple[tarfile.TarInfo, ...]:
    safe: list[tarfile.TarInfo] = []
    for member in archive.getmembers():
        member_path = destination / member.name
        if Path(member.name).is_absolute() or not _inside(destination, member_path):
            _fail(f"archive member escapes extraction root: {member.name!r}")
        if member.isdev() or member.isfifo():
            _fail(f"archive member has a forbidden special type: {member.name!r}")
        if member.issym():
            link = member_path.parent / member.linkname
            if Path(member.linkname).is_absolute() or not _inside(destination, link):
                # QEMU 7.1 contains one irrelevant X11 include convenience
                # link to /opt/X11.  Omitting unsafe links keeps extraction
                # confined and does not affect an AArch64 linux-user build.
                continue
        elif member.islnk():
            link = destination / member.linkname
            if Path(member.linkname).is_absolute() or not _inside(destination, link):
                continue
        safe.append(member)
    return tuple(safe)


def _extract(release: QemuRelease, archive_path: Path, sources: Path) -> Path:
    destination = sources / release.source_directory
    if destination.is_dir():
        return destination
    sources.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{release.id}-", dir=sources) as temporary:
        temporary_root = Path(temporary)
        try:
            with tarfile.open(archive_path, mode="r:xz") as archive:
                members = _safe_archive_members(archive, temporary_root)
                try:
                    archive.extractall(temporary_root, members=members, filter="data")
                except TypeError:  # Python 3.11 has no extraction filters.
                    archive.extractall(temporary_root, members=members)
        except (OSError, tarfile.TarError) as exc:
            raise ProvisionError(f"cannot extract {archive_path}: {exc}") from exc
        extracted = temporary_root / release.source_directory
        if not extracted.is_dir():
            _fail(f"{archive_path} did not contain {release.source_directory}/")
        try:
            extracted.rename(destination)
        except OSError as exc:
            raise ProvisionError(f"cannot install extracted source at {destination}: {exc}") from exc
    return destination


def _run(command: list[str], *, cwd: Path | None = None) -> None:
    process = subprocess.run(command, cwd=cwd, text=True, check=False)
    if process.returncode:
        _fail(f"command exited {process.returncode}: {command!r}")


def _install_built_binary(release: QemuRelease, built: Path, destination: Path) -> Path:
    if not built.is_file():
        _fail(f"the {release.id} build did not produce {built}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".partial")
    shutil.copy2(built, temporary)
    temporary.chmod(temporary.stat().st_mode | 0o111)
    os.replace(temporary, destination)
    attest_qemu_binary(release, destination)
    return destination


def _build_native(
    release: QemuRelease,
    source: Path,
    root: Path,
    jobs: int,
    emulator: str,
    target_list: str,
) -> Path:
    destination = root / release.id / "bin" / emulator
    if destination.is_file() and os.access(destination, os.X_OK):
        attest_qemu_binary(release, destination)
        return destination

    for tool in ("cc", "make", "ninja", "pkg-config"):
        if shutil.which(tool) is None:
            _fail(f"building {release.id} requires {tool!r} on PATH")
    build = root / "build" / release.id
    build.mkdir(parents=True, exist_ok=True)
    if not (build / "build.ninja").is_file():
        _run(
            [
                str(source / "configure"),
                f"--target-list={target_list}",
                "--disable-docs",
                "--disable-werror",
            ],
            cwd=build,
        )
    _run(["ninja", "-C", str(build), f"-j{jobs}", emulator])
    return _install_built_binary(release, build / emulator, destination)


def _container_engine(requested: str | None) -> str:
    candidates = (requested,) if requested else ("docker", "podman")
    for candidate in candidates:
        if candidate and shutil.which(candidate) is not None:
            return candidate
    detail = requested or "docker or podman"
    _fail(f"the pinned Ubuntu 22.04 QEMU build requires {detail} on PATH; use --native-build only on a compatible host")


def _builder_image(engine: str, base: str) -> str:
    recipe = _BUILDER_DOCKERFILE.read_bytes()
    identity = hashlib.sha256(base.encode() + b"\0" + recipe).hexdigest()
    tag = f"pwnc-qemu-version-builder:{identity[:16]}"
    inspected = subprocess.run([engine, "image", "inspect", tag], capture_output=True, check=False)
    if inspected.returncode == 0:
        return tag
    _run(
        [
            engine,
            "build",
            "--build-arg",
            f"BUILD_BASE={base}",
            "--file",
            str(_BUILDER_DOCKERFILE),
            "--tag",
            tag,
            str(_BUILDER_DOCKERFILE.parent),
        ]
    )
    return tag


def _build_containerized(
    release: QemuRelease,
    root: Path,
    jobs: int,
    emulator: str,
    target_list: str,
    *,
    engine: str,
    builder_image: str,
) -> Path:
    destination = root / release.id / "bin" / emulator
    if destination.is_file() and os.access(destination, os.X_OK):
        attest_qemu_binary(release, destination)
        return destination
    build = root / "build" / release.id
    build.mkdir(parents=True, exist_ok=True)
    source_in_container = f"/work/sources/{release.source_directory}"
    build_in_container = f"/work/build/{release.id}"
    configure = f"{source_in_container}/configure --target-list={target_list} --disable-docs --disable-werror"
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
            "--volume",
            f"{root}:/work",
            "--workdir",
            "/work",
            builder_image,
            "sh",
            "-ec",
            command,
        )
    )
    _run(run)
    return _install_built_binary(release, build / emulator, destination)


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
    attestations: list[dict[str, str | bool]] = []
    engine = None if download_only or native_build else _container_engine(container_engine)
    image = None if engine is None else _builder_image(engine, manifest.build_container_image)
    for release in releases:
        archive = _download(release, selected_root / "downloads")
        if download_only:
            continue
        source = _extract(release, archive, selected_root / "sources")
        if native_build:
            binary = _build_native(
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
                release,
                selected_root,
                jobs,
                manifest.emulator,
                manifest.target_list,
                engine=engine,
                builder_image=image,
            )
        record = attest_qemu_binary(release, binary).as_dict()
        record["source_url"] = release.source_url
        record["source_sha256"] = release.source_sha256
        record["exec_permission_fix"] = manifest.exec_permission_fix
        attestations.append(record)
    if not download_only:
        report = {
            "schema_version": manifest.schema_version,
            "architecture": manifest.architecture,
            "emulator": manifest.emulator,
            "build_container_image": None if native_build else manifest.build_container_image,
            "releases": attestations,
        }
        (selected_root / "attestation.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


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
