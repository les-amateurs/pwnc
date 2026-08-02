"""Pinned old/new QEMU linux-user execute-permission tests.

Run the execution class after provisioning both exact releases::

    python3 -m payloads.tests.provision_qemu_versions --root /tmp/pwnc-qemu
    PWNC_QEMU_VERSION_ROOT=/tmp/pwnc-qemu PWNC_QEMU_VERSION_TESTS=1 \
        python3 -m unittest payloads.tests.test_qemu_versions -v
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from payloads import Architecture, ExecutionPolicy, Linkage, inspect_elf
from payloads.tests.provision_qemu_versions import (
    ProvisionError,
    _build_record,
    _extract,
    _native_build_environment,
    _prepare_build_directory,
    _provenance_record,
    _reuse_installed_binary,
    _safe_extract_archive,
    _sha256,
)
from payloads.tests.qemu_version_matrix import (
    QemuVersionMatrixError,
    attest_provisioned_qemu_binary,
    attest_qemu_binary,
    load_qemu_version_manifest,
    qemu_build_identity,
    qemu_provenance_path,
    qemu_test_environment,
    resolve_qemu_binary,
    resolve_qemu_binary_with_origin,
)

_OPT_IN = os.environ.get("PWNC_QEMU_VERSION_TESTS") == "1"
_FIXTURE = Path(__file__).with_name("fixtures") / "qemu_exec_policy_aarch64.S"


class QemuVersionManifestTests(unittest.TestCase):
    def test_manifest_pins_the_exact_upstream_policy_boundary(self) -> None:
        manifest = load_qemu_version_manifest()
        self.assertEqual(manifest.schema_version, 1)
        self.assertEqual(manifest.exec_permission_fix, "cdf7130851318004e6512dbfdb73156fe59c7a59")
        self.assertEqual(manifest.architecture, "aarch64")
        self.assertEqual(manifest.emulator, "qemu-aarch64")
        self.assertEqual(
            manifest.build_container_image,
            "docker.io/library/ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982",
        )
        self.assertEqual(
            {release.version for release in manifest.releases},
            {"7.1.0", "7.2.0"},
        )
        self.assertEqual(
            {release.execution_policy for release in manifest.releases},
            {
                ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE,
                ExecutionPolicy.QEMU_ELF_PERMISSIONS,
            },
        )
        for release in manifest.releases:
            with self.subTest(release=release.id):
                self.assertTrue(release.source_url.startswith("https://download.qemu.org/"))
                self.assertRegex(release.source_sha256, r"\A[0-9a-f]{64}\Z")

    def test_binary_resolution_requires_an_explicit_versioned_location(self) -> None:
        manifest = load_qemu_version_manifest()
        release = manifest.release("qemu-7.1.0")
        with self.assertRaisesRegex(QemuVersionMatrixError, "PWNC_QEMU_7_1_AARCH64"):
            resolve_qemu_binary(manifest, release, environment={})

    def test_explicit_override_is_labeled_external(self) -> None:
        manifest = load_qemu_version_manifest()
        release = manifest.release("qemu-7.1.0")
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-resolution-") as directory:
            binary = Path(directory, "qemu-aarch64")
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            resolution = resolve_qemu_binary_with_origin(
                manifest,
                release,
                environment={release.binary_environment: str(binary), "PWNC_QEMU_VERSION_ROOT": "/ignored"},
            )
            self.assertEqual(resolution.origin, "external")
            self.assertEqual(resolution.path, binary.resolve())

    def test_qemu_environment_cannot_override_guest_execution(self) -> None:
        environment = {
            "PATH": "/usr/bin",
            "LD_PRELOAD": "/tmp/host-hook.so",
            "QEMU_CPU": "max",
            "QEMU_GUEST_BASE": "0x10000",
            "QEMU_LD_PREFIX": "/tmp/foreign-sysroot",
            "QEMU_LOG": "in_asm",
            "QEMU_RESERVED_VA": "1G",
            "QEMU_STACK_SIZE": "1M",
            "QEMU_STRACE": "1",
        }
        sanitized = qemu_test_environment(environment)
        self.assertEqual(sanitized, {"PATH": "/usr/bin"})

    def test_binary_attestation_records_hash_and_rejects_a_wrong_version(self) -> None:
        manifest = load_qemu_version_manifest()
        release = manifest.release("qemu-7.1.0")
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-attest-") as directory:
            binary = Path(directory, "qemu-aarch64")
            binary.write_text("#!/bin/sh\nprintf 'qemu-aarch64 version 7.1.0\\n'\n")
            binary.chmod(0o755)
            attestation = attest_qemu_binary(release, binary, environment={})
            self.assertEqual(attestation.observed_version, "7.1.0")
            self.assertEqual(attestation.banner, "qemu-aarch64 version 7.1.0")
            self.assertRegex(attestation.sha256, r"\A[0-9a-f]{64}\Z")
            self.assertEqual(attestation.as_dict()["execution_policy"], "qemu-legacy-all-executable")

            binary.write_text("#!/bin/sh\nprintf 'QEMU emulator version 8.2.2\\n'\n")
            with self.assertRaisesRegex(QemuVersionMatrixError, "reports QEMU 8.2.2"):
                attest_qemu_binary(release, binary, environment={})


def _fake_native_toolchain(suffix: str = "") -> dict[str, dict[str, str]]:
    return {
        name: {"path": f"/tools/{name}", "version": f"{name} 1.0{suffix}"}
        for name in ("cc", "make", "meson", "ninja", "pkg-config", "python3")
    }


def _write_test_qemu(path: Path, version: str) -> None:
    path.write_text(f"#!/bin/sh\nprintf 'qemu-aarch64 version {version}\\n'\n")
    path.chmod(0o755)


class QemuProvisioningProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_qemu_version_manifest()
        self.release = self.manifest.release("qemu-7.1.0")

    def _container_build_record(self) -> dict[str, object]:
        return _build_record(
            self.manifest,
            self.release,
            build_mode="container",
            source_tree_sha256="3" * 64,
            builder_recipe_sha256="1" * 64,
            builder_image_id=f"sha256:{'2' * 64}",
            native_toolchain=None,
        )

    def _native_build_record(self) -> dict[str, object]:
        return _build_record(
            self.manifest,
            self.release,
            build_mode="native",
            source_tree_sha256="3" * 64,
            builder_recipe_sha256=None,
            builder_image_id=None,
            native_toolchain=_fake_native_toolchain(),
        )

    def test_sidecar_binds_binary_source_configuration_and_build_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-provenance-") as directory:
            binary = Path(directory, "qemu-aarch64")
            _write_test_qemu(binary, self.release.version)
            attestation = attest_qemu_binary(self.release, binary, environment={})
            record = _provenance_record(
                self.manifest,
                self.release,
                attestation,
                self._container_build_record(),
            )
            sidecar = qemu_provenance_path(binary)
            sidecar.write_text(json.dumps(record))

            validated = attest_provisioned_qemu_binary(self.manifest, self.release, binary, environment={})
            self.assertEqual(validated.build_mode, "container")
            self.assertEqual(validated.binary.sha256, record["binary"]["sha256"])

            record["source"]["sha256"] = "0" * 64
            sidecar.write_text(json.dumps(record))
            with self.assertRaisesRegex(QemuVersionMatrixError, "pinned source archive"):
                attest_provisioned_qemu_binary(self.manifest, self.release, binary, environment={})
            record["source"]["sha256"] = self.release.source_sha256

            record["configure"]["arguments"].append("--enable-system")
            sidecar.write_text(json.dumps(record))
            with self.assertRaisesRegex(QemuVersionMatrixError, "configure arguments"):
                attest_provisioned_qemu_binary(self.manifest, self.release, binary, environment={})
            record["configure"]["arguments"].pop()

            record["source"]["tree_sha256"] = "4" * 64
            sidecar.write_text(json.dumps(record))
            with self.assertRaisesRegex(QemuVersionMatrixError, "build identity"):
                attest_provisioned_qemu_binary(self.manifest, self.release, binary, environment={})

    def test_binary_tampering_invalidates_the_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-provenance-") as directory:
            binary = Path(directory, "qemu-aarch64")
            _write_test_qemu(binary, self.release.version)
            attestation = attest_qemu_binary(self.release, binary, environment={})
            qemu_provenance_path(binary).write_text(
                json.dumps(
                    _provenance_record(
                        self.manifest,
                        self.release,
                        attestation,
                        self._container_build_record(),
                    )
                )
            )
            binary.write_text(binary.read_text() + "# changed\n")
            with self.assertRaisesRegex(QemuVersionMatrixError, "binary hash and banner"):
                attest_provisioned_qemu_binary(self.manifest, self.release, binary, environment={})

    def test_native_toolchain_and_container_image_identity_partition_build_caches(self) -> None:
        container = self._container_build_record()
        native = self._native_build_record()
        changed_native = qemu_build_identity(
            self.manifest,
            self.release,
            build_mode="native",
            source_tree_sha256="3" * 64,
            builder_recipe_sha256=None,
            builder_image_id=None,
            native_toolchain=_fake_native_toolchain("-changed"),
        )
        self.assertNotEqual(container["identity"], native["identity"])
        self.assertNotEqual(native["identity"], changed_native)
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-build-cache-") as directory:
            root = Path(directory)
            container_path = _prepare_build_directory(root, self.release, container)
            native_path = _prepare_build_directory(root, self.release, native)
            self.assertNotEqual(container_path, native_path)
            with self.assertRaisesRegex(ProvisionError, "refusing to reuse preexisting build cache"):
                _prepare_build_directory(root, self.release, container)

    def test_native_build_environment_drops_ambient_compiler_and_loader_controls(self) -> None:
        environment = _native_build_environment(
            {
                "PATH": "/tools",
                "CC": "/tmp/wrapper",
                "CFLAGS": "-DBACKDOOR",
                "LDFLAGS": "-Wl,--unresolved-symbols=ignore-all",
                "LD_PRELOAD": "/tmp/hook.so",
                "PKG_CONFIG_PATH": "/tmp/pkgconfig",
                "QEMU_LD_PREFIX": "/tmp/guest",
            }
        )
        self.assertEqual(
            environment,
            {
                "HOME": "/tmp",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/tools",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

    def test_preexisting_binary_cannot_be_reused_as_the_opposite_build_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-install-") as directory:
            destination = Path(directory, self.release.id, "bin", self.manifest.emulator)
            destination.parent.mkdir(parents=True)
            _write_test_qemu(destination, self.release.version)
            attestation = attest_qemu_binary(self.release, destination, environment={})
            qemu_provenance_path(destination).write_text(
                json.dumps(
                    _provenance_record(
                        self.manifest,
                        self.release,
                        attestation,
                        self._container_build_record(),
                    )
                )
            )
            with self.assertRaisesRegex(ProvisionError, "not requested native"):
                _reuse_installed_binary(
                    self.manifest,
                    self.release,
                    destination,
                    self._native_build_record(),
                )


class QemuProvisioningExtractionTests(unittest.TestCase):
    @staticmethod
    def _add_directory(archive: tarfile.TarFile, name: str) -> None:
        member = tarfile.TarInfo(name)
        member.type = tarfile.DIRTYPE
        member.mode = 0o755
        archive.addfile(member)

    @staticmethod
    def _add_file(archive: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
        member = tarfile.TarInfo(name)
        member.size = len(data)
        member.mode = mode
        archive.addfile(member, io.BytesIO(data))

    def test_python311_path_never_writes_through_an_archive_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-extract-") as directory:
            archive_path = Path(directory, "malicious.tar.xz")
            with tarfile.open(archive_path, "w:xz") as archive:
                self._add_directory(archive, "qemu-7.1.0")
                self._add_directory(archive, "qemu-7.1.0/inside")
                link = tarfile.TarInfo("qemu-7.1.0/pivot")
                link.type = tarfile.SYMTYPE
                link.linkname = "inside"
                archive.addfile(link)
                self._add_file(archive, "qemu-7.1.0/pivot/payload", b"escaped")
            with (
                tarfile.open(archive_path, "r:xz") as archive,
                self.assertRaisesRegex(ProvisionError, "traverses an earlier symbolic link"),
            ):
                _safe_extract_archive(archive, Path(directory, "output"))

    def test_safe_parent_relative_symlink_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-extract-") as directory:
            archive_path = Path(directory, "safe.tar.xz")
            with tarfile.open(archive_path, "w:xz") as archive:
                self._add_directory(archive, "qemu-7.1.0")
                self._add_directory(archive, "qemu-7.1.0/sub")
                self._add_file(archive, "qemu-7.1.0/target", b"target")
                link = tarfile.TarInfo("qemu-7.1.0/sub/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "../target"
                archive.addfile(link)
            output = Path(directory, "output")
            with tarfile.open(archive_path, "r:xz") as archive:
                _safe_extract_archive(archive, output)
            self.assertEqual(os.readlink(output / "qemu-7.1.0" / "sub" / "link"), "../target")

    def test_cached_source_tree_mutation_is_rejected(self) -> None:
        manifest = load_qemu_version_manifest()
        release = manifest.release("qemu-7.1.0")
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-source-cache-") as directory:
            root = Path(directory)
            archive_path = root / release.archive_name
            with tarfile.open(archive_path, "w:xz") as archive:
                self._add_directory(archive, release.source_directory)
                self._add_file(archive, f"{release.source_directory}/VERSION", b"7.1.0\n")
                self._add_file(archive, f"{release.source_directory}/configure", b"#!/bin/sh\n", 0o755)
                self._add_file(archive, f"{release.source_directory}/source.c", b"original\n")
            release = dataclasses.replace(release, source_sha256=_sha256(archive_path))
            sources = root / "sources"
            extracted = _extract(release, archive_path, sources)
            (extracted / "source.c").write_text("changed\n")
            with self.assertRaisesRegex(ProvisionError, "cached source tree"):
                _extract(release, archive_path, sources)


def _compile_probe(zig: str, output: Path, *, add_exec: bool) -> None:
    process = subprocess.run(
        [
            zig,
            "cc",
            "-target",
            "aarch64-linux-none",
            "-nostdlib",
            "-static",
            "-fno-pie",
            "-no-pie",
            "-Wl,-e,_start",
            "-Wl,-z,noexecstack",
            f"-DPWNC_ADD_EXEC={int(add_exec)}",
            "-x",
            "assembler-with-cpp",
            str(_FIXTURE),
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise AssertionError(f"Zig could not link the AArch64 policy probe:\n{process.stdout}\n{process.stderr}")


def _run_probe(binary: Path, fixture: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(binary), str(fixture)],
        capture_output=True,
        timeout=10,
        check=False,
        env=qemu_test_environment(),
    )


@unittest.skipUnless(
    _OPT_IN,
    "set PWNC_QEMU_VERSION_TESTS=1 with exact QEMU 7.1.0 and 7.2.0 binaries",
)
class QemuExecutePermissionBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not sys.platform.startswith("linux"):
            raise AssertionError("the QEMU linux-user policy matrix requires a Linux host")
        cls.zig = shutil.which("zig")
        if cls.zig is None:
            raise AssertionError("the QEMU execute-permission probe requires Zig on PATH")
        cls.manifest = load_qemu_version_manifest()
        cls.attestations = {}
        cls.origins = {}
        for release in cls.manifest.releases:
            resolution = resolve_qemu_binary_with_origin(cls.manifest, release)
            if resolution.origin == "provisioned":
                provisioned = attest_provisioned_qemu_binary(cls.manifest, release, resolution.path)
                attestation = provisioned.binary
                origin = f"provisioned:{provisioned.build_mode}:{provisioned.build_identity}"
            else:
                # An explicit override is useful behavior evidence, but a
                # version banner alone is not exact upstream build provenance.
                attestation = attest_qemu_binary(release, resolution.path)
                origin = "external:behavior-attested"
            cls.attestations[release.id] = attestation
            cls.origins[release.id] = origin
            print(
                f"{release.id}: {attestation.banner}; binary_sha256={attestation.sha256}; origin={origin}",
                file=sys.stderr,
            )

    def test_rw_fetch_changes_at_the_pinned_boundary_but_rx_works_on_both_sides(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-qemu-exec-policy-") as directory:
            root = Path(directory)
            rw = root / "rw-probe"
            rx = root / "rx-probe"
            _compile_probe(self.zig, rw, add_exec=False)
            _compile_probe(self.zig, rx, add_exec=True)

            for executable in (rw, rx):
                profile = inspect_elf(executable)
                self.assertIs(profile.target.arch, Architecture.ARM64)
                self.assertIs(profile.linkage, Linkage.STATIC)
                self.assertTrue(profile.nx)
                self.assertTrue(
                    any(item.executable and item.contains(profile.entry_offset) for item in profile.load_ranges)
                )

            records: dict[str, dict[str, int | str]] = {}
            for release in self.manifest.releases:
                attestation = self.attestations[release.id]
                with self.subTest(release=release.id, banner=attestation.banner, mapping="rw"):
                    rw_result = _run_probe(attestation.path, rw)
                with self.subTest(release=release.id, banner=attestation.banner, mapping="rx"):
                    rx_result = _run_probe(attestation.path, rx)

                self.assertEqual(rx_result.returncode, 42, rx_result.stderr.decode(errors="replace"))
                self.assertEqual(rx_result.stdout, b"")
                if release.execution_policy is ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE:
                    self.assertEqual(rw_result.returncode, 42, rw_result.stderr.decode(errors="replace"))
                else:
                    self.assertIn(rw_result.returncode, {-signal.SIGSEGV, 128 + signal.SIGSEGV})
                self.assertEqual(rw_result.stdout, b"")
                records[release.id] = {
                    "banner": attestation.banner,
                    "rw_returncode": rw_result.returncode,
                    "rx_returncode": rx_result.returncode,
                }
                print(
                    f"{release.id}: rw_returncode={rw_result.returncode}; rx_returncode={rx_result.returncode}",
                    file=sys.stderr,
                )

            self.assertEqual(records["qemu-7.1.0"]["rw_returncode"], 42)
            self.assertNotEqual(records["qemu-7.2.0"]["rw_returncode"], 42)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
