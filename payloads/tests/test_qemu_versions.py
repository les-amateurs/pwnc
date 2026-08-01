"""Pinned old/new QEMU linux-user execute-permission tests.

Run the execution class after provisioning both exact releases::

    python3 -m payloads.tests.provision_qemu_versions --root /tmp/pwnc-qemu
    PWNC_QEMU_VERSION_ROOT=/tmp/pwnc-qemu PWNC_QEMU_VERSION_TESTS=1 \
        python3 -m unittest payloads.tests.test_qemu_versions -v
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from payloads import Architecture, ExecutionPolicy, Linkage, inspect_elf
from payloads.tests.qemu_version_matrix import (
    QemuVersionMatrixError,
    attest_qemu_binary,
    load_qemu_version_manifest,
    qemu_test_environment,
    resolve_qemu_binary,
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
        for release in cls.manifest.releases:
            binary = resolve_qemu_binary(cls.manifest, release)
            attestation = attest_qemu_binary(release, binary)
            cls.attestations[release.id] = attestation
            print(
                f"{release.id}: {attestation.banner}; binary_sha256={attestation.sha256}",
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
