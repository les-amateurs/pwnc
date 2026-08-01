from __future__ import annotations

import io
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from payloads.target import SUPPORTED_TARGETS, resolve_target
from payloads.tests.runtime_support import (
    DEFAULT_GLIBC_LANE,
    ProvisionedSysroot,
    SysrootError,
    UnsupportedSysrootError,
    load_manifest,
    resolve_sysroot,
    validate_provisioned_sysroot,
)
from payloads.tests.runtime_support.sysroots import _safe_extract_tar


class GlibcSysrootManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest()

    def test_full_239_lane_is_every_qemu_runnable_catalog_target(self) -> None:
        ppc32le = resolve_target("powerpc32", endian="little").name
        expected = {target.name for target in SUPPORTED_TARGETS} - {ppc32le}
        actual = {target for (lane, target), _ in self.manifest.by_lane_target.items() if lane == DEFAULT_GLIBC_LANE}
        self.assertEqual(DEFAULT_GLIBC_LANE, "glibc-2.39")
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 20)
        self.assertEqual(
            sum(spec.lane == DEFAULT_GLIBC_LANE for spec in self.manifest.sysroots),
            18,
        )

    def test_arm_and_thumb_share_their_exact_libc_roots(self) -> None:
        for endian in ("little", "big"):
            with self.subTest(endian=endian):
                arm = resolve_sysroot(resolve_target("arm", endian=endian))
                thumb = resolve_sysroot(resolve_target("thumb", endian=endian))
                self.assertIs(arm, thumb)

    def test_ppc32le_is_explicitly_unsupported_not_silently_missing(self) -> None:
        target = resolve_target("powerpc32", endian="little")
        record = self.manifest.unsupported[target.name]
        self.assertFalse(record.upstream_glibc)
        self.assertIn("no standardized upstream", record.reason)
        with self.assertRaisesRegex(UnsupportedSysrootError, "no standardized upstream"):
            self.manifest.resolve(target)

    def test_every_input_is_immutable_https_and_content_pinned(self) -> None:
        artifacts = {artifact for spec in self.manifest.sysroots for artifact in spec.artifacts}
        self.assertGreater(len(artifacts), 30)
        for artifact in artifacts:
            with self.subTest(artifact=artifact.name):
                self.assertTrue(artifact.url.startswith("https://"))
                self.assertEqual(len(artifact.sha256), 64)
                self.assertEqual(set(artifact.sha256) - set("0123456789abcdef"), set())
                self.assertNotIn("latest", artifact.url.lower())
                self.assertTrue(artifact.url.endswith(artifact.name))

    def test_bootlin_artifact_names_encode_exact_release(self) -> None:
        expected_release = {
            "glibc-2.24": "stable-2017.05-toolchains-1-1",
            "glibc-2.39": "stable-2024.05-1",
            "glibc-2.41": "stable-2025.08-1",
        }
        for spec in self.manifest.sysroots:
            if not spec.source.startswith("Bootlin"):
                continue
            artifact = spec.artifacts[0]
            with self.subTest(spec=spec.id):
                self.assertIn(expected_release[spec.lane], artifact.name)
                self.assertIn("toolchains.bootlin.com/downloads/releases/", artifact.url)

    def test_224_bootlin_archives_have_unversioned_internal_tops(self) -> None:
        specs = [spec for spec in self.manifest.sysroots if spec.lane == "glibc-2.24"]
        self.assertTrue(specs)
        for spec in specs:
            artifact = spec.artifacts[0]
            slug, separator, _ = artifact.name.partition("--glibc--stable-")
            with self.subTest(spec=spec.id):
                self.assertEqual(separator, "--glibc--stable-")
                self.assertEqual(spec.extraction_top, f"{slug}--glibc--stable")
                self.assertNotEqual(artifact.name.removesuffix(".tar.bz2"), spec.extraction_top)

    def test_noble_mips64_roots_are_real_n64_not_bootlin_n32(self) -> None:
        for endian in ("little", "big"):
            spec = resolve_sysroot(resolve_target("mips64", endian=endian))
            with self.subTest(endian=endian):
                self.assertEqual(spec.elf.elf_class, 64)
                self.assertEqual(spec.loader, "lib64/ld.so.1")
                self.assertEqual(spec.compiler.kind, "zig")
                self.assertIn("gnuabi64", spec.compiler.target or "")
                self.assertTrue(all("archive.ubuntu.com" in item.url for item in spec.artifacts))
                self.assertTrue(any("linux-libc-dev" in item.name for item in spec.artifacts))

    def test_sparc32_records_v8plus_emulator_and_real_multilib_root(self) -> None:
        spec = resolve_sysroot("sparc32")
        self.assertEqual(spec.qemu, "qemu-sparc32plus")
        self.assertEqual(spec.loader, "lib32/ld-linux.so.2")
        self.assertEqual(spec.libc, "lib32/libc.so.6")
        self.assertEqual((spec.elf.elf_class, spec.elf.machine), (32, 2))
        self.assertEqual(spec.compiler.argv, ("sparc64-linux-gnu-gcc", "-m32"))

    def test_ppc64_roots_attest_elfv1_and_elfv2_e_flags(self) -> None:
        big = resolve_sysroot(resolve_target("ppc64"))
        little = resolve_sysroot(resolve_target("ppc64le"))
        self.assertEqual((big.elf.flags_mask, big.elf.flags_value), (3, 1))
        self.assertEqual((little.elf.flags_mask, little.elf.flags_value), (3, 2))
        self.assertEqual(big.loader, "lib/ld64.so.1")
        self.assertEqual(little.loader, "lib/ld64.so.2")

    def test_223_lane_is_exact_canonical_xenial_legacy_libc(self) -> None:
        spec = self.manifest.resolve("x86_64", "glibc-2.23")
        self.assertEqual(spec.glibc_version, "2.23-0ubuntu11.3")
        self.assertEqual(len(spec.artifacts), 3)
        self.assertEqual(
            {artifact.name.split("_", 1)[0] for artifact in spec.artifacts},
            {"libc6", "libc6-dev", "libc-dev-bin"},
        )
        self.assertTrue(all("launchpadlibrarian.net" in artifact.url for artifact in spec.artifacts))
        self.assertEqual(spec.version_marker, "stable release version 2.23")
        self.assertEqual(spec.compiler.target, "x86_64-linux-gnu.2.23")

    def test_224_and_241_lanes_cover_every_word_size_and_endian_pair(self) -> None:
        expected = {(32, "little"), (32, "big"), (64, "little"), (64, "big")}
        for lane in ("glibc-2.24", "glibc-2.41"):
            specs = [spec for spec in self.manifest.sysroots if spec.lane == lane]
            with self.subTest(lane=lane):
                self.assertEqual({(spec.elf.elf_class, spec.elf.endian) for spec in specs}, expected)
                self.assertTrue(all(spec.glibc_version.startswith(lane.removeprefix("glibc-")) for spec in specs))

    def test_224_lane_covers_validation_boundary_and_ppc_call_models(self) -> None:
        targets = {target for (lane, target), _ in self.manifest.by_lane_target.items() if lane == "glibc-2.24"}
        self.assertIn(resolve_target("ppc64").name, targets)
        self.assertIn(resolve_target("ppc64le").name, targets)
        self.assertNotIn(resolve_target("mips64").name, targets)
        self.assertNotIn(resolve_target("riscv32").name, targets)
        with self.assertRaisesRegex(UnsupportedSysrootError, "no glibc-2.24"):
            self.manifest.resolve("mips64", "glibc-2.24")

    def test_241_lane_covers_flags2_layout_and_riscv32(self) -> None:
        specs = [spec for spec in self.manifest.sysroots if spec.lane == "glibc-2.41"]
        self.assertTrue(all(spec.version_marker == "stable release version 2.41" for spec in specs))
        self.assertIsNotNone(self.manifest.resolve("riscv32", "glibc-2.41"))

    def test_missing_representative_lane_is_an_explicit_error(self) -> None:
        with self.assertRaisesRegex(UnsupportedSysrootError, "no glibc-2.23"):
            self.manifest.resolve("aarch64", "glibc-2.23")

    def test_manifest_mappings_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            self.manifest.unsupported["new"] = next(iter(self.manifest.unsupported.values()))  # type: ignore[index]
        with self.assertRaises(TypeError):
            self.manifest.by_lane_target[("new", "new")] = self.manifest.sysroots[0]  # type: ignore[index]


class GlibcSysrootArtifactValidationTests(unittest.TestCase):
    def test_exact_elf_identity_and_version_marker_are_required(self) -> None:
        spec = resolve_sysroot("x86_64")
        with tempfile.TemporaryDirectory(prefix="pwnc-sysroot-unit-") as directory:
            sysroot = Path(directory)
            libc = sysroot / spec.libc
            loader = sysroot / spec.loader
            libc.parent.mkdir(parents=True)
            loader.parent.mkdir(parents=True, exist_ok=True)
            image = _minimal_elf(64, "little", 62, 0) + spec.version_marker.encode()
            libc.write_bytes(image)
            loader.write_bytes(image)
            provisioned = ProvisionedSysroot(spec, sysroot, sysroot, libc, loader)
            validate_provisioned_sysroot(provisioned)

            libc.write_bytes(_minimal_elf(64, "little", 21, 0) + spec.version_marker.encode())
            with self.assertRaisesRegex(SysrootError, "expected e_machine 62"):
                validate_provisioned_sysroot(provisioned)

    def test_ppc64_abi_flag_mismatch_is_rejected(self) -> None:
        spec = resolve_sysroot("ppc64")
        with tempfile.TemporaryDirectory(prefix="pwnc-sysroot-unit-") as directory:
            sysroot = Path(directory)
            libc = sysroot / spec.libc
            loader = sysroot / spec.loader
            libc.parent.mkdir(parents=True)
            loader.parent.mkdir(parents=True, exist_ok=True)
            wrong_elfv2 = _minimal_elf(64, "big", 21, 2) + spec.version_marker.encode()
            libc.write_bytes(wrong_elfv2)
            loader.write_bytes(wrong_elfv2)
            provisioned = ProvisionedSysroot(spec, sysroot, sysroot, libc, loader)
            with self.assertRaisesRegex(SysrootError, "does not match mask"):
                validate_provisioned_sysroot(provisioned)

    def test_python311_tar_fallback_rejects_escape_links_and_special_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-sysroot-unit-") as directory:
            base = Path(directory)
            for name, configure in (
                ("escape.tar", lambda member: setattr(member, "linkname", "../../outside")),
                ("fifo.tar", lambda member: setattr(member, "type", tarfile.FIFOTYPE)),
            ):
                archive_path = base / name
                with tarfile.open(archive_path, "w") as archive:
                    member = tarfile.TarInfo("sdk/link")
                    member.type = tarfile.SYMTYPE
                    configure(member)
                    archive.addfile(member)
                with (
                    tarfile.open(archive_path) as archive,
                    mock.patch.object(tarfile, "data_filter", None),
                    self.assertRaises(SysrootError),
                ):
                    _safe_extract_tar(archive, base / f"extract-{name}")

    def test_python311_tar_fallback_accepts_a_bounded_relative_sdk_link(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-sysroot-unit-") as directory:
            base = Path(directory)
            archive_path = base / "safe.tar"
            with tarfile.open(archive_path, "w") as archive:
                library = tarfile.TarInfo("sdk/lib/ld.so")
                data = b"loader"
                library.size = len(data)
                archive.addfile(library, io.BytesIO(data))
                link = tarfile.TarInfo("sdk/usr/bin/ld.so")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../lib/ld.so"
                archive.addfile(link)
            destination = base / "extract"
            with tarfile.open(archive_path) as archive, mock.patch.object(tarfile, "data_filter", None):
                _safe_extract_tar(archive, destination)
            self.assertEqual((destination / "sdk/usr/bin/ld.so").read_bytes(), b"loader")

    def test_python311_tar_fallback_rejects_member_order_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-sysroot-unit-") as directory:
            base = Path(directory)
            archive_path = base / "symlink-chain.tar"
            with tarfile.open(archive_path, "w") as archive:
                pivot = tarfile.TarInfo("sdk/pivot")
                pivot.type = tarfile.SYMTYPE
                pivot.linkname = ".."
                archive.addfile(pivot)

                escape = tarfile.TarInfo("sdk/pivot/link")
                escape.type = tarfile.SYMTYPE
                escape.linkname = "../outside"
                archive.addfile(escape)

                payload = tarfile.TarInfo("sdk/pivot/link/payload")
                data = b"escaped"
                payload.size = len(data)
                archive.addfile(payload, io.BytesIO(data))

            outside = base / "outside"
            outside.mkdir()
            destination = base / "extract"
            with (
                tarfile.open(archive_path) as archive,
                mock.patch.object(tarfile, "data_filter", None),
                self.assertRaisesRegex(SysrootError, "outside destination"),
            ):
                _safe_extract_tar(archive, destination)
            self.assertFalse((outside / "payload").exists())


def _minimal_elf(elf_class: int, endian: str, machine: int, flags: int) -> bytes:
    header = bytearray(64)
    header[:6] = b"\x7fELF" + bytes((1 if elf_class == 32 else 2, 1 if endian == "little" else 2))
    order = "<" if endian == "little" else ">"
    struct.pack_into(f"{order}H", header, 18, machine)
    struct.pack_into(f"{order}I", header, 36 if elf_class == 32 else 48, flags)
    return bytes(header)


if __name__ == "__main__":
    unittest.main()
