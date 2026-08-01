from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from payloads import (
    Architecture,
    ELFImageKind,
    ELFInspectionError,
    ELFProfile,
    ELFRange,
    ExecutionPolicy,
    LibcImage,
    Linkage,
    Permission,
    Relro,
    inspect_elf,
    load_elf_profile,
    resolve_target,
)
from payloads.tests.test_shellcode import PRIMARY_TARGETS
from payloads.tests.test_shellcode_qemu import _link_raw_payload


def _mutate_program_header(source: Path, destination: Path, predicate, changes) -> None:
    raw = bytearray(source.read_bytes())
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:  # pragma: no cover - project dependency
        raise unittest.SkipTest(str(exc)) from exc
    elf = ELFFile(BytesIO(raw))
    layouts = {
        32: {
            "p_type": (0, 4),
            "p_offset": (4, 4),
            "p_vaddr": (8, 4),
            "p_paddr": (12, 4),
            "p_filesz": (16, 4),
            "p_memsz": (20, 4),
            "p_flags": (24, 4),
            "p_align": (28, 4),
        },
        64: {
            "p_type": (0, 4),
            "p_flags": (4, 4),
            "p_offset": (8, 8),
            "p_vaddr": (16, 8),
            "p_paddr": (24, 8),
            "p_filesz": (32, 8),
            "p_memsz": (40, 8),
            "p_align": (48, 8),
        },
    }
    byte_order = "little" if elf.little_endian else "big"
    for index, segment in enumerate(elf.iter_segments()):
        if not predicate(segment):
            continue
        values = changes(segment.header, elf.elfclass, len(raw))
        base = int(elf.header.e_phoff) + index * int(elf.header.e_phentsize)
        for name, value in values.items():
            relative, width = layouts[elf.elfclass][name]
            raw[base + relative : base + relative + width] = int(value).to_bytes(width, byte_order)
        destination.write_bytes(raw)
        return
    raise AssertionError("matching program header was not found")


def _mutate_elf_flags(source: Path, destination: Path, flags: int) -> None:
    raw = bytearray(source.read_bytes())
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:  # pragma: no cover - project dependency
        raise unittest.SkipTest(str(exc)) from exc
    elf = ELFFile(BytesIO(raw))
    offset = 36 if elf.elfclass == 32 else 48
    byte_order = "little" if elf.little_endian else "big"
    raw[offset : offset + 4] = flags.to_bytes(4, byte_order)
    destination.write_bytes(raw)


class InvalidELFTests(unittest.TestCase):
    def test_non_elf_and_truncated_elf_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pwnc-elf-invalid-") as directory:
            text = Path(directory, "text")
            text.write_bytes(b"this is not an ELF")
            with self.assertRaisesRegex(ELFInspectionError, "not an ELF"):
                inspect_elf(text)

            truncated = Path(directory, "truncated")
            truncated.write_bytes(b"\x7fELF" + b"\0" * 12)
            with self.assertRaisesRegex(ELFInspectionError, "malformed|unable to inspect"):
                inspect_elf(truncated)

    def test_missing_file_has_stable_domain_error(self) -> None:
        with self.assertRaisesRegex(ELFInspectionError, "unable to read ELF artifact"):
            inspect_elf("/definitely/not/a/pwnc/fixture")

    def test_malformed_load_ranges_are_rejected_before_profiling(self) -> None:
        source = Path("/bin/true")
        if not source.is_file():
            self.skipTest("/bin/true is unavailable")
        with tempfile.TemporaryDirectory(prefix="pwnc-elf-malformed-") as directory:
            root = Path(directory)

            file_larger_than_memory = root / "filesz-over-memsz"
            _mutate_program_header(
                source,
                file_larger_than_memory,
                lambda segment: str(segment.header.p_type) == "PT_LOAD" and int(segment.header.p_filesz) > 0,
                lambda header, _bits, _artifact_size: {"p_memsz": int(header.p_filesz) - 1},
            )
            with self.assertRaisesRegex(ELFInspectionError, "file size exceeds"):
                inspect_elf(file_larger_than_memory)

            outside_file = root / "outside-file"
            _mutate_program_header(
                source,
                outside_file,
                lambda segment: str(segment.header.p_type) == "PT_LOAD" and int(segment.header.p_filesz) > 0,
                lambda header, _bits, artifact_size: {
                    "p_offset": artifact_size,
                    "p_filesz": 1,
                    "p_memsz": max(1, int(header.p_memsz)),
                },
            )
            with self.assertRaisesRegex(ELFInspectionError, "beyond the artifact"):
                inspect_elf(outside_file)

            bad_alignment = root / "bad-alignment"
            _mutate_program_header(
                source,
                bad_alignment,
                lambda segment: str(segment.header.p_type) == "PT_LOAD",
                lambda _header, _bits, _artifact_size: {"p_align": 3},
            )
            with self.assertRaisesRegex(ELFInspectionError, "not a power of two"):
                inspect_elf(bad_alignment)

            address_overflow = root / "address-overflow"

            def overflow_changes(header, bits, _artifact_size):
                alignment = max(0x1000, int(header.p_align))
                start = (1 << bits) - alignment + int(header.p_offset) % alignment
                return {
                    "p_vaddr": start,
                    "p_memsz": max(int(header.p_filesz), 2 * alignment),
                }

            _mutate_program_header(
                source,
                address_overflow,
                lambda segment: str(segment.header.p_type) == "PT_LOAD" and bool(int(segment.header.p_flags) & 2),
                overflow_changes,
            )
            with self.assertRaisesRegex(ELFInspectionError, "address space"):
                inspect_elf(address_overflow)


class CompilerELFFixtures(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    directory: Path
    fixtures: dict[str, Path]
    static_pie: Path | None
    ambiguous_dynamic: Path | None

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise unittest.SkipTest("a host C compiler is required for ELF fixture tests")
        cls.temporary = tempfile.TemporaryDirectory(prefix="pwnc-elf-fixtures-")
        cls.directory = Path(cls.temporary.name)
        source = cls.directory / "fixture.c"
        source.write_text(
            "#include <stdio.h>\n"
            "int writable_global = 3;\n"
            "int exported(void) { return writable_global; }\n"
            'int main(void) { return puts("fixture"); }\n'
        )

        variants = {
            "nonpie_partial": ("-fno-pie", "-no-pie", "-Wl,-z,relro", "-Wl,-z,lazy"),
            "pie_full": ("-fPIE", "-pie", "-Wl,-z,relro", "-Wl,-z,now"),
            "nonpie_none": ("-fno-pie", "-no-pie", "-Wl,-z,norelro"),
            "execstack": ("-fno-pie", "-no-pie", "-Wl,-z,execstack"),
        }
        cls.fixtures = {}
        for name, flags in variants.items():
            output = cls.directory / name
            result = subprocess.run(
                [compiler, str(source), "-o", str(output), "-Wl,--build-id", *flags],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode:
                raise unittest.SkipTest(f"host compiler cannot build {name}: {result.stderr.strip()}")
            cls.fixtures[name] = output

        shared = cls.directory / "fixture.so"
        result = subprocess.run(
            [
                compiler,
                str(source),
                "-o",
                str(shared),
                "-shared",
                "-fPIC",
                "-Wl,-soname,fixture.so",
                "-Wl,-z,relro",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise unittest.SkipTest(f"host compiler cannot build shared fixture: {result.stderr.strip()}")
        cls.fixtures["shared"] = shared

        ambiguous_dynamic = cls.directory / "ambiguous.so"
        result = subprocess.run(
            [
                compiler,
                str(source),
                "-o",
                str(ambiguous_dynamic),
                "-shared",
                "-fPIC",
                "-nostdlib",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        cls.ambiguous_dynamic = ambiguous_dynamic if result.returncode == 0 else None

        static_pie = cls.directory / "static_pie"
        result = subprocess.run(
            [
                compiler,
                str(source),
                "-o",
                str(static_pie),
                "-static-pie",
                "-Wl,-z,relro",
                "-Wl,-z,now",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        cls.static_pie = static_pie if result.returncode == 0 else None

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def profile(self, name: str) -> ELFProfile:
        return inspect_elf(self.fixtures[name])

    def test_exact_identity_target_and_immutable_runtime_ranges(self) -> None:
        path = self.fixtures["nonpie_partial"]
        profile = ELFProfile.from_file(path)
        self.assertEqual(profile.sha256, hashlib.sha256(path.read_bytes()).hexdigest())
        if profile.build_id is not None:
            self.assertRegex(profile.build_id, r"\A[0-9a-f]+\Z")
            self.assertEqual(len(profile.build_id) % 2, 0)
        self.assertIn(profile.target.bits, {32, 64})
        self.assertGreater(len(profile.load_ranges), 1)
        self.assertTrue(any(item.executable for item in profile.load_ranges))
        self.assertTrue(any(item.writable for item in profile.load_ranges))
        self.assertTrue(all(item.kind == "PT_LOAD" for item in profile.load_ranges))
        with self.assertRaises(TypeError):
            profile.symbol_offsets["new"] = 1  # type: ignore[index]
        with self.assertRaisesRegex(Exception, "cannot assign"):
            profile.pie = True  # type: ignore[misc]
        self.assertEqual(load_elf_profile(path), profile)

    def test_pie_nonpie_and_shared_object_are_distinguished(self) -> None:
        nonpie = self.profile("nonpie_partial")
        pie = self.profile("pie_full")
        shared = self.profile("shared")

        self.assertEqual((nonpie.elf_type, nonpie.image_kind, nonpie.pie), ("ET_EXEC", ELFImageKind.EXECUTABLE, False))
        self.assertEqual(nonpie.linkage, Linkage.DYNAMIC)
        self.assertTrue(nonpie.is_main_executable)

        self.assertEqual((pie.elf_type, pie.image_kind, pie.pie), ("ET_DYN", ELFImageKind.PIE_EXECUTABLE, True))
        self.assertEqual(pie.linkage, Linkage.DYNAMIC)
        self.assertTrue(pie.is_main_executable)

        self.assertEqual(shared.image_kind, ELFImageKind.SHARED_OBJECT)
        self.assertTrue(shared.pie)
        self.assertEqual(shared.linkage, Linkage.DYNAMIC)
        self.assertTrue(shared.is_shared_object)
        self.assertFalse(shared.is_main_executable)
        self.assertEqual(shared.soname, "fixture.so")

    def test_soname_outweighs_interpreter_for_dual_role_libc_images(self) -> None:
        with patch("payloads.elf._interpreter", return_value="/lib/pwnc-test-loader"):
            shared = self.profile("shared")
        self.assertEqual(shared.image_kind, ELFImageKind.SHARED_OBJECT)
        self.assertEqual(shared.linkage, Linkage.DYNAMIC)
        self.assertTrue(shared.is_shared_object)

    def test_ambiguous_et_dyn_requires_external_linkage_evidence(self) -> None:
        if self.ambiguous_dynamic is None:
            self.skipTest("host compiler cannot build an unclassified ET_DYN fixture")
        profile = inspect_elf(self.ambiguous_dynamic)
        self.assertEqual(profile.image_kind, ELFImageKind.ET_DYN_AMBIGUOUS)
        self.assertIsNone(profile.linkage)
        self.assertIsNone(profile.is_main_executable)
        with self.assertRaisesRegex(ELFInspectionError, "role/linkage is ambiguous"):
            profile.to_mitigations(ExecutionPolicy.ELF_PERMISSIONS)
        mitigations = profile.to_mitigations(
            ExecutionPolicy.ELF_PERMISSIONS,
            linkage_if_unknown=Linkage.DYNAMIC,
        )
        self.assertEqual(mitigations.linkage, Linkage.DYNAMIC)

    @unittest.skipUnless(
        shutil.which("llvm-mc") and shutil.which("ld.lld"),
        "LLVM/LLD are required for cross-target ELF inspection",
    )
    def test_cross_linked_primary_targets_resolve_exact_bits_endian_abi_and_entry_state(self) -> None:
        for architecture, endian in PRIMARY_TARGETS:
            expected = resolve_target(architecture, endian=endian)
            with self.subTest(target=expected.name), tempfile.TemporaryDirectory(prefix="pwnc-elf-cross-") as directory:
                executable = Path(directory, "minimal.elf")
                _link_raw_payload(b"\0\0\0\0", expected, executable)
                profile = inspect_elf(executable)
                self.assertEqual(profile.target, expected)
                self.assertEqual(profile.linkage, Linkage.STATIC)
                self.assertEqual(profile.image_kind, ELFImageKind.EXECUTABLE)

    @unittest.skipUnless(
        shutil.which("llvm-mc") and shutil.which("ld.lld"),
        "LLVM/LLD are required for RISC-V ELF inspection",
    )
    def test_riscv_embedded_register_abi_is_rejected(self) -> None:
        target = resolve_target("riscv32")
        with tempfile.TemporaryDirectory(prefix="pwnc-elf-rve-") as directory:
            executable = Path(directory, "standard.elf")
            embedded = Path(directory, "embedded.elf")
            _link_raw_payload(b"\0\0\0\0", target, executable)
            profile = inspect_elf(executable)
            self.assertEqual(profile.target, target)
            _mutate_elf_flags(executable, embedded, 0x8)
            with self.assertRaisesRegex(ELFInspectionError, "E/ILP32E"):
                inspect_elf(embedded)

    def test_static_pie_is_not_mislabeled_as_shared_object(self) -> None:
        if self.static_pie is None:
            self.skipTest("host compiler cannot build -static-pie")
        profile = inspect_elf(self.static_pie)
        self.assertEqual(profile.elf_type, "ET_DYN")
        self.assertEqual(profile.image_kind, ELFImageKind.STATIC_PIE)
        self.assertTrue(profile.pie)
        self.assertTrue(profile.is_static_pie)
        self.assertFalse(profile.is_shared_object)
        self.assertEqual(profile.linkage, Linkage.STATIC)
        self.assertIsNone(profile.interpreter)
        self.assertEqual(profile.needed_libraries, ())

    def test_relro_variants_and_bind_now_match_linker_inputs(self) -> None:
        none = self.profile("nonpie_none")
        partial = self.profile("nonpie_partial")
        full = self.profile("pie_full")
        self.assertEqual((none.relro, none.bind_now, none.relro_ranges), (Relro.NONE, False, ()))
        self.assertEqual((partial.relro, partial.bind_now), (Relro.PARTIAL, False))
        self.assertGreater(len(partial.relro_ranges), 0)
        self.assertEqual((full.relro, full.bind_now), (Relro.FULL, True))
        self.assertGreater(len(full.relro_ranges), 0)

    def test_symbols_got_plt_and_post_relro_writability(self) -> None:
        partial = self.profile("nonpie_partial")
        full = self.profile("pie_full")
        self.assertIn("main", partial.symbol_offsets)
        self.assertIn("writable_global", partial.symbol_offsets)
        self.assertFalse(partial.is_writable_after_relro(partial.symbol_offsets["main"], runtime_page_size=0x1000))
        self.assertFalse(partial.is_writable_after_relro(partial.symbol_offsets["writable_global"], 4))
        self.assertTrue(
            partial.is_writable_after_relro(
                partial.symbol_offsets["writable_global"],
                4,
                runtime_page_size=0x1000,
            )
        )
        self.assertFalse(partial.is_writable_after_relro(partial.target.mask + 1, runtime_page_size=0x1000))

        self.assertIn("puts", partial.got_offsets)
        self.assertIn("puts", full.got_offsets)
        self.assertFalse(partial.got_slot_writable("puts"))
        self.assertTrue(partial.got_slot_writable("puts", runtime_page_size=0x1000))
        self.assertFalse(full.got_slot_writable("puts", runtime_page_size=0x1000))
        with self.assertRaisesRegex(KeyError, "no unambiguous GOT slot"):
            full.got_slot_writable("definitely_absent")

        if partial.target.arch in {Architecture.X86, Architecture.X86_64}:
            self.assertIn("puts", partial.plt_offsets)
            self.assertFalse(partial.is_writable_after_relro(partial.plt_offsets["puts"], runtime_page_size=0x1000))

    def test_runtime_page_size_not_load_alignment_controls_relro_answers(self) -> None:
        base = self.profile("nonpie_partial")
        synthetic = replace(
            base,
            load_ranges=(
                ELFRange(
                    0x10000,
                    0x40000,
                    Permission.READ | Permission.WRITE,
                    0,
                    0,
                    0x1000,
                    "PT_LOAD",
                ),
            ),
            relro_ranges=(ELFRange(0x12000, 0x23000, Permission.READ, 0, 0, 1, "PT_GNU_RELRO"),),
            load_alignment_hint=0x1000,
            got_offsets={"slot": 0x11000},
        )
        self.assertFalse(synthetic.got_slot_writable("slot"))
        self.assertTrue(synthetic.got_slot_writable("slot", runtime_page_size=0x1000))
        self.assertFalse(synthetic.got_slot_writable("slot", runtime_page_size=0x10000))
        with self.assertRaisesRegex(ValueError, "positive power of two"):
            synthetic.got_slot_writable("slot", runtime_page_size=3000)

    def test_libc_image_uses_the_same_exact_nonexecuting_profile(self) -> None:
        path = self.fixtures["shared"]
        profile = inspect_elf(path)
        image = LibcImage.from_file(path, symbols=("exported",), distro="fixture", package_release="1")

        self.assertEqual(image.identity.sha256, profile.sha256)
        self.assertEqual(image.identity.build_id, profile.build_id)
        self.assertEqual(image.target, profile.target)
        self.assertEqual(image.offset("exported"), profile.symbol_offsets["exported"])
        self.assertEqual((image.identity.distro, image.identity.package_release), ("fixture", "1"))

    def test_nx_exec_stack_and_mitigations_are_evidence_driven(self) -> None:
        normal = self.profile("nonpie_partial")
        executable = self.profile("execstack")
        self.assertTrue(normal.nx)
        self.assertFalse(normal.executable_stack)
        self.assertIn("without execute", normal.nx_evidence)
        self.assertFalse(executable.nx)
        self.assertTrue(executable.executable_stack)
        self.assertIn("requests execute", executable.nx_evidence)

        mitigations = normal.to_mitigations(ExecutionPolicy.QEMU_ELF_PERMISSIONS)
        self.assertEqual(mitigations.pie, normal.pie)
        self.assertEqual(mitigations.nx, normal.nx)
        self.assertEqual(mitigations.relro, Relro.PARTIAL)
        self.assertEqual(mitigations.linkage, Linkage.DYNAMIC)
        self.assertEqual(mitigations.execution_policy, ExecutionPolicy.QEMU_ELF_PERMISSIONS)

    def test_absent_gnu_stack_remains_unknown_until_caller_override(self) -> None:
        source = self.fixtures["nonpie_partial"]
        raw = bytearray(source.read_bytes())
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:  # pragma: no cover - project dependency
            self.skipTest(str(exc))
        elf = ELFFile(BytesIO(raw))
        header_offset = int(elf.header.e_phoff)
        header_size = int(elf.header.e_phentsize)
        byte_order = "little" if elf.little_endian else "big"
        found = False
        for index, segment in enumerate(elf.iter_segments()):
            if str(segment.header.p_type) != "PT_GNU_STACK":
                continue
            offset = header_offset + index * header_size
            raw[offset : offset + 4] = (0).to_bytes(4, byte_order)
            found = True
        if not found:
            self.skipTest("host linker did not emit PT_GNU_STACK")

        path = self.directory / "without_gnu_stack"
        path.write_bytes(raw)
        profile = inspect_elf(path)
        self.assertIsNone(profile.nx)
        self.assertIsNone(profile.executable_stack)
        self.assertIn("absent", profile.nx_evidence)
        with self.assertRaisesRegex(ELFInspectionError, "PT_GNU_STACK is absent"):
            profile.to_mitigations(ExecutionPolicy.ELF_PERMISSIONS)
        assumed = profile.to_mitigations(
            ExecutionPolicy.ELF_PERMISSIONS,
            nx_if_unknown=True,
        )
        self.assertTrue(assumed.nx)


if __name__ == "__main__":
    unittest.main()
