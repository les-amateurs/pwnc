from __future__ import annotations

import shutil
import unittest

from payloads import (
    SUPPORTED_TARGETS,
    LLVMAssembler,
    command_shellcode,
    command_source,
    exit_shellcode,
    exit_source,
    mmap_stager,
    mmap_stager_source,
    orw_shellcode,
    orw_source,
    resolve_target,
)

PRIMARY_TARGETS = (
    ("x86", None),
    ("x86_64", None),
    ("arm", "little"),
    ("arm", "big"),
    ("thumb", "little"),
    ("thumb", "big"),
    ("arm64", "little"),
    ("arm64", "big"),
    ("mips32", "little"),
    ("mips32", "big"),
    ("mips64", "little"),
    ("mips64", "big"),
    ("riscv32", None),
    ("riscv64", None),
)

EXTRA_SHELLCODE_TARGETS = (
    ("powerpc32", "big"),
    ("powerpc32", "little"),
    ("powerpc64", "big"),
    ("powerpc64", "little"),
    ("sparc32", None),
    ("sparc64", None),
    ("s390x", None),
)

SHELLCODE_TARGETS = PRIMARY_TARGETS + EXTRA_SHELLCODE_TARGETS


class CommandSourceTests(unittest.TestCase):
    def test_implemented_shellcode_matrix_is_catalog_exact(self) -> None:
        implemented = {resolve_target(architecture, endian=endian).name for architecture, endian in SHELLCODE_TARGETS}
        self.assertEqual(implemented, {target.name for target in SUPPORTED_TARGETS})

    def test_all_implemented_targets_lower_without_pwntools_shellcraft(self) -> None:
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                source, stack_size = command_source("printf pwnc", target)
                self.assertIn("_start:", source)
                self.assertGreater(stack_size, len("printf pwnc"))
                self.assertEqual(stack_size % target.convention.stack_alignment, 0)

    def test_command_validation(self) -> None:
        target = resolve_target("x86_64")
        with self.assertRaises(ValueError):
            command_source("", target)
        with self.assertRaises(ValueError):
            command_source(b"bad\0command", target)
        with self.assertRaises(ValueError):
            command_source("A" * 1800, target)


class OrwSourceTests(unittest.TestCase):
    def test_all_implemented_targets_lower(self) -> None:
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                source, stack_size = orw_source("/flag", target, max_bytes=257)
                self.assertIn("_start:", source)
                self.assertGreaterEqual(stack_size, 257 + len("/flag") + 1)

    def test_orw_validation(self) -> None:
        target = resolve_target("x86_64")
        with self.assertRaises(ValueError):
            orw_source("", target)
        with self.assertRaises(ValueError):
            orw_source(b"/bad\0path", target)
        with self.assertRaises(ValueError):
            orw_source("/flag", target, max_bytes=0)
        with self.assertRaises(ValueError):
            orw_source("/flag", target, output_fd=0x10000)


class StagerSourceTests(unittest.TestCase):
    def test_exit_and_stager_lower_for_all_implemented_targets(self) -> None:
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                child_source = exit_source(42, target)
                stage_source, map_size = mmap_stager_source(123, target)
                self.assertIn("_start:", child_source)
                self.assertIn(".Lstage_read:", stage_source)
                self.assertEqual(map_size, 0x1000)

    def test_stager_validation(self) -> None:
        target = resolve_target("x86_64")
        with self.assertRaises(ValueError):
            exit_source(256, target)
        with self.assertRaises(ValueError):
            mmap_stager_source(0, target)
        with self.assertRaises(ValueError):
            mmap_stager_source(1, target, page_size=3000)
        with self.assertRaises(ValueError):
            mmap_stager_source(1, target, input_fd=0x10000)
        with self.assertRaises(ValueError):
            mmap_stager_source(1, resolve_target("x86"), page_size=1 << 32)


@unittest.skipUnless(shutil.which("llvm-mc"), "llvm-mc is not installed")
class CommandAssemblyTests(unittest.TestCase):
    def test_all_implemented_targets_assemble_to_relocation_free_bytes(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                payload = command_shellcode("printf pwnc", target, assembler=assembler)
                self.assertGreater(len(payload.data), 8)
                self.assertEqual(payload.metadata["operation"], "run-command")
                self.assertTrue(payload.metadata["position_independent"])

    def test_orw_assembles_for_all_implemented_targets(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                payload = orw_shellcode("/flag", target, max_bytes=257, assembler=assembler)
                self.assertGreater(len(payload.data), 8)
                self.assertEqual(payload.metadata["operation"], "open-read-write")

    def test_exit_and_rw_to_rx_stager_assemble_for_all_implemented_targets(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                child = exit_shellcode(42, target, assembler=assembler)
                stager = mmap_stager(len(child.data), target, assembler=assembler)
                self.assertEqual(stager.metadata["mapping_transition"], "rw-to-rx")
                self.assertTrue(stager.metadata["exact_read_loop"])

    def test_64_bit_stagers_materialize_large_mapping_sizes(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in (("sparc64", None), ("s390x", None), ("powerpc64", "little")):
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                payload = mmap_stager(1, target, page_size=1 << 40, assembler=assembler)
                self.assertEqual(payload.metadata["mapping_size"], 1 << 40)

    def test_s390x_instruction_alignment_and_cache_metadata(self) -> None:
        target = resolve_target("s390x")
        child = exit_shellcode(42, target)
        stager = mmap_stager(len(child.data), target)
        self.assertEqual(child.memory[0].alignment, 2)
        self.assertFalse(child.metadata["requires_instruction_cache_sync_after_runtime_write"])
        self.assertTrue(stager.metadata["instruction_cache_finalized"])
        self.assertFalse(stager.metadata["requires_instruction_cache_sync_after_runtime_write"])


if __name__ == "__main__":
    unittest.main()
