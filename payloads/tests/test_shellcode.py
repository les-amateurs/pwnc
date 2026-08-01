from __future__ import annotations

import shutil
import unittest

from payloads import (
    SUPPORTED_TARGETS,
    LLVMAssembler,
    UnsupportedTargetError,
    command_shellcode,
    command_source,
    exit_shellcode,
    exit_source,
    mmap_stager,
    mmap_stager_source,
    orw_shellcode,
    orw_source,
    qemu_semihosting_command_shellcode,
    qemu_semihosting_command_source,
    resolve_target,
)
from payloads.shellcode import sendfile_orw_shellcode, sendfile_orw_source

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

QEMU_USER_SEMIHOSTING_TARGETS = (
    ("arm", "little"),
    ("arm", "big"),
    ("thumb", "little"),
    ("thumb", "big"),
    ("arm64", "little"),
    ("arm64", "big"),
    ("riscv32", None),
    ("riscv64", None),
)


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


class SendfileOrwSourceTests(unittest.TestCase):
    def test_all_catalog_targets_lower_without_a_read_buffer(self) -> None:
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                source, stack_size = sendfile_orw_source("/flag", target, count=257)
                _, buffered_stack_size = orw_source("/flag", target, max_bytes=257)
                self.assertIn("_start:", source)
                self.assertIn(".Lsendfile_fail:", source)
                self.assertEqual(stack_size % target.convention.stack_alignment, 0)
                self.assertLess(stack_size, buffered_stack_size)

    def test_source_uses_exact_linux_sendfile_syscall_numbers(self) -> None:
        expected = {
            "x86": 187,
            "x86_64": 40,
            "arm": 187,
            "thumb": 187,
            "arm64": 71,
            "mips32": 4207,
            "mips64": 5039,
            "riscv32": 71,
            "riscv64": 71,
            "powerpc32": 186,
            "powerpc64": 186,
            "sparc32": 39,
            "sparc64": 39,
            "s390x": 187,
        }
        assembler = LLVMAssembler()
        for architecture, number in expected.items():
            with self.subTest(architecture=architecture):
                target = resolve_target(architecture)
                payload = sendfile_orw_shellcode("/flag", target, count=257, assembler=assembler)
                self.assertEqual(payload.metadata["sendfile_syscall_number"], number)
                self.assertEqual(
                    payload.metadata["sendfile_syscall"], "sendfile64" if architecture == "riscv32" else "sendfile"
                )

    def test_sendfile_validation(self) -> None:
        target = resolve_target("x86_64")
        with self.assertRaises(ValueError):
            sendfile_orw_source("", target)
        with self.assertRaises(ValueError):
            sendfile_orw_source(b"/bad\0path", target)
        with self.assertRaises(ValueError):
            sendfile_orw_source("/flag", target, count=0)
        with self.assertRaises(ValueError):
            sendfile_orw_source("/flag", resolve_target("x86"), count=1 << 32)
        with self.assertRaises(ValueError):
            sendfile_orw_source("/flag", target, output_fd=0x10000)
        with self.assertRaises(ValueError):
            sendfile_orw_source("/" + "A" * 1800, target)


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

    def test_x86_mmap_checks_only_linux_error_pointer_range(self) -> None:
        source32, _ = mmap_stager_source(16, resolve_target("x86"))
        source64, _ = mmap_stager_source(16, resolve_target("x86_64"))
        self.assertIn("cmp eax, 0xfffff001\njae .Lstage_fail", source32)
        self.assertIn("cmp rax, -4095\njae .Lstage_fail", source64)
        self.assertNotIn("mov eax, 192\nint 0x80\ntest eax, eax\njs .Lstage_fail", source32)


class QemuSemihostingSourceTests(unittest.TestCase):
    def test_supported_matrix_is_exactly_the_automatic_qemu_user_targets(self) -> None:
        supported = {
            resolve_target(architecture, endian=endian).name for architecture, endian in QEMU_USER_SEMIHOSTING_TARGETS
        }
        self.assertEqual(
            supported,
            {
                "arm-le-arm-eabi",
                "arm-be-arm-eabi",
                "thumb-le-arm-eabi",
                "thumb-be-arm-eabi",
                "arm64-le-aarch64-aapcs64",
                "arm64-be-aarch64-aapcs64",
                "riscv32-le-riscv-ilp32",
                "riscv64-le-riscv-lp64",
            },
        )
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                if target.name in supported:
                    source, stack_size = qemu_semihosting_command_source("printf pwnc", target)
                    self.assertIn("_start:", source)
                    self.assertEqual(stack_size % target.convention.stack_alignment, 0)
                else:
                    with self.assertRaisesRegex(
                        UnsupportedTargetError,
                        f"automatic QEMU user-mode semihosting is not implemented for {target.name}",
                    ):
                        qemu_semihosting_command_source("printf pwnc", target)

    def test_source_uses_exact_architecture_traps(self) -> None:
        expected = {
            ("arm", "little"): "svc #0x123456",
            ("arm", "big"): "svc #0x123456",
            ("thumb", "little"): "svc #0xab",
            ("thumb", "big"): "svc #0xab",
            ("arm64", "little"): "hlt #0xf000",
            ("arm64", "big"): "hlt #0xf000",
        }
        for (architecture, endian), trap in expected.items():
            with self.subTest(architecture=architecture, endian=endian):
                source, _ = qemu_semihosting_command_source("printf pwnc", resolve_target(architecture, endian=endian))
                self.assertIn(trap, source)
        for architecture in ("riscv32", "riscv64"):
            with self.subTest(architecture=architecture):
                source, _ = qemu_semihosting_command_source("printf pwnc", resolve_target(architecture))
                self.assertIn(
                    ".balign 16\nslli zero, zero, 0x1f\nebreak\nsrai zero, zero, 0x7",
                    source,
                )

    def test_command_validation(self) -> None:
        target = resolve_target("arm64")
        with self.assertRaises(ValueError):
            qemu_semihosting_command_source("", target)
        with self.assertRaises(ValueError):
            qemu_semihosting_command_source(b"bad\0command", target)
        with self.assertRaises(ValueError):
            qemu_semihosting_command_source("A" * 1800, target)


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

    def test_sendfile_orw_assembles_for_all_targets_without_read_buffer(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                payload = sendfile_orw_shellcode("/flag", target, count=257, assembler=assembler)
                self.assertGreater(len(payload.data), 8)
                self.assertEqual(payload.metadata["operation"], "open-sendfile")
                self.assertEqual(payload.metadata["count"], 257)
                self.assertEqual(payload.metadata["offset_pointer"], None)
                self.assertFalse(payload.metadata["uses_read_buffer"])
                self.assertIn("sendfile path", payload.memory[1].purpose)
                self.assertNotIn("buffer", payload.memory[1].purpose)
                expected_source = "linux-uapi" if architecture in {"mips64", "riscv32"} else "pwntools:"
                self.assertTrue(payload.metadata["syscall_constants_source"].startswith(expected_source))

    def test_sendfile_orw_materializes_full_width_counts(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in SHELLCODE_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                count = 0x81234567 if target.bits == 32 else 0x8123456789ABCDEF
                payload = sendfile_orw_shellcode("/flag", target, count=count, assembler=assembler)
                self.assertEqual(payload.metadata["count"], count)
                self.assertEqual(payload.memory[1].size, target.convention.stack_alignment)

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

    def test_qemu_semihosting_escape_assembles_with_exact_trap_bytes(self) -> None:
        assembler = LLVMAssembler()
        expected_traps = {
            ("arm", "little"): bytes.fromhex("56 34 12 ef"),
            ("arm", "big"): bytes.fromhex("ef 12 34 56"),
            ("thumb", "little"): bytes.fromhex("ab df"),
            ("thumb", "big"): bytes.fromhex("df ab"),
            ("arm64", "little"): bytes.fromhex("00 00 5e d4"),
            ("arm64", "big"): bytes.fromhex("00 00 5e d4"),
            ("riscv32", None): bytes.fromhex("13 10 f0 01 73 00 10 00 13 50 70 40"),
            ("riscv64", None): bytes.fromhex("13 10 f0 01 73 00 10 00 13 50 70 40"),
        }
        for (architecture, endian), trap in expected_traps.items():
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                payload = qemu_semihosting_command_shellcode("printf pwnc", target, assembler=assembler)
                self.assertIn(trap, payload.data)
                self.assertEqual(payload.metadata["semihosting_call"], "SYS_SYSTEM")
                self.assertEqual(payload.metadata["semihosting_operation_number"], 0x12)
                self.assertTrue(payload.metadata["command_executes_on_host"])
                self.assertTrue(payload.metadata["qemu_user_automatic_interception"])
                expected_alignment = 16 if architecture.startswith("riscv") else 2 if architecture == "thumb" else 4
                self.assertEqual(payload.memory[0].alignment, expected_alignment)
                if architecture.startswith("riscv"):
                    self.assertEqual(payload.data.index(trap) % 16, 0)
                    self.assertTrue(payload.metadata["semihosting_trap_same_page_required"])
                else:
                    self.assertFalse(payload.metadata["semihosting_trap_same_page_required"])

    def test_qemu_semihosting_materializes_nontrivial_argument_offsets(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in QEMU_USER_SEMIHOSTING_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                payload = qemu_semihosting_command_shellcode("A" * 1301, target, assembler=assembler)
                self.assertGreater(len(payload.data), 8)


if __name__ == "__main__":
    unittest.main()
