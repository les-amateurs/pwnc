from __future__ import annotations

import shutil
import unittest

from payloads import LLVMAssembler, command_shellcode, command_source, resolve_target


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


class CommandSourceTests(unittest.TestCase):
    def test_all_primary_targets_lower_without_pwntools_shellcraft(self) -> None:
        for architecture, endian in PRIMARY_TARGETS:
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


@unittest.skipUnless(shutil.which("llvm-mc"), "llvm-mc is not installed")
class CommandAssemblyTests(unittest.TestCase):
    def test_all_primary_targets_assemble_to_relocation_free_bytes(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in PRIMARY_TARGETS:
            with self.subTest(architecture=architecture, endian=endian):
                target = resolve_target(architecture, endian=endian)
                payload = command_shellcode("printf pwnc", target, assembler=assembler)
                self.assertGreater(len(payload.data), 8)
                self.assertEqual(payload.metadata["operation"], "run-command")
                self.assertTrue(payload.metadata["position_independent"])


if __name__ == "__main__":
    unittest.main()
