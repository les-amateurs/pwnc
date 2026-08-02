from __future__ import annotations

import shutil
import unittest

from payloads.assembler import LLVMAssembler, ZigAssembler
from payloads.errors import AssemblyError
from payloads.shellcode import exit_source
from payloads.target import SUPPORTED_TARGETS, resolve_target


class _FixedAssembler:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.calls = 0

    def assemble(self, source: str, target) -> bytes:
        self.calls += 1
        return self.data


class ZigAssemblerTests(unittest.TestCase):
    def test_missing_zig_uses_fallback(self) -> None:
        fallback = _FixedAssembler(b"fallback")
        assembler = ZigAssembler("/definitely/missing/pwnc-zig", fallback=fallback)
        target = resolve_target("riscv64")
        self.assertFalse(assembler.available)
        self.assertEqual(assembler.assemble(exit_source(7, target), target), b"fallback")
        self.assertEqual(fallback.calls, 1)
        self.assertEqual(assembler.last_backend, "fallback")
        self.assertEqual(assembler.last_fallback_diagnostics, "zig was not found")

    @unittest.skipUnless(shutil.which("zig") and shutil.which("llvm-mc"), "Zig and LLVM are required")
    def test_zig_and_llvm_agree_across_the_catalog(self) -> None:
        assembler = ZigAssembler()
        reference = LLVMAssembler()
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                source = exit_source(37, target)
                self.assertEqual(assembler.assemble(source, target), reference.assemble(source, target))

    @unittest.skipUnless(shutil.which("zig") and shutil.which("llvm-mc"), "Zig and LLVM are required")
    def test_zig_failure_falls_back_for_ppc64_elfv1(self) -> None:
        target = resolve_target("ppc64")
        source = exit_source(7, target)
        self.assertEqual(ZigAssembler().assemble(source, target), LLVMAssembler().assemble(source, target))

    @unittest.skipUnless(shutil.which("zig") and shutil.which("llvm-mc"), "Zig and LLVM are required")
    def test_valid_riscv_pseudoinstruction_variation_is_not_rejected_by_default(self) -> None:
        target = resolve_target("riscv64")
        source = """\
.text
.option norvc
.globl _start
_start:
li t0, 0x68732f6e69622f
"""
        observed = ZigAssembler().assemble(source, target)
        reference = LLVMAssembler().assemble(source, target)
        self.assertNotEqual(observed, reference)
        with self.assertRaisesRegex(AssemblyError, "different shellcode"):
            ZigAssembler(verify_with_fallback=True).assemble(source, target)

    @unittest.skipUnless(shutil.which("zig"), "Zig is required")
    def test_default_arm_orw_stack_adjustment_stays_on_zig(self) -> None:
        from payloads.shellcode import orw_source

        for target_name in ("arm", "thumb"):
            with self.subTest(target=target_name):
                target = resolve_target(target_name)
                source = orw_source("/flag", target)[0]
                assembler = ZigAssembler()
                self.assertTrue(assembler.assemble(source, target))
                self.assertEqual(assembler.last_backend, "zig", assembler.last_fallback_diagnostics)


if __name__ == "__main__":
    unittest.main()
