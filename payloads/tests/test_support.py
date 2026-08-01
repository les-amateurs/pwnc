from __future__ import annotations

import json
import unittest

from payloads.support import (
    SUPPORT_MATRIX,
    Capability,
    SupportLevel,
    capability_support,
    support_matrix_data,
    target_support,
)
from payloads.target import SUPPORTED_TARGETS, resolve_target

_PRIMARY_SHELLCODE_TARGETS = {
    resolve_target("x86").name,
    resolve_target("x86_64").name,
    resolve_target("arm", endian="little").name,
    resolve_target("arm", endian="big").name,
    resolve_target("thumb", endian="little").name,
    resolve_target("thumb", endian="big").name,
    resolve_target("arm64", endian="little").name,
    resolve_target("arm64", endian="big").name,
    resolve_target("mips32", endian="little").name,
    resolve_target("mips32", endian="big").name,
    resolve_target("mips64", endian="little").name,
    resolve_target("mips64", endian="big").name,
    resolve_target("riscv32").name,
    resolve_target("riscv64").name,
}

_DIRECT_CALL_UNSUPPORTED = {
    resolve_target("ppc64").name,
    resolve_target("sparc32").name,
    resolve_target("sparc64").name,
}


class SupportMatrixTests(unittest.TestCase):
    def test_matrix_has_one_exact_row_for_every_recognized_target(self) -> None:
        self.assertEqual(set(SUPPORT_MATRIX), {target.name for target in SUPPORTED_TARGETS})
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                row = SUPPORT_MATRIX[target.name]
                self.assertEqual(row.target, target)
                self.assertEqual(set(row.capabilities), set(Capability))

    def test_shellcode_coverage_matches_implementation_and_qemu_tests(self) -> None:
        for target in SUPPORTED_TARGETS:
            for capability in (Capability.COMMAND, Capability.ORW, Capability.STAGER):
                with self.subTest(target=target.name, capability=capability.value):
                    coverage = capability_support(target, capability)
                    expected = (
                        SupportLevel.QEMU_VERIFIED
                        if target.name in _PRIMARY_SHELLCODE_TARGETS
                        else SupportLevel.RECOGNIZED
                    )
                    self.assertEqual(coverage.level, expected)
                    self.assertEqual(coverage.implemented, target.name in _PRIMARY_SHELLCODE_TARGETS)
                    self.assertEqual(coverage.qemu_verified, target.name in _PRIMARY_SHELLCODE_TARGETS)

    def test_arb_executor_is_target_generic_but_not_qemu_executed(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                coverage = capability_support(target, Capability.ARB_EXECUTOR)
                self.assertTrue(coverage.recognized)
                self.assertTrue(coverage.implemented)
                self.assertFalse(coverage.qemu_verified)
                self.assertEqual(coverage.level, SupportLevel.IMPLEMENTED)

    def test_ret2libc_coverage_matches_direct_call_abi_support(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                coverage = capability_support(target, Capability.RET2LIBC)
                expected = (
                    SupportLevel.RECOGNIZED if target.name in _DIRECT_CALL_UNSUPPORTED else SupportLevel.IMPLEMENTED
                )
                self.assertEqual(coverage.level, expected)
                self.assertEqual(coverage.implemented, target.name not in _DIRECT_CALL_UNSUPPORTED)
                self.assertFalse(coverage.qemu_verified)

    def test_static_rop_has_all_target_syscall_builders_but_no_qemu_execution_test(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                coverage = capability_support(target, Capability.STATIC_ROP)
                self.assertEqual(coverage.level, SupportLevel.IMPLEMENTED)
                self.assertTrue(coverage.implemented)
                self.assertFalse(coverage.qemu_verified)
                if target.name in _DIRECT_CALL_UNSUPPORTED:
                    self.assertIn("direct function calls are unsupported", coverage.detail)

    def test_queries_accept_aliases_canonical_names_and_targets(self) -> None:
        target = resolve_target("mipseb")
        self.assertIs(target_support("mipseb"), SUPPORT_MATRIX[target.name])
        self.assertIs(target_support(target.name), SUPPORT_MATRIX[target.name])
        self.assertIs(target_support(target), SUPPORT_MATRIX[target.name])
        self.assertIs(
            capability_support("mips32", "command", endian="big"),
            SUPPORT_MATRIX[target.name].capabilities[Capability.COMMAND],
        )

    def test_export_is_versioned_and_json_serializable(self) -> None:
        exported = support_matrix_data()
        self.assertEqual(exported["schema_version"], 1)
        self.assertEqual(exported["capabilities"], [capability.value for capability in Capability])
        self.assertEqual(len(exported["targets"]), len(SUPPORTED_TARGETS))
        encoded = json.dumps(exported, sort_keys=True)
        self.assertIn('"qemu_verified": true', encoded)
        self.assertIn('"implemented": false', encoded)

    def test_public_matrix_is_immutable(self) -> None:
        with self.assertRaises(TypeError):
            SUPPORT_MATRIX["new"] = SUPPORT_MATRIX[next(iter(SUPPORT_MATRIX))]  # type: ignore[index]
        with self.assertRaises(TypeError):
            target_support("x86").capabilities[Capability.ORW] = capability_support(  # type: ignore[index]
                "x86", Capability.COMMAND
            )


if __name__ == "__main__":
    unittest.main()
