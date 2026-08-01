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

_PPC32_LE = resolve_target("powerpc32", endian="little").name
_PPC64_ELFV1 = resolve_target("ppc64").name
_RET2LIBC_QEMU_TARGETS = {resolve_target("x86").name, resolve_target("x86_64").name}
_NATIVE_X86_TARGETS = _RET2LIBC_QEMU_TARGETS
_NATIVE_CAPABILITIES = {
    Capability.COMMAND,
    Capability.ORW,
    Capability.STAGER,
    Capability.RET2LIBC,
    Capability.STATIC_ROP,
}
_QEMU_SEMIHOSTING_TARGETS = {
    resolve_target("arm", endian="little").name,
    resolve_target("arm", endian="big").name,
    resolve_target("thumb", endian="little").name,
    resolve_target("thumb", endian="big").name,
    resolve_target("arm64", endian="little").name,
    resolve_target("arm64", endian="big").name,
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
                    expected = SupportLevel.IMPLEMENTED if target.name == _PPC32_LE else SupportLevel.QEMU_VERIFIED
                    self.assertEqual(coverage.level, expected)
                    self.assertTrue(coverage.implemented)
                    self.assertEqual(coverage.qemu_verified, target.name != _PPC32_LE)
                    if target.name == _PPC32_LE:
                        self.assertTrue(any("CommandAssemblyTests" in item for item in coverage.evidence))

    def test_arb_executor_is_target_generic_but_not_qemu_executed(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                coverage = capability_support(target, Capability.ARB_EXECUTOR)
                self.assertTrue(coverage.recognized)
                self.assertTrue(coverage.implemented)
                self.assertFalse(coverage.qemu_verified)
                self.assertEqual(coverage.level, SupportLevel.IMPLEMENTED)
                got_evidence = any("GotSystemWorkflow" in item for item in coverage.evidence)
                if target.name == _PPC64_ELFV1:
                    self.assertFalse(got_evidence)
                    self.assertIn("GOT-to-system replacement is unsupported", coverage.detail)
                else:
                    self.assertTrue(got_evidence)

    def test_ret2libc_coverage_matches_direct_call_abi_support(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                coverage = capability_support(target, Capability.RET2LIBC)
                if target.name in _DIRECT_CALL_UNSUPPORTED:
                    expected = SupportLevel.RECOGNIZED
                elif target.name in _RET2LIBC_QEMU_TARGETS:
                    expected = SupportLevel.QEMU_VERIFIED
                else:
                    expected = SupportLevel.IMPLEMENTED
                self.assertEqual(coverage.level, expected)
                self.assertEqual(coverage.implemented, target.name not in _DIRECT_CALL_UNSUPPORTED)
                self.assertEqual(coverage.qemu_verified, target.name in _RET2LIBC_QEMU_TARGETS)

    def test_static_rop_qemu_coverage_matches_runtime_matrix(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                coverage = capability_support(target, Capability.STATIC_ROP)
                expected = SupportLevel.IMPLEMENTED if target.name == _PPC32_LE else SupportLevel.QEMU_VERIFIED
                self.assertEqual(coverage.level, expected)
                self.assertTrue(coverage.implemented)
                self.assertEqual(coverage.qemu_verified, target.name != _PPC32_LE)
                direct_call_evidence = any(
                    "build_static_call" in item or "test_static_call_materializes" in item for item in coverage.evidence
                )
                if target.name in _DIRECT_CALL_UNSUPPORTED:
                    self.assertIn("direct function calls remain unsupported", coverage.detail)
                    self.assertFalse(direct_call_evidence)
                else:
                    self.assertTrue(direct_call_evidence)

    def test_qemu_semihosting_coverage_is_exactly_the_automatic_user_mode_matrix(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                coverage = capability_support(target, Capability.QEMU_SEMIHOSTING)
                supported = target.name in _QEMU_SEMIHOSTING_TARGETS
                expected = SupportLevel.QEMU_VERIFIED if supported else SupportLevel.RECOGNIZED
                self.assertEqual(coverage.level, expected)
                self.assertEqual(coverage.implemented, supported)
                self.assertEqual(coverage.qemu_verified, supported)
                self.assertFalse(coverage.native_verified)
                if supported:
                    self.assertIn("SYS_SYSTEM host-command escape", coverage.detail)
                    self.assertTrue(any("test_semihost_qemu.py" in item for item in coverage.evidence))
                else:
                    self.assertIn("does not automatically intercept", coverage.detail)

    def test_native_verification_is_orthogonal_and_exactly_x86_execution_evidence(self) -> None:
        for target in SUPPORTED_TARGETS:
            for capability in Capability:
                with self.subTest(target=target.name, capability=capability.value):
                    coverage = capability_support(target, capability)
                    expected = target.name in _NATIVE_X86_TARGETS and capability in _NATIVE_CAPABILITIES
                    self.assertEqual(coverage.native_verified, expected)
                    has_native_evidence = any("test_native_x86.py" in item for item in coverage.evidence)
                    self.assertEqual(has_native_evidence, expected)

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
        self.assertEqual(exported["schema_version"], 2)
        self.assertEqual(exported["capabilities"], [capability.value for capability in Capability])
        self.assertEqual(len(exported["targets"]), len(SUPPORTED_TARGETS))
        encoded = json.dumps(exported, sort_keys=True)
        self.assertIn('"qemu_verified": true', encoded)
        self.assertIn('"native_verified": true', encoded)
        self.assertIn('"native_verified": false', encoded)
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
