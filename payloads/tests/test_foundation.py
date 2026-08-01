from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from payloads import (
    Address,
    AddressResolutionError,
    ConstraintError,
    Endian,
    ExecutionPolicy,
    Image,
    LibcIdentity,
    LibcImage,
    Linkage,
    Mitigations,
    Payload,
    PayloadKind,
    Relro,
    RuntimeLayout,
    UnsupportedTargetError,
    resolve_target,
)


class TargetTests(unittest.TestCase):
    def test_primary_architecture_aliases(self) -> None:
        expected = {
            "x86": (32, Endian.LITTLE),
            "x86-64": (64, Endian.LITTLE),
            "arm": (32, Endian.LITTLE),
            "arm64": (64, Endian.LITTLE),
            "mips32": (32, Endian.LITTLE),
            "mips64": (64, Endian.LITTLE),
            "riscv32": (32, Endian.LITTLE),
            "riscv64": (64, Endian.LITTLE),
        }
        for alias, properties in expected.items():
            with self.subTest(alias=alias):
                target = resolve_target(alias)
                self.assertEqual((target.bits, target.endian), properties)

    def test_explicit_endian_aliases_and_packing(self) -> None:
        little = resolve_target("mipsel")
        big = resolve_target("mipseb")
        self.assertEqual(little.pack(0x11223344), b"\x44\x33\x22\x11")
        self.assertEqual(big.pack(0x11223344), b"\x11\x22\x33\x44")
        self.assertEqual(big.unpack(b"\x11\x22\x33\x44"), 0x11223344)

    def test_conflicting_alias_is_rejected(self) -> None:
        with self.assertRaises(UnsupportedTargetError):
            resolve_target("mipsel", endian="big")
        with self.assertRaises(UnsupportedTargetError):
            resolve_target("riscv64", endian="big")

    def test_word_overflow_is_not_silently_truncated(self) -> None:
        target = resolve_target("x86")
        with self.assertRaises(OverflowError):
            target.pack(1 << 32)
        self.assertEqual(target.pack(-1, truncate=True), b"\xff" * 4)


class RuntimeModelTests(unittest.TestCase):
    def test_relative_addresses_require_and_use_correct_base(self) -> None:
        symbol = Address(0x1234, Image.LIBC, "system")
        with self.assertRaises(AddressResolutionError):
            symbol.resolve()
        self.assertEqual(symbol.resolve(RuntimeLayout(libc_base=0x7F0000000000)), 0x7F0000001234)

    def test_mitigation_decisions(self) -> None:
        full_relro = Mitigations(True, True, Relro.FULL, Linkage.DYNAMIC, ExecutionPolicy.ELF_PERMISSIONS)
        with self.assertRaises(ConstraintError):
            full_relro.require_got_overwrite()
        with self.assertRaises(ConstraintError):
            full_relro.require_shellcode_path()
        full_relro.require_shellcode_path(can_change_permissions=True)

        legacy_qemu = Mitigations(
            False, True, Relro.PARTIAL, Linkage.DYNAMIC, ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE
        )
        legacy_qemu.require_shellcode_path()
        legacy_qemu.require_got_overwrite()

    def test_payload_metadata_is_copied_and_immutable(self) -> None:
        metadata = {"operation": "execve"}
        payload = Payload(b"\x90", resolve_target("x86"), PayloadKind.SHELLCODE, "test", metadata=metadata)
        metadata["operation"] = "changed"
        self.assertEqual(payload.metadata["operation"], "execve")
        with self.assertRaises(TypeError):
            payload.metadata["new"] = "value"  # type: ignore[index]


class LibcIdentityTests(unittest.TestCase):
    def test_identity_hashes_exact_artifact(self) -> None:
        data = b"distro-patched-glibc-artifact"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "libc.so.6")
            path.write_bytes(data)
            identity = LibcIdentity.from_file(
                path,
                glibc_version="2.39",
                distro="ubuntu",
                package_release="0ubuntu8.4",
            )
        self.assertEqual(identity.sha256, hashlib.sha256(data).hexdigest())
        self.assertTrue(identity.matches(data))
        self.assertFalse(identity.matches(data + b"patched"))
        self.assertEqual(identity.package_release, "0ubuntu8.4")

    def test_symbol_leak_uses_offsets_from_exact_image(self) -> None:
        identity = LibcIdentity("00" * 32, build_id="abcd")
        image = LibcImage(identity, resolve_target("x86_64"), {"puts": 0x77980, "system": 0x4C490})
        base = image.base_from_leak("puts", 0x7F0000077980)
        self.assertEqual(base, 0x7F0000000000)
        layout = RuntimeLayout(libc_base=base)
        self.assertEqual(image.address("system", layout), 0x7F000004C490)


if __name__ == "__main__":
    unittest.main()
