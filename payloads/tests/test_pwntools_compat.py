from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from pwnlib.context import context

from payloads import SUPPORTED_TARGETS, Relro, inspect_elf, resolve_target
from payloads.libc import LibcIdentity
from payloads.pwntools_compat import (
    ExactELFAdapter,
    PwntoolsCompatibilityError,
    _crosscheck_pwntools_elf,
    pack_target_word,
)

_FIXTURE_SOURCES = {
    64: r"""
.text
.globl open, read, write, sendfile, exit
.type open,@function
open: ret
.type read,@function
read: ret
.type write,@function
write: ret
.type sendfile,@function
sendfile: ret
.type exit,@function
exit: ret
.globl gadget_rdi, gadget_rsi, gadget_rdx, gadget_rcx
gadget_rdi: pop %rdi; ret
gadget_rsi: pop %rsi; ret
gadget_rdx: pop %rdx; ret
gadget_rcx: pop %rcx; ret
""",
    32: r"""
.text
.globl open, read, write, sendfile, exit
.type open,@function
open: ret
.type read,@function
read: ret
.type write,@function
write: ret
.type sendfile,@function
sendfile: ret
.type exit,@function
exit: ret
.globl cleanup4, cleanup12, cleanup16
cleanup4: add $4,%esp; ret
cleanup12: add $12,%esp; ret
cleanup16: add $16,%esp; ret
""",
}


def _compile_exact_rop_fixture(
    root: Path,
    bits: int,
    *,
    name: str = "libc-rop",
    extra_source: str = "",
    source: str | None = None,
) -> Path:
    output = root / f"{name}-{bits}.so"
    result = subprocess.run(
        [
            "cc",
            f"-m{bits}",
            "-nostdlib",
            "-shared",
            "-Wl,-soname,libc-rop-fixture.so",
            "-Wl,--build-id",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "-x",
            "assembler",
            "-",
            "-o",
            str(output),
        ],
        input=(_FIXTURE_SOURCES[bits] if source is None else source) + extra_source,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise unittest.SkipTest(f"{bits}-bit exact ELF fixture is unavailable: {result.stderr.strip()}")
    return output


@unittest.skipUnless(shutil.which("cc"), "a C compiler/linker is required for the exact ELF fixture")
class ExactELFAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="pwnc-pwntools-compat-")
        self.root = Path(self.temporary.name)
        self.artifact = _compile_exact_rop_fixture(self.root, 64)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_read_only_adapter_crosschecks_independent_profile_and_symbols(self) -> None:
        profile = inspect_elf(self.artifact)
        identity = LibcIdentity(
            profile.sha256,
            build_id=profile.build_id,
            distro="test fixture",
            source=str(self.artifact),
        )
        adapter = ExactELFAdapter.from_file(
            self.artifact,
            profile=profile,
            expected_identity=identity,
            expected_target=resolve_target("x86_64"),
        )

        self.assertIs(adapter.identity, identity)
        self.assertEqual(adapter.target, profile.target)
        self.assertEqual(adapter.symbol("open"), profile.symbol_offsets["open"])
        self.assertEqual(adapter.mitigations.pie, profile.pie)
        self.assertEqual(adapter.mitigations.nx, profile.nx)
        self.assertIs(adapter.mitigations.relro, profile.relro)
        self.assertFalse(adapter.mitigations.canary)
        self.assertFalse(adapter.mitigations.fortify)
        adapter.crosscheck_profile(profile)
        with self.assertRaises(TypeError):
            adapter.symbols["open"] = 0  # type: ignore[index]

    def test_adapter_rejects_wrong_target_and_changed_artifact(self) -> None:
        with self.assertRaisesRegex(PwntoolsCompatibilityError, "does not match required target"):
            ExactELFAdapter.from_file(self.artifact, expected_target=resolve_target("x86"))

        adapter = ExactELFAdapter.from_file(self.artifact)
        self.artifact.write_bytes(self.artifact.read_bytes() + b"changed")
        with self.assertRaisesRegex(PwntoolsCompatibilityError, "changed after"):
            adapter.fresh_elf()

    def test_profile_crosscheck_rejects_mitigation_drift(self) -> None:
        adapter = ExactELFAdapter.from_file(self.artifact)
        contradictory = replace(adapter.profile, pie=not adapter.profile.pie)
        with self.assertRaisesRegex(PwntoolsCompatibilityError, "mitigation"):
            adapter.crosscheck_profile(contradictory)

    def test_adapter_does_not_expose_process_backed_conveniences(self) -> None:
        adapter = ExactELFAdapter.from_file(self.artifact)
        for name in ("libs", "maps", "libc"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(adapter, name))

    def test_combined_rop_search_space_requires_distinct_exact_target_images(self) -> None:
        adapter = ExactELFAdapter.from_file(self.artifact)
        supplemental_path = _compile_exact_rop_fixture(
            self.root,
            64,
            name="supplemental",
            extra_source="\n.globl supplemental_marker\nsupplemental_marker: nop; ret\n",
        )
        supplemental = ExactELFAdapter.from_file(supplemental_path)

        images, rop = adapter.fresh_rop_group(extra_images=((supplemental, None),))
        try:
            self.assertEqual(len(images), 2)
            self.assertIsNotNone(rop.find_gadget(["pop rdx", "ret"]))
        finally:
            for image in images:
                image.close()

        with self.assertRaisesRegex(PwntoolsCompatibilityError, "same exact ELF twice"):
            adapter.fresh_rop_group(extra_images=((adapter, None),))

        wrong_target = ExactELFAdapter.from_file(_compile_exact_rop_fixture(self.root, 32, name="wrong-target"))
        with self.assertRaisesRegex(PwntoolsCompatibilityError, "does not match primary target"):
            adapter.fresh_rop_group(extra_images=((wrong_target, None),))


class PwntoolsPackingTests(unittest.TestCase):
    def test_pwntools_packing_matches_every_exact_target_without_context_leakage(self) -> None:
        before = (context.arch, context.bits, context.endian, context.os)
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                self.assertEqual(pack_target_word(target, 0x1234), target.pack(0x1234))
        self.assertEqual((context.arch, context.bits, context.endian, context.os), before)

    def test_strict_pack_rejects_out_of_range_values(self) -> None:
        target = resolve_target("x86")
        with self.assertRaises(OverflowError):
            pack_target_word(target, 1 << target.bits)


class PwntoolsArchitectureAliasTests(unittest.TestCase):
    @staticmethod
    def _profile(*, backend_arch: str = "s390") -> mock.Mock:
        target = replace(resolve_target("s390x"), pwntools_arch=backend_arch)
        return mock.Mock(
            target=target,
            pie=False,
            nx=True,
            relro=Relro.FULL,
            symbol_offsets={"write": 0x12340},
        )

    @staticmethod
    def _elf(arch: str) -> mock.Mock:
        return mock.Mock(
            arch=arch,
            bits=64,
            endian="big",
            os="linux",
            pie=False,
            nx=True,
            relro="Full",
            canary=False,
            fortify=False,
            symbols={"write": 0x12340},
        )

    def test_real_s390_elf_parser_alias_is_accepted(self) -> None:
        mitigations = _crosscheck_pwntools_elf(self._elf("em_s390"), self._profile())
        self.assertTrue(mitigations.nx)

    def test_unrelated_s390_arch_spelling_is_rejected(self) -> None:
        with self.assertRaisesRegex(PwntoolsCompatibilityError, "expected one of 's390', 'em_s390'"):
            _crosscheck_pwntools_elf(self._elf("s390x"), self._profile())

    def test_s390_context_backend_alias_remains_strict(self) -> None:
        with self.assertRaisesRegex(PwntoolsCompatibilityError, "target backend alias 'em_s390'"):
            _crosscheck_pwntools_elf(self._elf("em_s390"), self._profile(backend_arch="em_s390"))


if __name__ == "__main__":
    unittest.main()
