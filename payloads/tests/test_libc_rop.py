from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from payloads.libc import LibcIdentity, LibcImage
from payloads.libc_rop import (
    InlineDataReference,
    LibcROPBuilder,
    LibcROPError,
    LibcROPStage,
    LibcROPStageKind,
    WritableArea,
)
from payloads.model import Address, Image, PayloadKind, RuntimeLayout
from payloads.rop import (
    AddressExpression,
    LibcBoundAddress,
    SemanticGadget,
    UnsupportedROPError,
    bind_libc_address,
)
from payloads.target import resolve_target
from payloads.tests.test_pwntools_compat import _compile_exact_rop_fixture


@unittest.skipUnless(shutil.which("cc"), "a C compiler/linker is required for exact libc ROP fixtures")
class LibcROPBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.temporary = tempfile.TemporaryDirectory(prefix="pwnc-libc-rop-builder-")
        cls.root = Path(cls.temporary.name)
        cls.libc_path = _compile_exact_rop_fixture(cls.root, 64)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()
        super().tearDownClass()

    def test_inline_path_and_sendfile_need_no_writable_buffer(self) -> None:
        builder = LibcROPBuilder.from_file(self.libc_path, b"/flag")
        opened = builder.open()
        sent = builder.sendfile(1, 3, 0x400)
        finished = builder.exit(7)
        program = builder.compose(opened, sent, finished)

        self.assertIsInstance(opened.arguments[0], InlineDataReference)
        self.assertEqual(opened.arguments[1:], (0, 0))
        self.assertEqual(sent.arguments, (1, 3, 0, 0x400))
        self.assertEqual(
            program.operations,
            (LibcROPStageKind.OPEN, LibcROPStageKind.SENDFILE, LibcROPStageKind.EXIT),
        )
        self.assertTrue(program.inline_path)
        self.assertEqual(program.path_data, b"/flag\0")
        self.assertEqual(program.external_placements, ())

        with self.assertRaisesRegex(LibcROPError, "require a writable area"):
            builder.read(3, 0x100)
        with self.assertRaisesRegex(LibcROPError, "require a writable area"):
            builder.write(1, 0x100)

    def test_writable_area_places_path_then_exposes_shared_read_write_buffer(self) -> None:
        area = WritableArea(Address(0x9000, Image.MAIN, "fixture scratch"), 0x1000)
        builder = LibcROPBuilder.from_file(self.libc_path, "/tmp/flag", writable_area=area)
        opened = builder.open()
        read = builder.read(3, 0x180, buffer_offset=0x20)
        write = builder.write(1, 0x180, buffer_offset=0x20)
        program = builder.compose([opened, read, write, builder.exit()])
        layout = RuntimeLayout(main_base=0x400000)

        reservation = 16  # len(b"/tmp/flag\0") rounded to an AMD64 word
        expected_buffer = 0x400000 + 0x9000 + reservation + 0x20
        self.assertEqual(program.external_placements[0].data, b"/tmp/flag\0")
        self.assertEqual(program.external_placements[0].resolved_address(layout), 0x409000)
        self.assertEqual(
            read.arguments,
            (
                3,
                AddressExpression(
                    Address(0x9000, Image.MAIN, "fixture scratch"),
                    reservation + 0x20,
                ),
                0x180,
            ),
        )
        self.assertEqual(write.arguments, (1, read.arguments[1], 0x180))
        self.assertEqual(read.arguments[1].resolve(layout), expected_buffer)
        self.assertFalse(program.inline_path)

    def test_explicit_separate_path_address_does_not_consume_buffer_prefix(self) -> None:
        area = Address(0xA000, Image.MAIN, "data buffer")
        path = Address(0xB000, Image.MAIN, "preplaced path")
        builder = LibcROPBuilder.from_file(
            self.libc_path,
            b"/secret",
            writable_area=area,
            writable_size=0x100,
            path_address=path,
        )
        read = builder.read(3, 0x40)

        self.assertEqual(builder.open().arguments[0], path)
        self.assertEqual(read.arguments[1], area)
        self.assertEqual(builder.external_placements[0].address, path)

    def test_writable_bounds_and_input_validation_are_strict(self) -> None:
        builder = LibcROPBuilder.from_file(
            self.libc_path,
            b"/f",
            writable_area=0x601000,
            writable_size=0x20,
        )
        with self.assertRaisesRegex(LibcROPError, "exceeds"):
            builder.read(3, 0x20)
        with self.assertRaises(ValueError):
            builder.sendfile(1, 3, 0)
        with self.assertRaises(ValueError):
            builder.read(-1, 1)
        with self.assertRaises(ValueError):
            LibcROPBuilder.from_file(self.libc_path, b"bad\0path")
        with self.assertRaises(ValueError):
            LibcROPBuilder.from_file(self.libc_path, b"")
        with self.assertRaises(ValueError):
            LibcROPBuilder.from_file(self.libc_path, b"/f", writable_size=0x100)
        with self.assertRaisesRegex(LibcROPError, "aligned path reservation"):
            LibcROPBuilder.from_file(
                self.libc_path,
                b"/flag",
                writable_area=0x601000,
                writable_size=4,
            )

    def test_composer_rejects_a_stage_from_another_exact_artifact(self) -> None:
        other_path = _compile_exact_rop_fixture(self.root, 32)
        first = LibcROPBuilder.from_file(self.libc_path, b"/first")
        other = LibcROPBuilder.from_file(other_path, b"/other")
        with self.assertRaisesRegex(LibcROPError, "different libc artifacts"):
            first.compose(first.open(), other.exit())


class SemanticLibcROPStageTests(unittest.TestCase):
    @staticmethod
    def _identity(seed: bytes) -> LibcIdentity:
        return LibcIdentity.from_bytes(seed)

    def test_amd64_stage_uses_exact_bound_function_and_semantic_gadgets(self) -> None:
        target = resolve_target("x86_64")
        libc = LibcImage(
            self._identity(b"amd64 semantic libc"),
            target,
            {"open": 0x1000, "pop_rdi": 0x2000, "pop_rsi": 0x2010, "pop_rdx": 0x2020},
        )
        stage = LibcROPStage(
            libc,
            LibcROPStageKind.OPEN,
            "open",
            (InlineDataReference("path"), 0, 0),
        )
        gadgets = tuple(
            SemanticGadget(
                target,
                bind_libc_address(libc, symbol),
                2,
                {register: 0},
                1,
                f"fixture pop {register}; ret",
            )
            for register, symbol in (("rdi", "pop_rdi"), ("rsi", "pop_rsi"), ("rdx", "pop_rdx"))
        )
        path = Address(0x240, Image.STACK, "inline path")
        chain = stage.lower_semantic(
            gadgets=gadgets,
            return_to=Address(0x1234, Image.MAIN, "next stage"),
            inline_addresses={"path": path},
        )

        self.assertIs(chain.kind, PayloadKind.RET2LIBC)
        self.assertEqual(chain.target, target)
        self.assertIn(libc.identity.sha256[:12], chain.description)
        bound = [word.value for word in chain.words if isinstance(word.value, LibcBoundAddress)]
        self.assertTrue(bound)
        self.assertTrue(all(value.identity == libc.identity for value in bound))
        self.assertIn(path, [word.value for word in chain.words])

    def test_arm_stage_is_lowerable_only_with_explicit_target_gadget_semantics(self) -> None:
        target = resolve_target("arm")
        libc = LibcImage(self._identity(b"arm semantic libc"), target, {"read": 0x1000, "loader": 0x2000})
        stage = LibcROPStage(libc, LibcROPStageKind.READ, "read", (3, 0x3000, 0x80))
        gadget = SemanticGadget(
            target,
            bind_libc_address(libc, "loader"),
            5,
            {"r0": 0, "r1": 1, "r2": 2, "lr": 3},
            4,
            "ARM load r0-r2/lr/pc",
        )
        chain = stage.lower_semantic(
            gadgets=(gadget,),
            return_to=Address(0x4000, Image.MAIN, "next"),
        )

        self.assertEqual(chain.target, target)
        self.assertIn("ARM load r0-r2/lr/pc", chain.steps)

    def test_i386_cdecl_stage_needs_no_register_gadgets(self) -> None:
        target = resolve_target("x86")
        libc = LibcImage(self._identity(b"i386 semantic libc"), target, {"write": 0x1000})
        stage = LibcROPStage(libc, LibcROPStageKind.WRITE, "write", (1, 0x804C000, 0x20))
        chain = stage.lower_semantic(return_to=0x8049000)

        self.assertEqual(
            chain.resolved_words(RuntimeLayout(libc_base=0)),
            (0x1000, 0x8049000, 1, 0x804C000, 0x20),
        )

    def test_ppc64_elfv1_rejects_a_false_raw_direct_call_claim(self) -> None:
        target = resolve_target("ppc64")
        libc = LibcImage(self._identity(b"ppc64v1 semantic libc"), target, {"exit": 0x1000})
        stage = LibcROPStage(libc, LibcROPStageKind.EXIT, "exit", (0,))
        with self.assertRaises(UnsupportedROPError):
            stage.lower_semantic()

    def test_unbound_libc_relative_arguments_are_rejected(self) -> None:
        target = resolve_target("x86")
        libc = LibcImage(self._identity(b"identity binding"), target, {"write": 0x1000})
        with self.assertRaisesRegex(LibcROPError, "lacks exact LibcIdentity"):
            LibcROPStage(libc, LibcROPStageKind.WRITE, "write", (1, Address(0x2000, Image.LIBC), 0x20))


@unittest.skipUnless(shutil.which("cc"), "a C compiler/linker is required for exact libc ROP fixtures")
class PwntoolsComposedProgramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.temporary = tempfile.TemporaryDirectory(prefix="pwnc-libc-rop-linked-")
        cls.root = Path(cls.temporary.name)
        cls.fixtures = {bits: _compile_exact_rop_fixture(cls.root, bits) for bits in (32, 64)}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()
        super().tearDownClass()

    def test_pwntools_links_open_sendfile_exit_with_inline_path_on_both_x86_abis(self) -> None:
        configurations = {
            32: (0xF7000000, 0x804C000),
            64: (0x700000000000, 0x404000),
        }
        for bits, (libc_base, chain_base) in configurations.items():
            with self.subTest(bits=bits):
                builder = LibcROPBuilder.from_file(self.fixtures[bits], b"/flag")
                program = builder.compose(builder.open(), builder.sendfile(1, 3, 0x100), builder.exit())
                layout = RuntimeLayout(libc_base=libc_base)
                lowered = program.lower_pwntools(layout, chain_base=chain_base)

                self.assertEqual(lowered.data[-6:], b"/flag\0")
                self.assertEqual(lowered.inline_path_address, chain_base + lowered.inline_path_offset)
                self.assertEqual(lowered.inline_path_offset % builder.target.word_size, 0)
                self.assertIn(builder.target.pack(lowered.inline_path_address), lowered.chain)
                for symbol in ("open", "sendfile", "exit"):
                    address = libc_base + builder.libc.offset(symbol)
                    self.assertIn(builder.target.pack(address), lowered.chain)

                payload = lowered.as_payload()
                self.assertIs(payload.kind, PayloadKind.RET2LIBC)
                self.assertEqual(payload.data, lowered.data)
                self.assertEqual(payload.metadata["libc_sha256"], builder.libc.identity.sha256)
                self.assertEqual(payload.metadata["operations"], ("open", "sendfile", "exit"))

    def test_pwntools_links_shared_buffer_orw_without_appending_path(self) -> None:
        configurations = {
            32: (0xF7000000, 0x804C000, 0x804E000),
            64: (0x700000000000, 0x404000, 0x406000),
        }
        for bits, (libc_base, chain_base, scratch) in configurations.items():
            with self.subTest(bits=bits):
                builder = LibcROPBuilder.from_file(
                    self.fixtures[bits],
                    b"/flag",
                    writable_area=scratch,
                    writable_size=0x1000,
                )
                read = builder.read(3, 0x80)
                program = builder.compose(builder.open(), read, builder.write(1, 0x80), builder.exit())
                lowered = program.lower_pwntools(
                    RuntimeLayout(libc_base=libc_base),
                    chain_base=chain_base,
                )

                self.assertIsNone(lowered.inline_path_offset)
                self.assertEqual(lowered.data, lowered.chain)
                self.assertEqual(program.external_placements[0].address, scratch)
                buffer = read.arguments[1]
                self.assertIsInstance(buffer, int)
                self.assertIn(builder.target.pack(buffer), lowered.chain)

    def test_materialization_requires_a_runtime_libc_base(self) -> None:
        builder = LibcROPBuilder.from_file(self.fixtures[64], b"/flag")
        program = builder.compose(builder.open(), builder.exit())
        with self.assertRaisesRegex(LibcROPError, "runtime libc base"):
            program.materialize(RuntimeLayout(), chain_base=0x404000)

    def test_independent_sendfile_stage_does_not_need_the_inline_open_path(self) -> None:
        builder = LibcROPBuilder.from_file(self.fixtures[32], b"/flag")
        program = builder.compose(builder.open(), builder.sendfile(1, 7, 0x100))

        chain = program.lower_stage(1, return_to=0x8049000)

        resolved = chain.resolved_words(RuntimeLayout(libc_base=0xF7000000))
        self.assertEqual(resolved[2:6], (1, 7, 0, 0x100))


if __name__ == "__main__":
    unittest.main()
