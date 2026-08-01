from __future__ import annotations

import unittest

from payloads import Address, AddressResolutionError, Image, LibcIdentity, LibcImage, PayloadKind, RuntimeLayout
from payloads.rop import (
    AddressExpression,
    ChainWord,
    GadgetSelectionError,
    PointerKind,
    ROPBuildError,
    SemanticGadget,
    UnsupportedROPError,
    bind_libc_address,
    build_call,
    build_register_chain,
    build_ret2libc_system,
    build_static_call,
    build_static_syscall,
    build_syscall,
)
from payloads.target import ABI, SUPPORTED_TARGETS, Architecture, Endian, resolve_target

_DIRECT_CALL_UNSUPPORTED = {
    resolve_target("ppc64").name,
    resolve_target("sparc32").name,
    resolve_target("sparc64").name,
}


def words_from_bytes(target, data: bytes) -> tuple[int, ...]:
    return tuple(
        target.unpack(data[offset : offset + target.word_size]) for offset in range(0, len(data), target.word_size)
    )


def _matrix_call_gadgets(target) -> tuple[SemanticGadget, ...]:
    """Return one synthetic restore gadget for matrix-level builder coverage."""

    if target.arch is Architecture.X86:
        return ()

    registers = [target.convention.function_arguments[0]]
    if target.convention.link_register is not None:
        registers.append(target.convention.link_register)

    control_register = {
        Architecture.ARM64: "x16",
        Architecture.MIPS32: "t9",
        Architecture.MIPS64: "t9",
        Architecture.RISCV32: "t0",
        Architecture.RISCV64: "t0",
        Architecture.POWERPC32: "ctr",
        Architecture.POWERPC64: "r12",
        Architecture.S390X: "r1",
    }.get(target.arch)

    if control_register is not None:
        registers.append(control_register)
        next_pc_slot = len(registers) - 1
    else:
        next_pc_slot = len(registers)

    return (
        SemanticGadget(
            target,
            Address(0x100, Image.MAIN, "matrix restore gadget"),
            len(registers) + (1 if control_register is None else 0),
            {register: slot for slot, register in enumerate(registers)},
            next_pc_slot,
            "matrix restore and transfer",
            next_pc_register=control_register,
        ),
    )


def _materialize_aligned(chain, layout: RuntimeLayout) -> bytes:
    if chain.call_frame is None:
        raise AssertionError("call builder did not expose a CallFrame")
    candidate = 0x60000000
    frame = chain.call_frame
    chain_base = candidate + ((frame.required_chain_base_remainder - candidate) % frame.entry_sp_alignment)
    return chain.materialize(layout, chain_base=chain_base)


class RopTargetMatrixTests(unittest.TestCase):
    def test_static_syscall_materializes_for_every_catalog_target(self) -> None:
        layout = RuntimeLayout(main_base=0x400000)
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                number_register = target.convention.syscall_number
                argument_register = target.convention.syscall_arguments[0]
                gadget = SemanticGadget(
                    target,
                    Address(0x100, Image.MAIN, "matrix syscall restore"),
                    3,
                    {number_register: 0, argument_register: 1},
                    2,
                    "matrix syscall restore and transfer",
                )
                chain = build_static_syscall(target, 0x500, 93, (42,), gadgets=(gadget,))
                resolved = chain.resolved_words(layout)
                data = chain.materialize(layout)

                self.assertEqual(chain.target, target)
                self.assertEqual(chain.kind, PayloadKind.ROP)
                self.assertIn(93, resolved)
                self.assertIn(42, resolved)
                self.assertIn(target.entry_address(layout.main_base + 0x500), resolved)
                self.assertEqual(words_from_bytes(target, data), resolved)

    def test_static_call_materializes_for_every_direct_call_target(self) -> None:
        layout = RuntimeLayout(main_base=0x400000)
        exercised = set()
        for target in SUPPORTED_TARGETS:
            if target.name in _DIRECT_CALL_UNSUPPORTED:
                continue
            with self.subTest(target=target.name):
                chain = build_static_call(
                    target,
                    0x500,
                    (0x1234,),
                    gadgets=_matrix_call_gadgets(target),
                    return_to=Address(0x900, Image.MAIN, "matrix return"),
                )
                resolved = chain.resolved_words(layout)
                data = _materialize_aligned(chain, layout)

                exercised.add(target.name)
                self.assertEqual(chain.target, target)
                self.assertEqual(chain.kind, PayloadKind.ROP)
                self.assertIn(0x1234, resolved)
                self.assertIn(target.function_pointer(layout.main_base + 0x500), resolved)
                self.assertEqual(words_from_bytes(target, data), resolved)

        self.assertEqual(exercised, {target.name for target in SUPPORTED_TARGETS} - _DIRECT_CALL_UNSUPPORTED)

    def test_exact_identity_ret2libc_matrix_is_complete(self) -> None:
        main_base = 0x400000
        libc_base = 0x70000000
        layout = RuntimeLayout(main_base=main_base, libc_base=libc_base)
        exercised = set()
        rejected = set()
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                libc = LibcImage(LibcIdentity("ab" * 32), target, {"system": 0x5000})
                command = bind_libc_address(libc, 0x8000, "matrix command")
                if target.name in _DIRECT_CALL_UNSUPPORTED:
                    with self.assertRaises(UnsupportedROPError):
                        build_ret2libc_system(libc, command)
                    rejected.add(target.name)
                    continue

                chain = build_ret2libc_system(
                    libc,
                    command,
                    gadgets=_matrix_call_gadgets(target),
                    return_to=Address(0x900, Image.MAIN, "matrix return"),
                )
                resolved = chain.resolved_words(layout)
                data = _materialize_aligned(chain, layout)

                exercised.add(target.name)
                self.assertEqual(chain.target, target)
                self.assertEqual(chain.kind, PayloadKind.RET2LIBC)
                self.assertIn(libc_base + 0x8000, resolved)
                self.assertIn(target.function_pointer(libc_base + 0x5000), resolved)
                self.assertIn(libc.identity.sha256[:12], chain.description)
                self.assertEqual(words_from_bytes(target, data), resolved)

        self.assertEqual(exercised, {target.name for target in SUPPORTED_TARGETS} - _DIRECT_CALL_UNSUPPORTED)
        self.assertEqual(rejected, _DIRECT_CALL_UNSUPPORTED)


class DeferredAddressTests(unittest.TestCase):
    def test_address_expression_is_not_resolved_during_construction(self) -> None:
        target = resolve_target("x86_64")
        destination = AddressExpression.main(0x120, "entry") + 0x34
        chain = build_register_chain(target, {}, (), destination)

        self.assertIs(chain.words[0].value, destination)
        with self.assertRaises(AddressResolutionError):
            chain.materialize()
        self.assertEqual(chain.resolved_words(RuntimeLayout(main_base=0x55555000)), (0x55555154,))

    def test_one_symbolic_chain_can_be_materialized_for_different_layouts(self) -> None:
        target = resolve_target("x86_64")
        gadget = SemanticGadget(
            target,
            Address(0x1010, Image.MAIN, "pop rdi; ret"),
            2,
            {"rdi": 0},
            1,
            "pop rdi; ret",
        )
        libc = LibcImage(LibcIdentity("01" * 32), target, {"system": 0x52290})
        command = bind_libc_address(libc, 0x1B45BD, "/bin/sh")
        chain = build_ret2libc_system(libc, command, gadgets=(gadget,), return_to=0)

        self.assertEqual(chain.kind, PayloadKind.RET2LIBC)
        with self.assertRaises(AddressResolutionError):
            chain.materialize()

        first = RuntimeLayout(main_base=0x55555000, libc_base=0x7F0000000000)
        second = RuntimeLayout(main_base=0x56556000, libc_base=0x7E0000000000)
        self.assertEqual(
            chain.resolved_words(first),
            (0x55556010, 0x7F00001B45BD, 0x7F0000052290, 0),
        )
        self.assertEqual(
            chain.resolved_words(second),
            (0x56557010, 0x7E00001B45BD, 0x7E0000052290, 0),
        )


class LibcProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = resolve_target("x86_64")
        self.libc = LibcImage(LibcIdentity("10" * 32), self.target, {"system": 0x50000})
        self.other_libc = LibcImage(LibcIdentity("20" * 32), self.target, {"system": 0x50000})

    def test_libc_relative_command_must_be_bound_to_selected_identity(self) -> None:
        with self.assertRaisesRegex(ROPBuildError, "no exact LibcIdentity binding"):
            build_ret2libc_system(self.libc, Address(0x180000, Image.LIBC))
        with self.assertRaisesRegex(ROPBuildError, self.other_libc.identity.sha256[:12]):
            build_ret2libc_system(self.libc, bind_libc_address(self.other_libc, 0x180000))

    def test_libc_relative_gadget_must_be_bound_to_selected_identity(self) -> None:
        raw_gadget = SemanticGadget(
            self.target,
            Address(0x1000, Image.LIBC, "pop rdi; ret"),
            2,
            {"rdi": 0},
            1,
            "libc pop rdi",
        )
        with self.assertRaisesRegex(ROPBuildError, "gadget .* no exact LibcIdentity binding"):
            build_ret2libc_system(
                self.libc,
                Address(0x80, Image.STACK, "command buffer"),
                gadgets=(raw_gadget,),
            )

        wrong_gadget = SemanticGadget(
            self.target,
            bind_libc_address(self.other_libc, 0x1000, "pop rdi; ret"),
            2,
            {"rdi": 0},
            1,
            "other-libc pop rdi",
        )
        with self.assertRaisesRegex(ROPBuildError, self.other_libc.identity.sha256[:12]):
            build_ret2libc_system(
                self.libc,
                Address(0x80, Image.STACK, "command buffer"),
                gadgets=(wrong_gadget,),
            )

    def test_bound_gadget_and_non_libc_command_stay_symbolic(self) -> None:
        gadget = SemanticGadget(
            self.target,
            bind_libc_address(self.libc, 0x1000, "pop rdi; ret"),
            2,
            {"rdi": 0},
            1,
            "libc pop rdi",
        )
        command = Address(0x80, Image.STACK, "command buffer")
        chain = build_ret2libc_system(self.libc, command, gadgets=(gadget,))

        with self.assertRaises(AddressResolutionError):
            chain.materialize()
        self.assertEqual(
            chain.resolved_words(RuntimeLayout(libc_base=0x70000000, stack_base=0x7FFFFFF0)),
            (0x70001000, 0x80000070, 0x70050000, 0),
        )


class CallingConventionTests(unittest.TestCase):
    def test_i386_ret2libc_uses_real_cdecl_stack_shape_and_little_endian_words(self) -> None:
        target = resolve_target("x86")
        libc = LibcImage(LibcIdentity("02" * 32), target, {"system": 0x3ADA0, "exit": 0x2E9D0})
        chain = build_ret2libc_system(
            libc,
            bind_libc_address(libc, 0x15BA0B, "/bin/sh"),
            return_to=bind_libc_address(libc, "exit"),
        )
        layout = RuntimeLayout(libc_base=0xF7D00000)
        expected = (0xF7D3ADA0, 0xF7D2E9D0, 0xF7E5BA0B)

        self.assertEqual(chain.resolved_words(layout), expected)
        self.assertEqual(chain.materialize(layout), b"".join(target.pack(word) for word in expected))
        self.assertEqual(chain.materialize(layout)[:4], b"\xa0\xad\xd3\xf7")

    def test_amd64_register_arguments_and_stack_overflow_arguments(self) -> None:
        target = resolve_target("x86_64")
        slots = {register: index for index, register in enumerate(target.convention.function_arguments)}
        gadget = SemanticGadget(target, 0x401000, 7, slots, 6, "load six argument registers")
        arguments = tuple(range(1, 8))
        chain = build_call(target, 0x402000, arguments, gadgets=(gadget,), return_to=0x403000)

        self.assertEqual(
            chain.resolved_words(),
            (0x401000, 1, 2, 3, 4, 5, 6, 0x402000, 0x403000, 7),
        )

    def test_big_endian_arm_call_loads_link_register_explicitly(self) -> None:
        target = resolve_target("arm", endian="big")
        gadget = SemanticGadget(
            target,
            Address(0x80, Image.MAIN),
            3,
            {"r0": 0, "lr": 1},
            2,
            "pop r0, lr, pc",
        )
        chain = build_static_call(
            target,
            0x400,
            (0x11223344,),
            gadgets=(gadget,),
            return_to=Address(0x500, Image.MAIN),
        )
        layout = RuntimeLayout(main_base=0x10000)
        expected = (0x10080, 0x11223344, 0x10500, 0x10400)

        self.assertEqual(chain.resolved_words(layout), expected)
        self.assertEqual(chain.materialize(layout), b"".join(target.pack(word) for word in expected))
        self.assertEqual(chain.materialize(layout)[4:8], b"\x11\x22\x33\x44")

    def test_thumb_state_bits_are_applied_only_to_execution_pointers(self) -> None:
        target = resolve_target("thumb")
        gadget = SemanticGadget(target, 0x1000, 3, {"r0": 0, "lr": 1}, 2, "thumb pop frame")
        chain = build_call(target, 0x2000, (0x3000,), gadgets=(gadget,), return_to=0x4000)

        # The argument is data and remains even.  Gadget, function, and LR are
        # execution pointers and select Thumb state at materialization.
        self.assertEqual(chain.resolved_words(), (0x1001, 0x3000, 0x4001, 0x2001))

    def test_mips_dynamic_call_prepares_t9(self) -> None:
        target = resolve_target("mips32", endian="big")
        gadget = SemanticGadget(
            target,
            0x1000,
            4,
            {"a0": 0, "t9": 1, "ra": 2},
            1,
            "restore a0, t9, ra; jr t9",
            fixed_slots={3: 0},
            next_pc_register="t9",
        )
        libc = LibcImage(LibcIdentity("03" * 32), target, {"system": 0x41000})
        chain = build_ret2libc_system(
            libc,
            bind_libc_address(libc, 0x100000, "/bin/sh"),
            gadgets=(gadget,),
            return_to=0,
        )
        words = chain.resolved_words(RuntimeLayout(libc_base=0x70000000))

        self.assertEqual(words, (0x1000, 0x70100000, 0x70041000, 0, 0, 0, 0, 0, 0))
        self.assertIsNotNone(chain.call_frame)
        self.assertEqual(chain.call_frame.caller_area_size, 16)
        self.assertEqual(chain.function_entry_sp_offset, 20)
        self.assertEqual(chain.function_entry_sp_alignment, 8)
        self.assertEqual(chain.validate_call_frame(0x70000004), 0x70000018)
        with self.assertRaises(ROPBuildError):
            chain.materialize(RuntimeLayout(libc_base=0x70000000), chain_base=0x70000000)

    def test_aarch64_call_needs_distinct_branch_and_return_registers(self) -> None:
        target = resolve_target("arm64")
        gadget = SemanticGadget(
            target,
            0x1000,
            3,
            {"x0": 0, "x30": 1, "x16": 2},
            2,
            "restore x0, x30, x16; br x16",
            next_pc_register="x16",
        )
        chain = build_call(target, 0x2000, (7,), gadgets=(gadget,), return_to=0x3000)
        self.assertEqual(chain.resolved_words(), (0x1000, 7, 0x3000, 0x2000))

        ret_x30 = SemanticGadget(
            target,
            0x1100,
            2,
            {"x0": 0, "x30": 1},
            1,
            "restore x0, x30; ret",
            next_pc_register="x30",
        )
        with self.assertRaises(GadgetSelectionError) as caught:
            build_call(target, 0x2000, (7,), gadgets=(ret_x30,), return_to=0x3000)
        self.assertEqual(caught.exception.missing_registers, ("x30",))


class SemanticGadgetTests(unittest.TestCase):
    def test_register_slot_cannot_also_be_declared_clobbered(self) -> None:
        target = resolve_target("x86_64")
        with self.assertRaisesRegex(ROPBuildError, "both stack-loaded and clobbered: rdi"):
            SemanticGadget(target, 0x1000, 2, {"rdi": 0}, 1, clobbers={"rdi"})

    def test_primary_register_abis_use_caller_supplied_semantics(self) -> None:
        aliases = (
            "x86_64",
            "arm",
            "arm64",
            "mips32",
            "mips64",
            "riscv32",
            "riscv64",
            "powerpc32",
            "powerpc64le",
            "s390x",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                target = resolve_target(alias)
                number_register = target.convention.syscall_number
                argument_register = target.convention.syscall_arguments[0]
                control_register = {
                    Architecture.ARM64: "x30",
                    Architecture.MIPS32: "ra",
                    Architecture.MIPS64: "ra",
                    Architecture.RISCV32: "ra",
                    Architecture.RISCV64: "ra",
                    Architecture.POWERPC32: "lr",
                    Architecture.POWERPC64: "lr",
                    Architecture.S390X: "r14",
                }.get(target.arch)
                register_slots = {number_register: 0, argument_register: 2}
                if control_register is not None:
                    register_slots[control_register] = 3
                gadget = SemanticGadget(
                    target,
                    0x1000,
                    4,
                    register_slots,
                    3,
                    f"{alias} explicit restore frame",
                    fixed_slots={1: 0xA5},
                    next_pc_register=control_register,
                )
                chain = build_syscall(target, 0x2000, 93, (7,), gadgets=(gadget,))
                expected = (target.entry_address(0x1000), 93, 0xA5, 7, target.entry_address(0x2000))

                self.assertEqual(chain.resolved_words(), expected)
                self.assertEqual(words_from_bytes(target, chain.materialize()), expected)

    def test_big_endian_64_bit_syscall_packing(self) -> None:
        target = resolve_target("mips64", endian="big")
        gadget = SemanticGadget(
            target,
            0x1200,
            3,
            {"v0": 0, "a0": 1, "ra": 2},
            2,
            "restore v0, a0, ra",
            next_pc_register="ra",
        )
        chain = build_syscall(target, 0x1400, 0x1122334455667788, (0xAABBCCDDEEFF0011,), gadgets=(gadget,))

        data = chain.materialize()
        self.assertEqual(data[8:16], b"\x11\x22\x33\x44\x55\x66\x77\x88")
        self.assertEqual(data[16:24], b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11")

    def test_selector_finds_an_order_that_preserves_live_registers(self) -> None:
        target = resolve_target("x86_64")
        load_rsi = SemanticGadget(target, 0x1100, 2, {"rsi": 0}, 1, "pop rsi", clobbers={"rdi"})
        load_rdi = SemanticGadget(target, 0x1000, 2, {"rdi": 0}, 1, "pop rdi", clobbers={"rsi"})
        reload_rsi = SemanticGadget(target, 0x1200, 2, {"rsi": 0}, 1, "pop rsi preserving rdi")
        chain = build_register_chain(
            target,
            {"rdi": 1, "rsi": 2},
            (load_rsi, load_rdi, reload_rsi),
            0x2000,
        )

        self.assertEqual(chain.steps, ("pop rdi", "pop rsi preserving rdi"))
        self.assertEqual(chain.resolved_words(), (0x1000, 1, 0x1200, 2, 0x2000))

    def test_missing_registers_are_reported_structurally(self) -> None:
        target = resolve_target("arm64")
        gadget = SemanticGadget(target, 0x1000, 2, {"x0": 0}, 1)
        with self.assertRaises(GadgetSelectionError) as caught:
            build_register_chain(target, {"x0": 1, "x8": 221}, (gadget,), 0x2000)

        self.assertEqual(caught.exception.target, target)
        self.assertEqual(caught.exception.missing_registers, ("x8",))
        self.assertIn("x8", str(caught.exception))


class StaticAndPeculiarAbiTests(unittest.TestCase):
    def test_static_main_relative_function_and_syscall_chains(self) -> None:
        target = resolve_target("x86_64")
        call_gadget = SemanticGadget(target, Address(0x100, Image.MAIN), 2, {"rdi": 0}, 1, "pop rdi")
        call = build_static_call(target, 0x500, (0xCAFE,), gadgets=(call_gadget,), return_to=0)

        syscall_gadget = SemanticGadget(
            target,
            Address(0x200, Image.MAIN),
            3,
            {"rax": 0, "rdi": 1},
            2,
            "pop rax, rdi",
        )
        syscall = build_static_syscall(target, 0x600, 60, (0,), gadgets=(syscall_gadget,))
        layout = RuntimeLayout(main_base=0x400000)

        self.assertEqual(call.resolved_words(layout), (0x400100, 0xCAFE, 0x400500, 0))
        self.assertEqual(syscall.resolved_words(layout), (0x400200, 60, 0, 0x400600))

    def test_static_ppc64_elfv2_prepares_r12_and_reserves_minimum_frame(self) -> None:
        target = resolve_target("powerpc64le")
        gadget = SemanticGadget(
            target,
            Address(0x100, Image.MAIN, "restore and branch ctr"),
            4,
            {"r3": 0, "lr": 1, "r12": 2, "ctr": 3},
            3,
            "restore r3, lr, r12, ctr; bctr",
            next_pc_register="ctr",
        )
        chain = build_static_call(
            target,
            0x500,
            (7,),
            gadgets=(gadget,),
            return_to=Address(0x900, Image.MAIN, "return"),
        )
        layout = RuntimeLayout(main_base=0x10000000)

        self.assertEqual(
            chain.resolved_words(layout),
            (0x10000100, 7, 0x10000900, 0x10000500, 0x10000500, 0, 0, 0, 0),
        )
        self.assertEqual(chain.call_frame.caller_area_size, 32)
        self.assertEqual(chain.call_frame.entry_sp_offset, 40)
        self.assertEqual(chain.call_frame.entry_sp_alignment, 16)
        self.assertEqual(chain.call_frame.required_chain_base_remainder, 8)
        self.assertEqual(chain.validate_entry_sp(0x10000030, chain_base=0x10000008), 0x10000030)

    def test_powerpc32_calls_reserve_the_linkage_frame_in_both_byte_orders(self) -> None:
        for endian in ("big", "little"):
            with self.subTest(endian=endian):
                target = resolve_target("powerpc32", endian=endian)
                gadget = SemanticGadget(
                    target,
                    0x1000,
                    3,
                    {"r3": 0, "lr": 1, "ctr": 2},
                    2,
                    "restore argument, lr, ctr; bctr",
                    next_pc_register="ctr",
                )
                chain = build_call(target, 0x4000, (7,), gadgets=(gadget,), return_to=0x5000)

                self.assertEqual(chain.resolved_words(), (0x1000, 7, 0x5000, 0x4000, 0, 0, 0, 0))
                self.assertEqual(chain.call_frame.caller_area_size, 16)
                self.assertEqual(chain.call_frame.entry_sp_alignment, 16)

    def test_s390x_call_reserves_caller_save_area(self) -> None:
        target = resolve_target("s390x")
        gadget = SemanticGadget(
            target,
            0x1000,
            3,
            {"r2": 0, "r14": 1, "r1": 2},
            2,
            "restore argument, return, and branch register",
            next_pc_register="r1",
        )
        chain = build_call(target, 0x4000, (7,), gadgets=(gadget,), return_to=0x5000)

        self.assertEqual(chain.resolved_words()[:4], (0x1000, 7, 0x5000, 0x4000))
        self.assertEqual(chain.resolved_words()[4:], (0,) * 20)
        self.assertEqual(chain.call_frame.caller_area_size, 160)
        self.assertEqual(chain.call_frame.entry_sp_offset, 32)
        self.assertEqual(chain.call_frame.entry_sp_alignment, 8)
        self.assertEqual(chain.validate_call_frame(entry_sp=0x7FFFFFE0), 0x7FFFFFE0)

    def test_ppc64_elfv1_function_calls_are_rejected_but_syscalls_are_not(self) -> None:
        target = resolve_target("ppc64")
        with self.assertRaises(UnsupportedROPError) as caught:
            build_call(target, 0x10000, (1,))
        self.assertEqual(caught.exception.feature, "direct function call")
        self.assertIn("descriptor", caught.exception.reason)
        self.assertIn("TOC", caught.exception.reason)

        gadget = SemanticGadget(
            target,
            0x20000,
            3,
            {"r0": 0, "r3": 1, "lr": 2},
            2,
            "restore syscall registers and lr",
            next_pc_register="lr",
        )
        chain = build_syscall(target, 0x21000, 1, (7,), gadgets=(gadget,))
        self.assertEqual(chain.resolved_words(), (0x20000, 1, 7, 0x21000))

    def test_sparc_direct_call_failure_is_explicit(self) -> None:
        target = resolve_target("sparc64")
        with self.assertRaises(UnsupportedROPError) as caught:
            build_call(target, 0x1000)
        self.assertEqual(caught.exception.target.arch, Architecture.SPARC64)
        self.assertIn("register windows", caught.exception.reason)

    def test_non_x86_register_overflow_is_not_guessed(self) -> None:
        target = resolve_target("arm")
        with self.assertRaises(UnsupportedROPError) as caught:
            build_call(target, 0x1000, (1, 2, 3, 4, 5))
        self.assertEqual(caught.exception.feature, "stack function arguments")
        self.assertEqual(caught.exception.target.abi, ABI.ARM_EABI)

    def test_chainword_code_and_data_pointer_kinds_differ_for_thumb(self) -> None:
        target = resolve_target("thumb")
        code = ChainWord(0x2000, pointer_kind=PointerKind.CODE)
        data = ChainWord(0x2000, pointer_kind=PointerKind.DATA)
        self.assertEqual(code.resolve(target), 0x2001)
        self.assertEqual(data.resolve(target), 0x2000)

    def test_target_matrix_includes_both_word_widths_and_byte_orders_used_here(self) -> None:
        targets = (
            resolve_target("x86"),
            resolve_target("x86_64"),
            resolve_target("mipseb"),
            resolve_target("mips64eb"),
        )
        self.assertEqual({target.bits for target in targets}, {32, 64})
        self.assertEqual({target.endian for target in targets}, {Endian.LITTLE, Endian.BIG})


if __name__ == "__main__":
    unittest.main()
