from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from payloads.arbio import ArbitraryMemory, IOPrimitiveTraits
from payloads.discovery import (
    DiscoveryAmbiguityError,
    DiscoveryError,
    ExactProcessDiscovery,
    ImageResolution,
    InconsistentLinkMapError,
    MemorySpan,
    PointerLeak,
    RDebugState,
    StaleDiscoveryError,
)
from payloads.elf import ELFImageKind, ELFProfile, ELFRange
from payloads.errors import ConstraintError, MemoryAccessError, UnsupportedTargetError
from payloads.libc import LibcIdentity
from payloads.model import Image, Linkage, Permission, Relro
from payloads.pwntools_compat import ExactELFAdapter, PwntoolsMitigations
from payloads.rop import ChainWord, ROPChain
from payloads.target import Target, resolve_target


class SparseMemory:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.write_calls: list[tuple[int, bytes]] = []

    def map(self, address: int, data: bytes | bytearray) -> None:
        self.bytes.update((address + offset, value) for offset, value in enumerate(bytes(data)))

    def read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.bytes[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError(f"unmapped address {int(exc.args[0]):#x}") from exc

    def write(self, address: int, data: bytes) -> int:
        raw = bytes(data)
        if any(address + offset not in self.bytes for offset in range(len(raw))):
            raise OSError("unmapped write")
        self.map(address, raw)
        self.write_calls.append((address, raw))
        return len(raw)


def exact_adapter(
    root: Path,
    target: Target,
    name: str,
    *,
    start: int = 0,
    size: int = 0x1000,
    writable: bool = True,
    executable: bool = True,
    symbols: dict[str, int] | None = None,
    elf_type: str = "ET_DYN",
    pie: bool = False,
    image_kind: ELFImageKind = ELFImageKind.SHARED_OBJECT,
    patches: dict[int, bytes] | None = None,
) -> ExactELFAdapter:
    data = bytearray(size)
    byteorder = target.endian.value
    header_size = 64 if target.bits == 64 else 52
    phentsize = 56 if target.bits == 64 else 32
    machine = {
        "x86": 3,
        "x86_64": 62,
        "arm": 40,
        "thumb": 40,
        "arm64": 183,
        "mips32": 8,
        "mips64": 8,
    }[target.arch.value]

    def put(offset: int, value: int, width: int) -> None:
        data[offset : offset + width] = value.to_bytes(width, byteorder)

    data[:16] = (
        b"\x7fELF"
        + (b"\x02" if target.bits == 64 else b"\x01")
        + (b"\x01" if target.endian.value == "little" else b"\x02")
        + b"\x01"
        + b"\0" * 9
    )
    put(16, 3 if elf_type == "ET_DYN" else 2, 2)
    put(18, machine, 2)
    put(20, 1, 4)
    if target.bits == 64:
        put(32, header_size, 8)
        put(52, header_size, 2)
        put(54, phentsize, 2)
        put(56, 1, 2)
        phdr = header_size
        put(phdr, 1, 4)
        put(phdr + 4, 7 if writable and executable else 6 if writable else 5 if executable else 4, 4)
        put(phdr + 8, 0, 8)
        put(phdr + 16, start, 8)
        put(phdr + 24, start, 8)
        put(phdr + 32, size, 8)
        put(phdr + 40, size, 8)
        put(phdr + 48, 0x1000, 8)
    else:
        put(28, header_size, 4)
        put(40, header_size, 2)
        put(42, phentsize, 2)
        put(44, 1, 2)
        phdr = header_size
        put(phdr, 1, 4)
        put(phdr + 4, 0, 4)
        put(phdr + 8, start, 4)
        put(phdr + 12, start, 4)
        put(phdr + 16, size, 4)
        put(phdr + 20, size, 4)
        put(phdr + 24, 7 if writable and executable else 6 if writable else 5 if executable else 4, 4)
        put(phdr + 28, 0x1000, 4)
    for offset, value in (patches or {}).items():
        data[offset : offset + len(value)] = value
    path = root / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    permissions = Permission.READ
    if writable:
        permissions |= Permission.WRITE
    if executable:
        permissions |= Permission.EXECUTE
    load = ELFRange(start, start + size, permissions, 0, size, 0x1000, "PT_LOAD")
    loaded_symbols = symbols or {}
    profile = ELFProfile(
        path=str(path),
        sha256=digest,
        build_id=None,
        target=target,
        osabi="ELFOSABI_SYSV",
        elf_type=elf_type,
        image_kind=image_kind,
        pie=pie,
        linkage=Linkage.DYNAMIC,
        nx=True,
        nx_evidence="synthetic test",
        relro=Relro.PARTIAL,
        bind_now=False,
        entry_offset=start,
        interpreter=None,
        needed_libraries=(),
        soname=name,
        load_ranges=(load,),
        relro_ranges=(),
        load_alignment_hint=0x1000,
        symbol_offsets=loaded_symbols,
    )
    return ExactELFAdapter(
        str(path),
        LibcIdentity(digest, source=str(path)),
        profile,
        loaded_symbols,
        PwntoolsMitigations(pie, True, Relro.PARTIAL, False, False),
    )


def map_adapter(backend: SparseMemory, adapter: ExactELFAdapter, load_bias: int) -> None:
    artifact = Path(adapter.path).read_bytes()
    for load in adapter.profile.load_ranges:
        data = artifact[load.file_offset : load.file_offset + load.file_size]
        backend.map(load_bias + load.start, data + b"\0" * (load.size - len(data)))


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def memory(self, target: Target, backend: SparseMemory, *, invalid_safe: bool = False) -> ArbitraryMemory:
        return ArbitraryMemory(
            target,
            read_at=backend.read,
            write_at=backend.write,
            traits=IOPrimitiveTraits(invalid_read_safe=invalid_safe),
        )

    def test_heap_to_libc_collapses_corroborating_pointer_slots(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc.so.6")
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        heap = 0x500000
        backend.map(heap, bytearray(0x40))
        backend.map(heap + 8, target.pack(libc_base + 0x120))
        backend.map(heap + 0x18, target.pack(libc_base + 0x300))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        result = resolver.heap_to_libc(
            heap,
            heap_base=heap,
            heap_span=MemorySpan(heap, 0x40),
            libc_base=libc_base,
        )

        self.assertEqual(result.base, libc_base)
        self.assertIn(hex(heap + 8), result.evidence[-1])
        self.assertIn(hex(heap + 0x18), result.evidence[-1])

    def test_heap_to_libc_rejects_distinct_runtime_images(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc.so.6")
        first, second = 0x700000, 0x900000
        map_adapter(backend, libc, first)
        map_adapter(backend, libc, second)
        heap = 0x500000
        backend.map(heap, bytearray(0x20))
        backend.map(heap, target.pack(first + 0x100) + target.pack(second + 0x100))
        resolver = ExactProcessDiscovery(self.memory(target, backend, invalid_safe=True), libc=libc)

        with self.assertRaises(DiscoveryAmbiguityError):
            resolver.heap_to_libc(
                heap,
                heap_span=MemorySpan(heap, 0x20),
                image_search_pages=2,
            )

    def test_embedded_page_aligned_elf_magic_cannot_misbase_image(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-magic.so.6", size=0x3000)
        libc_base = 0x700000
        false_header = libc_base + 0x1000
        map_adapter(backend, libc, libc_base)
        backend.map(false_header, b"\x7fELF" + b"not-a-runtime-header")
        heap = 0x500000
        backend.map(heap, target.pack(false_header + 0x100))
        resolver = ExactProcessDiscovery(self.memory(target, backend, invalid_safe=True), libc=libc)

        result = resolver.heap_to_libc(
            heap,
            heap_span=MemorySpan(heap, target.word_size),
            image_search_pages=2,
        )

        self.assertEqual(result.base, libc_base)

    def test_explicit_image_base_is_verified_against_runtime_bytes(self) -> None:
        target = resolve_target("x86")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc32.so.6")
        base = 0x70000000
        backend.map(base, b"X" * 0x1000)
        heap = 0x10000
        backend.map(heap, target.pack(base + 0x100))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(DiscoveryError, "identity mismatch"):
            resolver.heap_to_libc(
                heap,
                heap_span=MemorySpan(heap, target.word_size),
                libc_base=base,
                libc_pointer=base + 0x100,
            )

    def test_libc_to_heap_collapses_multiple_pointers_into_one_span(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc.so.6")
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        heap = MemorySpan(0x500000, 0x1000)
        backend.map(libc_base + 0x400, target.pack(heap.address + 0x20))
        backend.map(libc_base + 0x500, target.pack(heap.address + 0x80))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)
        libc_resolution = ImageResolution(
            Image.LIBC,
            libc_base,
            libc,
            PointerLeak(libc_base + 0x100),
        )

        result = resolver.libc_to_heap(libc_resolution, heap_base=heap.address, heap_span=heap)

        self.assertTrue(heap.contains(result.pointer))
        self.assertIn(hex(libc_base + 0x400), result.evidence[-1])
        self.assertIn(hex(libc_base + 0x500), result.evidence[-1])

    def test_libc_to_heap_requires_positive_classification_evidence(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc.so.6")
        base = 0x700000
        map_adapter(backend, libc, base)
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(ConstraintError, "heap classification"):
            resolver.libc_to_heap(PointerLeak(base + 0x100), libc_base=base)

    def _return_fixture(self):
        target = resolve_target("x86_64")
        backend = SparseMemory()
        main_base = 0x400000
        call_offset = 0x200
        main = exact_adapter(
            self.root,
            target,
            "main",
            pie=True,
            image_kind=ELFImageKind.PIE_EXECUTABLE,
            symbols={"main": 0x100},
            patches={call_offset: b"\xe8\0\0\0\0"},
        )
        libc_base = 0x700000
        environ_offset = 0x300
        libc = exact_adapter(self.root, target, "libc.so.6", symbols={"environ": environ_offset})
        map_adapter(backend, main, main_base)
        map_adapter(backend, libc, libc_base)
        stack = MemorySpan(0x900000, 0x200)
        backend.map(stack.address, bytearray(stack.size))
        environ_pointer = stack.address + 0x100
        backend.map(libc_base + environ_offset, target.pack(environ_pointer))
        backend.map(environ_pointer, target.pack(stack.address + 0x180))
        backend.map(stack.address + 0x180, b"X=1\0")
        return_address = main_base + call_offset + 5
        return_slot = stack.address + 0x80
        backend.map(return_slot, target.pack(return_address))
        resolver = ExactProcessDiscovery(self.memory(target, backend), main=main, libc=libc)
        return target, backend, resolver, libc_base, main_base, stack, return_slot, return_address

    def test_environ_return_classification_and_flat_rop_plan(self) -> None:
        target, backend, resolver, libc_base, main_base, stack, slot, return_address = self._return_fixture()
        stack_result = resolver.libc_to_stack(
            PointerLeak(libc_base + 0x100),
            libc_base=libc_base,
            stack_base=stack.address,
            stack_span=stack,
        )
        result = resolver.environ_to_main_return(
            stack_result,
            main_base=main_base,
            return_slot=slot,
        )
        self.assertEqual((result.slot_address, result.return_address), (slot, return_address))
        self.assertEqual(result.call_site, main_base + 0x200)

        chain = ROPChain(target, (ChainWord(0x4141414142424242), ChainWord(0x4343434344444444)))
        plan = resolver.plan_rop_insertion(result, chain, main_base=main_base)
        self.assertEqual(plan.apply(resolver.memory), chain.byte_length)
        self.assertEqual(backend.read(slot, chain.byte_length), chain.materialize())

    def test_return_slots_remain_strictly_ambiguous(self) -> None:
        _target, backend, resolver, libc_base, main_base, stack, slot, return_address = self._return_fixture()
        backend.map(slot + 0x10, resolver.target.pack(return_address))
        stack_result = resolver.libc_to_stack(
            PointerLeak(libc_base + 0x100),
            libc_base=libc_base,
            stack_base=stack.address,
            stack_span=stack,
        )
        with self.assertRaises(DiscoveryAmbiguityError):
            resolver.environ_to_main_return(stack_result, main_base=main_base)

    def test_stale_rop_plan_performs_no_writes(self) -> None:
        target, backend, resolver, libc_base, main_base, stack, slot, _return_address = self._return_fixture()
        stack_result = resolver.libc_to_stack(
            PointerLeak(libc_base + 0x100),
            libc_base=libc_base,
            stack_base=stack.address,
            stack_span=stack,
        )
        result = resolver.environ_to_main_return(stack_result, main_base=main_base, return_slot=slot)
        chain = ROPChain(target, (ChainWord(0x4141414141414141), ChainWord(0x4242424242424242)))
        plan = resolver.plan_rop_insertion(result, chain)
        backend.map(slot + target.word_size, b"Z" * target.word_size)
        writes_before = len(backend.write_calls)

        with self.assertRaises(StaleDiscoveryError):
            plan.apply(resolver.memory)
        self.assertEqual(len(backend.write_calls), writes_before)

    def test_non_x86_flat_rop_insertion_is_explicitly_unsupported(self) -> None:
        target = resolve_target("mips32", endian="big")
        backend = SparseMemory()
        main = exact_adapter(self.root, target, "main-mips", pie=True, image_kind=ELFImageKind.PIE_EXECUTABLE)
        map_adapter(backend, main, 0x400000)
        backend.map(0x900000, b"\0" * 0x20)
        resolver = ExactProcessDiscovery(self.memory(target, backend), main=main)
        from payloads.discovery import MainReturnAddress, ReturnClassification

        site = MainReturnAddress(
            0x900000,
            0x400100,
            0x400000,
            0x100,
            None,
            ReturnClassification.MAIN_EXECUTABLE_POINTER,
        )
        with self.assertRaises(UnsupportedTargetError):
            resolver.plan_rop_insertion(site, ROPChain(target, (ChainWord(0x400200),)))

    def test_pointer_scans_preflight_primitive_constraints(self) -> None:
        target = resolve_target("x86")
        backend = SparseMemory()
        backend.map(0x1000, b"\0" * 8)
        memory = ArbitraryMemory(
            target,
            read_at=backend.read,
            traits=IOPrimitiveTraits(read_alignment=4, read_width=4),
        )
        resolver = ExactProcessDiscovery(memory)
        with self.assertRaises(MemoryAccessError):
            resolver.scan_pointers(MemorySpan(0x1001, 4))

    def test_link_map_layout_is_target_width_and_endian_driven(self) -> None:
        cases = (
            resolve_target("x86"),
            resolve_target("x86_64"),
            resolve_target("mips32", endian="big"),
            resolve_target("mips64", endian="big"),
        )
        for index, target in enumerate(cases):
            with self.subTest(target=target.name):
                backend = SparseMemory()
                loader = exact_adapter(self.root, target, f"ld-{index}.so", symbols={"_r_debug": 0x200})
                loader_base = 0x70000000 if target.bits == 32 else 0x700000000000
                map_adapter(backend, loader, loader_base)
                word = target.word_size
                debug = loader_base + 0x200
                first = 0x50000000 if target.bits == 32 else 0x500000000000
                second = first + 0x100
                first_name = first + 0x300
                second_name = second + 0x300

                r_debug = bytearray(word * 5)
                r_debug[:4] = (1).to_bytes(4, target.endian.value)
                r_debug[word : word * 2] = target.pack(first)
                r_debug[word * 2 : word * 3] = target.pack(loader_base + 0x300)
                r_debug[word * 3 : word * 3 + 4] = (0).to_bytes(4, target.endian.value)
                r_debug[word * 4 : word * 5] = target.pack(loader_base)
                backend.map(debug, r_debug)
                backend.map(
                    first,
                    target.pack(0)
                    + target.pack(first_name)
                    + target.pack(0x1110)
                    + target.pack(second)
                    + target.pack(0),
                )
                backend.map(
                    second,
                    target.pack(loader_base)
                    + target.pack(second_name)
                    + target.pack(loader_base + 0x500)
                    + target.pack(0)
                    + target.pack(first),
                )
                backend.map(first_name, b"\0")
                backend.map(second_name, b"ld-test.so\0")
                resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

                snapshot = resolver.loader_to_link_map(
                    PointerLeak(loader_base + 0x100),
                    loader_base=loader_base,
                    max_entries=4,
                )

                self.assertIs(snapshot.r_state, RDebugState.CONSISTENT)
                self.assertEqual(snapshot.r_ldbase, loader_base)
                self.assertEqual([item.name for item in snapshot.objects], ["", "ld-test.so"])
                self.assertEqual(snapshot.objects[1].previous_address, first)

    def test_link_map_cycle_and_bad_backlink_are_rejected(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        loader = exact_adapter(self.root, target, "ld.so", symbols={"_r_debug": 0x200})
        base = 0x700000
        map_adapter(backend, loader, base)
        debug = base + 0x200
        node = 0x500000
        word = target.word_size
        block = bytearray(word * 5)
        block[:4] = (1).to_bytes(4, "little")
        block[word : word * 2] = target.pack(node)
        block[word * 4 : word * 5] = target.pack(base)
        backend.map(debug, block)
        backend.map(node, target.pack(0) * 3 + target.pack(node) + target.pack(0))
        resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

        with self.assertRaisesRegex(InconsistentLinkMapError, "cycle"):
            resolver.loader_to_link_map(PointerLeak(base + 0x100), loader_base=base)

    def test_unknown_or_transitioning_r_debug_state_is_rejected(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        loader = exact_adapter(self.root, target, "ld.so", symbols={"_r_debug": 0x200})
        base = 0x700000
        map_adapter(backend, loader, base)
        debug = base + 0x200
        word = target.word_size
        block = bytearray(word * 5)
        block[:4] = (1).to_bytes(4, "little")
        block[word * 3 : word * 3 + 4] = (RDebugState.ADDING).to_bytes(4, "little")
        block[word * 4 : word * 5] = target.pack(base)
        backend.map(debug, block)
        resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

        with self.assertRaisesRegex(InconsistentLinkMapError, "not consistent"):
            resolver.loader_to_link_map(PointerLeak(base + 0x100), loader_base=base)

    def test_loader_override_must_point_inside_exact_loader(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc.so.6")
        loader = exact_adapter(self.root, target, "ld.so")
        libc_base, loader_base = 0x500000, 0x700000
        map_adapter(backend, libc, libc_base)
        map_adapter(backend, loader, loader_base)
        slot = libc_base + 0x500
        backend.map(slot, target.pack(0x1234))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc, loader=loader)
        libc_result = ImageResolution(
            Image.LIBC,
            libc_base,
            libc,
            PointerLeak(libc_base + 0x100),
        )

        with self.assertRaisesRegex(DiscoveryError, "outside exact loader"):
            resolver.libc_to_loader(
                libc_result,
                loader_base=loader_base,
                loader_pointer_address=slot,
            )

    @unittest.skipUnless(shutil.which("cc"), "a native C compiler is required")
    def test_libc_to_loader_prefers_pwntools_exact_got_slots(self) -> None:
        source = self.root / "source.c"
        shared = self.root / "libsource.so"
        source.write_text(
            "extern long loader_owned;\nlong read_loader_owned(void) { return loader_owned; }\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["cc", "-shared", "-fPIC", "-Wl,-soname,libsource.so", "-o", str(shared), str(source)],
            check=True,
            capture_output=True,
        )
        libc = ExactELFAdapter.from_file(shared)
        target = libc.target
        loader = exact_adapter(self.root, target, "ld-synthetic.so")
        backend = SparseMemory()
        libc_base, loader_base = 0x500000, 0x700000
        map_adapter(backend, libc, libc_base)
        map_adapter(backend, loader, loader_base)
        elf = libc.fresh_elf(runtime_base=libc_base)
        try:
            loader_slot = int(elf.got["loader_owned"])
        finally:
            elf.close()
        backend.map(loader_slot, target.pack(loader_base + 0x180))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc, loader=loader)

        result = resolver.libc_to_loader(
            PointerLeak(libc_base + 0x100),
            libc_base=libc_base,
            loader_base=loader_base,
        )

        self.assertEqual(result.base, loader_base)
        self.assertEqual(result.leak.address, loader_slot)
        self.assertIn("GOT slot", result.evidence[0])


if __name__ == "__main__":
    unittest.main()
