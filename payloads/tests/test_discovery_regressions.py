from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from payloads.arbio import ArbitraryMemory, IOPrimitiveTraits
from payloads.discovery import (
    DiscoveryError,
    DiscoveryNotFoundError,
    ExactProcessDiscovery,
    ImageResolution,
    MemorySpan,
    PointerLeak,
)
from payloads.elf import ELFImageKind
from payloads.errors import ConstraintError, MemoryAccessError
from payloads.model import Image
from payloads.target import resolve_target
from payloads.tests.test_discovery import SparseMemory, exact_adapter, map_adapter


class DiscoveryRegressionTests(unittest.TestCase):
    """Independent regressions for runtime-layout boundaries."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def memory(target, backend: SparseMemory, *, invalid_safe: bool = False) -> ArbitraryMemory:
        return ArbitraryMemory(
            target,
            read_at=backend.read,
            write_at=backend.write,
            traits=IOPrimitiveTraits(invalid_read_safe=invalid_safe),
        )

    def test_et_exec_uses_zero_load_bias_but_nonzero_header_address(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        linked_header = 0x400000
        call_offset = linked_header + 0x200
        main = exact_adapter(
            self.root,
            target,
            "nonpie-main",
            start=linked_header,
            elf_type="ET_EXEC",
            pie=False,
            image_kind=ELFImageKind.EXECUTABLE,
            symbols={"main": linked_header + 0x100},
            patches={0x200: b"\xe8\0\0\0\0"},
        )
        map_adapter(backend, main, 0)
        stack = MemorySpan(0x7FFF0000, 0x100)
        backend.map(stack.address, b"\0" * stack.size)
        return_slot = stack.address + 0x40
        return_address = call_offset + 5
        backend.map(return_slot, target.pack(return_address))
        resolver = ExactProcessDiscovery(self.memory(target, backend), main=main)

        result = resolver.environ_to_main_return(
            stack.address + 0x80,
            stack_span=stack,
            return_slot=return_slot,
        )

        self.assertEqual(result.main_base, 0)
        self.assertEqual(result.main_offset, return_address)
        self.assertEqual(result.call_site, call_offset)
        self.assertEqual(backend.read(linked_header, 4), b"\x7fELF")

    def test_explicit_pie_base_avoids_speculative_reads_and_wrong_base_is_rejected(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        main_base = 0x55555000
        main = exact_adapter(
            self.root,
            target,
            "pie-main",
            pie=True,
            image_kind=ELFImageKind.PIE_EXECUTABLE,
            patches={0x200: b"\xe8\0\0\0\0"},
        )
        map_adapter(backend, main, main_base)
        stack = MemorySpan(0x7FFF0000, 0x100)
        backend.map(stack.address, b"\0" * stack.size)
        return_slot = stack.address + 0x40
        backend.map(return_slot, target.pack(main_base + 0x205))
        resolver = ExactProcessDiscovery(self.memory(target, backend), main=main)

        result = resolver.environ_to_main_return(
            stack.address + 0x80,
            stack_span=stack,
            main_base=main_base,
            return_slot=return_slot,
        )
        self.assertEqual(result.main_base, main_base)

        with self.assertRaises((DiscoveryError, MemoryAccessError)):
            resolver.environ_to_main_return(
                stack.address + 0x80,
                stack_span=stack,
                main_base=main_base + 0x1000,
                return_slot=return_slot,
            )

    def test_malformed_page_aligned_elf_candidate_is_not_accepted(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-malformed.so.6")
        malformed_base = 0x710000
        malformed = bytearray(Path(libc.path).read_bytes())
        # Preserve convincing ELF identity bytes but make e_phnum invalid.
        malformed[56:58] = b"\0\0"
        backend.map(malformed_base, malformed)
        heap = 0x500000
        backend.map(heap, target.pack(malformed_base + 0x100))
        resolver = ExactProcessDiscovery(self.memory(target, backend, invalid_safe=True), libc=libc)

        with self.assertRaises(DiscoveryNotFoundError):
            resolver.heap_to_libc(
                heap,
                heap_span=MemorySpan(heap, target.word_size),
                image_search_pages=1,
            )

    def test_page_aligned_embedded_magic_resolves_enclosing_exact_image(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-embedded.so.6", size=0x4000)
        libc_base = 0x700000
        false_base = libc_base + 0x2000
        map_adapter(backend, libc, libc_base)
        backend.map(false_base, b"\x7fELF" + b"embedded-not-a-header")
        heap = 0x500000
        backend.map(heap, target.pack(false_base + 0x80))
        resolver = ExactProcessDiscovery(self.memory(target, backend, invalid_safe=True), libc=libc)

        result = resolver.heap_to_libc(
            heap,
            heap_span=MemorySpan(heap, target.word_size),
            image_search_pages=3,
        )

        self.assertEqual(result.base, libc_base)

    def test_big_endian_32_bit_link_map_honors_explicit_rendezvous_addresses(self) -> None:
        target = resolve_target("mips32", endian="big")
        backend = SparseMemory()
        loader = exact_adapter(self.root, target, "ld-mips.so")
        loader_base = 0x70000000
        map_adapter(backend, loader, loader_base)
        debug = loader_base + 0x280
        first = 0x50000000
        second = first + 0x80
        first_name = first + 0x200
        second_name = second + 0x200
        word = target.word_size

        r_debug = bytearray(word * 5)
        r_debug[:4] = (1).to_bytes(4, "big")
        r_debug[word : word * 2] = target.pack(first)
        r_debug[word * 2 : word * 3] = target.pack(loader_base + 0x444)
        r_debug[word * 3 : word * 3 + 4] = (0).to_bytes(4, "big")
        r_debug[word * 4 : word * 5] = target.pack(loader_base)
        backend.map(debug, r_debug)
        backend.map(
            first,
            target.pack(0x11110000)
            + target.pack(first_name)
            + target.pack(0x22220000)
            + target.pack(second)
            + target.pack(0),
        )
        backend.map(
            second,
            target.pack(loader_base)
            + target.pack(second_name)
            + target.pack(loader_base + 0x600)
            + target.pack(0)
            + target.pack(first),
        )
        backend.map(first_name, b"main\0")
        backend.map(second_name, b"ld-mips.so\0")
        resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

        snapshot = resolver.loader_to_link_map(
            PointerLeak(loader_base + 0x100),
            loader_base=loader_base,
            r_debug_address=debug,
            link_map_address=first,
        )

        self.assertEqual(snapshot.loader_base, loader_base)
        self.assertEqual(snapshot.r_debug_address, debug)
        self.assertEqual(snapshot.head_address, first)
        self.assertEqual([item.base for item in snapshot.objects], [0x11110000, loader_base])
        self.assertEqual([item.name for item in snapshot.objects], ["main", "ld-mips.so"])
        self.assertEqual(snapshot.objects[1].previous_address, first)

        with self.assertRaises(ConstraintError):
            resolver.loader_to_link_map(
                PointerLeak(loader_base + 0x100),
                loader_base=loader_base,
                r_debug_address=debug,
                link_map_address=second,
            )

    def test_explicit_libc_and_environ_addresses_work_without_loaded_symbol(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "stripped-libc.so.6", symbols={})
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        environ_address = libc_base + 0x380
        stack = MemorySpan(0x7FFF0000, 0x200)
        backend.map(stack.address, b"\0" * stack.size)
        environ_pointer = stack.address + 0x80
        first_environment = stack.address + 0x180
        backend.map(environ_address, target.pack(environ_pointer))
        backend.map(environ_pointer, target.pack(first_environment))
        backend.map(first_environment, b"A=B\0")
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)
        libc_resolution = ImageResolution(
            Image.LIBC,
            libc_base,
            libc,
            PointerLeak(libc_base + 0x100),
        )

        result = resolver.libc_to_stack(
            libc_resolution,
            libc_base=libc_base,
            environ_address=environ_address,
            stack_base=stack.address,
            stack_span=stack,
        )

        self.assertEqual(result.environ_symbol_address, environ_address)
        self.assertEqual(result.environ_pointer, environ_pointer)
        self.assertEqual(result.first_environment_pointer, first_environment)


if __name__ == "__main__":
    unittest.main()
