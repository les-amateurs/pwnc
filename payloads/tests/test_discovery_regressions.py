from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
from payloads.pwntools_compat import PwntoolsCompatibilityError
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
        resolver = ExactProcessDiscovery(
            ArbitraryMemory(
                target,
                read_at=backend.read,
                traits=IOPrimitiveTraits(
                    read_alignment=target.word_size,
                    read_width=target.word_size,
                    invalid_read_safe=True,
                    covering_read_safe=True,
                ),
            ),
            libc=libc,
        )

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

    def test_discovery_rehashes_local_exact_artifact_before_using_its_bytes(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-local-mutation.so.6")
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        changed = bytearray(Path(libc.path).read_bytes())
        changed[0x300] ^= 1
        Path(libc.path).write_bytes(changed)
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(PwntoolsCompatibilityError, "artifact changed"):
            resolver.heap_to_libc(
                0x500000,
                libc_pointer=libc_base + 0x100,
                libc_base=libc_base,
            )

    def test_heap_base_and_span_are_consistency_assertions(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-base-span.so.6")
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        heap = MemorySpan(0x500000, target.word_size)
        backend.map(heap.address, target.pack(libc_base + 0x100))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(ConstraintError, "heap_base and heap_span"):
            resolver.heap_to_libc(
                heap.address,
                heap_base=heap.address + 0x1000,
                heap_span=heap,
                libc_base=libc_base,
            )

    def test_unsafe_remote_reads_require_explicit_scan_spans(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-no-speculative-scan.so.6")
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(ConstraintError, "explicit heap_span"):
            resolver.heap_to_libc(0x500123, libc_base=libc_base)

        explicit = resolver.heap_to_libc(
            0x500123,
            libc_pointer=libc_base + 0x100,
            libc_base=libc_base,
        )
        self.assertEqual(explicit.base, libc_base)

        with self.assertRaisesRegex(ConstraintError, "explicit heap_span"):
            resolver.libc_to_heap(explicit, heap_base=0x500000)

        heap = resolver.libc_to_heap(
            explicit,
            heap_base=0x500000,
            heap_pointer=0x500123,
        )
        self.assertEqual(heap.pointer, 0x500123)
        self.assertIsNone(heap.span)
        with self.assertRaisesRegex(ConstraintError, "explicit heap_span"):
            resolver.heap_to_libc(heap, libc_base=libc_base)

        main_base = 0x400000
        main = exact_adapter(
            self.root,
            target,
            "main-no-speculative-stack",
            pie=True,
            image_kind=ELFImageKind.PIE_EXECUTABLE,
            patches={0x200: b"\xe8\0\0\0\0"},
        )
        map_adapter(backend, main, main_base)
        return_slot = 0x7FFF0080
        backend.map(return_slot, target.pack(main_base + 0x205))
        main_resolver = ExactProcessDiscovery(self.memory(target, backend), main=main)

        with self.assertRaisesRegex(ConstraintError, "explicit stack_span"):
            main_resolver.environ_to_main_returns(
                return_slot + 0x80,
                main_base=main_base,
            )

        classified = main_resolver.environ_to_main_return(
            return_slot + 0x80,
            main_base=main_base,
            return_slot=return_slot,
        )
        self.assertEqual(classified.slot_address, return_slot)

    def test_riscv_call_continuation_requires_the_abi_link_register(self) -> None:
        target = resolve_target("riscv64")
        backend = SparseMemory()
        main_base = 0x400000
        linked_call = 0x000000EF  # jal ra, 0
        unlinked_jump = 0x0000006F  # jal zero, 0
        main = exact_adapter(
            self.root,
            target,
            "main-riscv64",
            pie=True,
            image_kind=ELFImageKind.PIE_EXECUTABLE,
            patches={
                0x200: linked_call.to_bytes(4, "little"),
                0x220: unlinked_jump.to_bytes(4, "little"),
            },
        )
        map_adapter(backend, main, main_base)
        stack = MemorySpan(0x7FFF0000, 0x40)
        backend.map(stack.address, b"\0" * stack.size)
        resolver = ExactProcessDiscovery(self.memory(target, backend), main=main)

        backend.map(stack.address, target.pack(main_base + 0x204))
        linked = resolver.environ_to_main_return(
            stack.address + 0x20,
            stack_span=stack,
            main_base=main_base,
            return_slot=stack.address,
        )
        self.assertEqual(linked.call_site, main_base + 0x200)

        backend.map(stack.address, target.pack(main_base + 0x224))
        with self.assertRaises(DiscoveryNotFoundError):
            resolver.environ_to_main_return(
                stack.address + 0x20,
                stack_span=stack,
                main_base=main_base,
                return_slot=stack.address,
            )

    def test_cross_arch_call_classifiers_require_linking_encodings(self) -> None:
        cases = (
            ("arm64", "little", 0x94000000, 0x14000000, 4, False),
            ("arm64", "big", b"\x00\x00\x00\x94", b"\x00\x00\x00\x14", 4, False),
            ("arm", "little", 0xEB000000, 0xEA000000, 4, False),
            ("thumb", "little", b"\x00\xf0\x00\xf8", b"\x00\xf0\x00\xb8", 4, True),
            ("mips32", "big", 0x0C000000, 0x08000000, 8, False),
            ("powerpc64", "big", 0x48000001, 0x48000000, 4, False),
            ("sparc64", "big", 0x40000000, 0x00000000, 0, False),
        )
        for index, (name, endian, linked, unlinked, return_delta, state_bit) in enumerate(cases):
            with self.subTest(target=name):
                target = resolve_target(name, endian=endian)
                byteorder = target.endian.value
                linked_bytes = linked if isinstance(linked, bytes) else linked.to_bytes(4, byteorder)
                unlinked_bytes = unlinked if isinstance(unlinked, bytes) else unlinked.to_bytes(4, byteorder)
                backend = SparseMemory()
                main_base = 0x400000
                main = exact_adapter(
                    self.root,
                    target,
                    f"main-call-{index}",
                    pie=True,
                    image_kind=ELFImageKind.PIE_EXECUTABLE,
                    patches={0x200: linked_bytes, 0x220: unlinked_bytes},
                )
                map_adapter(backend, main, main_base)
                stack = MemorySpan(0x7FFF0000, 0x40)
                backend.map(stack.address, b"\0" * stack.size)
                resolver = ExactProcessDiscovery(self.memory(target, backend), main=main)

                linked_return = main_base + 0x200 + return_delta
                if state_bit:
                    linked_return |= 1
                backend.map(stack.address, target.pack(linked_return))
                result = resolver.environ_to_main_return(
                    stack.address + 0x20,
                    stack_span=stack,
                    main_base=main_base,
                    return_slot=stack.address,
                )
                self.assertEqual(result.call_site, main_base + 0x200)

                unlinked_return = main_base + 0x220 + return_delta
                if state_bit:
                    unlinked_return |= 1
                backend.map(stack.address, target.pack(unlinked_return))
                with self.assertRaises(DiscoveryNotFoundError):
                    resolver.environ_to_main_return(
                        stack.address + 0x20,
                        stack_span=stack,
                        main_base=main_base,
                        return_slot=stack.address,
                    )

    def test_covering_reads_require_an_explicit_primitive_capability(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        main_base = 0x400000
        main = exact_adapter(
            self.root,
            target,
            "main-word-read",
            pie=True,
            image_kind=ELFImageKind.PIE_EXECUTABLE,
            patches={0x200: b"\xe8\0\0\0\0"},
        )
        map_adapter(backend, main, main_base)
        stack = MemorySpan(0x7FFF0000, 0x40)
        backend.map(stack.address, b"\0" * stack.size)
        backend.map(stack.address, target.pack(main_base + 0x205))
        memory = ArbitraryMemory(
            target,
            read_at=backend.read,
            traits=IOPrimitiveTraits(
                read_alignment=target.word_size,
                read_width=target.word_size,
            ),
        )
        resolver = ExactProcessDiscovery(memory, main=main)

        with self.assertRaisesRegex(MemoryAccessError, "covering_read_safe"):
            resolver.environ_to_main_return(
                stack.address + 0x20,
                stack_span=stack,
                main_base=main_base,
                return_slot=stack.address,
            )

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

    def test_libc_symbol_leak_and_hardcoded_base_must_agree(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(
            self.root,
            target,
            "libc-symbol-assertion.so.6",
            symbols={"known": 0x180, "environ": 0x380},
        )
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(DiscoveryError, "symbol leak.*disagrees"):
            resolver.libc_to_stack(
                PointerLeak(libc_base + 0x188, symbol="known"),
                libc_base=libc_base,
            )

    def test_unsafe_loader_discovery_does_not_probe_a_lazy_named_got_target(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-lazy-loader.so.6")
        loader = exact_adapter(self.root, target, "ld-lazy-loader.so", symbols={"lazy_call": 0x180})
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        slot = libc_base + 0x680
        bogus_loader_base = 0xA00000
        backend.map(slot, target.pack(bogus_loader_base + loader.symbol("lazy_call")))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc, loader=loader)

        with (
            mock.patch.object(resolver, "_pwntools_got_entries", return_value=(("lazy_call", slot),)),
            self.assertRaisesRegex(ConstraintError, "invalid_read_safe"),
        ):
            resolver.libc_to_loader(PointerLeak(libc_base + 0x100), libc_base=libc_base)

    def test_explicit_image_scan_span_must_be_a_writable_libc_load(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-span-assertion.so.6")
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        heap = MemorySpan(0x500000, 0x100)
        backend.map(heap.address, b"\0" * heap.size)
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(DiscoveryError, "explicit image scan span"):
            resolver.libc_to_heap(
                PointerLeak(libc_base + 0x100),
                libc_base=libc_base,
                libc_span=MemorySpan(libc_base + 0x2000, target.word_size),
                heap_span=heap,
            )

        read_only = exact_adapter(
            self.root,
            target,
            "libc-read-only-span.so.6",
            writable=False,
        )
        read_only_base = 0x900000
        map_adapter(backend, read_only, read_only_base)
        read_only_resolver = ExactProcessDiscovery(self.memory(target, backend), libc=read_only)
        with self.assertRaisesRegex(DiscoveryError, "readable/writable"):
            read_only_resolver.libc_to_heap(
                PointerLeak(read_only_base + 0x100),
                libc_base=read_only_base,
                libc_span=MemorySpan(read_only_base + 0x200, target.word_size),
                heap_span=heap,
            )

    def test_explicit_environ_address_must_be_writable_libc_data(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        libc = exact_adapter(self.root, target, "libc-environ-assertion.so.6")
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(DiscoveryError, "environ address"):
            resolver.libc_to_stack(
                PointerLeak(libc_base + 0x100),
                libc_base=libc_base,
                environ_address=libc_base + 0x2000,
            )

        read_only = exact_adapter(
            self.root,
            target,
            "libc-environ-read-only.so.6",
            writable=False,
        )
        read_only_base = 0x900000
        map_adapter(backend, read_only, read_only_base)
        read_only_resolver = ExactProcessDiscovery(self.memory(target, backend), libc=read_only)
        with self.assertRaisesRegex(DiscoveryError, "readable/writable"):
            read_only_resolver.libc_to_stack(
                PointerLeak(read_only_base + 0x100),
                libc_base=read_only_base,
                environ_address=read_only_base + 0x380,
            )

    def test_environ_pointer_is_the_stack_leak_without_optional_remote_dereference(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        environ_offset = 0x380
        libc = exact_adapter(
            self.root,
            target,
            "libc-no-stack-probe.so.6",
            symbols={"environ": environ_offset},
        )
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        unmapped_stack_pointer = 0x7FFF0000
        backend.map(libc_base + environ_offset, target.pack(unmapped_stack_pointer))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        result = resolver.libc_to_stack(PointerLeak(libc_base + 0x100), libc_base=libc_base)

        self.assertEqual(result.environ_pointer, unmapped_stack_pointer)
        self.assertIsNone(result.first_environment_pointer)

    def test_environment_string_may_live_outside_the_stack_span(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        environ_offset = 0x380
        libc = exact_adapter(
            self.root,
            target,
            "libc-heap-environment.so.6",
            symbols={"environ": environ_offset},
        )
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        stack = MemorySpan(0x7FFF0000, 0x100)
        heap_string = 0x500800
        backend.map(stack.address, b"\0" * stack.size)
        backend.map(libc_base + environ_offset, target.pack(stack.address + 0x40))
        backend.map(stack.address + 0x40, target.pack(heap_string))
        backend.map(heap_string, b"HEAP=1\0")
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        result = resolver.libc_to_stack(
            PointerLeak(libc_base + 0x100),
            libc_base=libc_base,
            stack_span=stack,
        )

        self.assertEqual(result.first_environment_pointer, heap_string)

    def test_explicit_r_debug_must_be_writable_loader_data(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        loader = exact_adapter(self.root, target, "ld-r-debug-assertion.so")
        loader_base = 0x700000
        map_adapter(backend, loader, loader_base)
        resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

        with self.assertRaisesRegex(DiscoveryError, "r_debug address"):
            resolver.loader_to_link_map(
                PointerLeak(loader_base + 0x100),
                loader_base=loader_base,
                r_debug_address=loader_base + 0x2000,
            )

        read_only = exact_adapter(
            self.root,
            target,
            "ld-r-debug-read-only.so",
            writable=False,
        )
        read_only_base = 0x900000
        map_adapter(backend, read_only, read_only_base)
        read_only_resolver = ExactProcessDiscovery(self.memory(target, backend), loader=read_only)
        with self.assertRaisesRegex(DiscoveryError, "readable/writable"):
            read_only_resolver.loader_to_link_map(
                PointerLeak(read_only_base + 0x100),
                loader_base=read_only_base,
                r_debug_address=read_only_base + 0x200,
            )

    def test_known_link_map_artifact_requires_exact_l_ld(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        loader = exact_adapter(
            self.root,
            target,
            "ld-l-ld-assertion.so",
            symbols={"_r_debug": 0x200},
        )
        loader_base = 0x700000
        map_adapter(backend, loader, loader_base)
        debug = loader_base + 0x200
        node = 0x500000
        name = node + 0x100
        word = target.word_size
        r_debug = bytearray(word * 5)
        r_debug[:4] = (1).to_bytes(4, target.endian.value)
        r_debug[word : word * 2] = target.pack(node)
        r_debug[word * 4 : word * 5] = target.pack(loader_base)
        backend.map(debug, r_debug)
        assert loader.profile.dynamic_range is not None
        wrong_dynamic = loader_base + loader.profile.dynamic_range.start + target.word_size
        backend.map(
            node,
            target.pack(loader_base) + target.pack(name) + target.pack(wrong_dynamic) + target.pack(0) + target.pack(0),
        )
        backend.map(name, Path(loader.path).name.encode() + b"\0" + b"\0" * target.word_size)
        resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

        with self.assertRaisesRegex(DiscoveryError, "PT_DYNAMIC"):
            resolver.loader_to_link_map(
                PointerLeak(loader_base + 0x100),
                loader_base=loader_base,
                known_images=(loader,),
            )

    def test_structural_image_without_mapped_build_id_is_not_attached(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        loader = exact_adapter(
            self.root,
            target,
            "ld-structural-list.so",
            symbols={"_r_debug": 0x200},
        )
        candidate = exact_adapter(
            self.root,
            target,
            "libstructural.so",
            runtime_build_id=False,
        )
        loader_base = 0x700000
        candidate_base = 0x900000
        map_adapter(backend, loader, loader_base)
        map_adapter(backend, candidate, candidate_base)
        debug = loader_base + 0x200
        node = 0x500000
        name = node + 0x100
        word = target.word_size
        r_debug = bytearray(word * 5)
        r_debug[:4] = (1).to_bytes(4, target.endian.value)
        r_debug[word : word * 2] = target.pack(node)
        r_debug[word * 4 : word * 5] = target.pack(loader_base)
        backend.map(debug, r_debug)
        assert candidate.profile.dynamic_range is not None
        backend.map(
            node,
            target.pack(candidate_base)
            + target.pack(name)
            + target.pack(candidate_base + candidate.profile.dynamic_range.start)
            + target.pack(0)
            + target.pack(0),
        )
        backend.map(name, b"libstructural.so\0" + b"\0" * target.word_size)
        resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

        snapshot = resolver.loader_to_link_map(
            PointerLeak(loader_base + 0x100),
            loader_base=loader_base,
            known_images=(candidate,),
        )

        self.assertIsNone(snapshot.objects[0].adapter)

    def test_et_exec_link_map_l_ld_uses_zero_load_bias(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        loader = exact_adapter(
            self.root,
            target,
            "ld-et-exec-list.so",
            symbols={"_r_debug": 0x200},
        )
        linked_base = 0x400000
        main = exact_adapter(
            self.root,
            target,
            "main-et-exec-list",
            start=linked_base,
            elf_type="ET_EXEC",
            image_kind=ELFImageKind.EXECUTABLE,
        )
        loader_base = 0x700000
        map_adapter(backend, loader, loader_base)
        map_adapter(backend, main, 0)
        debug = loader_base + 0x200
        node = 0x500000
        name = node + 0x100
        word = target.word_size
        r_debug = bytearray(word * 5)
        r_debug[:4] = (1).to_bytes(4, target.endian.value)
        r_debug[word : word * 2] = target.pack(node)
        r_debug[word * 4 : word * 5] = target.pack(loader_base)
        backend.map(debug, r_debug)
        assert main.profile.dynamic_range is not None
        backend.map(
            node,
            target.pack(0)
            + target.pack(name)
            + target.pack(main.profile.dynamic_range.start)
            + target.pack(0)
            + target.pack(0),
        )
        backend.map(name, Path(main.path).name.encode() + b"\0" + b"\0" * target.word_size)
        resolver = ExactProcessDiscovery(self.memory(target, backend), loader=loader)

        snapshot = resolver.loader_to_link_map(
            PointerLeak(loader_base + 0x100),
            loader_base=loader_base,
            known_images=(main,),
        )

        self.assertIs(snapshot.objects[0].adapter, main)
        self.assertEqual(snapshot.objects[0].base, 0)
        self.assertEqual(snapshot.objects[0].dynamic_address, linked_base + 0x500)

    def test_null_environ_is_not_dereferenced(self) -> None:
        target = resolve_target("x86_64")
        backend = SparseMemory()
        environ_offset = 0x380
        libc = exact_adapter(
            self.root,
            target,
            "libc-null-environ.so.6",
            symbols={"environ": environ_offset},
        )
        libc_base = 0x700000
        map_adapter(backend, libc, libc_base)
        backend.map(libc_base + environ_offset, target.pack(0))
        resolver = ExactProcessDiscovery(self.memory(target, backend), libc=libc)

        with self.assertRaisesRegex(DiscoveryNotFoundError, "environ is NULL"):
            resolver.libc_to_stack(PointerLeak(libc_base + 0x100), libc_base=libc_base)


if __name__ == "__main__":
    unittest.main()
