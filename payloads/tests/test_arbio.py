from __future__ import annotations

import unittest

from payloads import (
    ConstraintError,
    ExecutionPolicy,
    LibcIdentity,
    LibcImage,
    Linkage,
    MemoryRequirement,
    Mitigations,
    Payload,
    PayloadKind,
    Permission,
    Relro,
    RuntimeLayout,
    SUPPORTED_TARGETS,
    resolve_target,
)
from payloads.arbio import (
    ArbitraryMemory,
    CallbackControlFlowTrigger,
    CallbackFunctionCall,
    ExactLibcFunction,
    ExecveCallWorkflow,
    GotSystemWorkflow,
    IOPrimitiveTraits,
    PayloadStager,
    ShortReadError,
    ShortWriteError,
    WriteVerificationError,
    build_execve_data_payload,
    build_shell_command_execve_data,
)
from payloads.errors import MemoryAccessError


class MemoryBackend:
    def __init__(self, base: int, size: int = 0x1000) -> None:
        self.base = base
        self.data = bytearray(size)
        self.read_calls: list[tuple[int, int]] = []
        self.write_calls: list[tuple[int, bytes]] = []

    def read(self, address: int, size: int) -> bytes:
        self.read_calls.append((address, size))
        offset = address - self.base
        if offset < 0 or offset + size > len(self.data):
            raise OSError("unmapped")
        return bytes(self.data[offset : offset + size])

    def write(self, address: int, data: bytes) -> int:
        raw = bytes(data)
        self.write_calls.append((address, raw))
        offset = address - self.base
        if offset < 0 or offset + len(raw) > len(self.data):
            raise OSError("unmapped")
        self.data[offset : offset + len(raw)] = raw
        return len(raw)


def memory_for(target_name: str, base: int = 0x1000, **trait_values: object) -> tuple[ArbitraryMemory, MemoryBackend]:
    target = resolve_target(target_name)
    backend = MemoryBackend(base)
    memory = ArbitraryMemory(
        target,
        read_at=backend.read,
        write_at=backend.write,
        traits=IOPrimitiveTraits(**trait_values),
    )
    return memory, backend


def mitigations(
    *,
    nx: bool = True,
    relro: Relro = Relro.PARTIAL,
    linkage: Linkage = Linkage.DYNAMIC,
    policy: ExecutionPolicy = ExecutionPolicy.ELF_PERMISSIONS,
) -> Mitigations:
    return Mitigations(False, nx, relro, linkage, policy)


def exact_libc(target_name: str, symbols: dict[str, int]) -> LibcImage:
    return LibcImage(LibcIdentity("ab" * 32, build_id="1234"), resolve_target(target_name), symbols)


class ArbitraryMemoryTests(unittest.TestCase):
    def test_pointer_width_and_endian_are_target_driven(self) -> None:
        cases = (
            ("x86", 0x11223344, b"\x44\x33\x22\x11"),
            ("mipseb", 0x11223344, b"\x11\x22\x33\x44"),
            ("x86_64", 0x1122334455667788, b"\x88\x77\x66\x55\x44\x33\x22\x11"),
            ("mips64eb", 0x1122334455667788, b"\x11\x22\x33\x44\x55\x66\x77\x88"),
        )
        for target_name, pointer, packed in cases:
            with self.subTest(target=target_name):
                memory, backend = memory_for(target_name)
                self.assertEqual(memory.write_ptr(0x1020, pointer), len(packed))
                self.assertEqual(bytes(backend.data[0x20 : 0x20 + len(packed)]), packed)
                self.assertEqual(memory.read_ptr(0x1020), pointer)

    def test_callbacks_are_chunked_exactly(self) -> None:
        memory, backend = memory_for("x86", read_chunk=4, write_chunk=4)
        data = bytes(range(12))
        memory.write(0x1010, data)
        self.assertEqual([len(chunk) for _, chunk in backend.write_calls], [4, 4, 4])
        backend.read_calls.clear()
        self.assertEqual(memory.read(0x1010, 12), data)
        self.assertEqual(backend.read_calls, [(0x1010, 4), (0x1014, 4), (0x1018, 4)])

    def test_chunker_keeps_each_callback_address_aligned(self) -> None:
        memory, backend = memory_for(
            "x86",
            read_chunk=6,
            write_chunk=6,
            read_alignment=4,
            write_alignment=4,
        )
        memory.write(0x1020, b"abcdefgh")
        self.assertEqual(backend.write_calls, [(0x1020, b"abcd"), (0x1024, b"efgh")])
        backend.read_calls.clear()
        self.assertEqual(memory.read(0x1020, 8), b"abcdefgh")
        self.assertEqual(backend.read_calls, [(0x1020, 4), (0x1024, 4)])

    def test_alignment_and_width_are_enforced_without_implicit_overread(self) -> None:
        memory, backend = memory_for(
            "x86",
            read_chunk=4,
            write_chunk=4,
            read_alignment=4,
            write_alignment=4,
            read_width=4,
            write_width=4,
        )
        with self.assertRaisesRegex(MemoryAccessError, "not aligned"):
            memory.read(0x1001, 4)
        with self.assertRaisesRegex(MemoryAccessError, "not a multiple"):
            memory.write(0x1000, b"abc")
        self.assertEqual(backend.read_calls, [])
        self.assertEqual(backend.write_calls, [])

    def test_short_read_has_exact_address_expected_and_actual(self) -> None:
        target = resolve_target("x86")
        memory = ArbitraryMemory(target, read_at=lambda _address, size: b"x" * (size - 1))
        with self.assertRaises(ShortReadError) as caught:
            memory.read(0x41410000, 4)
        self.assertEqual(
            (caught.exception.address, caught.exception.expected, caught.exception.actual),
            (0x41410000, 4, 3),
        )
        self.assertEqual(
            str(caught.exception),
            "short read at 0x41410000: expected exactly 4 bytes, got 3",
        )

    def test_short_write_has_exact_address_expected_and_actual(self) -> None:
        target = resolve_target("x86_64")
        memory = ArbitraryMemory(target, write_at=lambda _address, data: len(data) - 2)
        with self.assertRaises(ShortWriteError) as caught:
            memory.write(0x404000, b"abcdefgh")
        self.assertEqual(
            (caught.exception.address, caught.exception.expected, caught.exception.actual),
            (0x404000, 8, 6),
        )
        self.assertEqual(
            str(caught.exception),
            "short write at 0x404000: expected exactly 8 bytes, wrote 6",
        )

    def test_read_back_verification_detects_silent_write_corruption(self) -> None:
        target = resolve_target("x86")
        backend = MemoryBackend(0x1000)

        def corrupting_write(address: int, data: bytes) -> None:
            offset = address - backend.base
            backend.data[offset : offset + len(data)] = data
            backend.data[offset + 1] ^= 0xFF

        memory = ArbitraryMemory(
            target,
            read_at=backend.read,
            write_at=corrupting_write,
            traits=IOPrimitiveTraits(verify_writes=True),
        )
        with self.assertRaises(WriteVerificationError) as caught:
            memory.write(0x1010, b"ABCD")
        self.assertIn("first mismatch at +0x1", str(caught.exception))

    def test_verification_can_be_enabled_per_write(self) -> None:
        memory, backend = memory_for("x86")
        memory.write(0x1020, b"verified", verify=True)
        self.assertEqual(backend.read_calls, [(0x1020, 8)])

    def test_probe_requires_invalid_read_safety_trait(self) -> None:
        unsafe, _ = memory_for("x86")
        with self.assertRaisesRegex(ConstraintError, "invalid_read_safe"):
            unsafe.probe(0xFFFF0000)

        safe, _ = memory_for("x86", invalid_read_safe=True)
        self.assertFalse(safe.probe(0xFFFF0000))
        self.assertTrue(safe.probe(0x1000))

    def test_bytes_provider_adapters_are_structural_and_rebasable(self) -> None:
        memory, backend = memory_for("mipseb")
        provider = memory.as_bytes_provider(0x1040)
        self.assertEqual((provider.address, provider.ptrbits, provider.byteorder), (0x1040, 32, 1))
        provider.write(4, b"ABCD")
        self.assertEqual(provider.read(4, 4), b"ABCD")
        self.assertEqual(provider.rebase(0x1080).address, 0x1080)

        round_trip = ArbitraryMemory.from_bytes_provider(provider, memory.target)
        round_trip.write(0x1048, b"EFGH")
        self.assertEqual(bytes(backend.data[0x48:0x4C]), b"EFGH")

    def test_bytes_provider_adapter_rejects_absolute_addresses_below_base(self) -> None:
        memory, _ = memory_for("x86")
        provider = memory.as_bytes_provider(0x1040)
        round_trip = ArbitraryMemory.from_bytes_provider(provider, memory.target)
        with self.assertRaisesRegex(MemoryAccessError, "below provider base"):
            round_trip.read(0x103F, 1)
        with self.assertRaisesRegex(MemoryAccessError, "below provider base"):
            round_trip.write(0x103F, b"X")


class PayloadStagerTests(unittest.TestCase):
    @staticmethod
    def code_payload(target_name: str = "x86", *, needs_cache_sync: bool = False) -> Payload:
        target = resolve_target(target_name)
        alignment = 1 if target_name == "x86" else 4
        data = b"\x90" if target_name == "x86" else b"\0" * 4
        return Payload(
            data,
            target,
            PayloadKind.SHELLCODE,
            "test staged code",
            memory=(MemoryRequirement(len(data), Permission.READ | Permission.EXECUTE, "code", alignment),),
            metadata={"requires_instruction_cache_sync_after_runtime_write": needs_cache_sync},
        )

    def test_nx_and_modern_qemu_reject_before_writing(self) -> None:
        memory, backend = memory_for("x86")
        stager = PayloadStager(
            memory,
            mitigations(policy=ExecutionPolicy.QEMU_ELF_PERMISSIONS),
        )
        with self.assertRaisesRegex(ConstraintError, "NX is enforced"):
            stager.stage(self.code_payload(), 0x1100)
        self.assertEqual(backend.write_calls, [])

    def test_permission_primitive_makes_nx_path_explicit(self) -> None:
        memory, backend = memory_for("x86")
        calls: list[tuple[int, int]] = []
        stager = PayloadStager(
            memory,
            mitigations(),
            make_executable=lambda address, size: calls.append((address, size)),
        )
        staged = stager.stage(self.code_payload(), 0x1100, verify=True)
        self.assertEqual(bytes(backend.data[0x100:0x101]), b"\x90")
        self.assertEqual(calls, [(0x1100, 1)])
        self.assertTrue(staged.permission_changed)
        self.assertTrue(staged.verified)

    def test_legacy_qemu_allows_writable_staging_without_permission_change(self) -> None:
        memory, backend = memory_for("x86")
        legacy = mitigations(policy=ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE)
        staged = PayloadStager(memory, legacy).stage(self.code_payload(), 0x1100)
        self.assertFalse(staged.permission_changed)
        self.assertEqual(bytes(backend.data[0x100:0x101]), b"\x90")

    def test_asserted_executable_region_allows_new_qemu(self) -> None:
        memory, _ = memory_for("x86")
        modern = mitigations(policy=ExecutionPolicy.QEMU_ELF_PERMISSIONS)
        staged = PayloadStager(memory, modern).stage(
            self.code_payload(),
            0x1100,
            executable_region=True,
        )
        self.assertFalse(staged.permission_changed)

    def test_cache_sync_is_preflighted_and_invoked_for_non_x86_code(self) -> None:
        memory, backend = memory_for("arm")
        legacy = mitigations(policy=ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE)
        payload = self.code_payload("arm", needs_cache_sync=True)
        with self.assertRaisesRegex(ConstraintError, "instruction-cache"):
            PayloadStager(memory, legacy).stage(payload, 0x1100)
        self.assertEqual(backend.write_calls, [])

        syncs: list[tuple[int, int]] = []
        staged = PayloadStager(
            memory,
            legacy,
            synchronize_instruction_cache=lambda address, size: syncs.append((address, size)),
        ).stage(payload, 0x1100)
        self.assertEqual(syncs, [(0x1100, 4)])
        self.assertTrue(staged.cache_synchronized)

    def test_staging_does_not_execute_without_explicit_trigger(self) -> None:
        memory, _ = memory_for("x86")
        stager = PayloadStager(memory, mitigations(policy=ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE))
        staged = stager.stage(self.code_payload(), 0x1120)
        with self.assertRaisesRegex(ConstraintError, "cannot execute"):
            staged.execute(None)  # type: ignore[arg-type]

        entries: list[int] = []
        trigger = CallbackControlFlowTrigger(memory.target, lambda address: entries.append(address) or "ran")
        self.assertEqual(staged.execute(trigger), "ran")
        self.assertEqual(entries, [0x1120])

    def test_thumb_trigger_gets_state_bit(self) -> None:
        target = resolve_target("thumb")
        backend = MemoryBackend(0x1000)
        memory = ArbitraryMemory(target, read_at=backend.read, write_at=backend.write)
        payload = Payload(
            b"\x00\xbf",
            target,
            PayloadKind.SHELLCODE,
            "thumb nop",
            memory=(MemoryRequirement(2, Permission.READ | Permission.EXECUTE, "code", 2),),
        )
        entries: list[int] = []
        trigger = CallbackControlFlowTrigger(target, lambda address: entries.append(address))
        PayloadStager(memory, mitigations(nx=False)).stage_and_execute(payload, 0x1100, trigger)
        self.assertEqual(entries, [0x1101])


class ExecveWorkflowTests(unittest.TestCase):
    def test_execve_data_builds_for_every_recognized_target(self) -> None:
        for target in SUPPORTED_TARGETS:
            with self.subTest(target=target.name):
                base = 0x10000
                data = build_shell_command_execve_data("true", target, base)
                argv_offset = data.argv_address - base
                first_pointer = data.payload.data[argv_offset : argv_offset + target.word_size]
                self.assertEqual(first_pointer, target.pack(data.argument_addresses[0]))

    def test_execve_data_uses_32_bit_little_endian_pointers(self) -> None:
        target = resolve_target("x86")
        data = build_shell_command_execve_data("id", target, 0x2000)
        argv = data.payload.data[data.argv_address - data.load_address :]
        expected = b"".join(target.pack(address) for address in data.argument_addresses) + target.pack(0)
        self.assertTrue(argv.startswith(expected))
        self.assertEqual(data.payload.metadata["pointer_width"], 32)
        self.assertEqual(data.payload.metadata["endian"], "little")

    def test_execve_data_uses_64_bit_big_endian_pointers_and_envp(self) -> None:
        target = resolve_target("mips64eb")
        data = build_execve_data_payload(
            target,
            0x100000,
            "/bin/echo",
            ("echo", "hello"),
            environment=("LANG=C",),
        )
        argv_offset = data.argv_address - data.load_address
        expected_argv = b"".join(target.pack(address) for address in data.argument_addresses) + target.pack(0)
        self.assertEqual(data.payload.data[argv_offset : argv_offset + len(expected_argv)], expected_argv)
        envp_offset = data.envp_address - data.load_address
        expected_envp = target.pack(data.environment_addresses[0]) + target.pack(0)
        self.assertEqual(data.payload.data[envp_offset : envp_offset + len(expected_envp)], expected_envp)
        self.assertEqual(expected_envp[:8], data.environment_addresses[0].to_bytes(8, "big"))

    def test_execve_workflow_stages_then_calls_exact_libc_address(self) -> None:
        target = resolve_target("x86_64")
        backend = MemoryBackend(0x400000)
        memory = ArbitraryMemory(target, read_at=backend.read, write_at=backend.write)
        stager = PayloadStager(memory, mitigations())
        data = build_shell_command_execve_data("id", target, 0x400100)
        libc = exact_libc("x86_64", {"execve": 0xD4AD0})
        workflow = ExecveCallWorkflow.from_libc(data, libc, RuntimeLayout(libc_base=0x7F0000000000))
        calls: list[tuple[int, tuple[int, ...]]] = []
        call = CallbackFunctionCall(target, lambda address, arguments: calls.append((address, arguments)) or 7)

        self.assertEqual(workflow.execute(stager, call, verify=True), 7)
        self.assertEqual(calls, [(0x7F00000D4AD0, (data.path_address, data.argv_address, 0))])
        offset = data.load_address - backend.base
        self.assertEqual(bytes(backend.data[offset : offset + len(data.payload.data)]), data.payload.data)

    def test_execve_workflow_rejects_raw_unproven_function_address(self) -> None:
        data = build_shell_command_execve_data("id", resolve_target("x86"), 0x2000)
        with self.assertRaisesRegex(TypeError, "ExactLibcFunction"):
            ExecveCallWorkflow(data, 0xF7E00000)  # type: ignore[arg-type]

    def test_exact_function_requires_runtime_libc_base(self) -> None:
        libc = exact_libc("x86", {"execve": 0x1234})
        with self.assertRaisesRegex(Exception, "runtime base"):
            ExactLibcFunction.resolve(libc, "execve", RuntimeLayout())


class GotSystemWorkflowTests(unittest.TestCase):
    def make_workflow(self, relro: Relro = Relro.PARTIAL) -> GotSystemWorkflow:
        target = resolve_target("x86_64")
        libc = exact_libc("x86_64", {"system": 0x4C490})
        return GotSystemWorkflow.from_libc(
            target,
            mitigations(relro=relro),
            libc,
            RuntimeLayout(libc_base=0x7F0000000000),
            got_address=0x400080,
            plt_address=0x401030,
            command_address=0x400200,
            command="id",
        )

    def test_partial_relro_overwrite_calls_plt_and_restores_got(self) -> None:
        workflow = self.make_workflow()
        backend = MemoryBackend(0x400000)
        target = workflow.target
        original = 0x7F0000080ED0
        backend.data[0x80:0x88] = target.pack(original)
        memory = ArbitraryMemory(target, read_at=backend.read, write_at=backend.write)
        observed: list[tuple[int, tuple[int, ...], int]] = []

        def call_at(address: int, arguments: tuple[int, ...]) -> str:
            observed.append((address, arguments, memory.read_ptr(workflow.got_address)))
            return "returned"

        result = workflow.execute(memory, CallbackFunctionCall(target, call_at), verify=True)
        self.assertEqual(result, "returned")
        self.assertEqual(
            observed,
            [(0x401030, (0x400200,), 0x7F000004C490)],
        )
        self.assertEqual(memory.read_ptr(workflow.got_address), original)
        self.assertEqual(bytes(backend.data[0x200:0x203]), b"id\0")

    def test_got_is_restored_when_call_primitive_raises(self) -> None:
        workflow = self.make_workflow()
        backend = MemoryBackend(0x400000)
        original = 0x7F0000080ED0
        backend.data[0x80:0x88] = workflow.target.pack(original)
        memory = ArbitraryMemory(workflow.target, read_at=backend.read, write_at=backend.write)

        def fail(_address: int, _arguments: tuple[int, ...]) -> None:
            raise RuntimeError("remote call failed")

        with self.assertRaisesRegex(RuntimeError, "remote call failed"):
            workflow.execute(memory, CallbackFunctionCall(workflow.target, fail))
        self.assertEqual(memory.read_ptr(workflow.got_address), original)

    def test_full_relro_rejects_before_any_memory_access(self) -> None:
        workflow = self.make_workflow(Relro.FULL)
        backend = MemoryBackend(0x400000)
        memory = ArbitraryMemory(workflow.target, read_at=backend.read, write_at=backend.write)
        call = CallbackFunctionCall(workflow.target, lambda _address, _arguments: None)
        with self.assertRaisesRegex(ConstraintError, "full RELRO"):
            workflow.execute(memory, call)
        self.assertEqual(backend.read_calls, [])
        self.assertEqual(backend.write_calls, [])

    def test_workflow_rejects_raw_system_address(self) -> None:
        target = resolve_target("x86_64")
        with self.assertRaisesRegex(TypeError, "ExactLibcFunction"):
            GotSystemWorkflow(
                target,
                mitigations(),
                0x7F000004C490,  # type: ignore[arg-type]
                0x400080,
                0x401030,
                0x400200,
                "id",
            )


if __name__ == "__main__":
    unittest.main()
