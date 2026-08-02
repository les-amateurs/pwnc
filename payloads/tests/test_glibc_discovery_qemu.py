"""Opt-in arbitrary-read discovery against real non-native glibc processes.

Enable with ``PWNC_GLIBC_DISCOVERY_QEMU_TESTS=1``.  The broader
``PWNC_GLIBC_QEMU_TESTS=1`` switch enables it too.  Provisioning uses the
shared ``PWNC_GLIBC_SYSROOT_CACHE`` cache, and
``PWNC_GLIBC_QEMU_SPECS=comma,separated,manifest-ids`` selects focused pinned
sysroots.  Without a selector this deliberately bounded lane runs AArch64 LE
and ARM EABI BE from the pinned glibc-2.39 catalog.

The guest exposes a small address/length protocol backed by an ordinary
in-process pointer read.  The host supplies target-endian requests through
``ArbitraryMemory``; neither side consults process memory pseudo-files.  From
one exact libc ``write`` leak, the test discovers ``environ``/the initial
stack, an exact loader pointer, and a stable SVR4 ``link_map`` snapshot.
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from payloads import (
    ArbitraryMemory,
    Architecture,
    ExactELFAdapter,
    ExactProcessDiscovery,
    IOPrimitiveTraits,
    Linkage,
    MemorySpan,
    PointerLeak,
    Target,
    inspect_elf,
)
from payloads.tests.runtime_support import SysrootSpec, provision_sysroot
from payloads.tests.test_glibc_qemu import (
    _assert_compiled_target,
    _assert_exact_interpreter,
    _assert_runtime_libc,
    _cache_dir,
    _catalog_target,
    _compile,
    _read_line,
    _selected_specs,
)

_OPT_IN = os.environ.get("PWNC_GLIBC_DISCOVERY_QEMU_TESTS") == "1" or os.environ.get("PWNC_GLIBC_QEMU_TESTS") == "1"
_DEFAULT_SPEC_IDS = (
    "aarch64-glibc-2.39",
    "armebv7-eabihf-glibc-2.39",
)
_REQUEST_LIMIT = 0x10000
_IO_TIMEOUT_SECONDS = 30.0
_SENTINEL = "PWNC_DISCOVERY_QEMU_SENTINEL=target-stack"


_ARBITRARY_READ_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PWNC_READ_LIMIT 0x10000u

static int read_exact(int fd, void *buffer, size_t size) {
    unsigned char *cursor = buffer;
    while (size != 0) {
        ssize_t count = read(fd, cursor, size);
        if (count > 0) {
            cursor += (size_t) count;
            size -= (size_t) count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int write_exact(int fd, const void *buffer, size_t size) {
    const unsigned char *cursor = buffer;
    while (size != 0) {
        ssize_t count = write(fd, cursor, size);
        if (count > 0) {
            cursor += (size_t) count;
            size -= (size_t) count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

int main(void) {
    void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *write_address = handle == NULL ? NULL : dlsym(handle, "write");
    void **heap_leak_slot = malloc(sizeof(*heap_leak_slot));
    Dl_info owner;

    if (write_address == NULL || heap_leak_slot == NULL ||
        dladdr(write_address, &owner) == 0)
        return 90;
    *heap_leak_slot = write_address;
    if (printf("PWNC_DISCOVERY_QEMU\t%s\t%p\t%s\t%p\t%p\n",
               owner.dli_fname, owner.dli_fbase,
               gnu_get_libc_version(), write_address, heap_leak_slot) < 0 ||
        fflush(stdout) != 0)
        return 91;

    for (;;) {
        uintptr_t address;
        uint32_t size;
        if (read_exact(STDIN_FILENO, &address, sizeof(address)) != 0 ||
            read_exact(STDIN_FILENO, &size, sizeof(size)) != 0)
            return 92;
        if (address == (uintptr_t) 0 && size == 0)
            return 0;
        if (address == (uintptr_t) 0 || size == 0 || size > PWNC_READ_LIMIT)
            return 93;
        if (write_exact(STDOUT_FILENO, (const void *) address, size) != 0)
            return 94;
    }
}
"""


def _selected_discovery_specs() -> tuple[SysrootSpec, ...]:
    selected = _selected_specs()
    raw_selector = os.environ.get("PWNC_GLIBC_QEMU_SPECS", "").strip()
    if not raw_selector:
        by_id = {spec.id: spec for spec in selected}
        return tuple(by_id[spec_id] for spec_id in _DEFAULT_SPEC_IDS)
    return tuple(
        spec
        for spec in selected
        if any(
            _catalog_target(target_name).arch not in {Architecture.X86, Architecture.X86_64, Architecture.THUMB}
            for target_name in spec.targets
        )
    )


def _execution_target(spec: SysrootSpec) -> Target:
    candidates = tuple(
        _catalog_target(name)
        for name in spec.targets
        if _catalog_target(name).arch not in {Architecture.X86, Architecture.X86_64, Architecture.THUMB}
    )
    if not candidates:
        raise AssertionError(f"{spec.id} has no non-x86 execution target")
    return candidates[0]


class _GuestArbitraryRead:
    """Adapt the guest's target-endian address/length protocol to ReadAt."""

    def __init__(self, process: subprocess.Popen[bytes], target: Target) -> None:
        if process.stdin is None or process.stdout is None:
            raise AssertionError("guest arbitrary-read process has no protocol pipes")
        self.process = process
        self.target = target

    def _read_exact(self, size: int) -> bytes:
        assert self.process.stdout is not None
        deadline = time.monotonic() + _IO_TIMEOUT_SECONDS
        result = bytearray()
        descriptor = self.process.stdout.fileno()
        while len(result) != size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out after receiving {len(result)}/{size} arbitrary-read bytes")
            ready, _, _ = select.select((descriptor,), (), (), remaining)
            if not ready:
                raise TimeoutError(f"timed out after receiving {len(result)}/{size} arbitrary-read bytes")
            chunk = os.read(descriptor, size - len(result))
            if not chunk:
                stderr = self.process.stderr.read().decode(errors="replace") if self.process.stderr else ""
                raise EOFError(f"guest arbitrary-read protocol closed early: {stderr}")
            result.extend(chunk)
        return bytes(result)

    def read_at(self, address: int, size: int) -> bytes:
        if not 0 < size <= _REQUEST_LIMIT:
            raise ValueError(f"guest arbitrary-read size is out of range: {size}")
        assert self.process.stdin is not None
        request = self.target.pack(address) + size.to_bytes(4, self.target.endian.value)
        self.process.stdin.write(request)
        self.process.stdin.flush()
        return self._read_exact(size)

    def finish(self) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(self.target.pack(0) + b"\0\0\0\0")
        self.process.stdin.flush()


def _read_cstring(memory: ArbitraryMemory, address: int, limit: int = 512) -> bytes:
    result = bytearray()
    for offset in range(limit):
        value = memory.read(address + offset, 1)
        if value == b"\0":
            return bytes(result)
        result.extend(value)
    raise AssertionError(f"guest string at {address:#x} exceeds {limit} bytes")


def _environment_with_sentinel() -> dict[str, str]:
    name, value = _SENTINEL.split("=", 1)
    # A minimal deterministic guest environment keeps the target-side stack
    # walk bounded and avoids inheriting unrelated, potentially huge host
    # values such as shell colour tables.
    return {"LC_ALL": "C", name: value}


class GlibcDiscoveryQemuHarnessTests(unittest.TestCase):
    def test_default_lane_is_bounded_non_x86_and_cross_endian(self) -> None:
        with mock.patch.dict(os.environ, {"PWNC_GLIBC_QEMU_SPECS": ""}):
            specs = _selected_discovery_specs()
        self.assertEqual(tuple(spec.id for spec in specs), _DEFAULT_SPEC_IDS)
        targets = tuple(_execution_target(spec) for spec in specs)
        self.assertTrue(all(target.arch not in {Architecture.X86, Architecture.X86_64} for target in targets))
        self.assertEqual({target.endian.value for target in targets}, {"little", "big"})

    def test_fixture_has_no_process_memory_pseudofile_dependency(self) -> None:
        forbidden = "/proc" + "/self/mem"
        self.assertNotIn(forbidden, _ARBITRARY_READ_SOURCE)
        self.assertNotIn(forbidden, __doc__ or "")


@unittest.skipUnless(
    _OPT_IN,
    "set PWNC_GLIBC_DISCOVERY_QEMU_TESTS=1 (or PWNC_GLIBC_QEMU_TESTS=1); "
    "PWNC_GLIBC_QEMU_SPECS selects exact manifest IDs",
)
class GlibcDiscoveryQemuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not sys.platform.startswith("linux"):
            raise AssertionError("qemu-user discovery tests require a Linux host")

    def test_real_target_arbitrary_read_discovers_glibc_process(self) -> None:
        specs = _selected_discovery_specs()
        if not specs:
            self.skipTest("selected sysroot specs contain no non-x86 discovery target")
        for spec in specs:
            provisioned = provision_sysroot(spec, _cache_dir())
            target = _execution_target(spec)
            with (
                self.subTest(spec=spec.id, target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-glibc-discovery-qemu-") as directory,
            ):
                executable = Path(directory, "arb-read-fixture")
                _compile(provisioned, _ARBITRARY_READ_SOURCE, executable, target=target)
                profile = inspect_elf(executable)
                _assert_compiled_target(self, profile.target, target)
                self.assertFalse(profile.pie)
                self.assertIs(profile.linkage, Linkage.DYNAMIC)
                self.assertTrue(profile.nx, profile.nx_evidence)
                _assert_exact_interpreter(self, provisioned, profile)
                self._run_discovery(provisioned, executable, target)

    def _run_discovery(self, provisioned, executable: Path, target: Target) -> None:
        process = subprocess.Popen(
            provisioned.qemu_argv(executable),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=_environment_with_sentinel(),
        )
        try:
            fields = _read_line(process, f"{provisioned.spec.id} discovery").split(b"\t")
            self.assertEqual(len(fields), 6, fields)
            self.assertEqual(fields[0], b"PWNC_DISCOVERY_QEMU")
            reported_base = int(fields[2], 16)
            reported_version = fields[3].decode("ascii")
            write_address = int(fields[4], 16)
            heap_leak_slot = int(fields[5], 16)
            exact_libc = ExactELFAdapter.from_file(provisioned.libc, expected_target=target)
            exact_loader = ExactELFAdapter.from_file(provisioned.loader, expected_target=target)
            attested_libc = _assert_runtime_libc(
                self,
                provisioned,
                fields[1],
                reported_version,
                reported_base,
                write_address,
                "write",
                symbols=("write", "environ"),
                intended_target=target,
            )
            self.assertEqual(exact_libc.identity.sha256, attested_libc.identity.sha256)

            transport = _GuestArbitraryRead(process, target)
            memory = ArbitraryMemory(
                target,
                read_at=transport.read_at,
                traits=IOPrimitiveTraits(read_chunk=_REQUEST_LIMIT),
            )
            discovery = ExactProcessDiscovery(memory, libc=exact_libc, loader=exact_loader)
            libc_result = discovery.heap_to_libc(
                heap_leak_slot,
                heap_span=MemorySpan(heap_leak_slot, target.word_size, "guest heap libc leak word"),
                libc_base=reported_base,
            )
            self.assertEqual(libc_result.base, reported_base)
            self.assertEqual(libc_result.leak.address, heap_leak_slot)
            self.assertEqual(libc_result.leak.value, write_address)
            self.assertEqual(libc_result.adapter.identity.sha256, exact_libc.identity.sha256)

            # Exercise symbol-relative base inference from the raw libc leak,
            # independently of the explicit-base seed used by the typed
            # heap-to-libc transition above.
            stack = discovery.libc_to_stack(PointerLeak(write_address, symbol="write"))
            self.assertEqual(stack.environ_symbol_address, reported_base + exact_libc.symbol("environ"))
            self.assertNotEqual(stack.environ_pointer, 0)
            environ_values: list[bytes] = []
            for index in range(256):
                pointer = memory.read_ptr(stack.environ_pointer + index * target.word_size)
                if pointer == 0:
                    break
                environ_values.append(_read_cstring(memory, pointer))
            else:
                self.fail("guest environ vector has no terminator within 256 pointers")
            self.assertIn(_SENTINEL.encode(), environ_values)

            loader_result = discovery.libc_to_loader(libc_result)
            self.assertEqual(loader_result.adapter.identity.sha256, exact_loader.identity.sha256)
            snapshot = discovery.loader_to_link_map(
                loader_result,
                known_images=(exact_libc, exact_loader),
            )
            self.assertEqual(snapshot.loader_base, loader_result.base)
            self.assertEqual(snapshot.r_ldbase, loader_result.base)
            self.assertGreaterEqual(len(snapshot.objects), 3)
            self.assertEqual(snapshot.objects[0].base, 0)
            libc_objects = [item for item in snapshot.objects if item.base == libc_result.base]
            loader_objects = [item for item in snapshot.objects if item.base == loader_result.base]
            self.assertEqual(len(libc_objects), 1)
            self.assertEqual(len(loader_objects), 1)
            self.assertIsNotNone(libc_objects[0].adapter)
            self.assertIsNotNone(loader_objects[0].adapter)
            assert libc_objects[0].adapter is not None
            assert loader_objects[0].adapter is not None
            self.assertEqual(libc_objects[0].adapter.identity.sha256, exact_libc.identity.sha256)
            self.assertEqual(loader_objects[0].adapter.identity.sha256, exact_loader.identity.sha256)

            transport.finish()
            return_code = process.wait(timeout=_IO_TIMEOUT_SECONDS)
            stderr = process.stderr.read().decode(errors="replace") if process.stderr is not None else ""
            self.assertEqual(return_code, 0, stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


if __name__ == "__main__":
    unittest.main()
