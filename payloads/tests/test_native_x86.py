"""Opt-in execution tests for payloads running directly on an x86 host.

Run with ``PWNC_NATIVE_TESTS=1 python3 -m unittest discover -s payloads/tests``.
Both AMD64 and Linux i386 compatibility mode are mandatory once enabled.  No
QEMU process or foreign userspace is involved: every fixture is passed directly
to ``execve(2)`` by ``subprocess``.
"""

from __future__ import annotations

import os
import platform
import select
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from payloads import (
    Address,
    Architecture,
    Image,
    LibcBoundAddress,
    LibcImage,
    Linkage,
    LLVMAssembler,
    PayloadKind,
    RuntimeLayout,
    SemanticGadget,
    command_shellcode,
    exit_shellcode,
    inspect_elf,
    mmap_stager,
    orw_shellcode,
    resolve_target,
)
from payloads.rop import build_ret2libc_system
from payloads.tests.test_rop_qemu import (
    _RET2LIBC_SOURCE,
    _assemble_static_fixture,
    _patch_virtual_address,
    _primary_static_chains,
    _symbols_and_image_base,
)
from payloads.tests.test_shellcode_qemu import _link_raw_payload

_NATIVE_OPT_IN = os.environ.get("PWNC_NATIVE_TESTS") == "1"
_NATIVE_TARGETS = (resolve_target("x86"), resolve_target("x86_64"))
_REQUIRED_TOOLS = ("cc", "llvm-mc", "ld.lld")
_MISSING_TOOLS = tuple(tool for tool in _REQUIRED_TOOLS if shutil.which(tool) is None)
_PROBE_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>

int main(void) {
    void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    return handle == NULL;
}
"""


@dataclass(frozen=True, slots=True)
class _ProcMap:
    start: int
    end: int
    permissions: str
    offset: int
    device_major: int
    device_minor: int
    inode: int
    path: str | None

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


def _compile_c(source: str, output: Path, bits: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "cc",
            f"-m{bits}",
            "-x",
            "c",
            "-",
            "-std=c11",
            "-O0",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-pie",
            "-no-pie",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-Wl,-z,noexecstack",
            "-o",
            str(output),
            "-ldl",
        ],
        input=source,
        capture_output=True,
        text=True,
        check=False,
    )


def _require_native_prerequisites() -> None:
    failures: list[str] = []
    if not sys.platform.startswith("linux"):
        failures.append(f"Linux is required (host is {sys.platform!r})")
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        failures.append(f"an x86_64 host is required (host is {platform.machine()!r})")
    if _MISSING_TOOLS:
        failures.append("missing tools: " + ", ".join(_MISSING_TOOLS))
    if not Path("/proc/self/maps").is_file():
        failures.append("a mounted /proc with process maps is required")

    if not failures:
        with tempfile.TemporaryDirectory(prefix="pwnc-native-probe-") as directory:
            root = Path(directory)
            for target in _NATIVE_TARGETS:
                probe = root / f"probe-{target.bits}"
                compiled = _compile_c(_PROBE_SOURCE, probe, target.bits)
                if compiled.returncode:
                    failures.append(
                        f"{target.bits}-bit compiler, headers, dynamic loader, and libc are required: "
                        f"{compiled.stderr.strip()}"
                    )
                    continue
                try:
                    result = subprocess.run([str(probe)], capture_output=True, timeout=10, check=False)
                except OSError as exc:
                    failures.append(f"the kernel cannot execute {target.bits}-bit x86 ELF files: {exc}")
                    continue
                if result.returncode:
                    detail = result.stderr.decode(errors="replace").strip()
                    failures.append(
                        f"native {target.bits}-bit libc probe exited {result.returncode}"
                        + (f": {detail}" if detail else "")
                    )

    if failures:
        raise AssertionError("PWNC_NATIVE_TESTS=1 prerequisites failed:\n- " + "\n- ".join(failures))


def _assert_exact_entry_bytes(test: unittest.TestCase, executable: Path, expected: bytes) -> None:
    profile = inspect_elf(executable)
    matches = [
        item
        for item in profile.load_ranges
        if item.contains(profile.entry_offset, len(expected))
        and profile.entry_offset + len(expected) <= item.start + item.file_size
    ]
    test.assertEqual(len(matches), 1)
    mapping = matches[0]
    file_offset = mapping.file_offset + profile.entry_offset - mapping.start
    test.assertEqual(executable.read_bytes()[file_offset : file_offset + len(expected)], expected)


def _read_process_line(process: subprocess.Popen[bytes], timeout: int = 10) -> bytes:
    assert process.stdout is not None
    ready, _, _ = select.select((process.stdout,), (), (), timeout)
    if not ready:
        raise AssertionError("timed out waiting for the native ret2libc fixture leak")
    line = process.stdout.readline()
    if not line:
        stderr = process.stderr.read().decode(errors="replace") if process.stderr is not None else ""
        raise AssertionError(f"native ret2libc fixture exited before disclosing libc: {stderr}")
    return line.rstrip(b"\n")


def _read_proc_maps(process: subprocess.Popen[bytes]) -> tuple[_ProcMap, ...]:
    records: list[_ProcMap] = []
    for line in Path(f"/proc/{process.pid}/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        address_range, permissions, offset, device, inode = fields[:5]
        path = fields[5] if len(fields) == 6 else None
        start, end = address_range.split("-", 1)
        device_major, device_minor = device.split(":", 1)
        records.append(
            _ProcMap(
                int(start, 16),
                int(end, 16),
                permissions,
                int(offset, 16),
                int(device_major, 16),
                int(device_minor, 16),
                int(inode),
                path,
            )
        )
    return tuple(records)


def _artifact_mappings(maps: tuple[_ProcMap, ...], artifact: Path) -> tuple[_ProcMap, ...]:
    artifact_stat = artifact.stat()
    return tuple(
        item
        for item in maps
        if item.inode == artifact_stat.st_ino
        and item.device_major == os.major(artifact_stat.st_dev)
        and item.device_minor == os.minor(artifact_stat.st_dev)
    )


def _native_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "QEMU_LD_PREFIX",
        "QEMU_SET_ENV",
        "QEMU_UNSET_ENV",
    ):
        environment.pop(name, None)
    return environment


def _host_aslr_enabled() -> bool:
    setting = Path("/proc/sys/kernel/randomize_va_space")
    try:
        return int(setting.read_text().strip()) > 0
    except (OSError, ValueError):
        return False


class NativeX86MatrixTests(unittest.TestCase):
    def test_native_matrix_is_exactly_linux_i386_and_amd64(self) -> None:
        self.assertEqual(
            {target.arch for target in _NATIVE_TARGETS},
            {Architecture.X86, Architecture.X86_64},
        )
        self.assertEqual({target.bits for target in _NATIVE_TARGETS}, {32, 64})


@unittest.skipUnless(
    _NATIVE_OPT_IN,
    "set PWNC_NATIVE_TESTS=1 to run direct Linux i386 and AMD64 execution tests",
)
class NativeShellcodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        _require_native_prerequisites()

    def test_raw_command_shellcode_executes_in_both_native_x86_modes(self) -> None:
        assembler = LLVMAssembler()
        for target in _NATIVE_TARGETS:
            marker = f"PWNC_NATIVE_{target.bits}"
            with (
                self.subTest(target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-native-shell-") as directory,
            ):
                payload = command_shellcode(f"printf {marker}", target, assembler=assembler)
                executable = Path(directory, "payload.elf")
                _link_raw_payload(payload.data, target, executable)
                _assert_exact_entry_bytes(self, executable, payload.data)

                result = subprocess.run([str(executable)], capture_output=True, timeout=10, check=False)

                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, marker.encode())

    def test_raw_orw_shellcode_preserves_binary_file_bytes_in_both_native_x86_modes(self) -> None:
        assembler = LLVMAssembler()
        expected = bytes(range(256)) + b"\0PWNC native ORW\n"
        for target in _NATIVE_TARGETS:
            with self.subTest(target=target.name), tempfile.TemporaryDirectory(prefix="pwnc-native-orw-") as directory:
                source_file = Path(directory, "orw-input")
                source_file.write_bytes(expected)
                payload = orw_shellcode(str(source_file), target, max_bytes=len(expected) + 32, assembler=assembler)
                executable = Path(directory, "payload.elf")
                _link_raw_payload(payload.data, target, executable)
                _assert_exact_entry_bytes(self, executable, payload.data)

                result = subprocess.run([str(executable)], capture_output=True, timeout=10, check=False)

                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, expected)

    def test_rw_to_rx_mmap_stager_runs_exact_child_in_both_native_x86_modes(self) -> None:
        assembler = LLVMAssembler()
        for target in _NATIVE_TARGETS:
            with (
                self.subTest(target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-native-stage-") as directory,
            ):
                child = exit_shellcode(42, target, assembler=assembler)
                stager = mmap_stager(len(child.data), target, assembler=assembler)
                executable = Path(directory, "payload.elf")
                _link_raw_payload(stager.data, target, executable)
                _assert_exact_entry_bytes(self, executable, stager.data)

                result = subprocess.run(
                    [str(executable)],
                    input=child.data,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )

                self.assertEqual(result.returncode, 42, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, b"")


@unittest.skipUnless(
    _NATIVE_OPT_IN,
    "set PWNC_NATIVE_TESTS=1 to run direct Linux i386 and AMD64 execution tests",
)
class NativeStaticRopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        _require_native_prerequisites()

    def test_static_syscall_and_direct_call_chains_execute_in_both_native_x86_modes(self) -> None:
        for target in _NATIVE_TARGETS:
            with self.subTest(target=target.name), tempfile.TemporaryDirectory(prefix="pwnc-native-rop-") as directory:
                root = Path(directory)
                template = _assemble_static_fixture(target, root)
                symbols, image_base = _symbols_and_image_base(template)
                syscall, syscall_data, call, call_data = _primary_static_chains(target, symbols, image_base)
                profile = inspect_elf(template)
                chain_mapping = next(item for item in profile.load_ranges if item.contains(symbols["chain"], 512))

                self.assertEqual(profile.target, target)
                self.assertFalse(profile.pie)
                self.assertIs(profile.linkage, Linkage.STATIC)
                self.assertEqual(syscall.kind, PayloadKind.ROP)
                self.assertEqual(call.kind, PayloadKind.ROP)
                self.assertEqual(call.validate_call_frame(symbols["chain"]), call.function_entry_sp(symbols["chain"]))
                self.assertTrue(chain_mapping.writable)
                self.assertFalse(chain_mapping.executable)

                syscall_executable = root / "syscall"
                call_executable = root / "call"
                _patch_virtual_address(template, syscall_executable, symbols["chain"], syscall_data)
                _patch_virtual_address(template, call_executable, symbols["chain"], call_data)

                syscall_run = subprocess.run([str(syscall_executable)], capture_output=True, timeout=10, check=False)
                call_run = subprocess.run([str(call_executable)], capture_output=True, timeout=10, check=False)

                self.assertEqual(syscall_run.returncode, 43, syscall_run.stderr.decode(errors="replace"))
                self.assertEqual(call_run.returncode, 42, call_run.stderr.decode(errors="replace"))


@unittest.skipUnless(
    _NATIVE_OPT_IN,
    "set PWNC_NATIVE_TESTS=1 to run direct Linux i386 and AMD64 execution tests",
)
class NativeRet2libcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        _require_native_prerequisites()

    def test_exact_loaded_libc_system_chain_executes_from_native_live_bases(self) -> None:
        for target in _NATIVE_TARGETS:
            with (
                self.subTest(target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-native-ret2libc-") as directory,
            ):
                root = Path(directory)
                executable = root / "fixture"
                compiled = _compile_c(_RET2LIBC_SOURCE, executable, target.bits)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                profile = inspect_elf(executable)
                self.assertEqual(profile.target, target)
                self.assertFalse(profile.pie)
                self.assertIs(profile.linkage, Linkage.DYNAMIC)
                self.assertTrue(profile.nx)

                observed_bases: set[int] = set()
                for attempt in range(3):
                    with self.subTest(target=target.name, attempt=attempt):
                        process = subprocess.Popen(
                            [str(executable)],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=_native_environment(),
                        )
                        try:
                            libc_path_bytes, leaked_bytes, owner_base_bytes, chain_base_bytes = _read_process_line(
                                process
                            ).split(b"\t")
                            libc_path = Path(os.fsdecode(libc_path_bytes)).resolve(strict=True)
                            leaked_system = int(leaked_bytes, 16)
                            owner_base = int(owner_base_bytes, 16)
                            disclosed_chain_base = int(chain_base_bytes, 16)
                            maps = _read_proc_maps(process)

                            self.assertTrue(os.path.samefile(f"/proc/{process.pid}/exe", executable))
                            libc_maps = _artifact_mappings(maps, libc_path)
                            self.assertTrue(libc_maps, f"{libc_path} is absent from /proc/{process.pid}/maps")
                            self.assertTrue(
                                any(item.contains(leaked_system) and "x" in item.permissions for item in libc_maps)
                            )
                            mapped_paths = {
                                Path(item.path).resolve()
                                for item in libc_maps
                                if item.path is not None and not item.path.startswith("[")
                            }
                            self.assertIn(libc_path, mapped_paths)
                            self.assertEqual({item.start for item in libc_maps if item.offset == 0}, {owner_base})

                            libc_profile = inspect_elf(libc_path)
                            libc = LibcImage.from_file(libc_path, symbols=("system",))
                            self.assertEqual(libc.target, target)
                            self.assertEqual(libc_profile.soname, "libc.so.6")
                            self.assertEqual(libc.identity.sha256, libc_profile.sha256)
                            self.assertEqual(libc.identity.build_id, libc_profile.build_id)
                            self.assertTrue(libc.identity.matches(libc_path.read_bytes()))
                            libc_base = libc.base_from_leak("system", leaked_system)
                            self.assertEqual(libc_base, owner_base)
                            self.assertEqual(libc_base + libc.offset("system"), leaked_system)
                            self.assertEqual(libc_base % 0x1000, 0)
                            observed_bases.add(libc_base)

                            command = Address(profile.symbol_offsets["pwnc_command"], Image.MAIN, "fixture command")
                            return_to = Address(profile.symbol_offsets["pwnc_success"], Image.MAIN, "success exit")
                            gadgets: tuple[SemanticGadget, ...] = ()
                            if target.arch is Architecture.X86_64:
                                gadgets = (
                                    SemanticGadget(
                                        target,
                                        Address(
                                            profile.symbol_offsets["pwnc_pop_rdi_ret"],
                                            Image.MAIN,
                                            "fixture pop rdi; ret",
                                        ),
                                        2,
                                        {"rdi": 0},
                                        1,
                                        "fixture pop rdi; ret",
                                    ),
                                )
                            chain = build_ret2libc_system(libc, command, gadgets=gadgets, return_to=return_to)
                            chain_base = (
                                profile.symbol_offsets["pwnc_chain"] + 0xF0000 + (8 if target.bits == 32 else 0)
                            )
                            self.assertEqual(disclosed_chain_base, chain_base)
                            chain_mapping = next(item for item in maps if item.contains(chain_base))
                            self.assertIn("r", chain_mapping.permissions)
                            self.assertIn("w", chain_mapping.permissions)
                            self.assertNotIn("x", chain_mapping.permissions)
                            layout = RuntimeLayout(main_base=0, libc_base=libc_base)
                            chain_data = chain.materialize(layout, chain_base=chain_base)
                            self.assertEqual(chain.kind, PayloadKind.RET2LIBC)
                            libc_words = [word for word in chain.words if isinstance(word.value, LibcBoundAddress)]
                            self.assertEqual(len(libc_words), 1)
                            self.assertEqual(libc_words[0].resolve(target, layout), leaked_system)
                            self.assertIn(libc.identity.sha256[:12], chain.description)
                            self.assertLessEqual(len(chain_data), 256)
                            chain_data += bytes(256 - len(chain_data))

                            stdout, stderr = process.communicate(chain_data, timeout=10)
                            self.assertEqual(process.returncode, 42, stderr.decode(errors="replace"))
                            self.assertEqual(stdout, b"PWNC_RET2LIBC_OK")
                        finally:
                            if process.poll() is None:
                                process.kill()
                            process.communicate()

                if _host_aslr_enabled():
                    self.assertGreater(
                        len(observed_bases),
                        1,
                        "three native processes should expose at least two distinct ASLR libc bases",
                    )


if __name__ == "__main__":
    unittest.main()
