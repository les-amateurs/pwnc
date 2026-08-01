"""Opt-in end-to-end execution tests for raw payload bytes.

Run with ``PWNC_QEMU_TESTS=1 python3 -m unittest discover -s payloads/tests``.
The test links only a minimal ELF envelope around the exact raw bytes returned
by :func:`payloads.command_shellcode`; libc or a foreign sysroot is not used.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from payloads import (
    ABI,
    Architecture,
    LLVMAssembler,
    command_shellcode,
    exit_shellcode,
    llvm_triple,
    mmap_stager,
    orw_shellcode,
    resolve_target,
)

from test_shellcode import PRIMARY_TARGETS


_QEMU = {
    (Architecture.X86, None): "qemu-i386",
    (Architecture.X86_64, None): "qemu-x86_64",
    (Architecture.ARM, "little"): "qemu-arm",
    (Architecture.ARM, "big"): "qemu-armeb",
    (Architecture.THUMB, "little"): "qemu-arm",
    (Architecture.THUMB, "big"): "qemu-armeb",
    (Architecture.ARM64, "little"): "qemu-aarch64",
    (Architecture.ARM64, "big"): "qemu-aarch64_be",
    (Architecture.MIPS32, "little"): "qemu-mipsel",
    (Architecture.MIPS32, "big"): "qemu-mips",
    (Architecture.MIPS64, "little"): "qemu-mips64el",
    (Architecture.MIPS64, "big"): "qemu-mips64",
    (Architecture.RISCV32, None): "qemu-riscv32",
    (Architecture.RISCV64, None): "qemu-riscv64",
}


def _link_raw_payload(data: bytes, target, output: Path) -> None:
    lines = [".text"]
    if target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend((".syntax unified", ".thumb" if target.arch is Architecture.THUMB else ".arm"))
    lines.append(".globl _start")
    if target.arch is Architecture.THUMB:
        lines.append(".thumb_func")
    lines.extend(("_start:", ".byte " + ", ".join(f"0x{byte:02x}" for byte in data)))
    source = "\n".join(lines) + "\n"

    object_path = output.with_suffix(".o")
    command = ["llvm-mc", f"-triple={llvm_triple(target)}", "-filetype=obj", "-o", str(object_path)]
    if target.abi is ABI.MIPS_O32:
        command.append("-target-abi=o32")
    elif target.abi is ABI.MIPS_N64:
        command.append("-target-abi=n64")
    assembled = subprocess.run(command, input=source, text=True, capture_output=True, check=False)
    if assembled.returncode:
        raise AssertionError(assembled.stderr)
    linked = subprocess.run(
        ["ld.lld", "-static", "-e", "_start", "-o", str(output), str(object_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if linked.returncode:
        raise AssertionError(linked.stderr)


_TOOLS_PRESENT = all(shutil.which(tool) for tool in ("llvm-mc", "ld.lld"))
_QEMU_PRESENT = all(shutil.which(binary) for binary in set(_QEMU.values()))


@unittest.skipUnless(
    os.environ.get("PWNC_QEMU_TESTS") == "1" and _TOOLS_PRESENT and _QEMU_PRESENT,
    "set PWNC_QEMU_TESTS=1 with LLVM/LLD and QEMU user emulators installed",
)
class CommandQemuTests(unittest.TestCase):
    def test_raw_command_shellcode_executes_on_every_primary_target(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in PRIMARY_TARGETS:
            target = resolve_target(architecture, endian=endian)
            marker = f"PWNC_{architecture}_{endian or 'default'}".replace("-", "_")
            with self.subTest(target=target.name), tempfile.TemporaryDirectory(prefix="pwnc-qemu-") as directory:
                payload = command_shellcode(f"printf {marker}", target, assembler=assembler)
                executable = Path(directory, "payload.elf")
                _link_raw_payload(payload.data, target, executable)
                qemu = _QEMU[(target.arch, endian)]
                result = subprocess.run(
                    [qemu, str(executable)],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, marker.encode())

    def test_raw_orw_shellcode_preserves_binary_file_bytes(self) -> None:
        assembler = LLVMAssembler()
        expected = b"pwnc ORW\0binary bytes\n"
        for architecture, endian in PRIMARY_TARGETS:
            target = resolve_target(architecture, endian=endian)
            with self.subTest(target=target.name), tempfile.TemporaryDirectory(prefix="pwnc-qemu-") as directory:
                source_file = Path(directory, "orw-input")
                source_file.write_bytes(expected)
                payload = orw_shellcode(str(source_file), target, max_bytes=256, assembler=assembler)
                executable = Path(directory, "payload.elf")
                _link_raw_payload(payload.data, target, executable)
                qemu = _QEMU[(target.arch, endian)]
                result = subprocess.run(
                    [qemu, str(executable)],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, expected)

    def test_rw_to_rx_mmap_stager_runs_exact_second_stage(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in PRIMARY_TARGETS:
            target = resolve_target(architecture, endian=endian)
            with self.subTest(target=target.name), tempfile.TemporaryDirectory(prefix="pwnc-qemu-") as directory:
                child = exit_shellcode(42, target, assembler=assembler)
                stager = mmap_stager(len(child.data), target, assembler=assembler)
                executable = Path(directory, "payload.elf")
                _link_raw_payload(stager.data, target, executable)
                qemu = _QEMU[(target.arch, endian)]
                result = subprocess.run(
                    [qemu, str(executable)],
                    input=child.data,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 42, result.stderr.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
