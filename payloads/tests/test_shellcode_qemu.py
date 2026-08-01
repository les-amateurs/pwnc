"""Opt-in end-to-end execution tests for raw payload bytes.

Run with ``PWNC_QEMU_TESTS=1 python3 -m unittest discover -s payloads/tests``.
The tests link only a minimal ELF envelope around the exact raw bytes returned
by the command, ORW, exit, and mmap-stager builders; libc or a foreign sysroot
is not used.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from payloads import (
    ABI,
    SUPPORTED_TARGETS,
    Architecture,
    LLVMAssembler,
    command_shellcode,
    exit_shellcode,
    llvm_triple,
    mmap_stager,
    orw_shellcode,
    resolve_target,
)
from payloads.tests.test_shellcode import PRIMARY_TARGETS

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
    (Architecture.POWERPC32, "big"): "qemu-ppc",
    (Architecture.POWERPC64, "big"): "qemu-ppc64",
    (Architecture.POWERPC64, "little"): "qemu-ppc64le",
    (Architecture.SPARC32, None): "qemu-sparc",
    (Architecture.SPARC64, None): "qemu-sparc64",
    (Architecture.S390X, None): "qemu-s390x",
}

QEMU_TARGETS = PRIMARY_TARGETS + (
    ("powerpc32", "big"),
    ("powerpc64", "big"),
    ("powerpc64", "little"),
    ("sparc32", None),
    ("sparc64", None),
    ("s390x", None),
)


class QemuMatrixTests(unittest.TestCase):
    def test_qemu_matrix_is_every_catalog_target_except_ppc32le(self) -> None:
        runtime_targets = {resolve_target(architecture, endian=endian).name for architecture, endian in QEMU_TARGETS}
        ppc32le = resolve_target("powerpc32", endian="little").name
        self.assertEqual(runtime_targets, {target.name for target in SUPPORTED_TARGETS} - {ppc32le})
        self.assertEqual(
            set(_QEMU),
            {(resolve_target(architecture, endian=endian).arch, endian) for architecture, endian in QEMU_TARGETS},
        )


def _write_sparc_elf(data: bytes, target, output: Path) -> None:
    """Wrap SPARC bytes without asking LLD to process unstable SPARC input."""

    if target.arch is Architecture.SPARC32:
        elf_class = 1
        machine = 2
        base = alignment = 0x10000
        header_size = 52
        program_header_size = 32
        header = struct.Struct(">HHIIIIIHHHHHH")
        program_header = struct.Struct(">IIIIIIII")
    else:
        elf_class = 2
        machine = 43
        base = alignment = 0x100000
        header_size = 64
        program_header_size = 56
        header = struct.Struct(">HHIQQQIHHHHHH")
        program_header = struct.Struct(">IIQQQQQQ")

    program_header_count = 4
    code_offset = header_size + program_header_size * program_header_count
    code_address = base + alignment + code_offset
    image_size = code_offset + len(data)
    ident = b"\x7fELF" + bytes((elf_class, 2, 1, 0, 0)) + bytes(7)
    elf_header = ident + header.pack(
        2,
        machine,
        1,
        code_address,
        header_size,
        0,
        0,
        header_size,
        program_header_size,
        program_header_count,
        0,
        0,
        0,
    )

    if target.arch is Architecture.SPARC32:
        headers = (
            program_header.pack(
                6,
                header_size,
                base + header_size,
                base + header_size,
                program_header_size * program_header_count,
                program_header_size * program_header_count,
                4,
                4,
            ),
            program_header.pack(1, 0, base, base, code_offset, code_offset, 4, alignment),
            program_header.pack(
                1,
                code_offset,
                code_address,
                code_address,
                len(data),
                len(data),
                5,
                alignment,
            ),
            program_header.pack(0x6474E551, 0, 0, 0, 0, 0, 6, 16),
        )
    else:
        headers = (
            program_header.pack(
                6,
                4,
                header_size,
                base + header_size,
                base + header_size,
                program_header_size * program_header_count,
                program_header_size * program_header_count,
                8,
            ),
            program_header.pack(1, 4, 0, base, base, code_offset, code_offset, alignment),
            program_header.pack(
                1,
                5,
                code_offset,
                code_address,
                code_address,
                len(data),
                len(data),
                alignment,
            ),
            program_header.pack(0x6474E551, 6, 0, 0, 0, 0, 0, 16),
        )

    image = elf_header + b"".join(headers) + data
    if len(image) != image_size:
        raise AssertionError("internal SPARC ELF size mismatch")
    output.write_bytes(image)
    output.chmod(0o755)


def _write_ppc64_elfv1(data: bytes, output: Path) -> None:
    """Wrap raw code with the function descriptor required by PPC64 ELFv1."""

    header_size = 64
    program_header_size = 56
    program_header_count = 3
    descriptor_size = 24
    descriptor_offset = header_size + program_header_size * program_header_count
    code_offset = descriptor_offset + descriptor_size
    base = 0x10000000
    alignment = 0x10000
    descriptor_address = base + descriptor_offset
    code_address = base + code_offset
    image_size = code_offset + len(data)
    ident = b"\x7fELF" + bytes((2, 2, 1, 0, 0)) + bytes(7)
    elf_header = ident + struct.pack(
        ">HHIQQQIHHHHHH",
        2,
        21,
        1,
        descriptor_address,
        header_size,
        0,
        1,
        header_size,
        program_header_size,
        program_header_count,
        0,
        0,
        0,
    )
    program_headers = b"".join(
        (
            struct.pack(
                ">IIQQQQQQ",
                6,
                4,
                header_size,
                base + header_size,
                base + header_size,
                program_header_size * program_header_count,
                program_header_size * program_header_count,
                8,
            ),
            struct.pack(">IIQQQQQQ", 1, 5, 0, base, base, image_size, image_size, alignment),
            struct.pack(">IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16),
        )
    )
    descriptor = struct.pack(">QQQ", code_address, 0, 0)
    image = elf_header + program_headers + descriptor + data
    if len(image) != image_size:
        raise AssertionError("internal PPC64 ELFv1 size mismatch")
    output.write_bytes(image)
    output.chmod(0o755)


def _link_raw_payload(data: bytes, target, output: Path) -> None:
    if target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
        _write_sparc_elf(data, target, output)
        return
    if target.abi is ABI.POWERPC64_ELFV1:
        _write_ppc64_elfv1(data, output)
        return

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
    def test_raw_command_shellcode_executes_on_every_qemu_target(self) -> None:
        assembler = LLVMAssembler()
        for architecture, endian in QEMU_TARGETS:
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
        for architecture, endian in QEMU_TARGETS:
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
        for architecture, endian in QEMU_TARGETS:
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
