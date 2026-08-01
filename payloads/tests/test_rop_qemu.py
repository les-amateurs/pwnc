"""Opt-in execution tests for materialized symbolic ROP chains.

Static fixtures contain concrete register-loading gadgets and reserved chain
storage.  The tests link each fixture, describe those exact gadgets with
``SemanticGadget``, materialize a builder-produced chain, patch it into the
fixture, and pivot to the first chain word under QEMU.

The dynamic x86 fixtures do not disable address randomization.  They disclose
the live ``system`` address, owner base, and loaded libc path, then the test
hashes/parses that exact artifact, verifies the base independently, and sends
a late-materialized ret2libc chain.  QEMU itself may choose a deterministic
guest layout, so the evidence is live-base validation rather than ASLR variance.
"""

from __future__ import annotations

import os
import select
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from payloads import (
    ABI,
    SUPPORTED_TARGETS,
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
    Target,
    build_ret2libc_system,
    build_static_call,
    build_static_syscall,
    inspect_elf,
    llvm_triple,
    resolve_target,
)
from payloads.tests.test_shellcode_qemu import _link_raw_payload


@dataclass(frozen=True, slots=True)
class _RopCase:
    architecture: str
    endian: str | None
    qemu: str


_PRIMARY_ROP_CASES = (
    _RopCase("x86", None, "qemu-i386"),
    _RopCase("x86_64", None, "qemu-x86_64"),
    _RopCase("arm", "little", "qemu-arm"),
    _RopCase("arm", "big", "qemu-armeb"),
    _RopCase("thumb", "little", "qemu-arm"),
    _RopCase("thumb", "big", "qemu-armeb"),
    _RopCase("arm64", "little", "qemu-aarch64"),
    _RopCase("arm64", "big", "qemu-aarch64_be"),
)

_EXTRA_SYSCALL_CASES = (
    _RopCase("mips32", "big", "qemu-mips"),
    _RopCase("mips32", "little", "qemu-mipsel"),
    _RopCase("mips64", "big", "qemu-mips64"),
    _RopCase("mips64", "little", "qemu-mips64el"),
    _RopCase("riscv32", None, "qemu-riscv32"),
    _RopCase("riscv64", None, "qemu-riscv64"),
    _RopCase("powerpc32", "big", "qemu-ppc"),
    _RopCase("powerpc64", "big", "qemu-ppc64"),
    _RopCase("powerpc64", "little", "qemu-ppc64le"),
    _RopCase("sparc32", None, "qemu-sparc"),
    _RopCase("sparc64", None, "qemu-sparc64"),
    _RopCase("s390x", None, "qemu-s390x"),
)

_EXTRA_CALL_CASES = tuple(
    case
    for case in _EXTRA_SYSCALL_CASES
    if not (case.architecture in {"sparc32", "sparc64"} or (case.architecture == "powerpc64" and case.endian == "big"))
)

_STATIC_SYSCALL_CASES = _PRIMARY_ROP_CASES + _EXTRA_SYSCALL_CASES
_STATIC_CALL_CASES = _PRIMARY_ROP_CASES + _EXTRA_CALL_CASES

_STATIC_TOOLS_PRESENT = all(shutil.which(tool) for tool in ("llvm-mc", "ld.lld"))
_STATIC_QEMU_PRESENT = all(shutil.which(case.qemu) for case in _STATIC_SYSCALL_CASES)


def _target(case: _RopCase) -> Target:
    return resolve_target(case.architecture, endian=case.endian)


def _static_fixture_source(target: Target) -> str:
    chain_padding = 8 if target.arch is Architecture.X86 else 0
    chain = f"""
.data
.balign 16
.space {chain_padding}
.global chain
chain:
.space 512
"""

    if target.arch is Architecture.X86:
        return f"""
.intel_syntax noprefix
.text
.global _start
_start:
  lea esp, [chain]
  ret
.global syscall_loader
syscall_loader:
  pop eax
  pop ebx
  ret
.global syscall_terminal
syscall_terminal:
  int 0x80
  ud2
.global test_function
test_function:
  lea ecx, [esp + 4]
  test ecx, 15
  jne alignment_failure
  mov eax, DWORD PTR [esp + 4]
  add eax, 5
  ret
.global return_handler
return_handler:
  mov ebx, eax
  mov eax, 1
  int 0x80
  ud2
alignment_failure:
  mov ebx, 99
  mov eax, 1
  int 0x80
  ud2
{chain}
"""

    if target.arch is Architecture.X86_64:
        return f"""
.intel_syntax noprefix
.text
.global _start
_start:
  lea rsp, [rip + chain]
  ret
.global syscall_loader
syscall_loader:
  pop rax
  pop rdi
  ret
.global syscall_terminal
syscall_terminal:
  syscall
  ud2
.global call_loader
call_loader:
  pop rdi
  ret
.global test_function
test_function:
  lea rax, [rsp + 8]
  test rax, 15
  jne alignment_failure
  lea rax, [rdi + 5]
  ret
.global return_handler
return_handler:
  mov rdi, rax
  mov eax, 60
  syscall
  ud2
alignment_failure:
  mov edi, 99
  mov eax, 60
  syscall
  ud2
{chain}
"""

    if target.arch in {Architecture.ARM, Architecture.THUMB}:
        mode = ".thumb" if target.arch is Architecture.THUMB else ".arm"
        thumb_func = ".thumb_func\n" if target.arch is Architecture.THUMB else ""
        if target.arch is Architecture.THUMB:
            bootstrap = "  ldr r4, =chain\n  mov sp, r4\n  pop {pc}"
            alignment_check = "  mov r1, sp\n  ands r1, r1, #7\n  bne alignment_failure"
        else:
            bootstrap = "  ldr sp, =chain\n  pop {pc}"
            alignment_check = "  tst sp, #7\n  bne alignment_failure"
        return f"""
.syntax unified
.arch armv7-a
{mode}
.text
.global _start
{thumb_func}_start:
{bootstrap}
.global syscall_loader
{thumb_func}syscall_loader:
  pop {{r0, r7, pc}}
.global syscall_terminal
{thumb_func}syscall_terminal:
  svc #0
  udf #0
.global call_loader
{thumb_func}call_loader:
  pop {{r0, r3}}
  mov lr, r3
  pop {{pc}}
.global test_function
{thumb_func}test_function:
{alignment_check}
  add r0, r0, #5
  bx lr
.global return_handler
{thumb_func}return_handler:
  mov r7, #1
  svc #0
  udf #0
alignment_failure:
  mov r0, #99
  mov r7, #1
  svc #0
  udf #0
{chain}
"""

    if target.arch is Architecture.ARM64:
        return f"""
.text
.global _start
_start:
  adrp x17, chain
  add x17, x17, :lo12:chain
  mov sp, x17
  ldr x16, [sp], #8
  br x16
.global syscall_loader
syscall_loader:
  ldp x0, x8, [sp], #16
  ldr x16, [sp], #8
  br x16
.global syscall_terminal
syscall_terminal:
  svc #0
  brk #0
.global call_loader
call_loader:
  ldp x0, x30, [sp], #16
  ldr x16, [sp], #8
  br x16
.global test_function
test_function:
  mov x1, sp
  tst x1, #15
  b.ne alignment_failure
  add x0, x0, #5
  ret
.global return_handler
return_handler:
  mov x8, #93
  svc #0
  brk #0
alignment_failure:
  mov x0, #99
  mov x8, #93
  svc #0
  brk #0
{chain}
"""

    raise AssertionError(f"no primary ROP fixture for {target.name}")


def _run_checked(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError(
            f"command failed with status {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}"
        )
    return result


def _assemble_static_fixture(target: Target, directory: Path) -> Path:
    source = directory / "fixture.s"
    object_path = directory / "fixture.o"
    executable = directory / "fixture"
    source.write_text(_static_fixture_source(target))
    _run_checked(["llvm-mc", f"-triple={llvm_triple(target)}", "-filetype=obj", "-o", str(object_path), str(source)])
    _run_checked(["ld.lld", "-static", "-e", "_start", "-o", str(executable), str(object_path)])
    executable.chmod(0o755)
    return executable


_STATIC_SYMBOLS = (
    "chain",
    "syscall_loader",
    "syscall_terminal",
    "call_loader",
    "test_function",
    "return_handler",
)


def _symbols_and_image_base(executable: Path) -> tuple[dict[str, int], int]:
    from elftools.elf.elffile import ELFFile

    symbols: dict[str, int] = {}
    with executable.open("rb") as stream:
        elf = ELFFile(stream)
        loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
        image_base = min(int(segment["p_vaddr"]) for segment in loads)
        table = elf.get_section_by_name(".symtab")
        if table is None:
            raise AssertionError("static ROP fixture has no symbol table")
        for name in _STATIC_SYMBOLS:
            entries = table.get_symbol_by_name(name)
            if entries:
                symbols[name] = int(entries[0]["st_value"])
    return symbols, image_base


def _patch_virtual_address(template: Path, output: Path, address: int, data: bytes) -> None:
    from elftools.elf.elffile import ELFFile

    shutil.copyfile(template, output)
    with output.open("rb") as stream:
        elf = ELFFile(stream)
        matching = [
            segment
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD"
            and int(segment["p_vaddr"]) <= address
            and address + len(data) <= int(segment["p_vaddr"]) + int(segment["p_filesz"])
        ]
        if len(matching) != 1:
            raise AssertionError(f"chain address {address:#x} is not in exactly one file-backed PT_LOAD")
        segment = matching[0]
        file_offset = int(segment["p_offset"]) + address - int(segment["p_vaddr"])
    image = bytearray(output.read_bytes())
    image[file_offset : file_offset + len(data)] = data
    output.write_bytes(image)
    output.chmod(0o755)


def _main_address(symbols: dict[str, int], image_base: int, name: str) -> Address:
    return Address(symbols[name] - image_base, Image.MAIN, name)


def _primary_static_chains(target: Target, symbols: dict[str, int], image_base: int):
    layout = RuntimeLayout(main_base=image_base)
    if target.arch is Architecture.X86:
        syscall_gadget = SemanticGadget(
            target,
            _main_address(symbols, image_base, "syscall_loader"),
            3,
            {"eax": 0, "ebx": 1},
            2,
            "pop eax; pop ebx; ret",
        )
        syscall = build_static_syscall(
            target,
            symbols["syscall_terminal"] - image_base,
            1,
            (43,),
            gadgets=(syscall_gadget,),
        )
        call = build_static_call(
            target,
            symbols["test_function"] - image_base,
            (37,),
            return_to=_main_address(symbols, image_base, "return_handler"),
        )
    elif target.arch is Architecture.X86_64:
        syscall_gadget = SemanticGadget(
            target,
            _main_address(symbols, image_base, "syscall_loader"),
            3,
            {"rax": 0, "rdi": 1},
            2,
            "pop rax; pop rdi; ret",
        )
        call_gadget = SemanticGadget(
            target,
            _main_address(symbols, image_base, "call_loader"),
            2,
            {"rdi": 0},
            1,
            "pop rdi; ret",
        )
        syscall = build_static_syscall(
            target,
            symbols["syscall_terminal"] - image_base,
            60,
            (43,),
            gadgets=(syscall_gadget,),
        )
        call = build_static_call(
            target,
            symbols["test_function"] - image_base,
            (37,),
            gadgets=(call_gadget,),
            return_to=_main_address(symbols, image_base, "return_handler"),
        )
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        syscall_gadget = SemanticGadget(
            target,
            _main_address(symbols, image_base, "syscall_loader"),
            3,
            {"r0": 0, "r7": 1},
            2,
            "pop r0, r7, pc",
        )
        call_gadget = SemanticGadget(
            target,
            _main_address(symbols, image_base, "call_loader"),
            3,
            {"r0": 0, "lr": 1},
            2,
            "restore r0, lr, pc",
            clobbers={"r3"},
        )
        syscall = build_static_syscall(
            target,
            symbols["syscall_terminal"] - image_base,
            1,
            (43,),
            gadgets=(syscall_gadget,),
        )
        call = build_static_call(
            target,
            symbols["test_function"] - image_base,
            (37,),
            gadgets=(call_gadget,),
            return_to=_main_address(symbols, image_base, "return_handler"),
        )
    elif target.arch is Architecture.ARM64:
        syscall_gadget = SemanticGadget(
            target,
            _main_address(symbols, image_base, "syscall_loader"),
            3,
            {"x0": 0, "x8": 1, "x16": 2},
            2,
            "restore x0, x8, x16; br x16",
            next_pc_register="x16",
        )
        call_gadget = SemanticGadget(
            target,
            _main_address(symbols, image_base, "call_loader"),
            3,
            {"x0": 0, "x30": 1, "x16": 2},
            2,
            "restore x0, x30, x16; br x16",
            next_pc_register="x16",
        )
        syscall = build_static_syscall(
            target,
            symbols["syscall_terminal"] - image_base,
            93,
            (43,),
            gadgets=(syscall_gadget,),
        )
        call = build_static_call(
            target,
            symbols["test_function"] - image_base,
            (37,),
            gadgets=(call_gadget,),
            return_to=_main_address(symbols, image_base, "return_handler"),
        )
    else:  # pragma: no cover - caller restricts the matrix
        raise AssertionError(target.name)
    return syscall, syscall.materialize(layout), call, call.materialize(layout, chain_base=symbols["chain"])


_CALLER_MARKER = 0x13579BDF
_EXTRA_ASSEMBLER = LLVMAssembler()


def _extra_code_address(target: Target, directory: Path) -> int:
    """Return the raw code VA used by the minimal exact-byte envelope."""

    probe = directory / "address-probe"
    _link_raw_payload(bytes(0x800), target, probe)
    return _linked_raw_code_address(target, probe)


def _linked_raw_code_address(target: Target, executable: Path) -> int:
    if target.arch is Architecture.SPARC32:
        return 0x200B4
    if target.arch is Architecture.SPARC64:
        return 0x200120
    if target.abi is ABI.POWERPC64_ELFV1:
        return 0x10000100

    from elftools.elf.elffile import ELFFile

    with executable.open("rb") as stream:
        return int(ELFFile(stream).header["e_entry"])


def _powerpc_load(target: Target, register: int, value: int) -> list[str]:
    value &= target.mask
    if target.bits == 32:
        return [
            f"lis {register}, 0x{value >> 16:04x}",
            f"ori {register}, {register}, 0x{value & 0xFFFF:04x}",
        ]
    chunks = [(value >> shift) & 0xFFFF for shift in (48, 32, 16, 0)]
    return [
        f"lis {register}, 0x{chunks[0]:04x}",
        f"ori {register}, {register}, 0x{chunks[1]:04x}",
        f"sldi {register}, {register}, 32",
        f"oris {register}, {register}, 0x{chunks[2]:04x}",
        f"ori {register}, {register}, 0x{chunks[3]:04x}",
    ]


def _s390_load(register: str, value: int) -> list[str]:
    return [
        f"llihf %{register}, 0x{value >> 32 & 0xFFFFFFFF:x}",
        f"oilf %{register}, 0x{value & 0xFFFFFFFF:x}",
    ]


def _chain_placeholder(lines: list[str], chain_offset: int, size: int) -> str:
    lines.extend((f".org 0x{chain_offset:x}", "chain:", f".space {size}"))
    return "\n".join(lines) + "\n"


def _assemble_and_patch_chain(source: str, target: Target, chain_offset: int, chain: bytes) -> bytes:
    raw = bytearray(_EXTRA_ASSEMBLER.assemble(source, target))
    end = chain_offset + len(chain)
    if end > len(raw):
        raise AssertionError(f"chain patch [{chain_offset:#x}, {end:#x}) exceeds text size {len(raw):#x}")
    if any(raw[chain_offset:end]):
        raise AssertionError("chain placeholder is not zero-filled")
    raw[chain_offset:end] = chain
    return bytes(raw)


def _link_extra_fixture(raw: bytes, target: Target, output: Path, expected_code: int) -> None:
    _link_raw_payload(raw, target, output)
    actual_code = _linked_raw_code_address(target, output)
    if actual_code != expected_code:
        raise AssertionError(f"raw code address moved from {expected_code:#x} to {actual_code:#x}")


def _extra_syscall_gadget(target: Target, code: int) -> SemanticGadget:
    controls = {
        Architecture.MIPS32: "ra",
        Architecture.MIPS64: "ra",
        Architecture.RISCV32: "ra",
        Architecture.RISCV64: "ra",
        Architecture.POWERPC32: "r12",
        Architecture.POWERPC64: "r12",
        Architecture.SPARC32: "g2",
        Architecture.SPARC64: "g2",
        Architecture.S390X: "r14",
    }
    descriptions = {
        Architecture.MIPS32: "lw v0/a0/ra from sp; advance sp; jr ra",
        Architecture.MIPS64: "ld v0/a0/ra from sp; advance sp; jr ra",
        Architecture.RISCV32: "lw a7/a0/ra from sp; advance sp; ret",
        Architecture.RISCV64: "ld a7/a0/ra from sp; advance sp; ret",
        Architecture.POWERPC32: "lwz r0/r3/r12; advance r1; mtctr r12; bctr",
        Architecture.POWERPC64: "ld r0/r3/r12; advance r1; mtctr r12; bctr",
        Architecture.SPARC32: "ld g1/o0/g2; jmp g2; advance sp in delay slot",
        Architecture.SPARC64: "ldx g1/o0/g2 from biased sp; jmp g2; advance sp",
        Architecture.S390X: "lg r1/r2/r14; advance r15; br r14",
    }
    control = controls[target.arch]
    return SemanticGadget(
        target,
        Address(code + 0x100, Image.MAIN, "restore syscall frame"),
        3,
        {
            target.convention.syscall_number: 0,
            target.convention.syscall_arguments[0]: 1,
            control: 2,
        },
        2,
        descriptions[target.arch],
        next_pc_register=control,
    )


def _extra_syscall_source(target: Target, code: int, chain_size: int) -> tuple[str, int]:
    arch = target.arch
    word = target.word_size
    chain_offset = 0x400
    chain_address = code + chain_offset
    lines: list[str] = []
    if arch is Architecture.POWERPC64:
        version = 1 if target.abi is ABI.POWERPC64_ELFV1 else 2
        lines.append(f".abiversion {version}")
    lines.extend((".text", ".globl _start", "_start:"))

    if arch in {Architecture.MIPS32, Architecture.MIPS64}:
        is_64 = arch is Architecture.MIPS64
        immediate = "dli" if is_64 else "li"
        load = "ld" if is_64 else "lw"
        add = "daddiu" if is_64 else "addiu"
        lines.extend(
            (
                ".set noreorder",
                f"{immediate} $sp, 0x{chain_address:x}",
                f"{load} $t9, 0($sp)",
                f"{add} $sp, $sp, {word}",
                "jr $t9",
                "nop",
                ".org 0x100",
                "restore_gadget:",
                f"{load} $v0, 0($sp)",
                f"{load} $a0, {word}($sp)",
                f"{load} $ra, {2 * word}($sp)",
                f"{add} $sp, $sp, {3 * word}",
                "jr $ra",
                "nop",
                ".org 0x200",
                "syscall_gadget:",
                "syscall",
                "nop",
            )
        )
    elif arch in {Architecture.RISCV32, Architecture.RISCV64}:
        load = "ld" if arch is Architecture.RISCV64 else "lw"
        lines.extend(
            (
                ".option norvc",
                f"li sp, 0x{chain_address:x}",
                f"{load} t0, 0(sp)",
                f"addi sp, sp, {word}",
                "jr t0",
                ".org 0x100",
                "restore_gadget:",
                f"{load} a7, 0(sp)",
                f"{load} a0, {word}(sp)",
                f"{load} ra, {2 * word}(sp)",
                f"addi sp, sp, {3 * word}",
                "ret",
                ".org 0x200",
                "syscall_gadget:",
                "ecall",
                "unimp",
            )
        )
    elif arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        load = "ld" if arch is Architecture.POWERPC64 else "lwz"
        lines.extend(_powerpc_load(target, 1, chain_address))
        lines.extend(
            (
                f"{load} 12, 0(1)",
                f"addi 1, 1, {word}",
                "mtctr 12",
                "bctr",
                ".org 0x100",
                "restore_gadget:",
                f"{load} 0, 0(1)",
                f"{load} 3, {word}(1)",
                f"{load} 12, {2 * word}(1)",
                f"addi 1, 1, {3 * word}",
                "mtctr 12",
                "bctr",
                ".org 0x200",
                "syscall_gadget:",
                "sc",
                "trap",
            )
        )
    elif arch in {Architecture.SPARC32, Architecture.SPARC64}:
        if arch is Architecture.SPARC64:
            biased_sp = chain_address - 2047
            lines.extend(
                (
                    f"setx 0x{biased_sp:x}, %g3, %sp",
                    "ldx [%sp + 2047], %g2",
                    "jmp %g2",
                    f"add %sp, {word}, %sp",
                    ".org 0x100",
                    "restore_gadget:",
                    "ldx [%sp + 2047], %g1",
                    f"ldx [%sp + {2047 + word}], %o0",
                    f"ldx [%sp + {2047 + 2 * word}], %g2",
                    "jmp %g2",
                    f"add %sp, {3 * word}, %sp",
                    ".org 0x200",
                    "syscall_gadget:",
                    "ta 0x6d",
                    "nop",
                )
            )
        else:
            lines.extend(
                (
                    f"set 0x{chain_address:x}, %sp",
                    "ld [%sp], %g2",
                    "jmp %g2",
                    f"add %sp, {word}, %sp",
                    ".org 0x100",
                    "restore_gadget:",
                    "ld [%sp], %g1",
                    f"ld [%sp + {word}], %o0",
                    f"ld [%sp + {2 * word}], %g2",
                    "jmp %g2",
                    f"add %sp, {3 * word}, %sp",
                    ".org 0x200",
                    "syscall_gadget:",
                    "ta 0x10",
                    "nop",
                )
            )
    elif arch is Architecture.S390X:
        lines.extend(_s390_load("r15", chain_address))
        lines.extend(
            (
                "lg %r14, 0(%r15)",
                f"aghi %r15, {word}",
                "br %r14",
                ".org 0x100",
                "restore_gadget:",
                "lg %r1, 0(%r15)",
                f"lg %r2, {word}(%r15)",
                f"lg %r14, {2 * word}(%r15)",
                f"aghi %r15, {3 * word}",
                "br %r14",
                ".org 0x200",
                "syscall_gadget:",
                "svc 0",
                "j .",
            )
        )
    else:  # pragma: no cover - caller restricts the matrix
        raise AssertionError(target.name)
    return _chain_placeholder(lines, chain_offset, chain_size), chain_offset


def _build_extra_syscall_fixture(case: _RopCase, directory: Path):
    target = _target(case)
    code = _extra_code_address(target, directory)
    number = {
        Architecture.MIPS32: 4001,
        Architecture.MIPS64: 5058,
        Architecture.RISCV32: 93,
        Architecture.RISCV64: 93,
    }.get(target.arch, 1)
    chain = build_static_syscall(
        target,
        code + 0x200,
        number,
        (43,),
        gadgets=(_extra_syscall_gadget(target, code),),
        label="exit syscall",
    )
    layout = RuntimeLayout(main_base=0)
    data = chain.materialize(layout)
    source, chain_offset = _extra_syscall_source(target, code, len(data))
    raw = _assemble_and_patch_chain(source, target, chain_offset, data)
    executable = directory / "syscall"
    _link_extra_fixture(raw, target, executable, code)
    return target, chain, executable, code + chain_offset


def _extra_call_gadget(target: Target, code: int) -> SemanticGadget:
    controls = {
        Architecture.MIPS32: "t9",
        Architecture.MIPS64: "t9",
        Architecture.RISCV32: "t0",
        Architecture.RISCV64: "t0",
        Architecture.POWERPC32: "r12",
        Architecture.POWERPC64: "r12",
        Architecture.S390X: "r8",
    }
    descriptions = {
        Architecture.MIPS32: "lw a0/ra/t9 from sp; advance sp; jr t9",
        Architecture.MIPS64: "ld a0/ra/t9 from sp; advance sp; jr t9",
        Architecture.RISCV32: "lw a0/ra/t0 from sp; advance sp; jr t0",
        Architecture.RISCV64: "ld a0/ra/t0 from sp; advance sp; jr t0",
        Architecture.POWERPC32: "lwz r3/r11/r12; mtlr r11; advance r1; bctr",
        Architecture.POWERPC64: "ld r3/r11/r12; mtlr r11; advance r1; bctr",
        Architecture.S390X: "lg r2/r14/r8; advance r15; br r8",
    }
    control = controls[target.arch]
    return SemanticGadget(
        target,
        Address(code + 0x100, Image.MAIN, "restore call frame"),
        3,
        {
            target.convention.function_arguments[0]: 0,
            target.convention.link_register: 1,
            control: 2,
        },
        2,
        descriptions[target.arch],
        next_pc_register=control,
    )


def _extra_call_source(
    target: Target,
    code: int,
    chain_address: int,
    chain_size: int,
    caller_area_size: int,
) -> tuple[str, int]:
    arch = target.arch
    word = target.word_size
    alignment = target.convention.stack_alignment
    chain_offset = chain_address - code
    lines: list[str] = []
    if target.abi is ABI.POWERPC64_ELFV2:
        lines.append(".abiversion 2")
    lines.extend((".text", ".globl _start", "_start:"))

    if arch in {Architecture.MIPS32, Architecture.MIPS64}:
        is_64 = arch is Architecture.MIPS64
        immediate = "dli" if is_64 else "li"
        load = "ld" if is_64 else "lw"
        add = "daddiu" if is_64 else "addiu"
        exit_number = 5058 if is_64 else 4001
        lines.extend(
            (
                ".set noreorder",
                f"{immediate} $sp, 0x{chain_address:x}",
                f"{load} $t9, 0($sp)",
                f"{add} $sp, $sp, {word}",
                "jr $t9",
                "nop",
                ".org 0x100",
                "restore_gadget:",
                f"{load} $a0, 0($sp)",
                f"{load} $ra, {word}($sp)",
                f"{load} $t9, {2 * word}($sp)",
                f"{add} $sp, $sp, {3 * word}",
                "jr $t9",
                "nop",
                ".org 0x200",
                "called_function:",
                f"andi $t0, $sp, {alignment - 1}",
                "bnez $t0, .Lbad",
                "nop",
            )
        )
        if caller_area_size:
            lines.extend(
                (
                    f"{immediate} $t1, 0x{_CALLER_MARKER:x}",
                    f"{load} $t0, 0($sp)",
                    "bne $t0, $t1, .Lbad",
                    "nop",
                    f"{load} $t0, {caller_area_size - word}($sp)",
                    "bne $t0, $t1, .Lbad",
                    "nop",
                )
            )
        lines.extend(
            (
                f"{add} $v0, $a0, 1",
                "jr $ra",
                "nop",
                ".Lbad:",
                f"{add} $v0, $zero, 99",
                "jr $ra",
                "nop",
                ".org 0x300",
                "return_handler:",
                "move $a0, $v0",
                f"{immediate} $v0, {exit_number}",
                "syscall",
                "nop",
            )
        )
    elif arch in {Architecture.RISCV32, Architecture.RISCV64}:
        load = "ld" if arch is Architecture.RISCV64 else "lw"
        lines.extend(
            (
                ".option norvc",
                f"li sp, 0x{chain_address:x}",
                f"{load} t0, 0(sp)",
                f"addi sp, sp, {word}",
                "jr t0",
                ".org 0x100",
                "restore_gadget:",
                f"{load} a0, 0(sp)",
                f"{load} ra, {word}(sp)",
                f"{load} t0, {2 * word}(sp)",
                f"addi sp, sp, {3 * word}",
                "jr t0",
                ".org 0x200",
                "called_function:",
                f"andi t1, sp, {alignment - 1}",
                "bnez t1, .Lbad",
                "addi a0, a0, 1",
                "ret",
                ".Lbad:",
                "li a0, 99",
                "ret",
                ".org 0x300",
                "return_handler:",
                "li a7, 93",
                "ecall",
                "unimp",
            )
        )
    elif arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        load = "ld" if arch is Architecture.POWERPC64 else "lwz"
        compare = "cmpd" if arch is Architecture.POWERPC64 else "cmpw"
        lines.extend(_powerpc_load(target, 1, chain_address))
        lines.extend(
            (
                f"{load} 12, 0(1)",
                f"addi 1, 1, {word}",
                "mtctr 12",
                "bctr",
                ".org 0x100",
                "restore_gadget:",
                f"{load} 3, 0(1)",
                f"{load} 11, {word}(1)",
                "mtlr 11",
                f"{load} 12, {2 * word}(1)",
                f"addi 1, 1, {3 * word}",
                "mtctr 12",
                "bctr",
                ".org 0x200",
                "called_function:",
                f"andi. 4, 1, {alignment - 1}",
                "bne .Lbad",
            )
        )
        if caller_area_size:
            lines.append(f"{load} 4, 0(1)")
            lines.extend(_powerpc_load(target, 5, _CALLER_MARKER))
            lines.extend(
                (
                    f"{compare} 4, 5",
                    "bne .Lbad",
                    f"{load} 4, {caller_area_size - word}(1)",
                    f"{compare} 4, 5",
                    "bne .Lbad",
                )
            )
        lines.extend(
            (
                "addi 3, 3, 1",
                "blr",
                ".Lbad:",
                "li 3, 99",
                "blr",
                ".org 0x300",
                "return_handler:",
                "li 0, 1",
                "sc",
                "trap",
            )
        )
    elif arch is Architecture.S390X:
        lines.extend(_s390_load("r15", chain_address))
        lines.extend(
            (
                "lg %r8, 0(%r15)",
                f"aghi %r15, {word}",
                "br %r8",
                ".org 0x100",
                "restore_gadget:",
                "lg %r2, 0(%r15)",
                f"lg %r14, {word}(%r15)",
                f"lg %r8, {2 * word}(%r15)",
                f"aghi %r15, {3 * word}",
                "br %r8",
                ".org 0x200",
                "called_function:",
                "lgr %r3, %r15",
                f"nill %r3, {alignment - 1}",
                "jne .Lbad",
            )
        )
        if caller_area_size:
            lines.extend(_s390_load("r4", _CALLER_MARKER))
            lines.extend(
                (
                    "lg %r3, 0(%r15)",
                    "cgr %r3, %r4",
                    "jne .Lbad",
                    f"lg %r3, {caller_area_size - word}(%r15)",
                    "cgr %r3, %r4",
                    "jne .Lbad",
                )
            )
        lines.extend(
            (
                "aghi %r2, 1",
                "br %r14",
                ".Lbad:",
                "lghi %r2, 99",
                "br %r14",
                ".org 0x300",
                "return_handler:",
                "lghi %r1, 1",
                "svc 0",
                "j .",
            )
        )
    else:  # pragma: no cover - caller restricts the matrix
        raise AssertionError(target.name)
    return _chain_placeholder(lines, chain_offset, chain_size), chain_offset


def _build_extra_call_fixture(case: _RopCase, directory: Path):
    target = _target(case)
    code = _extra_code_address(target, directory)
    chain = build_static_call(
        target,
        code + 0x200,
        (41,),
        gadgets=(_extra_call_gadget(target, code),),
        return_to=Address(code + 0x300, Image.MAIN, "exit return handler"),
        filler=_CALLER_MARKER,
        label="increment and return",
    )
    if chain.call_frame is None:  # pragma: no cover - builder invariant
        raise AssertionError("static call has no CallFrame")
    candidate = code + 0x500
    frame = chain.call_frame
    chain_address = candidate + ((frame.required_chain_base_remainder - candidate) % frame.entry_sp_alignment)
    entry_sp = chain.function_entry_sp(chain_address)
    layout = RuntimeLayout(main_base=0)
    data = chain.materialize(layout, chain_base=chain_address, entry_sp=entry_sp)
    source, chain_offset = _extra_call_source(
        target,
        code,
        chain_address,
        len(data),
        frame.caller_area_size,
    )
    raw = _assemble_and_patch_chain(source, target, chain_offset, data)
    executable = directory / "call"
    _link_extra_fixture(raw, target, executable, code)
    return target, chain, executable, chain_address, entry_sp


class RopQemuMatrixTests(unittest.TestCase):
    def test_static_and_ret2libc_execution_matrices_are_exact(self) -> None:
        ppc32le = resolve_target("powerpc32", endian="little").name
        runtime_targets = {target.name for target in SUPPORTED_TARGETS} - {ppc32le}
        syscall_targets = {_target(case).name for case in _STATIC_SYSCALL_CASES}
        self.assertEqual(syscall_targets, runtime_targets)
        self.assertEqual(len(syscall_targets), len(_STATIC_SYSCALL_CASES))

        direct_call_exclusions = {
            resolve_target("powerpc64", endian="big").name,
            resolve_target("sparc32").name,
            resolve_target("sparc64").name,
        }
        call_targets = {_target(case).name for case in _STATIC_CALL_CASES}
        self.assertEqual(call_targets, runtime_targets - direct_call_exclusions)
        self.assertEqual(len(call_targets), len(_STATIC_CALL_CASES))

        self.assertEqual(
            {_target(case).name for case in _RET2LIBC_CASES},
            {resolve_target("x86").name, resolve_target("x86_64").name},
        )


@unittest.skipUnless(
    os.environ.get("PWNC_QEMU_TESTS") == "1" and _STATIC_TOOLS_PRESENT and _STATIC_QEMU_PRESENT,
    "set PWNC_QEMU_TESTS=1 with LLVM/LLD and the complete QEMU user-emulator matrix installed",
)
class StaticRopQemuTests(unittest.TestCase):
    def test_static_syscall_and_call_chains_execute_on_primary_targets(self) -> None:
        for case in _PRIMARY_ROP_CASES:
            target = _target(case)
            with self.subTest(target=target.name), tempfile.TemporaryDirectory(prefix="pwnc-rop-") as directory:
                root = Path(directory)
                template = _assemble_static_fixture(target, root)
                symbols, image_base = _symbols_and_image_base(template)
                syscall, syscall_data, call, call_data = _primary_static_chains(target, symbols, image_base)
                profile = inspect_elf(template)
                chain_mapping = next(item for item in profile.load_ranges if item.contains(symbols["chain"], 512))

                self.assertEqual(syscall.kind, PayloadKind.ROP)
                self.assertEqual(call.validate_call_frame(symbols["chain"]), call.function_entry_sp(symbols["chain"]))
                self.assertTrue(chain_mapping.writable)
                self.assertFalse(chain_mapping.executable)

                syscall_executable = root / "syscall"
                call_executable = root / "call"
                _patch_virtual_address(template, syscall_executable, symbols["chain"], syscall_data)
                _patch_virtual_address(template, call_executable, symbols["chain"], call_data)

                syscall_run = subprocess.run(
                    [case.qemu, str(syscall_executable)], capture_output=True, timeout=10, check=False
                )
                call_run = subprocess.run(
                    [case.qemu, str(call_executable)], capture_output=True, timeout=10, check=False
                )
                self.assertEqual(syscall_run.returncode, 43, syscall_run.stderr.decode(errors="replace"))
                self.assertEqual(call_run.returncode, 42, call_run.stderr.decode(errors="replace"))

    def test_static_syscall_chains_execute_on_extra_targets(self) -> None:
        for case in _EXTRA_SYSCALL_CASES:
            with (
                self.subTest(architecture=case.architecture, endian=case.endian),
                tempfile.TemporaryDirectory(prefix="pwnc-rop-extra-") as directory,
            ):
                target, chain, executable, chain_address = _build_extra_syscall_fixture(case, Path(directory))
                profile = inspect_elf(executable)
                self.assertEqual(profile.target, target)
                self.assertEqual(chain.kind, PayloadKind.ROP)
                chain_mapping = next(
                    item for item in profile.load_ranges if item.contains(chain_address, chain.byte_length)
                )
                self.assertTrue(chain_mapping.readable)
                self.assertFalse(chain_mapping.writable)

                result = subprocess.run([case.qemu, str(executable)], capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 43, result.stderr.decode(errors="replace"))

    def test_static_call_chains_execute_on_extra_supported_targets(self) -> None:
        for case in _EXTRA_CALL_CASES:
            with (
                self.subTest(architecture=case.architecture, endian=case.endian),
                tempfile.TemporaryDirectory(prefix="pwnc-rop-call-") as directory,
            ):
                target, chain, executable, chain_address, entry_sp = _build_extra_call_fixture(case, Path(directory))
                self.assertEqual(chain.validate_call_frame(chain_address, entry_sp=entry_sp), entry_sp)
                assert chain.call_frame is not None
                caller_words = chain.call_frame.caller_area_size // target.word_size
                if caller_words:
                    resolved = chain.resolved_words(RuntimeLayout(main_base=0))
                    self.assertEqual(resolved[-caller_words:], (_CALLER_MARKER,) * caller_words)

                result = subprocess.run([case.qemu, str(executable)], capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 42, result.stderr.decode(errors="replace"))


_RET2LIBC_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((aligned(4096))) unsigned char pwnc_chain[0x100000];
const char pwnc_command[] = "printf PWNC_RET2LIBC_OK";

extern void pwnc_pivot(void *chain) __attribute__((noreturn));

int main(void) {
    void *libc_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *system_address = libc_handle == NULL ? NULL : dlsym(libc_handle, "system");
    Dl_info info;
    if (system_address == NULL || dladdr(system_address, &info) == 0) {
        return 100;
    }
    void *chain_base = pwnc_chain + 0xF0000 + (sizeof(void *) == 4 ? 8 : 0);
    printf("%s\t%p\t%p\t%p\n", info.dli_fname, system_address, info.dli_fbase, chain_base);
    fflush(stdout);
    unsigned char *cursor = chain_base;
    size_t remaining = 256;
    while (remaining != 0) {
        ssize_t count = read(STDIN_FILENO, cursor, remaining);
        if (count <= 0) {
            return 101;
        }
        cursor += count;
        remaining -= (size_t)count;
    }
    pwnc_pivot(chain_base);
}

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl pwnc_pop_rdi_ret\n"
    ".type pwnc_pop_rdi_ret,@function\n"
    "pwnc_pop_rdi_ret:\n"
    "pop %rdi\n"
    "ret\n"
    ".globl pwnc_pivot\n"
    ".type pwnc_pivot,@function\n"
    "pwnc_pivot:\n"
    "mov %rdi, %rsp\n"
    "ret\n"
    ".globl pwnc_success\n"
    ".type pwnc_success,@function\n"
    "pwnc_success:\n"
    "mov $42, %edi\n"
    "mov $60, %eax\n"
    "syscall\n"
    "ud2\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
);
#elif defined(__i386__)
__asm__(
    ".text\n"
    ".globl pwnc_pivot\n"
    ".type pwnc_pivot,@function\n"
    "pwnc_pivot:\n"
    "mov 4(%esp), %eax\n"
    "mov %eax, %esp\n"
    "ret\n"
    ".globl pwnc_success\n"
    ".type pwnc_success,@function\n"
    "pwnc_success:\n"
    "mov $42, %ebx\n"
    "mov $1, %eax\n"
    "int $0x80\n"
    "ud2\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
);
#endif
"""

_RET2LIBC_CASES = (
    _RopCase("x86", None, "qemu-i386"),
    _RopCase("x86_64", None, "qemu-x86_64"),
)
_RET2LIBC_TOOLS_PRESENT = shutil.which("cc") is not None and all(shutil.which(case.qemu) for case in _RET2LIBC_CASES)


def _compile_ret2libc_fixture(case: _RopCase, directory: Path) -> Path:
    source = directory / "fixture.c"
    executable = directory / "fixture"
    source.write_text(_RET2LIBC_SOURCE)
    target = _target(case)
    command = [
        "cc",
        f"-m{target.bits}",
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
        str(executable),
        str(source),
        "-ldl",
    ]
    compiled = subprocess.run(command, capture_output=True, text=True, check=False)
    if compiled.returncode:
        dependency_markers = (
            "cannot find",
            "No such file or directory",
            "bits/libc-header-start.h",
            "skipping incompatible",
        )
        if any(marker in compiled.stderr for marker in dependency_markers):
            raise unittest.SkipTest(f"{target.bits}-bit compiler/runtime support is unavailable: {compiled.stderr}")
        raise AssertionError(f"ret2libc fixture compilation failed:\n{compiled.stdout}\n{compiled.stderr}")
    return executable


def _read_process_line(process: subprocess.Popen[bytes], timeout: int = 10) -> bytes:
    assert process.stdout is not None
    ready, _, _ = select.select((process.stdout,), (), (), timeout)
    if not ready:
        raise AssertionError("timed out waiting for the ret2libc fixture leak")
    line = process.stdout.readline()
    if not line:
        stderr = process.stderr.read().decode(errors="replace") if process.stderr is not None else ""
        raise AssertionError(f"ret2libc fixture exited before disclosing libc: {stderr}")
    return line.rstrip(b"\n")


@unittest.skipUnless(
    os.environ.get("PWNC_QEMU_TESTS") == "1" and sys.platform.startswith("linux") and _RET2LIBC_TOOLS_PRESENT,
    "set PWNC_QEMU_TESTS=1 on Linux with cc and x86 QEMU user emulators installed",
)
class Ret2libcQemuTests(unittest.TestCase):
    def test_exact_loaded_libc_system_chain_executes_from_live_base(self) -> None:
        for case in _RET2LIBC_CASES:
            target = _target(case)
            with self.subTest(target=target.name), tempfile.TemporaryDirectory(prefix="pwnc-ret2libc-") as directory:
                executable = _compile_ret2libc_fixture(case, Path(directory))
                profile = inspect_elf(executable)
                self.assertEqual(profile.target, target)
                self.assertFalse(profile.pie)
                self.assertIs(profile.linkage, Linkage.DYNAMIC)
                self.assertTrue(profile.nx)

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
                process = subprocess.Popen(
                    [case.qemu, "-L", "/", str(executable)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                )
                try:
                    libc_path_bytes, leaked_bytes, owner_base_bytes, chain_base_bytes = _read_process_line(
                        process
                    ).split(b"\t")
                    libc_path = Path(os.fsdecode(libc_path_bytes)).resolve()
                    leaked_system = int(leaked_bytes, 16)
                    owner_base = int(owner_base_bytes, 16)
                    disclosed_chain_base = int(chain_base_bytes, 16)
                    libc = LibcImage.from_file(libc_path, symbols=("system",))
                    self.assertEqual(libc.target, target)
                    self.assertEqual(inspect_elf(libc_path).soname, "libc.so.6")
                    libc_base = libc.base_from_leak("system", leaked_system)
                    self.assertEqual(libc_base, owner_base)
                    self.assertEqual(libc_base + libc.offset("system"), leaked_system)
                    self.assertEqual(libc_base % 0x1000, 0)

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
                    chain_base = profile.symbol_offsets["pwnc_chain"] + 0xF0000 + (8 if target.bits == 32 else 0)
                    self.assertEqual(disclosed_chain_base, chain_base)
                    chain_mapping = next(item for item in profile.load_ranges if item.contains(chain_base, 256))
                    self.assertTrue(chain_mapping.writable)
                    self.assertFalse(chain_mapping.executable)
                    layout = RuntimeLayout(main_base=0, libc_base=libc_base)
                    chain_data = chain.materialize(layout, chain_base=chain_base)
                    self.assertEqual(chain.kind, PayloadKind.RET2LIBC)
                    libc_words = [word for word in chain.words if isinstance(word.value, LibcBoundAddress)]
                    self.assertEqual(len(libc_words), 1)
                    self.assertEqual(libc_words[0].resolve(target, layout), leaked_system)
                    self.assertLessEqual(len(chain_data), 256)
                    chain_data += bytes(256 - len(chain_data))

                    stdout, stderr = process.communicate(chain_data, timeout=10)
                    self.assertEqual(process.returncode, 42, stderr.decode(errors="replace"))
                    self.assertEqual(stdout, b"PWNC_RET2LIBC_OK")
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    unittest.main()
