"""Opt-in ROP execution in binaries linked to every pinned static glibc.

Enable with either ``PWNC_GLIBC_QEMU_TESTS=1`` (the complete pinned-glibc
contract) or the focused ``PWNC_GLIBC_STATIC_ROP_TESTS=1`` switch.  The
persistent sysroot cache and optional manifest selector are shared with
:mod:`test_glibc_qemu` through ``PWNC_GLIBC_SYSROOT_CACHE`` and
``PWNC_GLIBC_QEMU_SPECS``.  With no selector, every manifest spec and every
mapped catalog target is mandatory: unavailable compilers, unsupported static
linking, and missing qemu-user binaries are test failures rather than skips.

Each target is compiled as a real static C program.  A GNU ld map proves that
the selected provisioned sysroot's exact ``libc.a`` supplied the program, and
the guest reports ``gnu_get_libc_version()`` before accepting a target-endian
ROP protocol.  Test-owned restore and pivot gadgets make the exploit primitive
explicit while :func:`build_static_syscall` and :func:`build_static_call`
produce the bytes which actually execute under qemu-user.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import select
import shutil
import struct
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
    ExactELFAdapter,
    Image,
    Linkage,
    RuntimeLayout,
    SemanticGadget,
    Target,
    UnsupportedROPError,
    build_static_call,
    build_static_syscall,
    inspect_elf,
)
from payloads.tests.runtime_support import ProvisionedSysroot, SysrootSpec, load_manifest, provision_sysroot

_OPT_IN = os.environ.get("PWNC_GLIBC_QEMU_TESTS") == "1" or os.environ.get("PWNC_GLIBC_STATIC_ROP_TESTS") == "1"
_CACHE_ENV = "PWNC_GLIBC_SYSROOT_CACHE"
_SELECTOR_ENV = "PWNC_GLIBC_QEMU_SPECS"
_DEFAULT_CACHE = Path(tempfile.gettempdir()) / "pwnc-runtime-sysroot-cache"
_CHAIN_CAPACITY = 0x10000
_TARGETS_BY_NAME = {target.name: target for target in SUPPORTED_TARGETS}
_LIBC_ARCHIVE_PATTERN = re.compile(r"(?m)^\s*(\S*libc\.a)\(")
_EXIT_DEFINITION_PATTERN = re.compile(r"(?P<archive>/\S*libc\.a)\((?P<member>[^)]+)\): definition of exit")
_NATIVE_X86_HOST = platform.machine().lower() in {"amd64", "x86_64"}
_XENIAL_SPEC_ID = "amd64-xenial-glibc-2.23"
_XENIAL_STATIC_COMPILER_SPEC_ID = "x86-64-glibc-2.24"


_FIXTURE_C = r"""
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PWNC_CHAIN_CAPACITY 0x10000u

__attribute__((aligned(4096))) unsigned char pwnc_chain[PWNC_CHAIN_CAPACITY];
extern void pwnc_pivot(void *chain) __attribute__((noreturn));
static void (*volatile pwnc_exit_keepalive)(int) __attribute__((used)) = exit;

static int read_exact(int fd, void *buffer, size_t size) {
    unsigned char *cursor = buffer;
    while (size != 0) {
        ssize_t count = read(fd, cursor, size);
        if (count > 0) {
            cursor += (size_t) count;
            size -= (size_t) count;
        } else {
            return -1;
        }
    }
    return 0;
}

int main(void) {
    const char *version = gnu_get_libc_version();
    uint32_t control[2];

    if (write(STDOUT_FILENO, version, strlen(version)) < 0 ||
        write(STDOUT_FILENO, "\n", 1) != 1)
        return 100;
    if (read_exact(STDIN_FILENO, control, sizeof(control)) != 0)
        return 101;
    if (control[0] > PWNC_CHAIN_CAPACITY ||
        control[1] == 0 ||
        control[1] > PWNC_CHAIN_CAPACITY - control[0])
        return 102;
    if (read_exact(STDIN_FILENO, pwnc_chain + control[0], control[1]) != 0)
        return 103;

    /* A runtime-dependent reference keeps real static glibc exit in the ELF. */
    if (control[0] == UINT32_MAX)
        pwnc_exit_keepalive(104);
    pwnc_pivot(pwnc_chain + control[0]);
}
"""


def _cache_dir() -> Path:
    return Path(os.environ.get(_CACHE_ENV, _DEFAULT_CACHE)).expanduser().resolve()


def _selected_specs() -> tuple[SysrootSpec, ...]:
    specs = load_manifest().sysroots
    raw = os.environ.get(_SELECTOR_ENV, "").strip()
    if not raw:
        return specs
    requested = tuple(item.strip() for item in raw.split(",") if item.strip())
    if not requested:
        raise AssertionError(f"{_SELECTOR_ENV} contains no manifest IDs")
    known = {spec.id: spec for spec in specs}
    unknown = sorted(set(requested).difference(known))
    if unknown:
        raise AssertionError(f"{_SELECTOR_ENV} contains unknown manifest IDs: {', '.join(unknown)}")
    return tuple(known[item] for item in requested)


def _environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "CC",
        "CFLAGS",
        "C_INCLUDE_PATH",
        "COMPILER_PATH",
        "CPATH",
        "GCC_EXEC_PREFIX",
        "LDFLAGS",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LIBRARY_PATH",
        "QEMU_LD_PREFIX",
        "QEMU_SET_ENV",
        "QEMU_UNSET_ENV",
    ):
        environment.pop(name, None)
    return environment


@dataclass(frozen=True, slots=True)
class _StaticCompilerInvocation:
    argv: tuple[str, ...]
    owner_spec_id: str
    invoked_driver: Path
    resolved_driver: Path
    driver_sha256: str
    borrowed: bool

    def revalidate(self) -> None:
        if self.invoked_driver.resolve(strict=True) != self.resolved_driver:
            raise AssertionError(f"static compiler driver target changed: {self.invoked_driver}")
        observed = hashlib.sha256(self.resolved_driver.read_bytes()).hexdigest()
        if observed != self.driver_sha256:
            raise AssertionError(f"static compiler driver bytes changed: {self.resolved_driver}")


def _driver_argument(argv: tuple[str, ...]) -> Path:
    if not argv:
        raise AssertionError("static compiler argv is empty")
    if argv[0] != "/usr/bin/env":
        return Path(argv[0])
    for argument in argv[1:]:
        if "=" not in argument:
            return Path(argument)
    raise AssertionError("/usr/bin/env static compiler argv contains no driver")


def _compiler_invocation(
    argv: tuple[str, ...],
    *,
    owner_spec_id: str,
    borrowed: bool,
) -> _StaticCompilerInvocation:
    driver = _driver_argument(argv)
    resolved = driver.resolve(strict=True)
    return _StaticCompilerInvocation(
        argv,
        owner_spec_id,
        driver,
        resolved,
        hashlib.sha256(resolved.read_bytes()).hexdigest(),
        borrowed,
    )


def _xenial_static_compiler_invocation(
    provisioned: ProvisionedSysroot,
    donor: ProvisionedSysroot,
) -> _StaticCompilerInvocation:
    if provisioned.spec.id != _XENIAL_SPEC_ID:
        raise AssertionError("Xenial static compiler fallback was requested for the wrong sysroot")
    if donor.spec.id != _XENIAL_STATIC_COMPILER_SPEC_ID:
        raise AssertionError("Xenial static compiler fallback has the wrong pinned donor")
    donor_argv = donor.compiler_argv
    if len(donor_argv) != 1:
        raise AssertionError("pinned Bootlin public compiler wrapper has unexpected arguments")
    driver = Path(donor_argv[0])
    if driver.name != "x86_64-linux-gcc" or ".br_real" in driver.name:
        raise AssertionError(f"Xenial fallback must invoke the public Bootlin wrapper: {driver}")
    include = provisioned.sysroot / "usr/include/x86_64-linux-gnu"
    library = provisioned.sysroot / "usr/lib/x86_64-linux-gnu"
    if not include.is_dir() or not library.is_dir():
        raise AssertionError("Xenial multiarch static compiler paths are missing")
    argv = (
        str(driver),
        f"--sysroot={provisioned.sysroot}",
        "-isystem",
        str(include),
        f"-B{library}/",
        f"-L{library}",
    )
    return _compiler_invocation(argv, owner_spec_id=donor.spec.id, borrowed=True)


def _static_compiler_invocation(
    provisioned: ProvisionedSysroot,
    cache_dir: Path,
) -> _StaticCompilerInvocation:
    if provisioned.spec.id != _XENIAL_SPEC_ID:
        return _compiler_invocation(
            provisioned.compiler_argv,
            owner_spec_id=provisioned.spec.id,
            borrowed=False,
        )
    try:
        donor_spec = next(spec for spec in load_manifest().sysroots if spec.id == _XENIAL_STATIC_COMPILER_SPEC_ID)
    except StopIteration as exc:  # guarded by the exact matrix unit test
        raise AssertionError("pinned Xenial static compiler donor is absent") from exc
    donor = provision_sysroot(donor_spec, cache_dir)
    return _xenial_static_compiler_invocation(provisioned, donor)


def _catalog_target(name: str) -> Target:
    try:
        return _TARGETS_BY_NAME[name]
    except KeyError as exc:  # guarded by manifest parsing
        raise AssertionError(f"manifest contains unknown target {name!r}") from exc


def _target_key(target: Target) -> tuple[object, ...]:
    return (target.bits, target.endian, target.abi, target.function_pointer_model)


def _assert_compiled_target(test: unittest.TestCase, observed: Target, intended: Target) -> None:
    if intended.arch is Architecture.THUMB:
        test.assertIs(observed.arch, Architecture.ARM)
        test.assertEqual((observed.bits, observed.endian, observed.abi), (32, intended.endian, intended.abi))
    else:
        test.assertEqual(_target_key(observed), _target_key(intended))


def _word_instruction(target: Target) -> tuple[str, str]:
    if target.bits == 64:
        return "ld", "daddiu"
    return "lw", "addiu"


def _fixture_assembly(target: Target) -> str:
    """Return exact test-owned pivot, restore, and syscall gadgets."""

    arch = target.arch
    word = target.word_size
    note = '\n.section .note.GNU-stack,"",@progbits\n'

    if arch is Architecture.X86:
        return (
            """
.text
.globl pwnc_pivot
.type pwnc_pivot,@function
pwnc_pivot:
  mov 4(%esp), %eax
  mov %eax, %esp
  ret
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  pop %eax
  pop %ebx
  ret
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  int $0x80
  ud2
"""
            + note
        )

    if arch is Architecture.X86_64:
        return (
            """
.text
.globl pwnc_pivot
.type pwnc_pivot,@function
pwnc_pivot:
  mov %rdi, %rsp
  ret
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  pop %rax
  pop %rdi
  ret
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  syscall
  ud2
.globl pwnc_call_loader
pwnc_call_loader:
  pop %rdi
  ret
"""
            + note
        )

    if arch in {Architecture.ARM, Architecture.THUMB}:
        mode = ".thumb" if arch is Architecture.THUMB else ".arm"
        thumb = ".thumb_func\n" if arch is Architecture.THUMB else ""
        arm_note = '\n.section .note.GNU-stack,"",%progbits\n'
        return f"""
.syntax unified
.arch armv7-a
{mode}
.text
.globl pwnc_pivot
.type pwnc_pivot,%function
{thumb}pwnc_pivot:
  mov sp, r0
  pop {{pc}}
.globl pwnc_syscall_loader
{thumb}pwnc_syscall_loader:
  pop {{r0, r7, pc}}
.globl pwnc_syscall_terminal
{thumb}pwnc_syscall_terminal:
  svc #0
  udf #0
.globl pwnc_call_loader
{thumb}pwnc_call_loader:
  pop {{r0, r3}}
  mov lr, r3
  pop {{pc}}
{arm_note}
"""

    if arch is Architecture.ARM64:
        return (
            """
.text
.globl pwnc_pivot
.type pwnc_pivot,%function
pwnc_pivot:
  mov sp, x0
  ldr x16, [sp], #8
  br x16
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  ldp x0, x8, [sp], #16
  ldr x16, [sp], #8
  br x16
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  svc #0
  brk #0
.globl pwnc_call_loader
pwnc_call_loader:
  ldp x0, x30, [sp], #16
  ldr x16, [sp], #8
  br x16
"""
            + note
        )

    if arch in {Architecture.MIPS32, Architecture.MIPS64}:
        load, add = _word_instruction(target)
        return f"""
.set noreorder
.set nomips16
.text
.globl pwnc_pivot
.type pwnc_pivot,@function
pwnc_pivot:
  move $sp, $a0
  {load} $t9, 0($sp)
  {add} $sp, $sp, {word}
  jr $t9
  nop
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  {load} $v0, 0($sp)
  {load} $a0, {word}($sp)
  {load} $t9, {2 * word}($sp)
  {add} $sp, $sp, {3 * word}
  jr $t9
  nop
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  syscall
  break
.globl pwnc_call_loader
pwnc_call_loader:
  {load} $a0, 0($sp)
  {load} $ra, {word}($sp)
  {load} $t9, {2 * word}($sp)
  {add} $sp, $sp, {3 * word}
  jr $t9
  nop
{note}
"""

    if arch in {Architecture.RISCV32, Architecture.RISCV64}:
        load = "ld" if arch is Architecture.RISCV64 else "lw"
        return f"""
.option norvc
.text
.globl pwnc_pivot
.type pwnc_pivot,@function
pwnc_pivot:
  mv sp, a0
  {load} t0, 0(sp)
  addi sp, sp, {word}
  jr t0
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  {load} a7, 0(sp)
  {load} a0, {word}(sp)
  {load} t0, {2 * word}(sp)
  addi sp, sp, {3 * word}
  jr t0
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  ecall
  unimp
.globl pwnc_call_loader
pwnc_call_loader:
  {load} a0, 0(sp)
  {load} ra, {word}(sp)
  {load} t0, {2 * word}(sp)
  addi sp, sp, {3 * word}
  jr t0
{note}
"""

    if arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        load = "ld" if arch is Architecture.POWERPC64 else "lwz"
        version = ""
        pivot = """
.globl pwnc_pivot
.type pwnc_pivot,@function
pwnc_pivot:
"""
        if target.abi is ABI.POWERPC64_ELFV1:
            version = ".abiversion 1\n"
            pivot = """
.section ".opd","aw"
.align 3
.globl pwnc_pivot
.type pwnc_pivot,@function
pwnc_pivot:
  .quad .pwnc_pivot, .TOC.@tocbase, 0
.size pwnc_pivot, 24
.previous
.pwnc_pivot:
"""
        elif target.abi is ABI.POWERPC64_ELFV2:
            version = ".abiversion 2\n"
        return f"""
{version}.text
{pivot}
  mr 1, 3
  {load} 12, 0(1)
  addi 1, 1, {word}
  mtctr 12
  bctr
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  {load} 0, 0(1)
  {load} 3, {word}(1)
  {load} 12, {2 * word}(1)
  addi 1, 1, {3 * word}
  mtctr 12
  bctr
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  sc
  trap
.globl pwnc_call_loader
pwnc_call_loader:
  {load} 3, 0(1)
  {load} 11, {word}(1)
  mtlr 11
  {load} 12, {2 * word}(1)
  addi 1, 1, {3 * word}
  mtctr 12
  bctr
{note}
"""

    if arch in {Architecture.SPARC32, Architecture.SPARC64}:
        if arch is Architecture.SPARC64:
            return f"""
.register %g2, #scratch
.text
.globl pwnc_pivot
.type pwnc_pivot,#function
pwnc_pivot:
  sub %o0, 2047, %sp
  ldx [%sp + 2047], %g2
  jmp %g2
  add %sp, {word}, %sp
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  ldx [%sp + 2047], %g1
  ldx [%sp + {2047 + word}], %o0
  ldx [%sp + {2047 + 2 * word}], %g2
  jmp %g2
  add %sp, {3 * word}, %sp
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  ta 0x6d
  nop
{note}
"""
        return f"""
.text
.globl pwnc_pivot
.type pwnc_pivot,#function
pwnc_pivot:
  mov %o0, %sp
  ld [%sp], %g2
  jmp %g2
  add %sp, {word}, %sp
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  ld [%sp], %g1
  ld [%sp + {word}], %o0
  ld [%sp + {2 * word}], %g2
  jmp %g2
  add %sp, {3 * word}, %sp
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  ta 0x10
  nop
{note}
"""

    if arch is Architecture.S390X:
        return f"""
.text
.globl pwnc_pivot
.type pwnc_pivot,@function
pwnc_pivot:
  lgr %r15, %r2
  lg %r8, 0(%r15)
  aghi %r15, {word}
  br %r8
.globl pwnc_syscall_loader
pwnc_syscall_loader:
  lg %r1, 0(%r15)
  lg %r2, {word}(%r15)
  lg %r8, {2 * word}(%r15)
  aghi %r15, {3 * word}
  br %r8
.globl pwnc_syscall_terminal
pwnc_syscall_terminal:
  svc 0
  j .
.globl pwnc_call_loader
pwnc_call_loader:
  lg %r2, 0(%r15)
  lg %r14, {word}(%r15)
  lg %r8, {2 * word}(%r15)
  aghi %r15, {3 * word}
  br %r8
{note}
"""

    raise AssertionError(f"no static glibc ROP fixture for {target.name}")


def _compile_fixture(
    provisioned: ProvisionedSysroot,
    target: Target,
    directory: Path,
    cache_dir: Path,
) -> tuple[Path, Path, str, _StaticCompilerInvocation]:
    source = directory / "fixture.c"
    assembly = directory / "gadgets.S"
    executable = directory / "fixture"
    linker_map = directory / "fixture.map"
    source.write_text(_FIXTURE_C, encoding="utf-8")
    assembly.write_text(_fixture_assembly(target), encoding="utf-8")
    target_flags = ("-mthumb",) if target.arch is Architecture.THUMB else ()
    compiler = _static_compiler_invocation(provisioned, cache_dir)
    command = (
        *compiler.argv,
        *target_flags,
        str(source),
        str(assembly),
        "-std=gnu11",
        "-O0",
        "-fno-pie",
        "-fno-stack-protector",
        "-Wl,-z,noexecstack",
        "-static",
        "-Wl,--trace-symbol=exit",
        f"-Wl,-Map,{linker_map}",
        "-o",
        str(executable),
    )
    compiled = subprocess.run(command, capture_output=True, text=True, check=False, env=_environment())
    if compiled.returncode:
        raise AssertionError(
            f"{provisioned.spec.id}/{target.name} static fixture compilation failed "
            f"with status {compiled.returncode}:\n{compiled.stdout}\n{compiled.stderr}"
        )
    if not linker_map.is_file():
        raise AssertionError(f"{provisioned.spec.id}/{target.name} compiler produced no GNU ld map")
    compiler.revalidate()
    return executable, linker_map, compiled.stdout + compiled.stderr, compiler


def _mapped_libc_archive(linker_map: Path, provisioned: ProvisionedSysroot) -> tuple[Path, str]:
    text = linker_map.read_text(encoding="utf-8", errors="replace")
    names = _LIBC_ARCHIVE_PATTERN.findall(text)
    if not names:
        raise AssertionError(f"{provisioned.spec.id}: linker map contains no libc.a archive members")
    resolved: set[Path] = set()
    for name in names:
        path = Path(name)
        if not path.is_absolute():
            path = linker_map.parent / path
        resolved.add(path.resolve(strict=True))
    if len(resolved) != 1:
        raise AssertionError(f"{provisioned.spec.id}: linker map selected multiple libc.a archives: {resolved}")
    archive = resolved.pop()
    try:
        archive.relative_to(provisioned.sysroot.resolve(strict=True))
    except ValueError as exc:
        raise AssertionError(f"{provisioned.spec.id}: mapped libc.a escaped the selected sysroot: {archive}") from exc
    if not os.path.samefile(archive, provisioned.static_libc):
        raise AssertionError(
            f"{provisioned.spec.id}: mapped libc.a {archive} is not the manifest-selected "
            f"archive {provisioned.static_libc}"
        )
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if len(digest) != 64:  # pragma: no cover - hashlib invariant
        raise AssertionError("invalid libc.a SHA-256")
    return archive, digest


def _assert_exit_definition_trace(trace: str, archive: Path, provisioned: ProvisionedSysroot) -> None:
    definitions = tuple(_EXIT_DEFINITION_PATTERN.finditer(trace))
    if len(definitions) != 1:
        raise AssertionError(
            f"{provisioned.spec.id}: expected one traced static libc definition of exit, found {len(definitions)}:\n"
            f"{trace}"
        )
    definition = definitions[0]
    traced_archive = Path(definition.group("archive")).resolve(strict=True)
    if traced_archive != archive:
        raise AssertionError(f"{provisioned.spec.id}: exit came from {traced_archive}, not mapped archive {archive}")
    if not definition.group("member"):
        raise AssertionError(f"{provisioned.spec.id}: traced exit definition has no archive member")


def _symbol(profile, name: str) -> int:
    try:
        return profile.symbol_offsets[name]
    except KeyError as exc:
        raise AssertionError(f"static fixture has no {name!r} symbol") from exc


def _main_address(profile, name: str) -> Address:
    return Address(_symbol(profile, name), Image.MAIN, name)


def _syscall_number(target: Target) -> int:
    if target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        return 4001 if target.arch is Architecture.MIPS32 else 5058
    if target.arch in {Architecture.ARM64, Architecture.RISCV32, Architecture.RISCV64}:
        return 93
    if target.arch is Architecture.X86_64:
        return 60
    return 1


def _syscall_restore_gadget(target: Target, profile) -> SemanticGadget:
    registers: dict[Architecture, tuple[dict[str, int], str | None]] = {
        Architecture.X86: ({"eax": 0, "ebx": 1}, None),
        Architecture.X86_64: ({"rax": 0, "rdi": 1}, None),
        Architecture.ARM: ({"r0": 0, "r7": 1}, None),
        Architecture.THUMB: ({"r0": 0, "r7": 1}, None),
        Architecture.ARM64: ({"x0": 0, "x8": 1, "x16": 2}, "x16"),
        Architecture.MIPS32: ({"v0": 0, "a0": 1, "t9": 2}, "t9"),
        Architecture.MIPS64: ({"v0": 0, "a0": 1, "t9": 2}, "t9"),
        Architecture.RISCV32: ({"a7": 0, "a0": 1, "t0": 2}, "t0"),
        Architecture.RISCV64: ({"a7": 0, "a0": 1, "t0": 2}, "t0"),
        Architecture.POWERPC32: ({"r0": 0, "r3": 1, "r12": 2}, "r12"),
        Architecture.POWERPC64: ({"r0": 0, "r3": 1, "r12": 2}, "r12"),
        Architecture.SPARC32: ({"g1": 0, "o0": 1, "g2": 2}, "g2"),
        Architecture.SPARC64: ({"g1": 0, "o0": 1, "g2": 2}, "g2"),
        Architecture.S390X: ({"r1": 0, "r2": 1, "r8": 2}, "r8"),
    }
    slots, control = registers[target.arch]
    return SemanticGadget(
        target,
        _main_address(profile, "pwnc_syscall_loader"),
        3,
        slots,
        2,
        "fixture restore syscall number, arg0, and continuation",
        next_pc_register=control,
    )


def _direct_call_supported(target: Target) -> bool:
    return (
        target.arch is not Architecture.THUMB
        and target.abi is not ABI.POWERPC64_ELFV1
        and target.arch
        not in {
            Architecture.SPARC32,
            Architecture.SPARC64,
        }
    )


def _call_restore_gadgets(target: Target, profile) -> tuple[SemanticGadget, ...]:
    if target.arch is Architecture.X86:
        return ()
    if target.arch is Architecture.X86_64:
        gadget = SemanticGadget(
            target,
            _main_address(profile, "pwnc_call_loader"),
            2,
            {"rdi": 0},
            1,
            "fixture pop rdi; ret",
        )
    elif target.arch in {Architecture.ARM, Architecture.THUMB}:
        gadget = SemanticGadget(
            target,
            _main_address(profile, "pwnc_call_loader"),
            3,
            {"r0": 0, "lr": 1},
            2,
            "fixture restore r0/lr/pc",
        )
    else:
        controls = {
            Architecture.ARM64: ("x0", "x30", "x16"),
            Architecture.MIPS32: ("a0", "ra", "t9"),
            Architecture.MIPS64: ("a0", "ra", "t9"),
            Architecture.RISCV32: ("a0", "ra", "t0"),
            Architecture.RISCV64: ("a0", "ra", "t0"),
            Architecture.POWERPC32: ("r3", "lr", "r12"),
            Architecture.POWERPC64: ("r3", "lr", "r12"),
            Architecture.S390X: ("r2", "r14", "r8"),
        }
        argument, link, control = controls[target.arch]
        # The PPC assembly restores LR through r11 before branching through
        # r12; the semantic destination is nevertheless the ABI link register.
        link_slot_name = "r11" if target.arch in {Architecture.POWERPC32, Architecture.POWERPC64} else link
        gadget = SemanticGadget(
            target,
            _main_address(profile, "pwnc_call_loader"),
            3,
            {argument: 0, link: 1, control: 2},
            2,
            f"fixture restore {argument}/{link_slot_name}/{control} and branch",
            next_pc_register=control,
        )
    return (gadget,)


def _aligned_chain_offset(chain, chain_symbol: int) -> int:
    if chain.call_frame is None:
        return 0
    alignment = chain.call_frame.entry_sp_alignment
    required = chain.call_frame.required_chain_base_remainder
    return (required - chain_symbol) % alignment


def _protocol(target: Target, offset: int, chain: bytes) -> bytes:
    endian = "<" if target.endian.value == "little" else ">"
    return struct.pack(f"{endian}II", offset, len(chain)) + chain


def _read_version_line(process: subprocess.Popen[bytes], label: str) -> bytes:
    assert process.stdout is not None
    ready, _, _ = select.select((process.stdout,), (), (), 30)
    if not ready:
        raise AssertionError(f"timed out waiting for {label} glibc version")
    line = process.stdout.readline()
    if not line:
        stderr = process.stderr.read().decode(errors="replace") if process.stderr is not None else ""
        raise AssertionError(f"{label} exited before its glibc version: {stderr}")
    return line.rstrip(b"\n")


def _run_chain(
    test: unittest.TestCase,
    provisioned: ProvisionedSysroot,
    target: Target,
    executable: Path,
    chain: bytes,
    offset: int,
    expected_status: int,
    *,
    argv: tuple[str, ...] | None = None,
    runner: str = "qemu-user",
) -> None:
    if argv is None:
        qemu = shutil.which(provisioned.qemu)
        if qemu is None:
            raise AssertionError(f"required qemu-user binary is unavailable: {provisioned.qemu}")
        argv = (qemu, str(executable))
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_environment(),
    )
    try:
        expected_version = provisioned.spec.glibc_version.split("-", 1)[0].encode("ascii")
        test.assertEqual(_read_version_line(process, f"{provisioned.spec.id} {runner}"), expected_version)
        stdout, stderr = process.communicate(_protocol(target, offset, chain), timeout=30)
        test.assertEqual(process.returncode, expected_status, stderr.decode(errors="replace"))
        test.assertEqual(stdout, b"")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


class GlibcStaticRopHarnessUnitTests(unittest.TestCase):
    def test_manifest_and_direct_call_exclusions_are_exact(self) -> None:
        manifest = load_manifest()
        mappings = tuple((spec, _catalog_target(name)) for spec in manifest.sysroots for name in spec.targets)
        self.assertEqual(len(manifest.sysroots), 33)
        self.assertEqual(len(mappings), 37)

        excluded_targets = {target.name for _spec, target in mappings if not _direct_call_supported(target)}
        self.assertEqual(
            excluded_targets,
            {
                "thumb-le-arm-eabi",
                "thumb-be-arm-eabi",
                "powerpc64-be-powerpc64-elfv1",
                "sparc32-be-sparc-sysv",
                "sparc64-be-sparc64-sysv",
            },
        )
        self.assertEqual(sum(_direct_call_supported(target) for _spec, target in mappings), 28)
        self.assertEqual(sum(not _direct_call_supported(target) for _spec, target in mappings), 9)

        for spec, target in mappings:
            with self.subTest(spec=spec.id, target=target.name):
                assembly = _fixture_assembly(target)
                self.assertIn("pwnc_pivot", assembly)
                self.assertIn("pwnc_syscall_loader", assembly)
                self.assertIn("pwnc_syscall_terminal", assembly)
                if _direct_call_supported(target) and target.arch is not Architecture.X86:
                    self.assertIn("pwnc_call_loader", assembly)

    def test_xenial_fallback_uses_pinned_public_bootlin_wrapper_and_exact_paths(self) -> None:
        manifest = load_manifest()
        xenial_spec = next(spec for spec in manifest.sysroots if spec.id == _XENIAL_SPEC_ID)
        donor_spec = next(spec for spec in manifest.sysroots if spec.id == _XENIAL_STATIC_COMPILER_SPEC_ID)
        with tempfile.TemporaryDirectory(prefix="pwnc-xenial-static-compiler-") as directory:
            root = Path(directory)
            xenial_root = root / "xenial"
            include = xenial_root / "usr/include/x86_64-linux-gnu"
            library = xenial_root / "usr/lib/x86_64-linux-gnu"
            include.mkdir(parents=True)
            library.mkdir(parents=True)
            donor_root = root / "donor"
            donor_sysroot = donor_root / "sysroot"
            donor_sysroot.mkdir(parents=True)
            donor_bin = donor_root / "bin"
            donor_bin.mkdir()
            wrapper_target = donor_bin / "toolchain-wrapper"
            wrapper_target.write_bytes(b"pinned public wrapper bytes\n")
            wrapper = donor_bin / "x86_64-linux-gcc"
            wrapper.symlink_to(wrapper_target.name)
            xenial = ProvisionedSysroot(
                xenial_spec,
                xenial_root,
                xenial_root,
                xenial_root / xenial_spec.libc,
                xenial_root / xenial_spec.loader,
            )
            donor = ProvisionedSysroot(
                donor_spec,
                donor_root,
                donor_sysroot,
                donor_sysroot / donor_spec.libc,
                donor_sysroot / donor_spec.loader,
                bootlin_compiler=wrapper,
            )

            invocation = _xenial_static_compiler_invocation(xenial, donor)

            self.assertEqual(
                invocation.argv,
                (
                    str(wrapper),
                    f"--sysroot={xenial_root}",
                    "-isystem",
                    str(include),
                    f"-B{library}/",
                    f"-L{library}",
                ),
            )
            self.assertEqual(invocation.owner_spec_id, _XENIAL_STATIC_COMPILER_SPEC_ID)
            self.assertTrue(invocation.borrowed)
            self.assertEqual(invocation.invoked_driver, wrapper)
            self.assertEqual(invocation.resolved_driver, wrapper_target)
            invocation.revalidate()


@unittest.skipUnless(
    _OPT_IN,
    f"set PWNC_GLIBC_QEMU_TESTS=1 or PWNC_GLIBC_STATIC_ROP_TESTS=1 to run; "
    f"cache: {_CACHE_ENV}, selector: {_SELECTOR_ENV}",
)
class GlibcStaticRopQemuTests(unittest.TestCase):
    def test_every_pinned_static_glibc_executes_syscall_and_supported_libc_call_rop(self) -> None:
        if not sys.platform.startswith("linux"):
            self.fail("static glibc qemu-user execution requires a Linux host")
        for spec in _selected_specs():
            provisioned = provision_sysroot(spec, _cache_dir())
            for target_name in spec.targets:
                target = _catalog_target(target_name)
                with (
                    self.subTest(spec=spec.id, target=target.name),
                    tempfile.TemporaryDirectory(prefix="pwnc-static-glibc-rop-") as directory,
                ):
                    self._exercise_target(provisioned, target, Path(directory))

    def _exercise_target(self, provisioned: ProvisionedSysroot, target: Target, root: Path) -> None:
        executable, linker_map, link_trace, compiler = _compile_fixture(
            provisioned,
            target,
            root,
            _cache_dir(),
        )
        if provisioned.spec.id == _XENIAL_SPEC_ID:
            self.assertTrue(compiler.borrowed)
            self.assertEqual(compiler.owner_spec_id, _XENIAL_STATIC_COMPILER_SPEC_ID)
            self.assertEqual(compiler.invoked_driver.name, "x86_64-linux-gcc")
            self.assertNotIn(".br_real", os.fspath(compiler.invoked_driver))
        else:
            self.assertFalse(compiler.borrowed)
            self.assertEqual(compiler.owner_spec_id, provisioned.spec.id)
        archive, archive_digest = _mapped_libc_archive(linker_map, provisioned)
        _assert_exit_definition_trace(link_trace, archive, provisioned)
        profile = inspect_elf(executable)
        _assert_compiled_target(self, profile.target, target)
        self.assertIs(profile.linkage, Linkage.STATIC)
        self.assertFalse(profile.pie)
        self.assertTrue(profile.nx, profile.nx_evidence)
        self.assertIsNone(profile.interpreter)
        self.assertFalse(profile.needed_libraries)

        adapter = ExactELFAdapter.from_file(executable, profile=profile, expected_target=profile.target)
        adapter.crosscheck_profile(profile)
        self.assertEqual(adapter.symbol("exit"), _symbol(profile, "exit"))
        self.assertFalse(adapter.mitigations.pie)
        self.assertTrue(adapter.mitigations.nx)

        chain_symbol = _symbol(profile, "pwnc_chain")
        syscall = build_static_syscall(
            target,
            _symbol(profile, "pwnc_syscall_terminal"),
            _syscall_number(target),
            (41,),
            gadgets=(_syscall_restore_gadget(target, profile),),
            label="fixture exit syscall",
        )
        syscall_data = syscall.materialize(RuntimeLayout(main_base=0))
        self.assertLessEqual(len(syscall_data), _CHAIN_CAPACITY)
        syscall_mapping = next(item for item in profile.load_ranges if item.contains(chain_symbol, len(syscall_data)))
        self.assertTrue(syscall_mapping.writable)
        if target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
            # These pinned GNU ld variants place the executable .iplt together
            # with .data/.bss in one RWX PT_LOAD.  PT_GNU_STACK is still RW and
            # the independent mitigation checks above therefore report NX.
            self.assertTrue(syscall_mapping.executable)
        else:
            self.assertFalse(syscall_mapping.executable)
        _run_chain(self, provisioned, target, executable, syscall_data, 0, 41)
        if _NATIVE_X86_HOST and target.arch in {Architecture.X86, Architecture.X86_64}:
            _run_chain(
                self,
                provisioned,
                target,
                executable,
                syscall_data,
                0,
                41,
                argv=(str(executable),),
                runner="native",
            )

        if _direct_call_supported(target):
            call = build_static_call(
                target,
                _symbol(profile, "exit"),
                (42,),
                gadgets=_call_restore_gadgets(target, profile),
                label="exact static-linked glibc exit",
            )
            offset = _aligned_chain_offset(call, chain_symbol)
            call_base = chain_symbol + offset
            call_data = call.materialize(RuntimeLayout(main_base=0), chain_base=call_base)
            self.assertLessEqual(offset + len(call_data), _CHAIN_CAPACITY)
            call_mapping = next(item for item in profile.load_ranges if item.contains(call_base, len(call_data)))
            self.assertTrue(call_mapping.writable)
            self.assertFalse(call_mapping.executable)
            _run_chain(self, provisioned, target, executable, call_data, offset, 42)
            if _NATIVE_X86_HOST and target.arch in {Architecture.X86, Architecture.X86_64}:
                _run_chain(
                    self,
                    provisioned,
                    target,
                    executable,
                    call_data,
                    offset,
                    42,
                    argv=(str(executable),),
                    runner="native",
                )
        elif target.arch is Architecture.THUMB:
            # The ARM hard-float glibc archives contain ARM-state functions,
            # even when the challenge fixture itself is compiled as Thumb.
            # Target-wide Thumb conversion would set bit zero on this even
            # symbol and incorrectly enter it as Thumb code.
            exit_address = _symbol(profile, "exit")
            self.assertEqual(exit_address & 1, 0)
            self.assertNotEqual(target.function_pointer(exit_address), exit_address)
        else:
            with self.assertRaises(UnsupportedROPError):
                build_static_call(target, _symbol(profile, "exit"), (42,), label="unsupported static libc exit")

        self.assertTrue(archive.is_file())
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), archive_digest)
        compiler.revalidate()


if __name__ == "__main__":
    unittest.main()
