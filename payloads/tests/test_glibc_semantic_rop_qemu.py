"""Opt-in exact-libc semantic-call ROP execution under qemu-user.

The composable pwntools linker is intentionally limited to i386 and AMD64.
This module exercises the lower semantic layer against every pinned glibc
artifact whose direct-call ABI is modeled honestly: ARM and AArch64, MIPS
o32/n64, RISC-V, PPC32, PPC64 ELFv2, s390x, and both x86 ABIs.  Thumb is not
included because the shared ARM libc's function symbols are ARM-state entries,
while PPC64 ELFv1 and SPARC need descriptor/TOC or register-window call
primitives which the public builder deliberately rejects.

Each real dynamic fixture discloses the loaded libc's path, base, version, and
``write`` address.  The shared helpers prove that the disclosed file is the
provisioned artifact and bind the symbol equation to its SHA-256/build ID.
The test then describes one fixture-owned register loader with
``SemanticGadget``, lowers an exact-libc ``write(1, marker, size)`` stage, and
pivots through the materialized chain from writable non-executable BSS.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from payloads import (
    ABI,
    Address,
    Architecture,
    Image,
    LibcROPBuilder,
    LibcROPStageKind,
    Linkage,
    PayloadKind,
    RuntimeLayout,
    SemanticGadget,
    inspect_elf,
)
from payloads.tests.runtime_support import provision_sysroot
from payloads.tests.test_glibc_qemu import (
    _assert_compiled_target,
    _assert_exact_interpreter,
    _assert_runtime_libc,
    _cache_dir,
    _catalog_target,
    _compile,
    _environment,
    _protocol_header,
    _read_line,
    _selected_specs,
)

_OPT_IN = os.environ.get("PWNC_GLIBC_QEMU_TESTS") == "1"
_NATIVE_OPT_IN = os.environ.get("PWNC_NATIVE_TESTS") == "1"
_MARKER = b"PWNC_GLIBC_SEMANTIC_ROP_OK"
_CHAIN_CAPACITY = 0x10000


_SEMANTIC_WRITE_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((aligned(4096))) unsigned char pwnc_chain[0x10000];
unsigned char pwnc_storage[] = "PWNC_GLIBC_SEMANTIC_ROP_OK";
char pwnc_path[] = "/unused";

extern void pwnc_load_write(void);
extern void pwnc_pivot(void *chain) __attribute__((noreturn));
extern void pwnc_success(void) __attribute__((noreturn));

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

int main(void) {
    void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *write_address = handle == NULL ? NULL : dlsym(handle, "write");
    Dl_info owner;
    uint32_t request[2];

    if (write_address == NULL || dladdr(write_address, &owner) == 0)
        return 100;
    if (printf("PWNC_SEMANTIC_ROP\t%s\t%p\t%s\t%p\t%p\t%p\t%p\t%p\t%p\n",
               owner.dli_fname, owner.dli_fbase, gnu_get_libc_version(),
               write_address, (void *) pwnc_chain, (void *) pwnc_storage,
               (void *) pwnc_path, (void *) (uintptr_t) pwnc_success,
               (void *) (uintptr_t) pwnc_load_write) < 0 || fflush(stdout) != 0)
        return 101;
    if (read_exact(STDIN_FILENO, request, sizeof(request)) != 0)
        return 102;
    if (request[0] > sizeof(pwnc_chain) ||
        request[1] > sizeof(pwnc_chain) - request[0])
        return 103;
    if (read_exact(STDIN_FILENO, pwnc_chain + request[0], request[1]) != 0)
        return 104;
    pwnc_pivot(pwnc_chain + request[0]);
}

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: pop %rdi; pop %rsi; pop %rdx; ret\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mov %rdi, %rsp; ret\n"
    ".globl pwnc_success\n"
    "pwnc_success: mov $42, %edi; mov $60, %eax; syscall; ud2\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
);
#elif defined(__i386__)
__asm__(
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: ret\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mov 4(%esp), %eax; mov %eax, %esp; ret\n"
    ".globl pwnc_success\n"
    "pwnc_success: mov $42, %ebx; mov $1, %eax; int $0x80; ud2\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
);
#elif defined(__arm__)
__asm__(
    ".syntax unified\n"
    ".arm\n"
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: pop {r0, r1, r2, r3, lr, pc}\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mov sp, r0; pop {pc}\n"
    ".globl pwnc_success\n"
    "pwnc_success: mov r0, #42; mov r7, #1; svc #0; udf #0\n"
);
#elif defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: ldp x0, x1, [sp], #16; ldp x2, x30, [sp], #16; "
    "ldr x16, [sp], #8; br x16\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mov sp, x0; ldr x16, [sp], #8; br x16\n"
    ".globl pwnc_success\n"
    "pwnc_success: mov x0, #42; mov x8, #93; svc #0; brk #0\n"
);
#elif defined(__mips64)
__asm__(
    ".set noreorder\n"
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: ld $a0, 0($sp); ld $a1, 8($sp); ld $a2, 16($sp); "
    "ld $ra, 24($sp); ld $t9, 32($sp); daddiu $sp, $sp, 40; jr $t9; nop\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: move $sp, $a0; ld $t9, 0($sp); daddiu $sp, $sp, 8; jr $t9; nop\n"
    ".globl pwnc_success\n"
    "pwnc_success: li $a0, 42; li $v0, 5058; syscall; break\n"
    ".set reorder\n"
);
#elif defined(__mips__)
__asm__(
    ".set noreorder\n"
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: lw $a0, 0($sp); lw $a1, 4($sp); lw $a2, 8($sp); "
    "lw $ra, 12($sp); lw $t9, 16($sp); addiu $sp, $sp, 20; jr $t9; nop\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: move $sp, $a0; lw $t9, 0($sp); addiu $sp, $sp, 4; jr $t9; nop\n"
    ".globl pwnc_success\n"
    "pwnc_success: li $a0, 42; li $v0, 4001; syscall; break\n"
    ".set reorder\n"
);
#elif defined(__riscv) && __riscv_xlen == 64
__asm__(
    ".option push\n"
    ".option norvc\n"
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: ld a0, 0(sp); ld a1, 8(sp); ld a2, 16(sp); "
    "ld ra, 24(sp); ld t0, 32(sp); addi sp, sp, 40; jr t0\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mv sp, a0; ld t0, 0(sp); addi sp, sp, 8; jr t0\n"
    ".globl pwnc_success\n"
    "pwnc_success: li a0, 42; li a7, 93; ecall; unimp\n"
    ".option pop\n"
);
#elif defined(__riscv) && __riscv_xlen == 32
__asm__(
    ".option push\n"
    ".option norvc\n"
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: lw a0, 0(sp); lw a1, 4(sp); lw a2, 8(sp); "
    "lw ra, 12(sp); lw t0, 16(sp); addi sp, sp, 20; jr t0\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mv sp, a0; lw t0, 0(sp); addi sp, sp, 4; jr t0\n"
    ".globl pwnc_success\n"
    "pwnc_success: li a0, 42; li a7, 93; ecall; unimp\n"
    ".option pop\n"
);
#elif defined(__powerpc64__)
__asm__(
    ".abiversion 2\n"
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: ld 3, 0(1); ld 4, 8(1); ld 5, 16(1); ld 11, 24(1); "
    "mtlr 11; ld 12, 32(1); addi 1, 1, 40; mtctr 12; bctr\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mr 1, 3; ld 12, 0(1); addi 1, 1, 8; mtctr 12; bctr\n"
    ".globl pwnc_success\n"
    "pwnc_success: li 3, 42; li 0, 1; sc; trap\n"
);
#elif defined(__powerpc__)
__asm__(
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: lwz 3, 0(1); lwz 4, 4(1); lwz 5, 8(1); lwz 11, 12(1); "
    "mtlr 11; lwz 12, 16(1); addi 1, 1, 20; mtctr 12; bctr\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mr 1, 3; lwz 12, 0(1); addi 1, 1, 4; mtctr 12; bctr\n"
    ".globl pwnc_success\n"
    "pwnc_success: li 3, 42; li 0, 1; sc; trap\n"
);
#elif defined(__s390x__)
__asm__(
    ".text\n"
    ".globl pwnc_load_write\n"
    "pwnc_load_write: lg %r2, 0(%r15); lg %r3, 8(%r15); lg %r4, 16(%r15); "
    "lg %r14, 24(%r15); lg %r8, 32(%r15); aghi %r15, 40; br %r8\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: lgr %r15, %r2; lg %r8, 0(%r15); aghi %r15, 8; br %r8\n"
    ".globl pwnc_success\n"
    "pwnc_success: lghi %r2, 42; lghi %r1, 1; svc 0; j .\n"
);
#else
#error unsupported semantic ROP fixture target
#endif
"""


def _is_honest_direct_libc_target(target) -> bool:
    return (
        target.arch not in {Architecture.THUMB, Architecture.SPARC32, Architecture.SPARC64}
        and target.abi is not ABI.POWERPC64_ELFV1
    )


def _write_gadget(target, address: Address) -> tuple[SemanticGadget, ...]:
    if target.arch is Architecture.X86:
        return ()
    if target.arch is Architecture.X86_64:
        return (SemanticGadget(target, address, 4, {"rdi": 0, "rsi": 1, "rdx": 2}, 3, "pop rdi/rsi/rdx; ret"),)
    if target.arch is Architecture.ARM:
        return (
            SemanticGadget(
                target,
                address,
                6,
                {"r0": 0, "r1": 1, "r2": 2, "lr": 4},
                5,
                "pop r0/r1/r2/r3/lr/pc",
                clobbers={"r3"},
            ),
        )
    if target.arch is Architecture.ARM64:
        return (
            SemanticGadget(
                target,
                address,
                5,
                {"x0": 0, "x1": 1, "x2": 2, "x30": 3, "x16": 4},
                4,
                "restore write arguments/x30/x16; br x16",
                next_pc_register="x16",
            ),
        )
    if target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        return (
            SemanticGadget(
                target,
                address,
                5,
                {"a0": 0, "a1": 1, "a2": 2, "ra": 3, "t9": 4},
                4,
                "restore write arguments/ra/t9; jr t9",
                next_pc_register="t9",
            ),
        )
    if target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
        return (
            SemanticGadget(
                target,
                address,
                5,
                {"a0": 0, "a1": 1, "a2": 2, "ra": 3, "t0": 4},
                4,
                "restore write arguments/ra/t0; jr t0",
                next_pc_register="t0",
            ),
        )
    if target.arch in {Architecture.POWERPC32, Architecture.POWERPC64}:
        return (
            SemanticGadget(
                target,
                address,
                5,
                {"r3": 0, "r4": 1, "r5": 2, "lr": 3, "r12": 4},
                4,
                "restore write arguments/lr/r12; bctr",
                next_pc_register="r12",
            ),
        )
    if target.arch is Architecture.S390X:
        return (
            SemanticGadget(
                target,
                address,
                5,
                {"r2": 0, "r3": 1, "r4": 2, "r14": 3, "r8": 4},
                4,
                "restore write arguments/r14/r8; br r8",
                next_pc_register="r8",
            ),
        )
    raise AssertionError(f"no semantic write gadget for {target.name}")


def _aligned_chain_base(chain, storage: int) -> tuple[int, int]:
    if chain.call_frame is None:
        raise AssertionError("semantic libc write chain has no call-frame contract")
    alignment = chain.call_frame.entry_sp_alignment
    required = chain.call_frame.required_chain_base_remainder
    offset = (required - storage) % alignment
    chain_base = storage + offset
    chain.validate_call_frame(chain_base)
    return chain_base, offset


def _native_loader_argv(provisioned, executable: Path) -> tuple[str, ...]:
    """Invoke an x86 guest through its exact loader without qemu-user."""

    return (
        str(provisioned.loader),
        "--inhibit-cache",
        "--library-path",
        str(provisioned.libc.parent),
        str(executable.resolve()),
    )


class GlibcSemanticRopMatrixUnitTests(unittest.TestCase):
    def test_honest_direct_call_matrix_is_exact(self) -> None:
        cases = [
            (spec.id, target.name)
            for spec in _selected_specs()
            for name in spec.targets
            if _is_honest_direct_libc_target(target := _catalog_target(name))
        ]
        if os.environ.get("PWNC_GLIBC_QEMU_SPECS"):
            self.assertEqual(len(cases), len(set(cases)))
            return
        self.assertEqual(len(cases), 28)
        self.assertEqual(len({spec for spec, _ in cases}), 28)
        self.assertEqual(len({target for _, target in cases}), 15)
        native_x86 = [
            (spec.id, target.name)
            for spec in _selected_specs()
            for name in spec.targets
            if (target := _catalog_target(name)).arch in {Architecture.X86, Architecture.X86_64}
        ]
        self.assertEqual(len(native_x86), 7)
        self.assertEqual(len({target for _, target in native_x86}), 2)
        excluded = {
            _catalog_target(name).name
            for spec in _selected_specs()
            for name in spec.targets
            if not _is_honest_direct_libc_target(_catalog_target(name))
        }
        self.assertEqual(
            excluded,
            {
                "thumb-le-arm-eabi",
                "thumb-be-arm-eabi",
                "powerpc64-be-powerpc64-elfv1",
                "sparc32-be-sparc-sysv",
                "sparc64-be-sparc64-sysv",
            },
        )


class _SemanticWriteRunner:
    def _run_semantic_write(self, provisioned, executable, profile, target, *, argv=None) -> None:
        process = subprocess.Popen(
            provisioned.qemu_argv(executable) if argv is None else argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_environment(),
        )
        try:
            fields = _read_line(process, f"{provisioned.spec.id} semantic libc ROP").split(b"\t")
            self.assertEqual(len(fields), 10, fields)
            self.assertEqual(fields[0], b"PWNC_SEMANTIC_ROP")
            owner_base = int(fields[2], 16)
            glibc_version = fields[3].decode("ascii")
            write_address = int(fields[4], 16)
            chain_storage = int(fields[5], 16)
            marker_address = int(fields[6], 16)
            path_address = int(fields[7], 16)
            success_address = int(fields[8], 16)
            gadget_address = int(fields[9], 16)
            libc = _assert_runtime_libc(
                self,
                provisioned,
                fields[1],
                glibc_version,
                owner_base,
                write_address,
                "write",
                symbols=("write",),
                intended_target=target,
            )
            self.assertEqual(chain_storage, profile.symbol_offsets["pwnc_chain"])
            self.assertEqual(marker_address, profile.symbol_offsets["pwnc_storage"])
            self.assertEqual(path_address, profile.symbol_offsets["pwnc_path"])
            self.assertEqual(success_address, profile.symbol_offsets["pwnc_success"])
            self.assertEqual(gadget_address, profile.symbol_offsets["pwnc_load_write"])

            buffer = Address(marker_address, Image.MAIN, "fixture write marker")
            builder = LibcROPBuilder.from_file(
                provisioned.libc,
                b"/unused",
                writable_area=buffer,
                writable_size=len(_MARKER) + 1,
                path_address=Address(path_address, Image.MAIN, "unused fixture path"),
                target=target,
            )
            stage = builder.write(1, len(_MARKER))
            self.assertIs(stage.operation, LibcROPStageKind.WRITE)
            # LibcROPBuilder derives the immutable artifact identity without
            # the runtime-reported informational glibc_version field.  Bind
            # executable offsets with the byte/build identities themselves.
            self.assertEqual(stage.libc.identity.sha256, libc.identity.sha256)
            self.assertEqual(stage.libc.identity.build_id, libc.identity.build_id)

            gadgets = _write_gadget(
                target,
                Address(gadget_address, Image.MAIN, "fixture semantic write loader"),
            )
            chain = stage.lower_semantic(
                gadgets=gadgets,
                return_to=Address(success_address, Image.MAIN, "fixture success exit"),
            )
            self.assertIs(chain.kind, PayloadKind.RET2LIBC)
            chain_base, chain_offset = _aligned_chain_base(chain, chain_storage)
            chain_data = chain.materialize(
                RuntimeLayout(main_base=0, libc_base=owner_base),
                chain_base=chain_base,
            )
            self.assertLessEqual(chain_offset + len(chain_data), _CHAIN_CAPACITY)
            chain_mapping = next(item for item in profile.load_ranges if item.contains(chain_base, len(chain_data)))
            self.assertTrue(chain_mapping.writable)
            self.assertFalse(chain_mapping.executable)

            protocol = _protocol_header(target, chain_offset, len(chain_data)) + chain_data
            stdout, stderr = process.communicate(protocol, timeout=30)
            self.assertEqual(process.returncode, 42, stderr.decode(errors="replace"))
            self.assertEqual(stdout, _MARKER)
            self.assertEqual(stage.libc.identity.sha256, libc.identity.sha256)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


@unittest.skipUnless(
    _OPT_IN,
    "set PWNC_GLIBC_QEMU_TESTS=1 to run exact-libc semantic ROP under qemu-user",
)
class GlibcQemuSemanticWriteROPTests(_SemanticWriteRunner, unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not sys.platform.startswith("linux"):
            raise AssertionError("live qemu-user glibc tests require a Linux host")

    def test_exact_libc_semantic_write_matrix(self) -> None:
        cases = [
            (spec, _catalog_target(name))
            for spec in _selected_specs()
            for name in spec.targets
            if _is_honest_direct_libc_target(_catalog_target(name))
        ]
        if not cases:
            self.skipTest("selected sysroot specs contain no honestly modeled direct-call target")
        for spec, target in cases:
            provisioned = provision_sysroot(spec, _cache_dir())
            with (
                self.subTest(spec=spec.id, target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-glibc-semantic-rop-") as directory,
            ):
                executable = Path(directory, "fixture")
                _compile(provisioned, _SEMANTIC_WRITE_SOURCE, executable, target=target)
                profile = inspect_elf(executable)
                _assert_compiled_target(self, profile.target, target)
                self.assertFalse(profile.pie)
                self.assertIs(profile.linkage, Linkage.DYNAMIC)
                self.assertTrue(profile.nx, profile.nx_evidence)
                _assert_exact_interpreter(self, provisioned, profile)
                self._run_semantic_write(provisioned, executable, profile, target)


@unittest.skipUnless(
    _NATIVE_OPT_IN,
    "set PWNC_NATIVE_TESTS=1 to run pinned-libc semantic ROP directly on native x86",
)
class GlibcNativeX86SemanticWriteROPTests(_SemanticWriteRunner, unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not sys.platform.startswith("linux"):
            raise AssertionError("native pinned-libc ROP tests require a Linux host")
        if platform.machine().lower() not in {"amd64", "x86_64"}:
            raise AssertionError(f"native pinned-libc ROP requires an x86_64 host, not {platform.machine()!r}")

    def test_every_pinned_i386_and_amd64_semantic_write_chain_executes_natively(self) -> None:
        cases = [
            (spec, _catalog_target(name))
            for spec in _selected_specs()
            for name in spec.targets
            if _catalog_target(name).arch in {Architecture.X86, Architecture.X86_64}
        ]
        if not cases:
            self.skipTest("selected sysroot specs contain no native x86 target")
        for spec, target in cases:
            provisioned = provision_sysroot(spec, _cache_dir())
            with (
                self.subTest(spec=spec.id, target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-glibc-native-rop-") as directory,
            ):
                executable = Path(directory, "fixture")
                _compile(provisioned, _SEMANTIC_WRITE_SOURCE, executable, target=target)
                profile = inspect_elf(executable)
                _assert_compiled_target(self, profile.target, target)
                self.assertFalse(profile.pie)
                self.assertIs(profile.linkage, Linkage.DYNAMIC)
                self.assertTrue(profile.nx, profile.nx_evidence)
                _assert_exact_interpreter(self, provisioned, profile)
                self._run_semantic_write(
                    provisioned,
                    executable,
                    profile,
                    target,
                    argv=_native_loader_argv(provisioned, executable),
                )


if __name__ == "__main__":
    unittest.main()
