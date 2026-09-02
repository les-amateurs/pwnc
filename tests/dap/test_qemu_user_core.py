"""Shared qemu-user core tests; kept with DAP tests so they are repository-tracked."""

from __future__ import annotations

import os
import platform
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from pwnc import qemu_user
from pwnc.qemu_user import (
    ElfInspectionError,
    GuestLayoutError,
    QemuNotFoundError,
    UnsupportedQemuArchitectureError,
    guest_layout_args,
    infer_solib_search_path,
    inspect_elf,
    normalize_qemu_arch,
    plan_guest_layout,
    plan_qemu,
    qemu_binary_names_for_arch,
    resolve_qemu,
)


def _write_elf(
    path: Path,
    *,
    machine: int,
    bits: int,
    endian: str,
    flags: int = 0,
    elf_type: int = 2,
) -> Path:
    byte_order = "<" if endian == "little" else ">"
    elf_class = 1 if bits == 32 else 2
    elf_data = 1 if endian == "little" else 2
    ident = b"\x7fELF" + bytes((elf_class, elf_data, 1, 0, 0)) + bytes(7)
    if bits == 32:
        header = struct.pack(
            byte_order + "HHIIIIIHHHHHH",
            elf_type,
            machine,
            1,
            0,
            0,
            0,
            flags,
            52,
            32,
            0,
            40,
            0,
            0,
        )
    else:
        header = struct.pack(
            byte_order + "HHIQQQIHHHHHH",
            elf_type,
            machine,
            1,
            0,
            0,
            0,
            flags,
            64,
            56,
            0,
            64,
            0,
            0,
        )
    path.write_bytes(ident + header)
    path.chmod(0o755)
    return path


@pytest.mark.parametrize(
    ("name", "canonical", "arch", "bits", "endian"),
    [
        ("qemu-aarch64-static", "aarch64", "aarch64", 64, "little"),
        ("aarch64_be", "aarch64_be", "aarch64", 64, "big"),
        ("s390x", "s390x", "s390", 64, "big"),
        ("sparc32", "sparc", "sparc", 32, "big"),
        ("mipsel", "mipsel", "mips", 32, "little"),
        ("mips64le", "mips64el", "mips64", 64, "little"),
        ("powerpc", "ppc", "powerpc", 32, "big"),
        ("ppc64el", "ppc64le", "powerpc64", 64, "little"),
        ("riscv32", "riscv32", "riscv32", 32, "little"),
        ("amd64", "x86_64", "amd64", 64, "little"),
        ("loong64", "loongarch64", "loongarch64", 64, "little"),
        ("microblazeel", "microblazeel", "microblaze", 32, "little"),
        ("xtensaeb", "xtensaeb", "xtensa", 32, "big"),
    ],
)
def test_normalize_qemu_arch_matrix(name, canonical, arch, bits, endian):
    target = normalize_qemu_arch(name)
    assert (target.qemu_arch, target.arch, target.bits, target.endian) == (canonical, arch, bits, endian)
    assert normalize_qemu_arch(target) is target


def test_normalize_qemu_arch_rejects_unknown_and_empty_values():
    with pytest.raises(UnsupportedQemuArchitectureError, match="unsupported qemu-user architecture"):
        normalize_qemu_arch("not-a-real-cpu")
    with pytest.raises(UnsupportedQemuArchitectureError, match="non-empty"):
        normalize_qemu_arch("")


def test_binary_names_cover_normal_static_and_distribution_aliases():
    assert qemu_binary_names_for_arch("aarch64", static=False) == ("qemu-aarch64", "qemu-arm64")
    assert qemu_binary_names_for_arch("aarch64", static=True) == (
        "qemu-aarch64-static",
        "qemu-arm64-static",
    )
    assert qemu_binary_names_for_arch("ppc64le") == (
        "qemu-ppc64le",
        "qemu-ppc64el",
        "qemu-ppc64le-static",
        "qemu-ppc64el-static",
    )
    with pytest.raises(TypeError, match="static"):
        qemu_binary_names_for_arch("arm", static=1)


@pytest.mark.parametrize(
    ("filename", "machine", "bits", "endian", "flags", "qemu_arch", "arch"),
    [
        ("aarch64", 183, 64, "little", 0, "aarch64", "aarch64"),
        ("aarch64-be", 183, 64, "big", 0, "aarch64_be", "aarch64"),
        ("s390x", 22, 64, "big", 0, "s390x", "s390"),
        ("sparc", 2, 32, "big", 0, "sparc", "sparc"),
        ("sparc32plus", 18, 32, "big", 0, "sparc32plus", "sparc"),
        ("sparc64", 43, 64, "big", 0, "sparc64", "sparc64"),
        ("mips", 8, 32, "big", 0, "mips", "mips"),
        ("mipsel", 8, 32, "little", 0, "mipsel", "mips"),
        ("mipsn32", 8, 32, "big", 0x20, "mipsn32", "mips64"),
        ("mipsn32el", 8, 32, "little", 0x20, "mipsn32el", "mips64"),
        ("mips64", 8, 64, "big", 0, "mips64", "mips64"),
        ("mips64el", 8, 64, "little", 0, "mips64el", "mips64"),
        ("ppc", 20, 32, "big", 0, "ppc", "powerpc"),
        ("ppc64", 21, 64, "big", 0, "ppc64", "powerpc64"),
        ("ppc64le", 21, 64, "little", 0, "ppc64le", "powerpc64"),
        ("riscv32", 243, 32, "little", 0, "riscv32", "riscv32"),
        ("riscv64", 243, 64, "little", 0, "riscv64", "riscv64"),
        ("i386", 3, 32, "little", 0, "i386", "i386"),
        ("amd64", 62, 64, "little", 0, "x86_64", "amd64"),
    ],
)
def test_inspect_elf_comprehensive_arch_endian_mapping(
    tmp_path,
    filename,
    machine,
    bits,
    endian,
    flags,
    qemu_arch,
    arch,
):
    path = _write_elf(tmp_path / filename, machine=machine, bits=bits, endian=endian, flags=flags)
    identity = inspect_elf(path)
    assert identity.path == str(path.resolve())
    assert identity.executable
    assert (identity.qemu_arch, identity.arch, identity.bits, identity.endian) == (qemu_arch, arch, bits, endian)


def test_inspect_elf_uses_pwntools_without_checksec(tmp_path, monkeypatch):
    path = _write_elf(tmp_path / "arm64", machine=183, bits=64, endian="little")
    original = qemu_user.PwntoolsELF
    calls = []

    def recording_elf(filename, *, checksec=True):
        calls.append((filename, checksec))
        return original(filename, checksec=checksec)

    monkeypatch.setattr(qemu_user, "PwntoolsELF", recording_elf)
    inspect_elf(path)
    assert calls == [(str(path.resolve()), False)]


def test_i386_is_native_on_x86_64_host(tmp_path):
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("x86 compatibility regression is host-specific")
    path = _write_elf(tmp_path / "i386", machine=3, bits=32, endian="little")
    assert inspect_elf(path).native is True
    assert inspect_elf("/bin/true").native is True


def test_inspect_elf_preserves_non_utf8_bytes_path(tmp_path):
    directory = os.fsencode(tmp_path)
    path = os.path.join(directory, b"guest-\xff")
    _write_elf(Path(os.fsdecode(path)), machine=183, bits=64, endian="little")
    identity = inspect_elf(path)
    assert isinstance(identity.path, bytes)
    assert identity.path == os.path.abspath(path)


def test_inspect_elf_rejects_non_elf_and_unsupported_ppc32le(tmp_path):
    invalid = tmp_path / "invalid"
    invalid.write_bytes(b"not an elf")
    with pytest.raises(ElfInspectionError, match="cannot inspect ELF"):
        inspect_elf(invalid)

    ppc32le = _write_elf(tmp_path / "ppc32le", machine=20, bits=32, endian="little")
    with pytest.raises(UnsupportedQemuArchitectureError, match="PowerPC32 little-endian"):
        inspect_elf(ppc32le)


def test_resolve_qemu_normal_and_explicit_paths():
    path = shutil.which("qemu-aarch64")
    if path is None:
        pytest.skip("qemu-aarch64 is not installed")
    automatic = resolve_qemu("aarch64", static=False)
    assert automatic.path == path
    assert automatic.architecture.qemu_arch == "aarch64"
    assert not automatic.explicit

    explicit = resolve_qemu("aarch64", executable=path)
    assert explicit.path == path
    assert explicit.explicit

    wrong_target = shutil.which("qemu-arm")
    if wrong_target is not None:
        with pytest.raises(QemuNotFoundError, match="targets arm, not requested aarch64"):
            resolve_qemu("aarch64", executable=wrong_target)


def test_resolve_qemu_static_validation_and_missing_diagnostics(tmp_path):
    path = shutil.which("qemu-aarch64")
    if path is not None and not inspect_elf(path).statically_linked:
        with pytest.raises(QemuNotFoundError, match="not static"):
            resolve_qemu("aarch64", executable=path, static=True)

    with pytest.raises(QemuNotFoundError, match="install qemu-user"):
        resolve_qemu("aarch64", search_path=tmp_path)
    with pytest.raises(QemuNotFoundError, match="qemu-user-static"):
        resolve_qemu("aarch64", static=True, search_path=tmp_path)


@pytest.mark.parametrize("architecture", ["arm", "aarch64", "mips", "mips64el", "ppc64le", "riscv64", "s390x"])
def test_guest_layout_none_is_upstream_and_false_is_fixed(architecture):
    upstream = plan_guest_layout(architecture, None)
    assert upstream.reserved_va is None
    assert upstream.arguments == ()
    assert not upstream.stable
    assert not upstream.randomized

    first = plan_guest_layout(architecture, False)
    second = plan_guest_layout(architecture, False)
    assert first == second
    assert first.stable
    assert first.reserved_va is not None
    assert first.arguments == ("-R", hex(first.reserved_va))
    assert guest_layout_args(architecture, False) == first.arguments


def test_guest_layout_true_uses_fresh_aligned_entropy_and_validates_source():
    low = plan_guest_layout("aarch64", True, randbelow=lambda _slots: 0)
    high = plan_guest_layout("aarch64", True, randbelow=lambda slots: slots - 1)
    assert low.randomized and high.randomized
    assert low.reserved_va != high.reserved_va
    assert low.reserved_va % (1 << 30) == 0
    assert high.reserved_va % (1 << 30) == 0
    assert low.arguments != high.arguments

    with pytest.raises(GuestLayoutError, match="out-of-range"):
        plan_guest_layout("aarch64", True, randbelow=lambda slots: slots)
    with pytest.raises(TypeError, match="guest_aslr"):
        plan_guest_layout("aarch64", 1)


def test_x86_64_refuses_to_mislabel_nonfunctional_layout_knobs_as_aslr():
    assert plan_guest_layout("x86_64", None).arguments == ()
    with pytest.raises(GuestLayoutError, match="vsyscall"):
        plan_guest_layout("x86_64", False)
    with pytest.raises(GuestLayoutError, match="vsyscall"):
        plan_guest_layout("x86_64", True)


def test_infer_solib_search_path_is_source_neutral_and_bytes_preserving():
    paths = infer_solib_search_path(b"/guest", "aarch64")
    assert paths[:4] == (b"/guest/lib", b"/guest/usr/lib", b"/guest/lib64", b"/guest/usr/lib64")
    assert b"/guest/lib/aarch64-linux-gnu" in paths
    assert infer_solib_search_path(None, "aarch64") == ()


def test_plan_qemu_preserves_exact_bytes_argv_and_separate_host_aslr(tmp_path):
    emulator = shutil.which("qemu-aarch64")
    if emulator is None:
        pytest.skip("qemu-aarch64 is not installed")
    program_path = tmp_path / "guest"
    _write_elf(program_path, machine=183, bits=64, endian="little")
    program = os.fsencode(program_path)
    argument = b"raw-\xff"

    plan = plan_qemu(
        program,
        argument,
        "two words",
        executable=emulator,
        sysroot=b"/guest-root",
        qemu_aslr=False,
        gdb=b"/tmp/gdb-\xfe.sock",
        host_aslr=False,
    )
    assert plan.argv == (
        emulator,
        "-g",
        b"/tmp/gdb-\xfe.sock",
        "-R",
        "0x1000000000",
        "-L",
        b"/guest-root",
        os.path.abspath(program),
        argument,
        "two words",
    )
    assert plan.env == {}
    assert plan.starts_stopped
    assert plan.gdb_endpoint == b"/tmp/gdb-\xfe.sock"
    assert plan.host_aslr is False
    assert plan.layout.guest_aslr is False
    assert plan.solib_search_path[0] == b"/guest-root/lib"


_ADDRESS_LINE = re.compile(rb"main=(0x[0-9a-f]+) libc=(0x[0-9a-f]+) heap=(0x[0-9a-f]+) stack=(0x[0-9a-f]+)")


def _run_live_layout(argv: tuple[str | bytes, ...], *, host_aslr: bool) -> tuple[int, int, int, int]:
    command: tuple[str | bytes, ...]
    if host_aslr:
        command = argv
    else:
        setarch = shutil.which("setarch")
        if setarch is None:
            pytest.skip("setarch is unavailable for the independent host-ASLR probe")
        command = (setarch, platform.machine(), "-R", *argv)
    completed = subprocess.run(command, capture_output=True, timeout=10, check=True)
    match = _ADDRESS_LINE.search(completed.stdout)
    assert match is not None, completed.stdout + completed.stderr
    return tuple(int(value, 16) for value in match.groups())


def test_live_aarch64_guest_layout_stability_and_variance_with_host_aslr_disabled(tmp_path):
    zig = shutil.which("zig")
    emulator = shutil.which("qemu-aarch64")
    if zig is None or emulator is None:
        pytest.skip("live AArch64 layout probe needs Zig and qemu-aarch64")

    source = b"""
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    void *allocation = malloc(1);
    int stack_value = 0;
    printf("main=%p libc=%p heap=%p stack=%p\\n",
           (void *)main, (void *)printf, allocation, (void *)&stack_value);
    return 0;
}
"""
    program = tmp_path / "layout-probe"
    subprocess.run(
        (
            zig,
            "cc",
            "-target",
            "aarch64-linux-musl",
            "-fPIE",
            "-pie",
            "-O0",
            "-x",
            "c",
            "-",
            "-o",
            str(program),
        ),
        input=source,
        capture_output=True,
        timeout=60,
        check=True,
    )

    stable = plan_qemu(program, executable=emulator, qemu_aslr=False)
    assert _run_live_layout(stable.argv, host_aslr=False) == _run_live_layout(stable.argv, host_aslr=False)

    low = plan_qemu(program, executable=emulator, qemu_aslr=True, randbelow=lambda _slots: 0)
    high = plan_qemu(program, executable=emulator, qemu_aslr=True, randbelow=lambda slots: slots - 1)
    low_addresses = _run_live_layout(low.argv, host_aslr=False)
    high_addresses = _run_live_layout(high.argv, host_aslr=False)
    assert all(first != second for first, second in zip(low_addresses, high_addresses, strict=True))


def test_live_i386_fixed_layout_stabilizes_pie_shared_libc_heap_and_stack(tmp_path):
    compiler = shutil.which("gcc")
    emulator = shutil.which("qemu-i386")
    if compiler is None or emulator is None:
        pytest.skip("live i386 layout probe needs GCC and qemu-i386")

    source = b"""
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    void *allocation = malloc(1);
    int stack_value = 0;
    printf("main=%p libc=%p heap=%p stack=%p\\n",
           (void *)main, (void *)printf, allocation, (void *)&stack_value);
    return 0;
}
"""
    program = tmp_path / "i386-layout-probe"
    compiled = subprocess.run(
        (
            compiler,
            "-m32",
            "-fPIE",
            "-pie",
            "-O0",
            "-x",
            "c",
            "-",
            "-o",
            str(program),
        ),
        input=source,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if compiled.returncode != 0:
        pytest.skip("32-bit glibc development files are unavailable: " + compiled.stderr.decode("utf-8", "replace"))

    identity = inspect_elf(program)
    assert identity.native is True
    assert not identity.statically_linked
    stable = plan_qemu(program, executable=emulator, qemu_aslr=False)
    host_randomized = _run_live_layout(stable.argv, host_aslr=True)
    host_disabled_first = _run_live_layout(stable.argv, host_aslr=False)
    host_disabled_second = _run_live_layout(stable.argv, host_aslr=False)

    # main is the PIE, printf resides in the separately mapped real i386
    # glibc, malloc supplies the heap address, and the local is on the stack.
    assert len(set(host_disabled_first)) == 4
    assert host_randomized == host_disabled_first == host_disabled_second


def test_live_qemu_x86_64_documents_nonzero_reserved_va_vsyscall_limit():
    emulator = shutil.which("qemu-x86_64")
    if emulator is None or not Path("/bin/true").is_file():
        pytest.skip("qemu-x86_64 and a native guest ELF are required")
    completed = subprocess.run(
        (emulator, "-R", "0x1000000000", "/bin/true"),
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode != 0
    assert b"vsyscall" in completed.stderr.lower()
