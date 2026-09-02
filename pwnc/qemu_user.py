"""Architecture-correct qemu-user discovery and launch planning.

This module deliberately separates three policies which are often conflated:

* :func:`inspect_elf` decides whether an ELF is native and which qemu-user
  target can execute it.
* :func:`resolve_qemu` finds and validates a *host* emulator.  Container code
  can instead use :func:`qemu_binary_names_for_arch` without requiring the
  guest image's filesystem to be visible on the host.
* :func:`plan_guest_layout` controls guest-visible layout through QEMU's
  reserved virtual address space.  It never changes the host QEMU process's
  personality or the host-wide ASLR sysctl.

QEMU does not implement Linux's normal guest ASLR algorithm in linux-user.
For targets where ``-R`` is usable, however, its reserved-address-space
allocator provides a deterministic search space for PIE, loader/libraries,
heap/brk, and stack mappings.  A fixed reservation therefore gives a
reproducible guest layout independent of host QEMU mappings.  A freshly
randomized reservation also moves all four regions for conventional zero-based
PIEs on targets such as AArch64 and RISC-V; target ABIs with fixed low PIE
bases, prelinked ET_DYN images, and ET_EXEC files naturally retain those fixed
image addresses.  This is deliberate reserved-layout entropy, not a claim that
QEMU implements the guest kernel's full ASLR algorithm.
"""

from __future__ import annotations

import os
import platform
import secrets
import shutil
import struct
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Literal, TypeAlias

from elftools.common.exceptions import ELFError
from pwnlib.context import context as pwntools_context
from pwnlib.elf.elf import ELF as PwntoolsELF

Endian = Literal["little", "big"]
PathValue: TypeAlias = str | bytes
PathInput: TypeAlias = str | bytes | os.PathLike[str] | os.PathLike[bytes]
Argument: TypeAlias = str | bytes


class QemuUserError(RuntimeError):
    """Base class for qemu-user inspection and planning failures."""


class ElfInspectionError(QemuUserError):
    """The requested program is not a usable ELF."""


class UnsupportedQemuArchitectureError(QemuUserError):
    """No qemu-user executable mapping exists for an ELF architecture."""


class QemuNotFoundError(QemuUserError):
    """No suitable host qemu-user executable could be resolved."""


class GuestLayoutError(QemuUserError):
    """The requested guest-visible layout policy is not safely supported."""


@dataclass(frozen=True, slots=True)
class QemuArchitecture:
    """One qemu-user executable target and its ELF identity."""

    qemu_arch: str
    arch: str
    bits: int
    endian: Endian
    executable_aliases: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        """Canonical qemu-user suffix, without the ``qemu-`` prefix."""

        return self.qemu_arch


def _architecture(
    qemu_arch: str,
    arch: str,
    bits: int,
    endian: Endian,
    *executable_aliases: str,
) -> QemuArchitecture:
    return QemuArchitecture(qemu_arch, arch, bits, endian, executable_aliases)


# This is the upstream linux-user executable matrix rather than pwntools'
# smaller qemu helper map.  In particular it preserves endian variants and
# ABI-specific emulators such as aarch64_be and MIPS n32.
_ARCHITECTURES: Mapping[str, QemuArchitecture] = MappingProxyType(
    {
        "aarch64": _architecture("aarch64", "aarch64", 64, "little", "arm64"),
        "aarch64_be": _architecture("aarch64_be", "aarch64", 64, "big"),
        "alpha": _architecture("alpha", "alpha", 64, "little"),
        "arm": _architecture("arm", "arm", 32, "little", "armel", "armhf"),
        "armeb": _architecture("armeb", "arm", 32, "big"),
        "cris": _architecture("cris", "cris", 32, "little"),
        "hexagon": _architecture("hexagon", "hexagon", 32, "little"),
        "hppa": _architecture("hppa", "hppa", 32, "big"),
        "i386": _architecture("i386", "i386", 32, "little"),
        "loongarch64": _architecture("loongarch64", "loongarch64", 64, "little", "loong64"),
        "m68k": _architecture("m68k", "m68k", 32, "big"),
        "microblaze": _architecture("microblaze", "microblaze", 32, "big"),
        "microblazeel": _architecture("microblazeel", "microblaze", 32, "little"),
        "mips": _architecture("mips", "mips", 32, "big"),
        "mipsel": _architecture("mipsel", "mips", 32, "little"),
        "mips64": _architecture("mips64", "mips64", 64, "big"),
        "mips64el": _architecture("mips64el", "mips64", 64, "little"),
        "mipsn32": _architecture("mipsn32", "mips64", 32, "big"),
        "mipsn32el": _architecture("mipsn32el", "mips64", 32, "little"),
        "nios2": _architecture("nios2", "nios2", 32, "little"),
        "or1k": _architecture("or1k", "or1k", 32, "big"),
        "ppc": _architecture("ppc", "powerpc", 32, "big", "powerpc"),
        "ppc64": _architecture("ppc64", "powerpc64", 64, "big"),
        "ppc64le": _architecture("ppc64le", "powerpc64", 64, "little", "ppc64el"),
        "riscv32": _architecture("riscv32", "riscv32", 32, "little"),
        "riscv64": _architecture("riscv64", "riscv64", 64, "little"),
        "s390x": _architecture("s390x", "s390", 64, "big"),
        "sh4": _architecture("sh4", "sh4", 32, "little"),
        "sh4eb": _architecture("sh4eb", "sh4", 32, "big"),
        "sparc": _architecture("sparc", "sparc", 32, "big"),
        "sparc32plus": _architecture("sparc32plus", "sparc", 32, "big"),
        "sparc64": _architecture("sparc64", "sparc64", 64, "big"),
        "x86_64": _architecture("x86_64", "amd64", 64, "little", "amd64"),
        "xtensa": _architecture("xtensa", "xtensa", 32, "little"),
        "xtensaeb": _architecture("xtensaeb", "xtensa", 32, "big"),
    }
)

_ARCH_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86": "i386",
        "i486": "i386",
        "i586": "i386",
        "i686": "i386",
        "arm64": "aarch64",
        "aarch64be": "aarch64_be",
        "aarch64-be": "aarch64_be",
        "armbe": "armeb",
        "mips32": "mips",
        "mips32el": "mipsel",
        "mips64le": "mips64el",
        "powerpc": "ppc",
        "powerpc32": "ppc",
        "powerpc64": "ppc64",
        "powerpc64le": "ppc64le",
        "ppc64el": "ppc64le",
        "riscv": "riscv64",
        "s390": "s390x",
        "sparc32": "sparc",
        "loong64": "loongarch64",
    }
)


@dataclass(frozen=True, slots=True)
class ElfIdentity:
    """The pwntools-derived execution identity of one ELF."""

    path: PathValue
    architecture: QemuArchitecture
    machine: str
    elf_type: str
    executable: bool
    statically_linked: bool
    native: bool

    @property
    def arch(self) -> str:
        return self.architecture.arch

    @property
    def bits(self) -> int:
        return self.architecture.bits

    @property
    def endian(self) -> Endian:
        return self.architecture.endian

    @property
    def qemu_arch(self) -> str:
        return self.architecture.qemu_arch


ArchitectureInput: TypeAlias = str | QemuArchitecture | ElfIdentity


def normalize_qemu_arch(architecture: ArchitectureInput) -> QemuArchitecture:
    """Resolve an architecture, qemu command, or ELF identity.

    Strings may be canonical suffixes (``aarch64_be``), common architecture
    aliases (``amd64``), or command names (``qemu-aarch64-static``).
    """

    if isinstance(architecture, ElfIdentity):
        return architecture.architecture
    if isinstance(architecture, QemuArchitecture):
        return architecture
    if not isinstance(architecture, str) or not architecture.strip():
        raise UnsupportedQemuArchitectureError("qemu-user architecture must be a non-empty string")

    name = os.path.basename(architecture.strip()).lower()
    name = name.removeprefix("qemu-").removesuffix("-static")
    name = _ARCH_ALIASES.get(name, name)
    try:
        return _ARCHITECTURES[name]
    except KeyError as exc:
        supported = ", ".join(sorted(_ARCHITECTURES))
        raise UnsupportedQemuArchitectureError(
            f"unsupported qemu-user architecture {architecture!r}; supported architectures: {supported}"
        ) from exc


def _mips_architecture(bits: int, endian: Endian, flags: int) -> QemuArchitecture:
    if bits == 64:
        return _ARCHITECTURES["mips64el" if endian == "little" else "mips64"]
    # EF_MIPS_ABI2 selects the n32 ABI: a 32-bit ELF class executed by the
    # MIPS64 n32 qemu-user binary.
    if flags & 0x20:
        return _ARCHITECTURES["mipsn32el" if endian == "little" else "mipsn32"]
    return _ARCHITECTURES["mipsel" if endian == "little" else "mips"]


def _elf_architecture(machine: str, arch: str, bits: int, endian: Endian, flags: int) -> QemuArchitecture:
    if machine in {"EM_386", "EM_486"}:
        return _ARCHITECTURES["i386"]
    if machine == "EM_X86_64":
        # QEMU's x86_64 linux-user target also executes the x32 ABI.
        return replace(_ARCHITECTURES["x86_64"], bits=bits)
    if machine == "EM_ARM":
        return _ARCHITECTURES["arm" if endian == "little" else "armeb"]
    if machine == "EM_AARCH64":
        return _ARCHITECTURES["aarch64" if endian == "little" else "aarch64_be"]
    if machine in {"EM_MIPS", "EM_MIPS_RS3_LE", "EM_MIPS_X"}:
        return _mips_architecture(bits, endian, flags)
    if machine == "EM_PPC":
        if endian == "little":
            raise UnsupportedQemuArchitectureError("qemu-user has no PowerPC32 little-endian linux-user target")
        return _ARCHITECTURES["ppc"]
    if machine == "EM_PPC64":
        return _ARCHITECTURES["ppc64le" if endian == "little" else "ppc64"]
    if machine == "EM_RISCV":
        return _ARCHITECTURES[f"riscv{bits}"]
    if machine == "EM_S390":
        return replace(_ARCHITECTURES["s390x"], bits=bits)
    if machine == "EM_SPARC":
        return _ARCHITECTURES["sparc"]
    if machine == "EM_SPARC32PLUS":
        return _ARCHITECTURES["sparc32plus"]
    if machine == "EM_SPARCV9":
        return _ARCHITECTURES["sparc64"]

    machine_map = {
        "EM_ALPHA": "alpha",
        "EM_68K": "m68k",
        "EM_CRIS": "cris",
        "EM_HEXAGON": "hexagon",
        "EM_PARISC": "hppa",
        "EM_LOONGARCH": "loongarch64",
        "EM_MICROBLAZE": "microblazeel" if endian == "little" else "microblaze",
        "EM_ALTERA_NIOS2": "nios2",
        "EM_OPENRISC": "or1k",
        "EM_SH": "sh4" if endian == "little" else "sh4eb",
        "EM_XTENSA": "xtensa" if endian == "little" else "xtensaeb",
    }
    if machine in machine_map:
        return _ARCHITECTURES[machine_map[machine]]

    matches = [
        candidate
        for candidate in _ARCHITECTURES.values()
        if candidate.arch == arch and candidate.bits == bits and candidate.endian == endian
    ]
    if len(matches) == 1:
        return matches[0]
    raise UnsupportedQemuArchitectureError(
        f"no qemu-user mapping for ELF machine={machine}, arch={arch}, bits={bits}, endian={endian}"
    )


def _pwntools_native(target: QemuArchitecture) -> bool:
    """Use pwntools' host normalization, then close its endian/width gaps."""

    try:
        with pwntools_context.local(
            arch=target.arch,
            bits=target.bits,
            endian=target.endian,
            os="linux",
            log_level="error",
        ):
            native = bool(pwntools_context.native)
    except (AttributeError, ValueError):
        try:
            host = normalize_qemu_arch(platform.machine())
        except UnsupportedQemuArchitectureError:
            return False
        native = host.arch == target.arch

    return native and target.endian == sys.byteorder and target.bits <= struct.calcsize("P") * 8


def inspect_elf(program: PathInput) -> ElfIdentity:
    """Inspect ``program`` with pwntools and return its qemu-user identity."""

    raw_path = os.fspath(program)
    absolute_path = os.path.abspath(raw_path)
    try:
        with pwntools_context.local(log_level="error"):
            elf = PwntoolsELF(os.fsdecode(absolute_path), checksec=False)
    except (ELFError, OSError, ValueError, TypeError) as exc:
        raise ElfInspectionError(f"cannot inspect ELF {os.fsdecode(absolute_path)!r}: {exc}") from exc

    try:
        machine = str(elf["e_machine"])
        arch = str(elf.arch).lower()
        bits = int(elf.bits)
        endian = str(elf.endian).lower()
        if endian not in {"little", "big"}:
            raise ElfInspectionError(f"ELF has unsupported byte order {endian!r}")
        flags = int(elf["e_flags"])
        target = _elf_architecture(machine, arch, bits, endian, flags)
        dynamic_flags_1 = elf.dynamic_value_by_tag("DT_FLAGS_1") or 0
        static_pie = str(elf.elftype) == "DYN" and bool(dynamic_flags_1 & 0x08000000) and elf.linker is None
        return ElfIdentity(
            path=absolute_path,
            architecture=target,
            machine=machine,
            elf_type=str(elf.elftype),
            # Pwntools 4.13 classifies ET_DYN solely through PT_INTERP and
            # therefore calls static PIE executables libraries.  DF_1_PIE is
            # the ABI marker which distinguishes this executable form.
            executable=bool(elf.executable or static_pie),
            statically_linked=bool(elf.statically_linked or static_pie),
            native=_pwntools_native(target),
        )
    except UnsupportedQemuArchitectureError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ElfInspectionError(f"cannot derive execution identity for {os.fsdecode(absolute_path)!r}: {exc}") from exc
    finally:
        elf.close()


def qemu_binary_names_for_arch(
    architecture: ArchitectureInput,
    *,
    static: bool | None = None,
) -> tuple[str, ...]:
    """Return ordered qemu-user command candidates for an architecture.

    ``static=False`` returns normal host commands, ``static=True`` returns
    ``*-static`` commands suitable for a read-only container mount, and
    ``None`` returns both with normal commands preferred.
    """

    if static is not None and not isinstance(static, bool):
        raise TypeError("static must be bool or None")
    target = normalize_qemu_arch(architecture)
    normal = tuple(f"qemu-{name}" for name in (target.qemu_arch, *target.executable_aliases))
    static_names = tuple(f"{name}-static" for name in normal)
    if static is True:
        return static_names
    if static is False:
        return normal
    return (*normal, *static_names)


def qemu_binary_names(identity: ArchitectureInput, *, static: bool | None = None) -> tuple[str, ...]:
    """ELF-friendly alias for :func:`qemu_binary_names_for_arch`."""

    return qemu_binary_names_for_arch(identity, static=static)


@dataclass(frozen=True, slots=True)
class QemuExecutable:
    """A locally validated, host-native qemu-user executable."""

    path: PathValue
    architecture: QemuArchitecture
    statically_linked: bool
    explicit: bool

    @property
    def name(self) -> str:
        return os.fsdecode(os.path.basename(self.path))


def _resolve_command(command: PathInput, search_path: PathInput | None) -> PathValue | None:
    raw = os.fspath(command)
    path = None if search_path is None else os.fspath(search_path)
    try:
        return shutil.which(raw, path=path)
    except TypeError:
        # ``shutil.which`` requires command and PATH to use the same text type.
        if isinstance(raw, bytes) and isinstance(path, str):
            return shutil.which(raw, path=os.fsencode(path))
        if isinstance(raw, str) and isinstance(path, bytes):
            return shutil.which(raw, path=os.fsdecode(path))
        raise


def _validate_qemu_executable(
    path: PathValue,
    target: QemuArchitecture,
    *,
    require_static: bool,
    explicit: bool,
) -> QemuExecutable:
    basename = os.fsdecode(os.path.basename(path))
    if basename.startswith("qemu-"):
        try:
            named_target = normalize_qemu_arch(basename)
        except UnsupportedQemuArchitectureError:
            # Explicit custom builds are commonly renamed with version or
            # challenge suffixes.  Their ELF can still be validated below;
            # the caller deliberately owns that override.
            named_target = None
        if named_target is not None and named_target.qemu_arch != target.qemu_arch:
            raise QemuNotFoundError(
                f"qemu-user executable {os.fsdecode(path)} targets {named_target.qemu_arch}, "
                f"not requested {target.qemu_arch}"
            )
    identity = inspect_elf(path)
    if not identity.executable:
        raise QemuNotFoundError(f"qemu-user candidate is not executable ELF code: {os.fsdecode(path)}")
    if not identity.native:
        raise QemuNotFoundError(
            f"qemu-user candidate is not native to this host: {os.fsdecode(path)} "
            f"({identity.arch}/{identity.bits}/{identity.endian})"
        )
    if require_static and not identity.statically_linked:
        raise QemuNotFoundError(f"container-mounted qemu-user executable is not static: {os.fsdecode(path)}")
    return QemuExecutable(path, target, identity.statically_linked, explicit)


def resolve_qemu(
    architecture: ArchitectureInput,
    *,
    executable: PathInput | None = None,
    static: bool | None = None,
    search_path: PathInput | None = None,
) -> QemuExecutable:
    """Resolve and validate a host-native qemu-user executable.

    An explicit command is still checked for executable ELF code, host-native
    architecture, and (when requested) static linkage.  ``static=True`` is the
    safe mode for mounting the host emulator into a challenge container.
    """

    if static is not None and not isinstance(static, bool):
        raise TypeError("static must be bool or None")
    target = normalize_qemu_arch(architecture)
    commands: Sequence[PathInput]
    explicit = executable is not None
    if explicit:
        commands = (executable,)
    else:
        commands = qemu_binary_names_for_arch(target, static=static)

    failures: list[str] = []
    for command in commands:
        resolved = _resolve_command(command, search_path)
        if resolved is None:
            continue
        try:
            return _validate_qemu_executable(
                resolved,
                target,
                require_static=static is True,
                explicit=explicit,
            )
        except (ElfInspectionError, QemuNotFoundError) as exc:
            failures.append(str(exc))

    requested = os.fsdecode(os.fspath(executable)) if explicit else ", ".join(os.fsdecode(x) for x in commands)
    suffix = f" ({'; '.join(failures)})" if failures else ""
    if static is True:
        hint = "; install qemu-user-static or provide a statically linked emulator"
    else:
        hint = "; install qemu-user or provide an explicit emulator"
    raise QemuNotFoundError(f"no usable qemu-user executable for {target.qemu_arch}: {requested}{suffix}{hint}")


@dataclass(frozen=True, slots=True)
class _LayoutRange:
    fixed: int
    random_min: int
    random_max: int
    alignment: int


_LAYOUT_32 = _LayoutRange(
    fixed=0x40000000,  # 1 GiB
    random_min=0x30000000,  # 768 MiB
    random_max=0x60000000,  # 1.5 GiB
    alignment=0x01000000,  # 16 MiB
)
_LAYOUT_64 = _LayoutRange(
    fixed=0x1000000000,  # 64 GiB
    random_min=0x0800000000,  # 32 GiB
    random_max=0x2000000000,  # 128 GiB
    alignment=0x40000000,  # 1 GiB
)


def _layout_range(target: QemuArchitecture) -> _LayoutRange:
    # QEMU's x86_64 linux-user target places the legacy vsyscall page above
    # every reservable userspace range and rejects non-zero -R.  Pretending
    # that -B or -seed randomizes guest addresses would be incorrect.
    if target.qemu_arch == "x86_64":
        raise GuestLayoutError(
            "qemu-x86_64 cannot safely control guest ASLR with -R because of its fixed vsyscall page; "
            "leave guest ASLR as None or use a QEMU build with an explicit guest-layout implementation"
        )
    return _LAYOUT_32 if target.bits <= 32 else _LAYOUT_64


@dataclass(frozen=True, slots=True)
class GuestLayout:
    """One explicit guest-visible qemu-user layout policy."""

    architecture: QemuArchitecture
    guest_aslr: bool | None
    reserved_va: int | None
    arguments: tuple[str, ...]

    @property
    def randomized(self) -> bool:
        return self.guest_aslr is True

    @property
    def stable(self) -> bool:
        return self.guest_aslr is False


def plan_guest_layout(
    architecture: ArchitectureInput,
    guest_aslr: bool | None,
    *,
    randbelow: Callable[[int], int] | None = None,
) -> GuestLayout:
    """Plan QEMU arguments for stable, randomized, or upstream guest layout."""

    if guest_aslr is not None and not isinstance(guest_aslr, bool):
        raise TypeError("guest_aslr must be bool or None")
    target = normalize_qemu_arch(architecture)
    if guest_aslr is None:
        return GuestLayout(target, None, None, ())

    limits = _layout_range(target)
    if guest_aslr is False:
        reserved_va = limits.fixed
    else:
        entropy = randbelow or secrets.randbelow
        slots = (limits.random_max - limits.random_min) // limits.alignment + 1
        selected = entropy(slots)
        if not isinstance(selected, int) or not 0 <= selected < slots:
            raise GuestLayoutError(f"layout entropy source returned out-of-range slot {selected!r} for {slots} slots")
        reserved_va = limits.random_min + selected * limits.alignment

    if reserved_va % limits.alignment:
        raise AssertionError("internal qemu-user reserved VA policy is not aligned")
    return GuestLayout(target, guest_aslr, reserved_va, ("-R", f"{reserved_va:#x}"))


def guest_layout_args(
    architecture: ArchitectureInput,
    qemu_aslr: bool | None,
    *,
    randbelow: Callable[[int], int] | None = None,
) -> tuple[str, ...]:
    """Return only the source-neutral QEMU guest-layout arguments."""

    return plan_guest_layout(architecture, qemu_aslr, randbelow=randbelow).arguments


_LIBRARY_TRIPLETS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "aarch64": ("aarch64-linux-gnu",),
        "aarch64_be": ("aarch64_be-linux-gnu",),
        "arm": ("arm-linux-gnueabihf", "arm-linux-gnueabi"),
        "armeb": ("armeb-linux-gnueabi",),
        "i386": ("i386-linux-gnu",),
        "x86_64": ("x86_64-linux-gnu",),
        "mips": ("mips-linux-gnu",),
        "mipsel": ("mipsel-linux-gnu",),
        "mips64": ("mips64-linux-gnuabi64",),
        "mips64el": ("mips64el-linux-gnuabi64",),
        "mipsn32": ("mips64-linux-gnuabin32",),
        "mipsn32el": ("mips64el-linux-gnuabin32",),
        "ppc": ("powerpc-linux-gnu",),
        "ppc64": ("powerpc64-linux-gnu",),
        "ppc64le": ("powerpc64le-linux-gnu",),
        "riscv32": ("riscv32-linux-gnu",),
        "riscv64": ("riscv64-linux-gnu",),
        "s390x": ("s390x-linux-gnu",),
        "sparc": ("sparc-linux-gnu",),
        "sparc32plus": ("sparc-linux-gnu",),
        "sparc64": ("sparc64-linux-gnu",),
    }
)


def infer_solib_search_path(sysroot: PathInput | None, architecture: ArchitectureInput) -> tuple[PathValue, ...]:
    """Infer conventional GDB shared-library directories beneath a sysroot."""

    if sysroot is None:
        return ()
    root = os.fspath(sysroot)
    target = normalize_qemu_arch(architecture)
    suffixes = ["lib", "usr/lib", "lib64", "usr/lib64"]
    for triplet in _LIBRARY_TRIPLETS.get(target.qemu_arch, ()):
        suffixes.extend((f"lib/{triplet}", f"usr/lib/{triplet}"))

    result: list[PathValue] = []
    for suffix in suffixes:
        encoded_suffix: PathValue = os.fsencode(suffix) if isinstance(root, bytes) else suffix
        candidate = os.path.normpath(os.path.join(root, encoded_suffix))
        if candidate not in result:
            result.append(candidate)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class QemuLaunch:
    """A side-effect-free qemu-user launch plan.

    ``env`` is a QEMU-only environment *delta*, not a copy of the host
    environment.  The current planner uses command-line options exclusively,
    so callers can pass the target's exact environment (including an empty or
    bytes-valued mapping) to their process API without an implicit host merge.
    ``host_aslr`` is retained as metadata for the launcher/shim and is never
    implemented by mutating the host-wide ASLR sysctl.
    """

    identity: ElfIdentity
    emulator: QemuExecutable
    layout: GuestLayout
    program: PathValue
    arguments: tuple[Argument, ...]
    argv: tuple[Argument, ...]
    env: Mapping[Argument, Argument] = field(default_factory=lambda: MappingProxyType({}))
    sysroot: PathValue | None = None
    solib_search_path: tuple[PathValue, ...] = ()
    gdb_endpoint: Argument | None = None
    starts_stopped: bool = False
    host_aslr: bool | None = None


def _argument(value: object) -> Argument:
    if isinstance(value, (str, bytes)):
        return value
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    return str(value)


def plan_qemu(
    program: PathInput,
    *arguments: object,
    executable: PathInput | None = None,
    static: bool | None = None,
    search_path: PathInput | None = None,
    sysroot: PathInput | None = None,
    qemu_aslr: bool | None = None,
    gdb: str | bytes | int | os.PathLike[str] | os.PathLike[bytes] | None = None,
    host_aslr: bool | None = None,
    randbelow: Callable[[int], int] | None = None,
) -> QemuLaunch:
    """Inspect a guest ELF and produce an exact qemu-user argv.

    Supplying ``gdb`` emits QEMU's ``-g endpoint`` option.  qemu-user creates
    the endpoint, waits for the debugger, and therefore stops before the first
    guest instruction.  A raw filesystem path is the Unix-socket syntax used
    by current QEMU; probing that socket would consume its single debugger
    connection, so endpoint readiness belongs to the GDB transport layer.
    """

    if host_aslr is not None and not isinstance(host_aslr, bool):
        raise TypeError("host_aslr must be bool or None")
    identity = inspect_elf(program)
    if not identity.executable:
        raise ElfInspectionError(f"ELF is not executable: {os.fsdecode(identity.path)}")
    emulator = resolve_qemu(
        identity,
        executable=executable,
        static=static,
        search_path=search_path,
    )
    layout = plan_guest_layout(identity, qemu_aslr, randbelow=randbelow)
    target_arguments = tuple(_argument(argument) for argument in arguments)

    argv: list[Argument] = [_argument(emulator.path)]
    endpoint: Argument | None = None
    if gdb is not None:
        endpoint = str(gdb) if isinstance(gdb, int) else _argument(gdb)
        if endpoint in {"", b""}:
            raise ValueError("gdb endpoint cannot be empty")
        argv.extend(("-g", endpoint))
    argv.extend(layout.arguments)

    resolved_sysroot: PathValue | None = None
    if sysroot is not None:
        resolved_sysroot = os.fspath(sysroot)
        argv.extend(("-L", resolved_sysroot))
    argv.extend((identity.path, *target_arguments))

    return QemuLaunch(
        identity=identity,
        emulator=emulator,
        layout=layout,
        program=identity.path,
        arguments=target_arguments,
        argv=tuple(argv),
        sysroot=resolved_sysroot,
        solib_search_path=infer_solib_search_path(resolved_sysroot, identity),
        gdb_endpoint=endpoint,
        starts_stopped=endpoint is not None,
        host_aslr=host_aslr,
    )


__all__ = [
    "ElfIdentity",
    "ElfInspectionError",
    "GuestLayout",
    "GuestLayoutError",
    "QemuArchitecture",
    "QemuExecutable",
    "QemuLaunch",
    "QemuNotFoundError",
    "QemuUserError",
    "UnsupportedQemuArchitectureError",
    "guest_layout_args",
    "infer_solib_search_path",
    "inspect_elf",
    "normalize_qemu_arch",
    "plan_guest_layout",
    "plan_qemu",
    "qemu_binary_names",
    "qemu_binary_names_for_arch",
    "resolve_qemu",
]
