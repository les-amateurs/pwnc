"""Architecture, ABI, endian, and word-packing definitions.

The rest of :mod:`payloads` only accepts a resolved :class:`Target`.  This is
intentional: an architecture name alone is insufficient for MIPS, ARM, and
PowerPC payloads, where byte order or ABI changes the emitted bytes and calling
convention.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from pwnlib.context import context as pwntools_context
from pwnlib.util.packing import pack as pwntools_pack
from pwnlib.util.packing import unpack as pwntools_unpack

from .errors import UnsupportedTargetError


class Endian(str, Enum):
    LITTLE = "little"
    BIG = "big"


class Architecture(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    THUMB = "thumb"
    ARM64 = "arm64"
    MIPS32 = "mips32"
    MIPS64 = "mips64"
    RISCV32 = "riscv32"
    RISCV64 = "riscv64"
    POWERPC32 = "powerpc32"
    POWERPC64 = "powerpc64"
    SPARC32 = "sparc32"
    SPARC64 = "sparc64"
    S390X = "s390x"


class ABI(str, Enum):
    I386_SYSV = "i386-sysv"
    AMD64_SYSV = "amd64-sysv"
    ARM_EABI = "arm-eabi"
    AARCH64_AAPCS = "aarch64-aapcs64"
    MIPS_O32 = "mips-o32"
    MIPS_N64 = "mips-n64"
    RISCV_ILP32 = "riscv-ilp32"
    RISCV_LP64 = "riscv-lp64"
    POWERPC_SYSV = "powerpc-sysv"
    POWERPC64_ELFV1 = "powerpc64-elfv1"
    POWERPC64_ELFV2 = "powerpc64-elfv2"
    SPARC_SYSV = "sparc-sysv"
    SPARC64_SYSV = "sparc64-sysv"
    S390X_SYSV = "s390x-sysv"


class FunctionPointerModel(str, Enum):
    RAW_CODE_ADDRESS = "raw-code-address"
    THUMB_STATE_BIT = "thumb-state-bit"
    PPC64_ELFV1_DESCRIPTOR = "ppc64-elfv1-descriptor"


@dataclass(frozen=True, slots=True)
class CallingConvention:
    """Registers and alignment needed by function-call and syscall builders."""

    function_arguments: tuple[str, ...]
    return_value: str
    stack_pointer: str
    program_counter: str
    link_register: str | None
    syscall_number: str
    syscall_arguments: tuple[str, ...]
    syscall_instruction: str
    stack_alignment: int


@dataclass(frozen=True, slots=True)
class Target:
    """A fully specified Linux target.

    ``pwntools_arch`` and ``zig_target`` are backend identifiers; consumers do
    not need to translate the public architecture names themselves.
    """

    arch: Architecture
    bits: int
    endian: Endian
    abi: ABI
    convention: CallingConvention
    pwntools_arch: str
    zig_target: str
    os: str = "linux"
    function_pointer_model: FunctionPointerModel = FunctionPointerModel.RAW_CODE_ADDRESS

    @property
    def word_size(self) -> int:
        return self.bits // 8

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    @property
    def name(self) -> str:
        suffix = "le" if self.endian is Endian.LITTLE else "be"
        return f"{self.arch.value}-{suffix}-{self.abi.value}"

    def local_context(self):
        """Return an isolated pwntools context for this exact target.

        Pwntools owns useful packing, ELF, ROP, and shellcraft machinery, but
        its process-global context must not leak between builders.  Callers
        should use this as a context manager::

            with target.local_context():
                ...

        The stricter :class:`Target` still owns ABI distinctions which a
        pwntools architecture name alone cannot express (MIPS o32/n64,
        PPC64 ELFv1/v2, and ARM-vs-Thumb function pointers).
        """

        return pwntools_context.local(
            arch=self.pwntools_arch,
            bits=self.bits,
            endian=self.endian.value,
            os=self.os,
        )

    def pack(self, value: int, *, signed: bool = False, truncate: bool = False) -> bytes:
        """Pack one target-width integer.

        Values are checked by default.  ``truncate=True`` is available for
        deliberate two's-complement constants such as ``-1`` or masked gadget
        values, but must be requested explicitly so accidental 32/64-bit
        mismatches are visible.
        """

        if not isinstance(value, int):
            raise TypeError(f"word must be int, got {type(value).__name__}")
        if truncate:
            value &= self.mask
            signed = False
        try:
            with self.local_context():
                return pwntools_pack(
                    value,
                    word_size=self.bits,
                    endianness=self.endian.value,
                    sign=signed,
                )
        except (OverflowError, ValueError) as exc:
            raise OverflowError(f"{value:#x} does not fit {self.bits}-bit {self.name}") from exc

    def unpack(self, data: bytes, *, signed: bool = False) -> int:
        if len(data) != self.word_size:
            raise ValueError(f"expected exactly {self.word_size} bytes, got {len(data)}")
        with self.local_context():
            return pwntools_unpack(
                data,
                word_size=self.bits,
                endianness=self.endian.value,
                sign=signed,
            )

    def pack_words(self, words: Iterable[int], *, truncate: bool = False) -> bytes:
        return b"".join(self.pack(word, truncate=truncate) for word in words)

    def entry_address(self, address: int) -> int:
        """Return an ISA-correct raw code entry address."""

        return address | 1 if self.function_pointer_model is FunctionPointerModel.THUMB_STATE_BIT else address

    def function_pointer(self, address: int) -> int:
        """Return an ABI-correct callable function pointer.

        Thumb uses bit zero to select instruction state.  PPC64 ELFv1 function
        symbols are descriptors rather than direct PCs and therefore cannot be
        converted without reading the descriptor and restoring its TOC value.
        """

        if self.function_pointer_model is FunctionPointerModel.THUMB_STATE_BIT:
            return address | 1
        if self.function_pointer_model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR:
            raise UnsupportedTargetError("PPC64 ELFv1 calls require a function descriptor and TOC-aware primitive")
        return address


def _cc(
    function_arguments: tuple[str, ...],
    return_value: str,
    stack_pointer: str,
    program_counter: str,
    link_register: str | None,
    syscall_number: str,
    syscall_arguments: tuple[str, ...],
    syscall_instruction: str,
    stack_alignment: int,
) -> CallingConvention:
    return CallingConvention(
        function_arguments=function_arguments,
        return_value=return_value,
        stack_pointer=stack_pointer,
        program_counter=program_counter,
        link_register=link_register,
        syscall_number=syscall_number,
        syscall_arguments=syscall_arguments,
        syscall_instruction=syscall_instruction,
        stack_alignment=stack_alignment,
    )


_I386 = _cc((), "eax", "esp", "eip", None, "eax", ("ebx", "ecx", "edx", "esi", "edi", "ebp"), "int 0x80", 16)
_AMD64 = _cc(
    ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "rax",
    "rsp",
    "rip",
    None,
    "rax",
    ("rdi", "rsi", "rdx", "r10", "r8", "r9"),
    "syscall",
    16,
)
_ARM = _cc(
    ("r0", "r1", "r2", "r3"), "r0", "sp", "pc", "lr", "r7", ("r0", "r1", "r2", "r3", "r4", "r5", "r6"), "svc 0", 8
)
_AARCH64 = _cc(
    tuple(f"x{i}" for i in range(8)), "x0", "sp", "pc", "x30", "x8", tuple(f"x{i}" for i in range(6)), "svc 0", 16
)
_MIPS32 = _cc(("a0", "a1", "a2", "a3"), "v0", "sp", "pc", "ra", "v0", ("a0", "a1", "a2", "a3"), "syscall", 8)
_MIPS64 = _cc(
    tuple(f"a{i}" for i in range(8)), "v0", "sp", "pc", "ra", "v0", tuple(f"a{i}" for i in range(6)), "syscall", 16
)
_RISCV32 = _cc(
    tuple(f"a{i}" for i in range(8)), "a0", "sp", "pc", "ra", "a7", tuple(f"a{i}" for i in range(6)), "ecall", 16
)
_RISCV64 = _RISCV32
_PPC32 = _cc(
    tuple(f"r{i}" for i in range(3, 11)), "r3", "r1", "pc", "lr", "r0", tuple(f"r{i}" for i in range(3, 9)), "sc", 16
)
_PPC64 = _cc(
    tuple(f"r{i}" for i in range(3, 11)), "r3", "r1", "pc", "lr", "r0", tuple(f"r{i}" for i in range(3, 9)), "sc", 16
)
_SPARC32 = _cc(
    tuple(f"o{i}" for i in range(6)), "o0", "sp", "pc", "o7", "g1", tuple(f"o{i}" for i in range(6)), "ta 0x10", 8
)
_SPARC64 = _cc(
    tuple(f"o{i}" for i in range(6)), "o0", "sp", "pc", "o7", "g1", tuple(f"o{i}" for i in range(6)), "ta 0x6d", 16
)
_S390X = _cc(
    ("r2", "r3", "r4", "r5", "r6"), "r2", "r15", "psw", "r14", "r1", ("r2", "r3", "r4", "r5", "r6", "r7"), "svc 0", 8
)


def _target(
    arch: Architecture,
    bits: int,
    endian: Endian,
    abi: ABI,
    convention: CallingConvention,
    pwntools_arch: str,
    zig_target: str,
    function_pointer_model: FunctionPointerModel = FunctionPointerModel.RAW_CODE_ADDRESS,
) -> Target:
    return Target(
        arch,
        bits,
        endian,
        abi,
        convention,
        pwntools_arch,
        zig_target,
        function_pointer_model=function_pointer_model,
    )


SUPPORTED_TARGETS: tuple[Target, ...] = (
    _target(Architecture.X86, 32, Endian.LITTLE, ABI.I386_SYSV, _I386, "i386", "x86-linux-none"),
    _target(Architecture.X86_64, 64, Endian.LITTLE, ABI.AMD64_SYSV, _AMD64, "amd64", "x86_64-linux-none"),
    _target(Architecture.ARM, 32, Endian.LITTLE, ABI.ARM_EABI, _ARM, "arm", "arm-linux-none"),
    _target(Architecture.ARM, 32, Endian.BIG, ABI.ARM_EABI, _ARM, "arm", "armeb-linux-none"),
    _target(
        Architecture.THUMB,
        32,
        Endian.LITTLE,
        ABI.ARM_EABI,
        _ARM,
        "thumb",
        "thumb-linux-none",
        FunctionPointerModel.THUMB_STATE_BIT,
    ),
    _target(
        Architecture.THUMB,
        32,
        Endian.BIG,
        ABI.ARM_EABI,
        _ARM,
        "thumb",
        "thumbeb-linux-none",
        FunctionPointerModel.THUMB_STATE_BIT,
    ),
    _target(Architecture.ARM64, 64, Endian.LITTLE, ABI.AARCH64_AAPCS, _AARCH64, "aarch64", "aarch64-linux-none"),
    _target(Architecture.ARM64, 64, Endian.BIG, ABI.AARCH64_AAPCS, _AARCH64, "aarch64", "aarch64_be-linux-none"),
    _target(Architecture.MIPS32, 32, Endian.LITTLE, ABI.MIPS_O32, _MIPS32, "mips", "mipsel-linux-none"),
    _target(Architecture.MIPS32, 32, Endian.BIG, ABI.MIPS_O32, _MIPS32, "mips", "mips-linux-none"),
    _target(Architecture.MIPS64, 64, Endian.LITTLE, ABI.MIPS_N64, _MIPS64, "mips64", "mips64el-linux-none"),
    _target(Architecture.MIPS64, 64, Endian.BIG, ABI.MIPS_N64, _MIPS64, "mips64", "mips64-linux-none"),
    _target(Architecture.RISCV32, 32, Endian.LITTLE, ABI.RISCV_ILP32, _RISCV32, "riscv32", "riscv32-linux-none"),
    _target(Architecture.RISCV64, 64, Endian.LITTLE, ABI.RISCV_LP64, _RISCV64, "riscv64", "riscv64-linux-none"),
    _target(Architecture.POWERPC32, 32, Endian.BIG, ABI.POWERPC_SYSV, _PPC32, "powerpc", "powerpc-linux-none"),
    _target(Architecture.POWERPC32, 32, Endian.LITTLE, ABI.POWERPC_SYSV, _PPC32, "powerpc", "powerpcle-linux-none"),
    _target(
        Architecture.POWERPC64,
        64,
        Endian.BIG,
        ABI.POWERPC64_ELFV1,
        _PPC64,
        "powerpc64",
        "powerpc64-linux-none",
        FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR,
    ),
    _target(
        Architecture.POWERPC64,
        64,
        Endian.LITTLE,
        ABI.POWERPC64_ELFV2,
        _PPC64,
        "powerpc64",
        "powerpc64le-linux-none",
    ),
    _target(Architecture.SPARC32, 32, Endian.BIG, ABI.SPARC_SYSV, _SPARC32, "sparc", "sparc-linux-none"),
    _target(Architecture.SPARC64, 64, Endian.BIG, ABI.SPARC64_SYSV, _SPARC64, "sparc64", "sparc64-linux-none"),
    _target(Architecture.S390X, 64, Endian.BIG, ABI.S390X_SYSV, _S390X, "s390", "s390x-linux-none"),
)


_ARCH_ALIASES: dict[str, Architecture] = {
    "x86": Architecture.X86,
    "i386": Architecture.X86,
    "i486": Architecture.X86,
    "i586": Architecture.X86,
    "i686": Architecture.X86,
    "x86_64": Architecture.X86_64,
    "x86-64": Architecture.X86_64,
    "amd64": Architecture.X86_64,
    "arm": Architecture.ARM,
    "arm32": Architecture.ARM,
    "armeb": Architecture.ARM,
    "thumb": Architecture.THUMB,
    "thumbeb": Architecture.THUMB,
    "arm64": Architecture.ARM64,
    "aarch64": Architecture.ARM64,
    "aarch64_be": Architecture.ARM64,
    "mips": Architecture.MIPS32,
    "mips32": Architecture.MIPS32,
    "mipsel": Architecture.MIPS32,
    "mipseb": Architecture.MIPS32,
    "mips64": Architecture.MIPS64,
    "mips64el": Architecture.MIPS64,
    "mips64eb": Architecture.MIPS64,
    "riscv32": Architecture.RISCV32,
    "rv32": Architecture.RISCV32,
    "riscv64": Architecture.RISCV64,
    "rv64": Architecture.RISCV64,
    "powerpc": Architecture.POWERPC32,
    "powerpc32": Architecture.POWERPC32,
    "ppc": Architecture.POWERPC32,
    "ppc32": Architecture.POWERPC32,
    "powerpcle": Architecture.POWERPC32,
    "ppcle": Architecture.POWERPC32,
    "powerpc64": Architecture.POWERPC64,
    "ppc64": Architecture.POWERPC64,
    "powerpc64le": Architecture.POWERPC64,
    "ppc64le": Architecture.POWERPC64,
    "sparc": Architecture.SPARC32,
    "sparc32": Architecture.SPARC32,
    "sparc64": Architecture.SPARC64,
    "s390x": Architecture.S390X,
    "s390": Architecture.S390X,
}

_BIG_ENDIAN_ALIASES = {
    "armeb",
    "thumbeb",
    "aarch64_be",
    "mipseb",
    "mips64eb",
}
_LITTLE_ENDIAN_ALIASES = {"mipsel", "mips64el", "powerpcle", "ppcle", "powerpc64le", "ppc64le"}


def resolve_target(
    architecture: str | Architecture,
    *,
    bits: int | None = None,
    endian: str | Endian | None = None,
    abi: str | ABI | None = None,
) -> Target:
    """Resolve aliases plus optional constraints to exactly one target.

    Ambiguous names use common CTF defaults: ARM/MIPS are little-endian while
    PowerPC/SPARC/S390 are big-endian.  Explicit endian aliases (``mipsel``,
    ``armeb``, ``ppc64le``) always win unless a conflicting ``endian=`` is
    supplied, which raises instead of silently changing the target.
    """

    raw = architecture.value if isinstance(architecture, Architecture) else str(architecture).strip().lower()
    try:
        arch = architecture if isinstance(architecture, Architecture) else _ARCH_ALIASES[raw]
    except KeyError as exc:
        raise UnsupportedTargetError(f"unknown architecture {architecture!r}") from exc

    implied_endian: Endian | None = None
    if raw in _BIG_ENDIAN_ALIASES:
        implied_endian = Endian.BIG
    elif raw in _LITTLE_ENDIAN_ALIASES:
        implied_endian = Endian.LITTLE

    requested_endian = Endian(endian) if endian is not None else implied_endian
    if endian is not None and implied_endian is not None and Endian(endian) is not implied_endian:
        raise UnsupportedTargetError(f"alias {raw!r} conflicts with endian={Endian(endian).value!r}")

    requested_abi = ABI(abi) if abi is not None else None
    candidates = [target for target in SUPPORTED_TARGETS if target.arch is arch]
    if bits is not None:
        candidates = [target for target in candidates if target.bits == bits]
    if requested_endian is not None:
        candidates = [target for target in candidates if target.endian is requested_endian]
    if requested_abi is not None:
        candidates = [target for target in candidates if target.abi is requested_abi]

    if not candidates:
        details = f"arch={arch.value}, bits={bits}, endian={endian}, abi={abi}"
        raise UnsupportedTargetError(f"unsupported target combination: {details}")
    if len(candidates) == 1:
        return candidates[0]

    # Defaults are deliberately centralized here, never inferred downstream.
    default_endian = (
        Endian.BIG
        if arch
        in {
            Architecture.POWERPC32,
            Architecture.POWERPC64,
            Architecture.SPARC32,
            Architecture.SPARC64,
            Architecture.S390X,
        }
        else Endian.LITTLE
    )
    defaults = [target for target in candidates if target.endian is default_endian]
    if arch is Architecture.POWERPC64:
        preferred_abi = ABI.POWERPC64_ELFV1 if default_endian is Endian.BIG else ABI.POWERPC64_ELFV2
        defaults = [target for target in defaults if target.abi is preferred_abi]
    if len(defaults) == 1:
        return defaults[0]
    names = ", ".join(target.name for target in candidates)
    raise UnsupportedTargetError(f"target is ambiguous; choose endian/ABI from: {names}")


__all__ = [
    "ABI",
    "SUPPORTED_TARGETS",
    "Architecture",
    "CallingConvention",
    "Endian",
    "FunctionPointerModel",
    "Target",
    "resolve_target",
]
