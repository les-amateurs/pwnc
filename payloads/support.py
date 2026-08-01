"""Machine-readable, evidence-based payload support coverage.

``SUPPORTED_TARGETS`` describes targets that the foundation can resolve and
pack.  It does *not* imply that every payload builder accepts every target.
This module keeps that distinction explicit and records end-to-end QEMU
coverage separately from implementation coverage.

The matrix is intentionally declarative.  Adding a builder is not enough to
change a claim here: its implemented target set and, separately, its QEMU test
evidence must be added below.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from .target import ABI, SUPPORTED_TARGETS, Endian, Target, resolve_target

SUPPORT_SCHEMA_VERSION = 1


class Capability(str, Enum):
    """Payload operations tracked by the public support contract."""

    COMMAND = "command"
    ORW = "orw"
    STAGER = "stager"
    RET2LIBC = "ret2libc"
    STATIC_ROP = "static-rop"
    ARB_EXECUTOR = "arb-executor"


class SupportLevel(str, Enum):
    """Highest evidenced level for a target/capability pair.

    ``RECOGNIZED`` only means the target model knows the architecture, word
    width, byte order, and ABI.  It explicitly does not mean a builder exists.
    ``IMPLEMENTED`` means a builder exists for the pair.  ``QEMU_VERIFIED``
    additionally means an opt-in end-to-end QEMU execution test covers it.
    """

    RECOGNIZED = "recognized"
    IMPLEMENTED = "implemented"
    QEMU_VERIFIED = "qemu-verified"


@dataclass(frozen=True, slots=True)
class CapabilitySupport:
    """One evidence-bearing cell in the support matrix."""

    level: SupportLevel
    detail: str
    evidence: tuple[str, ...]

    @property
    def recognized(self) -> bool:
        return True

    @property
    def implemented(self) -> bool:
        return self.level in {SupportLevel.IMPLEMENTED, SupportLevel.QEMU_VERIFIED}

    @property
    def qemu_verified(self) -> bool:
        return self.level is SupportLevel.QEMU_VERIFIED

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation with explicit booleans."""

        return {
            "level": self.level.value,
            "recognized": self.recognized,
            "implemented": self.implemented,
            "qemu_verified": self.qemu_verified,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class TargetSupport:
    """Coverage for one exact architecture/bits/endian/ABI target."""

    target: Target
    capabilities: Mapping[Capability, CapabilitySupport]

    def __post_init__(self) -> None:
        missing = set(Capability).difference(self.capabilities)
        extra = set(self.capabilities).difference(Capability)
        if missing or extra:
            raise ValueError(f"capability coverage must be exact; missing={missing!r}, extra={extra!r}")
        object.__setattr__(self, "capabilities", MappingProxyType(dict(self.capabilities)))

    def as_dict(self) -> dict[str, Any]:
        """Return this row as JSON-serializable target metadata and cells."""

        return {
            "name": self.target.name,
            "architecture": self.target.arch.value,
            "bits": self.target.bits,
            "endian": self.target.endian.value,
            "abi": self.target.abi.value,
            "capabilities": {capability.value: self.capabilities[capability].as_dict() for capability in Capability},
        }


# These are the exact variants exercised by CommandQemuTests for command, ORW,
# and mmap-stager shellcode.  PowerPC, SPARC, and s390x are recognized targets,
# but all three lowering entry points reject them.
_PRIMARY_SHELLCODE_QEMU_VERIFIED = frozenset(
    {
        "x86-le-i386-sysv",
        "x86_64-le-amd64-sysv",
        "arm-le-arm-eabi",
        "arm-be-arm-eabi",
        "thumb-le-arm-eabi",
        "thumb-be-arm-eabi",
        "arm64-le-aarch64-aapcs64",
        "arm64-be-aarch64-aapcs64",
        "mips32-le-mips-o32",
        "mips32-be-mips-o32",
        "mips64-le-mips-n64",
        "mips64-be-mips-n64",
        "riscv32-le-riscv-ilp32",
        "riscv64-le-riscv-lp64",
    }
)

_ALL_TARGET_NAMES = frozenset(target.name for target in SUPPORTED_TARGETS)
_DIRECT_CALL_UNSUPPORTED = frozenset(
    {
        "powerpc64-be-powerpc64-elfv1",
        "sparc32-be-sparc-sysv",
        "sparc64-be-sparc64-sysv",
    }
)
_DIRECT_CALL_IMPLEMENTED = _ALL_TARGET_NAMES - _DIRECT_CALL_UNSUPPORTED


_IMPLEMENTED: Mapping[Capability, frozenset[str]] = MappingProxyType(
    {
        Capability.COMMAND: _PRIMARY_SHELLCODE_QEMU_VERIFIED,
        Capability.ORW: _PRIMARY_SHELLCODE_QEMU_VERIFIED,
        Capability.STAGER: _PRIMARY_SHELLCODE_QEMU_VERIFIED,
        Capability.RET2LIBC: _DIRECT_CALL_IMPLEMENTED,
        Capability.STATIC_ROP: _ALL_TARGET_NAMES,
        Capability.ARB_EXECUTOR: _ALL_TARGET_NAMES,
    }
)

_QEMU_VERIFIED: Mapping[Capability, frozenset[str]] = MappingProxyType(
    {
        Capability.COMMAND: _PRIMARY_SHELLCODE_QEMU_VERIFIED,
        Capability.ORW: _PRIMARY_SHELLCODE_QEMU_VERIFIED,
        Capability.STAGER: _PRIMARY_SHELLCODE_QEMU_VERIFIED,
        Capability.RET2LIBC: frozenset(),
        Capability.STATIC_ROP: frozenset(),
        Capability.ARB_EXECUTOR: frozenset(),
    }
)

_IMPLEMENTATION_EVIDENCE: Mapping[Capability, tuple[str, ...]] = MappingProxyType(
    {
        Capability.COMMAND: ("payloads.shellcode.command_shellcode",),
        Capability.ORW: ("payloads.shellcode.orw_shellcode",),
        Capability.STAGER: ("payloads.shellcode.mmap_stager",),
        Capability.RET2LIBC: ("payloads.rop.build_ret2libc_system",),
        Capability.STATIC_ROP: (
            "payloads.rop.build_static_call",
            "payloads.rop.build_static_syscall",
        ),
        Capability.ARB_EXECUTOR: (
            "payloads.arbio.ArbitraryMemory",
            "payloads.arbio.PayloadStager",
            "payloads.arbio.ExecveCallWorkflow",
            "payloads.arbio.GotSystemWorkflow",
        ),
    }
)

_QEMU_EVIDENCE: Mapping[Capability, str] = MappingProxyType(
    {
        Capability.COMMAND: (
            "payloads/tests/test_shellcode_qemu.py::"
            "CommandQemuTests.test_raw_command_shellcode_executes_on_every_primary_target"
        ),
        Capability.ORW: (
            "payloads/tests/test_shellcode_qemu.py::CommandQemuTests.test_raw_orw_shellcode_preserves_binary_file_bytes"
        ),
        Capability.STAGER: (
            "payloads/tests/test_shellcode_qemu.py::CommandQemuTests.test_rw_to_rx_mmap_stager_runs_exact_second_stage"
        ),
        Capability.RET2LIBC: "no QEMU execution test in current tree",
        Capability.STATIC_ROP: "no QEMU execution test in current tree",
        Capability.ARB_EXECUTOR: "no QEMU execution test in current tree",
    }
)

_UNIMPLEMENTED_DETAIL: Mapping[Capability, str] = MappingProxyType(
    {
        Capability.COMMAND: "target is recognized, but command shellcode lowering is not implemented",
        Capability.ORW: "target is recognized, but no open/read/write shellcode builder is implemented",
        Capability.STAGER: "target is recognized, but mmap/read/mprotect shellcode lowering is not implemented",
        Capability.RET2LIBC: "target is recognized, but its ABI is not supported by the ret2libc call builder",
        Capability.STATIC_ROP: "target is recognized, but no static-binary ROP builder is implemented",
        Capability.ARB_EXECUTOR: "target is recognized, but no arbitrary-read/write executor is implemented",
    }
)


def _implemented_detail(target: Target, capability: Capability) -> str:
    if capability is Capability.COMMAND:
        return "position-independent /bin/sh -c command shellcode builder exists"
    if capability is Capability.ORW:
        return "position-independent one-pass open/read/write shellcode builder exists"
    if capability is Capability.STAGER:
        return "position-independent mmap/read/mprotect/cache-finalize/jump stager exists"
    if capability is Capability.RET2LIBC:
        return "symbolic system(command) chain builder exists and requires offsets from one exact LibcImage"
    if capability is Capability.STATIC_ROP:
        if target.name in _DIRECT_CALL_UNSUPPORTED:
            return "symbolic static syscall chains are implemented; direct function calls are unsupported for this ABI"
        return "symbolic static function-call and syscall chain builders exist for caller-supplied semantic gadgets"
    if capability is Capability.ARB_EXECUTOR:
        return (
            "target-endian arbitrary-memory adapters, explicit payload staging/triggering, "
            "and exact-libc call workflows exist"
        )
    raise AssertionError(f"unhandled capability {capability.value}")


def _unimplemented_detail(target: Target, capability: Capability) -> str:
    if capability is Capability.RET2LIBC and target.name == "powerpc64-be-powerpc64-elfv1":
        return (
            "target is recognized, but ret2libc direct calls require an ELFv1 function-descriptor reader "
            "and a TOC-restoring call primitive"
        )
    if capability is Capability.RET2LIBC and target.name in {
        "sparc32-be-sparc-sysv",
        "sparc64-be-sparc64-sysv",
    }:
        return "target is recognized, but SPARC register windows and o7+8 returns need a target-specific call frame"
    return _UNIMPLEMENTED_DETAIL[capability]


def _capability_support(target: Target, capability: Capability) -> CapabilitySupport:
    name = target.name
    qemu_verified = name in _QEMU_VERIFIED[capability]
    implemented = name in _IMPLEMENTED[capability]
    if qemu_verified and not implemented:  # pragma: no cover - declaration invariant
        raise RuntimeError(f"{capability.value}/{name} cannot be QEMU-verified without an implementation")

    evidence = ["payloads.target.SUPPORTED_TARGETS"]
    if implemented:
        evidence.extend(_IMPLEMENTATION_EVIDENCE[capability])
    if qemu_verified:
        evidence.append(_QEMU_EVIDENCE[capability])
        return CapabilitySupport(
            SupportLevel.QEMU_VERIFIED,
            "builder exists and raw payload execution is covered by the opt-in QEMU test",
            tuple(evidence),
        )
    if implemented:
        return CapabilitySupport(
            SupportLevel.IMPLEMENTED,
            _implemented_detail(target, capability)
            + "; no end-to-end QEMU execution test covers this target/capability pair",
            tuple(evidence),
        )
    return CapabilitySupport(SupportLevel.RECOGNIZED, _unimplemented_detail(target, capability), tuple(evidence))


SUPPORT_MATRIX: Mapping[str, TargetSupport] = MappingProxyType(
    {
        target.name: TargetSupport(
            target,
            {capability: _capability_support(target, capability) for capability in Capability},
        )
        for target in SUPPORTED_TARGETS
    }
)


def target_support(
    target: Target | str,
    *,
    bits: int | None = None,
    endian: str | Endian | None = None,
    abi: str | ABI | None = None,
) -> TargetSupport:
    """Return one row by :class:`Target`, canonical name, or target alias."""

    if isinstance(target, Target):
        resolved = target
    elif target in SUPPORT_MATRIX and bits is None and endian is None and abi is None:
        return SUPPORT_MATRIX[target]
    else:
        resolved = resolve_target(target, bits=bits, endian=endian, abi=abi)
    try:
        return SUPPORT_MATRIX[resolved.name]
    except KeyError as exc:
        raise KeyError(f"target {resolved.name!r} is not in the support matrix") from exc


def capability_support(
    target: Target | str,
    capability: Capability | str,
    *,
    bits: int | None = None,
    endian: str | Endian | None = None,
    abi: str | ABI | None = None,
) -> CapabilitySupport:
    """Query one target/capability pair."""

    selected = capability if isinstance(capability, Capability) else Capability(capability)
    return target_support(target, bits=bits, endian=endian, abi=abi).capabilities[selected]


def support_matrix_data() -> dict[str, Any]:
    """Return the complete versioned matrix using only JSON-native values."""

    return {
        "schema_version": SUPPORT_SCHEMA_VERSION,
        "levels": [level.value for level in SupportLevel],
        "capabilities": [capability.value for capability in Capability],
        "targets": [SUPPORT_MATRIX[target.name].as_dict() for target in SUPPORTED_TARGETS],
    }


__all__ = [
    "SUPPORT_MATRIX",
    "SUPPORT_SCHEMA_VERSION",
    "Capability",
    "CapabilitySupport",
    "SupportLevel",
    "TargetSupport",
    "capability_support",
    "support_matrix_data",
    "target_support",
]
