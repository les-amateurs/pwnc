"""Machine-readable, evidence-based payload support coverage.

``SUPPORTED_TARGETS`` describes targets that the foundation can resolve and
pack.  It does *not* imply that every payload builder accepts every target.
This module keeps that distinction explicit and records end-to-end QEMU and
native-host coverage separately from implementation coverage.

The matrix is intentionally declarative.  Adding a builder is not enough to
change a claim here: its implemented target set and, separately, its QEMU and
native test evidence must be added below.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from .target import ABI, SUPPORTED_TARGETS, Architecture, Endian, Target, resolve_target

SUPPORT_SCHEMA_VERSION = 4


class Capability(str, Enum):
    """Payload operations tracked by the public support contract."""

    COMMAND = "command"
    ORW = "orw"
    SENDFILE_ORW = "sendfile-orw"
    STAGER = "stager"
    RET2LIBC = "ret2libc"
    STATIC_ROP = "static-rop"
    FSOP = "fsop"
    ARB_EXECUTOR = "arb-executor"
    QEMU_SEMIHOSTING = "qemu-semihosting"


class SupportLevel(str, Enum):
    """Highest evidenced level for a target/capability pair.

    ``RECOGNIZED`` only means the target model knows the architecture, word
    width, byte order, and ABI.  It explicitly does not mean a builder exists.
    ``IMPLEMENTED`` means a builder exists for the pair.  ``QEMU_VERIFIED``
    additionally means an opt-in end-to-end QEMU execution test covers it.
    Direct host execution is an orthogonal fact exposed by
    :attr:`CapabilitySupport.native_verified` rather than another level.
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
    native_verified: bool = False

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
            "native_verified": self.native_verified,
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


_ALL_TARGET_NAMES = frozenset(target.name for target in SUPPORTED_TARGETS)
# Command, ORW, and mmap-stager shellcode lowering exists for every catalog
# target.  CommandQemuTests executes each variant except PPC32 little-endian,
# for which the available qemu-user suite has no matching emulator.
_SHELLCODE_IMPLEMENTED = _ALL_TARGET_NAMES
_SHELLCODE_QEMU_VERIFIED = _ALL_TARGET_NAMES - frozenset({"powerpc32-le-powerpc-sysv"})
_STATIC_ROP_QEMU_VERIFIED = _SHELLCODE_QEMU_VERIFIED
_RET2LIBC_QEMU_VERIFIED = frozenset({"x86-le-i386-sysv", "x86_64-le-amd64-sysv"})
_NATIVE_X86_VERIFIED = frozenset({"x86-le-i386-sysv", "x86_64-le-amd64-sysv"})
_QEMU_SEMIHOSTING_IMPLEMENTED = frozenset(
    {
        "arm-le-arm-eabi",
        "arm-be-arm-eabi",
        "thumb-le-arm-eabi",
        "thumb-be-arm-eabi",
        "arm64-le-aarch64-aapcs64",
        "arm64-be-aarch64-aapcs64",
        "riscv32-le-riscv-ilp32",
        "riscv64-le-riscv-lp64",
    }
)
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
        Capability.COMMAND: _SHELLCODE_IMPLEMENTED,
        Capability.ORW: _SHELLCODE_IMPLEMENTED,
        Capability.SENDFILE_ORW: _SHELLCODE_IMPLEMENTED,
        Capability.STAGER: _SHELLCODE_IMPLEMENTED,
        Capability.RET2LIBC: _DIRECT_CALL_IMPLEMENTED,
        Capability.STATIC_ROP: _ALL_TARGET_NAMES,
        Capability.FSOP: _ALL_TARGET_NAMES,
        Capability.ARB_EXECUTOR: _ALL_TARGET_NAMES,
        Capability.QEMU_SEMIHOSTING: _QEMU_SEMIHOSTING_IMPLEMENTED,
    }
)

_QEMU_VERIFIED: Mapping[Capability, frozenset[str]] = MappingProxyType(
    {
        Capability.COMMAND: _SHELLCODE_QEMU_VERIFIED,
        Capability.ORW: _SHELLCODE_QEMU_VERIFIED,
        Capability.SENDFILE_ORW: _SHELLCODE_QEMU_VERIFIED,
        Capability.STAGER: _SHELLCODE_QEMU_VERIFIED,
        Capability.RET2LIBC: _RET2LIBC_QEMU_VERIFIED,
        Capability.STATIC_ROP: _STATIC_ROP_QEMU_VERIFIED,
        Capability.FSOP: frozenset(),
        Capability.ARB_EXECUTOR: frozenset(),
        Capability.QEMU_SEMIHOSTING: _QEMU_SEMIHOSTING_IMPLEMENTED,
    }
)

_NATIVE_VERIFIED: Mapping[Capability, frozenset[str]] = MappingProxyType(
    {
        Capability.COMMAND: _NATIVE_X86_VERIFIED,
        Capability.ORW: _NATIVE_X86_VERIFIED,
        Capability.SENDFILE_ORW: _NATIVE_X86_VERIFIED,
        Capability.STAGER: _NATIVE_X86_VERIFIED,
        Capability.RET2LIBC: _NATIVE_X86_VERIFIED,
        Capability.STATIC_ROP: _NATIVE_X86_VERIFIED,
        Capability.FSOP: _NATIVE_X86_VERIFIED,
        Capability.ARB_EXECUTOR: frozenset(),
        Capability.QEMU_SEMIHOSTING: frozenset(),
    }
)

_IMPLEMENTATION_EVIDENCE: Mapping[Capability, tuple[str, ...]] = MappingProxyType(
    {
        Capability.COMMAND: (
            "payloads.shellcode.command_shellcode",
            (
                "payloads/tests/test_shellcode.py::"
                "CommandAssemblyTests.test_all_implemented_targets_assemble_to_relocation_free_bytes"
            ),
        ),
        Capability.ORW: (
            "payloads.shellcode.orw_shellcode",
            "payloads/tests/test_shellcode.py::CommandAssemblyTests.test_orw_assembles_for_all_implemented_targets",
        ),
        Capability.SENDFILE_ORW: (
            "payloads.shellcode.sendfile_orw_source",
            "payloads.shellcode.sendfile_orw_shellcode",
            (
                "payloads/tests/test_shellcode.py::"
                "CommandAssemblyTests.test_sendfile_orw_assembles_for_all_targets_without_read_buffer"
            ),
        ),
        Capability.STAGER: (
            "payloads.shellcode.mmap_stager",
            (
                "payloads/tests/test_shellcode.py::"
                "CommandAssemblyTests.test_exit_and_rw_to_rx_stager_assemble_for_all_implemented_targets"
            ),
        ),
        Capability.RET2LIBC: (
            "payloads.rop.build_ret2libc_system",
            "payloads.libc_rop.LibcROPBuilder",
            "payloads/tests/test_rop.py::RopTargetMatrixTests.test_exact_identity_ret2libc_matrix_is_complete",
            "payloads/tests/test_libc_rop.py::SemanticLibcROPStageTests",
            "payloads/tests/test_libc_rop.py::PwntoolsComposedProgramTests",
        ),
        Capability.STATIC_ROP: (
            "payloads.rop.build_static_call",
            "payloads.rop.build_static_syscall",
            "payloads/tests/test_rop.py::RopTargetMatrixTests.test_static_call_materializes_for_every_direct_call_target",
            "payloads/tests/test_rop.py::RopTargetMatrixTests.test_static_syscall_materializes_for_every_catalog_target",
        ),
        Capability.FSOP: (
            "payloads.fsop.FSOP",
            "payloads.fsop.FSOPPayload.overlay",
            (
                "payloads/tests/test_fsop.py::"
                "FSOPLayoutMatrixTests.test_legacy_file_and_vtable_layouts_cover_all_catalog_targets"
            ),
            (
                "payloads/tests/test_fsop.py::"
                "FSOPLayoutMatrixTests.test_wide_layouts_and_callback_relocations_cover_all_catalog_targets"
            ),
            (
                "payloads/tests/test_fsop.py::"
                "FSOPOverlayTests.test_endian_safe_arg0_commands_are_accepted_for_every_target"
            ),
        ),
        Capability.ARB_EXECUTOR: (
            "payloads.arbio.ArbitraryMemory",
            "payloads.arbio.PayloadStager",
            "payloads.arbio.ExecveCallWorkflow",
            "payloads.arbio.GotSystemWorkflow",
        ),
        Capability.QEMU_SEMIHOSTING: (
            "payloads.shellcode.qemu_semihosting_command_source",
            "payloads.shellcode.qemu_semihosting_command_shellcode",
        ),
    }
)

_QEMU_EVIDENCE: Mapping[Capability, str] = MappingProxyType(
    {
        Capability.COMMAND: (
            "payloads/tests/test_shellcode_qemu.py::"
            "CommandQemuTests.test_raw_command_shellcode_executes_on_every_qemu_target"
        ),
        Capability.ORW: (
            "payloads/tests/test_shellcode_qemu.py::CommandQemuTests.test_raw_orw_shellcode_preserves_binary_file_bytes"
        ),
        Capability.SENDFILE_ORW: (
            "payloads/tests/test_shellcode_qemu.py::"
            "CommandQemuTests.test_raw_sendfile_orw_shellcode_preserves_binary_file_bytes"
        ),
        Capability.STAGER: (
            "payloads/tests/test_shellcode_qemu.py::CommandQemuTests.test_rw_to_rx_mmap_stager_runs_exact_second_stage"
        ),
        Capability.RET2LIBC: (
            "payloads/tests/test_rop_qemu.py::"
            "Ret2libcQemuTests.test_exact_loaded_libc_system_chain_executes_from_live_base"
        ),
        Capability.STATIC_ROP: "payloads/tests/test_rop_qemu.py::StaticRopQemuTests",
        Capability.FSOP: "no end-to-end FSOP activation test in current tree",
        Capability.ARB_EXECUTOR: "no QEMU execution test in current tree",
        Capability.QEMU_SEMIHOSTING: (
            "payloads/tests/test_semihost_qemu.py::"
            "QemuSemihostingExecutionTests.test_host_command_escape_executes_on_every_automatic_qemu_user_target"
        ),
    }
)

_NATIVE_EVIDENCE: Mapping[Capability, str] = MappingProxyType(
    {
        Capability.COMMAND: (
            "payloads/tests/test_native_x86.py::"
            "NativeShellcodeTests.test_raw_command_shellcode_executes_in_both_native_x86_modes"
        ),
        Capability.ORW: (
            "payloads/tests/test_native_x86.py::"
            "NativeShellcodeTests.test_raw_orw_shellcode_preserves_binary_file_bytes_in_both_native_x86_modes"
        ),
        Capability.SENDFILE_ORW: (
            "payloads/tests/test_native_x86.py::"
            "NativeShellcodeTests.test_raw_sendfile_orw_shellcode_runs_without_a_read_buffer_in_both_native_x86_modes"
        ),
        Capability.STAGER: (
            "payloads/tests/test_native_x86.py::"
            "NativeShellcodeTests.test_rw_to_rx_mmap_stager_runs_exact_child_in_both_native_x86_modes"
        ),
        Capability.RET2LIBC: (
            "payloads/tests/test_native_x86.py::"
            "NativeRet2libcTests.test_exact_loaded_libc_system_chain_executes_from_native_live_bases"
        ),
        Capability.STATIC_ROP: (
            "payloads/tests/test_native_x86.py::"
            "NativeStaticRopTests.test_static_syscall_and_direct_call_chains_execute_in_both_native_x86_modes"
        ),
        Capability.FSOP: (
            "payloads/tests/test_native_x86.py::"
            "NativeFSOPTests.test_wide_fflush_and_seek_routes_dispatch_on_both_native_x86_modes"
        ),
    }
)

_UNIMPLEMENTED_DETAIL: Mapping[Capability, str] = MappingProxyType(
    {
        Capability.COMMAND: "target is recognized, but command shellcode lowering is not implemented",
        Capability.ORW: "target is recognized, but no open/read/write shellcode builder is implemented",
        Capability.SENDFILE_ORW: "target is recognized, but no open/sendfile shellcode builder is implemented",
        Capability.STAGER: "target is recognized, but mmap/read/mprotect shellcode lowering is not implemented",
        Capability.RET2LIBC: "target is recognized, but its ABI is not supported by the ret2libc call builder",
        Capability.STATIC_ROP: "target is recognized, but no static-binary ROP builder is implemented",
        Capability.FSOP: "target is recognized, but no glibc FILE-stream payload serializer is implemented",
        Capability.ARB_EXECUTOR: "target is recognized, but no arbitrary-read/write executor is implemented",
        Capability.QEMU_SEMIHOSTING: (
            "target is recognized, but qemu-user does not automatically intercept its semihosting trap"
        ),
    }
)


def _implemented_detail(target: Target, capability: Capability) -> str:
    if capability is Capability.COMMAND:
        return "position-independent /bin/sh -c command shellcode builder exists"
    if capability is Capability.ORW:
        return "position-independent one-pass open/read/write shellcode builder exists"
    if capability is Capability.SENDFILE_ORW:
        return "position-independent one-pass open/sendfile shellcode builder exists without a read buffer"
    if capability is Capability.STAGER:
        return "position-independent mmap/read/mprotect/cache-finalize/jump stager exists"
    if capability is Capability.RET2LIBC:
        return (
            "symbolic system(command) chain builder exists, binds every libc-relative operand to one exact "
            "LibcIdentity, and exposes ABI call-frame placement constraints"
        )
    if capability is Capability.STATIC_ROP:
        if target.name in _DIRECT_CALL_UNSUPPORTED:
            return "symbolic static syscall chains are implemented; direct function calls are unsupported for this ABI"
        return (
            "symbolic static function-call and syscall chain builders exist for caller-supplied semantic gadgets; "
            "direct calls expose ABI call-frame placement constraints"
        )
    if capability is Capability.FSOP:
        detail = (
            "exact-libc-bound, glibc-version-dependent legacy and wide FILE-stream payload serialization exists; "
            "structural byte-layout, relocation, dispatch-route, and overlay tests cover all 21 catalog targets"
        )
        if target.arch in {Architecture.RISCV32, Architecture.RISCV64}:
            detail += (
                "; upstream RISC-V glibc postdates primary-vtable validation, so legacy fake-vtable routes require "
                "an explicit real validation bypass"
            )
        if target.name == "powerpc32-le-powerpc-sysv":
            detail += (
                "; PPC32 little-endian has no upstream glibc target, so use requires an exact downstream or "
                "custom libc artifact"
            )
        return detail
    if capability is Capability.ARB_EXECUTOR:
        if target.abi is ABI.POWERPC64_ELFV1:
            return (
                "target-endian arbitrary-memory adapters, explicit payload staging/triggering, and "
                "descriptor-aware exact-libc call workflows exist; raw-address GOT-to-system replacement is "
                "unsupported for ELFv1"
            )
        return (
            "target-endian arbitrary-memory adapters, explicit payload staging/triggering, "
            "and exact-libc call workflows exist"
        )
    if capability is Capability.QEMU_SEMIHOSTING:
        return "intentional QEMU user-mode SYS_SYSTEM host-command escape shellcode builder exists"
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
    native_verified = name in _NATIVE_VERIFIED[capability]
    implemented = name in _IMPLEMENTED[capability]
    if qemu_verified and not implemented:  # pragma: no cover - declaration invariant
        raise RuntimeError(f"{capability.value}/{name} cannot be QEMU-verified without an implementation")
    if native_verified and not implemented:  # pragma: no cover - declaration invariant
        raise RuntimeError(f"{capability.value}/{name} cannot be native-verified without an implementation")

    evidence = ["payloads.target.SUPPORTED_TARGETS"]
    if implemented:
        implementation_evidence = _IMPLEMENTATION_EVIDENCE[capability]
        if capability is Capability.STATIC_ROP and target.name in _DIRECT_CALL_UNSUPPORTED:
            implementation_evidence = tuple(
                item
                for item in implementation_evidence
                if item
                not in {
                    "payloads.rop.build_static_call",
                    (
                        "payloads/tests/test_rop.py::"
                        "RopTargetMatrixTests.test_static_call_materializes_for_every_direct_call_target"
                    ),
                }
            )
        if capability is Capability.ARB_EXECUTOR and target.abi is ABI.POWERPC64_ELFV1:
            implementation_evidence = tuple(
                item for item in implementation_evidence if item != "payloads.arbio.GotSystemWorkflow"
            )
        evidence.extend(implementation_evidence)
    if qemu_verified:
        if capability is Capability.RET2LIBC:
            detail = (
                "builder exists and a live-base chain against the exact loaded libc artifact is covered by the "
                "opt-in QEMU test"
            )
        elif capability is Capability.STATIC_ROP:
            if target.name in _DIRECT_CALL_UNSUPPORTED:
                detail = (
                    "materialized static syscall ROP executes in the opt-in QEMU test; "
                    "direct function calls remain unsupported for this ABI"
                )
            else:
                detail = "materialized static syscall and direct-call ROP both execute in the opt-in QEMU test"
        elif capability is Capability.QEMU_SEMIHOSTING:
            detail = (
                "intentional SYS_SYSTEM host-command escape executes through automatic qemu-user semihosting "
                "interception in the opt-in QEMU test"
            )
        else:
            detail = (
                _implemented_detail(target, capability) + "; raw payload execution is covered by the opt-in QEMU test"
            )
        evidence.append(_QEMU_EVIDENCE[capability])
        if native_verified:
            evidence.append(_NATIVE_EVIDENCE[capability])
            detail += "; direct execution on native Linux i386 and AMD64 is also covered"
        return CapabilitySupport(
            SupportLevel.QEMU_VERIFIED,
            detail,
            tuple(evidence),
            native_verified,
        )
    if implemented:
        detail = (
            _implemented_detail(target, capability)
            + "; no end-to-end QEMU execution test covers this target/capability pair"
        )
        if native_verified:
            evidence.append(_NATIVE_EVIDENCE[capability])
            detail += "; direct native execution is covered"
        return CapabilitySupport(
            SupportLevel.IMPLEMENTED,
            detail,
            tuple(evidence),
            native_verified,
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
