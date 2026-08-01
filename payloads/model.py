"""Shared payload, address, runtime-layout, and mitigation models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
from types import MappingProxyType
from typing import Any, Mapping

from .errors import AddressResolutionError, ConstraintError
from .target import Target


class PayloadKind(str, Enum):
    SHELLCODE = "shellcode"
    RET2LIBC = "ret2libc"
    ROP = "rop"
    DATA = "data"
    COMPOSITE = "composite"


class Permission(IntFlag):
    READ = 1
    WRITE = 2
    EXECUTE = 4


@dataclass(frozen=True, slots=True)
class MemoryRequirement:
    """Memory properties a payload needs at execution time."""

    size: int
    permissions: Permission
    purpose: str
    alignment: int = 1

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("memory requirement size cannot be negative")
        if self.alignment <= 0 or self.alignment & (self.alignment - 1):
            raise ValueError("memory alignment must be a positive power of two")


@dataclass(frozen=True, slots=True)
class Payload:
    """Machine-consumable payload bytes plus execution requirements."""

    data: bytes
    target: Target
    kind: PayloadKind
    description: str
    entry_offset: int = 0
    memory: tuple[MemoryRequirement, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("payload data must be bytes")
        if self.entry_offset < 0 or (self.data and self.entry_offset >= len(self.data)):
            raise ValueError("entry_offset must point inside non-empty payload data")
        if not self.data and self.entry_offset:
            raise ValueError("empty payload must have entry_offset=0")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def entry(self, load_address: int) -> int:
        return load_address + self.entry_offset


class Image(str, Enum):
    ABSOLUTE = "absolute"
    MAIN = "main"
    LIBC = "libc"
    LOADER = "loader"
    STACK = "stack"


@dataclass(frozen=True, slots=True)
class RuntimeLayout:
    """Known load bases used to resolve PIE/ASLR-relative addresses."""

    main_base: int | None = None
    libc_base: int | None = None
    loader_base: int | None = None
    stack_base: int | None = None
    extra_bases: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extra_bases", MappingProxyType(dict(self.extra_bases)))

    def base_for(self, image: Image | str) -> int:
        if not isinstance(image, Image):
            try:
                image = Image(image)
            except ValueError:
                try:
                    return self.extra_bases[str(image)]
                except KeyError as exc:
                    raise AddressResolutionError(f"no runtime base for image {image!r}") from exc
        if image is Image.ABSOLUTE:
            return 0
        value = {
            Image.MAIN: self.main_base,
            Image.LIBC: self.libc_base,
            Image.LOADER: self.loader_base,
            Image.STACK: self.stack_base,
        }[image]
        if value is None:
            raise AddressResolutionError(f"runtime base for {image.value} is unknown")
        return value


@dataclass(frozen=True, slots=True)
class Address:
    """An absolute value or an offset relative to a runtime image base."""

    value: int
    image: Image | str = Image.ABSOLUTE
    label: str | None = None

    def resolve(self, layout: RuntimeLayout | None = None) -> int:
        if self.image is Image.ABSOLUTE or self.image == Image.ABSOLUTE.value:
            return self.value
        if layout is None:
            name = self.image.value if isinstance(self.image, Image) else self.image
            raise AddressResolutionError(f"{self.label or 'address'} needs the {name!r} runtime base")
        return layout.base_for(self.image) + self.value


class Linkage(str, Enum):
    DYNAMIC = "dynamic"
    STATIC = "static"


class Relro(str, Enum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


class ExecutionPolicy(str, Enum):
    """How the runtime treats writable/non-executable mappings."""

    ELF_PERMISSIONS = "elf-permissions"
    QEMU_LEGACY_ALL_EXECUTABLE = "qemu-legacy-all-executable"
    QEMU_ELF_PERMISSIONS = "qemu-elf-permissions"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Mitigations:
    pie: bool
    nx: bool
    relro: Relro
    linkage: Linkage
    execution_policy: ExecutionPolicy = ExecutionPolicy.UNKNOWN

    @property
    def writable_memory_is_executable(self) -> bool:
        return not self.nx or self.execution_policy is ExecutionPolicy.QEMU_LEGACY_ALL_EXECUTABLE

    @property
    def got_is_writable(self) -> bool:
        return self.linkage is Linkage.DYNAMIC and self.relro is not Relro.FULL

    def require_shellcode_path(self, *, can_change_permissions: bool = False, executable_region: bool = False) -> None:
        if self.writable_memory_is_executable or executable_region or can_change_permissions:
            return
        if self.execution_policy is ExecutionPolicy.UNKNOWN:
            detail = "NX is enabled and the QEMU/native execute policy is unknown"
        else:
            detail = "NX is enforced by the runtime"
        raise ConstraintError(f"{detail}; provide an executable region or an mprotect/mmap call primitive")

    def require_got_overwrite(self) -> None:
        if not self.got_is_writable:
            reason = "full RELRO" if self.relro is Relro.FULL else "a static binary has no dynamic GOT target"
            raise ConstraintError(f"GOT overwrite is unavailable: {reason}")


__all__ = [
    "Address",
    "ExecutionPolicy",
    "Image",
    "Linkage",
    "MemoryRequirement",
    "Mitigations",
    "Payload",
    "PayloadKind",
    "Permission",
    "Relro",
    "RuntimeLayout",
]
