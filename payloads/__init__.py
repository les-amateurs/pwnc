"""Cross-architecture exploit payload construction primitives."""

from .errors import (
    AddressResolutionError,
    AssemblyError,
    ConstraintError,
    MemoryAccessError,
    PayloadError,
    UnsupportedTargetError,
)
from .libc import LibcError, LibcIdentity, LibcImage
from .model import (
    Address,
    ExecutionPolicy,
    Image,
    Linkage,
    MemoryRequirement,
    Mitigations,
    Payload,
    PayloadKind,
    Permission,
    Relro,
    RuntimeLayout,
)
from .target import ABI, Architecture, CallingConvention, Endian, SUPPORTED_TARGETS, Target, resolve_target

__all__ = [
    "ABI",
    "Address",
    "AddressResolutionError",
    "Architecture",
    "AssemblyError",
    "CallingConvention",
    "ConstraintError",
    "Endian",
    "ExecutionPolicy",
    "Image",
    "LibcError",
    "LibcIdentity",
    "LibcImage",
    "Linkage",
    "MemoryAccessError",
    "MemoryRequirement",
    "Mitigations",
    "Payload",
    "PayloadError",
    "PayloadKind",
    "Permission",
    "Relro",
    "RuntimeLayout",
    "SUPPORTED_TARGETS",
    "Target",
    "UnsupportedTargetError",
    "resolve_target",
]
