"""Exceptions raised by the payload construction framework."""


class PayloadError(Exception):
    """Base class for payload construction and execution failures."""


class UnsupportedTargetError(PayloadError, ValueError):
    """Raised when an architecture, ABI, bit width, or endian is unsupported."""


class AddressResolutionError(PayloadError, ValueError):
    """Raised when a relative address cannot be resolved at runtime."""


class ConstraintError(PayloadError, ValueError):
    """Raised when a requested payload conflicts with target mitigations."""


class AssemblyError(PayloadError):
    """Raised when assembly source cannot be converted to machine code."""


class MemoryAccessError(PayloadError):
    """Raised when an arbitrary-memory primitive fails or is incomplete."""
