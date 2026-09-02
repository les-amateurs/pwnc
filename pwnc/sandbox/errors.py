"""Typed failures for the local challenge sandbox manager."""


class SandboxError(RuntimeError):
    """Base class for sandbox configuration and lifecycle failures."""


class SandboxConfigError(SandboxError):
    """A sandbox profile or explicit specification is invalid."""


class SandboxCapabilityError(SandboxError):
    """The selected backend cannot provide a requested isolation feature."""


class SandboxBackendError(SandboxError):
    """A backend command failed or returned inconsistent state."""


class SandboxProtocolError(SandboxError):
    """A manager/client control message is invalid or incompatible."""


class SandboxDiscoveryError(SandboxError):
    """A persistent manager rendezvous could not be resolved safely."""


class SandboxAlreadyRunningError(SandboxDiscoveryError):
    """A manager already owns the selected project rendezvous."""


class SandboxNotFoundError(SandboxError):
    """No live sandbox matches a requested identifier."""
