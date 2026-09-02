"""Persistent, locally isolated challenge execution."""

from .client import RemoteSandbox, SandboxClient
from .config import SandboxProjectConfig, load_profile, load_project_config
from .discovery import (
    SandboxManagerAddress,
    SandboxManagerSocketLease,
    acquire_manager_socket,
    discover_client,
    discover_manager,
)
from .docker import DockerAttach, DockerBackend, DockerInstance
from .errors import (
    SandboxAlreadyRunningError,
    SandboxBackendError,
    SandboxCapabilityError,
    SandboxConfigError,
    SandboxDiscoveryError,
    SandboxError,
    SandboxNotFoundError,
    SandboxProtocolError,
)
from .manager import SandboxManager, run_manager
from .model import (
    DockerSpec,
    QemuSpec,
    SandboxBackend,
    SandboxDebug,
    SandboxMount,
    SandboxPort,
    SandboxPortBinding,
    SandboxSnapshot,
    SandboxSpec,
    SandboxState,
    SandboxStdio,
)

__all__ = [
    "DockerAttach",
    "DockerBackend",
    "DockerInstance",
    "DockerSpec",
    "QemuSpec",
    "RemoteSandbox",
    "SandboxAlreadyRunningError",
    "SandboxBackend",
    "SandboxBackendError",
    "SandboxCapabilityError",
    "SandboxClient",
    "SandboxConfigError",
    "SandboxDebug",
    "SandboxDiscoveryError",
    "SandboxError",
    "SandboxManager",
    "SandboxManagerAddress",
    "SandboxManagerSocketLease",
    "SandboxMount",
    "SandboxNotFoundError",
    "SandboxPort",
    "SandboxPortBinding",
    "SandboxProjectConfig",
    "SandboxProtocolError",
    "SandboxSnapshot",
    "SandboxSpec",
    "SandboxState",
    "SandboxStdio",
    "acquire_manager_socket",
    "discover_client",
    "discover_manager",
    "load_profile",
    "load_project_config",
    "run_manager",
]
