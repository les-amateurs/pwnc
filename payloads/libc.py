"""Exact libc artifact identity and symbol-offset handling.

glibc's upstream version is not a sufficient payload identity.  Distribution
patches and rebuilds can move symbols and gadgets while preserving a version
string, so payload construction is tied to the artifact SHA-256 and, when
available, its GNU build ID.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType

from .elf import ELFInspectionError, inspect_elf
from .errors import PayloadError
from .model import Address, Image, RuntimeLayout
from .target import Target


class LibcError(PayloadError):
    """Raised for invalid or mismatched libc artifacts."""


@dataclass(frozen=True, slots=True)
class LibcIdentity:
    sha256: str
    build_id: str | None = None
    glibc_version: str | None = None
    distro: str | None = None
    package_release: str | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        digest = self.sha256.lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("sha256 must be exactly 64 hexadecimal characters")
        object.__setattr__(self, "sha256", digest)
        if self.build_id is not None:
            build_id = self.build_id.lower().removeprefix("0x")
            if not build_id or len(build_id) % 2 or any(character not in "0123456789abcdef" for character in build_id):
                raise ValueError("build_id must be an even-length hexadecimal string")
            object.__setattr__(self, "build_id", build_id)

    @classmethod
    def from_bytes(cls, data: bytes, **metadata: str | None) -> LibcIdentity:
        return cls(sha256(data).hexdigest(), **metadata)

    @classmethod
    def from_file(cls, path: str | Path, **metadata: str | None) -> LibcIdentity:
        artifact = Path(path)
        return cls.from_bytes(artifact.read_bytes(), source=str(artifact), **metadata)

    def matches(self, data: bytes) -> bool:
        return sha256(data).hexdigest() == self.sha256


@dataclass(frozen=True, slots=True)
class LibcImage:
    """Symbol offsets from one exact libc artifact."""

    identity: LibcIdentity
    target: Target
    symbols: Mapping[str, int]
    path: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized: dict[str, int] = {}
        for name, offset in self.symbols.items():
            if not name:
                raise ValueError("libc symbol names cannot be empty")
            if not isinstance(offset, int) or offset < 0:
                raise ValueError(f"invalid offset for libc symbol {name!r}: {offset!r}")
            normalized[str(name)] = offset
        object.__setattr__(self, "symbols", MappingProxyType(normalized))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        symbols: Iterable[str] | None = None,
        distro: str | None = None,
        package_release: str | None = None,
        glibc_version: str | None = None,
    ) -> LibcImage:
        """Load offsets and identity from the supplied ELF, never a version guess."""

        artifact = Path(path)
        if not artifact.is_file():
            raise LibcError(f"libc artifact does not exist: {artifact}")
        try:
            profile = inspect_elf(artifact)
        except ELFInspectionError as exc:
            raise LibcError(f"unable to parse libc ELF {artifact}: {exc}") from exc

        identity = LibcIdentity(
            profile.sha256,
            build_id=profile.build_id,
            distro=distro,
            package_release=package_release,
            glibc_version=glibc_version,
            source=str(artifact),
        )
        requested = set(symbols) if symbols is not None else None
        offsets = {
            name: int(value) for name, value in profile.symbol_offsets.items() if requested is None or name in requested
        }
        if requested is not None:
            missing = requested.difference(offsets)
            if missing:
                raise LibcError(f"symbols absent from exact libc artifact: {', '.join(sorted(missing))}")
        return cls(identity=identity, target=profile.target, symbols=offsets, path=str(artifact))

    def offset(self, symbol: str) -> int:
        try:
            return self.symbols[symbol]
        except KeyError as exc:
            raise LibcError(f"symbol {symbol!r} was not loaded from {self.identity.sha256[:12]}") from exc

    def address(self, symbol: str, layout: RuntimeLayout | None = None) -> Address | int:
        reference = Address(self.offset(symbol), Image.LIBC, symbol)
        return reference.resolve(layout) if layout is not None else reference

    def base_from_leak(self, symbol: str, leaked_address: int) -> int:
        base = leaked_address - self.offset(symbol)
        if base < 0:
            raise LibcError(f"leak {leaked_address:#x} is below {symbol} offset {self.offset(symbol):#x}")
        return base


__all__ = ["LibcError", "LibcIdentity", "LibcImage"]
