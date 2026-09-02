"""Semantic address, range, typed-memory, heap, and payload marks."""

from __future__ import annotations

import base64
import math
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any

from pwnc.types.containers import Array, Enum as TypeEnum, Struct, Union
from pwnc.types.primitives import Bits, Double, Float, Int, Ptr


class MarkKind(str, Enum):
    MEMORY = "memory"
    TYPED = "typed"
    HEAP_CHUNK = "heap-chunk"
    PAYLOAD = "payload"


@dataclass(frozen=True, slots=True)
class SemanticSpan:
    offset: int
    size: int
    role: str
    pointer_kind: str | None = None
    expression: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "role": self.role,
            "pointer_kind": self.pointer_kind,
            "expression": self.expression,
        }


@dataclass(frozen=True, slots=True)
class PayloadAnnotation:
    kind: str
    description: str
    architecture: str
    bits: int
    endian: str
    spans: tuple[SemanticSpan, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "spans", tuple(self.spans))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "description": self.description,
            "architecture": self.architecture,
            "bits": self.bits,
            "endian": self.endian,
            "spans": [item.to_json() for item in self.spans],
            "metadata": _json_metadata(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class TypedField:
    """One primitive leaf from a coherent typed-memory capture."""

    path: str
    type_name: str
    offset: int
    size: int
    value: Any
    display: str
    pointer: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "type": self.type_name,
            "offset": self.offset,
            "size": self.size,
            "value": self.value,
            "display": self.display,
            "pointer": self.pointer,
        }


@dataclass(frozen=True, slots=True)
class _MarkRecord:
    id: str
    address: int
    size: int
    label: str
    kind: MarkKind
    tags: tuple[str, ...]
    type_name: str | None
    ptype: Any
    allocation_id: str | None
    allocation_generation: int | None
    payload: PayloadAnnotation | None
    expected: bytes | None
    metadata: Mapping[str, Any]
    created_ns: int


@dataclass(frozen=True, slots=True)
class CapturedMark:
    mark_id: str
    label: str
    kind: MarkKind
    address: int
    size: int
    data: bytes | None
    display: str | None
    error: str | None
    allocation_id: str | None
    allocation_generation: int | None
    payload: PayloadAnnotation | None
    type_name: str | None = None
    typed_fields: tuple[TypedField, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "mark_id": self.mark_id,
            "label": self.label,
            "kind": self.kind.value,
            "address": self.address,
            "size": self.size,
            "encoding": "base64" if self.data is not None else None,
            "data": None if self.data is None else base64.b64encode(self.data).decode("ascii"),
            "display": self.display,
            "error": self.error,
            "allocation_id": self.allocation_id,
            "allocation_generation": self.allocation_generation,
            "payload": None if self.payload is None else self.payload.to_json(),
            "type": self.type_name,
            "typed_fields": [item.to_json() for item in self.typed_fields],
        }


class MemoryMark:
    """A stable handle whose mutable label/tags live in its owning registry."""

    def __init__(self, owner: "Marks", mark_id: str):
        self._owner = owner
        self._id = mark_id

    def _record(self) -> _MarkRecord:
        return self._owner._record(self._id)

    @property
    def id(self) -> str:
        return self._id

    @property
    def address(self) -> int:
        return self._record().address

    @property
    def size(self) -> int:
        return self._record().size

    @property
    def end(self) -> int:
        record = self._record()
        return record.address + record.size

    @property
    def label(self) -> str:
        return self._record().label

    @label.setter
    def label(self, value: str) -> None:
        self._owner.rename(self, value)

    @property
    def kind(self) -> MarkKind:
        return self._record().kind

    @property
    def tags(self) -> tuple[str, ...]:
        return self._record().tags

    @property
    def type(self):
        return self._record().ptype

    @property
    def allocation_id(self) -> str | None:
        return self._record().allocation_id

    @property
    def allocation_generation(self) -> int | None:
        return self._record().allocation_generation

    @property
    def payload(self) -> PayloadAnnotation | None:
        return self._record().payload

    @property
    def expected(self) -> bytes | None:
        return self._record().expected

    @property
    def metadata(self) -> Mapping[str, Any]:
        return self._record().metadata

    def contains(self, address: int, size: int = 1) -> bool:
        if size < 0:
            raise ValueError("size cannot be negative")
        return self.address <= int(address) and int(address) + size <= self.end

    def capture(self) -> CapturedMark:
        return self._owner.capture(self)

    def read(self) -> bytes:
        return self._owner._runtime.memory.read(self.address, self.size)

    def view(self):
        record = self._record()
        if record.ptype is None:
            raise TypeError(f"mark {record.label!r} has no associated type")
        return self._owner._runtime.memory.view(record.address, record.ptype)

    def rename(self, label: str) -> "MemoryMark":
        self._owner.rename(self, label)
        return self

    def tag(self, *tags: str) -> "MemoryMark":
        self._owner.tag(self, *tags)
        return self

    def remove(self) -> None:
        self._owner.remove(self)

    def to_json(self) -> dict[str, Any]:
        record = self._record()
        return {
            "id": record.id,
            "address": record.address,
            "size": record.size,
            "label": record.label,
            "kind": record.kind.value,
            "tags": list(record.tags),
            "type": record.type_name,
            "allocation_id": record.allocation_id,
            "allocation_generation": record.allocation_generation,
            "payload": None if record.payload is None else record.payload.to_json(),
            "has_expected": record.expected is not None,
            "metadata": _json_metadata(record.metadata),
            "created_ns": record.created_ns,
        }

    def __repr__(self) -> str:
        try:
            return f"<MemoryMark {self.label!r} {self.address:#x}:{self.end:#x} {self.kind.value}>"
        except KeyError:
            return f"<MemoryMark {self._id} removed>"


class Marks(Sequence[MemoryMark]):
    def __init__(self, runtime):
        self._runtime = runtime
        self._lock = threading.RLock()
        self._next_id = 1
        self._records: dict[str, _MarkRecord] = {}

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __getitem__(self, index):
        with self._lock:
            if isinstance(index, str):
                if index not in self._records:
                    raise KeyError(index)
                return MemoryMark(self, index)
            mark_id = tuple(self._records)[index]
        return MemoryMark(self, mark_id)

    def __iter__(self) -> Iterator[MemoryMark]:
        with self._lock:
            ids = tuple(self._records)
        return iter(MemoryMark(self, mark_id) for mark_id in ids)

    def _record(self, mark_id: str) -> _MarkRecord:
        with self._lock:
            return self._records[mark_id]

    def add(
        self,
        address,
        size: int | None = None,
        label: str | None = None,
        *,
        kind: MarkKind | str = MarkKind.MEMORY,
        type=None,
        tags: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
        allocation_id: str | None = None,
        allocation_generation: int | None = None,
        payload: PayloadAnnotation | None = None,
        expected: bytes | bytearray | memoryview | None = None,
    ) -> MemoryMark:
        address, size, type = _marked_range(address, size, type, self._runtime.layout)
        kind = MarkKind(kind)
        if kind is MarkKind.MEMORY and type is not None:
            kind = MarkKind.TYPED
        if not label:
            label = f"{kind.value}@{address:#x}"
        if not isinstance(label, str):
            raise TypeError("mark label must be text")
        normalized_tags = tuple(dict.fromkeys(_tag(item) for item in tags))
        if expected is not None:
            expected = bytes(expected)
            if len(expected) != size:
                raise ValueError("expected mark bytes must exactly match the marked size")
        if allocation_generation is not None and allocation_generation < 0:
            raise ValueError("allocation generation cannot be negative")
        with self._lock:
            mark_id = f"m{self._next_id}"
            self._next_id += 1
            record = _MarkRecord(
                mark_id,
                address,
                size,
                label,
                kind,
                normalized_tags,
                None if type is None else _type_label(type),
                type,
                allocation_id,
                allocation_generation,
                payload,
                expected,
                MappingProxyType(dict(metadata or {})),
                time.time_ns(),
            )
            self._records[mark_id] = record
        self._changed("mark-added", MemoryMark(self, mark_id))
        return MemoryMark(self, mark_id)

    def at(self, address: int) -> tuple[MemoryMark, ...]:
        return tuple(mark for mark in self if mark.contains(int(address)))

    def overlapping(self, address: int, size: int) -> tuple[MemoryMark, ...]:
        if size < 0:
            raise ValueError("size cannot be negative")
        start, end = int(address), int(address) + size
        return tuple(mark for mark in self if start < mark.end and mark.address < end)

    def rename(self, mark: MemoryMark | str, label: str) -> None:
        if not isinstance(label, str) or not label:
            raise ValueError("mark label must be nonempty text")
        mark_id = _mark_id(mark)
        with self._lock:
            self._records[mark_id] = replace(self._records[mark_id], label=label)
        self._changed("mark-updated", MemoryMark(self, mark_id))

    def tag(self, mark: MemoryMark | str, *tags: str) -> None:
        mark_id = _mark_id(mark)
        with self._lock:
            record = self._records[mark_id]
            combined = tuple(dict.fromkeys((*record.tags, *(_tag(item) for item in tags))))
            self._records[mark_id] = replace(record, tags=combined)
        self._changed("mark-updated", MemoryMark(self, mark_id))

    def remove(self, mark: MemoryMark | str) -> None:
        mark_id = _mark_id(mark)
        with self._lock:
            record = self._records.pop(mark_id)
        self._changed("mark-removed", _record_json(record))

    def clear(self) -> None:
        with self._lock:
            ids = tuple(self._records)
        for mark_id in ids:
            self.remove(mark_id)

    def capture(self, mark: MemoryMark | str) -> CapturedMark:
        record = self._record(_mark_id(mark))
        try:
            if record.ptype is not None:
                typed = self._runtime.memory.capture(record.address, record.ptype)
                data = typed.data
                display = str(typed.value)
                typed_fields = _capture_typed_fields(typed.value)
            else:
                data = self._runtime.memory.read(record.address, record.size)
                display = None
                typed_fields = ()
            error = None
        except Exception as caught:
            data = None
            display = None
            typed_fields = ()
            error = f"{type(caught).__name__}: {caught}"
        return CapturedMark(
            record.id,
            record.label,
            record.kind,
            record.address,
            record.size,
            data,
            display,
            error,
            record.allocation_id,
            record.allocation_generation,
            record.payload,
            record.type_name,
            typed_fields,
        )

    def _prepare_payload(self, address: int, value, layout=None) -> tuple[bytes, PayloadAnnotation] | None:
        return _payload_bytes(int(address), value, self._runtime.layout if layout is None else layout)

    def _commit_payload(
        self,
        address: int,
        raw: bytes,
        annotation: PayloadAnnotation,
        *,
        label: str | None = None,
    ) -> MemoryMark:
        return self.add(
            address,
            len(raw),
            label or annotation.description,
            kind=MarkKind.PAYLOAD,
            tags=("payload", annotation.kind),
            metadata={"verified_write": False},
            payload=annotation,
            expected=raw,
        )

    def _changed(self, event: str, value) -> None:
        callback = getattr(self._runtime, "_record_event", None)
        if callback is not None:
            callback(event, value)

    def to_json(self) -> list[dict[str, Any]]:
        return [mark.to_json() for mark in self]


def _marked_range(address, size, ptype, layout):
    try:
        from payloads.model import Address
    except ImportError:
        Address = ()
    if Address and isinstance(address, Address):
        address = address.resolve(layout)
    elif hasattr(address, "address") and not isinstance(address, int):
        if size is None:
            size = getattr(address, "nbytes", None)
        if ptype is None:
            ptype = getattr(address, "type", None)
        address = address.address
    if isinstance(address, bool) or not isinstance(address, int) or address < 0:
        raise ValueError("mark address must be a nonnegative integer or addressed typed value")
    if size is None and ptype is not None:
        size = ptype.nbytes
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError("mark size must be a positive integer")
    return address, size, ptype


def _type_label(ptype) -> str:
    if isinstance(ptype, Struct):
        return f"struct {ptype.name}"
    if isinstance(ptype, Union):
        return f"union {ptype.name}"
    if isinstance(ptype, TypeEnum) and ptype.name:
        return f"enum {ptype.name}"
    if isinstance(ptype, Array):
        count = "" if ptype.count == 0 else str(ptype.count)
        return f"{_type_label(ptype.child)}[{count}]"
    return str(ptype)


def _payload_bytes(address: int, value, layout) -> tuple[bytes, PayloadAnnotation] | None:
    from payloads import FSOPWrite, LoweredLibcROP, Payload, ROPChain, StagedPayload

    chain = value if isinstance(value, ROPChain) else None
    if isinstance(value, StagedPayload):
        value = value.payload
    elif isinstance(value, LoweredLibcROP):
        value = value.as_payload()
    elif isinstance(value, FSOPWrite):
        if value.address != address:
            raise ValueError(f"FSOP write belongs at {value.address:#x}, not {address:#x}")
        raw = value.data
        annotation = PayloadAnnotation(
            "fsop-write",
            f"FSOP {value.placement} write",
            "unknown",
            0,
            "unknown",
            (SemanticSpan(0, len(raw), value.placement, expression=f"placement+{value.offset:#x}"),),
            {"placement": value.placement, "offset": value.offset},
        )
        return raw, annotation
    elif chain is not None:
        arguments = {"layout": layout}
        if chain.call_frame is not None:
            arguments["chain_base"] = address
        value = chain.as_payload(**arguments)
    if not isinstance(value, Payload):
        return None
    raw = value.data
    target = value.target
    spans = []
    if chain is not None:
        for index, word in enumerate(chain.words):
            spans.append(
                SemanticSpan(
                    index * target.word_size,
                    target.word_size,
                    word.role,
                    word.pointer_kind.value,
                    repr(word.value),
                )
            )
    else:
        roles = tuple(value.metadata.get("word_roles", ()))
        if roles and len(roles) * target.word_size <= len(raw):
            spans.extend(
                SemanticSpan(index * target.word_size, target.word_size, str(role))
                for index, role in enumerate(roles)
            )
    if not spans and raw:
        spans.append(SemanticSpan(0, len(raw), value.description))
    return raw, PayloadAnnotation(
        value.kind.value,
        value.description,
        value.target.arch.value,
        value.target.bits,
        value.target.endian.value,
        tuple(spans),
        value.metadata,
    )


def _capture_typed_fields(root, *, limit: int = 4096) -> tuple[TypedField, ...]:
    """Flatten pwnc typed leaves without dereferencing pointers.

    This is a purpose-built typed-memory adapter for snapshots, not a generic
    Python object serializer.  The ordinary scripting API remains the live
    ``Value`` tree.
    """

    fields = []
    root_address = int(root.address)

    def visit(value, path: str) -> None:
        if len(fields) >= limit:
            return
        ptype = value.type
        if isinstance(ptype, (Struct, Union)):
            for name, _bound in ptype.fields():
                visit(getattr(value, name), name if path == "$" else f"{path}.{name}")
                if len(fields) >= limit:
                    break
            return
        if isinstance(ptype, Array):
            for index in range(ptype.count):
                visit(value[index], f"{path}[{index}]")
                if len(fields) >= limit:
                    break
            return
        if not isinstance(ptype, (Bits, Int, Float, Double, Ptr, TypeEnum)):
            return
        resolved = value._resolve()
        if isinstance(resolved, float) and not math.isfinite(resolved):
            resolved = str(resolved)
        if not isinstance(resolved, (str, int, float, bool)) and resolved is not None:
            resolved = str(resolved)
        fields.append(
            TypedField(
                path,
                str(ptype),
                int(value.address) - root_address,
                int(ptype.nbytes),
                resolved,
                str(value),
                int(value) if isinstance(ptype, Ptr) else None,
            )
        )

    visit(root, "$")
    return tuple(fields)


def _mark_id(mark: MemoryMark | str) -> str:
    return mark.id if isinstance(mark, MemoryMark) else str(mark)


def _tag(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("mark tags must be nonempty text")
    return value


def _record_json(record: _MarkRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "address": record.address,
        "size": record.size,
        "label": record.label,
        "kind": record.kind.value,
    }


def _json_metadata(value):
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_metadata(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_json_metadata(item) for item in value]
    return str(value)


__all__ = [
    "CapturedMark",
    "MarkKind",
    "Marks",
    "MemoryMark",
    "PayloadAnnotation",
    "SemanticSpan",
    "TypedField",
]
