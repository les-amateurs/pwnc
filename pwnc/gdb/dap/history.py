"""Selective runtime snapshots, bounded history, and semantic diffs."""

from __future__ import annotations

import base64
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .facts import ThreadFacts
from .heap import HeapArena, HeapChunk
from .marks import CapturedMark, MarkKind, MemoryMark

if TYPE_CHECKING:
    from .runtime import MemoryMap, Module


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    sequence: int
    timestamp_ns: int
    generation: int
    kind: str
    details: Mapping[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp_ns": self.timestamp_ns,
            "generation": self.generation,
            "kind": self.kind,
            "details": _event_details(self.details),
        }


@dataclass(frozen=True, slots=True)
class ModuleSnapshot:
    id: str
    name: str
    path: str | None
    kind: str
    build_id: str | None
    base: int | None
    end: int | None
    load_bias: int | None

    @classmethod
    def capture(cls, module: Module) -> "ModuleSnapshot":
        return cls(
            module.id,
            module.name,
            module.path,
            module.kind,
            module.build_id,
            module.base,
            module.end,
            module.load_bias,
        )

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ValueChange:
    before: Any
    after: Any

    def to_json(self) -> dict[str, Any]:
        return {"before": _event_details(self.before), "after": _event_details(self.after)}


@dataclass(frozen=True, slots=True)
class ByteRangeChange:
    offset: int
    before: bytes
    after: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "before": base64.b64encode(self.before).decode("ascii"),
            "after": base64.b64encode(self.after).decode("ascii"),
            "encoding": "base64",
        }


@dataclass(frozen=True, slots=True)
class ModuleChange:
    id: str
    fields: Mapping[str, ValueChange]

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "fields": {name: value.to_json() for name, value in self.fields.items()}}


@dataclass(frozen=True, slots=True)
class ThreadChange:
    id: int
    registers: Mapping[str, ValueChange]
    facts: Mapping[str, ValueChange]
    variables: Mapping[str, ValueChange]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "registers": {name: value.to_json() for name, value in self.registers.items()},
            "facts": {name: value.to_json() for name, value in self.facts.items()},
            "variables": {name: value.to_json() for name, value in self.variables.items()},
        }


@dataclass(frozen=True, slots=True)
class MarkChange:
    id: str
    fields: Mapping[str, ValueChange]
    bytes: tuple[ByteRangeChange, ...]
    typed_fields: Mapping[str, ValueChange]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fields": {name: value.to_json() for name, value in self.fields.items()},
            "bytes": [item.to_json() for item in self.bytes],
            "typed_fields": {name: value.to_json() for name, value in self.typed_fields.items()},
        }


@dataclass(frozen=True, slots=True)
class HeapArenaChange:
    address: int
    fields: Mapping[str, ValueChange]

    def to_json(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "fields": {name: value.to_json() for name, value in self.fields.items()},
        }


@dataclass(frozen=True, slots=True)
class HeapChunkChange:
    allocation_id: str
    fields: Mapping[str, ValueChange]

    def to_json(self) -> dict[str, Any]:
        return {
            "allocation_id": self.allocation_id,
            "fields": {name: value.to_json() for name, value in self.fields.items()},
        }


@dataclass(frozen=True, slots=True)
class SnapshotDiff:
    before_sequence: int
    after_sequence: int
    modules_added: tuple[ModuleSnapshot, ...]
    modules_removed: tuple[ModuleSnapshot, ...]
    modules_changed: tuple[ModuleChange, ...]
    maps_added: tuple[MemoryMap, ...]
    maps_removed: tuple[MemoryMap, ...]
    threads_added: tuple[int, ...]
    threads_removed: tuple[int, ...]
    threads_changed: tuple[ThreadChange, ...]
    marks_added: tuple[CapturedMark, ...]
    marks_removed: tuple[CapturedMark, ...]
    marks_changed: tuple[MarkChange, ...]
    heap_arenas_added: tuple[HeapArena, ...]
    heap_arenas_removed: tuple[HeapArena, ...]
    heap_arenas_changed: tuple[HeapArenaChange, ...]
    heap_chunks_added: tuple[HeapChunk, ...]
    heap_chunks_removed: tuple[HeapChunk, ...]
    heap_chunks_changed: tuple[HeapChunkChange, ...]
    verifications_added: tuple[Any, ...]

    @property
    def changed(self) -> bool:
        return any(
            (
                self.modules_added,
                self.modules_removed,
                self.modules_changed,
                self.maps_added,
                self.maps_removed,
                self.threads_added,
                self.threads_removed,
                self.threads_changed,
                self.marks_added,
                self.marks_removed,
                self.marks_changed,
                self.heap_arenas_added,
                self.heap_arenas_removed,
                self.heap_arenas_changed,
                self.heap_chunks_added,
                self.heap_chunks_removed,
                self.heap_chunks_changed,
                self.verifications_added,
            )
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "before_sequence": self.before_sequence,
            "after_sequence": self.after_sequence,
            "changed": self.changed,
            "modules": {
                "added": [item.to_json() for item in self.modules_added],
                "removed": [item.to_json() for item in self.modules_removed],
                "changed": [item.to_json() for item in self.modules_changed],
            },
            "maps": {
                "added": [item.to_json() for item in self.maps_added],
                "removed": [item.to_json() for item in self.maps_removed],
            },
            "threads": {
                "added": list(self.threads_added),
                "removed": list(self.threads_removed),
                "changed": [item.to_json() for item in self.threads_changed],
            },
            "marks": {
                "added": [item.to_json() for item in self.marks_added],
                "removed": [item.to_json() for item in self.marks_removed],
                "changed": [item.to_json() for item in self.marks_changed],
            },
            "heap": {
                "arenas": {
                    "added": [item.to_json() for item in self.heap_arenas_added],
                    "removed": [item.to_json() for item in self.heap_arenas_removed],
                    "changed": [item.to_json() for item in self.heap_arenas_changed],
                },
                "chunks": {
                    "added": [item.to_json() for item in self.heap_chunks_added],
                    "removed": [item.to_json() for item in self.heap_chunks_removed],
                    "changed": [item.to_json() for item in self.heap_chunks_changed],
                },
            },
            "verifications_added": [item.to_json() for item in self.verifications_added],
        }


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    sequence: int
    name: str
    timestamp_ns: int
    generation: int
    modules: tuple[ModuleSnapshot, ...]
    maps: tuple[MemoryMap, ...]
    threads: tuple[ThreadFacts, ...]
    marks: tuple[CapturedMark, ...]
    heap_arenas: tuple[HeapArena, ...]
    heap_chunks: tuple[HeapChunk, ...]
    verifications: tuple[Any, ...]
    errors: Mapping[str, str]

    def diff(self, after: "RuntimeSnapshot") -> SnapshotDiff:
        if not isinstance(after, RuntimeSnapshot):
            raise TypeError("snapshot diff requires another RuntimeSnapshot")
        return _snapshot_diff(self, after)

    def to_json(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "name": self.name,
            "timestamp_ns": self.timestamp_ns,
            "generation": self.generation,
            "modules": [item.to_json() for item in self.modules],
            "maps": [item.to_json() for item in self.maps],
            "threads": [item.to_json() for item in self.threads],
            "marks": [item.to_json() for item in self.marks],
            "heap": {
                "arenas": [item.to_json() for item in self.heap_arenas],
                "chunks": [item.to_json() for item in self.heap_chunks],
            },
            "verifications": [item.to_json() for item in self.verifications],
            "errors": dict(self.errors),
        }


class RuntimeHistory(Sequence[RuntimeSnapshot]):
    """Bounded explicit captures plus cheap lifecycle/annotation events."""

    def __init__(self, runtime, *, snapshots: int = 128, events: int = 4096):
        if snapshots <= 0 or events <= 0:
            raise ValueError("history limits must be positive")
        self._runtime = runtime
        self._lock = threading.RLock()
        self._snapshots: deque[RuntimeSnapshot] = deque(maxlen=snapshots)
        self._events: deque[RuntimeEvent] = deque(maxlen=events)
        self._snapshot_sequence = 0
        self._event_sequence = 0
        self._listeners: dict[int, Callable[[str, Any], None]] = {}
        self._next_listener = 1

    def __len__(self) -> int:
        with self._lock:
            return len(self._snapshots)

    def __getitem__(self, index):
        with self._lock:
            if isinstance(index, str):
                matches = [item for item in self._snapshots if item.name == index]
                if not matches:
                    raise KeyError(index)
                return matches[-1]
            return tuple(self._snapshots)[index]

    def __iter__(self) -> Iterator[RuntimeSnapshot]:
        with self._lock:
            return iter(tuple(self._snapshots))

    @property
    def latest(self) -> RuntimeSnapshot | None:
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    @property
    def events(self) -> tuple[RuntimeEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def record(self, kind: str, details: Mapping[str, Any] | None = None) -> RuntimeEvent:
        with self._lock:
            sequence = self._event_sequence
            self._event_sequence += 1
            event = RuntimeEvent(
                sequence,
                time.time_ns(),
                self._runtime.generation,
                str(kind),
                MappingProxyType(dict(details or {})),
            )
            self._events.append(event)
            listeners = tuple(self._listeners.values())
        for listener in listeners:
            try:
                listener("event", event)
            except Exception:
                pass
        return event

    def snapshot(
        self,
        name: str | None = None,
        *,
        modules: bool = True,
        maps: bool = True,
        threads: bool = True,
        frames: int = 16,
        variables: bool = True,
        libc: bool = True,
        marks: bool | Sequence[MemoryMark | str] = True,
        heap: bool = False,
        verifications: bool = True,
    ) -> RuntimeSnapshot:
        with self._lock:
            sequence = self._snapshot_sequence
            self._snapshot_sequence += 1
        if name is None:
            name = f"snapshot-{sequence}"
        if not isinstance(name, str) or not name:
            raise ValueError("snapshot name must be nonempty text")
        errors: dict[str, str] = {}
        captured_modules = ()
        if modules:
            try:
                captured_modules = tuple(ModuleSnapshot.capture(item) for item in self._runtime.modules)
            except Exception as error:
                errors["modules"] = _error(error)
        captured_maps = ()
        if maps:
            try:
                captured_maps = tuple(self._runtime.maps)
            except Exception as error:
                errors["maps"] = _error(error)
        captured_threads = []
        if threads:
            try:
                summaries = tuple(self._runtime.threads)
            except Exception as error:
                summaries = ()
                errors["threads"] = _error(error)
            for summary in summaries:
                try:
                    captured_threads.append(
                        summary.capture(frames=frames, registers=True, variables=variables, libc=libc)
                    )
                except Exception as error:
                    errors[f"thread:{summary.id}"] = _error(error)
        selected_marks = _select_marks(self._runtime, marks)
        captured_marks = tuple(mark.capture() for mark in selected_marks)
        arenas: tuple[HeapArena, ...] = ()
        chunks = []
        if heap:
            try:
                arenas = self._runtime.heap.arenas()
            except Exception as error:
                errors["heap:arenas"] = _error(error)
            for mark in selected_marks:
                if mark.kind is not MarkKind.HEAP_CHUNK:
                    continue
                try:
                    chunks.append(self._runtime.heap.chunk(mark.address, from_base=True))
                except Exception as error:
                    errors[f"heap:mark:{mark.id}"] = _error(error)
        snapshot = RuntimeSnapshot(
            sequence,
            name,
            time.time_ns(),
            self._runtime.generation,
            captured_modules,
            captured_maps,
            tuple(captured_threads),
            captured_marks,
            arenas,
            tuple(chunks),
            tuple(self._runtime.verify) if verifications else (),
            MappingProxyType(errors),
        )
        with self._lock:
            self._snapshots.append(snapshot)
            listeners = tuple(self._listeners.values())
        self.record("snapshot", {"sequence": sequence, "name": name})
        for listener in listeners:
            try:
                listener("snapshot", snapshot)
            except Exception:
                pass
        return snapshot

    def diff(self, before, after=None) -> SnapshotDiff:
        if after is None:
            after = self.latest
        before = self._resolve(before)
        after = self._resolve(after)
        return before.diff(after)

    def _resolve(self, value) -> RuntimeSnapshot:
        if isinstance(value, RuntimeSnapshot):
            return value
        if value is None:
            raise ValueError("history has no snapshot to select")
        return self[value]

    def subscribe(self, listener: Callable[[str, Any], None]) -> Callable[[], None]:
        if not callable(listener):
            raise TypeError("history listener must be callable")
        with self._lock:
            token = self._next_listener
            self._next_listener += 1
            self._listeners[token] = listener

        def unsubscribe() -> None:
            with self._lock:
                self._listeners.pop(token, None)

        return unsubscribe


def _select_marks(runtime, selection) -> tuple[MemoryMark, ...]:
    if selection is True:
        return tuple(runtime.marks)
    if selection is False or selection is None:
        return ()
    result = []
    for item in selection:
        result.append(item if isinstance(item, MemoryMark) else runtime.marks[str(item)])
    return tuple(result)


def _snapshot_diff(before: RuntimeSnapshot, after: RuntimeSnapshot) -> SnapshotDiff:
    before_modules = {item.id: item for item in before.modules}
    after_modules = {item.id: item for item in after.modules}
    modules_added = tuple(after_modules[key] for key in sorted(after_modules.keys() - before_modules.keys()))
    modules_removed = tuple(before_modules[key] for key in sorted(before_modules.keys() - after_modules.keys()))
    modules_changed = []
    for key in sorted(before_modules.keys() & after_modules.keys()):
        fields = _field_changes(before_modules[key].to_json(), after_modules[key].to_json(), exclude={"id"})
        if fields:
            modules_changed.append(ModuleChange(key, MappingProxyType(fields)))

    before_maps = {_map_key(item): item for item in before.maps}
    after_maps = {_map_key(item): item for item in after.maps}
    maps_added = tuple(after_maps[key] for key in sorted(after_maps.keys() - before_maps.keys(), key=repr))
    maps_removed = tuple(before_maps[key] for key in sorted(before_maps.keys() - after_maps.keys(), key=repr))

    before_threads = {item.id: item for item in before.threads}
    after_threads = {item.id: item for item in after.threads}
    thread_changes = []
    for key in sorted(before_threads.keys() & after_threads.keys()):
        change = _thread_change(before_threads[key], after_threads[key])
        if change is not None:
            thread_changes.append(change)

    before_marks = {item.mark_id: item for item in before.marks}
    after_marks = {item.mark_id: item for item in after.marks}
    mark_changes = []
    for key in sorted(before_marks.keys() & after_marks.keys()):
        change = _mark_change(before_marks[key], after_marks[key])
        if change is not None:
            mark_changes.append(change)

    before_arenas = {item.address: item for item in before.heap_arenas}
    after_arenas = {item.address: item for item in after.heap_arenas}
    arena_changes = []
    for key in sorted(before_arenas.keys() & after_arenas.keys()):
        fields = _field_changes(
            before_arenas[key].to_json(),
            after_arenas[key].to_json(),
            exclude={"address"},
        )
        if fields:
            arena_changes.append(HeapArenaChange(key, MappingProxyType(fields)))

    # Allocation identity includes arena, base, and generation.  Address reuse
    # therefore appears as removal plus addition instead of conflating two
    # logically different objects.
    before_chunks = {item.allocation_id: item for item in before.heap_chunks}
    after_chunks = {item.allocation_id: item for item in after.heap_chunks}
    chunk_changes = []
    for key in sorted(before_chunks.keys() & after_chunks.keys()):
        fields = _field_changes(
            before_chunks[key].to_json(),
            after_chunks[key].to_json(),
            exclude={"allocation_id"},
        )
        if fields:
            chunk_changes.append(HeapChunkChange(key, MappingProxyType(fields)))

    prior_verifications = {item.sequence for item in before.verifications}

    return SnapshotDiff(
        before.sequence,
        after.sequence,
        modules_added,
        modules_removed,
        tuple(modules_changed),
        maps_added,
        maps_removed,
        tuple(sorted(after_threads.keys() - before_threads.keys())),
        tuple(sorted(before_threads.keys() - after_threads.keys())),
        tuple(thread_changes),
        tuple(after_marks[key] for key in sorted(after_marks.keys() - before_marks.keys())),
        tuple(before_marks[key] for key in sorted(before_marks.keys() - after_marks.keys())),
        tuple(mark_changes),
        tuple(after_arenas[key] for key in sorted(after_arenas.keys() - before_arenas.keys())),
        tuple(before_arenas[key] for key in sorted(before_arenas.keys() - after_arenas.keys())),
        tuple(arena_changes),
        tuple(after_chunks[key] for key in sorted(after_chunks.keys() - before_chunks.keys())),
        tuple(before_chunks[key] for key in sorted(before_chunks.keys() - after_chunks.keys())),
        tuple(chunk_changes),
        tuple(
            item
            for item in after.verifications
            if item.sequence not in prior_verifications
        ),
    )


def _thread_change(before: ThreadFacts, after: ThreadFacts) -> ThreadChange | None:
    registers = _field_changes(before.registers, after.registers)
    before_facts = {
        "state": before.state,
        "name": before.name,
        "top_pc": None if before.top is None else before.top.pc,
        **before.libc.to_json(),
    }
    after_facts = {
        "state": after.state,
        "name": after.name,
        "top_pc": None if after.top is None else after.top.pc,
        **after.libc.to_json(),
    }
    facts = _field_changes(before_facts, after_facts)
    variables = _field_changes(_variables(before), _variables(after))
    if not registers and not facts and not variables:
        return None
    return ThreadChange(
        before.id,
        MappingProxyType(registers),
        MappingProxyType(facts),
        MappingProxyType(variables),
    )


def _variables(thread: ThreadFacts) -> dict[str, Any]:
    result = {}
    for frame in thread.frames:
        for category, values in (("arg", frame.arguments), ("local", frame.locals)):
            for value in values:
                key = f"{frame.level}:{category}:{value.scope_depth}:{value.name}"
                result[key] = {
                    "type": value.type_name,
                    "available": value.available,
                    "optimized_out": value.optimized_out,
                    "value": value.value,
                    "address": value.address,
                    "pointer": value.pointer,
                }
    return result


def _mark_change(before: CapturedMark, after: CapturedMark) -> MarkChange | None:
    before_fields = {
        "label": before.label,
        "kind": before.kind.value,
        "address": before.address,
        "size": before.size,
        "display": before.display,
        "error": before.error,
        "allocation_id": before.allocation_id,
        "allocation_generation": before.allocation_generation,
    }
    after_fields = {
        "label": after.label,
        "kind": after.kind.value,
        "address": after.address,
        "size": after.size,
        "display": after.display,
        "error": after.error,
        "allocation_id": after.allocation_id,
        "allocation_generation": after.allocation_generation,
    }
    fields = _field_changes(before_fields, after_fields)
    byte_changes = _byte_changes(before.data, after.data)
    before_typed = {item.path: item.to_json() for item in before.typed_fields}
    after_typed = {item.path: item.to_json() for item in after.typed_fields}
    typed_fields = _field_changes(before_typed, after_typed)
    if not fields and not byte_changes and not typed_fields:
        return None
    return MarkChange(
        before.mark_id,
        MappingProxyType(fields),
        byte_changes,
        MappingProxyType(typed_fields),
    )


def _field_changes(before: Mapping, after: Mapping, *, exclude=frozenset()) -> dict[str, ValueChange]:
    result = {}
    for key in sorted(before.keys() | after.keys(), key=str):
        if key in exclude:
            continue
        left = before.get(key)
        right = after.get(key)
        if left != right:
            result[str(key)] = ValueChange(left, right)
    return result


def _byte_changes(before: bytes | None, after: bytes | None) -> tuple[ByteRangeChange, ...]:
    if before is None or after is None:
        return () if before is after else (ByteRangeChange(0, before or b"", after or b""),)
    limit = max(len(before), len(after))
    changes = []
    start = None
    for offset in range(limit):
        different = (before[offset : offset + 1] != after[offset : offset + 1])
        if different and start is None:
            start = offset
        if not different and start is not None:
            changes.append(ByteRangeChange(start, before[start:offset], after[start:offset]))
            start = None
    if start is not None:
        changes.append(ByteRangeChange(start, before[start:limit], after[start:limit]))
    return tuple(changes)


def _map_key(value: MemoryMap):
    return (
        value.start,
        value.end,
        value.permissions,
        value.offset,
        value.path,
        value.inode,
        value.private,
        value.module_id,
    )


def _event_details(value):
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _event_details(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_event_details(item) for item in value]
    if hasattr(value, "to_json"):
        return value.to_json()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _error(error: Exception) -> str:
    return f"{type(error).__name__}: {error}"


__all__ = [
    "ByteRangeChange",
    "HeapArenaChange",
    "HeapChunkChange",
    "MarkChange",
    "ModuleChange",
    "ModuleSnapshot",
    "RuntimeEvent",
    "RuntimeHistory",
    "RuntimeSnapshot",
    "SnapshotDiff",
    "ThreadChange",
    "ValueChange",
]
