"""Structured glibc heap facts backed by bata24 objects inside GDB."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from .marks import MarkKind, MemoryMark


class HeapUnavailableError(RuntimeError):
    """bata24 could not provide the requested heap fact."""


@dataclass(frozen=True, slots=True)
class HeapArena:
    address: int
    name: str
    main: bool
    heap_base: int | None
    top: int
    last_remainder: int
    system_mem: int
    tcache: int | None

    def to_json(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "main": self.main,
            "heap_base": self.heap_base,
            "top": self.top,
            "last_remainder": self.last_remainder,
            "system_mem": self.system_mem,
            "tcache": self.tcache,
        }


@dataclass(frozen=True, slots=True)
class HeapChunk:
    _heap: "Heap"
    address: int
    base: int
    size: int
    usable_size: int
    previous_size: int
    arena: int
    heap_base: int | None
    state: str
    bins: tuple[str, ...]
    prev_inuse: bool
    mmapped: bool
    non_main_arena: bool
    fd: int | None
    decoded_fd: int | None
    bk: int | None
    allocation_id: str
    generation: int

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def allocated(self) -> bool:
        return self.state in {"allocated", "top"}

    @property
    def free(self) -> bool:
        return self.state in {"tcache", "fastbin", "unsorted", "smallbin", "largebin", "free"}

    def refresh(self) -> "HeapChunk":
        return self._heap.chunk(self.base, from_base=True, arena=self.arena)

    def mark(self, label: str, *, tags=(), metadata=None) -> MemoryMark:
        details = self.to_json()
        details.update(dict(metadata or {}))
        return self._heap._runtime.marks.add(
            self.base,
            self.size,
            label,
            kind=MarkKind.HEAP_CHUNK,
            tags=("heap", self.state, *tags),
            metadata=details,
            allocation_id=self.allocation_id,
            allocation_generation=self.generation,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "base": self.base,
            "size": self.size,
            "usable_size": self.usable_size,
            "previous_size": self.previous_size,
            "arena": self.arena,
            "heap_base": self.heap_base,
            "state": self.state,
            "bins": list(self.bins),
            "flags": {
                "prev_inuse": self.prev_inuse,
                "mmapped": self.mmapped,
                "non_main_arena": self.non_main_arena,
            },
            "fd": self.fd,
            "decoded_fd": self.decoded_fd,
            "bk": self.bk,
            "allocation_id": self.allocation_id,
            "generation": self.generation,
        }


@dataclass(slots=True)
class _ObservedAllocation:
    generation: int
    state: str
    size: int


class Heap:
    """On-demand heap queries; no work occurs on stops unless explicitly enabled."""

    _FREE_STATES = frozenset({"tcache", "fastbin", "unsorted", "smallbin", "largebin", "free"})

    def __init__(self, runtime):
        self._runtime = runtime
        self._lock = threading.Lock()
        self._observed: dict[tuple[int, int], _ObservedAllocation] = {}

    @property
    def available(self) -> bool:
        return bool(self._runtime._info().get("bata24", {}).get("heap"))

    def arenas(self) -> tuple[HeapArena, ...]:
        result = self._runtime._gdb._request("pwncBataHeapArenas")
        if not result.get("available"):
            raise _heap_error(result)
        return tuple(
            HeapArena(
                int(item["address"]),
                str(item["name"]),
                bool(item["main"]),
                None if item.get("heap_base") is None else int(item["heap_base"]),
                int(item["top"]),
                int(item["last_remainder"]),
                int(item["system_mem"]),
                None if item.get("tcache") is None else int(item["tcache"]),
            )
            for item in result.get("arenas", ())
        )

    def chunk(self, address: int, *, from_base: bool = False, arena: int | None = None) -> HeapChunk:
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError("chunk address must be a nonnegative integer")
        if arena is not None and (isinstance(arena, bool) or not isinstance(arena, int) or arena < 0):
            raise ValueError("arena must be a nonnegative address or None")
        result = self._runtime._gdb._request(
            "pwncBataHeapChunk",
            {
                "address": address,
                "fromBase": bool(from_base),
                "arenaAddress": 0 if arena is None else arena,
            },
        )
        if not result.get("available"):
            raise _heap_error(result)
        base = int(result["base"])
        arena_address = int(result["arena"])
        size = int(result["size"])
        state = str(result.get("state") or "unknown")
        generation, event, previous_state = self._generation(arena_address, base, size, state)
        allocation_id = f"{arena_address:x}:{base:x}:{generation}"
        flags = result.get("flags") or {}
        chunk = HeapChunk(
            self,
            int(result["address"]),
            base,
            size,
            int(result["usable_size"]),
            int(result["previous_size"]),
            arena_address,
            None if result.get("heap_base") is None else int(result["heap_base"]),
            state,
            tuple(str(item) for item in result.get("bins", ())),
            bool(flags.get("prev_inuse")),
            bool(flags.get("mmapped")),
            bool(flags.get("non_main_arena")),
            None if result.get("fd") is None else int(result["fd"]),
            None if result.get("decoded_fd") is None else int(result["decoded_fd"]),
            None if result.get("bk") is None else int(result["bk"]),
            allocation_id,
            generation,
        )
        if event is not None:
            details = chunk.to_json()
            details["previous_state"] = previous_state
            self._runtime._record_event(event, details)
        return chunk

    def try_chunk(self, address: int, **options) -> HeapChunk | None:
        try:
            return self.chunk(address, **options)
        except HeapUnavailableError:
            return None

    def _generation(self, arena: int, base: int, size: int, state: str) -> tuple[int, str | None, str | None]:
        key = arena, base
        with self._lock:
            previous = self._observed.get(key)
            generation = 0 if previous is None else previous.generation
            reused = previous is not None and (
                previous.state in self._FREE_STATES and state not in self._FREE_STATES
            )
            resized = previous is not None and previous.size != size
            if reused or resized:
                generation += 1
            self._observed[key] = _ObservedAllocation(generation, state, size)
            if previous is None:
                event = "heap-allocation" if state not in self._FREE_STATES else "heap-observed"
            elif reused:
                event = "heap-reuse"
            elif previous.state not in self._FREE_STATES and state in self._FREE_STATES:
                event = "heap-free"
            elif resized:
                event = "heap-resized"
            elif previous.state != state:
                event = "heap-state"
            else:
                event = None
            return generation, event, None if previous is None else previous.state

    def reset_generations(self) -> None:
        with self._lock:
            self._observed.clear()


def _heap_error(result) -> HeapUnavailableError:
    error = result.get("error") or {}
    detail = error.get("message") or "bata24 heap provider is unavailable"
    return HeapUnavailableError(str(detail))


__all__ = ["Heap", "HeapArena", "HeapChunk", "HeapUnavailableError"]
