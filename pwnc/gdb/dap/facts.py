"""Ergonomic per-thread debugger facts.

The public objects in this module are regular Python values.  Their explicit
``to_json`` methods exist solely for the native viewer boundary.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


class RegisterSet(Mapping[str, int]):
    """One coherent batched register capture with attribute access."""

    def __init__(self, values: Mapping[str, int] = ()):
        self._values = MappingProxyType({str(name): int(value) for name, value in dict(values).items()})

    def __getitem__(self, name: str) -> int:
        return self._values[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __getattr__(self, name: str) -> int:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._values[name]
        except KeyError as error:
            raise AttributeError(name) from error

    def to_json(self) -> dict[str, int]:
        return dict(self._values)


@dataclass(frozen=True, slots=True)
class ScopedVariable:
    name: str
    type_name: str | None
    argument: bool
    scope_depth: int
    available: bool
    optimized_out: bool
    value: str | None
    address: int | None
    pointer: int | None
    error: Mapping[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type_name,
            "argument": self.argument,
            "scope_depth": self.scope_depth,
            "available": self.available,
            "optimized_out": self.optimized_out,
            "value": self.value,
            "address": self.address,
            "pointer": self.pointer,
            "error": None if self.error is None else dict(self.error),
        }


@dataclass(frozen=True, slots=True)
class RuntimeFrame:
    level: int
    pc: int
    name: str | None
    frame_type: str
    source: str | None
    line: int | None
    arguments: tuple[ScopedVariable, ...]
    locals: tuple[ScopedVariable, ...]

    def variable(self, name: str, *, scope_depth: int | None = None) -> ScopedVariable | None:
        matches = [
            item
            for item in (*self.arguments, *self.locals)
            if item.name == name and (scope_depth is None or item.scope_depth == scope_depth)
        ]
        if not matches:
            return None
        return min(matches, key=lambda item: item.scope_depth)

    def to_json(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "pc": self.pc,
            "name": self.name,
            "type": self.frame_type,
            "source": self.source,
            "line": self.line,
            "arguments": [item.to_json() for item in self.arguments],
            "locals": [item.to_json() for item in self.locals],
        }


@dataclass(frozen=True, slots=True)
class LibcThreadFacts:
    tls: int | None = None
    tls_provider: str | None = None
    tcache: int | None = None
    arena: int | None = None
    errno: int | None = None
    canary: int | None = None
    canary_source: int | None = None
    canary_error: Mapping[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "tls": self.tls,
            "tls_provider": self.tls_provider,
            "tcache": self.tcache,
            "arena": self.arena,
            "errno": self.errno,
            "canary": self.canary,
            "canary_source": self.canary_source,
            "canary_error": None if self.canary_error is None else dict(self.canary_error),
        }


@dataclass(frozen=True, slots=True)
class ThreadFacts:
    id: int
    inferior_thread: int
    name: str | None
    details: str | None
    state: str
    ptid: tuple[int, int, int]
    frames: tuple[RuntimeFrame, ...]
    registers: RegisterSet
    libc: LibcThreadFacts
    errors: Mapping[str, Any]

    @property
    def reg(self) -> RegisterSet:
        return self.registers

    @property
    def top(self) -> RuntimeFrame | None:
        return self.frames[0] if self.frames else None

    def frame(self, level: int = 0) -> RuntimeFrame | None:
        return next((item for item in self.frames if item.level == level), None)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "inferior_thread": self.inferior_thread,
            "name": self.name,
            "details": self.details,
            "state": self.state,
            "ptid": list(self.ptid),
            "frames": [item.to_json() for item in self.frames],
            "registers": self.registers.to_json(),
            "libc": self.libc.to_json(),
            "errors": dict(self.errors),
        }


@dataclass(frozen=True, slots=True)
class ThreadView:
    _threads: "ThreadViews"
    id: int
    inferior_thread: int
    name: str | None
    details: str | None
    state: str
    ptid: tuple[int, int, int]

    def capture(
        self,
        *,
        frames: int = 64,
        registers: bool = True,
        variables: bool = True,
        libc: bool = True,
    ) -> ThreadFacts:
        return self._threads.capture(
            self.id,
            frames=frames,
            registers=registers,
            variables=variables,
            libc=libc,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "inferior_thread": self.inferior_thread,
            "name": self.name,
            "details": self.details,
            "state": self.state,
            "ptid": list(self.ptid),
        }


class ThreadViews(Sequence[ThreadView]):
    """Lazy thread summaries and explicit coherent fact captures."""

    def __init__(self, runtime):
        self._runtime = runtime
        self._lock = threading.Lock()
        self._generation = -1
        self._cache: tuple[ThreadView, ...] = ()

    def _items(self) -> tuple[ThreadView, ...]:
        generation = self._runtime.generation
        with self._lock:
            if self._generation == generation:
                return self._cache
        raw = self._runtime._gdb._request("pwncRuntimeThreads").get("threads", ())
        items = tuple(_thread_view(self, item) for item in raw)
        with self._lock:
            if self._runtime.generation == generation:
                self._generation = generation
                self._cache = items
        return items

    def __len__(self) -> int:
        return len(self._items())

    def __getitem__(self, index):
        return self._items()[index]

    def __iter__(self) -> Iterator[ThreadView]:
        return iter(self._items())

    def by_id(self, thread_id: int) -> ThreadView | None:
        return next((item for item in self._items() if item.id == int(thread_id)), None)

    @property
    def current(self) -> ThreadView | None:
        current = self._runtime._gdb.thread()
        return None if current is None else self.by_id(current)

    def refresh(self) -> "ThreadViews":
        with self._lock:
            self._generation = -1
            self._cache = ()
        self._items()
        return self

    def capture(
        self,
        thread_id: int | None = None,
        *,
        frames: int = 64,
        registers: bool = True,
        variables: bool = True,
        libc: bool = True,
    ) -> ThreadFacts:
        if thread_id is None:
            thread_id = self._runtime._gdb.thread()
        if thread_id is None:
            raise RuntimeError("GDB has no selected thread")
        if isinstance(frames, bool) or not isinstance(frames, int) or not 0 <= frames <= 4096:
            raise ValueError("frames must be an integer between 0 and 4096")
        raw = self._runtime._gdb._request(
            "pwncRuntimeThread",
            {
                "threadId": int(thread_id),
                "maxFrames": frames,
                "registers": bool(registers),
                "variables": bool(variables),
                "libcFacts": bool(libc),
            },
        )
        return _thread_facts(raw)

    def to_json(self) -> list[dict[str, Any]]:
        return [item.to_json() for item in self._items()]


def _thread_view(owner: ThreadViews, raw: Mapping[str, Any]) -> ThreadView:
    ptid = tuple(int(item) for item in raw.get("ptid", (0, 0, 0)))
    return ThreadView(
        owner,
        int(raw["id"]),
        int(raw.get("inferior_thread") or 0),
        raw.get("name"),
        raw.get("details"),
        str(raw.get("state") or "unknown"),
        (ptid + (0, 0, 0))[:3],
    )


def _variable(raw: Mapping[str, Any]) -> ScopedVariable:
    return ScopedVariable(
        str(raw.get("name") or ""),
        raw.get("type"),
        bool(raw.get("argument")),
        int(raw.get("scope_depth") or 0),
        bool(raw.get("available")),
        bool(raw.get("optimized_out")),
        raw.get("value"),
        None if raw.get("address") is None else int(raw["address"]),
        None if raw.get("pointer") is None else int(raw["pointer"]),
        raw.get("error"),
    )


def _thread_facts(raw: Mapping[str, Any]) -> ThreadFacts:
    frames = []
    for item in raw.get("frames", ()):
        frames.append(
            RuntimeFrame(
                int(item["level"]),
                int(item["pc"]),
                item.get("name"),
                str(item.get("type") or "unknown"),
                item.get("source"),
                None if item.get("line") is None else int(item["line"]),
                tuple(_variable(value) for value in item.get("arguments", ())),
                tuple(_variable(value) for value in item.get("locals", ())),
            )
        )
    libc = raw.get("libc") or {}
    ptid = tuple(int(item) for item in raw.get("ptid", (0, 0, 0)))
    return ThreadFacts(
        int(raw["id"]),
        int(raw.get("inferior_thread") or 0),
        raw.get("name"),
        raw.get("details"),
        str(raw.get("state") or "unknown"),
        (ptid + (0, 0, 0))[:3],
        tuple(frames),
        RegisterSet(raw.get("registers") or {}),
        LibcThreadFacts(
            tls=libc.get("tls"),
            tls_provider=libc.get("tls_provider"),
            tcache=libc.get("tcache"),
            arena=libc.get("arena"),
            errno=libc.get("errno"),
            canary=libc.get("canary"),
            canary_source=libc.get("canary_source"),
            canary_error=libc.get("canary_error"),
        ),
        MappingProxyType(dict(raw.get("errors") or {})),
    )


__all__ = [
    "LibcThreadFacts",
    "RegisterSet",
    "RuntimeFrame",
    "ScopedVariable",
    "ThreadFacts",
    "ThreadView",
    "ThreadViews",
]
