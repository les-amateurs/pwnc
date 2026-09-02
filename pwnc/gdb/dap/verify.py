"""Explicit debugger-truth verification for exploit-derived facts."""

from __future__ import annotations

import base64
import itertools
import math
import threading
import time
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .heap import HeapChunk
from .marks import MemoryMark


class VerificationError(AssertionError):
    def __init__(self, result: "VerificationResult"):
        self.result = result
        super().__init__(f"{result.name}: expected {result.expected!r}, observed {result.actual!r}")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    sequence: int
    timestamp_ns: int
    name: str
    kind: str
    ok: bool
    expected: Any
    actual: Any
    details: Mapping[str, Any]

    def require(self) -> "VerificationResult":
        if not self.ok:
            raise VerificationError(self)
        return self

    def to_json(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp_ns": self.timestamp_ns,
            "name": self.name,
            "kind": self.kind,
            "ok": self.ok,
            "expected": _json_value(self.expected),
            "actual": _json_value(self.actual),
            "details": _json_value(self.details),
        }


class Verifier(Sequence[VerificationResult]):
    """A bounded verification log; every check requires caller evidence."""

    def __init__(self, runtime, *, limit: int = 1024):
        if limit <= 0:
            raise ValueError("verification history limit must be positive")
        self._runtime = runtime
        self._lock = threading.Lock()
        self._results: deque[VerificationResult] = deque(maxlen=limit)
        self._sequence = itertools.count()

    def __len__(self) -> int:
        with self._lock:
            return len(self._results)

    def __getitem__(self, index):
        with self._lock:
            return tuple(self._results)[index]

    def __iter__(self) -> Iterator[VerificationResult]:
        with self._lock:
            return iter(tuple(self._results))

    @property
    def latest(self) -> VerificationResult | None:
        with self._lock:
            return self._results[-1] if self._results else None

    @property
    def failures(self) -> tuple[VerificationResult, ...]:
        with self._lock:
            return tuple(item for item in self._results if not item.ok)

    def base(self, module, expected: int, *, mapped: bool = False, name: str | None = None) -> VerificationResult:
        expected = _expected_int(expected, "expected base")
        image = self._module(module)
        actual = image.base if mapped else image.load_bias
        label = name or f"{image.kind} {'mapped base' if mapped else 'load bias'}"
        return self._result(label, "base", expected, actual, {"module": image.id, "mapped": mapped})

    def symbol(self, module, symbol: str, expected: int, *, table: str = "sym") -> VerificationResult:
        expected = _expected_int(expected, "expected symbol address")
        image = self._module(module)
        if table not in {"sym", "got", "plt"}:
            raise ValueError("symbol table must be 'sym', 'got', or 'plt'")
        actual = getattr(image, table)[symbol]
        return self._result(
            f"{image.name}:{table}.{symbol}",
            "symbol",
            expected,
            actual,
            {"module": image.id, "symbol": symbol, "table": table},
        )

    def leak(
        self,
        observed: int,
        module,
        *,
        offset: int | None = None,
        symbol: str | None = None,
        name: str | None = None,
    ) -> VerificationResult:
        observed = _expected_int(observed, "observed leak")
        image = self._module(module)
        if (offset is None) == (symbol is None):
            raise TypeError("provide exactly one of offset or symbol")
        if symbol is not None:
            actual = image.sym[symbol]
            detail = {"module": image.id, "symbol": symbol}
            label = name or f"leak of {image.name}:{symbol}"
        else:
            actual = image.address(_expected_int(offset, "image offset"))
            detail = {"module": image.id, "offset": offset}
            label = name or f"leak of {image.name}+{offset:#x}"
        return self._result(label, "leak", observed, actual, detail)

    def identity(
        self,
        module,
        *,
        build_id: str | None = None,
        sha256: str | None = None,
    ) -> tuple[VerificationResult, ...]:
        if build_id is None and sha256 is None:
            raise TypeError("identity verification requires build_id and/or sha256 evidence")
        image = self._module(module)
        results = []
        if build_id is not None:
            normalized = build_id.lower().removeprefix("0x")
            results.append(
                self._result(
                    f"{image.name} build ID",
                    "module-identity",
                    normalized,
                    image.build_id,
                    {"module": image.id},
                )
            )
        if sha256 is not None:
            normalized = sha256.lower()
            results.append(
                self._result(
                    f"{image.name} SHA-256",
                    "module-identity",
                    normalized,
                    image.profile.sha256,
                    {"module": image.id},
                )
            )
        return tuple(results)

    def memory(
        self,
        address: int,
        expected: bytes | bytearray | memoryview,
        *,
        name: str | None = None,
    ) -> VerificationResult:
        address = _expected_int(address, "memory address")
        expected = bytes(expected)
        actual = self._runtime.memory.read(address, len(expected))
        return self._result(
            name or f"memory at {address:#x}",
            "memory",
            expected,
            actual,
            {"address": address, "size": len(expected)},
        )

    def mark(self, mark: MemoryMark | str) -> VerificationResult:
        if not isinstance(mark, MemoryMark):
            mark = self._runtime.marks[str(mark)]
        expected = mark.expected
        if expected is None:
            raise TypeError(f"mark {mark.label!r} has no retained expected bytes")
        actual = self._runtime.memory.read(mark.address, mark.size)
        return self._result(
            f"marked placement {mark.label}",
            "mark",
            expected,
            actual,
            {"mark_id": mark.id, "address": mark.address, "size": mark.size},
        )

    def typed(self, address: int, ptype, expected, *, name: str | None = None) -> VerificationResult:
        if expected is None:
            raise TypeError("typed verification requires explicit expected evidence")
        capture = self._runtime.memory.capture(_expected_int(address, "typed address"), ptype)
        if isinstance(expected, Mapping):
            actual = {str(field): _plain_value(getattr(capture.value, str(field))) for field in expected}
            expected_value = dict(expected)
        else:
            actual = _plain_value(capture.value)
            expected_value = expected
        return self._result(
            name or f"typed value at {capture.address:#x}",
            "typed-memory",
            expected_value,
            actual,
            {"address": capture.address, "type": str(capture.type)},
        )

    def heap(
        self,
        chunk: HeapChunk | int,
        *,
        state: str | None = None,
        size: int | None = None,
        generation: int | None = None,
        from_base: bool = False,
    ) -> tuple[VerificationResult, ...]:
        if state is None and size is None and generation is None:
            raise TypeError("heap verification requires expected state, size, and/or generation")
        current = chunk.refresh() if isinstance(chunk, HeapChunk) else self._runtime.heap.chunk(chunk, from_base=from_base)
        results = []
        details = {"base": current.base, "allocation_id": current.allocation_id}
        if state is not None:
            results.append(self._result(f"heap chunk {current.base:#x} state", "heap", state, current.state, details))
        if size is not None:
            results.append(
                self._result(
                    f"heap chunk {current.base:#x} size",
                    "heap",
                    _expected_int(size, "expected chunk size"),
                    current.size,
                    details,
                )
            )
        if generation is not None:
            results.append(
                self._result(
                    f"heap chunk {current.base:#x} generation",
                    "heap",
                    _expected_int(generation, "expected allocation generation"),
                    current.generation,
                    details,
                )
            )
        return tuple(results)

    def _module(self, selector):
        if all(hasattr(selector, name) for name in ("id", "load_bias", "sym", "kind")):
            return selector
        if not isinstance(selector, str):
            raise TypeError("module must be a loaded Module or text selector")
        if selector in {"main", "libc", "loader"}:
            result = self._runtime.modules.by_kind(selector)
        else:
            result = self._runtime.modules[selector]
        if result is None:
            raise RuntimeError(f"module {selector!r} is not loaded")
        return result

    def _result(self, name, kind, expected, actual, details) -> VerificationResult:
        with self._lock:
            result = VerificationResult(
                next(self._sequence),
                time.time_ns(),
                str(name),
                str(kind),
                expected == actual,
                expected,
                actual,
                MappingProxyType(dict(details)),
            )
            self._results.append(result)
        self._runtime._record_event("verification" if result.ok else "verification-failed", result)
        return result

    def to_json(self) -> list[dict[str, Any]]:
        with self._lock:
            return [item.to_json() for item in self._results]


def _expected_int(value, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer supplied by the caller")
    return value


def _plain_value(value):
    if hasattr(value, "_resolve"):
        resolved = value._resolve()
        return str(resolved) if resolved is value else resolved
    return value


def _json_value(value):
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "to_json"):
        return value.to_json()
    return str(value)


__all__ = ["VerificationError", "VerificationResult", "Verifier"]
