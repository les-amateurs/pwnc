"""Ergonomic host-side views of one live GDB inferior.

These are normal Python objects intended for exploit scripts.  JSON is only an
explicit export boundary for the standalone viewer; it does not define the
internal API or leak dictionaries into ordinary user code.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from pwnc.types.containers import Array, Enum
from pwnc.types.primitives import Double, Float, Int, Ptr
from pwnc.types.provider import BufferProvider, ByteOrder
from pwnc.types.serial import from_descriptor
from pwnc.types.value import ArrayValue, Value, _typed_value as _primitive_value

from .client import DapBytesProvider
from .facts import ThreadViews
from .heap import Heap
from .history import RuntimeHistory
from .inspector import RuntimeViewer
from .marks import Marks
from .verify import Verifier


class RuntimeUnavailableError(RuntimeError):
    """A requested live-inferior fact is not available."""


class AmbiguousModuleError(RuntimeError):
    """A convenience selector matched more than one loaded module."""


def _json_copy(value):
    """Validate and copy one viewer-facing JSON value."""

    return json.loads(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")))


class _AddressedBufferProvider(BufferProvider):
    """A coherent captured byte range with its original inferior address."""

    def __init__(self, data, address, byteorder, ptrbits):
        super().__init__(data, byteorder, ptrbits)
        self._address = int(address)

    @property
    def address(self):
        return self._address

    def rebase(self, address):
        offset = int(address) - self._address
        if offset < 0 or offset > len(self._data):
            raise RuntimeUnavailableError("pointer leaves the coherent typed-memory capture")
        provider = _AddressedBufferProvider(self._data[offset:], address, self.byteorder, self.ptrbits)
        return provider


@dataclass(frozen=True, slots=True)
class MemoryMap:
    start: int
    end: int
    permissions: str
    offset: int
    path: str
    inode: int | None
    private: bool | None
    module_id: str | None = None

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return "r" in self.permissions[:1]

    @property
    def writable(self) -> bool:
        return len(self.permissions) > 1 and self.permissions[1] == "w"

    @property
    def executable(self) -> bool:
        return len(self.permissions) > 2 and self.permissions[2] == "x"

    def contains(self, address: int, size: int = 1) -> bool:
        if size < 0:
            raise ValueError("size cannot be negative")
        return self.start <= int(address) and int(address) + size <= self.end

    def to_json(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "permissions": self.permissions,
            "offset": self.offset,
            "path": self.path,
            "inode": self.inode,
            "private": self.private,
            "module_id": self.module_id,
        }


class MemoryMaps(Sequence[MemoryMap]):
    def __init__(self, runtime: "Runtime"):
        self._runtime = runtime

    def _items(self) -> tuple[MemoryMap, ...]:
        return self._runtime._maps()

    def __len__(self) -> int:
        return len(self._items())

    def __getitem__(self, index):
        return self._items()[index]

    def __iter__(self) -> Iterator[MemoryMap]:
        return iter(self._items())

    def at(self, address: int) -> MemoryMap | None:
        address = int(address)
        return next((item for item in self._items() if item.contains(address)), None)

    def require(self, address: int) -> MemoryMap:
        result = self.at(address)
        if result is None:
            raise RuntimeUnavailableError(f"no known mapping contains {int(address):#x}")
        return result

    def refresh(self) -> "MemoryMaps":
        self._runtime.refresh()
        return self

    def to_json(self) -> list[dict[str, Any]]:
        return [item.to_json() for item in self._items()]


class ModuleAddressTable(Mapping[str, int]):
    """Runtime addresses for one module's symbols, GOT, or PLT."""

    def __init__(self, module: "Module", table: str):
        self._module = module
        self._table = table

    def _offsets(self) -> Mapping[str, int]:
        return getattr(self._module.profile, self._table)

    def __getitem__(self, name: str) -> int:
        return self._module.address(self._offsets()[name])

    def __iter__(self) -> Iterator[str]:
        return iter(self._offsets())

    def __len__(self) -> int:
        return len(self._offsets())

    def __getattr__(self, name: str) -> int:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self[name]
        except KeyError as error:
            raise AttributeError(name) from error

    def offset(self, name: str) -> int:
        return int(self._offsets()[name])

    def to_json(self) -> dict[str, int]:
        return {name: self._module.address(offset) for name, offset in self._offsets().items()}


@dataclass(frozen=True, slots=True)
class Module:
    """One exact loaded image with lazy artifact inspection."""

    _runtime: "Runtime"
    id: str
    name: str
    path: str | None
    kind: str
    build_id: str | None
    base: int | None
    end: int | None
    load_bias: int | None
    map_indexes: tuple[int, ...]

    @property
    def loaded(self) -> bool:
        return self.base is not None

    @property
    def size(self) -> int | None:
        if self.base is None or self.end is None:
            return None
        return self.end - self.base

    @property
    def maps(self) -> tuple[MemoryMap, ...]:
        mappings = self._runtime._maps()
        return tuple(mappings[index] for index in self.map_indexes if index < len(mappings))

    @property
    def sym(self) -> ModuleAddressTable:
        return ModuleAddressTable(self, "symbol_offsets")

    @property
    def got(self) -> ModuleAddressTable:
        return ModuleAddressTable(self, "got_offsets")

    @property
    def plt(self) -> ModuleAddressTable:
        return ModuleAddressTable(self, "plt_offsets")

    @property
    def profile(self):
        if self.path is None:
            raise RuntimeUnavailableError(f"module {self.name!r} has no local artifact path")
        try:
            return _profile_for_path(self.path)
        except Exception as error:
            raise RuntimeUnavailableError(f"cannot inspect module {self.path!r}: {error}") from error

    def address(self, offset: int) -> int:
        if self.load_bias is None:
            raise RuntimeUnavailableError(f"module {self.name!r} has no known load bias")
        return self.load_bias + int(offset)

    def offset(self, address: int) -> int:
        if self.load_bias is None:
            raise RuntimeUnavailableError(f"module {self.name!r} has no known load bias")
        return int(address) - self.load_bias

    def contains(self, address: int) -> bool:
        return any(mapping.contains(int(address)) for mapping in self.maps)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "kind": self.kind,
            "build_id": self.build_id,
            "base": self.base,
            "end": self.end,
            "load_bias": self.load_bias,
            "map_indexes": list(self.map_indexes),
        }


class Modules(Sequence[Module]):
    def __init__(self, runtime: "Runtime"):
        self._runtime = runtime

    def _items(self) -> tuple[Module, ...]:
        return self._runtime._modules()

    def __len__(self) -> int:
        return len(self._items())

    def __getitem__(self, index):
        if isinstance(index, str):
            matches = [item for item in self._items() if item.id == index or item.name == index or item.path == index]
            return self._unique(matches, index)
        return self._items()[index]

    def __iter__(self) -> Iterator[Module]:
        return iter(self._items())

    @staticmethod
    def _unique(matches: list[Module], label: str) -> Module | None:
        if not matches:
            return None
        if len(matches) > 1:
            raise AmbiguousModuleError(f"module selector {label!r} matched {len(matches)} loaded images")
        return matches[0]

    def by_kind(self, kind: str) -> Module | None:
        return self._unique([item for item in self._items() if item.kind == kind], kind)

    @property
    def main(self) -> Module | None:
        return self.by_kind("main")

    @property
    def libc(self) -> Module | None:
        return self.by_kind("libc")

    @property
    def loader(self) -> Module | None:
        return self.by_kind("loader")

    def by_build_id(self, build_id: str) -> Module | None:
        normalized = build_id.lower().removeprefix("0x")
        return self._unique([item for item in self._items() if item.build_id == normalized], normalized)

    def at(self, address: int) -> Module | None:
        return self._unique([item for item in self._items() if item.contains(int(address))], hex(int(address)))

    def refresh(self) -> "Modules":
        self._runtime.refresh()
        return self

    def to_json(self) -> list[dict[str, Any]]:
        return [item.to_json() for item in self._items()]


@dataclass(frozen=True, slots=True)
class TypedMemoryCapture:
    address: int
    type: Any
    value: Value
    data: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "type": str(self.type),
            "size": len(self.data),
            "encoding": "base64",
            "data": base64.b64encode(self.data).decode("ascii"),
            "display": str(self.value),
        }


class Memory:
    def __init__(self, runtime: "Runtime"):
        self._runtime = runtime

    @property
    def _gdb(self):
        return self._runtime._gdb

    def read(self, address: int, size: int, **kwargs) -> bytes:
        return self._gdb.read(int(address), int(size), **kwargs)

    def write(self, address: int, data, **kwargs):
        return self._gdb.write(int(address), data, **kwargs)

    def place(self, address: int, payload, **kwargs):
        """Write a semantic payload object and return its retained mark."""
        if self._runtime.marks._prepare_payload(int(address), payload) is None:
            raise TypeError("place() requires a Payload, ROPChain, lowered libc ROP, staged payload, or FSOPWrite")
        return self._gdb.write(int(address), payload, **kwargs)

    def type(self, name: str):
        if not isinstance(name, str) or not name:
            raise ValueError("type name must be nonempty text")
        result = self._gdb._request("pwncLookupType", {"name": name})
        return from_descriptor(result["type"])

    def view(self, address: int, ptype):
        if isinstance(ptype, str):
            ptype = self.type(ptype)
        provider = DapBytesProvider(
            self._gdb.transport,
            int(address),
            self._gdb._byteorder,
            self._gdb._ptrbits,
            on_write=self._gdb._on_typed_memory_write,
        )
        return _make_value(ptype, provider)

    def capture(self, address: int, ptype) -> TypedMemoryCapture:
        if isinstance(ptype, str):
            ptype = self.type(ptype)
        raw = self.read(int(address), ptype.nbytes)
        provider = _AddressedBufferProvider(raw, int(address), self._gdb._byteorder, self._gdb._ptrbits)
        return TypedMemoryCapture(int(address), ptype, _make_value(ptype, provider), raw)


def _make_value(ptype, provider):
    if isinstance(ptype, (Int, Float, Double, Ptr, Enum)):
        return _primitive_value(ptype, provider, 0)
    if isinstance(ptype, Array):
        return ArrayValue(ptype, provider, 0)
    return Value(ptype, provider, 0)


class Runtime:
    """Generation-cached facts for one GDB controller."""

    def __init__(self, gdb):
        self._gdb = gdb
        self._lock = threading.RLock()
        self._generation = 0
        self._info_generation = -1
        self._info_cache = None
        self._maps_cache: tuple[MemoryMap, ...] = ()
        self._modules_cache: tuple[Module, ...] = ()
        self.history = RuntimeHistory(self)
        self.modules = Modules(self)
        self.maps = MemoryMaps(self)
        self.memory = Memory(self)
        self.threads = ThreadViews(self)
        self.marks = Marks(self)
        self.heap = Heap(self)
        self.verify = Verifier(self)
        self.viewer = RuntimeViewer(self)

    def _record_event(self, kind: str, value) -> None:
        details = value if isinstance(value, Mapping) else {"value": value}
        self.history.record(kind, details)

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    @property
    def architecture(self) -> str | None:
        return self._info().get("architecture")

    @property
    def target(self):
        from payloads import resolve_target

        architecture = (self.architecture or "").lower()
        if "aarch64" in architecture or "arm64" in architecture:
            name = "arm64"
        elif "arm" in architecture:
            name = "arm"
        elif "x86-64" in architecture or "x86_64" in architecture or "amd64" in architecture:
            name = "x86_64"
        elif "i386" in architecture or "i686" in architecture or "x86" in architecture:
            name = "x86"
        else:
            raise RuntimeUnavailableError(f"unsupported GDB architecture {self.architecture!r}")
        endian = "little" if self._gdb._byteorder == ByteOrder.Little else "big"
        return resolve_target(name, bits=self._gdb._ptrbits, endian=endian)

    def invalidate(self) -> None:
        with self._lock:
            self._generation += 1
            self._info_cache = None
            self._info_generation = -1
            self._maps_cache = ()
            self._modules_cache = ()

    def refresh(self) -> "Runtime":
        self.invalidate()
        self._info()
        return self

    def _snapshot(self) -> tuple[Mapping[str, Any], tuple[MemoryMap, ...], tuple[Module, ...]]:
        with self._lock:
            generation = self._generation
            if self._info_cache is not None and self._info_generation == generation:
                return self._info_cache, self._maps_cache, self._modules_cache
        info = self._gdb._request("pwncRuntimeInfo")
        if not isinstance(info, dict):
            raise RuntimeUnavailableError("GDB returned invalid runtime information")
        maps = []
        for item in info.get("maps", ()):
            maps.append(
                MemoryMap(
                    int(item["start"]),
                    int(item["end"]),
                    str(item.get("permissions") or "---"),
                    int(item.get("offset") or 0),
                    str(item.get("path") or ""),
                    None if item.get("inode") is None else int(item["inode"]),
                    item.get("private"),
                )
            )
        normalized_modules = []
        seen_ids = {}
        module_ids = {}
        for module in info.get("modules", ()):
            build_id = module.get("build_id")
            path = module.get("path")
            if build_id is None and path:
                try:
                    build_id = _profile_for_path(path).build_id
                except Exception:
                    pass
            module_id = str(module["id"])
            if build_id and module_id.startswith("path:"):
                module_id = "build-id:" + str(build_id)
            duplicate = seen_ids.get(module_id, 0)
            seen_ids[module_id] = duplicate + 1
            if duplicate:
                module_id += f"#{duplicate + 1}"
            normalized_modules.append((module, module_id, build_id))
            for index in module.get("map_indexes", ()):
                module_ids[int(index)] = module_id
        maps = [
            MemoryMap(
                item.start,
                item.end,
                item.permissions,
                item.offset,
                item.path,
                item.inode,
                item.private,
                module_ids.get(index),
            )
            for index, item in enumerate(maps)
        ]
        modules = []
        for item, module_id, build_id in normalized_modules:
            indexes = tuple(int(index) for index in item.get("map_indexes", ()))
            load_bias = item.get("load_bias")
            if load_bias is None:
                load_bias = _load_bias(
                    item.get("path"),
                    tuple(maps[index] for index in indexes if index < len(maps)),
                )
            modules.append(
                Module(
                    self,
                    module_id,
                    str(item["name"]),
                    item.get("path"),
                    str(item.get("kind") or "shared-library"),
                    build_id,
                    item.get("base"),
                    item.get("end"),
                    load_bias,
                    indexes,
                )
            )
        copied = _json_copy(info)
        with self._lock:
            if self._generation == generation:
                self._info_cache = copied
                self._info_generation = generation
                self._maps_cache = tuple(maps)
                self._modules_cache = tuple(modules)
        return copied, tuple(maps), tuple(modules)

    def _info(self) -> Mapping[str, Any]:
        return self._snapshot()[0]

    def _maps(self) -> tuple[MemoryMap, ...]:
        return self._snapshot()[1]

    def _modules(self) -> tuple[Module, ...]:
        return self._snapshot()[2]

    @property
    def main(self) -> Module | None:
        return self.modules.main

    @property
    def libc(self) -> Module | None:
        return self.modules.libc

    @property
    def loader(self) -> Module | None:
        return self.modules.loader

    @property
    def layout(self):
        from payloads.model import RuntimeLayout

        main = self.main
        libc = self.libc
        loader = self.loader
        extras = {
            item.id: item.load_bias
            for item in self.modules
            if item.load_bias is not None and item not in {main, libc, loader}
        }
        return RuntimeLayout(
            main_base=None if main is None else main.load_bias,
            libc_base=None if libc is None else libc.load_bias,
            loader_base=None if loader is None else loader.load_bias,
            extra_bases=extras,
        )

    def to_json(self) -> dict[str, Any]:
        info = dict(self._info())
        info["maps"] = self.maps.to_json()
        info["modules"] = self.modules.to_json()
        info["generation"] = self.generation
        return _json_copy(info)


def _load_bias(path: str | None, mappings: tuple[MemoryMap, ...]) -> int | None:
    if path is None or not mappings:
        return None
    try:
        profile = _profile_for_path(path)
    except Exception:
        return None
    candidates: dict[int, int] = {}
    for mapping in mappings:
        for segment in profile.load_ranges:
            file_delta = segment.file_offset - mapping.offset
            if file_delta < 0 or file_delta >= mapping.size:
                continue
            candidate = mapping.start - segment.start + file_delta
            candidates[candidate] = candidates.get(candidate, 0) + 1
    if not candidates:
        return None
    return max(candidates, key=lambda value: (candidates[value], -abs(value)))


def _profile_for_path(path: str | os.PathLike[str]):
    normalized = os.path.realpath(os.fsdecode(path))
    stat = os.stat(normalized)
    return _cached_profile(normalized, stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=128)
def _cached_profile(path: str, _mtime_ns: int, _size: int):
    from payloads.elf import inspect_elf

    return inspect_elf(Path(path))


__all__ = [
    "AmbiguousModuleError",
    "Memory",
    "MemoryMap",
    "MemoryMaps",
    "Module",
    "ModuleAddressTable",
    "Modules",
    "Runtime",
    "RuntimeUnavailableError",
    "TypedMemoryCapture",
]
