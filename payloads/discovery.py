"""Strict, composable discovery over an arbitrary-memory read/write primitive.

Discovery is deliberately separate from transport.  Every address in this
module is an absolute target address, scans are bounded, ambiguous results are
errors, and the only mutating operation is an explicit compare-before-write
ROP insertion plan.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import Enum, IntEnum
from math import lcm
from pathlib import Path

from .arbio import ArbitraryMemory
from .errors import ConstraintError, MemoryAccessError, PayloadError, UnsupportedTargetError
from .model import Image, RuntimeLayout
from .pwntools_compat import ExactELFAdapter, PwntoolsCompatibilityError
from .rop import ROPChain
from .target import ABI, Architecture, Target


class DiscoveryError(PayloadError):
    """A runtime address could not be discovered with strict evidence."""


class DiscoveryNotFoundError(DiscoveryError):
    """No candidate satisfied a requested discovery transition."""


class DiscoveryAmbiguityError(DiscoveryError):
    """More than one candidate satisfied a requested transition."""

    def __init__(self, description: str, candidates: Sequence[DiscoveryCandidate]) -> None:
        self.description = description
        self.candidates = tuple(candidates)
        rendered = ", ".join(f"{item.address:#x}->{item.value:#x}" for item in self.candidates)
        super().__init__(f"ambiguous {description}: {len(self.candidates)} candidates ({rendered})")


class StaleDiscoveryError(DiscoveryError):
    """Memory changed after a mutation plan captured its expected bytes."""


class InconsistentLinkMapError(DiscoveryError):
    """The runtime loader list was malformed or changed during traversal."""


def _integer(value: object, name: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if value < (1 if positive else 0):
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{name} must be {qualifier}")
    return value


def _read_covered(memory: ArbitraryMemory, address: int, size: int) -> bytes:
    """Read a slice through a primitive which may require wider transfers.

    ``ArbitraryMemory.read`` intentionally never over-reads.  Runtime
    structures, instruction bytes, and C strings sometimes occupy sub-word
    fields, while real primitives such as ptrace only transfer aligned words.
    Discovery explicitly reads the smallest aligned covering interval and
    returns only the requested slice.
    """

    _integer(address, "read address")
    _integer(size, "read size")
    if not size:
        return b""
    alignment = memory.traits.read_alignment
    width = memory.traits.read_width
    if address % alignment == 0 and size % width == 0:
        return memory.read(address, size)
    if not memory.traits.covering_read_safe:
        raise MemoryAccessError(
            "discovery needs an aligned covering read for this sub-width field; "
            "normalize it in the transport adapter or declare covering_read_safe"
        )
    start = address - address % alignment
    prefix = address - start
    covered = prefix + size
    total = covered + (-covered % width)
    raw = memory.read(start, total)
    return raw[prefix : prefix + size]


@dataclass(frozen=True, slots=True)
class MemorySpan:
    """One bounded half-open runtime memory interval."""

    address: int
    size: int
    label: str = ""

    def __post_init__(self) -> None:
        _integer(self.address, "span address")
        _integer(self.size, "span size", positive=True)
        if not isinstance(self.label, str):
            raise TypeError("span label must be a str")

    @property
    def end(self) -> int:
        return self.address + self.size

    def contains(self, address: int, size: int = 1) -> bool:
        return self.address <= address and address + size <= self.end


def _same_span_bounds(left: MemorySpan, right: MemorySpan) -> bool:
    return left.address == right.address and left.size == right.size


@dataclass(frozen=True, slots=True)
class PointerLeak:
    value: int
    address: int | None = None
    symbol: str | None = None
    addend: int = 0

    def __post_init__(self) -> None:
        _integer(self.value, "leaked pointer")
        if self.address is not None:
            _integer(self.address, "leak address")
        if self.symbol is not None and (not isinstance(self.symbol, str) or not self.symbol):
            raise ValueError("leak symbol must be a non-empty str or None")
        if isinstance(self.addend, bool) or not isinstance(self.addend, int):
            raise TypeError("leak addend must be an int")


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    address: int
    value: int
    classification: str
    evidence: tuple[str, ...] = ()
    image_offset: int | None = None

    def __post_init__(self) -> None:
        _integer(self.address, "candidate address")
        _integer(self.value, "candidate value")
        if not self.classification:
            raise ValueError("candidate classification cannot be empty")
        object.__setattr__(self, "evidence", tuple(self.evidence))


def _merge_layout(layout: RuntimeLayout | None, image: Image | str, base: int) -> RuntimeLayout:
    current = layout or RuntimeLayout()
    if image is Image.MAIN:
        return replace(current, main_base=base)
    if image is Image.LIBC:
        return replace(current, libc_base=base)
    if image is Image.LOADER:
        return replace(current, loader_base=base)
    if image is Image.STACK:
        return replace(current, stack_base=base)
    extra = dict(current.extra_bases)
    extra[str(image)] = base
    return replace(current, extra_bases=extra)


@dataclass(frozen=True, slots=True)
class ImageResolution:
    image: Image
    base: int
    adapter: ExactELFAdapter
    leak: PointerLeak
    evidence: tuple[str, ...] = ()

    def merged_layout(self, layout: RuntimeLayout | None = None) -> RuntimeLayout:
        return _merge_layout(layout, self.image, self.base)


@dataclass(frozen=True, slots=True)
class HeapResolution:
    pointer: int
    base: int | None
    span: MemorySpan | None
    source_address: int | None
    evidence: tuple[str, ...] = ()

    def merged_layout(self, layout: RuntimeLayout | None = None) -> RuntimeLayout:
        if self.base is None:
            raise ConstraintError("cannot add an unresolved heap base to RuntimeLayout")
        return _merge_layout(layout, "heap", self.base)


@dataclass(frozen=True, slots=True)
class StackResolution:
    environ_symbol_address: int
    environ_pointer: int
    first_environment_pointer: int | None
    base: int | None
    span: MemorySpan | None
    evidence: tuple[str, ...] = ()

    def merged_layout(self, layout: RuntimeLayout | None = None) -> RuntimeLayout:
        if self.base is None:
            raise ConstraintError("cannot add an unresolved stack base to RuntimeLayout")
        return _merge_layout(layout, Image.STACK, self.base)


class ReturnClassification(str, Enum):
    MAIN_EXECUTABLE_POINTER = "main-executable-pointer"
    CALL_CONTINUATION = "call-continuation"
    SYMBOLIZED_CALL_CONTINUATION = "symbolized-call-continuation"


@dataclass(frozen=True, slots=True)
class MainReturnAddress:
    slot_address: int
    return_address: int
    main_base: int
    main_offset: int
    call_site: int | None
    classification: ReturnClassification
    symbol: str | None = None
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedMemoryWrite:
    address: int
    expected: bytes
    replacement: bytes
    purpose: str

    def __post_init__(self) -> None:
        if not self.replacement:
            raise ValueError("planned replacement cannot be empty")
        if len(self.expected) != len(self.replacement):
            raise ValueError("planned expected and replacement byte counts must match")


@dataclass(frozen=True, slots=True)
class ROPInsertionPlan:
    target: Target
    return_site: MainReturnAddress
    writes: tuple[PlannedMemoryWrite, ...]
    chain: ROPChain

    def __post_init__(self) -> None:
        object.__setattr__(self, "writes", tuple(self.writes))
        if not self.writes:
            raise ValueError("ROP insertion plan needs at least one write")

    def apply(self, memory: ArbitraryMemory, *, verify: bool = True) -> int:
        if memory.target != self.target:
            raise ConstraintError("ROP insertion memory target differs from the planned target")
        if not isinstance(verify, bool):
            raise TypeError("verify must be bool")
        # Check every expectation before making the first mutation.
        for write in self.writes:
            actual = _read_covered(memory, write.address, len(write.expected))
            if actual != write.expected:
                raise StaleDiscoveryError(f"memory at {write.address:#x} changed after ROP insertion was planned")
        total = 0
        for write in self.writes:
            total += memory.write(write.address, write.replacement, verify=verify)
        return total


class RDebugState(IntEnum):
    CONSISTENT = 0
    ADDING = 1
    DELETING = 2


@dataclass(frozen=True, slots=True)
class LoadedObject:
    link_map_address: int
    base: int
    name_address: int
    name_bytes: bytes
    dynamic_address: int
    next_address: int
    previous_address: int
    adapter: ExactELFAdapter | None = None
    evidence: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.name_bytes.decode(errors="surrogateescape")


@dataclass(frozen=True, slots=True)
class LinkMapSnapshot:
    loader_base: int
    r_debug_address: int
    r_version: int
    r_state: RDebugState
    r_brk: int
    r_ldbase: int
    head_address: int
    objects: tuple[LoadedObject, ...]


HeapValidator = Callable[[ArbitraryMemory, int], bool]


def _process_targets_compatible(left: Target, right: Target) -> bool:
    if left == right:
        return True
    return (
        {left.arch, right.arch} == {Architecture.ARM, Architecture.THUMB}
        and left.bits == right.bits
        and left.endian is right.endian
        and left.abi is right.abi
        and left.os == right.os
    )


class ExactProcessDiscovery:
    """Resolve process layout facts from strict arbitrary-memory reads."""

    def __init__(
        self,
        memory: ArbitraryMemory,
        *,
        main: ExactELFAdapter | None = None,
        libc: ExactELFAdapter | None = None,
        loader: ExactELFAdapter | None = None,
        layout: RuntimeLayout | None = None,
        runtime_page_size: int = 0x1000,
    ) -> None:
        if not isinstance(memory, ArbitraryMemory):
            raise TypeError("memory must be ArbitraryMemory")
        for name, adapter in (("main", main), ("libc", libc), ("loader", loader)):
            if adapter is not None and not isinstance(adapter, ExactELFAdapter):
                raise TypeError(f"{name} must be ExactELFAdapter or None")
            if adapter is not None and not _process_targets_compatible(adapter.target, memory.target):
                raise ConstraintError(f"{name} target differs from arbitrary-memory target")
        _integer(runtime_page_size, "runtime_page_size", positive=True)
        if runtime_page_size & (runtime_page_size - 1):
            raise ValueError("runtime_page_size must be a power of two")
        self.memory = memory
        self.main = main
        self.libc = libc
        self.loader = loader
        self.layout = layout or RuntimeLayout()
        self.runtime_page_size = runtime_page_size

    @property
    def target(self) -> Target:
        return self.memory.target

    def _check_address(self, address: int, name: str) -> int:
        _integer(address, name)
        if address > self.target.mask:
            raise ValueError(f"{name} does not fit the target address width")
        return address

    def _check_span(self, span: MemorySpan) -> MemorySpan:
        if not isinstance(span, MemorySpan):
            raise TypeError("span must be MemorySpan")
        self._check_address(span.address, "span address")
        if span.end - 1 > self.target.mask:
            raise ValueError("span does not fit the target address width")
        return span

    def _read_bytes(self, address: int, size: int) -> bytes:
        self._check_address(address, "read address")
        _integer(size, "read size")
        if size and address + size - 1 > self.target.mask:
            raise ValueError("read does not fit the target address width")
        return _read_covered(self.memory, address, size)

    def _read_pointer(self, address: int) -> int:
        return self.target.unpack(self._read_bytes(address, self.target.word_size))

    def scan_pointers(
        self,
        span: MemorySpan,
        *,
        alignment: int | None = None,
    ) -> tuple[DiscoveryCandidate, ...]:
        span = self._check_span(span)
        step = self.target.word_size if alignment is None else _integer(alignment, "alignment", positive=True)
        if span.address % self.memory.traits.read_alignment:
            raise MemoryAccessError("pointer-scan start does not satisfy primitive read alignment")
        if span.size % self.memory.traits.read_width:
            raise MemoryAccessError("pointer-scan size does not satisfy primitive read width")
        raw = self.memory.read(span.address, span.size)
        candidates: list[DiscoveryCandidate] = []
        for offset in range(0, span.size - self.target.word_size + 1, step):
            address = span.address + offset
            if address % self.target.word_size:
                continue
            value = self.target.unpack(raw[offset : offset + self.target.word_size])
            candidates.append(DiscoveryCandidate(address, value, "pointer-word"))
        return tuple(candidates)

    def _runtime_ranges(self, adapter: ExactELFAdapter, base: int):
        """Return ranges rebased by ELF load bias, not ELF header address."""

        return tuple((base + item.start, base + item.end, item) for item in adapter.profile.load_ranges)

    def _pointer_in_image(self, pointer: int, adapter: ExactELFAdapter, base: int) -> bool:
        # Image discovery accepts arbitrary data pointers.  Thumb state-bit
        # normalization belongs only to explicitly classified code pointers,
        # as in ``environ_to_main_returns`` below.
        return any(start <= pointer < end for start, end, _item in self._runtime_ranges(adapter, base))

    def _require_image_span(
        self,
        adapter: ExactELFAdapter,
        base: int,
        address: int,
        size: int,
        *,
        label: str,
        writable: bool = False,
        executable: bool = False,
    ) -> None:
        """Require one complete interval to occupy a suitable exact PT_LOAD."""

        self._check_address(address, label)
        _integer(size, f"{label} size", positive=True)
        if address + size - 1 > self.target.mask:
            raise DiscoveryError(f"{label} does not fit the target address width")
        if not any(
            start <= address
            and address + size <= end
            and load.readable
            and (load.writable or not writable)
            and (load.executable or not executable)
            for start, end, load in self._runtime_ranges(adapter, base)
        ):
            permissions = "readable"
            if writable:
                permissions += "/writable"
            if executable:
                permissions += "/executable"
            raise DiscoveryError(f"{label} is outside one exact {permissions} PT_LOAD")

    def _validate_runtime_image(self, adapter: ExactELFAdapter, base: int) -> None:
        self._check_address(base, "image base")
        if base % self.runtime_page_size:
            raise DiscoveryError(f"image base {base:#x} is not page aligned")
        header_size = 64 if adapter.target.bits == 64 else 52
        header_range = next(
            (item for item in adapter.profile.load_ranges if item.file_offset == 0 and item.file_size >= header_size),
            None,
        )
        if header_range is None:
            raise DiscoveryError("exact ELF has no file-offset-zero PT_LOAD suitable for runtime validation")
        runtime_address = base + header_range.start
        artifact = adapter.verified_artifact_bytes()
        expected = artifact[:header_size]
        if len(expected) != header_size or not expected.startswith(b"\x7fELF"):
            raise PwntoolsCompatibilityError("exact adapter path no longer contains an ELF header")
        actual = self._read_bytes(runtime_address, header_size)
        if actual != expected:
            raise DiscoveryError(f"runtime ELF identity mismatch at {runtime_address:#x}")
        expected_class = 2 if adapter.target.bits == 64 else 1
        expected_data = 1 if adapter.target.endian.value == "little" else 2
        if actual[4] != expected_class or actual[5] != expected_data or actual[6] != 1:
            raise DiscoveryError("runtime ELF class, byte order, or identification version is invalid")
        byteorder = adapter.target.endian.value

        def field(offset: int, size: int) -> int:
            return int.from_bytes(actual[offset : offset + size], byteorder)

        elf_type = field(16, 2)
        machine = field(18, 2)
        version = field(20, 4)
        if elf_type not in {2, 3} or machine == 0 or version != 1:
            raise DiscoveryError("runtime ELF type, machine, or header version is invalid")
        if adapter.target.bits == 64:
            phoff = field(32, 8)
            ehsize = field(52, 2)
            phentsize = field(54, 2)
            phnum = field(56, 2)
            canonical_phentsize = 56
        else:
            phoff = field(28, 4)
            ehsize = field(40, 2)
            phentsize = field(42, 2)
            phnum = field(44, 2)
            canonical_phentsize = 32
        if ehsize != header_size or phentsize != canonical_phentsize or not 0 < phnum < 0xFFFF:
            raise DiscoveryError("runtime ELF header/program-header dimensions are invalid")
        table_size = phentsize * phnum
        if phoff > len(artifact) or table_size > len(artifact) - phoff:
            raise PwntoolsCompatibilityError("exact ELF program-header table is outside the artifact")
        expected_table = artifact[phoff : phoff + table_size]
        actual_table = self._read_bytes(runtime_address + phoff, table_size)
        if actual_table != expected_table:
            raise DiscoveryError("runtime ELF program-header table differs from the exact artifact")

        observed_loads: list[tuple[int, int, int, int, int, int]] = []
        for index in range(phnum):
            entry = actual_table[index * phentsize : (index + 1) * phentsize]
            if int.from_bytes(entry[:4], byteorder) != 1:  # PT_LOAD
                continue
            if adapter.target.bits == 64:
                flags = int.from_bytes(entry[4:8], byteorder)
                offset = int.from_bytes(entry[8:16], byteorder)
                vaddr = int.from_bytes(entry[16:24], byteorder)
                filesz = int.from_bytes(entry[32:40], byteorder)
                memsz = int.from_bytes(entry[40:48], byteorder)
                alignment = int.from_bytes(entry[48:56], byteorder)
            else:
                offset = int.from_bytes(entry[4:8], byteorder)
                vaddr = int.from_bytes(entry[8:12], byteorder)
                filesz = int.from_bytes(entry[16:20], byteorder)
                memsz = int.from_bytes(entry[20:24], byteorder)
                flags = int.from_bytes(entry[24:28], byteorder)
                alignment = int.from_bytes(entry[28:32], byteorder)
            observed_loads.append((offset, vaddr, filesz, memsz, flags, alignment))
        expected_loads = [
            (
                item.file_offset,
                item.start,
                item.file_size,
                item.size,
                (4 if item.readable else 0) | (2 if item.writable else 0) | (1 if item.executable else 0),
                item.alignment,
            )
            for item in adapter.profile.load_ranges
        ]
        if observed_loads != expected_loads:
            raise DiscoveryError("runtime ELF PT_LOAD records differ from the exact ELF profile")

        # A mapped GNU build-ID descriptor gives a runtime identity check in
        # addition to the structural ELF/program-header comparison above.
        # Some valid ELFs expose a section-only build ID; those deliberately
        # remain structural matches because section bytes need not be mapped.
        expected_build_id = bytes.fromhex(adapter.profile.build_id) if adapter.profile.build_id else None
        for note in adapter.profile.build_id_ranges:
            expected_note = artifact[note.file_offset : note.file_offset + note.file_size]
            if expected_build_id is None or expected_note != expected_build_id:
                raise PwntoolsCompatibilityError("exact ELF profile has inconsistent GNU build-ID metadata")
            actual_note = self._read_bytes(base + note.start, note.file_size)
            if actual_note != expected_note:
                raise DiscoveryError("runtime GNU build ID differs from the exact artifact")

    def _exact_runtime_bytes(
        self,
        adapter: ExactELFAdapter,
        base: int,
        address: int,
        size: int,
    ) -> bytes | None:
        """Read exact file bytes corresponding to one runtime-mapped range."""

        for start, _end, load in self._runtime_ranges(adapter, base):
            offset = address - start
            if offset < 0 or offset + size > load.file_size:
                continue
            artifact_offset = load.file_offset + offset
            artifact = adapter.verified_artifact_bytes()
            data = artifact[artifact_offset : artifact_offset + size]
            return data if len(data) == size else None
        return None

    def _base_from_leak(
        self,
        leak: PointerLeak,
        adapter: ExactELFAdapter,
        explicit_base: int | None,
        *,
        image_name: str,
        search_pages: int,
    ) -> int:
        if explicit_base is not None:
            base = self._check_address(explicit_base, f"{image_name}_base")
            if leak.symbol is not None:
                expected = base + adapter.symbol(leak.symbol) + leak.addend
                if leak.value != expected:
                    raise DiscoveryError(
                        f"{image_name} symbol leak {leak.value:#x} disagrees with "
                        f"{leak.symbol}+{leak.addend:#x} at hardcoded base {base:#x}"
                    )
            # Reject the overwhelmingly common non-image pointer before doing
            # any transport reads.  This keeps large heap/libc scans usable on
            # menu-driven primitives while the one surviving base is still
            # checked against runtime ELF geometry and any mapped build ID.
            if not self._pointer_in_image(leak.value, adapter, base):
                raise DiscoveryError(f"leak {leak.value:#x} is outside exact {image_name} runtime ranges")
        elif leak.symbol is not None:
            base = leak.value - adapter.symbol(leak.symbol) - leak.addend
            if base < 0:
                raise DiscoveryError(f"{image_name} symbol leak produces a negative base")
        else:
            if not self.memory.traits.invalid_read_safe:
                raise ConstraintError(
                    f"inferring {image_name} base requires invalid_read_safe or an explicit "
                    f"{image_name}_base/symbol leak"
                )
            page = leak.value & -self.runtime_page_size
            matches: list[int] = []
            header = next(
                (item for item in adapter.profile.load_ranges if item.file_offset == 0 and item.file_size >= 4),
                None,
            )
            if header is None:
                raise DiscoveryError(f"exact {image_name} has no runtime ELF header mapping")
            for index in range(_integer(search_pages, "image_search_pages", positive=True)):
                candidate = page - index * self.runtime_page_size
                if candidate < 0:
                    break
                try:
                    if self._read_bytes(candidate + header.start, 4) != b"\x7fELF":
                        continue
                    self._validate_runtime_image(adapter, candidate)
                except (DiscoveryError, MemoryAccessError):
                    continue
                if self._pointer_in_image(leak.value, adapter, candidate):
                    matches.append(candidate)
            if not matches:
                raise DiscoveryNotFoundError(f"no exact {image_name} image contains leak {leak.value:#x}")
            if len(matches) != 1:
                values = tuple(
                    DiscoveryCandidate(leak.address or leak.value, value, f"{image_name}-base") for value in matches
                )
                raise DiscoveryAmbiguityError(f"{image_name} base", values)
            base = matches[0]
        self._validate_runtime_image(adapter, base)
        if not self._pointer_in_image(leak.value, adapter, base):
            raise DiscoveryError(f"leak {leak.value:#x} is outside exact {image_name} runtime ranges")
        return base

    @staticmethod
    def _one(description: str, candidates: Sequence[DiscoveryCandidate]) -> DiscoveryCandidate:
        if not candidates:
            raise DiscoveryNotFoundError(f"no {description} candidate was found")
        if len(candidates) != 1:
            raise DiscoveryAmbiguityError(description, candidates)
        return candidates[0]

    @staticmethod
    def _as_leak(value: PointerLeak | int, *, address: int | None = None) -> PointerLeak:
        if isinstance(value, PointerLeak):
            return value
        return PointerLeak(_integer(value, "leaked pointer"), address)

    def heap_to_libc(
        self,
        heap_leak: HeapResolution | PointerLeak | int,
        *,
        heap_base: int | None = None,
        heap_span: MemorySpan | None = None,
        libc_base: int | None = None,
        libc_pointer: int | None = None,
        libc_pointer_address: int | None = None,
        scan_size: int = 0x10000,
        image_search_pages: int = 0x400,
    ) -> ImageResolution:
        if self.libc is None:
            raise ConstraintError("heap_to_libc requires an exact libc adapter")
        if isinstance(heap_leak, HeapResolution):
            origin = heap_leak.pointer
            if heap_base is not None and heap_leak.base is not None and heap_base != heap_leak.base:
                raise ConstraintError("heap_base override conflicts with HeapResolution.base")
            if (
                heap_span is not None
                and heap_leak.span is not None
                and not _same_span_bounds(heap_span, heap_leak.span)
            ):
                raise ConstraintError("heap_span override conflicts with HeapResolution.span")
            heap_base = heap_leak.base if heap_base is None else heap_base
            heap_span = heap_leak.span if heap_span is None else heap_span
        elif isinstance(heap_leak, PointerLeak):
            origin = heap_leak.value
        else:
            origin = _integer(heap_leak, "heap leak")
        if heap_base is not None:
            self._check_address(heap_base, "heap_base")
        if heap_span is not None:
            self._check_span(heap_span)
            if heap_base is not None and heap_span.address != heap_base:
                raise ConstraintError("heap_base and heap_span.address disagree")

        if libc_pointer_address is not None:
            address = self._check_address(libc_pointer_address, "libc_pointer_address")
            observed = self._read_pointer(address)
            if libc_pointer is not None and observed != libc_pointer:
                raise DiscoveryError("hardcoded libc pointer does not match its supplied memory slot")
            leak = PointerLeak(observed, address)
            base = self._base_from_leak(leak, self.libc, libc_base, image_name="libc", search_pages=image_search_pages)
            return ImageResolution(Image.LIBC, base, self.libc, leak, ("explicit pointer slot",))
        if libc_pointer is not None:
            leak = PointerLeak(self._check_address(libc_pointer, "libc_pointer"))
            base = self._base_from_leak(leak, self.libc, libc_base, image_name="libc", search_pages=image_search_pages)
            return ImageResolution(Image.LIBC, base, self.libc, leak, ("explicit pointer",))

        if heap_span is None:
            if not self.memory.traits.invalid_read_safe:
                raise ConstraintError("scanning from a heap leak requires an explicit heap_span or invalid_read_safe")
            start = heap_base if heap_base is not None else origin & -self.runtime_page_size
            heap_span = MemorySpan(start, _integer(scan_size, "scan_size", positive=True), "speculative heap scan")

        candidates: list[tuple[DiscoveryCandidate, int]] = []
        for item in self.scan_pointers(heap_span):
            try:
                base = self._base_from_leak(
                    PointerLeak(item.value, item.address),
                    self.libc,
                    libc_base,
                    image_name="libc",
                    search_pages=image_search_pages,
                )
            except DiscoveryError:
                continue
            candidates.append(
                (
                    DiscoveryCandidate(
                        item.address,
                        item.value,
                        "libc-pointer",
                        ("points into exact libc PT_LOAD",),
                        item.value - base,
                    ),
                    base,
                )
            )
        by_base: dict[int, list[DiscoveryCandidate]] = {}
        for item, base in candidates:
            by_base.setdefault(base, []).append(item)
        representatives = [items[0] for items in by_base.values()]
        chosen = self._one("heap-to-libc resolution", representatives)
        base = next(base for base, items in by_base.items() if chosen in items)
        corroboration = tuple(item.address for item in by_base[base])
        return ImageResolution(
            Image.LIBC,
            base,
            self.libc,
            PointerLeak(chosen.value, chosen.address),
            chosen.evidence + (f"corroborating pointer slots: {', '.join(hex(item) for item in corroboration)}",),
        )

    def _resolve_image_input(
        self,
        value: ImageResolution | PointerLeak | int,
        adapter: ExactELFAdapter,
        explicit_base: int | None,
        *,
        image_name: str,
    ) -> tuple[PointerLeak, int]:
        if isinstance(value, ImageResolution):
            if value.adapter.identity != adapter.identity:
                raise ConstraintError(f"{image_name} resolution belongs to a different exact artifact")
            base = value.base if explicit_base is None else explicit_base
            leak = value.leak
        else:
            leak = self._as_leak(value)
            base = explicit_base
        resolved = self._base_from_leak(leak, adapter, base, image_name=image_name, search_pages=0x400)
        return leak, resolved

    def _image_scan_spans(
        self,
        adapter: ExactELFAdapter,
        base: int,
        explicit: MemorySpan | None,
        *,
        writable_only: bool,
    ) -> tuple[MemorySpan, ...]:
        if explicit is not None:
            span = self._check_span(explicit)
            self._require_image_span(
                adapter,
                base,
                span.address,
                span.size,
                label="explicit image scan span",
                writable=writable_only,
            )
            return (span,)
        return tuple(
            MemorySpan(base + item.start, item.size, "exact image scan")
            for item in adapter.profile.load_ranges
            if item.readable and (item.writable or not writable_only) and item.size >= self.target.word_size
        )

    def libc_to_heap(
        self,
        libc_leak: ImageResolution | PointerLeak | int,
        *,
        libc_base: int | None = None,
        libc_span: MemorySpan | None = None,
        heap_base: int | None = None,
        heap_span: MemorySpan | None = None,
        heap_pointer: int | None = None,
        heap_pointer_address: int | None = None,
        validator: HeapValidator | None = None,
    ) -> HeapResolution:
        if self.libc is None:
            raise ConstraintError("libc_to_heap requires an exact libc adapter")
        _leak, base = self._resolve_image_input(libc_leak, self.libc, libc_base, image_name="libc")
        if heap_base is not None:
            self._check_address(heap_base, "heap_base")
        if heap_span is not None:
            self._check_span(heap_span)
            if heap_base is not None and heap_span.address != heap_base:
                raise ConstraintError("heap_base and heap_span.address disagree")

        explicit_pointer = heap_pointer is not None or heap_pointer_address is not None
        if heap_span is None and validator is None and not explicit_pointer:
            raise ConstraintError("automatic heap classification requires an explicit heap_span or allocator validator")

        def valid(pointer: int) -> bool:
            in_span = heap_span is not None and heap_span.contains(pointer)
            checked = validator is not None and bool(validator(self.memory, pointer))
            explicit = explicit_pointer and heap_span is None and validator is None
            above_base = heap_base is None or pointer >= heap_base
            return (in_span or checked or explicit) and above_base

        if heap_pointer_address is not None:
            slot = self._check_address(heap_pointer_address, "heap_pointer_address")
            observed = self._read_pointer(slot)
            if heap_pointer is not None and observed != heap_pointer:
                raise DiscoveryError("hardcoded heap pointer does not match its supplied memory slot")
            if not valid(observed):
                raise DiscoveryError("hardcoded heap pointer fails heap classification")
            return HeapResolution(observed, heap_base, heap_span, slot, ("explicit pointer slot",))
        if heap_pointer is not None:
            pointer = self._check_address(heap_pointer, "heap_pointer")
            if not valid(pointer):
                raise DiscoveryError("hardcoded heap pointer fails heap classification")
            return HeapResolution(pointer, heap_base, heap_span, None, ("explicit pointer",))

        candidates: list[DiscoveryCandidate] = []
        for span in self._image_scan_spans(self.libc, base, libc_span, writable_only=True):
            for item in self.scan_pointers(span):
                if valid(item.value):
                    candidates.append(
                        DiscoveryCandidate(item.address, item.value, "heap-pointer", ("heap classifier accepted",))
                    )
        groups: dict[tuple[object, ...], list[DiscoveryCandidate]] = {}
        for item in candidates:
            key = (
                ("span", heap_span.address, heap_span.size)
                if heap_span is not None and heap_span.contains(item.value)
                else ("validated-pointer", item.value)
            )
            groups.setdefault(key, []).append(item)
        representative = self._one("libc-to-heap resolution", [items[0] for items in groups.values()])
        group = next(items for items in groups.values() if representative in items)
        corroboration = tuple(item.address for item in group)
        return HeapResolution(
            representative.value,
            heap_base,
            heap_span,
            representative.address,
            representative.evidence
            + (f"corroborating pointer slots: {', '.join(hex(item) for item in corroboration)}",),
        )

    def libc_to_stack(
        self,
        libc_leak: ImageResolution | PointerLeak | int,
        *,
        libc_base: int | None = None,
        environ_symbol: str = "environ",
        environ_address: int | None = None,
        stack_base: int | None = None,
        stack_span: MemorySpan | None = None,
    ) -> StackResolution:
        if self.libc is None:
            raise ConstraintError("libc_to_stack requires an exact libc adapter")
        _leak, base = self._resolve_image_input(libc_leak, self.libc, libc_base, image_name="libc")
        if not isinstance(environ_symbol, str) or not environ_symbol:
            raise ValueError("environ_symbol must be a non-empty str")
        symbol_address = (
            self._check_address(environ_address, "environ_address")
            if environ_address is not None
            else base + self.libc.symbol(environ_symbol)
        )
        self._require_image_span(
            self.libc,
            base,
            symbol_address,
            self.target.word_size,
            label=f"{environ_symbol} address",
            writable=True,
        )
        environ_pointer = self._read_pointer(symbol_address)
        if not environ_pointer:
            raise DiscoveryNotFoundError(f"resolved {environ_symbol} is NULL")
        if stack_base is not None:
            self._check_address(stack_base, "stack_base")
        if stack_span is not None:
            self._check_span(stack_span)
            if stack_base is not None and stack_span.address != stack_base:
                raise ConstraintError("stack_base and stack_span.address disagree")
            if not stack_span.contains(environ_pointer, self.target.word_size):
                raise DiscoveryError("environ does not point into the supplied stack span")
        elif stack_base is not None and environ_pointer < stack_base:
            raise DiscoveryError("environ points below the supplied stack base")
        # `environ` itself is the stack leak.  Its first string is only useful
        # corroboration and may legally point into heap storage after setenv()
        # or putenv().  Do not turn that optional read into a remote primitive
        # requirement when no safe stack interval was supplied.
        first: int | None = None
        if stack_span is not None:
            first = self._read_pointer(environ_pointer) or None
        elif self.memory.traits.invalid_read_safe:
            try:
                first = self._read_pointer(environ_pointer) or None
            except MemoryAccessError:
                first = None
        return StackResolution(
            symbol_address,
            environ_pointer,
            first,
            stack_base,
            stack_span,
            (f"resolved exact {environ_symbol}",),
        )

    @staticmethod
    def _normalize_code_pointer(target: Target, value: int) -> int:
        return value & ~1 if target.arch is Architecture.THUMB else value

    def _call_site(self, return_address: int, adapter: ExactELFAdapter, base: int) -> int | None:
        target = self.target

        def exact_instruction(address: int, size: int) -> bytes | None:
            try:
                self._require_image_span(
                    adapter,
                    base,
                    address,
                    size,
                    label="candidate call instruction",
                    executable=True,
                )
            except DiscoveryError:
                return None
            exact = self._exact_runtime_bytes(adapter, base, address, size)
            if exact is None:
                return None
            return exact if self._read_bytes(address, size) == exact else None

        if target.arch in {Architecture.X86, Architecture.X86_64}:
            if return_address >= 5:
                call_site = return_address - 5
                exact = self._exact_runtime_bytes(adapter, base, call_site, 5)
                if exact is not None and exact[:1] == b"\xe8" and exact_instruction(call_site, 5) is not None:
                    return call_site
            return None
        if target.arch is Architecture.ARM64 and return_address >= 4:
            call_site = return_address - 4
            exact = self._exact_runtime_bytes(adapter, base, call_site, 4)
            if exact is None:
                return None
            # A64 instructions are always encoded little-endian, including
            # big-endian data-mode ELF processes.
            instruction = int.from_bytes(exact, "little")
            if instruction & 0xFC000000 != 0x94000000:
                return None
            if exact_instruction(call_site, 4) is None:
                return None
            return call_site
        if target.arch is Architecture.ARM and return_address >= 4:
            call_site = return_address - 4
            exact = self._exact_runtime_bytes(adapter, base, call_site, 4)
            if exact is None:
                return None
            instruction = int.from_bytes(exact, target.endian.value)
            if instruction & 0x0F000000 != 0x0B000000:
                return None
            return call_site if exact_instruction(call_site, 4) is not None else None
        if target.arch is Architecture.THUMB and return_address >= 4:
            call_site = return_address - 4
            exact = self._exact_runtime_bytes(adapter, base, call_site, 4)
            if exact is None:
                return None
            first = int.from_bytes(exact[:2], target.endian.value)
            second = int.from_bytes(exact[2:], target.endian.value)
            # Thumb-2 BL and BLX-immediate share a 11110 first halfword and a
            # linked 11xx second halfword.  B.W uses a different second prefix.
            if first & 0xF800 != 0xF000 or second & 0xC000 != 0xC000:
                return None
            return call_site if exact_instruction(call_site, 4) is not None else None
        if target.arch is Architecture.MIPS32 or target.arch is Architecture.MIPS64:
            if return_address >= 8:
                call_site = return_address - 8
                exact = self._exact_runtime_bytes(adapter, base, call_site, 4)
                if exact is None:
                    return None
                instruction = int.from_bytes(exact, target.endian.value)
                if instruction >> 26 == 3 and exact_instruction(call_site, 4) is not None:
                    return call_site
            return None
        if target.arch in {Architecture.RISCV32, Architecture.RISCV64} and return_address >= 4:
            call_site = return_address - 4
            exact = self._exact_runtime_bytes(adapter, base, call_site, 4)
            if exact is None:
                return None
            instruction = int.from_bytes(exact, target.endian.value)
            opcode = instruction & 0x7F
            destination = instruction >> 7 & 0x1F
            linked = destination == 1 and (opcode == 0x6F or (opcode == 0x67 and instruction >> 12 & 0x7 == 0))
            if not linked:
                return None
            return call_site if exact_instruction(call_site, 4) is not None else None
        if target.arch in {Architecture.POWERPC32, Architecture.POWERPC64} and return_address >= 4:
            call_site = return_address - 4
            exact = self._exact_runtime_bytes(adapter, base, call_site, 4)
            if exact is None:
                return None
            instruction = int.from_bytes(exact, target.endian.value)
            if instruction >> 26 == 18 and instruction & 1 and exact_instruction(call_site, 4) is not None:
                return call_site
            return None
        if target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
            # SPARC `call` stores its own PC in %o7/%i7; `ret` reaches the
            # architectural continuation by adding 8 for the delay slot.
            call_site = return_address
            exact = self._exact_runtime_bytes(adapter, base, call_site, 4)
            if exact is None:
                return None
            instruction = int.from_bytes(exact, target.endian.value)
            if instruction >> 30 == 1 and exact_instruction(call_site, 4) is not None:
                return call_site
            return None
        return None

    def _nearest_symbol(self, adapter: ExactELFAdapter, offset: int) -> str | None:
        eligible = [(value, name) for name, value in adapter.symbols.items() if value <= offset]
        return max(eligible, default=(0, None))[1]

    def _main_bases_from_pointer(self, pointer: int) -> tuple[int, ...]:
        """Infer PIE load bias from exact executable-segment geometry.

        A return address must occupy one page of an executable ``PT_LOAD``.
        Enumerating those usually few relative pages is both bounded and much
        cheaper than walking hundreds of pages backward for every stack word.
        Full ELF/program-header validation still decides each candidate.
        """

        assert self.main is not None
        normalized = self._normalize_code_pointer(self.target, pointer)
        pointer_page = normalized & -self.runtime_page_size
        candidates: list[int] = []
        for load in self.main.profile.load_ranges:
            if not load.executable or not load.size:
                continue
            first_page = load.start & -self.runtime_page_size
            final_page = (load.end - 1) & -self.runtime_page_size
            for relative_page in range(first_page, final_page + self.runtime_page_size, self.runtime_page_size):
                base = pointer_page - relative_page
                if base < 0 or base % self.runtime_page_size or base in candidates:
                    continue
                if not self._pointer_in_image(normalized, self.main, base):
                    continue
                try:
                    self._validate_runtime_image(self.main, base)
                except (DiscoveryError, MemoryAccessError):
                    continue
                candidates.append(base)
        return tuple(candidates)

    def environ_to_main_returns(
        self,
        stack: StackResolution | PointerLeak | int,
        *,
        stack_base: int | None = None,
        stack_span: MemorySpan | None = None,
        main_base: int | None = None,
        return_slot: int | None = None,
        scan_before: int = 0x10000,
        scan_after: int = 0,
        require_call_continuation: bool = True,
    ) -> tuple[MainReturnAddress, ...]:
        """Classify every saved main-image return address in a stack span.

        PIE load bias is inferred from exact executable-segment geometry when
        ``main_base`` is omitted.  Pass ``main_base`` to avoid speculative
        image reads when the primitive cannot safely reject invalid pages.
        """

        if self.main is None:
            raise ConstraintError("environ_to_main_returns requires an exact main ELF adapter")
        if isinstance(stack, StackResolution):
            environ_pointer = stack.environ_pointer
            if stack_base is not None and stack.base is not None and stack_base != stack.base:
                raise ConstraintError("stack_base override conflicts with StackResolution.base")
            if stack_span is not None and stack.span is not None and not _same_span_bounds(stack_span, stack.span):
                raise ConstraintError("stack_span override conflicts with StackResolution.span")
            stack_base = stack.base if stack_base is None else stack_base
            stack_span = stack.span if stack_span is None else stack_span
        elif isinstance(stack, PointerLeak):
            environ_pointer = stack.value
        else:
            environ_pointer = _integer(stack, "environ pointer")
        if stack_base is not None:
            self._check_address(stack_base, "stack_base")
        resolved_main_base = main_base if main_base is not None else self.layout.main_base
        if resolved_main_base is None:
            if not self.main.profile.pie:
                resolved_main_base = 0
            elif not self.memory.traits.invalid_read_safe:
                raise ConstraintError("inferring PIE main base requires invalid_read_safe or an explicit main_base")
        if resolved_main_base is not None:
            self._validate_runtime_image(self.main, resolved_main_base)

        if stack_span is not None:
            self._check_span(stack_span)
            if stack_base is not None and stack_span.address != stack_base:
                raise ConstraintError("stack_base and stack_span.address disagree")

        slots: tuple[DiscoveryCandidate, ...]
        if return_slot is not None:
            slot = self._check_address(return_slot, "return_slot")
            if stack_span is not None and not stack_span.contains(slot, self.target.word_size):
                raise DiscoveryError("return_slot is outside the supplied stack span")
            if stack_base is not None and slot < stack_base:
                raise DiscoveryError("return_slot is below the supplied stack base")
            slots = (DiscoveryCandidate(slot, self._read_pointer(slot), "stack-pointer"),)
        else:
            if stack_span is None:
                if not self.memory.traits.invalid_read_safe:
                    raise ConstraintError(
                        "scanning from environ requires an explicit stack_span, return_slot, or invalid_read_safe"
                    )
                before = _integer(scan_before, "scan_before")
                after = _integer(scan_after, "scan_after")
                start = environ_pointer - before
                if start < 0:
                    raise ValueError("stack scan starts below zero")
                stack_span = MemorySpan(
                    start,
                    before + after + self.target.word_size,
                    "speculative environ stack scan",
                )
            slots = self.scan_pointers(stack_span)
        candidates: list[MainReturnAddress] = []
        for item in slots:
            normalized = self._normalize_code_pointer(self.target, item.value)
            bases = (
                (resolved_main_base,) if resolved_main_base is not None else self._main_bases_from_pointer(normalized)
            )
            for candidate_base in bases:
                executable = any(
                    start <= normalized < end and load.executable
                    for start, end, load in self._runtime_ranges(self.main, candidate_base)
                )
                if not executable:
                    continue
                call_site = self._call_site(normalized, self.main, candidate_base)
                if require_call_continuation and call_site is None:
                    continue
                offset = normalized - candidate_base
                symbol = self._nearest_symbol(self.main, offset)
                classification = (
                    ReturnClassification.SYMBOLIZED_CALL_CONTINUATION
                    if call_site is not None and symbol is not None
                    else ReturnClassification.CALL_CONTINUATION
                    if call_site is not None
                    else ReturnClassification.MAIN_EXECUTABLE_POINTER
                )
                candidates.append(
                    MainReturnAddress(
                        item.address,
                        item.value,
                        candidate_base,
                        offset,
                        call_site,
                        classification,
                        symbol,
                        ("points into exact main executable PT_LOAD",),
                    )
                )
        unique = {(item.slot_address, item.return_address, item.main_base): item for item in candidates}
        return tuple(sorted(unique.values(), key=lambda item: item.slot_address))

    def environ_to_main_return(
        self,
        stack: StackResolution | PointerLeak | int,
        *,
        stack_base: int | None = None,
        stack_span: MemorySpan | None = None,
        main_base: int | None = None,
        return_slot: int | None = None,
        symbol: str | None = None,
        scan_before: int = 0x10000,
        scan_after: int = 0,
        require_call_continuation: bool = True,
    ) -> MainReturnAddress:
        """Return one strict classification, optionally filtered by symbol."""

        if symbol is not None and (not isinstance(symbol, str) or not symbol):
            raise ValueError("symbol must be a non-empty str or None")
        candidates = self.environ_to_main_returns(
            stack,
            stack_base=stack_base,
            stack_span=stack_span,
            main_base=main_base,
            return_slot=return_slot,
            scan_before=scan_before,
            scan_after=scan_after,
            require_call_continuation=require_call_continuation,
        )
        if symbol is not None:
            candidates = tuple(item for item in candidates if item.symbol == symbol)
        chosen = self._one(
            "main return address",
            tuple(
                DiscoveryCandidate(
                    item.slot_address,
                    item.return_address,
                    item.classification.value,
                    item.evidence,
                    item.main_offset,
                )
                for item in candidates
            ),
        )
        return next(
            item for item in candidates if item.slot_address == chosen.address and item.return_address == chosen.value
        )

    def plan_rop_insertion(
        self,
        return_site: MainReturnAddress,
        chain: ROPChain,
        *,
        layout: RuntimeLayout | None = None,
        stack_base: int | None = None,
        main_base: int | None = None,
        return_slot: int | None = None,
        post_return_sp: int | None = None,
    ) -> ROPInsertionPlan:
        if not isinstance(return_site, MainReturnAddress):
            raise TypeError("return_site must be MainReturnAddress")
        if not isinstance(chain, ROPChain):
            raise TypeError("chain must be ROPChain")
        if chain.target != self.target:
            raise ConstraintError("ROP chain target differs from discovery target")
        if self.target.abi not in {ABI.I386_SYSV, ABI.AMD64_SYSV}:
            raise UnsupportedTargetError(
                f"automatic flat return-slot ROP insertion is not supported for {self.target.name}"
            )
        slot = return_site.slot_address if return_slot is None else self._check_address(return_slot, "return_slot")
        if slot != return_site.slot_address:
            raise ConstraintError("return_slot override does not match the classified return site")
        if main_base is not None and main_base != return_site.main_base:
            raise ConstraintError("main_base override does not match the classified return site")
        expected_sp = slot + self.target.word_size
        if post_return_sp is not None and post_return_sp != expected_sp:
            raise ConstraintError("flat x86 ROP insertion requires post_return_sp immediately after return_slot")
        if stack_base is not None and slot < stack_base:
            raise ConstraintError("return slot is below the hardcoded stack base")
        active_layout = layout or self.layout
        if chain.call_frame is None:
            replacement = chain.materialize(active_layout)
        else:
            replacement = chain.materialize(active_layout, chain_base=slot)
        expected = self._read_bytes(slot, len(replacement))
        if self.target.unpack(expected[: self.target.word_size]) != return_site.return_address:
            raise StaleDiscoveryError("classified return address changed before ROP insertion was planned")
        write = PlannedMemoryWrite(slot, expected, replacement, "replace saved return address with flat ROP chain")
        return ROPInsertionPlan(self.target, return_site, (write,), chain)

    def _pwntools_got_entries(self, adapter: ExactELFAdapter, base: int) -> tuple[tuple[str, int], ...]:
        # ExactELFAdapter/pwntools ``ELF.address`` means the runtime address of
        # the lowest PT_LOAD.  RuntimeLayout and link_map l_addr mean additive
        # ELF load bias.  They differ for an ET_EXEC linked at e.g. 0x400000.
        lowest_load = min(item.start for item in adapter.profile.load_ranges)
        elf = adapter.fresh_elf(runtime_base=base + lowest_load)
        try:
            return tuple(sorted((str(name), int(value)) for name, value in elf.got.items()))
        finally:
            elf.close()

    def _pwntools_got_slots(self, adapter: ExactELFAdapter, base: int) -> tuple[int, ...]:
        """Return unique rebased GOT slots while preserving the older helper boundary."""

        return tuple(sorted({slot for _name, slot in self._pwntools_got_entries(adapter, base)}))

    def libc_to_loader(
        self,
        libc_leak: ImageResolution | PointerLeak | int,
        *,
        libc_base: int | None = None,
        libc_span: MemorySpan | None = None,
        loader_base: int | None = None,
        loader_pointer: int | None = None,
        loader_pointer_address: int | None = None,
        image_search_pages: int = 0x200,
    ) -> ImageResolution:
        """Resolve the exact loader, preferring rebased pwntools GOT slots.

        This path uses the loader's exact ``_r_debug`` symbol later; it never
        assumes a populated main ``DT_DEBUG``.  Consequently MIPS
        ``DT_MIPS_RLD_MAP``/``DT_MIPS_RLD_MAP_REL`` do not need special cases.
        """

        if self.libc is None or self.loader is None:
            raise ConstraintError("libc_to_loader requires exact libc and loader adapters")
        _leak, resolved_libc = self._resolve_image_input(libc_leak, self.libc, libc_base, image_name="libc")
        if loader_pointer_address is not None:
            slot = self._check_address(loader_pointer_address, "loader_pointer_address")
            observed = self._read_pointer(slot)
            if loader_pointer is not None and observed != loader_pointer:
                raise DiscoveryError("hardcoded loader pointer does not match its supplied memory slot")
            leak = PointerLeak(observed, slot)
            base = self._base_from_leak(
                leak, self.loader, loader_base, image_name="loader", search_pages=image_search_pages
            )
            return ImageResolution(Image.LOADER, base, self.loader, leak, ("explicit pointer slot",))
        if loader_pointer is not None:
            leak = PointerLeak(self._check_address(loader_pointer, "loader_pointer"))
            base = self._base_from_leak(
                leak, self.loader, loader_base, image_name="loader", search_pages=image_search_pages
            )
            return ImageResolution(Image.LOADER, base, self.loader, leak, ("explicit pointer",))

        got_entries = self._pwntools_got_entries(self.libc, resolved_libc)
        matches: list[tuple[DiscoveryCandidate, int]] = []

        def collect(candidate_slots: Sequence[tuple[int, str | None, str]]) -> None:
            for slot, symbol, source in dict.fromkeys(candidate_slots):
                pointer = self._read_pointer(slot)
                try:
                    base = self._base_from_leak(
                        PointerLeak(pointer, slot, symbol=symbol),
                        self.loader,
                        loader_base,
                        image_name="loader",
                        search_pages=image_search_pages,
                    )
                except DiscoveryError:
                    continue
                matches.append(
                    (
                        DiscoveryCandidate(
                            slot,
                            pointer,
                            "loader-pointer",
                            (f"{source} points into exact loader PT_LOAD",),
                            pointer - base,
                        ),
                        base,
                    )
                )

        # These libc relocations point at data symbols owned by ld.so.  Keeping
        # the relocation name lets the exact loader turn one pointer into its
        # load bias without probing any unknown page.  `_rtld_global` is
        # present in every pinned glibc sysroot; the remaining names are useful
        # corroboration and compatibility fallbacks.
        preferred_names = ("_rtld_global", "_rtld_global_ro", "__libc_stack_end", "_dl_argv")
        named = {name: slot for name, slot in got_entries if name in self.loader.symbols}
        preferred = [
            (named[name], name, f"resolved libc GOT slot for {name}") for name in preferred_names if name in named
        ]
        collect(preferred)

        # Other same-named GOT entries may be lazy function relocations. A
        # symbolic loader offset would derive a candidate load bias, but
        # validating that bias probes an address which is not yet known to be
        # mapped. Only consider those entries when the caller supplied the
        # loader base or the primitive explicitly tolerates invalid reads.
        extended_named = [
            (slot, name, f"resolved libc GOT slot for {name}")
            for name, slot in got_entries
            if name in self.loader.symbols and name not in preferred_names
        ]
        if not matches and (loader_base is not None or self.memory.traits.invalid_read_safe):
            collect(extended_named)

        # Unnamed pointers require either a caller-supplied base or a primitive
        # which explicitly tolerates invalid exploratory reads.
        if not matches and (loader_base is not None or self.memory.traits.invalid_read_safe):
            collect([(slot, None, "resolved libc GOT slot") for _name, slot in got_entries])
        if not matches and loader_base is None and not self.memory.traits.invalid_read_safe:
            raise ConstraintError(
                "resolving an unnamed loader pointer requires invalid_read_safe, loader_base, "
                "or an exact loader-owned libc relocation"
            )
        if not matches:
            fallback_slots: list[int] = []
            for span in self._image_scan_spans(
                self.libc,
                resolved_libc,
                libc_span,
                writable_only=True,
            ):
                fallback_slots.extend(item.address for item in self.scan_pointers(span))
            if loader_base is not None or self.memory.traits.invalid_read_safe:
                collect([(slot, None, "exact libc writable PT_LOAD") for slot in fallback_slots])
        by_base: dict[int, list[DiscoveryCandidate]] = {}
        for item, base in matches:
            by_base.setdefault(base, []).append(item)
        representatives = [items[0] for items in by_base.values()]
        chosen = self._one("libc-to-loader resolution", representatives)
        base = next(base for base, items in by_base.items() if chosen in items)
        corroboration = tuple(item.address for item in by_base[base])
        leaked_symbol = next(
            (name for name, slot in got_entries if slot == chosen.address and name in self.loader.symbols),
            None,
        )
        return ImageResolution(
            Image.LOADER,
            base,
            self.loader,
            PointerLeak(chosen.value, chosen.address, leaked_symbol),
            chosen.evidence + (f"corroborating pointer slots: {', '.join(hex(item) for item in corroboration)}",),
        )

    def _read_cstring(self, address: int, limit: int) -> bytes:
        _integer(limit, "max_name_size", positive=True)
        result = bytearray()
        quantum = lcm(self.memory.traits.read_alignment, self.memory.traits.read_width)
        while len(result) < limit:
            current = address + len(result)
            boundary = (current // quantum + 1) * quantum
            amount = min(limit - len(result), boundary - current)
            block = self._read_bytes(current, amount)
            terminator = block.find(b"\0")
            if terminator >= 0:
                result.extend(block[:terminator])
                return bytes(result)
            result.extend(block)
        raise InconsistentLinkMapError(f"link_map name at {address:#x} is not NUL-terminated within {limit} bytes")

    def _match_loaded_adapter(
        self,
        name: bytes,
        base: int,
        dynamic_address: int,
        known_images: Sequence[ExactELFAdapter],
    ) -> ExactELFAdapter | None:
        basename = Path(name.decode(errors="surrogateescape")).name if name else ""
        named = [
            item
            for item in known_images
            if basename
            and basename
            in {
                Path(item.path).name,
                item.profile.soname or "",
            }
        ]
        if not named:
            return None

        # The name is target-controlled and only selects candidates. Runtime
        # ELF geometry, a mapped GNU build ID, and link_map.l_ld decide which
        # artifact, if any, is allowed to attach. A structural match without a
        # mapped build ID remains enumerated but deliberately unattached.
        deduplicated = {item.identity.sha256: item for item in named}
        matches: list[ExactELFAdapter] = []
        structural_without_identity = False
        for item in deduplicated.values():
            dynamic = item.profile.dynamic_range
            if dynamic is None or dynamic_address != base + dynamic.start:
                continue
            try:
                self._validate_runtime_image(item, base)
            except (DiscoveryError, MemoryAccessError):
                continue
            if not item.profile.build_id_ranges:
                structural_without_identity = True
                continue
            matches.append(item)
        if not matches:
            if structural_without_identity:
                return None
            raise DiscoveryError(
                f"loaded object {basename!r} does not match any named exact artifact and PT_DYNAMIC address"
            )
        if len(matches) > 1:
            candidates = tuple(
                DiscoveryCandidate(base, base, "loaded-object-artifact", (item.path,)) for item in matches
            )
            raise DiscoveryAmbiguityError(f"loaded object {basename!r}", candidates)
        return matches[0]

    def loader_to_link_map(
        self,
        loader_leak: ImageResolution | PointerLeak | int,
        *,
        loader_base: int | None = None,
        r_debug_address: int | None = None,
        link_map_address: int | None = None,
        known_images: Sequence[ExactELFAdapter] = (),
        max_entries: int = 128,
        max_name_size: int = 4096,
    ) -> LinkMapSnapshot:
        if self.loader is None:
            raise ConstraintError("loader_to_link_map requires an exact loader adapter")
        _leak, base = self._resolve_image_input(loader_leak, self.loader, loader_base, image_name="loader")
        debug = (
            self._check_address(r_debug_address, "r_debug_address")
            if r_debug_address is not None
            else base + self.loader.symbol("_r_debug")
        )
        word = self.target.word_size
        r_map_offset = word
        r_brk_offset = word * 2
        r_state_offset = word * 3
        r_ldbase_offset = word * 4

        self._require_image_span(
            self.loader,
            base,
            debug,
            word * 5,
            label="r_debug address",
            writable=True,
        )

        version_before = int.from_bytes(self._read_bytes(debug, 4), self.target.endian.value)
        if version_before not in {1, 2}:
            raise InconsistentLinkMapError(f"unsupported r_debug version {version_before}")
        head_before = self._read_pointer(debug + r_map_offset)
        r_brk = self._read_pointer(debug + r_brk_offset)
        state_before = int.from_bytes(self._read_bytes(debug + r_state_offset, 4), self.target.endian.value)
        r_ldbase = self._read_pointer(debug + r_ldbase_offset)
        try:
            state = RDebugState(state_before)
        except ValueError as exc:
            raise InconsistentLinkMapError(f"unknown r_debug state {state_before}") from exc
        if state is not RDebugState.CONSISTENT:
            raise InconsistentLinkMapError(f"loader is not consistent: {state.name.lower()}")
        if r_ldbase != base:
            raise InconsistentLinkMapError(
                f"r_debug loader base {r_ldbase:#x} differs from exact loader base {base:#x}"
            )
        head = head_before if link_map_address is None else self._check_address(link_map_address, "link_map_address")
        if link_map_address is not None and head_before and head != head_before:
            raise ConstraintError("link_map_address override disagrees with r_debug.r_map")

        limit = _integer(max_entries, "max_entries", positive=True)
        normalized_known = tuple(known_images)
        for item in normalized_known:
            if not isinstance(item, ExactELFAdapter):
                raise TypeError("known_images must contain ExactELFAdapter values")
            if not _process_targets_compatible(item.target, self.target):
                raise ConstraintError("known image target differs from discovery target")
        objects: list[LoadedObject] = []
        seen: set[int] = set()
        current = head
        previous = 0
        while current:
            if current in seen:
                raise InconsistentLinkMapError(f"link_map cycle detected at {current:#x}")
            if len(objects) >= limit:
                raise InconsistentLinkMapError(f"link_map exceeds max_entries={limit}")
            seen.add(current)
            values = tuple(self._read_pointer(current + index * word) for index in range(5))
            object_base, name_address, dynamic_address, next_address, previous_address = values
            if previous_address != previous:
                raise InconsistentLinkMapError(
                    f"link_map backlink at {current:#x} is {previous_address:#x}, expected {previous:#x}"
                )
            name = b"" if name_address == 0 else self._read_cstring(name_address, max_name_size)
            adapter = self._match_loaded_adapter(name, object_base, dynamic_address, normalized_known)
            objects.append(
                LoadedObject(
                    current,
                    object_base,
                    name_address,
                    name,
                    dynamic_address,
                    next_address,
                    previous_address,
                    adapter,
                    ("validated bidirectional link_map prefix",),
                )
            )
            previous, current = current, next_address

        state_after = int.from_bytes(self._read_bytes(debug + r_state_offset, 4), self.target.endian.value)
        head_after = self._read_pointer(debug + r_map_offset)
        if state_after != state_before or head_after != head_before:
            raise InconsistentLinkMapError("r_debug changed while link_map was being traversed")
        return LinkMapSnapshot(
            base,
            debug,
            version_before,
            state,
            r_brk,
            r_ldbase,
            head,
            tuple(objects),
        )


__all__ = [
    "DiscoveryAmbiguityError",
    "DiscoveryCandidate",
    "DiscoveryError",
    "DiscoveryNotFoundError",
    "ExactProcessDiscovery",
    "HeapResolution",
    "ImageResolution",
    "InconsistentLinkMapError",
    "LinkMapSnapshot",
    "LoadedObject",
    "MainReturnAddress",
    "MemorySpan",
    "PlannedMemoryWrite",
    "PointerLeak",
    "RDebugState",
    "ROPInsertionPlan",
    "ReturnClassification",
    "StackResolution",
    "StaleDiscoveryError",
]
