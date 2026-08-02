"""Read-only inspection of untrusted ELF runtime properties.

The inspector parses bytes with :mod:`pyelftools`.  It never loads the ELF,
executes it, asks pwntools for ``ELF.libs``, or starts a process.  Addresses in
the resulting profile are the virtual values stored in the ELF (and therefore
match :class:`payloads.model.Address` offsets): add the runtime load bias for
PIE/shared objects, and use a zero bias for ordinary ``ET_EXEC`` images.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .errors import PayloadError, UnsupportedTargetError
from .model import ExecutionPolicy, Linkage, Mitigations, Permission, Relro
from .target import ABI, Architecture, Endian, Target, resolve_target


class ELFInspectionError(PayloadError):
    """An ELF is malformed, unsupported, or too ambiguous for a safe claim."""


class ELFImageKind(str, Enum):
    """Runtime role supported by the inspector.

    ``ET_DYN_AMBIGUOUS`` is deliberate.  An ``ET_DYN`` file without
    ``DF_1_PIE``, ``PT_INTERP``, ``DT_SONAME``, or ``DT_NEEDED`` is not safely
    distinguishable from an old static PIE or a minimal shared object.
    """

    EXECUTABLE = "executable"
    PIE_EXECUTABLE = "pie-executable"
    STATIC_PIE = "static-pie"
    SHARED_OBJECT = "shared-object"
    ET_DYN_AMBIGUOUS = "et-dyn-ambiguous"


@dataclass(frozen=True, slots=True)
class ELFRange:
    """One half-open virtual range from a program header."""

    start: int
    end: int
    permissions: Permission
    file_offset: int
    file_size: int
    alignment: int
    kind: str

    def __post_init__(self) -> None:
        for name in ("start", "end", "file_offset", "file_size", "alignment"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.end < self.start:
            raise ValueError("ELF range end cannot precede its start")
        if not isinstance(self.permissions, Permission):
            object.__setattr__(self, "permissions", Permission(self.permissions))

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return bool(self.permissions & Permission.READ)

    @property
    def writable(self) -> bool:
        return bool(self.permissions & Permission.WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.permissions & Permission.EXECUTE)

    def contains(self, address: int, size: int = 1) -> bool:
        if size < 0:
            raise ValueError("size cannot be negative")
        return self.start <= address and address + size <= self.end

    def overlaps(self, start: int, end: int) -> bool:
        return start < self.end and self.start < end


@dataclass(frozen=True, slots=True)
class ELFProfile:
    """Immutable runtime facts extracted from one exact ELF artifact."""

    path: str
    sha256: str
    build_id: str | None
    target: Target
    osabi: str
    elf_type: str
    image_kind: ELFImageKind
    pie: bool
    linkage: Linkage | None
    nx: bool | None
    nx_evidence: str
    relro: Relro
    bind_now: bool
    entry_offset: int
    interpreter: str | None
    needed_libraries: tuple[str, ...]
    soname: str | None
    load_ranges: tuple[ELFRange, ...]
    relro_ranges: tuple[ELFRange, ...]
    load_alignment_hint: int | None
    symbol_offsets: Mapping[str, int] = field(default_factory=dict)
    got_offsets: Mapping[str, int] = field(default_factory=dict)
    plt_offsets: Mapping[str, int] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()
    build_id_ranges: tuple[ELFRange, ...] = ()
    dynamic_range: ELFRange | None = None

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
        if not isinstance(self.image_kind, ELFImageKind):
            object.__setattr__(self, "image_kind", ELFImageKind(self.image_kind))
        if self.linkage is not None and not isinstance(self.linkage, Linkage):
            object.__setattr__(self, "linkage", Linkage(self.linkage))
        if not isinstance(self.relro, Relro):
            object.__setattr__(self, "relro", Relro(self.relro))
        if self.nx is not None and not isinstance(self.nx, bool):
            raise TypeError("nx must be bool or None")
        if not isinstance(self.pie, bool) or not isinstance(self.bind_now, bool):
            raise TypeError("pie and bind_now must be bool")
        if self.load_alignment_hint is not None and (
            not isinstance(self.load_alignment_hint, int)
            or isinstance(self.load_alignment_hint, bool)
            or self.load_alignment_hint <= 0
            or self.load_alignment_hint & (self.load_alignment_hint - 1)
        ):
            raise ValueError("load_alignment_hint must be a positive power of two or None")
        object.__setattr__(self, "needed_libraries", tuple(self.needed_libraries))
        object.__setattr__(self, "load_ranges", tuple(self.load_ranges))
        object.__setattr__(self, "relro_ranges", tuple(self.relro_ranges))
        object.__setattr__(
            self,
            "build_id_ranges",
            tuple(sorted(self.build_id_ranges, key=lambda item: (item.start, item.end, item.file_offset))),
        )
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if (
            not isinstance(self.entry_offset, int)
            or isinstance(self.entry_offset, bool)
            or not 0 <= self.entry_offset <= self.target.mask
        ):
            raise ValueError("entry_offset must fit the target address width")
        for name in ("load_ranges", "relro_ranges", "build_id_ranges"):
            for item in getattr(self, name):
                if not isinstance(item, ELFRange):
                    raise TypeError(f"{name} must contain ELFRange values")
                if item.start > self.target.mask or item.end > self.target.mask + 1:
                    raise ValueError(f"{name} contains a range outside the target address space")
        if self.dynamic_range is not None:
            if not isinstance(self.dynamic_range, ELFRange):
                raise TypeError("dynamic_range must be ELFRange or None")
            if self.dynamic_range.start > self.target.mask or self.dynamic_range.end > self.target.mask + 1:
                raise ValueError("dynamic_range lies outside the target address space")
            if self.dynamic_range.kind != "PT_DYNAMIC" or not self.dynamic_range.size:
                raise ValueError("dynamic_range must describe a nonempty PT_DYNAMIC")
            if not _exact_file_backed_loads(self.dynamic_range, self.load_ranges):
                raise ValueError("dynamic_range is not exactly file-backed by a readable PT_LOAD")
        expected_build_id_size = len(bytes.fromhex(self.build_id)) if self.build_id is not None else None
        for item in self.build_id_ranges:
            if item.kind != "NT_GNU_BUILD_ID" or not item.size or item.file_size != item.size:
                raise ValueError("build_id_ranges must describe nonempty file-backed GNU build-ID bytes")
            if expected_build_id_size is None or item.size != expected_build_id_size:
                raise ValueError("build_id_ranges disagree with build_id")
            if not _exact_file_backed_loads(item, self.load_ranges):
                raise ValueError("build_id_ranges are not exactly file-backed by a readable PT_LOAD")
        for name in ("symbol_offsets", "got_offsets", "plt_offsets"):
            values = dict(getattr(self, name))
            if any(
                not key or not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= self.target.mask
                for key, value in values.items()
            ):
                raise ValueError(f"{name} must map non-empty names to target-width offsets")
            object.__setattr__(self, name, MappingProxyType(values))

    @classmethod
    def from_file(cls, path: str | Path) -> ELFProfile:
        return inspect_elf(path)

    @property
    def is_static_pie(self) -> bool:
        return self.image_kind is ELFImageKind.STATIC_PIE

    @property
    def is_shared_object(self) -> bool:
        return self.image_kind is ELFImageKind.SHARED_OBJECT

    @property
    def is_main_executable(self) -> bool | None:
        if self.image_kind is ELFImageKind.ET_DYN_AMBIGUOUS:
            return None
        return self.image_kind is not ELFImageKind.SHARED_OBJECT

    @property
    def executable_stack(self) -> bool | None:
        return None if self.nx is None else not self.nx

    def to_mitigations(
        self,
        execution_policy: ExecutionPolicy | str,
        *,
        nx_if_unknown: bool | None = None,
        linkage_if_unknown: Linkage | str | None = None,
    ) -> Mitigations:
        """Convert known facts without guessing unknown stack/linkage state."""

        try:
            policy = (
                execution_policy if isinstance(execution_policy, ExecutionPolicy) else ExecutionPolicy(execution_policy)
            )
        except ValueError as exc:
            raise ValueError(f"invalid execution policy {execution_policy!r}") from exc
        nx = self.nx
        if nx is None:
            if nx_if_unknown is None:
                raise ELFInspectionError(
                    "PT_GNU_STACK is absent; pass nx_if_unknown only from runtime/toolchain evidence"
                )
            if not isinstance(nx_if_unknown, bool):
                raise TypeError("nx_if_unknown must be bool or None")
            nx = nx_if_unknown
        linkage = self.linkage
        if linkage is None:
            if linkage_if_unknown is None:
                raise ELFInspectionError(
                    "ET_DYN role/linkage is ambiguous; pass linkage_if_unknown only from external evidence"
                )
            linkage = linkage_if_unknown if isinstance(linkage_if_unknown, Linkage) else Linkage(linkage_if_unknown)
        return Mitigations(
            pie=self.pie,
            nx=nx,
            relro=self.relro,
            linkage=linkage,
            execution_policy=policy,
        )

    def mitigations(
        self,
        execution_policy: ExecutionPolicy | str,
        *,
        nx_if_unknown: bool | None = None,
        linkage_if_unknown: Linkage | str | None = None,
    ) -> Mitigations:
        """Compatibility spelling for :meth:`to_mitigations`."""

        return self.to_mitigations(
            execution_policy,
            nx_if_unknown=nx_if_unknown,
            linkage_if_unknown=linkage_if_unknown,
        )

    def _validate_runtime_page_size(self, runtime_page_size: int | None) -> int | None:
        if runtime_page_size is None:
            return None
        if (
            not isinstance(runtime_page_size, int)
            or isinstance(runtime_page_size, bool)
            or runtime_page_size <= 0
            or runtime_page_size & (runtime_page_size - 1)
        ):
            raise ValueError("runtime_page_size must be a positive power of two or None")
        if runtime_page_size > self.target.mask + 1:
            raise ValueError("runtime_page_size exceeds the target address space")
        return runtime_page_size

    def _relro_protected_ranges(self, runtime_page_size: int) -> tuple[tuple[int, int], ...]:
        page = runtime_page_size
        return tuple((item.start // page * page, (item.end + page - 1) // page * page) for item in self.relro_ranges)

    def is_writable_after_relro(
        self,
        image_offset: int,
        size: int = 1,
        *,
        runtime_page_size: int | None = None,
    ) -> bool:
        """Return true only when the complete range is confidently writable.

        The ELF's ``p_align`` values do not establish the loader's page size.
        Therefore an affirmative answer requires ``runtime_page_size`` from
        the actual process or emulator.  Unknown/unmapped/overlapping segment
        layouts return ``False``; RELRO is rounded to a conservative
        page-aligned superset.
        """

        if not isinstance(image_offset, int) or isinstance(image_offset, bool) or image_offset < 0:
            raise ValueError("image_offset must be a non-negative integer")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError("size must be a positive integer")
        page = self._validate_runtime_page_size(runtime_page_size)
        if page is None:
            return False
        try:
            end = image_offset + size
        except OverflowError:  # pragma: no cover - Python ints do not overflow
            return False
        if end - 1 > self.target.mask:
            return False

        overlapping_loads = [item for item in self.load_ranges if item.overlaps(image_offset, end)]
        if not overlapping_loads:
            return False
        if not any(item.contains(image_offset, size) for item in overlapping_loads):
            return False
        # Overlapping LOAD headers with conflicting permissions are loader-
        # order/page-size dependent.  Do not call the range writable.
        if any(not item.writable for item in overlapping_loads):
            return False
        rounded_start = image_offset // page * page
        rounded_end = (end + page - 1) // page * page
        page_overlapping_loads = [
            item
            for item in self.load_ranges
            if item.start // page * page < rounded_end and rounded_start < (item.end + page - 1) // page * page
        ]
        if any(not item.writable for item in page_overlapping_loads):
            return False
        return not any(
            image_offset < relro_end and relro_start < end
            for relro_start, relro_end in self._relro_protected_ranges(page)
        )

    def got_slot_writable(self, symbol: str, *, runtime_page_size: int | None = None) -> bool:
        """Check one known GOT relocation slot after RELRO is applied."""

        try:
            offset = self.got_offsets[symbol]
        except KeyError as exc:
            raise KeyError(f"no unambiguous GOT slot for symbol {symbol!r}") from exc
        return self.is_writable_after_relro(
            offset,
            self.target.word_size,
            runtime_page_size=runtime_page_size,
        )

    def is_got_writable(self, symbol: str, *, runtime_page_size: int | None = None) -> bool:
        return self.got_slot_writable(symbol, runtime_page_size=runtime_page_size)


_PF_X = 1
_PF_W = 2
_PF_R = 4
_DF_BIND_NOW = 0x8
_DF_1_NOW = 0x1
_DF_1_PIE = 0x08000000
_EF_MIPS_ABI2 = 0x20
_EF_MIPS_ABI_MASK = 0xF000
_EF_MIPS_ABI_O32 = 0x1000
_EF_PPC64_ABI_MASK = 0x3
_EF_PPC64_ABI_V1 = 0x1
_EF_PPC64_ABI_V2 = 0x2
_EF_RISCV_RVE = 0x8


def _permissions(flags: int) -> Permission:
    result = Permission(0)
    if flags & _PF_R:
        result |= Permission.READ
    if flags & _PF_W:
        result |= Permission.WRITE
    if flags & _PF_X:
        result |= Permission.EXECUTE
    return result


def _program_range(segment: Any, kind: str) -> ELFRange:
    header = segment.header
    start = int(header.p_vaddr)
    return ELFRange(
        start=start,
        end=start + int(header.p_memsz),
        permissions=_permissions(int(header.p_flags)),
        file_offset=int(header.p_offset),
        file_size=int(header.p_filesz),
        alignment=int(header.p_align),
        kind=kind,
    )


def _validate_program_segment(segment: Any, target: Target, artifact_size: int, kind: str) -> None:
    header = segment.header
    offset = int(header.p_offset)
    file_size = int(header.p_filesz)
    memory_size = int(header.p_memsz)
    virtual_address = int(header.p_vaddr)
    alignment = int(header.p_align)

    if kind in {"PT_LOAD", "PT_DYNAMIC"} and file_size > memory_size:
        raise ELFInspectionError(f"{kind} file size exceeds its memory size")
    if offset > artifact_size or file_size > artifact_size - offset:
        raise ELFInspectionError(f"{kind} file range extends beyond the artifact")
    if virtual_address > target.mask or memory_size > target.mask + 1 - virtual_address:
        raise ELFInspectionError(f"{kind} virtual range exceeds the {target.bits}-bit address space")
    if alignment not in {0, 1}:
        if alignment & (alignment - 1):
            raise ELFInspectionError(f"{kind} alignment is not a power of two")
        if virtual_address % alignment != offset % alignment:
            raise ELFInspectionError(f"{kind} virtual address and file offset violate p_align congruence")


def _range_is_load_mapped(candidate: ELFRange, load_ranges: tuple[ELFRange, ...]) -> bool:
    if candidate.size == 0:
        return True
    cursor = candidate.start
    for item in load_ranges:
        if item.end <= cursor:
            continue
        if item.start > cursor:
            return False
        cursor = max(cursor, item.end)
        if cursor >= candidate.end:
            return True
    return False


def _exact_file_backed_loads(
    candidate: ELFRange,
    load_ranges: tuple[ELFRange, ...],
) -> tuple[ELFRange, ...]:
    """Return readable loads which map a range from the claimed file bytes."""

    matches: list[ELFRange] = []
    for load in load_ranges:
        relative = candidate.start - load.start
        if relative < 0 or not load.readable or not load.contains(candidate.start, candidate.size):
            continue
        if relative + candidate.file_size > load.file_size:
            continue
        if load.file_offset + relative != candidate.file_offset:
            continue
        matches.append(load)
    return tuple(matches)


def _runtime_mapped_range(
    candidate: ELFRange,
    load_ranges: tuple[ELFRange, ...],
    *,
    required: bool,
) -> ELFRange | None:
    """Attach conservative runtime permissions to one exact file mapping."""

    loads = _exact_file_backed_loads(candidate, load_ranges)
    if not loads:
        if required:
            raise ELFInspectionError(f"{candidate.kind} is not exactly file-backed by a readable PT_LOAD segment")
        return None
    permissions = loads[0].permissions
    for load in loads[1:]:
        permissions &= load.permissions
    return ELFRange(
        candidate.start,
        candidate.end,
        permissions,
        candidate.file_offset,
        candidate.file_size,
        candidate.alignment,
        candidate.kind,
    )


def _runtime_build_id_ranges(
    elf: Any,
    data: bytes,
    target: Target,
    segments: tuple[Any, ...],
    load_ranges: tuple[ELFRange, ...],
) -> tuple[ELFRange, ...]:
    """Locate GNU build-ID descriptor bytes mapped by exact PT_NOTE records."""

    try:
        from elftools.elf.segments import NoteSegment
    except ImportError as exc:  # pragma: no cover
        raise ELFInspectionError("pyelftools is required for ELF inspection") from exc

    header_size = int(elf.structs.Elf_Nhdr.sizeof())
    found: dict[tuple[int, int, int], tuple[ELFRange, bytes]] = {}
    for segment in segments:
        if not isinstance(segment, NoteSegment):
            continue
        _validate_program_segment(segment, target, len(data), "PT_NOTE")
        segment_offset = int(segment.header.p_offset)
        segment_file_end = segment_offset + int(segment.header.p_filesz)
        segment_vaddr = int(segment.header.p_vaddr)
        segment_memory_end = segment_vaddr + int(segment.header.p_memsz)
        for note in segment.iter_notes():
            note_type = note.get("n_type")
            note_name = str(note.get("n_name") or "").rstrip("\0")
            if note_type not in {3, "NT_GNU_BUILD_ID"} or note_name != "GNU":
                continue
            description = note.get("n_descdata")
            if not isinstance(description, (bytes, bytearray, memoryview)) or not description:
                raise ELFInspectionError("GNU build-ID note has an empty or invalid descriptor")
            raw_description = bytes(description)
            note_offset = int(note["n_offset"])
            name_size = int(note["n_namesz"])
            description_size = int(note["n_descsz"])
            if description_size != len(raw_description):
                raise ELFInspectionError("GNU build-ID descriptor size is inconsistent")
            description_offset = note_offset + header_size + ((name_size + 3) & ~3)
            description_end = description_offset + description_size
            description_vaddr = segment_vaddr + description_offset - segment_offset
            if note_offset < segment_offset or description_end > segment_file_end:
                raise ELFInspectionError("GNU build-ID descriptor lies outside its PT_NOTE segment")
            if description_vaddr < segment_vaddr or description_vaddr + description_size > segment_memory_end:
                # PT_NOTE records need not be mapped.  Retain their artifact
                # identity through `_build_id`, but expose runtime coordinates
                # only when the program header describes them in memory.
                continue
            if data[description_offset:description_end] != raw_description:
                raise ELFInspectionError("GNU build-ID descriptor differs from the exact artifact bytes")
            candidate = ELFRange(
                description_vaddr,
                description_vaddr + description_size,
                _permissions(int(segment.header.p_flags)),
                description_offset,
                description_size,
                4,
                "NT_GNU_BUILD_ID",
            )
            mapped = _runtime_mapped_range(candidate, load_ranges, required=False)
            if mapped is None:
                continue
            key = (mapped.start, mapped.file_offset, mapped.file_size)
            previous = found.get(key)
            if previous is not None and previous[1] != raw_description:
                raise ELFInspectionError("conflicting GNU build-ID descriptors share one runtime address")
            found[key] = (mapped, raw_description)
    return tuple(item[0] for _key, item in sorted(found.items()))


def _exact_dynamic_range(
    elf: Any,
    data: bytes,
    target: Target,
    segments: tuple[Any, ...],
    load_ranges: tuple[ELFRange, ...],
) -> ELFRange | None:
    """Return the unique, exactly mapped PT_DYNAMIC range when present."""

    dynamic_segments = tuple(segment for segment in segments if str(segment.header.p_type) == "PT_DYNAMIC")
    if len(dynamic_segments) > 1:
        raise ELFInspectionError("ELF contains multiple PT_DYNAMIC headers")
    if not dynamic_segments:
        return None
    segment = dynamic_segments[0]
    _validate_program_segment(segment, target, len(data), "PT_DYNAMIC")
    candidate = _program_range(segment, "PT_DYNAMIC")
    entry_size = int(elf.structs.Elf_Dyn.sizeof())
    if (
        not candidate.size
        or not candidate.file_size
        or candidate.file_size % entry_size
        or candidate.start % target.word_size
    ):
        raise ELFInspectionError("PT_DYNAMIC has invalid address or entry-table dimensions")
    return _runtime_mapped_range(candidate, load_ranges, required=True)


def _resolve_target(elf: Any) -> Target:
    machine = str(elf.header.e_machine)
    bits = int(elf.elfclass)
    endian = Endian.LITTLE if elf.little_endian else Endian.BIG
    flags = int(elf.header.e_flags)

    aliases: dict[str, tuple[str, int | None]] = {
        "EM_386": ("x86", 32),
        "EM_X86_64": ("x86_64", 64),
        "EM_ARM": ("arm", 32),
        "EM_AARCH64": ("arm64", 64),
        "EM_MIPS": ("mips32" if bits == 32 else "mips64", bits),
        "EM_RISCV": ("riscv32" if bits == 32 else "riscv64", bits),
        "EM_PPC": ("powerpc32", 32),
        "EM_PPC64": ("powerpc64", 64),
        "EM_SPARC": ("sparc32", 32),
        "EM_SPARC32PLUS": ("sparc32", 32),
        "EM_SPARCV9": ("sparc64", 64),
        "EM_S390": ("s390x", 64),
    }
    try:
        alias, required_bits = aliases[machine]
    except KeyError as exc:
        raise ELFInspectionError(f"unsupported ELF machine {machine!r}") from exc
    if required_bits is not None and bits != required_bits:
        raise ELFInspectionError(f"unsupported {machine} ELFCLASS{bits} target")
    if machine == "EM_ARM" and int(elf.header.e_entry) & 1:
        # The ARM ELF ABI uses bit zero of e_entry to select Thumb state.
        # Shared objects normally have a zero entry and remain process-level
        # ARM targets because individual symbols may use either instruction
        # set.
        alias = "thumb"

    abi: ABI | None = None
    if machine == "EM_ARM":
        eabi_version = (flags >> 24) & 0xFF
        if eabi_version == 0:
            raise ELFInspectionError("ARM ELF does not declare EABI; OABI/unknown ARM ABI is unsupported")
        abi = ABI.ARM_EABI
    elif machine == "EM_MIPS":
        abi_bits = flags & _EF_MIPS_ABI_MASK
        if bits == 32:
            if flags & _EF_MIPS_ABI2:
                raise ELFInspectionError("MIPS n32 ABI is not represented by the target catalog")
            if abi_bits not in {0, _EF_MIPS_ABI_O32}:
                raise ELFInspectionError(f"unsupported MIPS32 ABI flags {abi_bits:#x}")
            abi = ABI.MIPS_O32
        else:
            if flags & _EF_MIPS_ABI2 or abi_bits not in {0}:
                raise ELFInspectionError(f"unsupported MIPS64 ABI flags {flags:#x}; expected n64")
            abi = ABI.MIPS_N64
    elif machine == "EM_PPC64":
        abi_version = flags & _EF_PPC64_ABI_MASK
        if abi_version == _EF_PPC64_ABI_V1:
            abi = ABI.POWERPC64_ELFV1
        elif abi_version == _EF_PPC64_ABI_V2:
            abi = ABI.POWERPC64_ELFV2
        else:
            raise ELFInspectionError("PPC64 ELF ABI version is unspecified; refusing an endian-based guess")
    elif machine == "EM_RISCV" and flags & _EF_RISCV_RVE:
        raise ELFInspectionError("RISC-V E/ILP32E register ABI is not represented by the target catalog")

    try:
        return resolve_target(alias, bits=bits, endian=endian, abi=abi)
    except (UnsupportedTargetError, ValueError) as exc:
        detail = f"machine={machine}, bits={bits}, endian={endian.value}, abi={abi.value if abi else None}"
        raise ELFInspectionError(f"unsupported ELF target combination: {detail}") from exc


def _unique_offsets(values: Mapping[str, Iterable[int]]) -> Mapping[str, int]:
    result: dict[str, int] = {}
    for name, offsets in values.items():
        unique = {int(offset) for offset in offsets}
        if name and len(unique) == 1:
            result[name] = unique.pop()
    return result


def _symbol_offsets(elf: Any) -> Mapping[str, int]:
    try:
        from elftools.elf.sections import SymbolTableSection
    except ImportError as exc:  # pragma: no cover - project dependency via pwntools
        raise ELFInspectionError("pyelftools is required for ELF inspection") from exc

    candidates: defaultdict[str, set[int]] = defaultdict(set)
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            name = symbol.name
            index = symbol.entry.st_shndx
            if not name or index in {"SHN_UNDEF", "SHN_COMMON"}:
                continue
            candidates[name].add(int(symbol.entry.st_value))
    return _unique_offsets(candidates)


def _got_and_plt_offsets(elf: Any, target: Target) -> tuple[Mapping[str, int], Mapping[str, int]]:
    try:
        from elftools.elf.relocation import RelocationSection
    except ImportError as exc:  # pragma: no cover
        raise ELFInspectionError("pyelftools is required for ELF inspection") from exc

    got_sections: list[tuple[int, int]] = []
    for section in elf.iter_sections():
        if section.name == ".got" or section.name.startswith(".got.") or section.name in {".igot", ".igot.plt"}:
            start = int(section.header.sh_addr)
            got_sections.append((start, start + int(section.header.sh_size)))

    got_candidates: defaultdict[str, set[int]] = defaultdict(set)
    plt_relocations: list[str | None] = []
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        symbols = elf.get_section(int(section.header.sh_link))
        if symbols is None or not hasattr(symbols, "get_symbol"):
            continue
        # Only the canonical PLT relocation tables have a one-to-one ordering
        # with x86 .plt/.plt.sec entries.  IPLT and auxiliary PLT relocation
        # sections use distinct stub layouts, so treating them as ordinary PLT
        # entries could manufacture a wrong callable address.
        is_plt_relocations = section.name in {".rel.plt", ".rela.plt"}
        for relocation in section.iter_relocations():
            symbol_index = int(relocation.entry.r_info_sym)
            symbol = symbols.get_symbol(symbol_index) if symbol_index else None
            name = symbol.name if symbol is not None and symbol.name else None
            if is_plt_relocations:
                # Symbol-less IRELATIVE entries still consume a PLT slot and
                # must remain in the index geometry even though the public map
                # cannot name them.
                plt_relocations.append(name)
            if name is None:
                continue
            offset = int(relocation.entry.r_offset)
            if any(start <= offset < end for start, end in got_sections):
                got_candidates[name].add(offset)

    # Explicit linker-provided foo@plt symbols are always safe to expose.
    plt_candidates: defaultdict[str, set[int]] = defaultdict(set)
    for name, offset in _symbol_offsets(elf).items():
        if name.endswith("@plt"):
            plt_candidates[name.removesuffix("@plt")].add(offset)

    # x86 PLT entry geometry is described by sh_entsize.  Other ISAs have
    # architecture-specific headers/stubs; leave them absent rather than guess.
    if target.arch in {Architecture.X86, Architecture.X86_64} and plt_relocations:
        count = len(plt_relocations)
        plt_section = elf.get_section_by_name(".plt.sec")
        reserved = 0
        if plt_section is None:
            plt_section = elf.get_section_by_name(".plt")
            reserved = 1
        if plt_section is not None:
            entry_size = int(plt_section.header.sh_entsize)
            section_size = int(plt_section.header.sh_size)
            required_size = (count + reserved) * entry_size
            if entry_size > 0 and section_size >= required_size:
                base = int(plt_section.header.sh_addr) + reserved * entry_size
                for index, name in enumerate(plt_relocations):
                    if name is not None:
                        plt_candidates[name].add(base + index * entry_size)

    return _unique_offsets(got_candidates), _unique_offsets(plt_candidates)


def _build_id(elf: Any) -> str | None:
    try:
        from elftools.elf.sections import NoteSection
        from elftools.elf.segments import NoteSegment
    except ImportError as exc:  # pragma: no cover
        raise ELFInspectionError("pyelftools is required for ELF inspection") from exc

    candidates: set[str] = set()
    note_containers = [section for section in elf.iter_sections() if isinstance(section, NoteSection)]
    note_containers.extend(segment for segment in elf.iter_segments() if isinstance(segment, NoteSegment))
    for container in note_containers:
        for note in container.iter_notes():
            if note.get("n_type") != "NT_GNU_BUILD_ID" or str(note.get("n_name", "")).rstrip("\0") != "GNU":
                continue
            description = note.get("n_desc")
            if isinstance(description, str):
                value = description.lower().removeprefix("0x")
            elif isinstance(description, (bytes, bytearray, memoryview)):
                value = bytes(description).hex()
            else:
                continue
            if value and len(value) % 2 == 0 and all(character in "0123456789abcdef" for character in value):
                candidates.add(value)
    if len(candidates) > 1:
        raise ELFInspectionError("ELF contains conflicting GNU build IDs")
    return next(iter(candidates)) if candidates else None


def _dynamic_facts(elf: Any) -> tuple[int, int, tuple[str, ...], str | None, bool]:
    try:
        from elftools.elf.dynamic import DynamicSection, DynamicSegment
    except ImportError as exc:  # pragma: no cover
        raise ELFInspectionError("pyelftools is required for ELF inspection") from exc

    flags = 0
    flags_1 = 0
    needed: set[str] = set()
    sonames: set[str] = set()
    bind_now_tag = False
    dynamic_containers = [section for section in elf.iter_sections() if isinstance(section, DynamicSection)]
    dynamic_containers.extend(segment for segment in elf.iter_segments() if isinstance(segment, DynamicSegment))
    for container in dynamic_containers:
        for tag in container.iter_tags():
            kind = str(tag.entry.d_tag)
            if kind == "DT_FLAGS":
                flags |= int(tag.entry.d_val)
            elif kind == "DT_FLAGS_1":
                flags_1 |= int(tag.entry.d_val)
            elif kind == "DT_BIND_NOW":
                bind_now_tag = True
            elif kind == "DT_NEEDED":
                needed.add(str(tag.needed))
            elif kind == "DT_SONAME":
                sonames.add(str(tag.soname))
    soname = next(iter(sonames)) if len(sonames) == 1 else None
    return flags, flags_1, tuple(sorted(needed)), soname, bind_now_tag


def _interpreter(segments: tuple[Any, ...]) -> str | None:
    values: set[str] = set()
    for segment in segments:
        if str(segment.header.p_type) != "PT_INTERP":
            continue
        value = str(segment.get_interp_name())
        if value:
            values.add(value)
    return next(iter(values)) if len(values) == 1 else None


def _classify_image(
    elf_type: str,
    *,
    interpreter: str | None,
    needed: tuple[str, ...],
    soname: str | None,
    flags_1: int,
) -> tuple[ELFImageKind, bool, Linkage | None, tuple[str, ...]]:
    evidence: list[str] = [f"ELF type {elf_type}"]
    if elf_type == "ET_EXEC":
        dynamic = bool(interpreter or needed)
        if interpreter:
            evidence.append("PT_INTERP present")
        if needed:
            evidence.append("DT_NEEDED present")
        return ELFImageKind.EXECUTABLE, False, Linkage.DYNAMIC if dynamic else Linkage.STATIC, tuple(evidence)
    if elf_type != "ET_DYN":
        raise ELFInspectionError(f"ELF type {elf_type!r} is not a loadable executable/shared image")

    pie_flag = bool(flags_1 & _DF_1_PIE)
    if pie_flag and not interpreter and not needed:
        evidence.append("DF_1_PIE present with no interpreter or needed libraries")
        return ELFImageKind.STATIC_PIE, True, Linkage.STATIC, tuple(evidence)
    if pie_flag:
        evidence.append("DF_1_PIE present")
        return ELFImageKind.PIE_EXECUTABLE, True, Linkage.DYNAMIC, tuple(evidence)
    # glibc is deliberately executable as a diagnostic program and therefore
    # carries PT_INTERP as well as DT_SONAME.  SONAME is the stronger role
    # discriminator: consumers still map it as a shared object.
    if soname:
        evidence.append("DT_SONAME present")
        return ELFImageKind.SHARED_OBJECT, True, Linkage.DYNAMIC, tuple(evidence)
    if interpreter:
        evidence.append("PT_INTERP present")
        return ELFImageKind.PIE_EXECUTABLE, True, Linkage.DYNAMIC, tuple(evidence)
    if needed:
        evidence.append("DT_NEEDED present")
        return ELFImageKind.SHARED_OBJECT, True, Linkage.DYNAMIC, tuple(evidence)
    evidence.append("no executable/shared-object discriminator present")
    return ELFImageKind.ET_DYN_AMBIGUOUS, True, None, tuple(evidence)


def _main_code_entry(
    data: bytes,
    entry_offset: int,
    target: Target,
    load_ranges: tuple[ELFRange, ...],
) -> tuple[int, str]:
    """Resolve the executable PC represented by ``e_entry``.

    Most Linux ELFs store a code address directly in ``e_entry`` (with bit
    zero selecting Thumb state where applicable).  PPC64 ELFv1 is the notable
    exception: a normal executable may put a three-word ``.opd`` function
    descriptor there.  Its first word is the actual entry PC and its second
    word supplies r2/TOC.  Keep :attr:`ELFProfile.entry_offset` equal to the
    ELF header value, but validate the descriptor's code word against an
    executable mapping.
    """

    direct = entry_offset & ~1 if target.arch is Architecture.THUMB else entry_offset
    if any(item.executable and item.contains(direct) for item in load_ranges):
        return direct, "e_entry resolves directly to an executable PT_LOAD segment"
    if target.abi is not ABI.POWERPC64_ELFV1:
        raise ELFInspectionError("main executable entry is not contained in an executable PT_LOAD segment")

    descriptor_size = 3 * target.word_size
    if entry_offset % target.word_size:
        raise ELFInspectionError("PPC64 ELFv1 e_entry function descriptor is not word-aligned")
    candidates = [
        item
        for item in load_ranges
        if item.readable
        and item.contains(entry_offset, descriptor_size)
        and entry_offset + descriptor_size <= item.start + item.file_size
    ]
    if len(candidates) != 1:
        raise ELFInspectionError(
            "PPC64 ELFv1 e_entry is neither executable code nor one file-backed function descriptor"
        )
    mapping = candidates[0]
    file_offset = mapping.file_offset + entry_offset - mapping.start
    end = file_offset + descriptor_size
    if file_offset < 0 or end > len(data):
        raise ELFInspectionError("PPC64 ELFv1 e_entry function descriptor lies beyond the artifact")
    code_entry = int.from_bytes(data[file_offset : file_offset + target.word_size], target.endian.value)
    if not any(item.executable and item.contains(code_entry) for item in load_ranges):
        raise ELFInspectionError("PPC64 ELFv1 e_entry descriptor code word is not in an executable PT_LOAD segment")
    return code_entry, f"PPC64 ELFv1 e_entry descriptor resolves to executable PC {code_entry:#x}"


def inspect_elf(path: str | Path) -> ELFProfile:
    """Parse one exact ELF artifact without executing or loading it."""

    artifact = Path(path)
    try:
        data = artifact.read_bytes()
    except OSError as exc:
        raise ELFInspectionError(f"unable to read ELF artifact {artifact}: {exc}") from exc
    digest = sha256(data).hexdigest()
    if len(data) < 16 or not data.startswith(b"\x7fELF"):
        raise ELFInspectionError(f"not an ELF artifact: {artifact}")

    try:
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:  # pragma: no cover - project dependency via pwntools
        raise ELFInspectionError("pyelftools is required for ELF inspection") from exc

    try:
        elf = ELFFile(BytesIO(data))
        target = _resolve_target(elf)
        osabi = str(elf.header.e_ident.EI_OSABI)
        if osabi not in {"ELFOSABI_SYSV", "ELFOSABI_LINUX", "ELFOSABI_GNU"}:
            raise ELFInspectionError(f"ELF OSABI {osabi!r} is not a supported Linux/System-V ABI")
        segments = tuple(elf.iter_segments())
        load_segments = tuple(segment for segment in segments if str(segment.header.p_type) == "PT_LOAD")
        for segment in load_segments:
            _validate_program_segment(segment, target, len(data), "PT_LOAD")
        load_ranges = tuple(
            sorted(
                (_program_range(segment, "PT_LOAD") for segment in load_segments),
                key=lambda item: (item.start, item.end),
            )
        )
        if not load_ranges:
            raise ELFInspectionError("ELF has no PT_LOAD segments")
        dynamic_range = _exact_dynamic_range(elf, data, target, segments, load_ranges)
        build_id_ranges = _runtime_build_id_ranges(elf, data, target, segments, load_ranges)
        relro_segments = tuple(segment for segment in segments if str(segment.header.p_type) == "PT_GNU_RELRO")
        for segment in relro_segments:
            _validate_program_segment(segment, target, len(data), "PT_GNU_RELRO")
        relro_ranges = tuple(
            sorted(
                (_program_range(segment, "PT_GNU_RELRO") for segment in relro_segments),
                key=lambda item: (item.start, item.end),
            )
        )
        if any(not _range_is_load_mapped(item, load_ranges) for item in relro_ranges):
            raise ELFInspectionError("PT_GNU_RELRO range is not completely covered by PT_LOAD segments")
        stack_segments = [segment for segment in segments if str(segment.header.p_type) == "PT_GNU_STACK"]
        if len(stack_segments) > 1:
            raise ELFInspectionError("ELF contains multiple PT_GNU_STACK headers")
        if not stack_segments:
            nx: bool | None = None
            nx_evidence = "PT_GNU_STACK is absent; stack executability is unknown"
        elif any(int(segment.header.p_flags) & _PF_X for segment in stack_segments):
            nx = False
            nx_evidence = "PT_GNU_STACK requests execute permission"
        else:
            nx = True
            nx_evidence = "PT_GNU_STACK is present without execute permission"

        flags, flags_1, needed, soname, bind_now_tag = _dynamic_facts(elf)
        bind_now = bind_now_tag or bool(flags & _DF_BIND_NOW) or bool(flags_1 & _DF_1_NOW)
        relro = Relro.NONE if not relro_ranges else Relro.FULL if bind_now else Relro.PARTIAL
        interpreter = _interpreter(segments)
        elf_type = str(elf.header.e_type)
        image_kind, pie, linkage, classification_evidence = _classify_image(
            elf_type,
            interpreter=interpreter,
            needed=needed,
            soname=soname,
            flags_1=flags_1,
        )
        entry_offset = int(elf.header.e_entry)
        entry_evidence = "e_entry is not interpreted for a shared or ambiguous ET_DYN image"
        if image_kind not in {ELFImageKind.SHARED_OBJECT, ELFImageKind.ET_DYN_AMBIGUOUS}:
            _, entry_evidence = _main_code_entry(data, entry_offset, target, load_ranges)
        alignments = [
            item.alignment
            for item in load_ranges
            if item.alignment >= 0x1000 and not item.alignment & (item.alignment - 1)
        ]
        load_alignment_hint = min(alignments) if alignments else None
        symbols = _symbol_offsets(elf)
        got, plt = _got_and_plt_offsets(elf, target)
        build_id = _build_id(elf)
        mapped_build_ids = {
            data[item.file_offset : item.file_offset + item.file_size].hex() for item in build_id_ranges
        }
        if mapped_build_ids and mapped_build_ids != {build_id}:
            raise ELFInspectionError("runtime-mapped GNU build ID disagrees with ELF identity metadata")
    except ELFInspectionError:
        raise
    except (ELFError, KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
        raise ELFInspectionError(f"malformed or unsupported ELF {artifact}: {exc}") from exc
    except Exception as exc:
        # pyelftools exposes several struct/assertion failures for deliberately
        # malformed section tables.  Keep parser internals behind one API error.
        raise ELFInspectionError(f"unable to inspect untrusted ELF {artifact}: {exc}") from exc

    evidence = [
        *classification_evidence,
        nx_evidence,
        entry_evidence,
        f"RELRO={relro.value} from PT_GNU_RELRO and bind-now tags",
        "target from ELF machine/class/endian/ABI flags and ARM entry state",
    ]
    if build_id_ranges:
        evidence.append(f"GNU build ID has {len(build_id_ranges)} exact runtime-mapped PT_NOTE descriptor(s)")
    if dynamic_range is not None:
        evidence.append("PT_DYNAMIC has an exact readable PT_LOAD mapping")
    try:
        return ELFProfile(
            path=str(artifact),
            sha256=digest,
            build_id=build_id,
            target=target,
            osabi=osabi,
            elf_type=elf_type,
            image_kind=image_kind,
            pie=pie,
            linkage=linkage,
            nx=nx,
            nx_evidence=nx_evidence,
            relro=relro,
            bind_now=bind_now,
            entry_offset=entry_offset,
            interpreter=interpreter,
            needed_libraries=needed,
            soname=soname,
            load_ranges=load_ranges,
            relro_ranges=relro_ranges,
            load_alignment_hint=load_alignment_hint,
            build_id_ranges=build_id_ranges,
            dynamic_range=dynamic_range,
            symbol_offsets=symbols,
            got_offsets=got,
            plt_offsets=plt,
            evidence=tuple(evidence),
        )
    except (TypeError, ValueError) as exc:
        raise ELFInspectionError(f"malformed or unsupported ELF {artifact}: {exc}") from exc


load_elf_profile = inspect_elf


__all__ = [
    "ELFImageKind",
    "ELFInspectionError",
    "ELFProfile",
    "ELFRange",
    "inspect_elf",
    "load_elf_profile",
]
