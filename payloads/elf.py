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
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if (
            not isinstance(self.entry_offset, int)
            or isinstance(self.entry_offset, bool)
            or not 0 <= self.entry_offset <= self.target.mask
        ):
            raise ValueError("entry_offset must fit the target address width")
        for name in ("load_ranges", "relro_ranges"):
            for item in getattr(self, name):
                if item.start > self.target.mask or item.end > self.target.mask + 1:
                    raise ValueError(f"{name} contains a range outside the target address space")
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

    if kind == "PT_LOAD" and file_size > memory_size:
        raise ELFInspectionError("PT_LOAD file size exceeds its memory size")
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
    return next(iter(candidates)) if len(candidates) == 1 else None


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
        code_entry = entry_offset & ~1 if target.arch is Architecture.THUMB else entry_offset
        if image_kind not in {ELFImageKind.SHARED_OBJECT, ELFImageKind.ET_DYN_AMBIGUOUS} and not any(
            item.executable and item.contains(code_entry) for item in load_ranges
        ):
            raise ELFInspectionError("main executable entry is not contained in an executable PT_LOAD segment")
        alignments = [
            item.alignment
            for item in load_ranges
            if item.alignment >= 0x1000 and not item.alignment & (item.alignment - 1)
        ]
        load_alignment_hint = min(alignments) if alignments else None
        symbols = _symbol_offsets(elf)
        got, plt = _got_and_plt_offsets(elf, target)
        build_id = _build_id(elf)
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
        f"RELRO={relro.value} from PT_GNU_RELRO and bind-now tags",
        "target from ELF machine/class/endian/ABI flags and ARM entry state",
    ]
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
