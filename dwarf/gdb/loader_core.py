"""GDB-independent ELF rebasing and Teemo manifest helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import os
from pathlib import Path
import struct
from typing import Iterable


MANIFEST_SCHEMA = "pwnc.teemo.manifest"
MANIFEST_VERSION = 1
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_NOTE = 4
NT_GNU_BUILD_ID = 3


class LoaderError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LoadSegment:
    offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int


@dataclass(frozen=True, slots=True)
class ElfImage:
    elf_class: int
    endianness: str
    object_type: int
    machine: int
    entry_point: int
    load_segments: tuple[LoadSegment, ...]
    build_id: str | None = None


@dataclass(frozen=True, slots=True)
class MapEntry:
    start: int
    end: int
    permissions: str
    offset: int
    path: str | None


@dataclass(frozen=True, slots=True)
class LoaderSection:
    name: str
    address: int
    size: int
    executable: bool
    writable: bool


@dataclass(frozen=True, slots=True)
class LoaderManifest:
    path: Path
    epoch: int
    view_id: str
    created_ns: int
    binary_path: Path
    binary_filename: str
    build_id: str | None
    architecture: str
    image_base: int
    entry_point: int
    debug_object: Path
    ir: Path
    source_root: Path
    primary_section: str
    sections: tuple[LoaderSection, ...]

    @classmethod
    def load(cls, path: str | Path, *, require_artifacts: bool = True) -> LoaderManifest:
        path = Path(path).expanduser().resolve(strict=False)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise LoaderError(f"cannot read Teemo manifest {path}: {error}") from error
        if raw.get("schema") != MANIFEST_SCHEMA or raw.get("version") != MANIFEST_VERSION:
            raise LoaderError(f"unsupported Teemo manifest schema in {path}")
        try:
            manifest = cls(
                path=path,
                epoch=int(raw["epoch"]),
                view_id=str(raw["view_id"]),
                created_ns=int(raw["created_ns"]),
                binary_path=Path(raw["binary_path"]).expanduser().resolve(strict=False),
                binary_filename=str(raw["binary_filename"]),
                build_id=str(raw["build_id"]) if raw.get("build_id") else None,
                architecture=str(raw["architecture"]),
                image_base=int(raw["image_base"]),
                entry_point=int(raw["entry_point"]),
                debug_object=Path(raw["debug_object"]).expanduser().resolve(strict=False),
                ir=Path(raw["ir"]).expanduser().resolve(strict=False),
                source_root=Path(raw["source_root"]).expanduser().resolve(strict=False),
                primary_section=str(raw["primary_section"]),
                sections=tuple(LoaderSection(**section) for section in raw["sections"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise LoaderError(f"malformed Teemo manifest {path}: {error}") from error
        manifest.validate(require_artifacts=require_artifacts)
        return manifest

    def validate(self, *, require_artifacts: bool = True) -> None:
        if self.epoch < 1 or not self.view_id:
            raise LoaderError("manifest has an invalid epoch or view id")
        if self.architecture not in {"x86_64", "x86", "arm", "aarch64"}:
            raise LoaderError(f"manifest has unsupported architecture {self.architecture!r}")
        if not self.sections:
            raise LoaderError("manifest contains no sections")
        names = [section.name for section in self.sections]
        if len(names) != len(set(names)):
            raise LoaderError("manifest contains duplicate section names")
        if self.primary_section not in names:
            raise LoaderError(f"manifest primary section {self.primary_section!r} does not exist")
        if any(section.address < 0 or section.size <= 0 for section in self.sections):
            raise LoaderError("manifest contains an invalid section")
        if require_artifacts:
            if not self.debug_object.is_file():
                raise LoaderError(f"debug object has disappeared: {self.debug_object}")
            if not self.ir.is_file():
                raise LoaderError(f"IR artifact has disappeared: {self.ir}")
            if not self.source_root.is_dir():
                raise LoaderError(f"generated source tree has disappeared: {self.source_root}")

    @property
    def primary(self) -> LoaderSection:
        return next(section for section in self.sections if section.name == self.primary_section)


def read_elf(path: str | Path) -> ElfImage:
    path = Path(path)
    try:
        with path.open("rb") as value:
            ident = value.read(16)
            if len(ident) != 16 or ident[:4] != b"\x7fELF":
                raise LoaderError(f"not an ELF file: {path}")
            elf_class = ident[4]
            data = ident[5]
            if elf_class not in {1, 2} or data not in {1, 2}:
                raise LoaderError(f"unsupported ELF class or byte order in {path}")
            endian = "<" if data == 1 else ">"
            header_format = endian + ("HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH")
            header_size = struct.calcsize(header_format)
            header = struct.unpack(header_format, value.read(header_size))
            object_type, machine, entry_point, phoff = header[0], header[1], header[3], header[4]
            phentsize, phnum = header[8], header[9]
            expected_ph_size = struct.calcsize(endian + ("IIIIIIII" if elf_class == 1 else "IIQQQQQQ"))
            if phentsize < expected_ph_size:
                raise LoaderError(f"ELF program header is too small in {path}")
            segments = []
            note_segments = []
            for index in range(phnum):
                value.seek(phoff + index * phentsize)
                raw = value.read(phentsize)
                if len(raw) != phentsize:
                    raise LoaderError(f"truncated ELF program headers in {path}")
                if elf_class == 1:
                    p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                        endian + "IIIIIIII", raw
                    )
                else:
                    p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                        endian + "IIQQQQQQ", raw
                    )
                if p_type == PT_LOAD:
                    segments.append(LoadSegment(p_offset, p_vaddr, p_filesz, p_memsz, p_flags, p_align))
                elif p_type == PT_NOTE and p_filesz:
                    note_segments.append((p_offset, p_filesz))
            build_id = None
            for note_offset, note_size in note_segments:
                value.seek(note_offset)
                notes = value.read(note_size)
                if len(notes) != note_size:
                    raise LoaderError(f"truncated ELF note segment in {path}")
                build_id = _gnu_build_id(notes, endian)
                if build_id is not None:
                    break
    except OSError as error:
        raise LoaderError(f"cannot read inferior ELF {path}: {error}") from error
    return ElfImage(
        elf_class=32 if elf_class == 1 else 64,
        endianness="little" if data == 1 else "big",
        object_type=object_type,
        machine=machine,
        entry_point=entry_point,
        load_segments=tuple(segments),
        build_id=build_id,
    )


def _gnu_build_id(notes: bytes, endian: str) -> str | None:
    """Return the GNU build ID from one ELF note segment, if present."""

    offset = 0
    while offset + 12 <= len(notes):
        name_size, description_size, note_type = struct.unpack_from(
            endian + "III",
            notes,
            offset,
        )
        offset += 12
        name_end = offset + name_size
        description_offset = _align_up(name_end, 4)
        description_end = description_offset + description_size
        next_offset = _align_up(description_end, 4)
        if (
            name_end > len(notes)
            or description_end > len(notes)
            or next_offset > len(notes)
        ):
            return None
        name = notes[offset:name_end].rstrip(b"\0")
        if note_type == NT_GNU_BUILD_ID and name == b"GNU" and description_size:
            return notes[description_offset:description_end].hex()
        offset = next_offset
    return None


def parse_proc_maps(lines: str | Iterable[str]) -> list[MapEntry]:
    if isinstance(lines, str):
        lines = lines.splitlines()
    result = []
    for line in lines:
        fields = line.rstrip("\n").split(None, 5)
        if len(fields) < 5:
            continue
        try:
            start_text, end_text = fields[0].split("-", 1)
            start, end = int(start_text, 16), int(end_text, 16)
            offset = int(fields[2], 16)
        except ValueError:
            continue
        path = fields[5] if len(fields) == 6 else None
        if path and path.endswith(" (deleted)"):
            path = path[: -len(" (deleted)")]
        result.append(MapEntry(start, end, fields[1], offset, path))
    return result


def compute_load_bias(
    binary_path: str | Path,
    image: ElfImage,
    mappings: Iterable[MapEntry],
    *,
    page_size: int | None = None,
) -> int:
    """Derive ``runtime VA - link-time VA`` by matching PT_LOAD file offsets."""

    binary_path = Path(binary_path).expanduser().resolve(strict=False)
    page_size = page_size or _page_size()
    relevant = [mapping for mapping in mappings if mapping.path and _same_path(binary_path, mapping.path)]
    candidates = []
    for mapping in relevant:
        for segment in image.load_segments:
            segment_offset = _align_down(segment.offset, page_size)
            segment_vaddr = _align_down(segment.virtual_address, page_size)
            mapped_file_end = _align_up(segment.offset + max(segment.file_size, 1), page_size)
            if not segment_offset <= mapping.offset < mapped_file_end:
                continue
            expected_vaddr = segment_vaddr + (mapping.offset - segment_offset)
            candidates.append(mapping.start - expected_vaddr)
    if not candidates:
        if image.object_type == ET_EXEC:
            return 0
        raise LoaderError(f"cannot derive PIE load bias for {binary_path} from process mappings")
    counts = Counter(candidates)
    bias, count = counts.most_common(1)[0]
    if list(counts.values()).count(count) > 1:
        raise LoaderError(f"ambiguous load bias candidates for {binary_path}: {sorted(counts)}")
    if bias < 0:
        raise LoaderError(f"derived a negative load bias {bias:#x} for {binary_path}")
    return bias


def add_symbol_file_command(manifest: LoaderManifest, bias: int) -> str:
    if bias < 0:
        raise LoaderError("load bias must not be negative")
    primary = manifest.primary
    arguments = [
        "add-symbol-file",
        _gdb_quote(str(manifest.debug_object)),
        f"{primary.address + bias:#x}",
    ]
    for section in manifest.sections:
        if section.name == primary.name:
            continue
        arguments.extend(("-s", _gdb_quote(section.name), f"{section.address + bias:#x}"))
    return " ".join(arguments)


def remove_symbol_file_command(manifest: LoaderManifest, bias: int) -> str:
    return f"remove-symbol-file -a {manifest.primary.address + bias:#x}"


def find_manifest(
    state_root: str | Path,
    program_path: str | Path,
    *,
    build_id: str | None = None,
) -> Path:
    root = Path(state_root).expanduser()
    program = Path(program_path).expanduser().resolve(strict=False)
    manifests = []
    for path in root.glob("*/current.json"):
        try:
            manifest = LoaderManifest.load(path)
        except LoaderError:
            continue
        manifests.append(manifest)
    exact = [manifest for manifest in manifests if _same_path(program, manifest.binary_path)]
    if exact:
        return max(exact, key=lambda manifest: manifest.created_ns).path
    if build_id:
        normalized = build_id.lower()
        matching_build_ids = [
            manifest
            for manifest in manifests
            if manifest.build_id is not None and manifest.build_id.lower() == normalized
        ]
        if matching_build_ids:
            return max(matching_build_ids, key=lambda manifest: manifest.created_ns).path
    raise LoaderError(f"no Teemo manifest matches {program}")


def architecture_matches(manifest_architecture: str, gdb_architecture: str) -> bool:
    normalized = gdb_architecture.lower().replace("-", "_")
    if manifest_architecture == "x86_64":
        return normalized in {"x86_64", "amd64", "i386:x86_64"} or normalized.startswith(
            ("x86_64:", "amd64:", "i386:x86_64:")
        )
    if manifest_architecture == "x86":
        if "x86_64" in normalized or "amd64" in normalized:
            return False
        return normalized == "x86" or any(
            normalized == prefix or normalized.startswith(prefix + ":")
            for prefix in ("i386", "i486", "i586", "i686")
        )
    if manifest_architecture == "arm":
        if normalized.startswith(("aarch64", "arm64")):
            return False
        return normalized.startswith(("arm", "thumb"))
    if manifest_architecture == "aarch64":
        return normalized in {"aarch64", "arm64"} or normalized.startswith(("aarch64:", "arm64:"))
    return False


def _same_path(first: str | Path, second: str | Path) -> bool:
    first_path = Path(first).expanduser()
    second_path = Path(second).expanduser()
    try:
        return first_path.samefile(second_path)
    except OSError:
        return first_path.resolve(strict=False) == second_path.resolve(strict=False)


def _gdb_quote(value: str) -> str:
    if "\0" in value or "\n" in value or "\r" in value:
        raise LoaderError("GDB command arguments cannot contain NUL or newlines")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _page_size() -> int:
    try:
        return int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, ValueError):
        return 4096


def _align_down(value: int, alignment: int) -> int:
    return value & -alignment


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment
