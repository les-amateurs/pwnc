"""JSON-native GDB requests used by the host-side runtime API.

This file is sourced inside GDB.  It intentionally imports neither pwnc nor
the viewer.  bata24 integration calls its Python objects directly when they are
present in the shared GDB Python namespace; no command output is parsed.
"""

import os
import re
import struct

import gdb
from gdb.dap.server import request


def _pwnc_error(error):
    try:
        message = str(error)
    except BaseException:
        message = "<exception stringification failed>"
    return {"type": type(error).__name__, "message": message}


def _pwnc_path(value):
    if value is None:
        return None
    value = str(value)
    if value.startswith("target:"):
        value = value[7:]
    return value


def _pwnc_build_id(objfile):
    value = getattr(objfile, "build_id", None)
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    value = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower()
    return value or None


def _pwnc_module_kind(path, main_path):
    if path and main_path and os.path.normpath(path) == os.path.normpath(main_path):
        return "main"
    name = os.path.basename(path or "")
    if name.startswith("libc.so") or re.match(r"^libc-[0-9]", name):
        return "libc"
    if name.startswith("ld-linux") or name.startswith("ld-musl") or name in {"ld.so", "ld.so.1"}:
        return "loader"
    if name in {"linux-vdso.so.1", "linux-gate.so.1"}:
        return "vdso"
    return "shared-library"


def _pwnc_proc_maps(pid):
    path = "/proc/{:d}/maps".format(pid)
    result = []
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as stream:
        for line in stream:
            columns = line.rstrip("\n").split(None, 5)
            if len(columns) < 5:
                continue
            bounds, permissions, offset, _device, inode = columns[:5]
            mapped_path = columns[5] if len(columns) == 6 else ""
            start, end = (int(item, 16) for item in bounds.split("-", 1))
            result.append(
                {
                    "start": start,
                    "end": end,
                    "permissions": permissions,
                    "offset": int(offset, 16),
                    "inode": int(inode),
                    "path": mapped_path,
                    "private": permissions.endswith("p"),
                }
            )
    return result


def _pwnc_bata_maps():
    provider = globals().get("ProcessMap")
    if provider is None:
        return None
    sections = provider.get_process_maps()
    return [
        {
            "start": int(section.page_start),
            "end": int(section.page_end),
            "permissions": str(section.permission),
            "offset": int(section.offset or 0),
            "inode": None if section.inode is None else int(section.inode),
            "path": str(section.path or ""),
            "private": None,
        }
        for section in sections
    ]


def _pwnc_bata_capabilities():
    process_map = globals().get("ProcessMap")
    heap = globals().get("GlibcHeap")
    architecture = globals().get("current_arch")
    return {
        "available": process_map is not None,
        "adapter": "bata24-direct-v1" if process_map is not None else None,
        "maps": bool(process_map is not None and callable(getattr(process_map, "get_process_maps", None))),
        "heap": bool(
            heap is not None
            and callable(getattr(heap, "get_arena", None))
            and callable(getattr(heap, "get_all_arenas", None))
            and getattr(heap, "GlibcChunk", None) is not None
        ),
        "tls": bool(architecture is not None and callable(getattr(architecture, "get_tls", None))),
        "canary": bool(globals().get("CanaryCommand") is not None),
    }


def _pwnc_validate_maps(maps):
    """Reject remote-provider file maps that do not cover the actual PC."""

    try:
        frame = gdb.selected_frame()
        pc = int(frame.pc())
    except BaseException:
        return maps, True
    if any(
        int(item["start"]) <= pc < int(item["end"])
        and "x" in str(item.get("permissions") or "")
        for item in maps
    ):
        return maps, True
    stack_pointer = None
    for name in ("sp", "rsp", "esp", "r13"):
        try:
            stack_pointer = int(frame.read_register(name))
            break
        except BaseException:
            pass
    retained = []
    for item in maps:
        path = str(item.get("path") or "")
        if not path.startswith("["):
            continue
        if stack_pointer is not None and int(item["start"]) <= stack_pointer < int(item["end"]):
            retained.append(item)
    return retained, False


def _pwnc_paths_match(left, right):
    if not left or not right:
        return False
    left = re.sub(r"<(?:tls|stack)-th\d+>", "", _pwnc_path(left)).removesuffix(" (deleted)")
    right = _pwnc_path(right).removesuffix(" (deleted)")
    if os.path.normpath(left) == os.path.normpath(right):
        return True
    try:
        return os.path.exists(left) and os.path.exists(right) and os.path.samefile(left, right)
    except OSError:
        return False


def _pwnc_local_module_path(path):
    """Resolve a target-absolute solib name through GDB's configured roots."""

    path = _pwnc_path(path)
    if not path or os.path.exists(path):
        return path
    if os.path.isabs(path):
        try:
            sysroot = str(gdb.parameter("sysroot") or "")
        except BaseException:
            sysroot = ""
        if sysroot.startswith("target:"):
            sysroot = ""
        candidate = os.path.join(sysroot, path.lstrip(os.sep)) if sysroot else ""
        if candidate and os.path.exists(candidate):
            return candidate
    try:
        search = str(gdb.parameter("solib-search-path") or "")
    except BaseException:
        search = ""
    for directory in search.split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, os.path.basename(path))
        if os.path.exists(candidate):
            return candidate
    return path


def _pwnc_mapped_module_path(item):
    path = _pwnc_path(item.get("path"))
    if not path or path.startswith("[") or path.startswith("<"):
        try:
            solib = gdb.solib_name(int(item["start"]))
        except BaseException:
            solib = None
        if solib:
            path = _pwnc_path(solib)
    return _pwnc_local_module_path(path)


_PWNC_PT_LOAD = 1
_PWNC_PT_DYNAMIC = 2
_PWNC_PT_NOTE = 4
_PWNC_PF_X = 1
_PWNC_PF_W = 2
_PWNC_NT_GNU_BUILD_ID = 3
_PWNC_NOTE_LIMIT = 1024 * 1024
_PWNC_NOTE_RECORD_LIMIT = 4096
_PWNC_IDENTITY_LIMIT = 64 * 1024 * 1024
_PWNC_IDENTITY_CHUNK = 1024 * 1024


def _pwnc_note_identity(stream, program_headers, endian):
    """Return one unambiguous GNU build-ID note and note parse status.

    The returned bytes cover the complete note record (header, padded owner,
    and padded descriptor), not merely its descriptor.  The remote verifier
    subsequently requires that record to live in an immutable PT_LOAD.
    """

    found = []
    malformed = False
    total_size = 0
    records = 0
    for segment in program_headers:
        if segment["type"] != _PWNC_PT_NOTE or not segment["file_size"]:
            continue
        size = int(segment["file_size"])
        total_size += size
        if size > _PWNC_NOTE_LIMIT or total_size > _PWNC_NOTE_LIMIT:
            return (), True
        stream.seek(int(segment["offset"]))
        data = stream.read(size)
        if len(data) != size:
            malformed = True
            continue
        cursor = 0
        while cursor < len(data):
            remaining = len(data) - cursor
            if remaining < 12:
                if any(memoryview(data)[cursor:]):
                    malformed = True
                break
            header = data[cursor : cursor + 12]
            if header == b"\0" * 12:
                if any(memoryview(data)[cursor:]):
                    malformed = True
                break
            records += 1
            if records > _PWNC_NOTE_RECORD_LIMIT:
                return (), True
            namesz, descsz, note_type = struct.unpack_from(endian + "III", data, cursor)
            name_end = cursor + 12 + namesz
            name_padded_end = (name_end + 3) & ~3
            desc_end = name_padded_end + descsz
            record_end = (desc_end + 3) & ~3
            if (
                namesz > _PWNC_NOTE_LIMIT
                or descsz > _PWNC_NOTE_LIMIT
                or record_end > len(data)
            ):
                malformed = True
                break
            owner = data[cursor + 12 : name_end].rstrip(b"\0")
            descriptor = data[name_padded_end:desc_end]
            if note_type == _PWNC_NT_GNU_BUILD_ID and owner == b"GNU":
                if not descriptor:
                    malformed = True
                else:
                    found.append(
                        {
                            "descriptor": descriptor,
                            "offset": int(segment["offset"]) + cursor,
                            "record": data[cursor:record_end],
                        }
                    )
            cursor = record_end

    if found:
        descriptors = {item["descriptor"] for item in found}
        if len(descriptors) != 1:
            return (), True
        return tuple(found), malformed
    return (), malformed


def _pwnc_dynamic_textrel(stream, dynamic, ptrsize, endian):
    """Return whether dynamic relocation metadata permits text relocation.

    ``None`` means the table is malformed or too large to classify safely.
    The immutable-segment fallback rejects both ``True`` and ``None``.
    """

    if dynamic is None:
        return False
    size = int(dynamic["file_size"])
    entry_size = ptrsize * 2
    if not size or size > _PWNC_NOTE_LIMIT or size % entry_size:
        return None
    stream.seek(int(dynamic["offset"]))
    data = stream.read(size)
    if len(data) != size:
        return None
    unpack = endian + ("qQ" if ptrsize == 8 else "iI")
    terminated = False
    textrel = False
    for cursor in range(0, len(data), entry_size):
        tag, value = struct.unpack_from(unpack, data, cursor)
        if tag == 0:  # DT_NULL
            terminated = True
            break
        if tag == 22 or (tag == 30 and value & 4):  # DT_TEXTREL / DF_TEXTREL
            textrel = True
    if not terminated:
        return None
    return textrel


def _pwnc_elf_image(path):
    """Read only the ELF program-header facts needed for link-map recovery."""

    path = _pwnc_local_module_path(path)
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as stream:
        image_size = os.fstat(stream.fileno()).st_size
        header = stream.read(64)
        if len(header) < 52 or header[:4] != b"\x7fELF":
            return None
        elf_class = header[4]
        byte_order = header[5]
        if elf_class not in (1, 2) or byte_order not in (1, 2):
            return None
        endian = "<" if byte_order == 1 else ">"
        elf_type = struct.unpack_from(endian + "H", header, 16)[0]
        header_size = 64 if elf_class == 2 else 52
        if elf_class == 2:
            phoff = struct.unpack_from(endian + "Q", header, 32)[0]
            phentsize = struct.unpack_from(endian + "H", header, 54)[0]
            phnum = struct.unpack_from(endian + "H", header, 56)[0]
            expected = 56
        else:
            phoff = struct.unpack_from(endian + "I", header, 28)[0]
            phentsize = struct.unpack_from(endian + "H", header, 42)[0]
            phnum = struct.unpack_from(endian + "H", header, 44)[0]
            expected = 32
        if phentsize < expected or phentsize > 4096 or phnum > 4096:
            return None
        ph_table_size = phentsize * phnum
        if phoff > image_size or ph_table_size > image_size - phoff:
            return None
        segments = []
        program_headers = []
        dynamic = None
        duplicate_dynamic = False
        ph_table = bytearray()
        for index in range(phnum):
            stream.seek(phoff + index * phentsize)
            raw = stream.read(phentsize)
            if len(raw) < expected:
                return None
            ph_table.extend(raw)
            if elf_class == 2:
                p_type, flags, offset, virtual, _physical, file_size, memory_size, alignment = struct.unpack_from(
                    endian + "IIQQQQQQ", raw
                )
            else:
                p_type, offset, virtual, _physical, file_size, memory_size, flags, alignment = struct.unpack_from(
                    endian + "IIIIIIII", raw
                )
            segment = {
                "type": p_type,
                "flags": flags,
                "offset": offset,
                "virtual": virtual,
                "file_size": file_size,
                "memory_size": memory_size,
                "alignment": alignment,
            }
            if offset > image_size or file_size > image_size - offset:
                return None
            if p_type == _PWNC_PT_LOAD and file_size > memory_size:
                return None
            program_headers.append(segment)
            if p_type == _PWNC_PT_LOAD:
                segments.append(segment)
            elif p_type == _PWNC_PT_DYNAMIC:
                if dynamic is not None:
                    duplicate_dynamic = True
                dynamic = segment
        build_ids, notes_malformed = _pwnc_note_identity(stream, program_headers, endian)
        ptrsize = 8 if elf_class == 2 else 4
        dynamic_textrel = (
            None
            if duplicate_dynamic
            else _pwnc_dynamic_textrel(stream, dynamic, ptrsize, endian)
        )
        return {
            "path": path,
            "type": elf_type,
            "header": header[:header_size],
            "ptrsize": ptrsize,
            "endian": endian,
            "segments": segments,
            "program_headers": program_headers,
            "dynamic": dynamic,
            "dynamic_textrel": dynamic_textrel,
            "build_id_notes": build_ids,
            "notes_malformed": notes_malformed,
            "layout": (
                (0, header[:header_size]),
                (phoff, bytes(ph_table)),
            ),
        }


def _pwnc_remote_offsets():
    """Return the relocation offsets reported by the active RSP target.

    QEMU-user exposes the guest executable's load bias through the standard
    ``qOffsets`` packet.  GDB consumes that packet while creating the remote
    target, but a later ``file`` command silently throws the relocation away.
    There is no public GDB Python packet API, so use GDB's packet command and
    parse only its quoted, protocol-owned response (the DAP session requests
    the English locale during initialization).
    """

    output = gdb.execute("maintenance packet qOffsets", to_string=True)
    response = re.search(r'received:\s*"([^"]*)"', output)
    if response is None:
        raise gdb.GdbError("cannot parse the QEMU qOffsets response")
    packet = response.group(1)
    if not packet:
        raise gdb.GdbError("QEMU did not report guest executable relocation via qOffsets")
    if packet.startswith("E"):
        raise gdb.GdbError("QEMU rejected qOffsets with " + packet)

    offsets = {}
    for field in packet.split(";"):
        name, separator, value = field.partition("=")
        if (
            not separator
            or name not in {"Text", "Data", "Bss"}
            or name in offsets
            or re.fullmatch(r"[0-9a-fA-F]+", value) is None
        ):
            raise gdb.GdbError("malformed qOffsets response: " + packet)
        try:
            offsets[name] = int(value, 16)
        except ValueError as error:
            raise gdb.GdbError("malformed qOffsets response: " + packet) from error
    return offsets


def _pwnc_gdb_path(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _pwnc_immutable_file_address(image, load_bias, offset, size):
    """Map one local file range through an immutable file-backed PT_LOAD."""

    result = []
    end = int(offset) + int(size)
    for segment in image["segments"]:
        if int(segment["flags"]) & _PWNC_PF_W:
            continue
        segment_offset = int(segment["offset"])
        segment_end = segment_offset + int(segment["file_size"])
        if segment_offset <= int(offset) and end <= segment_end:
            result.append(
                int(load_bias)
                + int(segment["virtual"])
                + int(offset)
                - segment_offset
            )
    if not result:
        return None
    # Overlapping PT_LOADs may alias one file range at the same address.  If
    # they disagree, selecting either would make the identity proof ambiguous.
    if len(set(result)) != 1:
        raise gdb.GdbError(
            "configured guest ELF maps one immutable identity range at multiple addresses"
        )
    return result[0]


def _pwnc_compare_remote_bytes(address, local, description):
    compared = 0
    while compared < len(local):
        amount = min(_PWNC_IDENTITY_CHUNK, len(local) - compared)
        try:
            remote = _pwnc_inferior_bytes(int(address) + compared, amount)
        except BaseException as error:
            raise gdb.GdbError(
                f"guest {description} is unreadable at {int(address) + compared:#x}"
            ) from error
        if remote != local[compared : compared + amount]:
            raise gdb.GdbError(
                "reported load bias does not identify the configured guest executable: "
                + description
                + " differs"
            )
        compared += amount
    return compared


def _pwnc_verify_layout(image, load_bias):
    """Verify the exact mapped ELF header and program-header layout bytes."""

    compared = 0
    for offset, local in image["layout"]:
        if not local:
            continue
        address = _pwnc_immutable_file_address(image, load_bias, offset, len(local))
        if address is None:
            raise gdb.GdbError(
                "configured guest ELF does not map its ELF/program-header layout "
                "through an immutable PT_LOAD"
            )
        compared += _pwnc_compare_remote_bytes(
            address,
            local,
            "ELF/program-header layout",
        )
    return compared


def _pwnc_verify_remote_image(image, load_bias):
    """Verify safe mapped identity evidence for the configured guest ELF.

    A valid mapped GNU build-ID is additional identity evidence; every image
    must also match every byte of every immutable file-backed PT_LOAD.  The
    comparison deliberately says nothing about ordinary writable initial data:
    reading writable or relocated state would make verification depend on
    loader or inferior execution timing rather than immutable identity.
    """

    _pwnc_verify_layout(image, load_bias)
    if image["notes_malformed"]:
        raise gdb.GdbError("configured guest ELF has malformed PT_NOTE data")
    if image["dynamic_textrel"] is None:
        raise gdb.GdbError(
            "configured guest ELF has malformed or ambiguous dynamic metadata; "
            "immutable identity verification is unsafe"
        )
    if image["dynamic_textrel"]:
        raise gdb.GdbError(
            "configured guest ELF permits text relocations; immutable identity verification is unsafe"
        )
    if any(
        int(segment["file_size"])
        and int(segment["flags"]) & _PWNC_PF_W
        and int(segment["flags"]) & _PWNC_PF_X
        for segment in image["segments"]
    ):
        raise gdb.GdbError(
            "configured guest ELF has a writable-executable PT_LOAD; immutable identity verification is unsafe"
        )

    build_id_mapped = False
    for note in image["build_id_notes"]:
        address = _pwnc_immutable_file_address(
            image,
            load_bias,
            note["offset"],
            len(note["record"]),
        )
        if address is not None:
            _pwnc_compare_remote_bytes(address, note["record"], "mapped GNU build-ID note")
            build_id_mapped = True

    immutable = [
        segment
        for segment in image["segments"]
        if not int(segment["flags"]) & _PWNC_PF_W and int(segment["file_size"])
    ]
    if not any(int(segment["flags"]) & _PWNC_PF_X for segment in immutable):
        raise gdb.GdbError(
            "configured guest ELF has no immutable executable PT_LOAD for identity verification"
        )
    total = sum(int(segment["file_size"]) for segment in immutable)
    if total > _PWNC_IDENTITY_LIMIT:
        raise gdb.GdbError(
            f"configured guest immutable PT_LOAD identity exceeds "
            f"the {_PWNC_IDENTITY_LIMIT}-byte safety limit"
        )

    with open(image["path"], "rb") as stream:
        for segment in sorted(
            immutable,
            key=lambda item: (int(item["offset"]), int(item["virtual"])),
        ):
            offset = int(segment["offset"])
            remaining = int(segment["file_size"])
            address = int(load_bias) + int(segment["virtual"])
            stream.seek(offset)
            cursor = 0
            while cursor < remaining:
                amount = min(_PWNC_IDENTITY_CHUNK, remaining - cursor)
                local = stream.read(amount)
                if len(local) != amount:
                    raise gdb.GdbError(
                        "configured guest ELF changed while verifying immutable PT_LOAD identity"
                    )
                _pwnc_compare_remote_bytes(
                    address + cursor,
                    local,
                    "immutable PT_LOAD segment",
                )
                cursor += amount
    if build_id_mapped:
        return "gnu-build-id+immutable-load-segments"
    return "immutable-load-segments"


@request("pwncQemuUserRebase")
def pwnc_qemu_user_rebase(*, program: str, **_extra):
    """Load main-executable symbols at QEMU's exact guest address.

    This deliberately uses only the stopped guest, its RSP ``qOffsets`` reply,
    and the configured local ELF.  It never consults host ``/proc`` mappings.
    """

    image = _pwnc_elf_image(program)
    if image is None:
        raise gdb.GdbError("configured QEMU guest program is not a readable ELF: " + str(program))
    if image["type"] == 2:  # ET_EXEC has link-time absolute symbols.
        identity = _pwnc_verify_remote_image(image, 0)
        gdb.execute(
            "symbol-file %s" % _pwnc_gdb_path(image["path"]),
            to_string=True,
        )
        return {
            "pie": False,
            "loadBias": 0,
            "source": "elf",
            "symbolsReloaded": True,
            "identity": identity,
        }
    if image["type"] != 3:
        raise gdb.GdbError("unsupported QEMU guest ELF type %d" % int(image["type"]))

    offsets = _pwnc_remote_offsets()
    if "Text" not in offsets or "Data" not in offsets:
        raise gdb.GdbError(
            "QEMU qOffsets did not provide Text and Data relocations; "
            "cannot rebase guest PIE symbols"
        )
    address_limit = 1 << (int(image["ptrsize"]) * 8)
    if any(value >= address_limit for value in offsets.values()):
        raise gdb.GdbError("QEMU qOffsets relocation exceeds the guest address width")
    load_bias = offsets["Text"]
    distinct = {
        value
        for name, value in offsets.items()
        if name in {"Text", "Data", "Bss"}
    }
    if len(distinct) != 1:
        raise gdb.GdbError(
            "QEMU reported different text/data PIE relocations; one symbol-file bias is insufficient"
        )
    if any(
        load_bias + int(segment["virtual"]) >= address_limit
        or int(segment["memory_size"])
        > address_limit - load_bias - int(segment["virtual"])
        for segment in image["segments"]
    ):
        raise gdb.GdbError("QEMU qOffsets relocation overflows a guest PT_LOAD address")

    identity = _pwnc_verify_remote_image(image, load_bias)
    gdb.execute(
        "symbol-file -o %#x %s" % (load_bias, _pwnc_gdb_path(image["path"])),
        to_string=True,
    )
    return {
        "pie": True,
        "loadBias": load_bias,
        "source": "qOffsets",
        "symbolsReloaded": True,
        "identity": identity,
    }


def _pwnc_image_load_bias(image, maps, path):
    candidates = {}
    for item in maps:
        if not _pwnc_paths_match(item.get("path"), path):
            continue
        for segment in image["segments"]:
            delta = int(item.get("offset") or 0) - segment["offset"]
            if delta < 0 or delta >= max(segment["file_size"], 1):
                continue
            candidate = int(item["start"]) - segment["virtual"] - delta
            candidates[candidate] = candidates.get(candidate, 0) + 1
    if not candidates:
        return None
    return max(candidates, key=lambda value: (candidates[value], -abs(value)))


def _pwnc_inferior_bytes(address, size):
    return bytes(gdb.selected_inferior().read_memory(int(address), int(size)))


def _pwnc_cstring(address, limit=4096):
    if not address:
        return ""
    result = bytearray()
    while len(result) < limit:
        block = _pwnc_inferior_bytes(address + len(result), min(256, limit - len(result)))
        terminator = block.find(b"\0")
        if terminator >= 0:
            result.extend(block[:terminator])
            break
        result.extend(block)
    return bytes(result).decode("utf-8", "surrogateescape")


def _pwnc_align_down(value, alignment):
    return value - value % alignment


def _pwnc_align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _pwnc_segment_maps(image, load_bias, path, role):
    result = []
    for segment in image["segments"]:
        if not segment["memory_size"]:
            continue
        alignment = int(segment["alignment"] or 4096)
        if alignment <= 0 or alignment & (alignment - 1):
            alignment = 4096
        alignment = max(4096, alignment)
        start = _pwnc_align_down(load_bias + segment["virtual"], alignment)
        end = _pwnc_align_up(load_bias + segment["virtual"] + segment["memory_size"], alignment)
        offset = _pwnc_align_down(segment["offset"], alignment)
        flags = segment["flags"]
        permissions = ("r" if flags & 4 else "-") + ("w" if flags & 2 else "-") + ("x" if flags & 1 else "-")
        result.append(
            {
                "start": start,
                "end": end,
                "permissions": permissions,
                "offset": offset,
                "inode": None,
                "path": path,
                "private": None,
                "_pwnc_load_bias": load_bias,
                "_pwnc_link_role": role,
            }
        )
    return result


def _pwnc_image_map_indexes(maps, image, load_bias, path):
    indexes = []
    for index, item in enumerate(maps):
        if not _pwnc_paths_match(item.get("path"), path):
            continue
        for segment in image["segments"]:
            start = load_bias + segment["virtual"]
            end = start + segment["memory_size"]
            if int(item["start"]) < end and start < int(item["end"]):
                indexes.append(index)
                break
    return indexes


def _pwnc_link_map_mappings(maps):
    """Recover missing SVR4 images without parsing GDB or plugin output."""

    main_path = _pwnc_path(getattr(gdb.current_progspace(), "filename", None))
    image = _pwnc_elf_image(main_path)
    if image is None or image["dynamic"] is None:
        return []
    ptrsize = image["ptrsize"]
    endian = image["endian"]
    integer = "Q" if ptrsize == 8 else "I"
    signed = "q" if ptrsize == 8 else "i"
    dynamic = image["dynamic"]
    entry_size = ptrsize * 2
    entry_limit = min(4096, max(1, dynamic["memory_size"] // entry_size))
    candidates = []
    try:
        symbol = gdb.lookup_global_symbol("_DYNAMIC") or gdb.lookup_static_symbol("_DYNAMIC")
        if symbol is not None:
            candidates.append(int(symbol.value().address) - dynamic["virtual"])
    except BaseException:
        pass
    if image["type"] == 2:
        candidates.append(0)
    mapped_bias = _pwnc_image_load_bias(image, maps, main_path)
    if mapped_bias is not None:
        candidates.append(mapped_bias)
    debug_address = None
    load_bias = None
    for candidate in dict.fromkeys(candidates):
        try:
            dynamic_address = candidate + dynamic["virtual"]
            for index in range(entry_limit):
                raw = _pwnc_inferior_bytes(dynamic_address + index * entry_size, entry_size)
                tag = struct.unpack_from(endian + signed, raw, 0)[0]
                value = struct.unpack_from(endian + integer, raw, ptrsize)[0]
                if tag == 0:
                    break
                if tag == 21 and value:
                    debug_address = value
                    load_bias = candidate
                    break
        except BaseException:
            continue
        if debug_address:
            break
    if not debug_address:
        return []
    map_offset = _pwnc_align_up(4, ptrsize)
    state_offset = map_offset + ptrsize * 2
    loader_offset = _pwnc_align_up(state_offset + 4, ptrsize)
    debug = _pwnc_inferior_bytes(debug_address, loader_offset + ptrsize)
    link = struct.unpack_from(endian + integer, debug, map_offset)[0]
    loader_bias = struct.unpack_from(endian + integer, debug, loader_offset)[0]
    result = []
    main_indexes = _pwnc_image_map_indexes(maps, image, load_bias, main_path)
    if main_indexes:
        for index in main_indexes:
            maps[index]["_pwnc_load_bias"] = load_bias
            maps[index]["_pwnc_link_role"] = "main"
    else:
        result.extend(_pwnc_segment_maps(image, load_bias, main_path, "main"))
    visited = set()
    while link and link not in visited and len(visited) < 4096:
        visited.add(link)
        raw = _pwnc_inferior_bytes(link, ptrsize * 5)
        load_address, name_address, _dynamic_address, next_link, _previous = struct.unpack(
            endian + integer * 5, raw
        )
        target_path = _pwnc_cstring(name_address)
        local_path = _pwnc_local_module_path(target_path)
        if local_path and not _pwnc_paths_match(local_path, main_path):
            linked_image = _pwnc_elf_image(local_path)
            path_kind = _pwnc_module_kind(local_path, main_path)
            if loader_bias and load_address == loader_bias:
                role = "loader"
            elif path_kind in {"libc", "loader"}:
                role = path_kind
            else:
                role = "shared-library"
            if linked_image is not None:
                indexes = _pwnc_image_map_indexes(maps, linked_image, load_address, local_path)
                if indexes:
                    for index in indexes:
                        maps[index]["_pwnc_load_bias"] = load_address
                        maps[index]["_pwnc_link_role"] = role
                else:
                    result.extend(_pwnc_segment_maps(linked_image, load_address, local_path, role))
        link = next_link
    return result


def _pwnc_modules(maps):
    progspace = gdb.current_progspace()
    main_path = _pwnc_path(getattr(progspace, "filename", None))
    modules = []
    seen = {}
    claimed_indexes = set()

    def append_module(path, name, build_id, indexes, kind=None):
        path = _pwnc_path(path)
        identity = "build-id:" + build_id if build_id else "path:" + (path or name)
        duplicate = seen.get(identity, 0)
        seen[identity] = duplicate + 1
        if duplicate:
            identity += "#" + str(duplicate + 1)
        starts = [maps[index]["start"] for index in indexes]
        ends = [maps[index]["end"] for index in indexes]
        biases = {
            int(maps[index]["_pwnc_load_bias"])
            for index in indexes
            if maps[index].get("_pwnc_load_bias") is not None
        }
        modules.append(
            {
                "id": identity,
                "name": name,
                "path": path,
                "kind": kind or _pwnc_module_kind(path, main_path),
                "build_id": build_id,
                "base": min(starts) if starts else None,
                "end": max(ends) if ends else None,
                "load_bias": next(iter(biases)) if len(biases) == 1 else None,
                "map_indexes": indexes,
            }
        )
        claimed_indexes.update(indexes)

    for objfile in gdb.objfiles():
        if not objfile.is_valid() or objfile.owner is not None:
            continue
        path = _pwnc_local_module_path(objfile.filename) if objfile.is_file else None
        name = str(objfile.username or os.path.basename(path or "module"))
        build_id = _pwnc_build_id(objfile)
        indexes = [index for index, item in enumerate(maps) if _pwnc_paths_match(item.get("path"), path)]
        default_kind = _pwnc_module_kind(path, main_path)
        preferred = [index for index in indexes if maps[index].get("_pwnc_link_role") == default_kind]
        append_module(path, name, build_id, preferred or indexes, default_kind)

    # A provider may spell two mappings of the same artifact through different
    # target/sysroot aliases.  Attach every equivalent unclaimed mapping to the
    # existing objfile record before creating path-only module records.
    for index, item in enumerate(maps):
        if index in claimed_indexes:
            continue
        mapped_path = _pwnc_mapped_module_path(item)
        mapped_role = item.get("_pwnc_link_role")
        existing = next(
            (
                module
                for module in modules
                if mapped_role is not None
                and module.get("kind") == mapped_role
                and _pwnc_paths_match(module.get("path"), mapped_path)
            ),
            None,
        )
        if existing is None:
            continue
        existing["map_indexes"].append(index)
        existing["base"] = min(existing["base"], item["start"]) if existing["base"] is not None else item["start"]
        existing["end"] = max(existing["end"], item["end"]) if existing["end"] is not None else item["end"]
        claimed_indexes.add(index)

    # Remote targets (notably QEMU-user) can expose accurate file-backed maps
    # without loading every corresponding symbol file into ``gdb.objfiles``.
    # Keep those images in the semantic module model and fall back to stable
    # path identity.  If symbols arrive later, the normal generation refresh
    # replaces the path-only record with its build-ID-backed objfile record.
    mapped_files = {}
    for index, item in enumerate(maps):
        if index in claimed_indexes:
            continue
        path = _pwnc_mapped_module_path(item)
        if not path or path.startswith("[") or path.startswith("<"):
            continue
        path = path.removesuffix(" (deleted)")
        mapped_files.setdefault(path, []).append(index)
    for path, indexes in mapped_files.items():
        roles = {maps[index].get("_pwnc_link_role") for index in indexes}
        roles.discard(None)
        kind = next(iter(roles)) if len(roles) == 1 else None
        if kind is None and any(_pwnc_paths_match(module.get("path"), path) for module in modules):
            kind = "shared-library"
        append_module(path, os.path.basename(path) or path, None, indexes, kind)
    return modules, main_path


@request("pwncRuntimeInfo")
def pwnc_runtime_info(**_extra):
    inferior = gdb.selected_inferior()
    errors = {}
    try:
        maps = _pwnc_bata_maps()
        map_provider = "bata24" if maps is not None else None
    except BaseException as error:
        maps = None
        map_provider = None
        errors["bata24.maps"] = _pwnc_error(error)
    if maps is None:
        try:
            maps = _pwnc_proc_maps(int(inferior.pid)) if inferior.pid else []
            map_provider = "procfs"
        except BaseException as error:
            maps = []
            map_provider = "unavailable"
            errors["procfs.maps"] = _pwnc_error(error)

    maps, maps_consistent = _pwnc_validate_maps(maps)
    if not maps_consistent:
        map_provider += "-partial"
    try:
        supplemental_maps = _pwnc_link_map_mappings(maps)
        if supplemental_maps:
            maps.extend(supplemental_maps)
            map_provider += "+link-map"
    except BaseException as error:
        errors["link-map.maps"] = _pwnc_error(error)

    modules, main_path = _pwnc_modules(maps)
    try:
        architecture = inferior.architecture().name()
    except BaseException as error:
        architecture = None
        errors["architecture"] = _pwnc_error(error)
    return {
        "inferior": {
            "number": int(inferior.num),
            "pid": int(inferior.pid),
            "attached": bool(inferior.was_attached),
            "main_name": inferior.main_name,
        },
        "architecture": architecture,
        "main_path": main_path,
        "modules": modules,
        "maps": maps,
        "map_provider": map_provider,
        "bata24": _pwnc_bata_capabilities(),
        "errors": errors,
    }


def _pwnc_thread_state(thread):
    if thread.is_exited():
        return "exited"
    if thread.is_running():
        return "running"
    if thread.is_stopped():
        return "stopped"
    return "unknown"


def _pwnc_thread_json(thread):
    return {
        "id": int(thread.global_num),
        "inferior_thread": int(thread.num),
        "name": thread.name,
        "details": thread.details,
        "state": _pwnc_thread_state(thread),
        "ptid": [int(item) for item in thread.ptid],
    }


@request("pwncRuntimeThreads", expect_stopped=False)
def pwnc_runtime_threads(**_extra):
    return {"threads": [_pwnc_thread_json(thread) for thread in gdb.selected_inferior().threads()]}


def _pwnc_frame_source(frame):
    try:
        sal = frame.find_sal()
        symtab = sal.symtab
        if symtab is None:
            return None, None
        try:
            source = symtab.fullname()
        except BaseException:
            source = symtab.filename
        return source, int(sal.line) if sal.line else None
    except BaseException:
        return None, None


def _pwnc_value_json(symbol, frame, depth):
    item = {
        "name": symbol.name,
        "argument": bool(symbol.is_argument),
        "scope_depth": depth,
        "type": str(symbol.type) if symbol.type is not None else None,
    }
    try:
        value = frame.read_var(symbol)
        item["optimized_out"] = bool(value.is_optimized_out)
        if not value.is_optimized_out:
            try:
                display = value.format_string(max_elements=64, max_depth=3)
            except (TypeError, gdb.error):
                display = str(value)
            item["value"] = display[:4096]
            try:
                item["address"] = int(value.address) if value.address is not None else None
            except BaseException:
                item["address"] = None
            try:
                if value.type.strip_typedefs().code == gdb.TYPE_CODE_PTR:
                    item["pointer"] = int(value)
            except BaseException:
                pass
        item["available"] = True
    except BaseException as error:
        item["available"] = False
        item["error"] = _pwnc_error(error)
    return item


def _pwnc_frame_variables(frame):
    arguments = []
    locals_ = []
    try:
        block = frame.block()
    except BaseException:
        return arguments, locals_
    depth = 0
    while block is not None and not block.is_global and not block.is_static:
        try:
            symbols = tuple(block)
        except BaseException:
            symbols = ()
        for symbol in symbols:
            if not symbol.is_argument and not symbol.is_variable:
                continue
            item = _pwnc_value_json(symbol, frame, depth)
            (arguments if symbol.is_argument else locals_).append(item)
        block = block.superblock
        depth += 1
    return arguments, locals_


def _pwnc_registers(frame):
    values = {}
    for register in frame.architecture().registers():
        try:
            values[register.name] = int(frame.read_register(register))
        except (gdb.error, ValueError):
            pass
    # Preserve the architecture's native names while also providing the small
    # canonical set exploit scripts use across targets.  These are aliases,
    # not separately sampled values, so the register capture stays coherent.
    aliases = {
        "pc": ("pc", "rip", "eip", "r15"),
        "sp": ("sp", "rsp", "esp", "r13"),
        "fp": ("fp", "rbp", "ebp", "x29", "r11"),
        "lr": ("lr", "x30", "r14"),
    }
    for alias, candidates in aliases.items():
        for candidate in candidates:
            if candidate in values:
                values.setdefault(alias, values[candidate])
                break
    return values


def _pwnc_tls(frame):
    architecture = globals().get("current_arch")
    if architecture is not None:
        try:
            value = architecture.get_tls()
            if value is not None:
                return int(value), "bata24"
        except BaseException:
            pass
    for name in ("fs_base", "gs_base", "TPIDR_EL0", "TPIDRURO", "tpidr_el0", "tpidruro"):
        try:
            return int(frame.read_register(name)), "register:" + name
        except BaseException:
            pass
    return None, None


def _pwnc_libc_facts(frame):
    facts = {}
    tls, provider = _pwnc_tls(frame)
    facts["tls"] = tls
    facts["tls_provider"] = provider
    for name, expression in (("tcache", "(void*) tcache"), ("arena", "(void*) thread_arena"), ("errno", "errno")):
        try:
            facts[name] = int(gdb.parse_and_eval(expression))
        except BaseException:
            facts[name] = None
    canary = globals().get("CanaryCommand")
    if canary is not None:
        try:
            result = canary.gef_read_canary()
            facts["canary"] = int(result[0]) if result else None
            facts["canary_source"] = int(result[1]) if result else None
        except BaseException as error:
            facts["canary"] = None
            facts["canary_error"] = _pwnc_error(error)
    else:
        facts["canary"] = None
    return facts


@request("pwncRuntimeThread")
def pwnc_runtime_thread(
    *, threadId: int, maxFrames: int = 64, registers: bool = True,
    variables: bool = True, libcFacts: bool = False, **_extra
):
    thread = next(
        (item for item in gdb.selected_inferior().threads() if item.global_num == threadId),
        None,
    )
    if thread is None:
        raise ValueError("unknown GDB thread id")
    if maxFrames < 0 or maxFrames > 4096:
        raise ValueError("maxFrames must be between 0 and 4096")
    original_thread = gdb.selected_thread()
    try:
        original_frame = gdb.selected_frame()
    except BaseException:
        original_frame = None
    errors = {}
    try:
        thread.switch()
        try:
            frame = gdb.newest_frame()
        except BaseException as error:
            frame = None
            errors["frame"] = _pwnc_error(error)
        frames = []
        current = frame
        level = 0
        while current is not None and level < maxFrames:
            source, line = _pwnc_frame_source(current)
            arguments, locals_ = _pwnc_frame_variables(current) if variables else ([], [])
            frames.append(
                {
                    "level": level,
                    "pc": int(current.pc()),
                    "name": current.name(),
                    "type": str(current.type()),
                    "source": source,
                    "line": line,
                    "arguments": arguments,
                    "locals": locals_,
                }
            )
            current = current.older()
            level += 1
        result = _pwnc_thread_json(thread)
        result["frames"] = frames
        result["registers"] = _pwnc_registers(frame) if registers and frame is not None else {}
        result["libc"] = _pwnc_libc_facts(frame) if libcFacts and frame is not None else {}
        result["errors"] = errors
        return result
    finally:
        try:
            if original_thread is not None and original_thread.is_valid():
                original_thread.switch()
            if original_frame is not None and original_frame.is_valid():
                original_frame.select()
        except BaseException:
            pass


@request("pwncLookupType", expect_stopped=False)
def pwnc_lookup_type(*, name: str, **_extra):
    value = gdb.lookup_type(name)
    # ``_ext.py`` is sourced into this same GDB Python namespace first.  Keep
    # the structural type encoder there as the single implementation.
    return {
        "name": str(value),
        "size": int(value.sizeof or 0),
        "type": _encode_doc(value),  # noqa: F821 - installed by _ext.py
    }


def _pwnc_heap_membership(arena, chunk):
    if chunk.is_top():
        return ["top"]
    result = []
    for name, method in (
        ("tcache", "is_chunk_in_tcache"),
        ("fastbin", "is_chunk_in_fastbins"),
        ("unsorted", "is_chunk_in_unsortedbin"),
        ("smallbin", "is_chunk_in_smallbins"),
        ("largebin", "is_chunk_in_largebins"),
    ):
        try:
            if getattr(arena, method)(chunk):
                result.append(name)
        except BaseException:
            pass
    return result


def _pwnc_heap_state(chunk, membership):
    if membership:
        return membership[0]
    try:
        return "allocated" if chunk.is_real_used() else "free"
    except BaseException:
        return "unknown"


@request("pwncBataHeapChunk")
def pwnc_bata_heap_chunk(
    *, address: int, fromBase: bool = False, arenaAddress: int = 0, **_extra
):
    heap = globals().get("GlibcHeap")
    if heap is None:
        return {"available": False, "provider": None, "error": {"type": "Unavailable", "message": "bata24 GlibcHeap is not loaded"}}
    try:
        arena = heap.get_arena(arenaAddress or None)
        if arena is None:
            raise RuntimeError("bata24 could not resolve a glibc arena")
        chunk = heap.GlibcChunk(arena, int(address), from_base=bool(fromBase))
        membership = _pwnc_heap_membership(arena, chunk)
        result = {
            "available": True,
            "provider": "bata24",
            "address": int(chunk.address),
            "base": int(chunk.chunk_base_address),
            "size": int(chunk.size),
            "usable_size": int(chunk.get_usable_size()),
            "previous_size": int(chunk.get_prev_chunk_size()),
            "arena": int(arena),
            "heap_base": None if arena.heap_base is None else int(arena.heap_base),
            "state": _pwnc_heap_state(chunk, membership),
            "bins": membership,
            "flags": {
                "prev_inuse": bool(chunk.has_p_bit()),
                "mmapped": bool(chunk.has_m_bit()),
                "non_main_arena": bool(chunk.has_n_bit()),
            },
        }
        if result["state"] not in {"allocated", "top"}:
            result["fd"] = chunk.get_fwd_ptr(False)
            result["decoded_fd"] = chunk.get_fwd_ptr(True)
            result["bk"] = chunk.get_bkw_ptr()
        return result
    except BaseException as error:
        return {"available": False, "provider": "bata24", "error": _pwnc_error(error)}


@request("pwncBataHeapArenas")
def pwnc_bata_heap_arenas(**_extra):
    heap = globals().get("GlibcHeap")
    if heap is None:
        return {"available": False, "provider": None, "arenas": []}
    try:
        arenas = []
        for arena in heap.get_all_arenas():
            arenas.append(
                {
                    "address": int(arena),
                    "name": arena.name,
                    "main": bool(arena.is_main_arena),
                    "heap_base": None if arena.heap_base is None else int(arena.heap_base),
                    "top": int(arena.top),
                    "last_remainder": int(arena.last_remainder),
                    "system_mem": int(arena.system_mem),
                    "tcache": None if arena.tcache is None else int(arena.tcache),
                }
            )
        return {"available": True, "provider": "bata24", "arenas": arenas}
    except BaseException as error:
        return {"available": False, "provider": "bata24", "arenas": [], "error": _pwnc_error(error)}
