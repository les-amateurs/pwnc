from ..util import *
from ..minelf import ELF
from ..minelf.types import dyntag
from ctypes import sizeof


"""
"Mostly" useless
(eg. technically it can be used for exploitation in some contexts,
 but those situations are fairly rare.)
    - DEBUG
"""
USELESS = [
    dyntag.Type.DEBUG
]


def command(args):
    try:
        raw_elf_bytes = open(args.file, "rb").read()
    except Exception as e:
        err.fatal(f"failed to read file: {e}")

    little_endian = None
    match args.endian:
        case "big":
            little_endian = False
        case _:
            little_endian = True
    elf = ELF(raw_elf_bytes, args.bits, little_endian)
    outfile = args.outfile or args.file

    dynamic = elf.section_from_name(b".dynamic")
    if dynamic is None:
        err(".dyanmic section not present")

    offset = 0
    contents = elf.section_content(dynamic)
    dyntags = []
    while offset < dynamic.size:
        dyntag = elf.Dyntag.from_buffer_copy(contents, offset)
        dyntags.append(dyntag)
        if dyntag.tag == 0:
            break
        offset += sizeof(elf.Dyntag)

    used = offset + sizeof(elf.Dyntag)
    """
    Round down since any extra space cannot be interpreted as a full dyntag.
    Although if the extra space is less than the necessary size for a full dyntag
    but is still enough space for the dyntag tag field, it could possible serve
    as the terminating NULL dyntag depending on the linker implementation.
    """
    size = dynamic.size - (dynamic.size % sizeof(elf.Dyntag))
    extra = (size - used) // sizeof(elf.Dyntag)

    err.warn(f"used {offset:#x} out of {dynamic.size:#x} ({offset / dynamic.size * 100:.0f}%) of DYNAMIC")
    err.warn(f"space for {extra} extra dynamic tags")

    if args.rpath:
        rpath_bytes = bytes(args.rpath, "utf8")
        if extra == 0:
            err.warn("not enough space for rpath in dynamic table")
            err.warn("attempting to replace useless dynamic entries instead")
            
            for i, dyntag in enumerate(dyntags):
                if dyntag.tag in USELESS:
                    offset = i * sizeof(elf.Dyntag)
                    break
            else:
                err.fatal("did not find any useless dynamic entries")

        if len(rpath_bytes) >= elf.Dyntag.val.size + sizeof(elf.Dyntag) * max(0, extra - 1):
            err.fatal(f"not enough space for rpath str (max {elf.Dyntag.val.size} bytes)")
        
        for dyntag in dyntags:
            if dyntag.tag == elf.Dyntag.Type.STRTAB:
                strtab = dyntag
                break
        else:
            err.fatal("failed to find STRTAB in DYNAMIC segment")
        
        for segment in elf.segments:
            if segment.type == elf.Segment.Type.DYNAMIC:
                address = segment.virtual_address
                break
        else:
            err.fatal("failed to get DYNAMIC segment base address")

        rpath_offset = offset + sizeof(elf.Dyntag) + elf.Dyntag.val.offset
        rpath_dyntag = elf.Dyntag(tag=elf.Dyntag.Type.RPATH, val=address + rpath_offset - strtab.val)
        contents[offset : offset + sizeof(elf.Dyntag)] = bytes(rpath_dyntag)
        contents[rpath_offset : rpath_offset + len(rpath_bytes)] = rpath_bytes
        err.warn(f"rpath     set to {args.rpath}")

    if args.interp:
        for segment in elf.segments:
            if segment.type == elf.Segment.Type.INTERP:
                interp = segment
                break
        else:
            err.fatal("failed to find existing INTERP segment")
            
        new_interp_path = bytes(args.interp, encoding="utf8")
        if len(new_interp_path) < interp.file_size:
            elf.raw_elf_bytes[interp.offset : interp.offset + interp.file_size] = new_interp_path.ljust(
                interp.file_size, b"\x00"
            )
            err.warn(f"interp    set to {args.interp}")
        else:
            err.fatal("new interp path is too long")

    with open(outfile, "wb+") as fp:
        fp.write(elf.raw_elf_bytes)
    outfile.chmod(0o755)