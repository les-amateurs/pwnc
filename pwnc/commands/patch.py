from ..util import *
from .. import err
from ..minelf import ELF
from ctypes import sizeof

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
        err(f".dyanmic section not present")

    offset = 0
    contents = elf.section_content(dynamic)
    dyntags = []
    while offset < dynamic.size:
        dyntag = elf.Dyntag.from_buffer_copy(contents, offset)
        dyntags.append(dyntag)
        if dyntag.tag == 0:
            break
        offset += sizeof(elf.Dyntag)

    used = offset + 0x10
    size = dynamic.size & ~0x0f
    extra = (size - used) // sizeof(elf.Dyntag)

    err.warn(f"used {offset:#x} out of {dynamic.size:#x} ({offset/dynamic.size*100:.0f}%) of DYNAMIC")
    err.warn(f"space for {extra} extra dynamic tags")

    if args.rpath:
        rpath_bytes = bytes(args.rpath, "utf8")
        if extra == 0:
            err(f"not enough space for rpath in dynamic table")
        if len(rpath_bytes) >= elf.Dyntag.val.size:
            err(f"not enough space for rpath str (max {elf.Dyntag.val.size} bytes)")
        strtab = next(filter(lambda dt: dt.tag == 5, dyntags))
        address = next(filter(lambda segment: segment.type == 2, elf.segments)).virtual_address
        rpath_offset = offset + sizeof(elf.Dyntag) + elf.Dyntag.val.offset
        rpath = elf.Dyntag(tag=15, val=address + rpath_offset - strtab.val)
        contents[offset:offset+sizeof(elf.Dyntag)] = bytes(rpath)
        contents[rpath_offset:rpath_offset+len(rpath_bytes)] = rpath_bytes
        offset += sizeof(elf.Dyntag)
        err.warn(f"rpath     set to {args.rpath}")

    if args.interp:
        interp = next(filter(lambda segment: segment.type == 3, elf.segments))
        new_interp_path = bytes(args.interp, encoding="utf8")
        if len(new_interp_path) < interp.file_size:
            elf.raw_elf_bytes[interp.offset:interp.offset+interp.file_size] = new_interp_path.ljust(interp.file_size, b"\x00")
            err.warn(f"interp    set to {args.interp}")
        else:
            err(f"new interp path is too long")

    with open(outfile, "wb+") as fp:
        fp.write(elf.raw_elf_bytes)