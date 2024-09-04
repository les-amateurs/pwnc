from ...util import *
from ... import err
import shutil
from tempfile import NamedTemporaryFile
from ... import minelf

def parse_modinfo(elf: minelf.ELF):
    for section in elf.sections:
        if elf.section_name(section).tobytes() == b".modinfo":
            modinfo = section
            break
    else:
        err.fatal("could not find .modinfo section")

    raw_modinfo_bytes = elf.section_content(section)
    info = dict()
    for entry in raw_modinfo_bytes.tobytes().strip(b"\x00").split(b"\x00"):
        if b"=" not in entry:
            err.warn(f"malformed modinfo entry: {entry}, does not contain `=`")
            continue

        key, value = entry.decode().split("=", maxsplit=1)
        if key in info:
            err.warn(f"modinfo key {key} already exists, overwriting")
        info[key] = value
    return section, raw_modinfo_bytes, info

def command(args: Args):
    with open(args.file, "rb") as fp:
        raw_elf_bytes = fp.read()

    elf = minelf.ELF(raw_elf_bytes)
    section, raw_modinfo_bytes, info = parse_modinfo(elf)
    for key, value in info.items():
        print(f"{key} = {value}")

    if args.set:
        for new_key, new_value in args.set:
            info[new_key] = new_value

        new_modinfo_bytes = b""
        for key, value in info.items():
            new_modinfo_bytes += f"{key}={value}".encode() + b"\x00"

        """ TODO: slight optimization, detect if .modinfo is already at the end of the file
            and extend that instead of appending a whole new section.
        """
        if len(new_modinfo_bytes) > section.size:
            section.size = len(new_modinfo_bytes)
            section.offset = len(elf.raw_elf_bytes)

            elf.raw_elf_bytes = bytearray(elf.raw_elf_bytes) + new_modinfo_bytes
            elf.invalidate()
        else:
            new_modinfo_bytes = new_modinfo_bytes.ljust(len(raw_modinfo_bytes), b"\x00")
            raw_modinfo_bytes[:] = new_modinfo_bytes

    output = args.o or args.file
    if output == args.file:
        backup(output)
    with open(output, "wb+") as fp:
        fp.write(elf.raw_elf_bytes)
