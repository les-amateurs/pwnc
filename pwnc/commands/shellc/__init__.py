from ...util import *
from ...minelf import ELF

DISCARD = [
    ".interp",
    ".comment*",
    ".note.*",
    ".gnu.*", ".gnu_*",
    ".eh_frame*",
    ".rela.* ",
    ".dynsym", ".dynsym.*",
    ".dynstr", ".dynstr.*",
    ".symtab", ".symtab.*",
    ".strtab", ".strtab.*",
    ".shstrtab.*",
    ".dynamic",
    ".debug_*",
    ".ARM.*",
    ".hash", ".hash.*",
]
KEEP = [ ".entry", ".text", ".rodata", ".data", ".bss" ]

gcc_linker_script = (Path(__file__).parent / "gcc-linker.ld").absolute()
zig_linker_script = (Path(__file__).parent / "zig-linker.ld").absolute()

def command(args: Args, extra: list[str]):
    if len(extra) != 0 and extra[0] == "--":
        extra = extra[1:]

    flags = "-fno-stack-protector -fomit-frame-pointer -Wl,-e,main -ffunction-sections -fdata-sections -Wl,--gc-sections -flto -masm=intel -static"
    pie = "-pie" if args.pie else "-no-pie"
    files = " ".join(["{!r}".format(file) for file in args.files])
    output = "{!r}".format(str(args.output))
    target = "-target {!r}".format(args.target) if args.target else ""
    user = " ".join(["{!r}".format(arg) for arg in extra])

    err.info(f"files = {files}")
    err.info(f"pie   = {args.pie}")
    err.info(f"flags = {flags}")
    err.info(f"user  = {user}")

    match args.backend:
        case "gcc":
            extra = f"-nostdlib -nostartfiles -Os"
        case "zig":
            extra = f"{target} -nostartfiles -Os"
        case _:
            err.fatal(f"backend {args.backend} currently unsupported")

    err.info(f"extra = {extra}")

    match args.backend:
        case "gcc":
            if args.target:
                err.warn(f"target {args.target} ignored")
            run(f"gcc       {files} -Wl,-T,{gcc_linker_script} {pie} {flags} -o {output} {extra} {user}")
        case "zig":
            run(f"zig cc    {files} -Wl,-T,{zig_linker_script} {pie} {flags} -o {output} {extra} {user}")

            with open(args.output, "rb") as fp:
                raw_elf_bytes = fp.read()
            elf = ELF(raw_elf_bytes)

            payload = b""
            base = None
            for section in sorted(elf.sections, key = lambda section: section.address):
                if elf.section_name(section).tobytes().decode() in KEEP:
                    if base is None:
                        base = section.address

                    offset = section.address - base
                    payload = payload.ljust(offset, b"\x00")
                    payload += elf.section_content(section)

            with open(args.output, "wb") as fp:
                fp.write(payload)