from ...util import *
from ...minelf import ELF

DISCARD = [
    ".interp",
    ".comment*",
    ".note.*",
    ".gnu.*",
    ".gnu_*",
    ".eh_frame*",
    ".rela.* ",
    ".dynsym",
    ".dynsym.*",
    ".dynstr",
    ".dynstr.*",
    ".symtab",
    ".symtab.*",
    ".strtab",
    ".strtab.*",
    ".shstrtab.*",
    ".dynamic",
    ".debug_*",
    ".ARM.*",
    ".hash",
    ".hash.*",
]

gcc_linker_script = (Path(__file__).parent / "gcc-linker.ld").absolute()
zig_linker_script = (Path(__file__).parent / "zig-linker.ld").absolute()

def command(args: Args):
    flags = "-fno-stack-protector -fomit-frame-pointer -Wl,-e,main -ffunction-sections -fdata-sections -Wl,--gc-sections -static"
    pie = "-pie" if args.pie else "-no-pie"
    files = " ".join(["{!r}".format(file) for file in args.files])
    output = "{!r}".format(str(args.output))
    target = "-target {!r}".format(args.target) if args.target else ""

    err.info(f"flags   = {flags}")
    err.info(f"pie     = {args.pie}")

    match args.backend:
        case "gcc":
            if args.target:
                err.warn(f"target {args.target} ignored")

            run(f"gcc       {files} -Wl,-T,{gcc_linker_script} {pie} {flags} -o {output} -nostdlib -nostartfiles -Os")
        case "zig":
            run(f"zig cc    {files} -Wl,-T,{zig_linker_script} {pie} {flags} -o {output} {target} -nostartfiles -Os")

            with open(args.output, "rb") as fp:
                raw_elf_bytes = fp.read()
            elf = ELF(raw_elf_bytes)
            # TODO: detect host architecture
            elf.header.machine = elf.Header.Machine.AMD64
            elf.write(args.output)

            discards = " ".join(["-R {!r}".format(section) for section in DISCARD])
            run(f"objcopy {discards} -S -O binary {output}")
        case _:
            err.fatal(f"backend {args.backend} currently unsupported")