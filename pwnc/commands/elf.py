from ..util import *
from ..minelf import *
from ..minelf.types.header import Machine

MACHINES = list(filter(lambda field: not field.startswith("_"), dir(Machine)))

def info_from_machine(machine: int):
    match machine:
        case Machine.AMD64:
            return (True, 64)
        case Machine.X86:
            return (True, 32)
        case Machine.ARM64:
            return (True, 64)
        case Machine.ARM:
            return (True, 32)
    return None, None

def command(args: Args):
    machine: str = args.machine.upper()
    if machine not in MACHINES:
        err.warn(f"machine {args.machine} not supported")
        err.info(f"supported machines: {MACHINES}")
        err.info(f"interpreting raw value")
        try:
            machine = int(args.machine, 0)
            err.info(f"interpreted machine as raw value: {machine}")
        except ValueError:
            machine = None
        if machine is None:
            err.fatal(f"failed to interpret machine as raw value")
    else:
        machine = getattr(Machine, machine)

    bits = args.bits
    little_endian = args.endian == "little" if args.endian is not None else None
    guessed_little_endian, guessed_bits = info_from_machine(machine)

    if bits is None:
        err.info("bits not specified, guessing")
        bits = guessed_bits
        if bits is None:
            err.fatal(f"unable to guess bits for {machine}\nspecify bits with -b")
    err.info(f"bits = {bits}")

    if little_endian is None:
        err.info("endianness not specified, guessing")
        little_endian = guessed_little_endian
        if guessed_little_endian is None:
            err.fatal(f"unable to guess endianness for {machine}\nspecify endianness with -e")
    human = ["big", "little"][little_endian]
    err.info(f"endianness = {human}")

    payload = open(args.file, "rb").read()
    elf = ELF(b"", bits=bits, little_endian=little_endian)

    # TODO: custom base load address
    # TODO: custom page size
    base_address = 0x1000000
    segment_offset = ctypes.sizeof(elf.Header) + ctypes.sizeof(elf.Segment)
    segment_offset = segment_offset + 0xfff & ~0xfff
    load_address = base_address
    total = segment_offset + len(payload)
    elf.raw_elf_bytes += b"\x00" * total

    elf.header.ident.magic = header.IdentStructure.Magic.from_buffer_copy(b"\x7fELF")
    elf.header.ident.bits = 1 if bits == 32 else 2
    elf.header.ident.endianness = 1 if little_endian else 2
    elf.header.ident.version = 1
    elf.header.type = 2
    elf.header.machine = machine
    elf.header.entrypoint = load_address
    elf.header.version = 1
    elf.header.segment_offset = ctypes.sizeof(elf.Segment)
    elf.header.sizeof_segment = ctypes.sizeof(elf.Segment)
    elf.header.sizeof_header = ctypes.sizeof(elf.Header)
    elf.header.number_of_segments = 1

    elf.segments[0].type = elf.Segment.Type.LOAD
    elf.segments[0].flags = elf.Segment.Flags.R | elf.Segment.Flags.W | elf.Segment.Flags.X
    elf.segments[0].offset = segment_offset
    elf.segments[0].virtual_address = load_address
    elf.segments[0].physical_address = load_address
    elf.segments[0].file_size = len(payload)
    elf.segments[0].mem_size = len(payload)
    elf.segments[0].alignment = 0

    elf.raw_elf_bytes[elf.segments[0].offset:elf.segments[0].offset+len(payload)] = payload

    elf.write(f"{args.file}.elf")