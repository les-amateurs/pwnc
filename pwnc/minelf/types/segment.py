from .util import *


class Type:
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    SHLIB = 5
    PHDR = 6
    TLS = 7
    LOOS = 0x60000000
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000
    HIPROC = 0x7FFFFFFF


class Flags:
    X = 0x01
    W = 0x02
    R = 0x04


def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [("type", u32)]
    if bits == 64:
        fields.append(("flags", u32))
    fields.extend(
        [
            ("offset", addrsize),
            ("virtual_address", addrsize),
            ("physical_address", addrsize),
            ("file_size", addrsize),
            ("mem_size", addrsize),
        ]
    )
    if bits == 32:
        fields.append(("flags", u32))
    fields.append(("alignment", addrsize))

    class Segment(structure_parent(little_endian)):
        _fields_ = fields

        Type = Type
        Flags = Flags

    return Segment


class Segment:
    type: u32
    flags: u32
    offset: addr
    virtual_address: addr
    physical_address: addr
    file_size: addr
    mem_size: addr
    alignment: addr
