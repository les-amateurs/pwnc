from .util import *


class Type:
    NULL = 0
    PROGBITS = 1
    SYMTAB = 2
    STRTAB = 3
    RELA = 4
    HASH = 5
    DYNAMIC = 6
    NOTE = 7
    NOBITS = 8
    REL = 9
    SHLIB = 10
    DYNSYM = 11
    INIT_ARRAY = 14
    FINI_ARRAY = 15
    PREINIT_ARRAY = 16
    GROUP = 17
    SYMTAB_SHNDX = 18
    LOOS = 0x60000000


class Flags:
    WRITE = 0x01
    ALLOC = 0x02
    EXECINSTR = 0x04
    MERGE = 0x10
    STRINGS = 0x20
    INFO_LINK = 0x40
    LINK_ORDER = 0x80
    OS_NONCONFORMING = 0x100
    GROUP = 0x200
    TLS = 0x400


def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [
        ("name", u32),
        ("type", u32),
        ("flags", addrsize),
        ("address", addrsize),
        ("offset", addrsize),
        ("size", addrsize),
        ("link", u32),
        ("info", u32),
        ("alignment", addrsize),
        ("entrysize", addrsize),
    ]

    class Section(structure_parent(little_endian)):
        _fields_ = fields

        Type = Type
        Flags = Flags

    return Section


class Section:
    name = u32
    type = u32
    flags = addr
    address = addr
    offset = addr
    size = addr
    link = u32
    info = u32
    alignment = addr
    entrysize = addr
