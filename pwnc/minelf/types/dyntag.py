from .util import *


class Type:
    NULL = 0x00
    NEEDED = 0x01
    PLTRELSZ = 0x02
    PLTGOT = 0x03
    HASH = 0x04
    STRTAB = 0x05
    SYMTAB = 0x06
    RELA = 0x07
    RELASZ = 0x08
    RELAENT = 0x09
    STRSZ = 0x0a
    SYMENT = 0x0b
    INIT = 0x0c
    FINI = 0x0d
    SONAME = 0x0e
    RPATH = 0x0f
    SYMBOLIC = 0x10
    REL = 0x11
    RELSZ = 0x12
    RELENT = 0x13
    PLTREL = 0x14
    DEBUG = 0x15
    TEXTREL = 0x16
    JMPREL = 0x17
    BIND_NOW = 0x18
    INIT_ARRAY = 0x19
    FINI_ARRAY = 0x1a
    INIT_ARRAYSZ = 0x1b
    FINI_ARRAYSZ = 0x1c
    RUNPATH = 0x1d
    FLAGS = 0x1e
    ENCODING = 0x1f
    PREINIT_ARRAY = 0x20
    PREINIT_ARRAYSZ = 0x28


def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)

    class Dyntag(structure_parent(little_endian)):
        _fields_ = [
            ("tag", addrsize),
            ("val", addrsize),
        ]

        Type = Type

    return Dyntag


class Dyntag:
    tag: addr
    val: addr
