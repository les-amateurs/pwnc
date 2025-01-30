from .util import *

class Machine:
    NONE = 0x00
    SPARC = 0x02
    X86 = 0x03
    M68K = 0x04
    M88K = 0x05
    MIPS = 0x08
    ARM = 0x28
    IA64 = 0x32
    AMD64 = 0x3e
    ARM64 = 0xb7
    RISCV = 0xf3

class Type:
    NONE = 0x00
    REL = 0x01
    EXEC = 0x02
    DYN = 0x03
    CORE = 0x04
    LOOS = 0xFE00
    HIOS = 0xFEFF
    LOPROC = 0xFF00
    HIPROC = 0xFFFF

class IdentStructure(ctypes.Structure):
    class Magic(ctypes.Union):
        _fields_ = [
            ("raw", u32),
            ("bytes", 4 * u8),
        ]

    _fields_ = [
        ("magic", Magic),
        ("bits", u8),
        ("endianness", u8),
        ("version", u8),
        ("osabi", u8),
        ("abiversion", u8),
        ("padding", 7 * u8),
    ]

def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [
        ("ident", IdentStructure),
        ("type", u16),
        ("machine", u16),
        ("version", u32),
        ("entrypoint", addrsize),
        ("segment_offset", addrsize),
        ("section_offset", addrsize),
        ("flags", u32),
        ("sizeof_header", u16),
        ("sizeof_segment", u16),
        ("number_of_segments", u16),
        ("sizeof_section", u16),
        ("number_of_sections", u16),
        ("section_name_table_index", u16)
    ]

    class Header(structure_parent(little_endian)):
        _fields_ = fields

        Machine = Machine
        Type = Type
    return Header

class Magic:
    raw: u32
    bytes: u8

class Ident:
    magic: Magic
    bits: u8
    endianness: u8
    version: u8
    osabi: u8
    abiversion: u8
    padding: u8

class Header:
    ident: Ident
    type: u16
    machine: u16
    version: u32
    entrypoint: addr
    segment_offset: addr
    section_offset: addr
    flags: u32
    sizeof_header: u16
    sizeof_segment: u16
    number_of_segments: u16
    sizeof_section: u16
    number_of_sections: u16
    section_name_table_index: u16