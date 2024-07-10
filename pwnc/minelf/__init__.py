from .. import err
import ctypes

"""
minimal elf parsing that does basically zero validation
"""

ALLOWED_BITS = [32, 64]

def addrsize_from_bits(bits: int):
    match bits:
        case 32: return ctypes.c_uint32
        case 64: return ctypes.c_uint64
        case _: err.fatal(f"bad bit length: {bits}")

class Ident(ctypes.Structure):
    _fields_ = [
        ("magic", 4 * ctypes.c_uint8),
        ("bits", ctypes.c_uint8),
        ("endianness", ctypes.c_uint8),
        ("version", ctypes.c_uint8),
        ("osabi", ctypes.c_uint8),
        ("abiversion", ctypes.c_uint8),
        ("padding", 7 * ctypes.c_uint8),
    ]

def generate_header(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [
        ("ident", Ident),
        ("type", ctypes.c_uint16),
        ("machine", ctypes.c_uint16),
        ("version", ctypes.c_uint32),
        ("entrypoint", addrsize),
        ("segment_offset", addrsize),
        ("section_offset", addrsize),
        ("flags", ctypes.c_uint32),
        ("sizeof_header", ctypes.c_uint16),
        ("sizeof_segment", ctypes.c_uint16),
        ("number_of_segments", ctypes.c_uint16),
        ("sizeof_section", ctypes.c_uint16),
        ("number_of_sections", ctypes.c_uint16),
        ("section_name_table_index", ctypes.c_uint16)
    ]

    if little_endian:
        class LE(ctypes.LittleEndianStructure):
            _fields_ = fields
        return LE
    else:
        class BE(ctypes.BigEndianStructure):
            _fields_ = fields
        return BE

def generate_section(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [
        ("name", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("flags", addrsize),
        ("address", addrsize),
        ("offset", addrsize),
        ("size", addrsize),
        ("link", ctypes.c_uint32),
        ("info", ctypes.c_uint32),
        ("alignment", addrsize),
        ("entrysize", addrsize)
    ]

    if little_endian:
        class LE(ctypes.LittleEndianStructure):
            _fields_ = fields
        return LE
    else:
        class BE(ctypes.BigEndianStructure):
            _fields_ = fields
        return BE

class ELF:
    def __init__(self, raw_elf_bytes: bytes, bits: int=None, little_endian: bool=None):
        if bits is not None and bits not in ALLOWED_BITS:
            err.fatal(f"{bits} not one of {ALLOWED_BITS}")

        self.raw_elf_bytes = bytearray(raw_elf_bytes)
        self.cached_header_type = None
        self.cached_section_type = None

        self.cached_ident = None
        self.cached_header = None
        self.cached_bits = bits
        self.cached_little_endian = little_endian
        self.cached_sections = None
        self.cached_segments = None

    def invalidate(self):
        for prop in self.__dict__:
            if prop.startswith("cached_"):
                setattr(self, prop, None)

    @property
    def Header(self):
        if not self.cached_header_type:
            self.cached_header_type = generate_header(self.bits, self.little_endian)
        return self.cached_header_type
    
    @property
    def Section(self):
        if not self.cached_section_type:
            self.cached_section_type = generate_section(self.bits, self.little_endian)
        return self.cached_section_type

    @property
    def ident(self):
        if not self.cached_ident:
            self.cached_ident = Ident.from_buffer(self.raw_elf_bytes)
        return self.cached_ident
    
    @property
    def bits(self):
        if not self.cached_bits:
            """ guess bits from ident """
            match self.ident.bits:
                case 1: self.cached_bits = 32
                case 2: self.cached_bits = 64
                case _: err.fatal("failed to guess bit width")
        return self.cached_bits
    
    @property
    def little_endian(self):
        if not self.cached_little_endian:
            """ guess little endian from ident """
            match self.ident.endianness:
                case 1: self.cached_little_endian = True
                case 2: self.cached_little_endian = False
                case _: err.fatal("failed to guess endianness")
        return self.cached_little_endian
    
    @property
    def header(self):
        if not self.cached_header:
            self.cached_header = self.Header.from_buffer(self.raw_elf_bytes)
        return self.cached_header
    
    @property
    def sections(self):
        if not self.cached_sections:
            self.cached_sections = []
            offset = self.header.section_offset
            for _ in range(self.header.number_of_sections):
                section = self.Section.from_buffer(self.raw_elf_bytes, offset)
                offset += ctypes.sizeof(self.Section)
                self.cached_sections.append(section)
        return self.cached_sections

    def section_name(self, section: "ELF.Section"):
        section_name_table = self.sections[self.header.section_name_table_index]
        contents = self.section_content(section_name_table)
        offset = section.name
        while contents[offset] != 0:
            offset += 1
        return contents[section.name:offset]
    
    def section_content(self, section: "ELF.Section"):
        return memoryview(self.raw_elf_bytes)[section.offset:section.offset+section.size]