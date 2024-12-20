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

def generate_symbol(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    if bits == 64:
        fields = [
            ("name", ctypes.c_uint32),
            ("info", ctypes.c_uint8),
            ("other", ctypes.c_uint8),
            ("section_index", ctypes.c_uint16),
            ("value", addrsize),
            ("size", addrsize)
        ]
    else:
        fields = [
            ("name", ctypes.c_uint32),
            ("value", addrsize),
            ("size", ctypes.c_uint32),
            ("info", ctypes.c_uint8),
            ("other", ctypes.c_uint8),
            ("section_index", ctypes.c_uint16)
        ]

    if little_endian:
        class LE(ctypes.LittleEndianStructure):
            _fields_ = fields
        return LE
    else:
        class BE(ctypes.BigEndianStructure):
            _fields_ = fields
        return BE
    
def generate_reloc(bits: int, little_endian: bool, addend: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [
        ("offset", addrsize),
        ("info", addrsize),
    ]

    if addend:
        fields.append(("addend", addrsize, ))

    split = 8 if bits == 32 else 32
    mask = (1 << split) - 1
    parent = ctypes.LittleEndianStructure if little_endian else ctypes.BigEndianStructure
    class Reloc(parent):
        _fields_ = fields

        @property
        def type(self):
            return self.info & mask
        
        @type.setter
        def type(self, val: int):
            self.info = (self.info & ~mask) | (val & mask)

        @property
        def sym(self):
            return self.info >> split
        
        @sym.setter
        def sym(self, val: int):
            self.info = (self.info & mask) | (val << split)
    
    return Reloc

def generate_dyntag(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    parent = ctypes.LittleEndianStructure if little_endian else ctypes.BigEndianStructure
    class Dyntag(parent):
        _fields_ = [
            ("tag", addrsize),
            ("val", addrsize),
        ]
    return Dyntag

def generate_segment(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    parent = ctypes.LittleEndianStructure if little_endian else ctypes.BigEndianStructure
    fields = [
        ("type", ctypes.c_uint32)
    ]
    if bits == 64:
        fields.append(("flags", ctypes.c_uint32))
    fields.extend([
        ("offset", addrsize),
        ("virtual_address", addrsize),
        ("physical_address", addrsize),
        ("file_size", addrsize),
        ("mem_size", addrsize)
    ])
    if bits == 32:
        fields.append(("flags", ctypes.c_uint32))
    fields.append(("alignment", addrsize))

    class Segment(parent):
        _fields_ = fields
    return Segment

def generate_note(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    parent = ctypes.LittleEndianStructure if little_endian else ctypes.BigEndianStructure
    fields = [
        ("name_size", ctypes.c_uint32),
        ("description_size", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
    ]

    class Note(parent):
        _fields_ = fields
    return Note

class ELF:
    def __init__(self, raw_elf_bytes: bytes, bits: int=None, little_endian: bool=None):
        if bits is not None and bits not in ALLOWED_BITS:
            err.fatal(f"{bits} not one of {ALLOWED_BITS}")

        self.raw_elf_bytes = bytearray(raw_elf_bytes)
        self.cached_header_type = None
        self.cached_segment_type = None
        self.cached_section_type = None
        self.cached_symbol_type = None
        self.cached_reloc_type = None
        self.cached_reloca_type = None
        self.cached_dyntag_type = None
        self.cached_note_type = None

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

    def check(self):
        if bytes(self.ident.magic) != b"\x7fELF":
            raise Exception("bad elf magic")

    @property
    def Header(self):
        if not self.cached_header_type:
            self.cached_header_type = generate_header(self.bits, self.little_endian)
        return self.cached_header_type
    
    @property
    def Segment(self):
        if not self.cached_segment_type:
            self.cached_segment_type = generate_segment(self.bits, self.little_endian)
        return self.cached_segment_type

    @property
    def Section(self):
        if not self.cached_section_type:
            self.cached_section_type = generate_section(self.bits, self.little_endian)
        return self.cached_section_type

    @property
    def Symbol(self):
        if not self.cached_symbol_type:
            self.cached_symbol_type = generate_symbol(self.bits, self.little_endian)
        return self.cached_symbol_type
    
    @property
    def Reloc(self):
        if not self.cached_reloc_type:
            self.cached_reloc_type = generate_reloc(self.bits, self.little_endian, False)
        return self.cached_reloc_type

    @property
    def Reloca(self):
        if not self.cached_reloca_type:
            self.cached_reloca_type = generate_reloc(self.bits, self.little_endian, True)
        return self.cached_reloca_type
    
    @property
    def Dyntag(self):
        if not self.cached_dyntag_type:
            self.cached_dyntag_type = generate_dyntag(self.bits, self.little_endian)
        return self.cached_dyntag_type
    
    @property
    def Note(self):
        if not self.cached_note_type:
            self.cached_note_type = generate_note(self.bits, self.little_endian)
        return self.cached_note_type

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
    def segments(self) -> list["ELF.Segment"]:
        if not self.cached_segments:
            self.cached_segments = []
            offset = self.header.segment_offset
            for _ in range(self.header.number_of_segments):
                segment = self.Segment.from_buffer(self.raw_elf_bytes, offset)
                offset += ctypes.sizeof(self.Segment)
                self.cached_segments.append(segment)
        return self.cached_segments

    @property
    def sections(self) -> list["ELF.Section"]:
        if not self.cached_sections:
            self.cached_sections = []
            offset = self.header.section_offset
            for _ in range(self.header.number_of_sections):
                section = self.Section.from_buffer(self.raw_elf_bytes, offset)
                offset += ctypes.sizeof(self.Section)
                self.cached_sections.append(section)
        return self.cached_sections
    
    @property
    def buildid(self):
        notes = self.notes(self.section_content(self.section_from_name(b".note.gnu.build-id")))
        if len(notes) == 0:
            err.fatal("unable to parse any notes from .note.gnu.build-id")
        note = notes[0]
        if note.type != 3:
            err.fatal(f"note type is not NT_GNU_BUILD_ID (3), was {note.type}")
        if note.name != b"GNU\x00":
            err.fatal(f"note name is not b'GNU\x00', was {note.name}")
        return note.description

    def section_name(self, section: "ELF.Section"):
        section_name_table = self.sections[self.header.section_name_table_index]
        contents = self.section_content(section_name_table)
        offset = section.name
        while contents[offset] != 0:
            offset += 1
        return contents[section.name:offset]

    def section_content(self, section: "ELF.Section", element = None):
        content = memoryview(self.raw_elf_bytes)[section.offset:section.offset+section.size]
        if element is None:
            return content
        else:
            elements = []
            for i in range(0, len(content), ctypes.sizeof(element)):
                elements.append(element.from_buffer(content, i))
            return elements
    
    def notes(self, content: bytes):
        offset = 0
        length = len(content)
        notes = []
        while offset < length:
            note = self.Note.from_buffer_copy(content, offset)
            offset += ctypes.sizeof(self.Note)
            name = content[offset:offset+note.name_size].tobytes()
            offset = (offset + note.name_size) + 3 & ~3
            description = content[offset:offset+note.description_size].tobytes()
            offset += note.description_size

            note.name = name
            note.description = description
            notes.append(note)
        
        return notes

    def section_from_name(self, name: bytes):
        for section in self.sections:
            if self.section_name(section) == name:
                return section
            
    def cstr(self, offset: int, maxlen = None):
        start = offset
        if maxlen is None:
            maxlen = len(self.raw_elf_bytes)
        else:
            maxlen = min(offset + maxlen, len(self.raw_elf_bytes))

        while offset < maxlen and self.raw_elf_bytes[offset] != 0:
            offset += 1
        return memoryview(self.raw_elf_bytes)[start:offset]
