import ctypes
from .. import err
from .types import header, section, segment, symbol, reloc, dyntag, note

"""
different loaders might handler overlapping LOAD segments differently.
"""
class MappingStyle:
    LinuxKernel = 0
    Glibc = 1

"""
minimal elf parsing that does basically zero validation
"""

ALLOWED_BITS = [32, 64]
# TODO: configurable page size
PAGE_SIZE = 0x1000

def round_down_to_page(addr: int):
    return addr & ~(PAGE_SIZE - 1)

def round_up_to_page(addr: int):
    return (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)

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
            self.cached_header_type = header.generate(self.bits, self.little_endian)
        return self.cached_header_type
    
    @property
    def Segment(self):
        if not self.cached_segment_type:
            self.cached_segment_type = segment.generate(self.bits, self.little_endian)
        return self.cached_segment_type

    @property
    def Section(self):
        if not self.cached_section_type:
            self.cached_section_type = section.generate(self.bits, self.little_endian)
        return self.cached_section_type

    @property
    def Symbol(self):
        if not self.cached_symbol_type:
            self.cached_symbol_type = symbol.generate(self.bits, self.little_endian)
        return self.cached_symbol_type
    
    @property
    def Reloc(self):
        if not self.cached_reloc_type:
            self.cached_reloc_type = reloc.generate(self.bits, self.little_endian, False)
        return self.cached_reloc_type

    @property
    def Reloca(self):
        if not self.cached_reloca_type:
            self.cached_reloca_type = reloc.generate(self.bits, self.little_endian, True)
        return self.cached_reloca_type
    
    @property
    def Dyntag(self):
        if not self.cached_dyntag_type:
            self.cached_dyntag_type = dyntag.generate(self.bits, self.little_endian)
        return self.cached_dyntag_type
    
    @property
    def Note(self):
        if not self.cached_note_type:
            self.cached_note_type = note.generate(self.bits, self.little_endian)
        return self.cached_note_type

    @property
    def ident(self):
        if not self.cached_ident:
            self.cached_ident = header.IdentStructure.from_buffer(self.raw_elf_bytes)
        return self.cached_ident

    @property
    def bits(self):
        if not self.cached_bits:
            """ guess bits from ident """
            match self.ident.bits:
                case 1: self.cached_bits = 32
                case 2: self.cached_bits = 64
                case _: err.fatal(f"failed to guess bit width ({self.ident.bits})")
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
    def header(self) -> header.Header:
        if not self.cached_header:
            self.cached_header = self.Header.from_buffer(self.raw_elf_bytes)
        return self.cached_header
    
    @property
    def segments(self) -> list[segment.Segment]:
        if not self.cached_segments:
            self.cached_segments = []
            offset = self.header.segment_offset
            for _ in range(self.header.number_of_segments):
                segment = self.Segment.from_buffer(self.raw_elf_bytes, offset)
                offset += ctypes.sizeof(self.Segment)
                self.cached_segments.append(segment)
        return self.cached_segments

    @property
    def sections(self) -> list[section.Section]:
        if not self.cached_sections:
            self.cached_sections = []
            offset = self.header.section_offset
            for _ in range(self.header.number_of_sections):
                section = self.Section.from_buffer(self.raw_elf_bytes, offset)
                offset += ctypes.sizeof(self.Section)
                self.cached_sections.append(section)
        return self.cached_sections
    
    def virtual_memory_segments(self, mapping_style: MappingStyle, combine: bool):
        load = self.segments
        load = filter(lambda segment: segment.type == self.Segment.Type.LOAD, load)

        segments: list[tuple[int, bytes]] = []
        for segment in load:
            match mapping_style:
                case MappingStyle.LinuxKernel:
                    start = round_down_to_page(segment.virtual_address)
                    end = round_up_to_page(segment.virtual_address + segment.mem_size)
                    offset = round_down_to_page(segment.offset)

                    content = self.raw_elf_bytes[offset:segment.offset + segment.file_size]
                    content = content.ljust(end - start, b"\0")

                case MappingStyle.Glibc:
                    err.fatal("not implemented")

        return segments
    
    def virtual_memory(self, addr: int, mapping_style: MappingStyle = MappingStyle.LinuxKernel):
        pass

    @property
    def buildid(self, section: "ELF.Section" = None):
        buildid_section = section or self.section_from_name(b".note.gnu.build-id")
        if buildid_section is None:
            err.fatal("failed to find .note.gnu.build-id section")
        notes = self.notes(self.section_content(buildid_section))
        if len(notes) == 0:
            err.fatal("unable to parse any notes from .note.gnu.build-id")
        note = notes[0]
        if note.type != 3:
            err.fatal(f"note type is not NT_GNU_BUILD_ID (3), was {note.type}")
        if note.name != b"GNU\x00":
            err.fatal(f"note name is not b'GNU\\x00', was {note.name}")
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
    
    def notes(self, content: bytes) -> list[note.Note]:
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

    def write(self, file: str):
        with open(file, "wb+") as fp:
            fp.write(self.raw_elf_bytes)