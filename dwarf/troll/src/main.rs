#![feature(generic_const_exprs)]

use gimli::{
    self, DebugTypeSignature, DebuggingInformationEntry, Encoding, Format, Register, RunTimeEndian,
    Unit, UnitOffset, UnitRef, UnitType, read,
    write::{
        self, Address, AttributeValue, Dwarf, DwarfUnit, EndianVec, Expression, LineString,
        Sections, UnitEntryId,
    },
};
use goblin::{
    elf::header::EM_AARCH64,
    elf64::{
        header::{
            EI_ABIVERSION, EI_CLASS, EI_DATA, EI_OSABI, EI_VERSION, ELFCLASS64, ELFDATA2LSB,
            ELFMAG, ET_EXEC, SIZEOF_EHDR, SIZEOF_IDENT, header64::Header,
        },
        program_header::SIZEOF_PHDR,
        section_header::{
            SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NULL, SHT_PROGBITS, SHT_STRTAB, SHT_SYMTAB,
            SIZEOF_SHDR, SectionHeader,
        },
        sym,
    },
};
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::{borrow::Cow, fmt::Debug};

enum Content {
    Backed(Vec<u8>),
    Zeroed(usize),
}

impl Default for Content {
    fn default() -> Self {
        Self::Backed(Vec::new())
    }
}

impl Content {
    fn backed_len(self: &Self) -> usize {
        match self {
            Self::Backed(v) => v.len(),
            Self::Zeroed(v) => *v,
        }
    }
}

#[derive(Default)]
struct Section {
    name: String,
    kind: u32,
    flags: u64,
    virtual_address: u64,
    content: Content,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}

struct Elf {
    header: Header,
    sections: Vec<Section>,
    shstrtab: Option<usize>,
    resolved_sections: Vec<SectionHeader>,
    offset: usize,
}

impl Elf {
    fn new() -> Self {
        let mut ident = [0; SIZEOF_IDENT];
        ident[0..ELFMAG.len()].copy_from_slice(ELFMAG);
        ident[EI_CLASS] = ELFCLASS64;
        ident[EI_DATA] = ELFDATA2LSB;
        ident[EI_VERSION] = 1;
        ident[EI_OSABI] = 0;
        ident[EI_ABIVERSION] = 0;

        return Self {
            header: Header {
                e_ident: ident,
                e_type: ET_EXEC,
                e_machine: EM_AARCH64,
                e_version: 1,
                e_entry: 0x0,
                e_phoff: UNKNOWN,
                e_shoff: UNKNOWN,
                e_flags: 0,
                e_ehsize: SIZEOF_EHDR as u16,
                e_phentsize: SIZEOF_PHDR as u16,
                e_phnum: UNKNOWN as u16,
                e_shentsize: SIZEOF_SHDR as u16,
                e_shnum: UNKNOWN as u16,
                e_shstrndx: UNKNOWN as u16,
            },
            sections: Vec::new(),
            shstrtab: None,
            resolved_sections: Vec::new(),
            offset: 0,
        };
    }

    fn add_section(self: &mut Self, section: Section) {
        self.sections.push(section);
    }

    fn add_null_section(self: &mut Self) {
        self.add_section(Section {
            ..Default::default()
        });
    }

    fn add_shstrtab_section(self: &mut Self, shstrtab: Section) {
        self.shstrtab = Some(self.sections.len());
        self.add_section(shstrtab);
    }

    fn resolve_section_names(self: &mut Self) {
        let mut section_names: Vec<u8> = Vec::new();
        for section in self.sections.iter() {
            let len = match &section.content {
                Content::Backed(v) => v.len(),
                Content::Zeroed(v) => *v,
            };

            let header = SectionHeader {
                sh_name: section_names.len() as u32,
                sh_type: section.kind,
                sh_flags: section.flags,
                sh_addr: section.virtual_address,
                sh_offset: 0,
                sh_size: len as u64,
                sh_link: section.link,
                sh_info: section.info,
                sh_addralign: section.alignment,
                sh_entsize: section.entry_size,
            };
            section_names.extend(section.name.as_bytes());
            section_names.push(0);
            self.resolved_sections.push(header);
        }

        let shstrtab = self.shstrtab.unwrap();
        self.resolved_sections[shstrtab].sh_size = section_names.len() as u64;
        self.sections[shstrtab].content = Content::Backed(section_names);
    }

    fn resolve_section_content(self: &mut Self) {
        for i in 0..self.sections.len() {
            self.resolved_sections[i].sh_offset = self.offset as u64;
            self.offset += self.sections[i].content.backed_len();
        }
    }

    fn resolve(self: &mut Self) {
        if self.shstrtab.is_none() {
            let shstrtab = Section {
                name: String::from(".shstrtab"),
                kind: SHT_STRTAB,
                flags: 0,
                virtual_address: 0,
                content: Content::default(),
                link: 0,
                info: 0,
                alignment: 1,
                entry_size: 0,
            };
            self.add_shstrtab_section(shstrtab);
        }

        self.header.e_shstrndx = self.shstrtab.unwrap() as u16;
        self.offset = self.header.e_ehsize as usize;

        self.resolve_section_names();
        self.resolve_section_content();

        self.header.e_shoff = self.offset as u64;
        self.header.e_shnum = self.sections.len() as u16;
        self.offset += (self.header.e_shentsize * self.header.e_shnum) as usize;
    }

    fn write(self: Self, file: &mut File) {
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write(&as_bytes(self.header)).unwrap();

        for i in 0..self.sections.len() {
            let section = &self.resolved_sections[i];
            match &self.sections[i].content {
                Content::Backed(v) => {
                    file.seek(SeekFrom::Start(section.sh_offset)).unwrap();
                    file.write(&v).unwrap();
                }
                _ => {}
            }
        }

        file.seek(SeekFrom::Start(self.header.e_shoff)).unwrap();
        for section in &self.resolved_sections {
            file.write(&as_bytes(*section)).unwrap();
        }
    }
}

type Reader<'data> = gimli::EndianSlice<'data, gimli::RunTimeEndian>;

const UNKNOWN: u64 = 0;

fn as_bytes<T: Sized>(object: T) -> [u8; std::mem::size_of::<T>()]
where
    [(); std::mem::size_of::<T>()]:,
{
    let mem: [u8; std::mem::size_of::<T>()] = unsafe { std::mem::transmute_copy(&object) };
    return mem;
}

type DynErr = Box<dyn std::error::Error>;
type Err = Result<(), DynErr>;

#[derive(Hash, PartialEq, Eq)]
enum Reference {
    UnitOffset((usize, UnitOffset)),
    Signature(DebugTypeSignature),
}

type Mapping = HashMap<UnitOffset, UnitEntryId>;
type Types = HashMap<String, UnitEntryId>;
const ALLOWED_ENTRIES: &[gimli::DwTag] = &[
    gimli::DW_TAG_structure_type,
    gimli::DW_TAG_union_type,
    gimli::DW_TAG_enumeration_type,
    gimli::DW_TAG_typedef,
    gimli::DW_TAG_base_type,
    gimli::DW_TAG_array_type,
    gimli::DW_TAG_pointer_type,
    gimli::DW_TAG_subroutine_type,
];

fn id_to_name(id: UnitEntryId, dwarf: &DwarfUnit) -> Option<String> {
    let unit = dwarf.unit.get(id);
    if let Some(AttributeValue::String(name)) = unit.get(gimli::DW_AT_name) {
        let name = str::from_utf8(&name).unwrap();
        let name = match unit.tag() {
            gimli::DW_TAG_structure_type => format!("struct {name}"),
            gimli::DW_TAG_union_type => format!("union {name}"),
            gimli::DW_TAG_enumeration_type => format!("enum {name}"),
            _ => format!("{name}"),
        };
        Some(name)
    } else {
        match unit.tag() {
            gimli::DW_TAG_pointer_type => unit.get(gimli::DW_AT_type).and_then(|attr| {
                if let AttributeValue::UnitRef(id) = attr {
                    id_to_name(*id, dwarf).map(|name| format!("{name}*"))
                } else {
                    None
                }
            }),
            gimli::DW_TAG_array_type => unit.get(gimli::DW_AT_type).and_then(|attr| {
                if let AttributeValue::UnitRef(id) = attr {
                    id_to_name(*id, dwarf).and_then(|name| {
                        let mut iter = unit.children();
                        while let Some(id) = iter.next() {
                            let unit = dwarf.unit.get(*id);
                            if let Some(AttributeValue::Udata(bound)) =
                                unit.get(gimli::DW_AT_upper_bound)
                            {
                                return Some(format!("{name}[{}]", bound + 1));
                            }
                        }
                        return None;
                    })
                } else {
                    None
                }
            }),
            _ => None,
        }
    }
}

fn process_unit<'data>(parent: &read::UnitRef<Reader<'data>>, dwarf: &mut DwarfUnit) -> Types {
    let mut mapping = Mapping::new();

    match parent.header.type_() {
        read::UnitType::Compilation => {
            let mut entries = parent.entries();
            let mut depth = 0;
            while let Some((delta_depth, entry)) = entries.next_dfs().unwrap() {
                depth += delta_depth;
                if depth != 1 {
                    continue;
                }

                if !ALLOWED_ENTRIES.contains(&entry.tag()) {
                    continue;
                }

                process_type(entry, &parent, dwarf, &mut mapping);
            }
        }
        _ => println!("unknown unit {:?}", parent.header.type_()),
    }

    let mut types = Types::new();
    for (_, id) in mapping {
        if let Some(name) = id_to_name(id, dwarf) {
            types.insert(name, id);
        }
    }

    types
}

fn process_type<'data>(
    entry: &DebuggingInformationEntry<'_, '_, Reader<'data>>,
    cu: &read::UnitRef<Reader<'data>>,
    dwarf: &mut DwarfUnit,
    mapping: &mut Mapping,
) -> UnitEntryId {
    let root = dwarf.unit.root();
    if let Some(id) = mapping.get(&entry.offset()) {
        return *id;
    }

    let id = dwarf.unit.add(root, entry.tag());
    mapping.insert(entry.offset(), id);

    let mut attrs = entry.attrs();
    while let Ok(Some(attr)) = attrs.next() {
        // println!("{}: {:?}", attr.name(), attr.value());
        if let Some(wattr) = attribute(attr, cu, dwarf, mapping) {
            dwarf.unit.get_mut(id).set(attr.name(), wattr);
        }
    }

    let mut entries = cu.entries_tree(Some(entry.offset())).unwrap();
    let mut children = entries.root().unwrap().children();
    while let Ok(Some(node)) = children.next() {
        let entry = node.entry();
        if entry.tag() == gimli::DW_TAG_member
            && let Ok(Some(attr)) = entry.attr(gimli::DW_AT_name)
        {
            let name = cu.attr_string(attr.value()).unwrap().to_vec();
            if name.starts_with(b"__padding") {
                // continue;
            }
        }

        let id = dwarf.unit.add(id, entry.tag());
        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            if let Some(wattr) = attribute(attr, cu, dwarf, mapping) {
                dwarf.unit.get_mut(id).set(attr.name(), wattr);
            }
        }
    }

    id
}

fn attribute<'data>(
    attr: read::Attribute<Reader<'data>>,
    cu: &read::UnitRef<Reader<'data>>,
    dwarf: &mut DwarfUnit,
    mapping: &mut Mapping,
) -> Option<AttributeValue> {
    Some(match attr.name() {
        gimli::DW_AT_name => {
            let name = cu.attr_string(attr.value()).unwrap().to_vec();
            AttributeValue::String(name)
        }
        gimli::DW_AT_byte_size | gimli::DW_AT_data_member_location | gimli::DW_AT_upper_bound => {
            AttributeValue::Udata(attr.udata_value().unwrap())
        }
        gimli::DW_AT_prototyped => {
            if let read::AttributeValue::Flag(flag) = attr.value() {
                AttributeValue::Flag(flag)
            } else {
                panic!("malformed DW_AT_prototyped");
            }
        }
        gimli::DW_AT_encoding => AttributeValue::Encoding(gimli::DwAte(attr.u8_value().unwrap())),
        gimli::DW_AT_type => {
            if let read::AttributeValue::UnitRef(offset) = attr.value() {
                let entry = cu.entry(offset).unwrap();
                AttributeValue::UnitRef(process_type(&entry, cu, dwarf, mapping))
            } else {
                panic!("malformed DW_AT_type");
            }
        }
        gimli::DW_AT_decl_file
        | gimli::DW_AT_decl_line
        | gimli::DW_AT_decl_column
        | gimli::DW_AT_sibling => return None,
        gimli::DW_AT_const_value => AttributeValue::Udata(attr.udata_value().unwrap()),
        _ => {
            println!("unhandled attribute {:?}", attr.name().static_string());
            return None;
        }
    })
}

struct UnitIterator<'data> {
    info_units: read::DebugInfoUnitHeadersIter<Reader<'data>>,
    type_units: read::DebugTypesUnitHeadersIter<Reader<'data>>,
}

impl<'data> UnitIterator<'data> {
    fn new(
        info_units: read::DebugInfoUnitHeadersIter<Reader<'data>>,
        type_units: read::DebugTypesUnitHeadersIter<Reader<'data>>,
    ) -> Self {
        Self {
            info_units,
            type_units,
        }
    }
}

impl<'data> std::iter::Iterator for UnitIterator<'data> {
    type Item = read::UnitHeader<Reader<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(Some(header)) = self.info_units.next() {
            return Some(header);
        }
        if let Ok(Some(header)) = self.type_units.next() {
            return Some(header);
        }
        return None;
    }
}

struct Struct {
    size: u64,
    fields: Vec<(String, u64, UnitEntryId)>,
}

struct Union {
    size: u64,
    fields: Vec<(String, UnitEntryId)>,
}

struct Enum {
    size: u64,
    base_type: UnitEntryId,
    fields: Vec<(String, u64)>,
}

struct DebugInfo<'data> {
    dwarf: DwarfUnit,
    types: Types,
    symbols: object::File<'data>,
    elf: Elf,
}

impl<'data> DebugInfo<'data> {
    fn new(types: &'data [u8], symbols: &'data [u8]) -> Self {
        let reference = object::File::parse(types).unwrap();

        fn load_section<'data>(
            object: &object::File<'data>,
            name: &str,
        ) -> Result<Cow<'data, [u8]>, DynErr> {
            Ok(match object.section_by_name(name) {
                Some(section) => section.uncompressed_data().unwrap(),
                None => Default::default(),
            })
        }

        fn borrow_section<'data>(section: &'data Cow<'data, [u8]>) -> Reader<'data> {
            let slice = gimli::EndianSlice::new(Cow::as_ref(section), RunTimeEndian::Little);
            slice
        }

        let dwarf_sections =
            gimli::DwarfSections::load(|id| load_section(&reference, id.name())).unwrap();
        let reference = dwarf_sections.borrow(|section| borrow_section(section));

        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf = DwarfUnit::new(encoding);
        let root = dwarf.unit.root();

        dwarf.unit.get_mut(root).set(
            gimli::DW_AT_language,
            AttributeValue::Language(gimli::DW_LANG_C),
        );

        let mut types = Types::new();
        let mut iter = reference.units();
        while let Ok(Some(header)) = iter.next() {
            let unit = reference.unit(header).unwrap();
            let unit = unit.unit_ref(&reference);
            let subtypes = process_unit(&unit, &mut dwarf);
            for (name, id) in subtypes {
                types.insert(name, id);
            }
        }

        let symbols = object::File::parse(symbols).unwrap();

        let mut elf = Elf::new();
        elf.add_null_section();

        Self {
            dwarf,
            types,
            symbols,
            elf,
        }
    }

    fn write(mut self, path: &str) {
        let mut dwarf_sections = Sections::new(EndianVec::new(gimli::LittleEndian));
        self.dwarf.write(&mut dwarf_sections).unwrap();

        dwarf_sections
            .for_each(|id, data| {
                let section = Section {
                    name: String::from(id.name()),
                    kind: SHT_PROGBITS,
                    flags: 0,
                    virtual_address: 0,
                    content: Content::Backed(data.clone().into_vec()),
                    link: 0,
                    info: 0,
                    alignment: 1,
                    entry_size: 0,
                };
                self.elf.add_section(section);
                Ok::<(), DynErr>(())
            })
            .unwrap();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)
            .unwrap();

        self.elf.resolve();
        self.elf.write(&mut file);
    }

    fn type_by_name(&self, name: &str) -> UnitEntryId {
        if let Some(id) = self.types.get(name) {
            return *id;
        }
        panic!("type {} does not exist", name);
    }

    fn symbol_by_name(&self, name: &str) -> object::Symbol<'data, '_> {
        if let Some(sym) = self.symbols.symbol_by_name(name) {
            return sym;
        }
        panic!("symbol {} does not exist", name);
    }

    fn type_symbol(&mut self, name: &str, type_id: UnitEntryId) {
        let addr = self.symbol_by_name(name).address();
        let root = self.dwarf.unit.root();
        let id = self.dwarf.unit.add(root, gimli::DW_TAG_variable);
        let unit = self.dwarf.unit.get_mut(id);
        unit.set(
            gimli::DW_AT_name,
            AttributeValue::String(name.to_string().as_bytes().to_vec()),
        );
        unit.set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
        let mut location = Expression::new();
        location.op_addr(Address::Constant(addr));
        unit.set(gimli::DW_AT_location, AttributeValue::Exprloc(location));
    }

    fn create_array_type(&mut self, type_id: UnitEntryId, elements: usize) -> UnitEntryId {
        let root = self.dwarf.unit.root();
        let id = self.dwarf.unit.add(root, gimli::DW_TAG_array_type);
        let unit = self.dwarf.unit.get_mut(id);
        unit.set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
        {
            let id = self.dwarf.unit.add(id, gimli::DW_TAG_subrange_type);
            let unit = self.dwarf.unit.get_mut(id);
            unit.set(
                gimli::DW_AT_upper_bound,
                AttributeValue::Udata(elements.saturating_sub(1) as u64),
            );
        }
        if let Some(name) = id_to_name(id, &mut self.dwarf) {
            self.types.insert(name, id);
        }
        id
    }

    fn create_pointer_type(&mut self, type_id: UnitEntryId, pointer_size: u64) -> UnitEntryId {
        let root = self.dwarf.unit.root();
        let id = self.dwarf.unit.add(root, gimli::DW_TAG_pointer_type);
        let unit = self.dwarf.unit.get_mut(id);
        unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(pointer_size));
        unit.set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
        if let Some(name) = id_to_name(id, &mut self.dwarf) {
            self.types.insert(name, id);
        }
        id
    }

    fn create_struct_type(&mut self, name: &str, structure: Struct) -> UnitEntryId {
        let root = self.dwarf.unit.root();
        let id = self.dwarf.unit.add(root, gimli::DW_TAG_structure_type);
        let unit = self.dwarf.unit.get_mut(id);
        unit.set(
            gimli::DW_AT_name,
            AttributeValue::String(name.as_bytes().to_vec()),
        );
        unit.set(
            gimli::DW_AT_byte_size,
            AttributeValue::Udata(structure.size),
        );
        for (name, offset, type_id) in structure.fields {
            let id = self.dwarf.unit.add(id, gimli::DW_TAG_member);
            let unit = self.dwarf.unit.get_mut(id);
            unit.set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
            );
            unit.set(
                gimli::DW_AT_data_member_location,
                AttributeValue::Udata(offset),
            );
            unit.set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
        }
        if let Some(name) = id_to_name(id, &mut self.dwarf) {
            self.types.insert(name, id);
        }
        id
    }

    fn create_union_type(&mut self, name: &str, union: Union) -> UnitEntryId {
        let root = self.dwarf.unit.root();
        let id = self.dwarf.unit.add(root, gimli::DW_TAG_union_type);
        let unit = self.dwarf.unit.get_mut(id);
        unit.set(
            gimli::DW_AT_name,
            AttributeValue::String(name.as_bytes().to_vec()),
        );
        unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(union.size));
        for (name, type_id) in union.fields {
            let id = self.dwarf.unit.add(id, gimli::DW_TAG_member);
            let unit = self.dwarf.unit.get_mut(id);
            unit.set(
                gimli::DW_AT_name,
                AttributeValue::String(name.as_bytes().to_vec()),
            );
            unit.set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
        }
        if let Some(name) = id_to_name(id, &mut self.dwarf) {
            self.types.insert(name, id);
        }
        id
    }

    fn create_typedef(&mut self, name: &str, type_id: UnitEntryId) -> UnitEntryId {
        let root = self.dwarf.unit.root();
        let id = self.dwarf.unit.add(root, gimli::DW_TAG_typedef);
        let unit = self.dwarf.unit.get_mut(id);
        unit.set(
            gimli::DW_AT_name,
            AttributeValue::String(name.as_bytes().to_vec()),
        );
        unit.set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
        if let Some(name) = id_to_name(id, &mut self.dwarf) {
            self.types.insert(name, id);
        }
        id
    }
}

fn main() {
    let type_contents = std::fs::read("types.debug").unwrap();
    let syms_contents = std::fs::read("kernel.reloc").unwrap();
    let mut info = DebugInfo::new(&*type_contents, &*syms_contents);

    // start annotations

    let id = info.create_array_type(info.type_by_name("physical_cpu"), 4);
    info.type_symbol("physical_cpu_array", id);
    info.type_symbol(
        "scheduler_global_queue",
        info.type_by_name("scheduler_queue"),
    );
    info.create_pointer_type(info.type_by_name("physical_cpu[4]"), 8);
    info.create_struct_type(
        "WTF",
        Struct {
            size: 0x100,
            fields: vec![(
                String::from("WTF"),
                0x1337,
                info.type_by_name("physical_cpu"),
            )],
        },
    );
    info.create_typedef("WTF", info.type_by_name("struct WTF"));

    // end annotations

    info.write("test.debug");
}
