use gimli::write::{
    Address, AttributeValue, CallFrameInstruction, CommonInformationEntry, DwarfUnit, EndianVec,
    Expression, FileInfo, FrameTable, LineProgram, LineString, Location, LocationList, Sections,
    UnitEntryId,
};
use gimli::{Encoding, LineEncoding, Register};
use goblin::elf::section_header::{SHF_ALLOC, SHT_PROGBITS};
use goblin::elf64::{
    header::*, program_header as segment, section_header as section, sym as symbol,
};
use std::collections::BTreeMap as HashMap;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::mem::transmute;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

type RawSection = section::SectionHeader;
type RawSegment = segment::ProgramHeader;
type RawSymbol = symbol::Sym;

#[allow(dead_code)]
struct Section {
    hdr: RawSection,
    raw: Option<Vec<u8>>,
    off: u64,
}

struct Symbol {
    hdr: RawSymbol,
    section: Option<String>,
}

#[allow(dead_code)]
struct Segment {
    hdr: RawSegment,
    raw: Vec<u8>,
    off: u64,
}

#[derive(Serialize, Deserialize)]
struct Field {
    offset: u64,
    name: String,
    typename: String,
}

#[derive(Serialize, Deserialize)]
struct Structure {
    size: u64,
    anon: bool,
    fields: Vec<Field>,
}

type Union = Structure;

#[derive(Serialize, Deserialize)]
struct Pointer {
    size: u64,
    target: String,
}

#[derive(Serialize, Deserialize)]
struct Typedef {
    target: String,
}

#[derive(Serialize, Deserialize)]
struct Parameter {
    name: String,
    typename: String,
}

#[derive(Serialize, Deserialize)]
struct Prototype {
    parameters: Vec<Parameter>,
    ellipsis: bool,
    returntype: String,
}

#[derive(Serialize, Deserialize)]
struct Array {
    count: u64,
    target: String,
}

#[derive(Serialize, Deserialize)]
struct EnumField {
    name: String,
    // can a backing enum type be larger than u64?
    value: u64,
}

#[derive(Serialize, Deserialize)]
struct Enum {
    size: u64,
    signed: bool,
    fields: Vec<EnumField>,
}

#[derive(Serialize, Deserialize)]
struct Integer {
    size: u64,
    signed: bool,
}

#[derive(Serialize, Deserialize)]
struct Float {
    size: u64,
}

#[derive(Serialize, Deserialize)]
struct GlobalVariable {
    name: String,
    size: u64,
    typename: String,
    section: Option<String>,
}

#[derive(Serialize, Deserialize)]
enum VariableLocation {
    Register(String),
    StackVariable(i64),
    None,
}

#[derive(Serialize, Deserialize)]
struct Argument {
    location: VariableLocation,
    name: String,
    typename: String,
}

#[derive(Serialize, Deserialize)]
struct Local {
    name: String,
    typename: String,
    location: VariableLocation,
}

#[derive(Serialize, Deserialize)]
struct CallInformation {
    return_pc: u64,
    target: u64,
}

#[derive(Serialize, Deserialize)]
struct Label {
    name: String,
    address: u64,
}

#[derive(Serialize, Deserialize)]
struct Function {
    name: String,
    start: u64,
    end: u64,
    arguments: Vec<Argument>,
    ellipsis: bool,
    returntype: String,
    locals: Option<Vec<Local>>,
    frame: Option<Vec<(u32, i32)>>,
    calls: Option<Vec<CallInformation>>,
    labels: Option<Vec<Label>>,
    lineinfo: Option<Vec<(u64, u64)>>,
    source: Option<String>,
    section: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BinjaSection {
    addr: u64,
    size: u64,
}

enum BinjaType {
    Structure(Structure),
    Union(Union),
    Integer(Integer),
    Pointer(Pointer),
    Typedef(Typedef),
    Prototype(Prototype),
    Enum(Enum),
    Array(Array),
    Float(Float),
}

type DynErr = Box<dyn std::error::Error>;
type Err = Result<(), DynErr>;

fn collect_types(tmp: PathBuf) -> Result<HashMap<String, BinjaType>, DynErr> {
    let mut types = HashMap::new();
    let read = |path: &str| fs::read_to_string(tmp.join(path));

    let structs: HashMap<String, Structure> = serde_json::from_str(&read("structs.json")?)?;
    structs.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Structure(v));
    });

    let unions: HashMap<String, Union> = serde_json::from_str(&read("unions.json")?)?;
    unions.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Union(v));
    });

    let integers: HashMap<String, Integer> = serde_json::from_str(&read("integers.json")?)?;
    integers.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Integer(v));
    });

    let pointers: HashMap<String, Pointer> = serde_json::from_str(&read("pointers.json")?)?;
    pointers.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Pointer(v));
    });

    let typedefs: HashMap<String, Typedef> = serde_json::from_str(&read("typedefs.json")?)?;
    typedefs.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Typedef(v));
    });

    let prototypes: HashMap<String, Prototype> = serde_json::from_str(&read("prototypes.json")?)?;
    prototypes.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Prototype(v));
    });

    let enums: HashMap<String, Enum> = serde_json::from_str(&read("enums.json")?)?;
    enums.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Enum(v));
    });

    let arrays: HashMap<String, Array> = serde_json::from_str(&read("arrays.json")?)?;
    arrays.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Array(v));
    });

    let floats: HashMap<String, Float> = serde_json::from_str(&read("floats.json")?)?;
    floats.into_iter().for_each(|(k, v)| {
        _ = types.insert(k, BinjaType::Float(v));
    });

    Ok(types)
}

fn collect_variables(tmp: PathBuf) -> Result<HashMap<u64, GlobalVariable>, DynErr> {
    Ok(serde_json::from_str(&fs::read_to_string(
        tmp.join("variables.json"),
    )?)?)
}

fn collect_functions(tmp: PathBuf) -> Result<HashMap<u64, Function>, DynErr> {
    Ok(serde_json::from_str(&fs::read_to_string(
        tmp.join("functions.json"),
    )?)?)
}

fn collect_sections(tmp: PathBuf) -> Result<HashMap<String, BinjaSection>, DynErr> {
    Ok(serde_json::from_str(&fs::read_to_string(
        tmp.join("sections.json"),
    )?)?)
}

fn visit(
    dwarf: &mut DwarfUnit,
    mappings: &HashMap<String, BinjaType>,
    dwarf_types: &mut HashMap<String, gimli::write::UnitEntryId>,
    name: &String,
) {
    if dwarf_types.contains_key(name) || name.len() == 0 {
        return;
    }

    let binja_type = mappings.get(name).unwrap();
    let tag = match binja_type {
        BinjaType::Structure(_) => gimli::DW_TAG_structure_type,
        BinjaType::Union(_) => gimli::DW_TAG_union_type,
        BinjaType::Integer(_) => gimli::DW_TAG_base_type,
        BinjaType::Pointer(_) => gimli::DW_TAG_pointer_type,
        BinjaType::Typedef(_) => gimli::DW_TAG_typedef,
        BinjaType::Prototype(_) => gimli::DW_TAG_subroutine_type,
        BinjaType::Enum(_) => gimli::DW_TAG_enumeration_type,
        BinjaType::Array(_) => gimli::DW_TAG_array_type,
        BinjaType::Float(_) => gimli::DW_TAG_base_type,
    };
    dwarf_types.insert(name.clone(), dwarf.unit.add(dwarf.unit.root(), tag));

    match binja_type {
        BinjaType::Structure(s) => s.fields.iter().for_each(
            |Field {
                 typename,
                 offset: _,
                 name: _,
             }| visit(dwarf, mappings, dwarf_types, typename),
        ),
        BinjaType::Union(u) => u.fields.iter().for_each(
            |Field {
                 typename,
                 offset: _,
                 name: _,
             }| visit(dwarf, mappings, dwarf_types, typename),
        ),
        BinjaType::Pointer(p) => visit(dwarf, mappings, dwarf_types, &p.target),
        BinjaType::Typedef(t) => visit(dwarf, mappings, dwarf_types, &t.target),
        BinjaType::Prototype(f) => {
            visit(dwarf, mappings, dwarf_types, &f.returntype);
            f.parameters
                .iter()
                .for_each(|Parameter { name: _, typename }| {
                    visit(dwarf, mappings, dwarf_types, typename)
                });
        }
        BinjaType::Array(a) => visit(dwarf, mappings, dwarf_types, &a.target),
        _ => {}
    }
}

const XMM_REGNUM_00_07: u16 = 17;
const XMM_REGNUM_08_0F: u16 = 25;
const XMM_REGNUM_10_1F: u16 = 69;

fn translate_register(register: String) -> Register {
    if let Some(reg) = gimli::X86_64::name_to_register(&register) {
        reg
    } else {
        if register.starts_with("temp") {
            // binja temp registers do not actually exist
            return Register(0xffff);
        }

        match register.as_str() {
            "zmm0" => Register(XMM_REGNUM_00_07 + 0),
            "zmm1" => Register(XMM_REGNUM_00_07 + 1),
            "zmm2" => Register(XMM_REGNUM_00_07 + 2),
            "zmm3" => Register(XMM_REGNUM_00_07 + 3),
            "zmm4" => Register(XMM_REGNUM_00_07 + 4),
            "zmm5" => Register(XMM_REGNUM_00_07 + 5),
            "zmm6" => Register(XMM_REGNUM_00_07 + 6),
            "zmm7" => Register(XMM_REGNUM_00_07 + 7),
            "zmm8" => Register(XMM_REGNUM_08_0F + 0),
            "zmm9" => Register(XMM_REGNUM_08_0F + 1),
            "zmm10" => Register(XMM_REGNUM_08_0F + 2),
            "zmm11" => Register(XMM_REGNUM_08_0F + 3),
            "zmm12" => Register(XMM_REGNUM_08_0F + 4),
            "zmm13" => Register(XMM_REGNUM_08_0F + 5),
            "zmm14" => Register(XMM_REGNUM_08_0F + 6),
            "zmm15" => Register(XMM_REGNUM_08_0F + 7),
            "zmm16" => Register(XMM_REGNUM_10_1F + 0),
            "zmm17" => Register(XMM_REGNUM_10_1F + 1),
            "zmm18" => Register(XMM_REGNUM_10_1F + 2),
            "zmm19" => Register(XMM_REGNUM_10_1F + 3),
            "zmm20" => Register(XMM_REGNUM_10_1F + 4),
            "zmm21" => Register(XMM_REGNUM_10_1F + 5),
            "zmm22" => Register(XMM_REGNUM_10_1F + 6),
            "zmm23" => Register(XMM_REGNUM_10_1F + 7),
            "zmm24" => Register(XMM_REGNUM_10_1F + 8),
            "zmm25" => Register(XMM_REGNUM_10_1F + 9),
            "zmm26" => Register(XMM_REGNUM_10_1F + 10),
            "zmm27" => Register(XMM_REGNUM_10_1F + 11),
            "zmm28" => Register(XMM_REGNUM_10_1F + 12),
            "zmm29" => Register(XMM_REGNUM_10_1F + 13),
            "zmm30" => Register(XMM_REGNUM_10_1F + 14),
            "zmm31" => Register(XMM_REGNUM_10_1F + 15),

            "fsbase" => Register(58),
            "gsbase" => Register(59),

            // used by xsave, xgetbv and xsetbv
            // no official dwarf register number???
            "xcr0" => Register(0xffff),

            _ => panic!("unknown register: {register}"),
        }
    }
}

pub fn main() -> Err {
    // idiomatic rust, trust me
    unsafe {
        let args: Vec<String> = std::env::args().collect();
        let tmp = Path::new(&args[1]);
        let name = Path::new(&args[2]);
        let mut file = File::create(name)?;

        let mut ident: [u8; SIZEOF_IDENT] = [0u8; 16];
        for i in 0..4 {
            ident[i] = ELFMAG[i];
        }
        ident[EI_ABIVERSION] = 0;
        ident[EI_CLASS] = ELFCLASS64;
        ident[EI_DATA] = ELFDATA2LSB;
        ident[EI_OSABI] = ELFOSABI_SYSV;
        ident[EI_VERSION] = 1;
        let mut header = Header {
            e_ident: ident,
            e_type: ET_DYN,
            e_machine: EM_X86_64,
            e_version: 1,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: SIZEOF_EHDR as u16,
            e_phentsize: segment::SIZEOF_PHDR as u16,
            e_phnum: 0,
            e_shentsize: section::SIZEOF_SHDR as u16,
            e_shnum: 0,
            e_shstrndx: 0,
        };

        let mut sections: HashMap<String, Section> = HashMap::new();
        let mut symbols: HashMap<String, Symbol> = HashMap::new();

        // Choose the encoding parameters.
        let encoding = gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        // Create a container for a single compilation unit.
        let mut dwarf = DwarfUnit::new(encoding);
        let root = dwarf.unit.root();

        // set CU attributes
        let sources = tmp.to_path_buf().join("sources");
        let comp_dir_name_id = dwarf.strings.add(sources.to_str().unwrap());
        dwarf.unit.get_mut(root).set(
            gimli::DW_AT_comp_dir,
            AttributeValue::StringRef(comp_dir_name_id),
        );
        let comp_file_name_id = dwarf.strings.add("teemo.c");
        dwarf.unit.get_mut(root).set(
            gimli::DW_AT_name,
            AttributeValue::StringRef(comp_file_name_id),
        );
        dwarf.unit.get_mut(root).set(
            gimli::DW_AT_language,
            AttributeValue::Language(gimli::DW_LANG_C),
        );
        dwarf.unit.get_mut(root).set(
            gimli::DW_AT_producer,
            AttributeValue::StringRef(dwarf.strings.add(":3")),
        );
        dwarf.unit.line_program = LineProgram::new(
            encoding,
            LineEncoding::default(),
            LineString::StringRef(comp_dir_name_id),
            LineString::StringRef(comp_file_name_id),
            None,
        );
        let sources = dwarf.unit.line_program.add_directory(LineString::String(
            dwarf.strings.get(comp_dir_name_id).to_vec(),
        ));

        let type_mapping = collect_types(tmp.to_path_buf())?;
        let global_variables = collect_variables(tmp.to_path_buf())?;
        let functions = collect_functions(tmp.to_path_buf())?;
        let mut dwarf_functions: HashMap<u64, UnitEntryId> = HashMap::new();
        let binja_sections = collect_sections(tmp.to_path_buf())?;
        for (name, BinjaSection { addr, size }) in binja_sections.iter() {
            sections.insert(
                name.clone(),
                Section {
                    hdr: section::SectionHeader {
                        sh_name: 0,
                        sh_type: SHT_PROGBITS,
                        sh_addr: *addr,
                        sh_flags: SHF_ALLOC as u64,
                        sh_offset: 0,
                        sh_size: *size,
                        sh_link: 0,
                        sh_info: 0,
                        sh_addralign: 0,
                        sh_entsize: 0,
                    },
                    raw: None, // Some(vec![0; *size as usize]),
                    off: 0,
                },
            );
        }

        let mut dwarf_types: HashMap<String, UnitEntryId> = HashMap::new();
        for name in type_mapping.keys() {
            visit(&mut dwarf, &type_mapping, &mut dwarf_types, name);
        }

        let base_type = |bytes: u64, signed: bool| {
            return *dwarf_types
                .get(&format!(
                    "{}int{}_t",
                    if signed { "" } else { "u" },
                    bytes * 8,
                ))
                .unwrap();
        };

        for (name, binja_type) in type_mapping.into_iter() {
            match binja_type {
                BinjaType::Structure(Structure { size, anon, fields }) => {
                    let id = *dwarf_types.get(&name).unwrap();
                    let unit = dwarf.unit.get_mut(id);
                    if !anon {
                        unit.set(
                            gimli::DW_AT_name,
                            AttributeValue::StringRef(dwarf.strings.add(name)),
                        );
                    }
                    unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(size));

                    for Field {
                        offset,
                        name,
                        typename,
                    } in fields
                    {
                        let id = dwarf.unit.add(id, gimli::DW_TAG_member);
                        let field = dwarf.unit.get_mut(id);
                        field.set(
                            gimli::DW_AT_name,
                            AttributeValue::StringRef(dwarf.strings.add(name)),
                        );
                        if typename.len() > 0 {
                            field.set(
                                gimli::DW_AT_type,
                                AttributeValue::UnitRef(*dwarf_types.get(&typename).unwrap()),
                            );
                        }
                        field.set(
                            gimli::DW_AT_data_member_location,
                            AttributeValue::Udata(offset),
                        );
                    }
                }
                BinjaType::Union(Union { size, anon, fields }) => {
                    let id = *dwarf_types.get(&name).unwrap();
                    let unit = dwarf.unit.get_mut(id);
                    if !anon {
                        unit.set(
                            gimli::DW_AT_name,
                            AttributeValue::StringRef(dwarf.strings.add(name)),
                        );
                    }
                    unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(size));

                    for Field {
                        offset,
                        name,
                        typename,
                    } in fields
                    {
                        let id = dwarf.unit.add(id, gimli::DW_TAG_member);
                        let field = dwarf.unit.get_mut(id);
                        field.set(
                            gimli::DW_AT_name,
                            AttributeValue::StringRef(dwarf.strings.add(name)),
                        );
                        field.set(
                            gimli::DW_AT_type,
                            AttributeValue::UnitRef(*dwarf_types.get(&typename).unwrap()),
                        );
                        field.set(
                            gimli::DW_AT_data_member_location,
                            AttributeValue::Udata(offset),
                        );
                    }
                }
                BinjaType::Integer(Integer { size, signed }) => {
                    let unit = dwarf.unit.get_mut(*dwarf_types.get(&name).unwrap());
                    unit.set(
                        gimli::DW_AT_name,
                        AttributeValue::StringRef(dwarf.strings.add(name)),
                    );
                    unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(size));
                    unit.set(
                        gimli::DW_AT_encoding,
                        AttributeValue::Encoding(if signed {
                            gimli::DW_ATE_signed
                        } else {
                            gimli::DW_ATE_unsigned
                        }),
                    );
                }
                BinjaType::Pointer(Pointer { size, target }) => {
                    let unit = dwarf.unit.get_mut(*dwarf_types.get(&name).unwrap());
                    unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(size));
                    if target.len() > 0 {
                        unit.set(
                            gimli::DW_AT_type,
                            AttributeValue::UnitRef(*dwarf_types.get(&target).unwrap()),
                        );
                    }
                }
                BinjaType::Typedef(Typedef { target }) => {
                    let unit = dwarf.unit.get_mut(*dwarf_types.get(&name).unwrap());
                    unit.set(
                        gimli::DW_AT_name,
                        AttributeValue::StringRef(dwarf.strings.add(name)),
                    );
                    unit.set(
                        gimli::DW_AT_type,
                        AttributeValue::UnitRef(*dwarf_types.get(&target).unwrap()),
                    );
                }
                BinjaType::Prototype(Prototype {
                    parameters,
                    ellipsis,
                    returntype,
                }) => {
                    let id = *dwarf_types.get(&name).unwrap();
                    let unit = dwarf.unit.get_mut(id);
                    unit.set(gimli::DW_AT_prototyped, AttributeValue::Flag(true));
                    if returntype.len() > 0 {
                        unit.set(
                            gimli::DW_AT_type,
                            AttributeValue::UnitRef(*dwarf_types.get(&returntype).unwrap()),
                        );
                    }

                    for Parameter { name, typename } in parameters {
                        let id = dwarf.unit.add(id, gimli::DW_TAG_formal_parameter);
                        let unit = dwarf.unit.get_mut(id);
                        if name.len() > 0 {
                            unit.set(
                                gimli::DW_AT_name,
                                AttributeValue::StringRef(dwarf.strings.add(name)),
                            );
                        }
                        unit.set(
                            gimli::DW_AT_type,
                            AttributeValue::UnitRef(*dwarf_types.get(&typename).unwrap()),
                        );
                    }

                    if ellipsis {
                        dwarf.unit.add(id, gimli::DW_TAG_unspecified_parameters);
                    }
                }
                BinjaType::Enum(Enum {
                    size,
                    signed,
                    fields,
                }) => {
                    let id = *dwarf_types.get(&name).unwrap();
                    let unit = dwarf.unit.get_mut(id);
                    unit.set(
                        gimli::DW_AT_name,
                        AttributeValue::StringRef(dwarf.strings.add(name)),
                    );
                    unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(size));
                    unit.set(
                        gimli::DW_AT_encoding,
                        AttributeValue::Encoding(if signed {
                            gimli::DW_ATE_signed
                        } else {
                            gimli::DW_ATE_unsigned
                        }),
                    );
                    unit.set(
                        gimli::DW_AT_type,
                        AttributeValue::UnitRef(base_type(size, signed)),
                    );

                    for EnumField { name, value } in fields {
                        let id = dwarf.unit.add(id, gimli::DW_TAG_enumerator);
                        let field = dwarf.unit.get_mut(id);
                        field.set(
                            gimli::DW_AT_name,
                            AttributeValue::StringRef(dwarf.strings.add(name)),
                        );
                        field.set(gimli::DW_AT_const_value, AttributeValue::Udata(value));
                    }
                }
                BinjaType::Array(Array { count, target }) => {
                    let id = *dwarf_types.get(&name).unwrap();
                    let unit = dwarf.unit.get_mut(id);

                    unit.set(
                        gimli::DW_AT_type,
                        AttributeValue::UnitRef(*dwarf_types.get(&target).unwrap()),
                    );

                    let id = dwarf.unit.add(id, gimli::DW_TAG_subrange_type);
                    let unit = dwarf.unit.get_mut(id);

                    unit.set(
                        gimli::DW_AT_type,
                        AttributeValue::UnitRef(base_type(8, false)),
                    );
                    unit.set(gimli::DW_AT_upper_bound, AttributeValue::Udata(count - 1));
                }
                BinjaType::Float(Float { size }) => {
                    let unit = dwarf.unit.get_mut(*dwarf_types.get(&name).unwrap());
                    unit.set(
                        gimli::DW_AT_name,
                        AttributeValue::StringRef(dwarf.strings.add(name)),
                    );
                    unit.set(gimli::DW_AT_byte_size, AttributeValue::Udata(size));
                    unit.set(
                        gimli::DW_AT_encoding,
                        AttributeValue::Encoding(gimli::DW_ATE_float),
                    );
                }
            }
        }

        for (
            address,
            GlobalVariable {
                name,
                size,
                typename,
                section,
            },
        ) in global_variables.into_iter()
        {
            let id = dwarf.unit.add(root, gimli::DW_TAG_variable);
            let unit = dwarf.unit.get_mut(id);
            unit.set(
                gimli::DW_AT_name,
                AttributeValue::StringRef(dwarf.strings.add(name.clone())),
            );
            if typename.len() > 0 {
                unit.set(
                    gimli::DW_AT_type,
                    AttributeValue::UnitRef(*dwarf_types.get(&typename).unwrap()),
                );
            }
            unit.set(gimli::DW_AT_external, AttributeValue::Flag(true));
            let mut location = Expression::new();
            location.op_addr(Address::Constant(address));
            unit.set(gimli::DW_AT_location, AttributeValue::Exprloc(location));

            // let adjust = if let Some(sectname) = &section {
            //     binja_sections.get(sectname).unwrap().addr
            // } else {
            //     0
            // };
            symbols.insert(
                name,
                Symbol {
                    hdr: RawSymbol {
                        st_name: 0,
                        // 0x10 <- global binding
                        // 0x01 <- object type
                        st_info: 0x11,
                        st_other: 0,
                        // TODO: parse original elf for section mappings
                        st_shndx: 0,
                        st_size: size,
                        // assumed to be non rebased offset
                        st_value: address,
                    },
                    section,
                },
            );
        }

        let mut frame_table = FrameTable::default();
        let encoding = Encoding {
            address_size: 8,
            format: gimli::Format::Dwarf32,
            // CIE version 1
            version: 1,
        };
        let mut cie = CommonInformationEntry::new(encoding, 1, 1, Register(7));
        cie.add_instruction(CallFrameInstruction::Offset(Register(16), -8));
        let _cie_id = frame_table.add_cie(cie);

        for address in functions.keys() {
            let fid = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
            dwarf_functions.insert(*address, fid);
        }

        for (
            address,
            Function {
                name,
                start,
                end,
                arguments,
                ellipsis,
                returntype,
                locals,
                frame: _frame,
                calls: _calls,
                labels,
                lineinfo,
                source,
                section,
            },
        ) in functions.into_iter()
        {
            let fid = *dwarf_functions.get(&address).unwrap();
            let unit = dwarf.unit.get_mut(fid);
            unit.set(gimli::DW_AT_external, AttributeValue::Flag(true));
            unit.set(
                gimli::DW_AT_name,
                AttributeValue::StringRef(dwarf.strings.add(name.clone())),
            );
            unit.set(gimli::DW_AT_prototyped, AttributeValue::Flag(true));
            if returntype.len() > 0 {
                unit.set(
                    gimli::DW_AT_type,
                    AttributeValue::UnitRef(*dwarf_types.get_mut(&returntype).unwrap()),
                );
            }
            unit.set(gimli::DW_AT_low_pc, AttributeValue::Udata(start));
            unit.set(gimli::DW_AT_high_pc, AttributeValue::Udata(end));
            let mut location = Expression::new();
            location.op(gimli::DW_OP_call_frame_cfa);
            unit.set(gimli::DW_AT_frame_base, AttributeValue::Exprloc(location));

            for Argument {
                location,
                name,
                typename,
            } in arguments
            {
                let id = dwarf.unit.add(fid, gimli::DW_TAG_formal_parameter);
                dwarf.unit.get_mut(id).set(
                    gimli::DW_AT_name,
                    AttributeValue::StringRef(dwarf.strings.add(name)),
                );
                if typename.len() > 0 {
                    dwarf.unit.get_mut(id).set(
                        gimli::DW_AT_type,
                        AttributeValue::UnitRef(*dwarf_types.get(&typename).unwrap()),
                    );
                }
                // let mut loclist = LocationList(Vec::new());
                let mut expression = Expression::new();

                match location {
                    VariableLocation::Register(regname) => {
                        let mut register = Expression::new();
                        register.op_reg(translate_register(regname));
                        expression.op_entry_value(register);
                        expression.op(gimli::DW_OP_stack_value);
                    }
                    VariableLocation::StackVariable(offset) => {
                        expression.op_fbreg(offset - 8);
                    }
                    VariableLocation::None => {}
                }

                // loclist.0.push(Location::OffsetPair {
                //     begin: start,
                //     end: end,
                //     data: expression,
                // });
                // let locid = dwarf.unit.locations.add(loclist);
                dwarf
                    .unit
                    .get_mut(id)
                    .set(gimli::DW_AT_location, AttributeValue::Exprloc(expression));
            }

            // if let Some(calls) = calls {
            //     for call in calls {
            //         let id = dwarf.unit.add(fid, gimli::DW_TAG_call_site);
            //         let unit = dwarf.unit.get_mut(id);

            //         unit.set(
            //             gimli::DW_AT_call_return_pc,
            //             AttributeValue::Udata(call.return_pc),
            //         );
            //         if let Some(target) = dwarf_functions.get(&call.target) {
            //             unit.set(gimli::DW_AT_call_target, AttributeValue::UnitRef(*target));
            //         }
            //     }
            // }

            if ellipsis {
                dwarf.unit.add(fid, gimli::DW_TAG_unspecified_parameters);
            }

            if let Some(locals) = locals {
                for Local {
                    name,
                    typename,
                    location,
                } in locals
                {
                    let id = dwarf.unit.add(fid, gimli::DW_TAG_variable);
                    let unit = dwarf.unit.get_mut(id);
                    unit.set(
                        gimli::DW_AT_name,
                        AttributeValue::StringRef(dwarf.strings.add(name)),
                    );
                    if typename.len() > 0 {
                        unit.set(
                            gimli::DW_AT_type,
                            AttributeValue::UnitRef(*dwarf_types.get(&typename).unwrap()),
                        );
                    }

                    let mut expression = Expression::new();
                    match location {
                        VariableLocation::Register(regname) => {
                            expression.op_reg(translate_register(regname));
                        }
                        VariableLocation::StackVariable(offset) => {
                            expression.op_fbreg(offset - 8);
                        }
                        VariableLocation::None => {}
                    }

                    unit.set(gimli::DW_AT_location, AttributeValue::Exprloc(expression));
                }
            }

            if let Some(labels) = labels {
                for Label { name, address } in labels {
                    let id = dwarf.unit.add(fid, gimli::DW_TAG_label);
                    let unit = dwarf.unit.get_mut(id);
                    unit.set(
                        gimli::DW_AT_name,
                        AttributeValue::StringRef(dwarf.strings.add(name)),
                    );
                    unit.set(
                        gimli::DW_AT_low_pc,
                        AttributeValue::Address(Address::Constant(address)),
                    );
                }
            }

            if let Some(lineinfo) = lineinfo {
                let file_id = dwarf.unit.line_program.add_file(
                    LineString::String(source.unwrap().into_bytes()),
                    sources,
                    None,
                );

                let start = lineinfo[0].0;
                dwarf
                    .unit
                    .line_program
                    .begin_sequence(Some(Address::Constant(start)));
                for (address, line) in lineinfo {
                    dwarf.unit.line_program.row().file = file_id;
                    dwarf.unit.line_program.row().address_offset = address - start;
                    dwarf.unit.line_program.row().is_statement = true;
                    dwarf.unit.line_program.row().line = line;
                    dwarf.unit.line_program.generate_row();
                }
                dwarf.unit.line_program.end_sequence(0);

                // let directory_id = dwarf.unit.line_program.add_directory(LineString::String(
                //     dwarf.strings.get(comp_dir_name_id).to_vec(),
                // ));
                // let file_id = dwarf.unit.line_program.add_file(
                //     LineString::String(dwarf.strings.get(comp_file_name_id).to_vec()),
                //     directory_id,
                //     None,
                // );
                // dwarf
                //     .unit
                //     .line_program
                //     .begin_sequence(Some(Address::Constant(0)));
                // dwarf.unit.line_program.row().file = file_id;
                // dwarf.unit.line_program.row().address_offset = 0;
                // dwarf.unit.line_program.row().is_statement = true;
                // dwarf.unit.line_program.row().line = 13;
                // dwarf.unit.line_program.row().column = 69;
                // dwarf.unit.line_program.generate_row();
                // dwarf.unit.line_program.end_sequence(4);
            }

            // if let Some(frame) = frame {
            //     let mut fde =
            //         FrameDescriptionEntry::new(Address::Constant(start), (end - start) as u32);

            //     for (pc_offset, frame_offset) in frame {
            //         println!("pc offset = {pc_offset}");
            //         fde.add_instruction(
            //             pc_offset,
            //             CallFrameInstruction::Cfa(Register(7), -frame_offset + 8),
            //         );
            //     }

            //     frame_table.add_fde(cie_id, fde);
            // }

            // let adjust = if let Some(sectname) = &section {
            //     binja_sections.get(sectname).unwrap().addr
            // } else {
            //     0
            // };
            symbols.insert(
                name,
                Symbol {
                    hdr: RawSymbol {
                        st_name: 0,
                        // 0x10 <- global binding
                        // 0x01 <- function type
                        st_info: 0x12,
                        st_other: 0,
                        // TODO: parse original elf for section mappings
                        st_shndx: 0,
                        st_size: end - start,
                        // assumed to be non rebased offset
                        st_value: address,
                    },
                    section,
                },
            );
        }

        // Create a `Vec` for each DWARF section.
        let mut dwarf_sections = Sections::new(EndianVec::new(gimli::LittleEndian));
        dwarf.write(&mut dwarf_sections)?;
        frame_table.write_eh_frame(&mut dwarf_sections.eh_frame)?;

        // Finally, write the DWARF data to the sections.
        dwarf_sections.for_each(|id, data| {
            // Here you can add the data to the output object file.
            sections.insert(
                String::from(id.name()),
                Section {
                    hdr: section::SectionHeader {
                        sh_type: section::SHT_PROGBITS,
                        ..Default::default()
                    },
                    raw: Some(data.clone().into_vec()),
                    off: 0,
                },
            );

            Err::Ok(())
        })?;

        // finalize elf file
        let mut section_names = Section {
            hdr: RawSection {
                sh_type: section::SHT_STRTAB,
                ..Default::default()
            },
            raw: Some(Vec::new()),
            off: 0,
        };

        let symbol_table = Section {
            hdr: RawSection {
                sh_type: section::SHT_SYMTAB,
                sh_link: 2,
                sh_entsize: symbol::SIZEOF_SYM as u64,
                ..Default::default()
            },
            raw: Some(Vec::new()),
            off: 0,
        };

        let mut symbol_names = Section {
            hdr: RawSection {
                sh_type: section::SHT_STRTAB,
                ..Default::default()
            },
            raw: Some(Vec::new()),
            off: 0,
        };

        sections.insert(String::from(".symtab"), symbol_table);

        // account for NULL section
        header.e_shnum += 1;

        // account for section names table
        header.e_shnum += 1;

        // account for symbol names table
        header.e_shnum += 1;

        // account for all the dwarf sections
        header.e_shnum += sections.len() as u16;

        // set section table start
        header.e_shoff = SIZEOF_EHDR as u64;

        // set section names index
        header.e_shstrndx = 1;

        file.write(&transmute::<_, [u8; SIZEOF_EHDR]>(header))?;

        // calculate where section data starts
        let section_contents_start =
            file.stream_position()? + header.e_shnum as u64 * section::SIZEOF_SHDR as u64;
        let mut section_contents_offset = section_contents_start;

        file.seek(SeekFrom::Start(section_contents_offset))?;
        section_names.hdr.sh_offset = section_contents_offset;

        // emit section names

        file.write(b"\x00")?;
        // write .shstrtab name
        section_names.hdr.sh_name = (file.stream_position()? - section_names.hdr.sh_offset) as u32;
        file.write(b".shstrtab\x00")?;

        let mut section_ordering: Vec<String> = Vec::new();
        for (name, section) in sections.iter_mut() {
            section_ordering.push(name.clone());
            section.hdr.sh_name = (file.stream_position()? - section_names.hdr.sh_offset) as u32;
            file.write(name.as_bytes())?;
            file.write(b"\x00")?;
        }
        file.write(b"\x00")?;

        section_contents_offset = file.stream_position()?;
        section_names.hdr.sh_size = section_contents_offset - section_names.hdr.sh_offset;

        // emit symbol names

        symbol_names.hdr.sh_offset = section_contents_offset;
        file.write(b"\x00")?;

        for (name, symbol) in symbols.iter_mut() {
            if let Some(section) = &symbol.section {
                symbol.hdr.st_shndx =
                    3 + section_ordering.iter().position(|n| n == section).unwrap() as u16;
            }
            symbol.hdr.st_name = (file.stream_position()? - symbol_names.hdr.sh_offset) as u32;
            file.write(name.as_bytes())?;
            file.write(b"\x00")?;
        }
        file.write(b"\x00")?;

        // fill out symtab contents

        sections.get_mut(".symtab").unwrap().raw = Some(
            symbols
                .values()
                .map(|sym| (&transmute::<_, [u8; symbol::SIZEOF_SYM]>(sym.hdr)).to_vec())
                .fold(vec![0u8; symbol::SIZEOF_SYM], |a, b| [a, b].concat()),
        );

        section_contents_offset = file.stream_position()?;
        symbol_names.hdr.sh_size = section_contents_offset - symbol_names.hdr.sh_offset;

        for (_, section) in sections.iter_mut() {
            file.seek(SeekFrom::Start(section_contents_offset))?;
            if let Some(raw) = &section.raw {
                file.write(raw.as_slice())?;
                section.hdr.sh_size = file.stream_position()? - section_contents_offset;
            }

            section.hdr.sh_offset = section_contents_offset;
            section_contents_offset = file.stream_position()?;
        }

        // seek to section headers
        file.seek(SeekFrom::Start(header.e_shoff))?;

        // write NULL section
        file.write(&transmute::<_, [u8; section::SIZEOF_SHDR]>(RawSection {
            ..Default::default()
        }))?;

        // write section names
        file.write(&transmute::<_, [u8; section::SIZEOF_SHDR]>(
            section_names.hdr,
        ))?;

        // write symbol names
        file.write(&transmute::<_, [u8; section::SIZEOF_SHDR]>(
            symbol_names.hdr,
        ))?;

        // write rest of sections
        for (_, section) in sections.iter() {
            // println!("section name: {}", name);
            // println!("section size: {}", section.hdr.sh_size);
            file.write(&transmute::<_, [u8; section::SIZEOF_SHDR]>(section.hdr))?;
        }

        Err::Ok(())
    }
}
