use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use gimli::write::{
    Address as DwarfAddress, AttributeValue, DwarfUnit, EndianVec, Expression, FileId, FileInfo,
    LineProgram, LineString, Location as DwarfLocation, LocationList, Range as DwarfRange,
    RangeList, RelocateWriter, Relocation as DwarfRelocation, RelocationTarget,
    Sections as DwarfSections, UnitEntryId,
};
use gimli::{Encoding, Format, LineEncoding, RunTimeEndian, SectionId as DwarfSectionId};
use object::elf::{EF_ARM_EABI_VER5, ELFOSABI_SYSV, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use object::write::{Object, Relocation, SectionId, Symbol, SymbolId, SymbolSection};
use object::{
    BinaryFormat, FileFlags, RelocationEncoding, RelocationFlags, RelocationKind, SectionFlags,
    SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use tempfile::NamedTempFile;

use crate::arch;
use crate::model::{
    Address, AddressRange, Architecture, Declaration, Document, LocationExpression, Scope,
    SignedOrUnsigned, Source, Type, Variable,
};

#[derive(Debug, Clone, Default)]
pub struct EmitOptions {
    /// Directory where generated source files are written.
    pub source_root: Option<PathBuf>,
    /// Directory recorded in DWARF when publication will atomically rename
    /// the materialized source tree to its final location.
    pub source_reference_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct EmitReport {
    pub output: PathBuf,
    pub source_root: PathBuf,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct RelocWriter {
    writer: EndianVec<RunTimeEndian>,
    relocations: Vec<DwarfRelocation>,
}

impl RelocWriter {
    fn new(endian: RunTimeEndian) -> Self {
        Self {
            writer: EndianVec::new(endian),
            relocations: Vec::new(),
        }
    }
}

impl RelocateWriter for RelocWriter {
    type Writer = EndianVec<RunTimeEndian>;

    fn writer(&self) -> &Self::Writer {
        &self.writer
    }

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }

    fn relocate(&mut self, relocation: DwarfRelocation) {
        self.relocations.push(relocation);
    }
}

#[derive(Debug, Clone)]
struct TargetSection {
    object_id: SectionId,
    object_symbol: SymbolId,
    address: u64,
    size: u64,
    dwarf_symbol: usize,
}

struct Emitter<'a> {
    document: &'a Document,
    dwarf: DwarfUnit,
    targets: HashMap<&'a str, TargetSection>,
    type_ids: HashMap<&'a str, UnitEntryId>,
    file_ids: HashMap<&'a str, FileId>,
    function_ids: HashMap<&'a str, UnitEntryId>,
    warnings: Vec<String>,
}

pub fn emit(document: &Document, output: &Path, options: &EmitOptions) -> Result<EmitReport> {
    document.validate()?;
    let output_parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_parent).with_context(|| {
        format!(
            "failed to create output directory {}",
            output_parent.display()
        )
    })?;
    let source_root = options.source_root.clone().unwrap_or_else(|| {
        let stem = output
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("teemo");
        output_parent.join(format!("{stem}.sources"))
    });
    materialize_sources(&document.sources, &source_root)?;
    let source_reference_root = options
        .source_reference_root
        .as_ref()
        .unwrap_or(&source_root);

    let mut object = Object::new(
        BinaryFormat::Elf,
        arch::object_architecture(document.binary.architecture),
        arch::object_endianness(document.binary.endianness),
    );
    object.flags = FileFlags::Elf {
        os_abi: ELFOSABI_SYSV,
        abi_version: 0,
        e_flags: if document.binary.architecture == Architecture::Arm {
            EF_ARM_EABI_VER5
        } else {
            0
        },
    };

    let targets = add_target_sections(document, &mut object)?;
    add_object_symbols(document, &targets, &mut object)?;

    let source_root_string = source_reference_root.to_str().ok_or_else(|| {
        anyhow!(
            "source reference root is not valid UTF-8: {}",
            source_reference_root.display()
        )
    })?;
    let mut emitter = Emitter::new(document, targets, source_root_string)?;
    emitter.emit_types()?;
    emitter.emit_globals()?;
    emitter.emit_functions()?;
    emitter.emit_labels()?;
    emitter.emit_lines()?;

    let endian = arch::gimli_endianness(document.binary.endianness);
    let mut dwarf_sections = DwarfSections::new(RelocWriter::new(endian));
    emitter.dwarf.write(&mut dwarf_sections)?;
    add_dwarf_sections(&mut object, &dwarf_sections, &emitter.targets)?;

    let bytes = object
        .write()
        .context("failed to serialize ELF debug object")?;
    atomic_write(output, &bytes)?;

    Ok(EmitReport {
        output: output.to_path_buf(),
        source_root,
        warnings: emitter.warnings,
    })
}

fn add_target_sections<'a>(
    document: &'a Document,
    object: &mut Object<'_>,
) -> Result<HashMap<&'a str, TargetSection>> {
    let mut targets = HashMap::new();
    for (dwarf_symbol, section) in document.sections.iter().enumerate() {
        // NOBITS keeps the debug companion small even for a large analyzed image.
        // GDB assigns runtime addresses to these sections via add-symbol-file.
        let object_id = object.add_section(
            Vec::new(),
            section.name.as_bytes().to_vec(),
            SectionKind::UninitializedData,
        );
        let mut flags = SHF_ALLOC as u64;
        if section.writable {
            flags |= SHF_WRITE as u64;
        }
        if section.executable {
            flags |= SHF_EXECINSTR as u64;
        }
        object.section_mut(object_id).flags = SectionFlags::Elf { sh_flags: flags };
        object.append_section_bss(object_id, section.size, 1);
        let object_symbol = object.section_symbol(object_id);
        targets.insert(
            section.id.as_str(),
            TargetSection {
                object_id,
                object_symbol,
                address: section.address,
                size: section.size,
                dwarf_symbol,
            },
        );
    }
    Ok(targets)
}

fn add_object_symbols(
    document: &Document,
    targets: &HashMap<&str, TargetSection>,
    object: &mut Object<'_>,
) -> Result<()> {
    for function in &document.functions {
        let Some(first) = function.ranges.first() else {
            continue;
        };
        let Some(section_id) = first.start.section.as_deref() else {
            continue;
        };
        let target = targets
            .get(section_id)
            .ok_or_else(|| anyhow!("function {:?} references missing section", function.id))?;
        let name = function.linkage_name.as_ref().unwrap_or(&function.name);
        let size = function.ranges.iter().filter_map(AddressRange::len).sum();
        object.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: first.start.value - target.address,
            size,
            kind: SymbolKind::Text,
            scope: if function.external {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Compilation
            },
            weak: false,
            section: SymbolSection::Section(target.object_id),
            flags: SymbolFlags::None,
        });
    }
    for global in &document.globals {
        let Some(LocationExpression::Address { address }) = &global.static_location else {
            continue;
        };
        let Some(section_id) = address.section.as_deref() else {
            continue;
        };
        let target = targets
            .get(section_id)
            .ok_or_else(|| anyhow!("global {:?} references missing section", global.id))?;
        let name = global.linkage_name.as_ref().unwrap_or(&global.name);
        object.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: address.value - target.address,
            size: 0,
            kind: SymbolKind::Data,
            scope: if global.external {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Compilation
            },
            weak: false,
            section: SymbolSection::Section(target.object_id),
            flags: SymbolFlags::None,
        });
    }
    for label in &document.labels {
        let Some(section_id) = label.address.section.as_deref() else {
            continue;
        };
        let target = targets
            .get(section_id)
            .ok_or_else(|| anyhow!("label {:?} references missing section", label.id))?;
        object.add_symbol(Symbol {
            name: label.name.as_bytes().to_vec(),
            value: label.address.value - target.address,
            size: 0,
            kind: SymbolKind::Label,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(target.object_id),
            flags: SymbolFlags::None,
        });
    }
    Ok(())
}

impl<'a> Emitter<'a> {
    fn new(
        document: &'a Document,
        targets: HashMap<&'a str, TargetSection>,
        source_root: &str,
    ) -> Result<Self> {
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: document.binary.address_size,
        };
        let mut dwarf = DwarfUnit::new(encoding);
        let root = dwarf.unit.root();

        set_string(&mut dwarf, root, gimli::DW_AT_producer, &document.producer);
        set_string(
            &mut dwarf,
            root,
            gimli::DW_AT_name,
            &format!("{}.teemo.c", document.binary.filename),
        );
        set_string(&mut dwarf, root, gimli::DW_AT_comp_dir, source_root);
        let language = if document
            .types
            .iter()
            .any(|ty| matches!(ty, Type::Class { .. }))
        {
            gimli::DW_LANG_C_plus_plus_14
        } else {
            gimli::DW_LANG_C11
        };
        dwarf
            .unit
            .get_mut(root)
            .set(gimli::DW_AT_language, AttributeValue::Language(language));

        let primary_path = document
            .sources
            .first()
            .map(|source| source.path.as_str())
            .unwrap_or("teemo-generated.c");
        dwarf.unit.line_program = LineProgram::new(
            encoding,
            LineEncoding::default(),
            LineString::String(source_root.as_bytes().to_vec()),
            None,
            LineString::String(primary_path.as_bytes().to_vec()),
            None,
        );
        dwarf.unit.line_program.file_has_source = true;
        let directory = dwarf.unit.line_program.default_directory();
        let mut file_ids = HashMap::new();
        for source in &document.sources {
            let file_id = dwarf.unit.line_program.add_file(
                LineString::String(source.path.as_bytes().to_vec()),
                directory,
                Some(FileInfo {
                    timestamp: 0,
                    size: source.contents.len() as u64,
                    md5: [0; 16],
                    source: Some(LineString::String(source.contents.as_bytes().to_vec())),
                }),
            );
            file_ids.insert(source.id.as_str(), file_id);
        }

        Ok(Self {
            document,
            dwarf,
            targets,
            type_ids: HashMap::new(),
            file_ids,
            function_ids: HashMap::new(),
            warnings: Vec::new(),
        })
    }

    fn emit_types(&mut self) -> Result<()> {
        let root = self.dwarf.unit.root();
        for ty in &self.document.types {
            let tag = match ty {
                Type::Base { .. } => gimli::DW_TAG_base_type,
                Type::Pointer { .. } => gimli::DW_TAG_pointer_type,
                Type::Array { .. } => gimli::DW_TAG_array_type,
                Type::Structure { .. } => gimli::DW_TAG_structure_type,
                Type::Class { .. } => gimli::DW_TAG_class_type,
                Type::Union { .. } => gimli::DW_TAG_union_type,
                Type::Enum { .. } => gimli::DW_TAG_enumeration_type,
                Type::Typedef { .. } => gimli::DW_TAG_typedef,
                Type::Qualified { qualifier, .. } => match qualifier.as_str() {
                    "const" => gimli::DW_TAG_const_type,
                    "volatile" => gimli::DW_TAG_volatile_type,
                    "restrict" => gimli::DW_TAG_restrict_type,
                    "atomic" => gimli::DW_TAG_atomic_type,
                    _ => unreachable!("validated qualifier"),
                },
                Type::Function { .. } => gimli::DW_TAG_subroutine_type,
            };
            let entry = self.dwarf.unit.add(root, tag);
            self.type_ids.insert(ty.id(), entry);
        }
        for ty in &self.document.types {
            self.emit_type(ty)?;
        }
        Ok(())
    }

    fn emit_type(&mut self, ty: &Type) -> Result<()> {
        let id = self.type_id(ty.id())?;
        match ty {
            Type::Base {
                name,
                byte_size,
                encoding,
                ..
            } => {
                self.set_optional_name(id, name.as_deref());
                self.dwarf
                    .unit
                    .get_mut(id)
                    .set(gimli::DW_AT_byte_size, AttributeValue::Udata(*byte_size));
                let encoding = match encoding.as_str() {
                    "address" => gimli::DW_ATE_address,
                    "boolean" => gimli::DW_ATE_boolean,
                    "complex_float" => gimli::DW_ATE_complex_float,
                    "float" => gimli::DW_ATE_float,
                    "signed" => gimli::DW_ATE_signed,
                    "signed_char" => gimli::DW_ATE_signed_char,
                    "unsigned" => gimli::DW_ATE_unsigned,
                    "unsigned_char" => gimli::DW_ATE_unsigned_char,
                    "utf" => gimli::DW_ATE_UTF,
                    _ => unreachable!("validated base encoding"),
                };
                self.dwarf
                    .unit
                    .get_mut(id)
                    .set(gimli::DW_AT_encoding, AttributeValue::Encoding(encoding));
            }
            Type::Pointer {
                name,
                byte_size,
                target,
                ..
            } => {
                self.set_optional_name(id, name.as_deref());
                self.dwarf
                    .unit
                    .get_mut(id)
                    .set(gimli::DW_AT_byte_size, AttributeValue::Udata(*byte_size));
                self.set_optional_type(id, target.as_deref())?;
            }
            Type::Array {
                name,
                byte_size,
                element_type,
                dimensions,
                ..
            } => {
                self.set_optional_name(id, name.as_deref());
                if let Some(byte_size) = byte_size {
                    self.dwarf
                        .unit
                        .get_mut(id)
                        .set(gimli::DW_AT_byte_size, AttributeValue::Udata(*byte_size));
                }
                self.set_type(id, element_type)?;
                for dimension in dimensions {
                    let child = self.dwarf.unit.add(id, gimli::DW_TAG_subrange_type);
                    self.dwarf.unit.get_mut(child).set(
                        gimli::DW_AT_lower_bound,
                        AttributeValue::Sdata(dimension.lower_bound),
                    );
                    if let Some(count) = dimension.count {
                        self.dwarf
                            .unit
                            .get_mut(child)
                            .set(gimli::DW_AT_count, AttributeValue::Udata(count));
                    }
                }
            }
            Type::Structure {
                name,
                byte_size,
                declaration_only,
                declaration,
                members,
                bases,
                ..
            }
            | Type::Class {
                name,
                byte_size,
                declaration_only,
                declaration,
                members,
                bases,
                ..
            } => {
                self.set_optional_name(id, name.as_deref());
                if let Some(byte_size) = byte_size {
                    self.dwarf
                        .unit
                        .get_mut(id)
                        .set(gimli::DW_AT_byte_size, AttributeValue::Udata(*byte_size));
                }
                if *declaration_only {
                    self.dwarf
                        .unit
                        .get_mut(id)
                        .set(gimli::DW_AT_declaration, AttributeValue::Flag(true));
                }
                self.set_declaration(id, declaration.as_ref());
                for base in bases {
                    let child = self.dwarf.unit.add(id, gimli::DW_TAG_inheritance);
                    self.set_type(child, &base.type_id)?;
                    self.dwarf.unit.get_mut(child).set(
                        gimli::DW_AT_data_member_location,
                        AttributeValue::Udata(base.offset),
                    );
                }
                self.emit_members(id, members)?;
            }
            Type::Union {
                name,
                byte_size,
                declaration_only,
                declaration,
                members,
                ..
            } => {
                self.set_optional_name(id, name.as_deref());
                if let Some(byte_size) = byte_size {
                    self.dwarf
                        .unit
                        .get_mut(id)
                        .set(gimli::DW_AT_byte_size, AttributeValue::Udata(*byte_size));
                }
                if *declaration_only {
                    self.dwarf
                        .unit
                        .get_mut(id)
                        .set(gimli::DW_AT_declaration, AttributeValue::Flag(true));
                }
                self.set_declaration(id, declaration.as_ref());
                self.emit_members(id, members)?;
            }
            Type::Enum {
                name,
                byte_size,
                underlying_type,
                declaration,
                enumerators,
                ..
            } => {
                self.set_optional_name(id, name.as_deref());
                self.dwarf
                    .unit
                    .get_mut(id)
                    .set(gimli::DW_AT_byte_size, AttributeValue::Udata(*byte_size));
                self.set_optional_type(id, underlying_type.as_deref())?;
                self.set_declaration(id, declaration.as_ref());
                for enumerator in enumerators {
                    let child = self.dwarf.unit.add(id, gimli::DW_TAG_enumerator);
                    self.set_optional_name(child, Some(&enumerator.name));
                    let value = match enumerator.value.parse().map_err(anyhow::Error::msg)? {
                        SignedOrUnsigned::Signed(value) => AttributeValue::Sdata(value),
                        SignedOrUnsigned::Unsigned(value) => AttributeValue::Udata(value),
                    };
                    self.dwarf
                        .unit
                        .get_mut(child)
                        .set(gimli::DW_AT_const_value, value);
                }
            }
            Type::Typedef {
                name,
                target,
                declaration,
                ..
            } => {
                self.set_optional_name(id, Some(name));
                self.set_type(id, target)?;
                self.set_declaration(id, declaration.as_ref());
            }
            Type::Qualified { target, .. } => self.set_type(id, target)?,
            Type::Function {
                name,
                return_type,
                parameters,
                variadic,
                calling_convention,
                ..
            } => {
                self.set_optional_name(id, name.as_deref());
                self.set_optional_type(id, return_type.as_deref())?;
                self.dwarf
                    .unit
                    .get_mut(id)
                    .set(gimli::DW_AT_prototyped, AttributeValue::Flag(true));
                if calling_convention.is_some() {
                    self.dwarf.unit.get_mut(id).set(
                        gimli::DW_AT_calling_convention,
                        AttributeValue::CallingConvention(gimli::DW_CC_normal),
                    );
                }
                for parameter in parameters {
                    let child = self.dwarf.unit.add(id, gimli::DW_TAG_formal_parameter);
                    self.set_optional_name(child, parameter.name.as_deref());
                    self.set_optional_type(child, parameter.type_id.as_deref())?;
                    if parameter.artificial {
                        self.dwarf
                            .unit
                            .get_mut(child)
                            .set(gimli::DW_AT_artificial, AttributeValue::Flag(true));
                    }
                }
                if *variadic {
                    self.dwarf
                        .unit
                        .add(id, gimli::DW_TAG_unspecified_parameters);
                }
            }
        }
        Ok(())
    }

    fn emit_members(
        &mut self,
        parent: UnitEntryId,
        members: &[crate::model::Member],
    ) -> Result<()> {
        for member in members {
            let child = self.dwarf.unit.add(parent, gimli::DW_TAG_member);
            self.set_optional_name(child, Some(&member.name));
            self.set_optional_type(child, member.type_id.as_deref())?;
            self.dwarf.unit.get_mut(child).set(
                gimli::DW_AT_data_member_location,
                AttributeValue::Udata(member.offset),
            );
            if let Some(bit_size) = member.bit_size {
                self.dwarf
                    .unit
                    .get_mut(child)
                    .set(gimli::DW_AT_bit_size, AttributeValue::Udata(bit_size));
            }
            if let Some(bit_offset) = member.bit_offset {
                self.dwarf.unit.get_mut(child).set(
                    gimli::DW_AT_data_bit_offset,
                    AttributeValue::Udata(bit_offset),
                );
            }
        }
        Ok(())
    }

    fn emit_globals(&mut self) -> Result<()> {
        let root = self.dwarf.unit.root();
        for variable in &self.document.globals {
            let id = self.dwarf.unit.add(root, gimli::DW_TAG_variable);
            self.emit_variable_attributes(id, variable)?;
        }
        Ok(())
    }

    fn emit_functions(&mut self) -> Result<()> {
        let root = self.dwarf.unit.root();
        for function in &self.document.functions {
            let id = self.dwarf.unit.add(root, gimli::DW_TAG_subprogram);
            self.function_ids.insert(function.id.as_str(), id);
            self.set_optional_name(id, Some(&function.name));
            if let Some(linkage_name) = &function.linkage_name {
                set_string(&mut self.dwarf, id, gimli::DW_AT_linkage_name, linkage_name);
            }
            self.set_optional_type(id, function.return_type.as_deref())?;
            self.set_ranges(id, &function.ranges)?;
            self.set_declaration(id, function.declaration.as_ref());
            self.dwarf
                .unit
                .get_mut(id)
                .set(gimli::DW_AT_prototyped, AttributeValue::Flag(true));
            self.dwarf.unit.get_mut(id).set(
                gimli::DW_AT_external,
                AttributeValue::Flag(function.external),
            );
            if function.calling_convention.is_some() {
                self.dwarf.unit.get_mut(id).set(
                    gimli::DW_AT_calling_convention,
                    AttributeValue::CallingConvention(gimli::DW_CC_normal),
                );
            }
            let mut frame_base = Expression::new();
            frame_base.op(gimli::DW_OP_call_frame_cfa);
            self.dwarf
                .unit
                .get_mut(id)
                .set(gimli::DW_AT_frame_base, AttributeValue::Exprloc(frame_base));

            for parameter in &function.parameters {
                let child = self.dwarf.unit.add(id, gimli::DW_TAG_formal_parameter);
                self.emit_variable_attributes(child, parameter)?;
            }
            if function.variadic {
                self.dwarf
                    .unit
                    .add(id, gimli::DW_TAG_unspecified_parameters);
            }
            for variable in &function.scope.variables {
                let child = self.dwarf.unit.add(id, gimli::DW_TAG_variable);
                self.emit_variable_attributes(child, variable)?;
            }
            for scope in &function.scope.children {
                self.emit_scope(id, scope)?;
            }
        }
        Ok(())
    }

    fn emit_labels(&mut self) -> Result<()> {
        let root = self.dwarf.unit.root();
        for label in &self.document.labels {
            let parent = label
                .function_id
                .as_deref()
                .and_then(|id| self.function_ids.get(id).copied())
                .unwrap_or(root);
            let id = self.dwarf.unit.add(parent, gimli::DW_TAG_label);
            self.set_optional_name(id, Some(&label.name));
            let address = self.dwarf_address(&label.address)?;
            self.dwarf
                .unit
                .get_mut(id)
                .set(gimli::DW_AT_low_pc, AttributeValue::Address(address));
            self.set_declaration(id, label.declaration.as_ref());
        }
        Ok(())
    }

    fn emit_scope(&mut self, parent: UnitEntryId, scope: &Scope) -> Result<()> {
        let id = self.dwarf.unit.add(parent, gimli::DW_TAG_lexical_block);
        self.set_ranges(id, &scope.ranges)?;
        for variable in &scope.variables {
            let child = self.dwarf.unit.add(id, gimli::DW_TAG_variable);
            self.emit_variable_attributes(child, variable)?;
        }
        for child in &scope.children {
            self.emit_scope(id, child)?;
        }
        Ok(())
    }

    fn emit_variable_attributes(&mut self, id: UnitEntryId, variable: &Variable) -> Result<()> {
        self.set_optional_name(id, Some(&variable.name));
        if let Some(linkage_name) = &variable.linkage_name {
            set_string(&mut self.dwarf, id, gimli::DW_AT_linkage_name, linkage_name);
        }
        self.set_optional_type(id, variable.type_id.as_deref())?;
        self.set_declaration(id, variable.declaration.as_ref());
        if variable.external {
            self.dwarf
                .unit
                .get_mut(id)
                .set(gimli::DW_AT_external, AttributeValue::Flag(true));
        }

        if let Some(location) = &variable.static_location {
            match self.location_expression(location) {
                Ok(Some(expression)) => self
                    .dwarf
                    .unit
                    .get_mut(id)
                    .set(gimli::DW_AT_location, AttributeValue::Exprloc(expression)),
                Ok(None) => {}
                Err(error) => self.warnings.push(format!(
                    "omitting static location for variable {:?}: {error:#}",
                    variable.id
                )),
            }
        }

        let mut locations = Vec::new();
        for location in &variable.locations {
            if !location.expression.is_available() {
                continue;
            }
            let expression = match self.location_expression(&location.expression) {
                Ok(Some(expression)) => expression,
                Ok(None) => continue,
                Err(error) => {
                    self.warnings.push(format!(
                        "omitting location for variable {:?} at {:#x}: {error:#}",
                        variable.id, location.range.start.value
                    ));
                    continue;
                }
            };
            locations.push(DwarfLocation::StartLength {
                begin: self.dwarf_address(&location.range.start)?,
                length: location.range.len().expect("validated range"),
                data: expression,
            });
        }
        if !locations.is_empty() {
            let location_id = self.dwarf.unit.locations.add(LocationList(locations));
            self.dwarf.unit.get_mut(id).set(
                gimli::DW_AT_location,
                AttributeValue::LocationListRef(location_id),
            );
        }
        Ok(())
    }

    fn location_expression(&self, location: &LocationExpression) -> Result<Option<Expression>> {
        let mut output = Expression::new();
        match location {
            LocationExpression::Register { register } => {
                output.op_reg(arch::register(self.document.binary.architecture, register)?)
            }
            LocationExpression::FrameOffset { offset } => output.op_fbreg(*offset),
            LocationExpression::CfaOffset { offset } => {
                output.op(gimli::DW_OP_call_frame_cfa);
                if *offset >= 0 {
                    output.op_plus_uconst(*offset as u64);
                } else {
                    output.op_consts(*offset);
                    output.op(gimli::DW_OP_plus);
                }
            }
            LocationExpression::Address { address } => {
                output.op_addr(self.dwarf_address(address)?);
            }
            LocationExpression::Constant { value } => output.op_consts(*value),
            LocationExpression::EntryValue { expression } => {
                let Some(nested) = self.location_expression(expression)? else {
                    return Ok(None);
                };
                output.op_entry_value(nested);
            }
            LocationExpression::StackValue { expression } => {
                let Some(mut nested) = self.location_expression(expression)? else {
                    return Ok(None);
                };
                nested.op(gimli::DW_OP_stack_value);
                return Ok(Some(nested));
            }
            LocationExpression::Dereference { expression } => {
                let Some(mut nested) = self.location_expression(expression)? else {
                    return Ok(None);
                };
                nested.op_deref();
                return Ok(Some(nested));
            }
            LocationExpression::Unavailable { .. } => return Ok(None),
        }
        Ok(Some(output))
    }

    fn emit_lines(&mut self) -> Result<()> {
        let mut lines: Vec<_> = self.document.lines.iter().collect();
        lines.sort_by_key(|line| {
            (
                line.range.start.section.as_deref().unwrap_or(""),
                line.range.start.value,
                line.discriminator,
                line.line,
            )
        });
        let mut index = 0;
        while index < lines.len() {
            let first = lines[index];
            let sequence_section = first.range.start.section.as_deref();
            let sequence_start = first.range.start.value;
            let mut sequence_end = first.range.end.value;
            self.dwarf
                .unit
                .line_program
                .begin_sequence(Some(self.dwarf_address(&first.range.start)?));

            while index < lines.len() {
                let line = lines[index];
                if line.range.start.section.as_deref() != sequence_section
                    || line.range.start.value > sequence_end
                {
                    break;
                }
                let file_id = *self
                    .file_ids
                    .get(line.source_id.as_str())
                    .ok_or_else(|| anyhow!("missing line file id for {:?}", line.source_id))?;
                let row = self.dwarf.unit.line_program.row();
                row.address_offset = line.range.start.value - sequence_start;
                row.file = file_id;
                row.line = line.line;
                row.column = line.column;
                row.discriminator = line.discriminator;
                row.is_statement = line.statement;
                self.dwarf.unit.line_program.generate_row();
                sequence_end = sequence_end.max(line.range.end.value);
                index += 1;
            }
            self.dwarf
                .unit
                .line_program
                .end_sequence(sequence_end - sequence_start);
        }
        Ok(())
    }

    fn set_ranges(&mut self, id: UnitEntryId, ranges: &[AddressRange]) -> Result<()> {
        if ranges.len() == 1 {
            let range = &ranges[0];
            let address = self.dwarf_address(&range.start)?;
            self.dwarf
                .unit
                .get_mut(id)
                .set(gimli::DW_AT_low_pc, AttributeValue::Address(address));
            self.dwarf.unit.get_mut(id).set(
                gimli::DW_AT_high_pc,
                AttributeValue::Udata(range.len().expect("validated range")),
            );
        } else {
            let mut dwarf_ranges = Vec::new();
            for range in ranges {
                dwarf_ranges.push(DwarfRange::StartLength {
                    begin: self.dwarf_address(&range.start)?,
                    length: range.len().expect("validated range"),
                });
            }
            let range_id = self.dwarf.unit.ranges.add(RangeList(dwarf_ranges));
            self.dwarf
                .unit
                .get_mut(id)
                .set(gimli::DW_AT_ranges, AttributeValue::RangeListRef(range_id));
        }
        Ok(())
    }

    fn dwarf_address(&self, address: &Address) -> Result<DwarfAddress> {
        if let Some(section_id) = address.section.as_deref() {
            let target = self
                .targets
                .get(section_id)
                .ok_or_else(|| anyhow!("address references missing section {section_id:?}"))?;
            let offset = address
                .value
                .checked_sub(target.address)
                .ok_or_else(|| anyhow!("address precedes section {section_id:?}"))?;
            if offset > target.size {
                bail!("address exceeds section {section_id:?}");
            }
            Ok(DwarfAddress::Symbol {
                symbol: target.dwarf_symbol,
                addend: i64::try_from(offset).context("section offset does not fit in i64")?,
            })
        } else {
            Ok(DwarfAddress::Constant(address.value))
        }
    }

    fn type_id(&self, id: &str) -> Result<UnitEntryId> {
        self.type_ids
            .get(id)
            .copied()
            .ok_or_else(|| anyhow!("missing type DIE for {id:?}"))
    }

    fn set_type(&mut self, id: UnitEntryId, type_id: &str) -> Result<()> {
        let type_id = self.type_id(type_id)?;
        self.dwarf
            .unit
            .get_mut(id)
            .set(gimli::DW_AT_type, AttributeValue::UnitRef(type_id));
        Ok(())
    }

    fn set_optional_type(&mut self, id: UnitEntryId, type_id: Option<&str>) -> Result<()> {
        if let Some(type_id) = type_id {
            self.set_type(id, type_id)?;
        }
        Ok(())
    }

    fn set_optional_name(&mut self, id: UnitEntryId, name: Option<&str>) {
        if let Some(name) = name.filter(|name| !name.is_empty()) {
            set_string(&mut self.dwarf, id, gimli::DW_AT_name, name);
        }
    }

    fn set_declaration(&mut self, id: UnitEntryId, declaration: Option<&Declaration>) {
        let Some(declaration) = declaration else {
            return;
        };
        let Some(file) = self.file_ids.get(declaration.source_id.as_str()).copied() else {
            return;
        };
        self.dwarf.unit.get_mut(id).set(
            gimli::DW_AT_decl_file,
            AttributeValue::FileIndex(Some(file)),
        );
        self.dwarf.unit.get_mut(id).set(
            gimli::DW_AT_decl_line,
            AttributeValue::Udata(declaration.line),
        );
        if declaration.column != 0 {
            self.dwarf.unit.get_mut(id).set(
                gimli::DW_AT_decl_column,
                AttributeValue::Udata(declaration.column),
            );
        }
    }
}

fn set_string(dwarf: &mut DwarfUnit, id: UnitEntryId, attribute: gimli::DwAt, value: &str) {
    let string = dwarf.strings.add(value.as_bytes().to_vec());
    dwarf
        .unit
        .get_mut(id)
        .set(attribute, AttributeValue::StringRef(string));
}

fn add_dwarf_sections(
    object: &mut Object<'_>,
    dwarf: &DwarfSections<RelocWriter>,
    targets: &HashMap<&str, TargetSection>,
) -> Result<()> {
    let mut section_ids = HashMap::<DwarfSectionId, SectionId>::new();
    dwarf.for_each(|id, section| -> Result<()> {
        if section.writer.slice().is_empty() {
            return Ok(());
        }
        let kind = if id == DwarfSectionId::DebugStr || id == DwarfSectionId::DebugLineStr {
            SectionKind::DebugString
        } else {
            SectionKind::Debug
        };
        let object_id = object.add_section(Vec::new(), id.name().as_bytes().to_vec(), kind);
        object.set_section_data(object_id, section.writer.slice().to_vec(), 1);
        section_ids.insert(id, object_id);
        Ok(())
    })?;

    let mut target_symbols: Vec<_> = targets.values().collect();
    target_symbols.sort_by_key(|target| target.dwarf_symbol);
    dwarf.for_each(|id, section| -> Result<()> {
        let Some(object_section) = section_ids.get(&id).copied() else {
            return Ok(());
        };
        for relocation in &section.relocations {
            if relocation.eh_pe.is_some() {
                bail!("EH pointer relocations are not supported in Teemo debug objects");
            }
            let symbol = match relocation.target {
                RelocationTarget::Symbol(index) => {
                    target_symbols
                        .get(index)
                        .ok_or_else(|| anyhow!("invalid target symbol relocation {index}"))?
                        .object_symbol
                }
                RelocationTarget::Section(target) => {
                    let target_section = section_ids.get(&target).copied().ok_or_else(|| {
                        anyhow!(
                            "relocation references absent DWARF section {}",
                            target.name()
                        )
                    })?;
                    object.section_symbol(target_section)
                }
            };
            object.add_relocation(
                object_section,
                Relocation {
                    offset: relocation.offset as u64,
                    symbol,
                    addend: relocation.addend,
                    flags: RelocationFlags::Generic {
                        kind: RelocationKind::Absolute,
                        encoding: RelocationEncoding::Generic,
                        size: relocation.size * 8,
                    },
                },
            )?;
        }
        Ok(())
    })?;
    Ok(())
}

fn materialize_sources(sources: &[Source], source_root: &Path) -> Result<()> {
    fs::create_dir_all(source_root)
        .with_context(|| format!("failed to create source root {}", source_root.display()))?;
    for source in sources {
        let relative = safe_relative_path(&source.path)?;
        let destination = source_root.join(relative);
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow!("source path has no parent: {}", destination.display()))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create source directory {}", parent.display()))?;
        atomic_write(&destination, source.contents.as_bytes())?;
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("generated source path must be non-empty and relative: {path:?}");
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            bail!("generated source path contains an unsafe component: {path:?}");
        }
    }
    Ok(path.to_path_buf())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    temporary
        .write_all(contents)
        .with_context(|| format!("failed to write temporary output for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temporary output for {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to publish {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Binary, Endianness, Function, Label, Line, Location, Scope, Section, Source, Type,
    };
    use object::Object as _;

    fn address(value: u64) -> Address {
        Address {
            value,
            section: Some("text".into()),
        }
    }

    fn range(start: u64, end: u64) -> AddressRange {
        AddressRange {
            start: address(start),
            end: address(end),
        }
    }

    fn document(architecture: Architecture, endianness: Endianness) -> Document {
        let base = 0x1000;
        let register = match architecture {
            Architecture::X86_64 => "rdi",
            Architecture::X86 => "eax",
            Architecture::Arm => "r0",
            Architecture::Aarch64 => "x0",
        };
        Document {
            schema: crate::model::SCHEMA_NAME.into(),
            version: crate::model::SCHEMA_VERSION,
            producer: "teemo test".into(),
            binary: Binary {
                filename: "fixture".into(),
                build_id: None,
                format: "elf".into(),
                architecture,
                endianness,
                address_size: architecture.address_size(),
                entry_point: base,
                image_base: 0,
            },
            sections: vec![Section {
                id: "text".into(),
                name: ".text".into(),
                address: base,
                size: 0x100,
                readable: true,
                writable: false,
                executable: true,
            }],
            types: vec![Type::Base {
                id: "int".into(),
                name: Some("int".into()),
                byte_size: 4,
                encoding: "signed".into(),
            }],
            globals: Vec::new(),
            functions: vec![Function {
                id: "main".into(),
                name: "main".into(),
                linkage_name: None,
                ranges: vec![range(base, base + 0x20)],
                return_type: Some("int".into()),
                parameters: vec![Variable {
                    id: "argc".into(),
                    name: "argc".into(),
                    linkage_name: None,
                    kind: "parameter".into(),
                    type_id: Some("int".into()),
                    declaration: None,
                    locations: vec![
                        Location {
                            range: range(base, base + 8),
                            expression: LocationExpression::Register {
                                register: register.into(),
                            },
                        },
                        Location {
                            range: range(base + 8, base + 0x20),
                            expression: LocationExpression::Unavailable {
                                reason: Some("entry storage no longer proven".into()),
                            },
                        },
                    ],
                    static_location: None,
                    external: false,
                }],
                scope: Scope {
                    id: "main.scope".into(),
                    ranges: vec![range(base, base + 0x20)],
                    variables: Vec::new(),
                    children: Vec::new(),
                },
                variadic: false,
                external: true,
                declaration: None,
                calling_convention: Some("cdecl".into()),
            }],
            labels: vec![Label {
                id: "main.loop".into(),
                name: "loop_body".into(),
                address: address(base + 0x10),
                function_id: Some("main".into()),
                declaration: None,
            }],
            sources: vec![Source {
                id: "main.c".into(),
                path: "teemo/main.c".into(),
                language: "c".into(),
                generated: true,
                contents: "int main(int argc) { return argc; }\n".into(),
            }],
            lines: vec![Line {
                range: range(base, base + 0x20),
                source_id: "main.c".into(),
                line: 1,
                column: 1,
                statement: true,
                discriminator: 0,
            }],
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn emits_all_required_architectures() {
        for architecture in [
            Architecture::X86_64,
            Architecture::X86,
            Architecture::Arm,
            Architecture::Aarch64,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("fixture.debug");
            let report = emit(
                &document(architecture, Endianness::Little),
                &output,
                &EmitOptions::default(),
            )
            .unwrap();
            assert!(report.warnings.is_empty(), "{:?}", report.warnings);
            assert!(report.source_root.join("teemo/main.c").is_file());
            let bytes = fs::read(&output).unwrap();
            let file = object::File::parse(bytes.as_slice()).unwrap();
            assert_eq!(file.format(), BinaryFormat::Elf);
            assert!(file.section_by_name(".debug_info").is_some());
            assert!(file.section_by_name(".debug_line").is_some());
            assert!(file.section_by_name(".debug_loclists").is_some());
            assert_eq!(file.architecture(), arch::object_architecture(architecture));

            if command_exists("llvm-dwarfdump") {
                let verification = std::process::Command::new("llvm-dwarfdump")
                    .args(["--verify", output.to_str().unwrap()])
                    .output()
                    .unwrap();
                assert!(
                    verification.status.success(),
                    "llvm-dwarfdump rejected {architecture:?}:\n{}\n{}",
                    String::from_utf8_lossy(&verification.stdout),
                    String::from_utf8_lossy(&verification.stderr)
                );
            }
            if command_exists("gdb-multiarch") {
                let command = format!("add-symbol-file {} 0x1000", output.display());
                let gdb = std::process::Command::new("gdb-multiarch")
                    .args([
                        "-q",
                        "-nx",
                        "-batch",
                        "-ex",
                        &command,
                        "-ex",
                        "info address main",
                        "-ex",
                        "info line *0x1000",
                    ])
                    .output()
                    .unwrap();
                assert!(
                    gdb.status.success(),
                    "GDB rejected {architecture:?}:\n{}\n{}",
                    String::from_utf8_lossy(&gdb.stdout),
                    String::from_utf8_lossy(&gdb.stderr)
                );
                let stdout = String::from_utf8_lossy(&gdb.stdout);
                assert!(stdout.contains("function at address 0x1000"), "{stdout}");
                assert!(stdout.contains("teemo/main.c"), "{stdout}");
            }
        }
    }

    #[test]
    fn emits_big_endian_arm_variants() {
        for architecture in [Architecture::Arm, Architecture::Aarch64] {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("fixture-be.debug");
            emit(
                &document(architecture, Endianness::Big),
                &output,
                &EmitOptions::default(),
            )
            .unwrap();
            let bytes = fs::read(&output).unwrap();
            let file = object::File::parse(bytes.as_slice()).unwrap();
            assert_eq!(file.endianness(), object::Endianness::Big);
            if command_exists("llvm-dwarfdump") {
                let verification = std::process::Command::new("llvm-dwarfdump")
                    .args(["--verify", output.to_str().unwrap()])
                    .output()
                    .unwrap();
                assert!(
                    verification.status.success(),
                    "llvm-dwarfdump rejected big-endian {architecture:?}:\n{}\n{}",
                    String::from_utf8_lossy(&verification.stdout),
                    String::from_utf8_lossy(&verification.stderr)
                );
            }
        }
    }

    fn command_exists(command: &str) -> bool {
        std::process::Command::new(command)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[test]
    fn rejects_unsafe_source_paths() {
        assert!(safe_relative_path("../escape.c").is_err());
        assert!(safe_relative_path("/escape.c").is_err());
        assert!(safe_relative_path("generated/main.c").is_ok());
    }

    #[test]
    fn records_the_committed_source_path_while_emitting_in_staging() {
        let temporary = tempfile::tempdir().unwrap();
        let staging = temporary.path().join("staging");
        let output = staging.join("teemo.debug");
        let materialized = staging.join("teemo.sources");
        let committed = temporary.path().join("generations/7/teemo.sources");
        let report = emit(
            &document(Architecture::X86_64, Endianness::Little),
            &output,
            &EmitOptions {
                source_root: Some(materialized.clone()),
                source_reference_root: Some(committed.clone()),
            },
        )
        .unwrap();

        assert_eq!(report.source_root, materialized);
        assert!(report.source_root.join("teemo/main.c").is_file());
        assert!(!committed.exists());
        let object = String::from_utf8_lossy(&fs::read(output).unwrap()).into_owned();
        assert!(object.contains(committed.to_str().unwrap()));
        assert!(!object.contains(report.source_root.to_str().unwrap()));
    }

    #[test]
    fn unavailable_location_does_not_create_an_empty_expression() {
        let mut document = document(Architecture::X86_64, Endianness::Little);
        document.functions[0].parameters[0].locations[0].expression =
            LocationExpression::Unavailable {
                reason: Some("clobbered".into()),
            };
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("fixture.debug");
        emit(&document, &output, &EmitOptions::default()).unwrap();
        let dump = std::process::Command::new("readelf")
            .args(["--debug-dump=info", output.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(dump.status.success());
        let text = String::from_utf8_lossy(&dump.stdout);
        assert!(text.contains("argc"));
    }
}
