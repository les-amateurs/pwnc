use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

pub const SCHEMA_NAME: &str = "pwnc.teemo.ir";
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    X86,
    Arm,
    Aarch64,
}

impl Architecture {
    pub const fn address_size(self) -> u8 {
        match self {
            Self::X86_64 | Self::Aarch64 => 8,
            Self::X86 | Self::Arm => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binary {
    pub filename: String,
    #[serde(default)]
    pub build_id: Option<String>,
    pub format: String,
    pub architecture: Architecture,
    pub endianness: Endianness,
    pub address_size: u8,
    pub entry_point: u64,
    pub image_base: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    pub id: String,
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Section {
    pub fn end(&self) -> Option<u64> {
        self.address.checked_add(self.size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    pub value: u64,
    #[serde(default)]
    pub section: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressRange {
    pub start: Address,
    pub end: Address,
}

impl AddressRange {
    pub fn len(&self) -> Option<u64> {
        self.end.value.checked_sub(self.start.value)
    }

    pub fn is_empty(&self) -> bool {
        self.start.value >= self.end.value
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub source_id: String,
    pub line: u64,
    pub column: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub name: String,
    #[serde(default)]
    pub type_id: Option<String>,
    pub offset: u64,
    #[serde(default)]
    pub bit_size: Option<u64>,
    #[serde(default)]
    pub bit_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseClass {
    pub type_id: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enumerator {
    pub name: String,
    pub value: IntegerValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntegerValue {
    Signed(i64),
    Unsigned(u64),
    Decimal(String),
}

impl IntegerValue {
    pub fn parse(&self) -> Result<SignedOrUnsigned, String> {
        match self {
            Self::Signed(value) => Ok(SignedOrUnsigned::Signed(*value)),
            Self::Unsigned(value) => Ok(SignedOrUnsigned::Unsigned(*value)),
            Self::Decimal(value) if value.starts_with('-') => value
                .parse::<i64>()
                .map(SignedOrUnsigned::Signed)
                .map_err(|_| format!("enum value {value:?} does not fit in i64")),
            Self::Decimal(value) => value
                .parse::<u64>()
                .map(SignedOrUnsigned::Unsigned)
                .map_err(|_| format!("enum value {value:?} does not fit in u64")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SignedOrUnsigned {
    Signed(i64),
    Unsigned(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrayDimension {
    #[serde(default)]
    pub lower_bound: i64,
    #[serde(default)]
    pub count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeParameter {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub type_id: Option<String>,
    #[serde(default)]
    pub artificial: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Type {
    Base {
        id: String,
        #[serde(default)]
        name: Option<String>,
        byte_size: u64,
        encoding: String,
    },
    Pointer {
        id: String,
        #[serde(default)]
        name: Option<String>,
        byte_size: u64,
        #[serde(default)]
        target: Option<String>,
    },
    Array {
        id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        byte_size: Option<u64>,
        element_type: String,
        dimensions: Vec<ArrayDimension>,
    },
    Structure {
        id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        byte_size: Option<u64>,
        #[serde(default)]
        declaration_only: bool,
        #[serde(default)]
        declaration: Option<Declaration>,
        #[serde(default)]
        members: Vec<Member>,
        #[serde(default)]
        bases: Vec<BaseClass>,
    },
    Class {
        id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        byte_size: Option<u64>,
        #[serde(default)]
        declaration_only: bool,
        #[serde(default)]
        declaration: Option<Declaration>,
        #[serde(default)]
        members: Vec<Member>,
        #[serde(default)]
        bases: Vec<BaseClass>,
    },
    Union {
        id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        byte_size: Option<u64>,
        #[serde(default)]
        declaration_only: bool,
        #[serde(default)]
        declaration: Option<Declaration>,
        #[serde(default)]
        members: Vec<Member>,
    },
    Enum {
        id: String,
        #[serde(default)]
        name: Option<String>,
        byte_size: u64,
        #[serde(default)]
        underlying_type: Option<String>,
        #[serde(default)]
        declaration: Option<Declaration>,
        enumerators: Vec<Enumerator>,
    },
    Typedef {
        id: String,
        name: String,
        target: String,
        #[serde(default)]
        declaration: Option<Declaration>,
    },
    Qualified {
        id: String,
        qualifier: String,
        target: String,
    },
    Function {
        id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        return_type: Option<String>,
        #[serde(default)]
        parameters: Vec<TypeParameter>,
        #[serde(default)]
        variadic: bool,
        #[serde(default)]
        calling_convention: Option<String>,
    },
}

impl Type {
    pub fn id(&self) -> &str {
        match self {
            Self::Base { id, .. }
            | Self::Pointer { id, .. }
            | Self::Array { id, .. }
            | Self::Structure { id, .. }
            | Self::Class { id, .. }
            | Self::Union { id, .. }
            | Self::Enum { id, .. }
            | Self::Typedef { id, .. }
            | Self::Qualified { id, .. }
            | Self::Function { id, .. } => id,
        }
    }

    pub fn references(&self) -> Vec<&str> {
        match self {
            Self::Pointer { target, .. } => target.iter().map(String::as_str).collect(),
            Self::Array { element_type, .. } => vec![element_type],
            Self::Structure { members, bases, .. } | Self::Class { members, bases, .. } => members
                .iter()
                .filter_map(|member| member.type_id.as_deref())
                .chain(bases.iter().map(|base| base.type_id.as_str()))
                .collect(),
            Self::Union { members, .. } => members
                .iter()
                .filter_map(|member| member.type_id.as_deref())
                .collect(),
            Self::Enum {
                underlying_type, ..
            } => underlying_type.iter().map(String::as_str).collect(),
            Self::Typedef { target, .. } | Self::Qualified { target, .. } => vec![target],
            Self::Function {
                return_type,
                parameters,
                ..
            } => return_type
                .iter()
                .map(String::as_str)
                .chain(
                    parameters
                        .iter()
                        .filter_map(|parameter| parameter.type_id.as_deref()),
                )
                .collect(),
            Self::Base { .. } => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocationExpression {
    Register {
        register: String,
    },
    FrameOffset {
        offset: i64,
    },
    CfaOffset {
        offset: i64,
    },
    Address {
        address: Address,
    },
    Constant {
        value: i64,
    },
    EntryValue {
        expression: Box<LocationExpression>,
    },
    StackValue {
        expression: Box<LocationExpression>,
    },
    Dereference {
        expression: Box<LocationExpression>,
    },
    Unavailable {
        #[serde(default)]
        reason: Option<String>,
    },
}

impl LocationExpression {
    pub fn is_available(&self) -> bool {
        !matches!(self, Self::Unavailable { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub range: AddressRange,
    pub expression: LocationExpression,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variable {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub linkage_name: Option<String>,
    pub kind: String,
    #[serde(default)]
    pub type_id: Option<String>,
    #[serde(default)]
    pub declaration: Option<Declaration>,
    #[serde(default)]
    pub locations: Vec<Location>,
    #[serde(default)]
    pub static_location: Option<LocationExpression>,
    #[serde(default)]
    pub external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub id: String,
    pub ranges: Vec<AddressRange>,
    #[serde(default)]
    pub variables: Vec<Variable>,
    #[serde(default)]
    pub children: Vec<Scope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub linkage_name: Option<String>,
    pub ranges: Vec<AddressRange>,
    #[serde(default)]
    pub return_type: Option<String>,
    #[serde(default)]
    pub parameters: Vec<Variable>,
    pub scope: Scope,
    #[serde(default)]
    pub variadic: bool,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub declaration: Option<Declaration>,
    #[serde(default)]
    pub calling_convention: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub id: String,
    pub name: String,
    pub address: Address,
    #[serde(default)]
    pub function_id: Option<String>,
    #[serde(default)]
    pub declaration: Option<Declaration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub path: String,
    pub language: String,
    pub generated: bool,
    pub contents: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line {
    pub range: AddressRange,
    pub source_id: String,
    pub line: u64,
    #[serde(default)]
    pub column: u64,
    #[serde(default)]
    pub statement: bool,
    #[serde(default)]
    pub discriminator: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub context: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema: String,
    pub version: u32,
    pub producer: String,
    pub binary: Binary,
    pub sections: Vec<Section>,
    #[serde(default)]
    pub types: Vec<Type>,
    #[serde(default)]
    pub globals: Vec<Variable>,
    #[serde(default)]
    pub functions: Vec<Function>,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub lines: Vec<Line>,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub struct ValidationError {
    pub errors: Vec<String>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "invalid Teemo IR:")?;
        for error in &self.errors {
            writeln!(formatter, "- {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationError {}

impl Document {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut validator = Validator::new(self);
        validator.validate();
        if validator.errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError {
                errors: validator.errors,
            })
        }
    }
}

struct Validator<'a> {
    document: &'a Document,
    sections: HashMap<&'a str, &'a Section>,
    types: HashSet<&'a str>,
    sources: HashSet<&'a str>,
    ids: HashSet<&'a str>,
    errors: Vec<String>,
}

impl<'a> Validator<'a> {
    fn new(document: &'a Document) -> Self {
        Self {
            document,
            sections: HashMap::new(),
            types: HashSet::new(),
            sources: HashSet::new(),
            ids: HashSet::new(),
            errors: Vec::new(),
        }
    }

    fn validate(&mut self) {
        if self.document.schema != SCHEMA_NAME {
            self.errors.push(format!(
                "unsupported schema {:?}; expected {SCHEMA_NAME:?}",
                self.document.schema
            ));
        }
        if self.document.version != SCHEMA_VERSION {
            self.errors.push(format!(
                "unsupported schema version {}; expected {SCHEMA_VERSION}",
                self.document.version
            ));
        }
        if self.document.producer.is_empty() {
            self.errors.push("producer must not be empty".into());
        }
        if self.document.binary.filename.is_empty() {
            self.errors.push("binary filename must not be empty".into());
        }
        if self.document.binary.format != "elf" {
            self.errors.push(format!(
                "unsupported binary format {:?}",
                self.document.binary.format
            ));
        }
        if self.document.binary.address_size != self.document.binary.architecture.address_size() {
            self.errors.push(format!(
                "address size {} does not match architecture {:?}",
                self.document.binary.address_size, self.document.binary.architecture
            ));
        }
        if self.document.binary.endianness == Endianness::Big
            && matches!(
                self.document.binary.architecture,
                Architecture::X86 | Architecture::X86_64
            )
        {
            self.errors.push("big-endian x86 ELF is unsupported".into());
        }
        if self
            .document
            .binary
            .build_id
            .as_ref()
            .is_some_and(|value| !valid_build_id(value))
        {
            self.errors
                .push("binary build id must be a non-empty even-length hexadecimal string".into());
        }

        if self.document.sections.is_empty() {
            self.errors.push("document has no target sections".into());
        }
        for section in &self.document.sections {
            self.insert_id(&section.id, "section");
            if self.sections.insert(&section.id, section).is_some() {
                self.errors
                    .push(format!("duplicate section id {:?}", section.id));
            }
            if section.name.is_empty() {
                self.errors
                    .push(format!("section {:?} has an empty name", section.id));
            }
            if section.size == 0 {
                self.errors
                    .push(format!("section {:?} has zero size", section.id));
            }
            if section.end().is_none() {
                self.errors
                    .push(format!("section {:?} address range overflows", section.id));
            }
        }
        let mut section_names = HashSet::new();
        for section in &self.document.sections {
            if !section_names.insert(section.name.as_str()) {
                self.errors
                    .push(format!("duplicate ELF section name {:?}", section.name));
            }
        }

        for source in &self.document.sources {
            self.insert_id(&source.id, "source");
            if !self.sources.insert(&source.id) {
                self.errors
                    .push(format!("duplicate source id {:?}", source.id));
            }
            if source.path.is_empty() {
                self.errors
                    .push(format!("source {:?} has an empty path", source.id));
            }
            if source.language.is_empty() {
                self.errors
                    .push(format!("source {:?} has an empty language", source.id));
            }
        }
        let mut source_paths = HashSet::new();
        for source in &self.document.sources {
            if !source_paths.insert(source.path.as_str()) {
                self.errors
                    .push(format!("duplicate generated source path {:?}", source.path));
            }
        }

        for ty in &self.document.types {
            self.insert_id(ty.id(), "type");
            if !self.types.insert(ty.id()) {
                self.errors.push(format!("duplicate type id {:?}", ty.id()));
            }
        }
        for ty in &self.document.types {
            for reference in ty.references() {
                self.validate_type_ref(reference, &format!("type {:?}", ty.id()));
            }
            match ty {
                Type::Base {
                    id,
                    byte_size,
                    encoding,
                    ..
                } => {
                    if *byte_size == 0 {
                        self.errors.push(format!("base type {id:?} has zero size"));
                    }
                    if !matches!(
                        encoding.as_str(),
                        "address"
                            | "boolean"
                            | "complex_float"
                            | "float"
                            | "signed"
                            | "signed_char"
                            | "unsigned"
                            | "unsigned_char"
                            | "utf"
                    ) {
                        self.errors.push(format!(
                            "base type {id:?} has unsupported encoding {encoding:?}"
                        ));
                    }
                }
                Type::Pointer { id, byte_size, .. }
                    if *byte_size != u64::from(self.document.binary.address_size) =>
                {
                    self.errors.push(format!(
                        "pointer type {id:?} size {byte_size} differs from target address size {}",
                        self.document.binary.address_size
                    ));
                }
                Type::Array { id, dimensions, .. } if dimensions.is_empty() => self
                    .errors
                    .push(format!("array type {id:?} has no dimensions")),
                Type::Structure {
                    id,
                    byte_size,
                    declaration_only,
                    declaration,
                    members,
                    bases,
                    ..
                }
                | Type::Class {
                    id,
                    byte_size,
                    declaration_only,
                    declaration,
                    members,
                    bases,
                    ..
                } => {
                    if !declaration_only && byte_size.is_none() {
                        self.errors
                            .push(format!("aggregate type {id:?} has no byte size"));
                    }
                    self.validate_declaration(declaration.as_ref(), &format!("type {id:?}"));
                    self.validate_members(id, *byte_size, members);
                    for base in bases {
                        if byte_size.is_some_and(|size| base.offset > size) {
                            self.errors.push(format!(
                                "aggregate type {id:?} base offset {} is outside size {:?}",
                                base.offset, byte_size
                            ));
                        }
                    }
                }
                Type::Union {
                    id,
                    byte_size,
                    declaration_only,
                    declaration,
                    members,
                    ..
                } => {
                    if !declaration_only && byte_size.is_none() {
                        self.errors
                            .push(format!("union type {id:?} has no byte size"));
                    }
                    self.validate_declaration(declaration.as_ref(), &format!("type {id:?}"));
                    self.validate_members(id, *byte_size, members);
                }
                Type::Qualified { id, qualifier, .. }
                    if !matches!(
                        qualifier.as_str(),
                        "const" | "volatile" | "restrict" | "atomic"
                    ) =>
                {
                    self.errors.push(format!(
                        "qualified type {id:?} has unsupported qualifier {qualifier:?}"
                    ));
                }
                Type::Enum {
                    id,
                    byte_size,
                    declaration,
                    enumerators,
                    ..
                } => {
                    if *byte_size == 0 {
                        self.errors.push(format!("enum type {id:?} has zero size"));
                    }
                    self.validate_declaration(declaration.as_ref(), &format!("type {id:?}"));
                    for enumerator in enumerators {
                        if let Err(error) = enumerator.value.parse() {
                            self.errors.push(format!("enum type {id:?}: {error}"));
                        }
                    }
                }
                Type::Typedef {
                    id,
                    name,
                    declaration,
                    ..
                } => {
                    if name.is_empty() {
                        self.errors.push(format!("typedef type {id:?} has no name"));
                    }
                    self.validate_declaration(declaration.as_ref(), &format!("type {id:?}"));
                }
                Type::Function {
                    id,
                    calling_convention: Some(calling_convention),
                    ..
                } if calling_convention.is_empty() => self.errors.push(format!(
                    "function type {id:?} has an empty calling convention"
                )),
                _ => {}
            }
        }

        for global in &self.document.globals {
            self.validate_variable(global, "global", None);
        }
        for function in &self.document.functions {
            self.insert_id(&function.id, "function");
            if function.name.is_empty() {
                self.errors
                    .push(format!("function {:?} has an empty name", function.id));
            }
            if function.ranges.is_empty() {
                self.errors
                    .push(format!("function {:?} has no ranges", function.id));
            }
            for range in &function.ranges {
                self.validate_range(range, &format!("function {:?}", function.id));
            }
            if let Some(type_id) = &function.return_type {
                self.validate_type_ref(type_id, &format!("function {:?}", function.id));
            }
            self.validate_declaration(
                function.declaration.as_ref(),
                &format!("function {:?}", function.id),
            );
            if function
                .calling_convention
                .as_ref()
                .is_some_and(String::is_empty)
            {
                self.errors.push(format!(
                    "function {:?} has an empty calling convention",
                    function.id
                ));
            }
            for parameter in &function.parameters {
                self.validate_variable(parameter, "parameter", Some(&function.ranges));
            }
            if range_keys(&function.scope.ranges) != range_keys(&function.ranges) {
                self.errors.push(format!(
                    "function {:?} root scope does not match its ranges",
                    function.id
                ));
            }
            let mut scope_ids = HashSet::new();
            self.validate_scope(&function.scope, &function.ranges, &mut scope_ids);
        }

        for label in &self.document.labels {
            self.insert_id(&label.id, "label");
            if label.name.is_empty() {
                self.errors
                    .push(format!("label {:?} has an empty name", label.id));
            }
            self.validate_address(&label.address, &format!("label {:?}", label.id));
            if let Some(function_id) = &label.function_id
                && !self
                    .document
                    .functions
                    .iter()
                    .any(|function| function.id == *function_id)
            {
                self.errors.push(format!(
                    "label {:?} references missing function {:?}",
                    label.id, function_id
                ));
            }
            self.validate_declaration(label.declaration.as_ref(), &format!("label {:?}", label.id));
        }

        for (index, line) in self.document.lines.iter().enumerate() {
            self.validate_range(&line.range, &format!("line record {index}"));
            if !self.sources.contains(line.source_id.as_str()) {
                self.errors.push(format!(
                    "line record {index} references missing source {:?}",
                    line.source_id
                ));
            }
            if line.line == 0 {
                self.errors
                    .push(format!("line record {index} has line number zero"));
            }
        }

        for (index, diagnostic) in self.document.diagnostics.iter().enumerate() {
            if diagnostic.code.is_empty() || diagnostic.message.is_empty() {
                self.errors
                    .push(format!("diagnostic {index} has an empty code or message"));
            }
        }
    }

    fn insert_id(&mut self, id: &'a str, noun: &str) {
        if id.is_empty() {
            self.errors.push(format!("{noun} id must not be empty"));
        } else if !self.ids.insert(id) {
            self.errors.push(format!("duplicate object id {id:?}"));
        }
    }

    fn validate_type_ref(&mut self, id: &str, owner: &str) {
        if !self.types.contains(id) {
            self.errors
                .push(format!("{owner} references missing type {id:?}"));
        }
    }

    fn validate_members(&mut self, id: &str, byte_size: Option<u64>, members: &[Member]) {
        for (index, member) in members.iter().enumerate() {
            if byte_size.is_some_and(|size| member.offset > size) {
                self.errors.push(format!(
                    "aggregate type {id:?} member {index} offset {} is outside size {:?}",
                    member.offset, byte_size
                ));
            }
            if member.bit_size.is_some() != member.bit_offset.is_some() {
                self.errors.push(format!(
                    "aggregate type {id:?} member {index} has incomplete bitfield metadata"
                ));
            }
            if member.bit_size == Some(0) {
                self.errors.push(format!(
                    "aggregate type {id:?} member {index} has zero bit size"
                ));
            }
        }
    }

    fn validate_declaration(&mut self, declaration: Option<&Declaration>, owner: &str) {
        if let Some(declaration) = declaration {
            if !self.sources.contains(declaration.source_id.as_str()) {
                self.errors.push(format!(
                    "{owner} declaration references missing source {:?}",
                    declaration.source_id
                ));
            }
            if declaration.line == 0 {
                self.errors
                    .push(format!("{owner} declaration has line number zero"));
            }
        }
    }

    fn validate_address(&mut self, address: &Address, owner: &str) {
        let Some(section_id) = &address.section else {
            return;
        };
        let Some(section) = self.sections.get(section_id.as_str()) else {
            self.errors
                .push(format!("{owner} references missing section {section_id:?}"));
            return;
        };
        let Some(end) = section.end() else {
            return;
        };
        if address.value < section.address || address.value > end {
            self.errors.push(format!(
                "{owner} address {:#x} is outside section {:?} [{:#x}, {:#x}]",
                address.value, section.id, section.address, end
            ));
        }
    }

    fn validate_range(&mut self, range: &AddressRange, owner: &str) {
        self.validate_address(&range.start, &format!("{owner} range start"));
        self.validate_address(&range.end, &format!("{owner} range end"));
        if range.end.value <= range.start.value {
            self.errors
                .push(format!("{owner} has an empty or reversed range"));
        }
        if range.start.section != range.end.section {
            self.errors
                .push(format!("{owner} range crosses section boundaries"));
        }
    }

    fn validate_expression(&mut self, expression: &LocationExpression, owner: &str) {
        match expression {
            LocationExpression::Register { register } if register.is_empty() => self
                .errors
                .push(format!("{owner} has an empty register name")),
            LocationExpression::Address { address } => self.validate_address(address, owner),
            LocationExpression::EntryValue { expression }
            | LocationExpression::StackValue { expression }
            | LocationExpression::Dereference { expression } => {
                self.validate_expression(expression, owner)
            }
            _ => {}
        }
    }

    fn validate_variable(
        &mut self,
        variable: &'a Variable,
        expected_kind: &str,
        containing_ranges: Option<&[AddressRange]>,
    ) {
        self.insert_id(&variable.id, expected_kind);
        let owner = format!("{expected_kind} {:?}", variable.id);
        if variable.kind != expected_kind {
            self.errors.push(format!(
                "{owner} declares variable kind {:?}",
                variable.kind
            ));
        }
        if variable.name.is_empty() {
            self.errors.push(format!("{owner} has an empty name"));
        }
        if let Some(type_id) = &variable.type_id {
            self.validate_type_ref(type_id, &owner);
        }
        self.validate_declaration(variable.declaration.as_ref(), &owner);
        if expected_kind == "global" && variable.static_location.is_none() {
            self.errors.push(format!("{owner} has no static location"));
        }
        if expected_kind != "global" && variable.static_location.is_some() {
            self.errors
                .push(format!("{owner} unexpectedly has a static location"));
        }
        if let Some(expression) = &variable.static_location {
            self.validate_expression(expression, &owner);
        }
        let mut locations: Vec<_> = variable.locations.iter().collect();
        locations.sort_by_key(|location| {
            (
                location.range.start.section.as_deref().unwrap_or(""),
                location.range.start.value,
            )
        });
        let mut previous: Option<(Option<&str>, u64)> = None;
        for (index, location) in locations.iter().enumerate() {
            self.validate_range(&location.range, &format!("{owner} location {index}"));
            let section = location.range.start.section.as_deref();
            if previous.is_some_and(|(previous_section, end)| {
                previous_section == section && location.range.start.value < end
            }) {
                self.errors
                    .push(format!("{owner} has overlapping location ranges"));
            }
            previous = Some((section, location.range.end.value));
            if containing_ranges.is_some_and(|ranges| !ranges_contain(ranges, &location.range)) {
                self.errors.push(format!(
                    "{owner} has a location outside its containing scope"
                ));
            }
            self.validate_expression(&location.expression, &format!("{owner} location {index}"));
        }
        if let Some(containing_ranges) = containing_ranges {
            self.validate_location_partition(variable, containing_ranges, &owner);
        }
    }

    fn validate_location_partition(
        &mut self,
        variable: &Variable,
        containing_ranges: &[AddressRange],
        owner: &str,
    ) {
        let mut locations: Vec<_> = variable.locations.iter().collect();
        locations.sort_by_key(|location| {
            (
                location.range.start.section.as_deref().unwrap_or(""),
                location.range.start.value,
                location.range.end.value,
            )
        });
        for containing in containing_ranges {
            let mut cursor = containing.start.value;
            for location in locations
                .iter()
                .filter(|location| range_contains(containing, &location.range))
            {
                if location.range.start.value != cursor {
                    self.errors.push(format!(
                        "{owner} does not explicitly cover location range at {cursor:#x}"
                    ));
                    break;
                }
                cursor = location.range.end.value;
            }
            if cursor != containing.end.value {
                self.errors.push(format!(
                    "{owner} does not explicitly cover location range at {cursor:#x}"
                ));
            }
        }
    }

    fn validate_scope(
        &mut self,
        scope: &'a Scope,
        parent_ranges: &[AddressRange],
        scope_ids: &mut HashSet<&'a str>,
    ) {
        if scope.id.is_empty() {
            self.errors.push("scope id must not be empty".into());
        } else if !scope_ids.insert(&scope.id) {
            self.errors
                .push(format!("duplicate scope id {:?}", scope.id));
        }
        if scope.ranges.is_empty() {
            self.errors
                .push(format!("scope {:?} has no ranges", scope.id));
        }
        for range in &scope.ranges {
            self.validate_range(range, &format!("scope {:?}", scope.id));
            if !ranges_contain(parent_ranges, range) {
                self.errors
                    .push(format!("scope {:?} lies outside its parent", scope.id));
            }
        }
        for variable in &scope.variables {
            self.validate_variable(variable, "local", Some(&scope.ranges));
        }
        for child in &scope.children {
            self.validate_scope(child, &scope.ranges, scope_ids);
        }
    }
}

fn range_contains(outer: &AddressRange, inner: &AddressRange) -> bool {
    outer.start.section == inner.start.section
        && outer.start.value <= inner.start.value
        && inner.end.value <= outer.end.value
}

fn valid_build_id(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn ranges_contain(outers: &[AddressRange], inner: &AddressRange) -> bool {
    outers.iter().any(|outer| range_contains(outer, inner))
}

fn range_keys(ranges: &[AddressRange]) -> Vec<(Option<&str>, u64, u64)> {
    let mut result: Vec<_> = ranges
        .iter()
        .map(|range| {
            (
                range.start.section.as_deref(),
                range.start.value,
                range.end.value,
            )
        })
        .collect();
    result.sort_unstable();
    result
}

#[cfg(test)]
mod serde_tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_on_tagged_variants() {
        let type_value = serde_json::json!({
            "kind": "base",
            "id": "type:int",
            "name": "int",
            "byte_size": 4,
            "encoding": "signed",
            "target": "type:unexpected"
        });
        assert!(serde_json::from_value::<Type>(type_value).is_err());

        let location_value = serde_json::json!({
            "kind": "register",
            "register": "r0",
            "offset": 4
        });
        assert!(serde_json::from_value::<LocationExpression>(location_value).is_err());
    }
}
