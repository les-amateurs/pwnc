"""Versioned, Binary Ninja-independent Teemo intermediate representation.

The extractor is allowed to depend on Binary Ninja. This module deliberately is
not, so schema validation and transformation tests run on ordinary CPython.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any


SCHEMA_NAME = "pwnc.teemo.ir"
SCHEMA_VERSION = 1


class IrValidationError(ValueError):
    """Raised when an IR document violates a cross-reference or range invariant."""


class Architecture(str, Enum):
    X86_64 = "x86_64"
    X86 = "x86"
    ARM = "arm"
    AARCH64 = "aarch64"

    @property
    def address_size(self) -> int:
        return 8 if self in {Architecture.X86_64, Architecture.AARCH64} else 4


class Endianness(str, Enum):
    LITTLE = "little"
    BIG = "big"


@dataclass(frozen=True, slots=True)
class Binary:
    filename: str
    architecture: Architecture
    endianness: Endianness
    entry_point: int
    image_base: int
    build_id: str | None = None
    format: str = "elf"

    @property
    def address_size(self) -> int:
        return self.architecture.address_size


@dataclass(frozen=True, slots=True)
class Section:
    id: str
    name: str
    address: int
    size: int
    readable: bool = True
    writable: bool = False
    executable: bool = False

    @property
    def end(self) -> int:
        return self.address + self.size


@dataclass(frozen=True, slots=True)
class Address:
    value: int
    section: str | None = None


@dataclass(frozen=True, slots=True)
class AddressRange:
    start: Address
    end: Address


@dataclass(frozen=True, slots=True)
class Declaration:
    source_id: str
    line: int
    column: int = 0


@dataclass(frozen=True, slots=True)
class LocationExpression:
    kind: str
    register: str | None = None
    offset: int | None = None
    address: Address | None = None
    value: int | None = None
    expression: LocationExpression | None = None
    reason: str | None = None

    @classmethod
    def register_location(cls, register: str) -> LocationExpression:
        return cls(kind="register", register=register)

    @classmethod
    def frame_offset(cls, offset: int) -> LocationExpression:
        return cls(kind="frame_offset", offset=offset)

    @classmethod
    def cfa_offset(cls, offset: int) -> LocationExpression:
        return cls(kind="cfa_offset", offset=offset)

    @classmethod
    def unavailable(cls, reason: str | None = None) -> LocationExpression:
        return cls(kind="unavailable", reason=reason)


@dataclass(frozen=True, slots=True)
class Location:
    range: AddressRange
    expression: LocationExpression


@dataclass(slots=True)
class Variable:
    id: str
    name: str
    kind: str
    type_id: str | None
    locations: list[Location] = field(default_factory=list)
    static_location: LocationExpression | None = None
    linkage_name: str | None = None
    declaration: Declaration | None = None
    external: bool = False


@dataclass(slots=True)
class Scope:
    id: str
    ranges: list[AddressRange]
    variables: list[Variable] = field(default_factory=list)
    children: list[Scope] = field(default_factory=list)


@dataclass(slots=True)
class Function:
    id: str
    name: str
    ranges: list[AddressRange]
    return_type: str | None
    parameters: list[Variable]
    scope: Scope
    variadic: bool = False
    external: bool = True
    linkage_name: str | None = None
    declaration: Declaration | None = None
    calling_convention: str | None = None


@dataclass(frozen=True, slots=True)
class Label:
    id: str
    name: str
    address: Address
    function_id: str | None = None
    declaration: Declaration | None = None


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    path: str
    language: str
    generated: bool
    contents: str


@dataclass(frozen=True, slots=True)
class Line:
    range: AddressRange
    source_id: str
    line: int
    column: int = 0
    statement: bool = True
    discriminator: int = 0


@dataclass(frozen=True, slots=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Document:
    producer: str
    binary: Binary
    sections: list[Section]
    types: list[dict[str, Any]] = field(default_factory=list)
    globals: list[Variable] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    labels: list[Label] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    lines: list[Line] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    schema: str = SCHEMA_NAME
    version: int = SCHEMA_VERSION

    def validate(self) -> None:
        errors: list[str] = []

        if self.schema != SCHEMA_NAME:
            errors.append(f"unsupported schema {self.schema!r}")
        if self.version != SCHEMA_VERSION:
            errors.append(f"unsupported schema version {self.version}")
        if not self.producer:
            errors.append("producer must not be empty")
        if not self.binary.filename:
            errors.append("binary filename must not be empty")
        if self.binary.format != "elf":
            errors.append(f"unsupported object format {self.binary.format!r}")
        if self.binary.entry_point < 0 or self.binary.image_base < 0:
            errors.append("binary addresses must be non-negative")
        if self.binary.endianness == Endianness.BIG and self.binary.architecture in {
            Architecture.X86,
            Architecture.X86_64,
        }:
            errors.append("big-endian x86 ELF is unsupported")
        if self.binary.build_id is not None and not re.fullmatch(
            r"(?:[0-9a-fA-F]{2})+", self.binary.build_id
        ):
            errors.append("binary build id must be a non-empty even-length hexadecimal string")

        sections = _unique_map(self.sections, "section", errors)
        types = _unique_dict_map(self.types, "type", errors)
        sources = _unique_map(self.sources, "source", errors)
        functions = _unique_map(self.functions, "function", errors)
        globals_by_id = _unique_map(self.globals, "global", errors)
        labels = _unique_map(self.labels, "label", errors)

        if not self.sections:
            errors.append("document has no target sections")
        section_names: set[str] = set()
        for section in self.sections:
            if not section.name:
                errors.append(f"section {section.id!r} has an empty name")
            if section.address < 0 or section.size <= 0:
                errors.append(f"section {section.id!r} has a negative address or non-positive size")
            if section.name in section_names:
                errors.append(f"duplicate ELF section name {section.name!r}")
            section_names.add(section.name)

        for type_id, type_entry in types.items():
            kind = type_entry.get("kind")
            if kind not in {
                "base",
                "pointer",
                "array",
                "structure",
                "class",
                "union",
                "enum",
                "typedef",
                "qualified",
                "function",
            }:
                errors.append(f"type {type_id!r} has unsupported kind {kind!r}")
                continue
            _validate_type_entry(type_id, type_entry, self.binary.address_size, sources, errors)
            for reference in _type_references(type_entry):
                if reference not in types:
                    errors.append(f"type {type_id!r} references missing type {reference!r}")

        seen_variables = set(globals_by_id)
        for variable in self.globals:
            _validate_variable(variable, "global", types, sections, sources, errors)

        for function in self.functions:
            if not function.name:
                errors.append(f"function {function.id!r} has an empty name")
            if not function.ranges:
                errors.append(f"function {function.id!r} has no ranges")
            for address_range in function.ranges:
                _validate_range(address_range, sections, f"function {function.id!r}", errors)
            if function.return_type is not None and function.return_type not in types:
                errors.append(
                    f"function {function.id!r} references missing return type {function.return_type!r}"
                )
            if function.declaration is not None:
                _validate_declaration(function.declaration, sources, f"function {function.id!r}", errors)
            if function.calling_convention is not None and not function.calling_convention:
                errors.append(f"function {function.id!r} has an empty calling convention")
            for parameter in function.parameters:
                if parameter.kind != "parameter":
                    errors.append(f"function {function.id!r} contains non-parameter {parameter.id!r}")
                if parameter.id in seen_variables:
                    errors.append(f"duplicate variable id {parameter.id!r}")
                seen_variables.add(parameter.id)
                _validate_variable(parameter, "parameter", types, sections, sources, errors)
                _validate_location_partition(
                    parameter,
                    function.ranges,
                    f"parameter {parameter.id!r}",
                    errors,
                )
            if _range_keys(function.scope.ranges) != _range_keys(function.ranges):
                errors.append(f"function {function.id!r} root scope does not match its ranges")
            _validate_scope(
                function.scope,
                function,
                types,
                sections,
                sources,
                seen_variables,
                set(),
                errors,
            )

        source_paths: set[str] = set()
        for source in self.sources:
            if not source.path:
                errors.append(f"source {source.id!r} has an empty path")
            if not source.language:
                errors.append(f"source {source.id!r} has an empty language")
            if source.path in source_paths:
                errors.append(f"duplicate generated source path {source.path!r}")
            source_paths.add(source.path)

        for label in labels.values():
            if not label.name:
                errors.append(f"label {label.id!r} has an empty name")
            _validate_address(label.address, sections, f"label {label.id!r}", errors)
            if label.function_id is not None and label.function_id not in functions:
                errors.append(
                    f"label {label.id!r} references missing function {label.function_id!r}"
                )
            if label.declaration is not None:
                _validate_declaration(label.declaration, sources, f"label {label.id!r}", errors)

        for index, line in enumerate(self.lines):
            _validate_range(line.range, sections, f"line record {index}", errors)
            if line.source_id not in sources:
                errors.append(f"line record {index} references missing source {line.source_id!r}")
            if line.line < 1 or line.column < 0 or line.discriminator < 0:
                errors.append(f"line record {index} has an invalid source position")

        for index, diagnostic in enumerate(self.diagnostics):
            if diagnostic.severity not in {"info", "warning", "error"}:
                errors.append(f"diagnostic {index} has invalid severity {diagnostic.severity!r}")
            if not diagnostic.code or not diagnostic.message:
                errors.append(f"diagnostic {index} has an empty code or message")
            if not isinstance(diagnostic.context, dict):
                errors.append(f"diagnostic {index} has a non-object context")

        if errors:
            raise IrValidationError("invalid Teemo IR:\n- " + "\n- ".join(errors))

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        if validate:
            self.validate()
        result = _drop_none(asdict(self))
        result["binary"]["address_size"] = self.binary.address_size
        return result

    def dumps(self, *, indent: int | None = 2, validate: bool = True) -> str:
        return json.dumps(
            self.to_dict(validate=validate),
            indent=indent,
            sort_keys=True,
        )

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(self.dumps() + "\n", encoding="utf-8")


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _drop_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_drop_none(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value


def _unique_map(entries: list[Any], noun: str, errors: list[str]) -> dict[str, Any]:
    result = {}
    for entry in entries:
        identifier = entry.id
        if not identifier:
            errors.append(f"{noun} id must not be empty")
        elif identifier in result:
            errors.append(f"duplicate {noun} id {identifier!r}")
        else:
            result[identifier] = entry
    return result


def _unique_dict_map(entries: list[dict[str, Any]], noun: str, errors: list[str]) -> dict[str, dict[str, Any]]:
    result = {}
    for entry in entries:
        identifier = entry.get("id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{noun} id must be a non-empty string")
        elif identifier in result:
            errors.append(f"duplicate {noun} id {identifier!r}")
        else:
            result[identifier] = entry
    return result


def _type_references(type_entry: dict[str, Any]) -> list[str]:
    references = []
    for key in ("target", "element_type", "underlying_type", "return_type"):
        reference = type_entry.get(key)
        if isinstance(reference, str) and reference:
            references.append(reference)
    for field in ("members", "bases", "parameters"):
        values = type_entry.get(field, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, dict):
                continue
            reference = value.get("type_id")
            if isinstance(reference, str) and reference:
                references.append(reference)
    return references


def _validate_type_entry(
    type_id: str,
    entry: dict[str, Any],
    address_size: int,
    sources: dict[str, Source],
    errors: list[str],
) -> None:
    kind = entry["kind"]
    common = {"id", "kind"}
    allowed: dict[str, set[str]] = {
        "base": common | {"name", "byte_size", "encoding"},
        "pointer": common | {"name", "byte_size", "target"},
        "array": common | {"name", "byte_size", "element_type", "dimensions"},
        "structure": common | {"name", "byte_size", "declaration_only", "declaration", "members", "bases"},
        "class": common | {"name", "byte_size", "declaration_only", "declaration", "members", "bases"},
        "union": common | {"name", "byte_size", "declaration_only", "declaration", "members"},
        "enum": common | {"name", "byte_size", "underlying_type", "declaration", "enumerators"},
        "typedef": common | {"name", "target", "declaration"},
        "qualified": common | {"qualifier", "target"},
        "function": common | {"name", "return_type", "parameters", "variadic", "calling_convention"},
    }
    unexpected = sorted(set(entry) - allowed[kind])
    if unexpected:
        errors.append(f"type {type_id!r} has unknown fields {unexpected!r}")

    name = entry.get("name")
    if name is not None and not isinstance(name, str):
        errors.append(f"type {type_id!r} has a non-string name")

    if kind == "base":
        _require_positive_integer(entry, "byte_size", type_id, errors)
        if entry.get("encoding") not in {
            "address",
            "boolean",
            "complex_float",
            "float",
            "signed",
            "signed_char",
            "unsigned",
            "unsigned_char",
            "utf",
        }:
            errors.append(f"type {type_id!r} has unsupported base encoding {entry.get('encoding')!r}")
    elif kind == "pointer":
        if entry.get("byte_size") != address_size:
            errors.append(
                f"pointer type {type_id!r} size {entry.get('byte_size')!r} "
                f"does not match address size {address_size}"
            )
        target = entry.get("target")
        if target is not None and (not isinstance(target, str) or not target):
            errors.append(f"pointer type {type_id!r} has an invalid target")
    elif kind == "array":
        if not isinstance(entry.get("element_type"), str) or not entry["element_type"]:
            errors.append(f"array type {type_id!r} has no element type")
        dimensions = entry.get("dimensions")
        if not isinstance(dimensions, list) or not dimensions:
            errors.append(f"array type {type_id!r} has no dimensions")
        else:
            for index, dimension in enumerate(dimensions):
                if not isinstance(dimension, dict):
                    errors.append(f"array type {type_id!r} dimension {index} is not an object")
                    continue
                if set(dimension) - {"lower_bound", "count"}:
                    errors.append(f"array type {type_id!r} dimension {index} has unknown fields")
                if not isinstance(dimension.get("lower_bound", 0), int):
                    errors.append(f"array type {type_id!r} dimension {index} has an invalid lower bound")
                count = dimension.get("count")
                if count is not None and (not isinstance(count, int) or isinstance(count, bool) or count < 0):
                    errors.append(f"array type {type_id!r} dimension {index} has an invalid count")
    elif kind in {"structure", "class", "union"}:
        byte_size = entry.get("byte_size")
        if byte_size is not None and (not isinstance(byte_size, int) or isinstance(byte_size, bool) or byte_size < 0):
            errors.append(f"aggregate type {type_id!r} has an invalid byte size")
        declaration_only = entry.get("declaration_only", False)
        if not isinstance(declaration_only, bool):
            errors.append(f"aggregate type {type_id!r} has an invalid declaration flag")
        members = entry.get("members", [])
        if not isinstance(members, list):
            errors.append(f"aggregate type {type_id!r} has a non-list member set")
        else:
            for index, member in enumerate(members):
                _validate_type_member(type_id, index, member, errors)
        if kind in {"structure", "class"}:
            bases = entry.get("bases", [])
            if not isinstance(bases, list):
                errors.append(f"aggregate type {type_id!r} has a non-list base set")
            else:
                for index, base in enumerate(bases):
                    if not isinstance(base, dict) or set(base) != {"type_id", "offset"}:
                        errors.append(f"aggregate type {type_id!r} base {index} is malformed")
                        continue
                    if not isinstance(base["type_id"], str) or not base["type_id"]:
                        errors.append(f"aggregate type {type_id!r} base {index} has no type")
                    if not isinstance(base["offset"], int) or isinstance(base["offset"], bool) or base["offset"] < 0:
                        errors.append(f"aggregate type {type_id!r} base {index} has an invalid offset")
        _validate_raw_declaration(entry.get("declaration"), sources, f"type {type_id!r}", errors)
    elif kind == "enum":
        _require_positive_integer(entry, "byte_size", type_id, errors)
        underlying = entry.get("underlying_type")
        if underlying is not None and (not isinstance(underlying, str) or not underlying):
            errors.append(f"enum type {type_id!r} has an invalid underlying type")
        enumerators = entry.get("enumerators")
        if not isinstance(enumerators, list):
            errors.append(f"enum type {type_id!r} has no enumerator list")
        else:
            for index, enumerator in enumerate(enumerators):
                if not isinstance(enumerator, dict) or set(enumerator) != {"name", "value"}:
                    errors.append(f"enum type {type_id!r} enumerator {index} is malformed")
                    continue
                if not isinstance(enumerator["name"], str) or not enumerator["name"]:
                    errors.append(f"enum type {type_id!r} enumerator {index} has no name")
                if not _valid_enum_value(enumerator["value"]):
                    errors.append(f"enum type {type_id!r} enumerator {index} has an invalid value")
        _validate_raw_declaration(entry.get("declaration"), sources, f"type {type_id!r}", errors)
    elif kind == "typedef":
        if not isinstance(entry.get("name"), str) or not entry["name"]:
            errors.append(f"typedef type {type_id!r} has no name")
        if not isinstance(entry.get("target"), str) or not entry["target"]:
            errors.append(f"typedef type {type_id!r} has no target")
        _validate_raw_declaration(entry.get("declaration"), sources, f"type {type_id!r}", errors)
    elif kind == "qualified":
        if entry.get("qualifier") not in {"const", "volatile", "restrict", "atomic"}:
            errors.append(f"type {type_id!r} has unsupported qualifier {entry.get('qualifier')!r}")
        if not isinstance(entry.get("target"), str) or not entry["target"]:
            errors.append(f"qualified type {type_id!r} has no target")
    elif kind == "function":
        parameters = entry.get("parameters")
        if not isinstance(parameters, list):
            errors.append(f"function type {type_id!r} has no parameter list")
        else:
            for index, parameter in enumerate(parameters):
                if not isinstance(parameter, dict) or set(parameter) - {"name", "type_id", "artificial"}:
                    errors.append(f"function type {type_id!r} parameter {index} is malformed")
                    continue
                if parameter.get("name") is not None and not isinstance(parameter["name"], str):
                    errors.append(f"function type {type_id!r} parameter {index} has an invalid name")
                if parameter.get("type_id") is not None and not isinstance(parameter["type_id"], str):
                    errors.append(f"function type {type_id!r} parameter {index} has an invalid type")
                elif parameter.get("type_id") == "":
                    errors.append(f"function type {type_id!r} parameter {index} has an empty type")
                if not isinstance(parameter.get("artificial", False), bool):
                    errors.append(f"function type {type_id!r} parameter {index} has an invalid artificial flag")
        if not isinstance(entry.get("variadic", False), bool):
            errors.append(f"function type {type_id!r} has an invalid variadic flag")
        convention = entry.get("calling_convention")
        if convention is not None and (not isinstance(convention, str) or not convention):
            errors.append(f"function type {type_id!r} has an invalid calling convention")
        return_type = entry.get("return_type")
        if return_type is not None and (not isinstance(return_type, str) or not return_type):
            errors.append(f"function type {type_id!r} has an invalid return type")


def _require_positive_integer(entry: dict[str, Any], key: str, type_id: str, errors: list[str]) -> None:
    value = entry.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        errors.append(f"type {type_id!r} has an invalid {key.replace('_', ' ')}")


def _validate_type_member(type_id: str, index: int, member: Any, errors: list[str]) -> None:
    if not isinstance(member, dict) or set(member) - {"name", "type_id", "offset", "bit_size", "bit_offset"}:
        errors.append(f"aggregate type {type_id!r} member {index} is malformed")
        return
    if not isinstance(member.get("name"), str):
        errors.append(f"aggregate type {type_id!r} member {index} has an invalid name")
    type_reference = member.get("type_id")
    if type_reference is not None and (not isinstance(type_reference, str) or not type_reference):
        errors.append(f"aggregate type {type_id!r} member {index} has an invalid type")
    offset = member.get("offset")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        errors.append(f"aggregate type {type_id!r} member {index} has an invalid offset")
    bit_size = member.get("bit_size")
    bit_offset = member.get("bit_offset")
    if (bit_size is None) != (bit_offset is None):
        errors.append(f"aggregate type {type_id!r} member {index} has incomplete bitfield metadata")
    if bit_size is not None and (not isinstance(bit_size, int) or isinstance(bit_size, bool) or bit_size <= 0):
        errors.append(f"aggregate type {type_id!r} member {index} has an invalid bit size")
    if bit_offset is not None and (not isinstance(bit_offset, int) or isinstance(bit_offset, bool) or bit_offset < 0):
        errors.append(f"aggregate type {type_id!r} member {index} has an invalid bit offset")


def _validate_raw_declaration(
    declaration: Any,
    sources: dict[str, Source],
    owner: str,
    errors: list[str],
) -> None:
    if declaration is None:
        return
    if not isinstance(declaration, dict) or set(declaration) - {"source_id", "line", "column"}:
        errors.append(f"{owner} has a malformed declaration")
        return
    source_id = declaration.get("source_id")
    if source_id not in sources:
        errors.append(f"{owner} declaration references missing source {source_id!r}")
    line = declaration.get("line")
    column = declaration.get("column", 0)
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        errors.append(f"{owner} has an invalid declaration line")
    if not isinstance(column, int) or isinstance(column, bool) or column < 0:
        errors.append(f"{owner} has an invalid declaration column")


def _valid_enum_value(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -(1 << 63) <= value < (1 << 64)
    if not isinstance(value, str) or not value or value.strip() != value:
        return False
    try:
        parsed = int(value, 10)
    except ValueError:
        return False
    return (-(1 << 63) <= parsed < 0) if value.startswith("-") else (0 <= parsed < (1 << 64))


def _validate_address(address: Address, sections: dict[str, Section], owner: str, errors: list[str]) -> None:
    if address.value < 0:
        errors.append(f"{owner} has a negative address")
    if address.section is None:
        return
    section = sections.get(address.section)
    if section is None:
        errors.append(f"{owner} references missing section {address.section!r}")
    elif not section.address <= address.value <= section.end:
        errors.append(
            f"{owner} address {address.value:#x} lies outside section {section.id!r} "
            f"[{section.address:#x}, {section.end:#x}]"
        )


def _validate_range(
    address_range: AddressRange,
    sections: dict[str, Section],
    owner: str,
    errors: list[str],
) -> None:
    _validate_address(address_range.start, sections, f"{owner} range start", errors)
    _validate_address(address_range.end, sections, f"{owner} range end", errors)
    if address_range.end.value <= address_range.start.value:
        errors.append(f"{owner} has an empty or reversed range")
    if address_range.start.section != address_range.end.section:
        errors.append(f"{owner} range crosses section boundaries")


def _validate_declaration(
    declaration: Declaration,
    sources: dict[str, Source],
    owner: str,
    errors: list[str],
) -> None:
    if declaration.source_id not in sources:
        errors.append(f"{owner} references missing source {declaration.source_id!r}")
    if declaration.line < 1 or declaration.column < 0:
        errors.append(f"{owner} has an invalid declaration position")


def _validate_expression(
    expression: LocationExpression,
    sections: dict[str, Section],
    owner: str,
    errors: list[str],
) -> None:
    payload = {
        "register": expression.register,
        "offset": expression.offset,
        "address": expression.address,
        "value": expression.value,
        "expression": expression.expression,
        "reason": expression.reason,
    }
    allowed = {
        "register": {"register"},
        "frame_offset": {"offset"},
        "cfa_offset": {"offset"},
        "address": {"address"},
        "constant": {"value"},
        "entry_value": {"expression"},
        "stack_value": {"expression"},
        "dereference": {"expression"},
        "unavailable": {"reason"},
    }
    if expression.kind not in allowed:
        errors.append(f"{owner} has unsupported location expression {expression.kind!r}")
        return
    unexpected = sorted(
        name for name, value in payload.items() if value is not None and name not in allowed[expression.kind]
    )
    if unexpected:
        errors.append(f"{owner} location expression has unexpected fields {unexpected!r}")

    if expression.kind == "register":
        if not isinstance(expression.register, str) or not expression.register:
            errors.append(f"{owner} has an empty register location")
    elif expression.kind in {"frame_offset", "cfa_offset"}:
        if (
            not isinstance(expression.offset, int)
            or isinstance(expression.offset, bool)
            or not -(1 << 63) <= expression.offset < (1 << 63)
        ):
            errors.append(f"{owner} has an invalid location offset")
    elif expression.kind == "address":
        if not isinstance(expression.address, Address):
            errors.append(f"{owner} is missing its address")
        else:
            _validate_address(expression.address, sections, owner, errors)
    elif expression.kind == "constant":
        if (
            not isinstance(expression.value, int)
            or isinstance(expression.value, bool)
            or not -(1 << 63) <= expression.value < (1 << 63)
        ):
            errors.append(f"{owner} has an invalid constant value")
    elif expression.kind in {"entry_value", "stack_value", "dereference"}:
        if not isinstance(expression.expression, LocationExpression):
            errors.append(f"{owner} is missing its nested expression")
        else:
            _validate_expression(expression.expression, sections, owner, errors)
    elif expression.reason is not None and not isinstance(expression.reason, str):
        errors.append(f"{owner} has a non-string unavailability reason")


def _validate_variable(
    variable: Variable,
    expected_kind: str,
    types: dict[str, dict[str, Any]],
    sections: dict[str, Section],
    sources: dict[str, Source],
    errors: list[str],
) -> None:
    owner = f"{expected_kind} {variable.id!r}"
    if variable.kind != expected_kind:
        errors.append(f"{owner} declares kind {variable.kind!r}")
    if not variable.name:
        errors.append(f"{owner} has an empty name")
    if variable.type_id is not None and variable.type_id not in types:
        errors.append(f"{owner} references missing type {variable.type_id!r}")
    if variable.declaration is not None:
        _validate_declaration(variable.declaration, sources, owner, errors)
    if expected_kind == "global" and variable.static_location is None:
        errors.append(f"{owner} has no static location")
    if expected_kind != "global" and variable.static_location is not None:
        errors.append(f"{owner} unexpectedly has a static location")
    if variable.static_location is not None:
        _validate_expression(variable.static_location, sections, owner, errors)
    previous: tuple[str | None, int] | None = None
    ordered = sorted(
        variable.locations,
        key=lambda item: (item.range.start.section or "", item.range.start.value),
    )
    for index, location in enumerate(ordered):
        _validate_range(location.range, sections, f"{owner} location {index}", errors)
        section = location.range.start.section
        if previous is not None and previous[0] == section and location.range.start.value < previous[1]:
            errors.append(f"{owner} has overlapping location ranges")
        previous = (section, location.range.end.value)
        _validate_expression(location.expression, sections, f"{owner} location {index}", errors)


def _range_contains(outer: AddressRange, inner: AddressRange) -> bool:
    return (
        outer.start.section == inner.start.section
        and outer.start.value <= inner.start.value
        and inner.end.value <= outer.end.value
    )


def _ranges_contain(outers: list[AddressRange], inner: AddressRange) -> bool:
    return any(_range_contains(outer, inner) for outer in outers)


def _range_keys(ranges: list[AddressRange]) -> list[tuple[str | None, int, int]]:
    return sorted((value.start.section, value.start.value, value.end.value) for value in ranges)


def _validate_location_partition(
    variable: Variable,
    containing_ranges: list[AddressRange],
    owner: str,
    errors: list[str],
) -> None:
    """Require explicit unavailable entries instead of implicit location gaps."""

    locations = sorted(
        variable.locations,
        key=lambda item: (item.range.start.section or "", item.range.start.value, item.range.end.value),
    )
    for containing in containing_ranges:
        cursor = containing.start.value
        pieces = [location.range for location in locations if _range_contains(containing, location.range)]
        for piece in pieces:
            if piece.start.value != cursor:
                errors.append(f"{owner} does not explicitly cover location range at {cursor:#x}")
                break
            cursor = piece.end.value
        if cursor != containing.end.value:
            errors.append(f"{owner} does not explicitly cover location range at {cursor:#x}")


def _validate_scope(
    scope: Scope,
    function: Function,
    types: dict[str, dict[str, Any]],
    sections: dict[str, Section],
    sources: dict[str, Source],
    seen_variables: set[str],
    seen_scopes: set[str],
    errors: list[str],
) -> None:
    if not scope.id:
        errors.append(f"function {function.id!r} contains a scope with an empty id")
    elif scope.id in seen_scopes:
        errors.append(f"function {function.id!r} contains duplicate scope id {scope.id!r}")
    seen_scopes.add(scope.id)
    if not scope.ranges:
        errors.append(f"scope {scope.id!r} has no ranges")
    for address_range in scope.ranges:
        _validate_range(address_range, sections, f"scope {scope.id!r}", errors)
        if not _ranges_contain(function.ranges, address_range):
            errors.append(f"scope {scope.id!r} lies outside function {function.id!r}")
    for variable in scope.variables:
        if variable.id in seen_variables:
            errors.append(f"duplicate variable id {variable.id!r}")
        seen_variables.add(variable.id)
        _validate_variable(variable, "local", types, sections, sources, errors)
        for location in variable.locations:
            if not _ranges_contain(scope.ranges, location.range):
                errors.append(f"local {variable.id!r} has a location outside scope {scope.id!r}")
        _validate_location_partition(variable, scope.ranges, f"local {variable.id!r}", errors)
    for child in scope.children:
        for address_range in child.ranges:
            if not _ranges_contain(scope.ranges, address_range):
                errors.append(f"scope {child.id!r} lies outside parent scope {scope.id!r}")
        _validate_scope(
            child,
            function,
            types,
            sections,
            sources,
            seen_variables,
            seen_scopes,
            errors,
        )
