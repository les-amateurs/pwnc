"""Export Binary Ninja types into Teemo's architecture-neutral type graph.

The implementation intentionally uses Binary Ninja's public attributes through
duck typing.  Importing this module therefore does not initialize Binary Ninja,
which keeps schema tests usable on machines without a license.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from .ir import Diagnostic


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value))


def _qualified_name(value: Any) -> str:
    if value is None:
        return ""
    components = getattr(value, "name", None)
    if isinstance(components, (list, tuple)):
        return "::".join(str(component) for component in components)
    return str(value)


def _confidence_bool(value: Any) -> bool:
    return bool(getattr(value, "value", value))


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:20]


@dataclass(frozen=True, slots=True)
class ExportedType:
    id: str | None
    supported: bool


class BinjaTypeExporter:
    """Cycle-safe conversion of Binary Ninja's type graph to IR dictionaries."""

    def __init__(self, binary_view: Any) -> None:
        self.bv = binary_view
        self.entries: list[dict[str, Any]] = []
        self.diagnostics: list[Diagnostic] = []
        self._by_key: dict[tuple[Any, ...], str | None] = {}
        self._entries_by_id: dict[str, dict[str, Any]] = {}
        self._in_progress: set[str] = set()

    def export(self, bn_type: Any, name: Any = None) -> str | None:
        """Return a type id, or ``None`` for void/unsupported types."""

        if bn_type is None:
            return None
        try:
            return self._export_qualified(bn_type, _qualified_name(name) or None)
        except Exception as error:  # Binary Ninja libraries can contain dangling references.
            self._warn(
                "type-export-failed",
                f"failed to export Binary Ninja type {self._display(bn_type)!r}: {error}",
            )
            return None

    def export_named_types(self) -> None:
        """Seed the graph with all named analysis types exposed by the view."""

        named = getattr(self.bv, "types", {})
        items = named.items() if hasattr(named, "items") else named
        for name, bn_type in sorted(items, key=lambda item: _qualified_name(item[0])):
            self.export(bn_type, name)

    def finish(self) -> list[dict[str, Any]]:
        """Return entries in deterministic dependency-independent id order."""

        return sorted(self.entries, key=lambda entry: entry["id"])

    def _export_qualified(self, bn_type: Any, name: str | None) -> str | None:
        raw_id = self._export_raw(bn_type, name)
        if raw_id is None:
            return None
        return self._apply_qualifiers(raw_id, self._qualifiers(bn_type))

    def _apply_qualifiers(self, raw_id: str, qualifiers: list[str]) -> str:
        result = raw_id
        for qualifier in qualifiers:
            key = ("qualifier", qualifier, result)
            cached = self._by_key.get(key, ...)
            if cached is not ...:
                result = cached
                continue
            identifier = f"type:qual:{qualifier}:{_short_hash(result)}"
            result = self._insert(key, {"id": identifier, "kind": "qualified", "qualifier": qualifier, "target": result})
        return result

    @staticmethod
    def _qualifiers(bn_type: Any) -> list[str]:
        result = []
        if _confidence_bool(getattr(bn_type, "const", False)):
            result.append("const")
        if _confidence_bool(getattr(bn_type, "volatile", False)):
            result.append("volatile")
        return result

    def _export_raw(self, bn_type: Any, name: str | None = None, forced_id: str | None = None) -> str | None:
        class_name = _enum_name(getattr(bn_type, "type_class", type(bn_type).__name__))
        if class_name in {"VoidTypeClass", "VarArgsTypeClass"}:
            return None

        registered = getattr(bn_type, "registered_name", None)
        if registered is not None and getattr(registered, "type_id", None):
            return self._export_named_reference(registered, concrete=bn_type)
        if class_name == "NamedTypeReferenceClass":
            return self._export_named_reference(bn_type)

        key = self._anonymous_key(bn_type, name)
        if key in self._by_key:
            return self._by_key[key]
        identifier = forced_id or f"type:anon:{_short_hash(repr(key))}"
        self._by_key[key] = identifier
        self._in_progress.add(identifier)
        try:
            entry = self._build_entry(identifier, bn_type, name)
            if entry is None:
                self._by_key[key] = None
                return None
            self._append_entry(entry)
            return identifier
        finally:
            self._in_progress.discard(identifier)

    def _export_named_reference(self, reference: Any, concrete: Any = None) -> str | None:
        type_id = str(getattr(reference, "type_id", ""))
        name = _qualified_name(getattr(reference, "name", None)) or self._display(reference)
        reference_class = _enum_name(getattr(reference, "named_type_class", "UnknownNamedTypeClass"))
        key = ("named", type_id or name, reference_class)
        if key in self._by_key:
            return self._by_key[key]
        identifier = f"type:named:{_short_hash(type_id or reference_class + ':' + name)}"
        self._by_key[key] = identifier
        self._in_progress.add(identifier)
        try:
            target = concrete
            if target is reference or _enum_name(getattr(target, "type_class", "")) == "NamedTypeReferenceClass":
                target = None
            if target is None and type_id:
                target = getattr(self.bv, "get_type_by_id", lambda _id: None)(type_id)

            if reference_class == "TypedefNamedTypeClass":
                target_id = self._export_named_target(type_id or name, target) if target is not None else None
                if target_id is None:
                    self._warn("unresolved-typedef", f"omitting unresolved typedef {name!r}", type_id=type_id)
                    self._by_key[key] = None
                    return None
                self._append_entry({"id": identifier, "kind": "typedef", "name": name, "target": target_id})
                return identifier

            if target is not None:
                entry = self._build_entry(identifier, target, name)
            else:
                kind = {
                    "StructNamedTypeClass": "structure",
                    "ClassNamedTypeClass": "class",
                    "UnionNamedTypeClass": "union",
                    "EnumNamedTypeClass": "enum",
                }.get(reference_class)
                if kind == "enum":
                    self._warn("unresolved-enum", f"omitting unresolved enum {name!r}", type_id=type_id)
                    self._by_key[key] = None
                    return None
                if kind is None:
                    self._warn("unresolved-type", f"omitting unresolved named type {name!r}", type_id=type_id)
                    self._by_key[key] = None
                    return None
                entry = {
                    "id": identifier,
                    "kind": kind,
                    "name": name,
                    "byte_size": None,
                    "declaration_only": True,
                    "members": [],
                }
                self._warn("opaque-type", f"exported unresolved {kind} {name!r} as an opaque declaration", type_id=type_id)
            if entry is None:
                self._by_key[key] = None
                return None
            self._append_entry(entry)
            return identifier
        finally:
            self._in_progress.discard(identifier)

    def _export_named_target(self, named_key: str, target: Any) -> str | None:
        """Export a typedef's concrete value without following its registered name."""

        key = ("named-target", named_key, self._anonymous_key(target, None))
        if key in self._by_key:
            return self._by_key[key]
        identifier = f"type:named-target:{_short_hash(repr(key))}"
        self._by_key[key] = identifier
        entry = self._build_entry(identifier, target, None)
        if entry is None:
            self._by_key[key] = None
            return None
        self._append_entry(entry)
        result = self._apply_qualifiers(identifier, self._qualifiers(target))
        self._by_key[key] = result
        return result

    def _build_entry(self, identifier: str, bn_type: Any, name: str | None) -> dict[str, Any] | None:
        class_name = _enum_name(getattr(bn_type, "type_class", type(bn_type).__name__))
        width = int(getattr(bn_type, "width", 0))
        display_name = name or str(getattr(bn_type, "altname", "") or self._display(bn_type))

        if class_name == "BoolTypeClass":
            return {"id": identifier, "kind": "base", "name": display_name or "bool", "byte_size": width or 1, "encoding": "boolean"}
        if class_name == "IntegerTypeClass":
            signed = _confidence_bool(getattr(bn_type, "signed", True))
            encoding = "signed_char" if width == 1 and display_name == "char" and signed else "signed" if signed else "unsigned"
            return {"id": identifier, "kind": "base", "name": display_name or None, "byte_size": width, "encoding": encoding}
        if class_name == "WideCharTypeClass":
            return {"id": identifier, "kind": "base", "name": display_name or "wchar_t", "byte_size": width, "encoding": "utf"}
        if class_name == "FloatTypeClass":
            return {"id": identifier, "kind": "base", "name": display_name or None, "byte_size": width, "encoding": "float"}
        if class_name == "PointerTypeClass":
            return {
                "id": identifier,
                "kind": "pointer",
                "name": name,
                "byte_size": width,
                "target": self._export_qualified(getattr(bn_type, "target"), None),
            }
        if class_name == "ArrayTypeClass":
            element = self._export_qualified(getattr(bn_type, "element_type"), None)
            if element is None:
                return self._unsupported(bn_type, "array element type is unsupported")
            return {
                "id": identifier,
                "kind": "array",
                "name": name,
                "byte_size": width or None,
                "element_type": element,
                "dimensions": [{"lower_bound": 0, "count": int(getattr(bn_type, "count"))}],
            }
        if class_name == "StructureTypeClass":
            variant = _enum_name(getattr(bn_type, "type", "StructStructureType"))
            kind = {
                "StructStructureType": "structure",
                "ClassStructureType": "class",
                "UnionStructureType": "union",
            }.get(variant)
            if kind is None:
                return self._unsupported(bn_type, f"unknown structure variant {variant!r}")
            members = []
            for index, member in enumerate(getattr(bn_type, "members", ())):
                member_id = self._export_qualified(getattr(member, "type", None), None)
                member_name = str(getattr(member, "name", "")) or f"anonymous_{index}"
                member_entry: dict[str, Any] = {
                    "name": member_name,
                    "type_id": member_id,
                    "offset": int(getattr(member, "offset", 0)),
                }
                bit_width = int(getattr(member, "bit_width", 0))
                if bit_width:
                    member_entry["bit_size"] = bit_width
                    member_entry["bit_offset"] = int(getattr(member, "bit_offset", member_entry["offset"] * 8))
                members.append(member_entry)
            bases = []
            if kind in {"structure", "class"}:
                for base in getattr(bn_type, "base_structures", ()):
                    base_id = self._export_qualified(getattr(base, "type", None), None)
                    if base_id is None:
                        self._warn(
                            "unsupported-base-class",
                            f"omitting unresolved base of {display_name!r}",
                        )
                        continue
                    bases.append({"type_id": base_id, "offset": int(getattr(base, "offset", 0))})
            return {
                "id": identifier,
                "kind": kind,
                "name": name or self._registered_name(bn_type),
                "byte_size": width,
                "declaration_only": False,
                "members": members,
                **({"bases": bases} if kind in {"structure", "class"} else {}),
            }
        if class_name == "EnumerationTypeClass":
            enumerators = []
            for member in getattr(bn_type, "members", ()):
                value = getattr(member, "value", None)
                if value is None:
                    self._warn("enum-default-member", f"omitting valueless enum member {getattr(member, 'name', '')!r}")
                    continue
                enumerators.append({"name": str(getattr(member, "name", "")), "value": int(value)})
            underlying_name = "int" if _confidence_bool(getattr(bn_type, "signed", False)) else "unsigned int"
            underlying = self._export_synthetic_integer(width, underlying_name, _confidence_bool(getattr(bn_type, "signed", False)))
            return {
                "id": identifier,
                "kind": "enum",
                "name": name or self._registered_name(bn_type),
                "byte_size": width,
                "underlying_type": underlying,
                "enumerators": enumerators,
            }
        if class_name == "FunctionTypeClass":
            parameters = []
            for parameter in getattr(bn_type, "parameters", ()):
                parameters.append({
                    "name": str(getattr(parameter, "name", "")) or None,
                    "type_id": self._export_qualified(getattr(parameter, "type", None), None),
                    "artificial": False,
                })
            convention = getattr(bn_type, "calling_convention", None)
            return {
                "id": identifier,
                "kind": "function",
                "name": name,
                "return_type": self._export_qualified(getattr(bn_type, "return_value", None), None),
                "parameters": parameters,
                "variadic": _confidence_bool(getattr(bn_type, "has_variable_arguments", False)),
                "calling_convention": getattr(convention, "name", None),
            }
        return self._unsupported(bn_type, f"unsupported Binary Ninja type class {class_name!r}")

    def _export_synthetic_integer(self, width: int, name: str, signed: bool) -> str:
        key = ("synthetic-int", width, name, signed)
        if key in self._by_key:
            result = self._by_key[key]
            assert result is not None
            return result
        identifier = f"type:base:{'s' if signed else 'u'}{width * 8}"
        return self._insert(key, {
            "id": identifier,
            "kind": "base",
            "name": name,
            "byte_size": width,
            "encoding": "signed" if signed else "unsigned",
        })

    def _anonymous_key(self, bn_type: Any, name: str | None) -> tuple[Any, ...]:
        class_name = _enum_name(getattr(bn_type, "type_class", type(bn_type).__name__))
        shallow = [class_name, int(getattr(bn_type, "width", 0)), name, self._display(bn_type)]
        if class_name == "StructureTypeClass":
            shallow.extend(
                (
                    str(getattr(member, "name", "")),
                    int(getattr(member, "offset", 0)),
                    self._display(getattr(member, "type", None)),
                )
                for member in getattr(bn_type, "members", ())
            )
            shallow.extend(
                (
                    "base",
                    int(getattr(base, "offset", 0)),
                    self._display(getattr(base, "type", None)),
                )
                for base in getattr(bn_type, "base_structures", ())
            )
        return tuple(shallow)

    def _registered_name(self, bn_type: Any) -> str | None:
        registered = getattr(bn_type, "registered_name", None)
        return _qualified_name(getattr(registered, "name", None)) or None

    def _display(self, bn_type: Any) -> str:
        if bn_type is None:
            return "void"
        try:
            return str(bn_type.get_string())
        except (AttributeError, TypeError):
            return str(bn_type)

    def _unsupported(self, bn_type: Any, reason: str) -> None:
        self._warn("unsupported-type", f"{reason}: {self._display(bn_type)!r}")
        return None

    def _insert(self, key: tuple[Any, ...], entry: dict[str, Any]) -> str:
        identifier = entry["id"]
        self._by_key[key] = identifier
        self._append_entry(entry)
        return identifier

    def _append_entry(self, entry: dict[str, Any]) -> None:
        identifier = entry["id"]
        existing = self._entries_by_id.get(identifier)
        if existing is not None:
            if existing != entry:
                raise ValueError(f"type id collision for {identifier!r}")
            return
        self._entries_by_id[identifier] = entry
        self.entries.append(entry)

    def _warn(self, code: str, message: str, **context: Any) -> None:
        self.diagnostics.append(Diagnostic("warning", code, message, context))
