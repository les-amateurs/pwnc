from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys
import unittest


PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.type_export import BinjaTypeExporter  # noqa: E402


@dataclass(frozen=True)
class EnumValue:
    name: str


@dataclass
class FakeType:
    type_class: EnumValue
    width: int = 0
    text: str = ""
    const: bool = False
    volatile: bool = False
    altname: str = ""
    signed: bool = True
    registered_name: object | None = None
    target: object | None = None
    element_type: object | None = None
    count: int = 0
    type: object | None = None
    members: list[object] = field(default_factory=list)
    base_structures: list[object] = field(default_factory=list)
    parameters: list[object] = field(default_factory=list)
    return_value: object | None = None
    has_variable_arguments: bool = False
    calling_convention: object | None = None

    def get_string(self) -> str:
        return self.text or self.type_class.name


@dataclass
class NamedReference(FakeType):
    type_id: str = ""
    name: str = ""
    named_type_class: EnumValue = field(default_factory=lambda: EnumValue("UnknownNamedTypeClass"))


@dataclass
class Member:
    name: str
    type: object
    offset: int
    bit_width: int = 0
    bit_offset: int = 0


@dataclass
class BaseStructure:
    type: object
    offset: int


class FakeView:
    def __init__(self) -> None:
        self.targets: dict[str, object] = {}
        self.types: dict[str, object] = {}

    def get_type_by_id(self, identifier: str) -> object | None:
        return self.targets.get(identifier)


def fake_type(class_name: str, **kwargs: object) -> FakeType:
    return FakeType(EnumValue(class_name), **kwargs)


class TypeExportTests(unittest.TestCase):
    def test_recursive_named_structure_is_cycle_safe(self) -> None:
        view = FakeView()
        node_ref = NamedReference(
            EnumValue("NamedTypeReferenceClass"),
            width=8,
            text="struct node",
            type_id="id-node",
            name="node",
            named_type_class=EnumValue("StructNamedTypeClass"),
        )
        pointer = fake_type("PointerTypeClass", width=8, text="struct node *", target=node_ref)
        integer = fake_type("IntegerTypeClass", width=4, text="int", altname="int")
        node = fake_type(
            "StructureTypeClass",
            width=16,
            text="struct node",
            type=EnumValue("StructStructureType"),
            members=[Member("value", integer, 0), Member("next", pointer, 8)],
        )
        view.targets["id-node"] = node
        exporter = BinjaTypeExporter(view)
        result = exporter.export(node_ref)
        entries = {entry["id"]: entry for entry in exporter.finish()}
        self.assertEqual(entries[result]["kind"], "structure")
        next_member = entries[result]["members"][1]
        pointer_entry = entries[next_member["type_id"]]
        self.assertEqual(pointer_entry["target"], result)
        self.assertFalse(exporter.diagnostics)

    def test_qualifiers_wrap_raw_type_deterministically(self) -> None:
        integer = fake_type(
            "IntegerTypeClass",
            width=4,
            text="const volatile unsigned int",
            altname="unsigned int",
            signed=False,
            const=True,
            volatile=True,
        )
        exporter = BinjaTypeExporter(FakeView())
        result = exporter.export(integer)
        entries = {entry["id"]: entry for entry in exporter.finish()}
        self.assertEqual(entries[result]["qualifier"], "volatile")
        const_id = entries[result]["target"]
        self.assertEqual(entries[const_id]["qualifier"], "const")
        self.assertEqual(entries[entries[const_id]["target"]]["encoding"], "unsigned")

    def test_arrays_enums_functions_and_bitfields(self) -> None:
        view = FakeView()
        integer = fake_type("IntegerTypeClass", width=4, text="int", altname="int")
        array = fake_type("ArrayTypeClass", width=12, text="int[3]", element_type=integer, count=3)
        enum_member = type("EnumMember", (), {"name": "RED", "value": 7})()
        enum = fake_type("EnumerationTypeClass", width=4, text="enum color", signed=False, members=[enum_member])
        structure = fake_type(
            "StructureTypeClass",
            width=4,
            text="struct bits",
            type=EnumValue("StructStructureType"),
            members=[Member("flag", integer, 0, bit_width=1, bit_offset=3)],
        )
        parameter = type("Parameter", (), {"name": "items", "type": array})()
        convention = type("Convention", (), {"name": "cdecl"})()
        function = fake_type(
            "FunctionTypeClass",
            text="int (int[3])",
            return_value=integer,
            parameters=[parameter],
            has_variable_arguments=True,
            calling_convention=convention,
        )
        exporter = BinjaTypeExporter(view)
        ids = [exporter.export(value) for value in (array, enum, structure, function)]
        entries = {entry["id"]: entry for entry in exporter.finish()}
        self.assertEqual(entries[ids[0]]["dimensions"], [{"lower_bound": 0, "count": 3}])
        self.assertEqual(entries[ids[1]]["enumerators"], [{"name": "RED", "value": 7}])
        self.assertEqual(entries[ids[2]]["members"][0]["bit_offset"], 3)
        self.assertTrue(entries[ids[3]]["variadic"])
        self.assertEqual(entries[ids[3]]["calling_convention"], "cdecl")

    def test_unresolved_named_structure_is_opaque_but_usable(self) -> None:
        reference = NamedReference(
            EnumValue("NamedTypeReferenceClass"),
            text="struct opaque",
            type_id="missing",
            name="opaque",
            named_type_class=EnumValue("StructNamedTypeClass"),
        )
        exporter = BinjaTypeExporter(FakeView())
        identifier = exporter.export(reference)
        entry = {entry["id"]: entry for entry in exporter.finish()}[identifier]
        self.assertTrue(entry["declaration_only"])
        self.assertEqual(exporter.diagnostics[0].code, "opaque-type")

    def test_registered_typedef_does_not_reference_itself(self) -> None:
        view = FakeView()
        reference = NamedReference(
            EnumValue("NamedTypeReferenceClass"),
            width=4,
            text="word",
            type_id="word-id",
            name="word",
            named_type_class=EnumValue("TypedefNamedTypeClass"),
        )
        integer = fake_type(
            "IntegerTypeClass",
            width=4,
            text="volatile word",
            altname="unsigned int",
            signed=False,
            volatile=True,
            registered_name=reference,
        )
        view.targets["word-id"] = integer
        exporter = BinjaTypeExporter(view)
        identifier = exporter.export(reference)
        entries = {entry["id"]: entry for entry in exporter.finish()}
        self.assertNotEqual(entries[identifier]["target"], identifier)
        qualified = entries[entries[identifier]["target"]]
        self.assertEqual(qualified["qualifier"], "volatile")
        self.assertEqual(entries[qualified["target"]]["encoding"], "unsigned")

    def test_class_inheritance_is_preserved(self) -> None:
        view = FakeView()
        integer = fake_type("IntegerTypeClass", width=4, text="int", altname="int")
        base_reference = NamedReference(
            EnumValue("NamedTypeReferenceClass"),
            text="class Base",
            type_id="base-id",
            name="Base",
            named_type_class=EnumValue("ClassNamedTypeClass"),
        )
        derived_reference = NamedReference(
            EnumValue("NamedTypeReferenceClass"),
            text="class Derived",
            type_id="derived-id",
            name="Derived",
            named_type_class=EnumValue("ClassNamedTypeClass"),
        )
        view.targets["base-id"] = fake_type(
            "StructureTypeClass",
            width=4,
            text="class Base",
            type=EnumValue("ClassStructureType"),
            members=[Member("base_value", integer, 0)],
        )
        view.targets["derived-id"] = fake_type(
            "StructureTypeClass",
            width=8,
            text="class Derived",
            type=EnumValue("ClassStructureType"),
            members=[Member("derived_value", integer, 4)],
            base_structures=[BaseStructure(base_reference, 0)],
        )
        exporter = BinjaTypeExporter(view)
        derived_id = exporter.export(derived_reference)
        entries = {entry["id"]: entry for entry in exporter.finish()}
        self.assertEqual(entries[derived_id]["kind"], "class")
        base_id = entries[derived_id]["bases"][0]["type_id"]
        self.assertEqual(entries[base_id]["name"], "Base")


if __name__ == "__main__":
    unittest.main()
