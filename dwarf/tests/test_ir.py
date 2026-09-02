from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.ir import (  # noqa: E402
    Address,
    AddressRange,
    Architecture,
    Binary,
    Document,
    Endianness,
    Function,
    IrValidationError,
    Line,
    Location,
    LocationExpression,
    Scope,
    Section,
    Source,
    Variable,
)


def code_range(start: int, end: int) -> AddressRange:
    return AddressRange(Address(start, "text"), Address(end, "text"))


def valid_document() -> Document:
    local = Variable(
        id="var:main:x",
        name="x",
        kind="local",
        type_id="type:int",
        locations=[
            Location(code_range(0x1010, 0x1020), LocationExpression.frame_offset(-16)),
            Location(
                code_range(0x1020, 0x1030),
                LocationExpression.unavailable("value is no longer proven"),
            ),
        ],
    )
    parameter = Variable(
        id="var:main:argc",
        name="argc",
        kind="parameter",
        type_id="type:int",
        locations=[
            Location(
                code_range(0x1000, 0x1008),
                LocationExpression(
                    kind="entry_value",
                    expression=LocationExpression.register_location("rdi"),
                ),
            ),
            Location(
                code_range(0x1008, 0x1040),
                LocationExpression.unavailable("entry argument storage is no longer proven"),
            ),
        ],
    )
    root_scope = Scope(
        id="scope:main",
        ranges=[code_range(0x1000, 0x1040)],
        children=[
            Scope(
                id="scope:main:body",
                ranges=[code_range(0x1010, 0x1030)],
                variables=[local],
            )
        ],
    )
    return Document(
        producer="test",
        binary=Binary(
            filename="fixture",
            architecture=Architecture.X86_64,
            endianness=Endianness.LITTLE,
            entry_point=0x1000,
            image_base=0,
        ),
        sections=[Section("text", ".text", 0x1000, 0x100, executable=True)],
        types=[
            {
                "id": "type:int",
                "kind": "base",
                "name": "int",
                "byte_size": 4,
                "encoding": "signed",
            }
        ],
        functions=[
            Function(
                id="function:main",
                name="main",
                ranges=[code_range(0x1000, 0x1040)],
                return_type="type:int",
                parameters=[parameter],
                scope=root_scope,
            )
        ],
        sources=[Source("source:main", "teemo/main.c", "c", True, "int main(void) {}\n")],
        lines=[Line(code_range(0x1000, 0x1010), "source:main", 1)],
    )


class IrTests(unittest.TestCase):
    def test_valid_document_serializes_enums_and_address_size(self) -> None:
        encoded = json.loads(valid_document().dumps())
        self.assertEqual(encoded["schema"], "pwnc.teemo.ir")
        self.assertEqual(encoded["version"], 1)
        self.assertEqual(encoded["binary"]["architecture"], "x86_64")
        self.assertEqual(encoded["binary"]["address_size"], 8)
        self.assertNotIn("build_id", encoded["binary"])

    def test_rejects_cross_section_range(self) -> None:
        document = valid_document()
        document.lines[0] = Line(
            AddressRange(Address(0x1000, "text"), Address(0x2000, None)),
            "source:main",
            1,
        )
        with self.assertRaisesRegex(IrValidationError, "crosses section boundaries"):
            document.validate()

    def test_rejects_overlapping_variable_locations(self) -> None:
        document = valid_document()
        variable = document.functions[0].scope.children[0].variables[0]
        variable.locations.append(
            Location(code_range(0x1018, 0x1028), LocationExpression.register_location("rax"))
        )
        with self.assertRaisesRegex(IrValidationError, "overlapping location ranges"):
            document.validate()

    def test_rejects_implicit_variable_location_gap(self) -> None:
        document = valid_document()
        document.functions[0].parameters[0].locations.pop()
        with self.assertRaisesRegex(IrValidationError, "does not explicitly cover"):
            document.validate()

    def test_rejects_scope_outside_function(self) -> None:
        document = valid_document()
        document.functions[0].scope.children[0].ranges = [code_range(0x1030, 0x1050)]
        with self.assertRaisesRegex(IrValidationError, "outside function"):
            document.validate()

    def test_rejects_root_scope_different_from_function(self) -> None:
        document = valid_document()
        document.functions[0].scope.ranges = [code_range(0x1010, 0x1040)]
        with self.assertRaisesRegex(IrValidationError, "root scope does not match"):
            document.validate()

    def test_rejects_missing_type_reference(self) -> None:
        document = valid_document()
        document.types.append(
            {"id": "type:pointer", "kind": "pointer", "target": "type:missing", "byte_size": 8}
        )
        with self.assertRaisesRegex(IrValidationError, "references missing type"):
            document.validate()

    def test_rejects_big_endian_x86(self) -> None:
        document = valid_document()
        document.binary = Binary(
            filename="fixture",
            architecture=Architecture.X86_64,
            endianness=Endianness.BIG,
            entry_point=0x1000,
            image_base=0,
        )
        with self.assertRaisesRegex(IrValidationError, "big-endian x86"):
            document.validate()

    def test_rejects_malformed_build_id_and_duplicate_source_path(self) -> None:
        document = valid_document()
        document.binary = Binary(
            filename="fixture",
            architecture=Architecture.X86_64,
            endianness=Endianness.LITTLE,
            entry_point=0x1000,
            image_base=0,
            build_id="not-hex",
        )
        document.sources.append(Source("source:duplicate", "teemo/main.c", "c", True, ""))
        with self.assertRaisesRegex(IrValidationError, "build id") as raised:
            document.validate()
        self.assertIn("duplicate generated source path", str(raised.exception))

    def test_rejects_location_payload_not_accepted_by_rust_contract(self) -> None:
        document = valid_document()
        document.functions[0].parameters[0].locations[0] = Location(
            code_range(0x1000, 0x1008),
            LocationExpression(kind="register", register="rdi", offset=8),
        )
        with self.assertRaisesRegex(IrValidationError, "unexpected fields"):
            document.validate()

        document = valid_document()
        document.functions[0].parameters[0].locations[0] = Location(
            code_range(0x1000, 0x1008),
            LocationExpression(kind="constant", value=1 << 80),
        )
        with self.assertRaisesRegex(IrValidationError, "invalid constant value"):
            document.validate()


if __name__ == "__main__":
    unittest.main()
