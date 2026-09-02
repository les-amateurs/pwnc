from __future__ import annotations

from pathlib import Path
import struct
import sys
import tempfile
import unittest


PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.extractor import (  # noqa: E402
    BinaryNinjaExtractor,
    ExtractionError,
    _architecture,
    _build_ssa_index,
    _constant_value,
    _elf_build_id,
    _gnu_build_id_from_notes,
    _sanitize_component,
    _ssa_constant_evidence,
    _stack_cfa_offset,
)
from teemo.analysis import MachineInstruction, Span  # noqa: E402
from teemo.ir import Architecture, Endianness  # noqa: E402


def _note(order: str, name: bytes, description: bytes, note_type: int = 3) -> bytes:
    result = struct.pack(order + "III", len(name), len(description), note_type)
    result += name + b"\0" * (-len(name) % 4)
    result += description + b"\0" * (-len(description) % 4)
    return result


def _elf_with_notes(elf_class: int, order: str, notes: bytes) -> bytes:
    encoding = 1 if order == "<" else 2
    ident = b"\x7fELF" + bytes((elf_class, encoding, 1)) + b"\0" * 9
    note_offset = 0x200
    image_size = note_offset + len(notes)
    if elf_class == 1:
        header_size = 52
        entry_size = 32
        header = struct.pack(
            order + "HHIIIIIHHHHHH",
            3,
            3,
            1,
            0,
            header_size,
            0,
            0,
            header_size,
            entry_size,
            2,
            0,
            0,
            0,
        )
        load = struct.pack(order + "IIIIIIII", 1, 0, 0, 0, image_size, image_size, 4, 0x1000)
        note = struct.pack(
            order + "IIIIIIII",
            4,
            note_offset,
            note_offset,
            note_offset,
            len(notes),
            len(notes),
            4,
            4,
        )
    else:
        header_size = 64
        entry_size = 56
        header = struct.pack(
            order + "HHIQQQIHHHHHH",
            3,
            62,
            1,
            0,
            header_size,
            0,
            0,
            header_size,
            entry_size,
            2,
            0,
            0,
            0,
        )
        load = struct.pack(order + "IIQQQQQQ", 1, 4, 0, 0, 0, image_size, image_size, 0x1000)
        note = struct.pack(
            order + "IIQQQQQQ",
            4,
            4,
            note_offset,
            note_offset,
            note_offset,
            len(notes),
            len(notes),
            4,
        )
    prefix = ident + header + load + note
    return prefix + b"\0" * (note_offset - len(prefix)) + notes


class _BytesView:
    sections: dict[str, object] = {}
    original_image_base = 0
    start = 0
    segments: tuple[object, ...] = ()
    name = "/definitely/missing/teemo-build-id-fixture"

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.reads: list[tuple[int, int]] = []

    def read(self, address: int, size: int) -> bytes:
        self.reads.append((address, size))
        if address < 0 or address > len(self.data):
            return b""
        return self.data[address : address + size]


class ExtractorHelperTests(unittest.TestCase):
    def test_required_architecture_aliases(self) -> None:
        self.assertEqual(_architecture("x86_64"), Architecture.X86_64)
        self.assertEqual(_architecture("i386"), Architecture.X86)
        self.assertEqual(_architecture("armv7"), Architecture.ARM)
        self.assertEqual(_architecture("thumb2"), Architecture.ARM)
        self.assertEqual(_architecture("aarch64"), Architecture.AARCH64)
        with self.assertRaises(ExtractionError):
            _architecture("mipsel32")

    def test_stack_storage_is_normalized_to_cfa(self) -> None:
        self.assertEqual(_stack_cfa_offset(Architecture.X86_64, -8), -16)
        self.assertEqual(_stack_cfa_offset(Architecture.X86, 8), 4)
        self.assertEqual(_stack_cfa_offset(Architecture.ARM, -8), -8)
        self.assertEqual(_stack_cfa_offset(Architecture.AARCH64, 16), 16)

    def test_safe_generated_component(self) -> None:
        self.assertEqual(_sanitize_component("operator /<bad>", "function"), "operator_bad")
        self.assertEqual(_sanitize_component("../", "function"), "function")

    def test_only_proven_constants_are_exported(self) -> None:
        constant = type("Value", (), {"type": type("Kind", (), {"name": "ConstantValue"})(), "value": 7})()
        unknown = type("Value", (), {"type": type("Kind", (), {"name": "UndeterminedValue"})(), "value": 7})()
        self.assertEqual(_constant_value(constant), 7)
        self.assertIsNone(_constant_value(unknown))

    def test_parses_gnu_build_id_note(self) -> None:
        note = b"\x04\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00GNU\x00\x01\x02\x03\x04"
        section = type("Section", (), {"start": 0x1000, "end": 0x1000 + len(note)})()
        view = type(
            "View",
            (),
            {"sections": {".note.gnu.build-id": section}, "read": lambda _self, _start, _size: note},
        )()
        self.assertEqual(_elf_build_id(view, Endianness.LITTLE), "01020304")

    def test_scans_noncanonical_note_sections_and_aligned_big_endian_records(self) -> None:
        notes = _note(">", b"CORE\0", b"ignored", 1) + _note(">", b"GNU\0", b"\xaa\xbb\xcc")
        section = type("Section", (), {"start": 0x2000, "end": 0x2000 + len(notes)})()
        view = type(
            "View",
            (),
            {
                "sections": {".note.vendor-build": section},
                "name": "/missing",
                "read": lambda _self, _start, _size: notes,
            },
        )()
        self.assertEqual(_elf_build_id(view, Endianness.BIG), "aabbcc")

    def test_note_parser_rejects_malformed_empty_and_wrong_endian_records(self) -> None:
        valid = _note("<", b"GNU\0", b"\x01\x02\x03\x04")
        oversized = struct.pack("<III", 4, 0xFFFFFFFF, 3) + b"GNU\0"
        empty = _note("<", b"GNU\0", b"")
        self.assertIsNone(_gnu_build_id_from_notes(valid[:-1], "<"))
        self.assertIsNone(_gnu_build_id_from_notes(oversized, "<"))
        self.assertIsNone(_gnu_build_id_from_notes(empty, "<"))
        self.assertIsNone(_gnu_build_id_from_notes(valid, ">"))
        self.assertIsNone(_gnu_build_id_from_notes(valid, "invalid"))

    def test_parses_bounded_program_notes_from_original_elf_file(self) -> None:
        build_id = bytes.fromhex("1a79fe02cc88ebf72a858a91b59c8d17c29a59fb")
        image = _elf_with_notes(1, "<", _note("<", b"GNU\0", build_id))
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "challenge"
            binary.write_bytes(image)
            view = type(
                "View",
                (),
                {
                    "sections": {},
                    "file": type("File", (), {"original_filename": str(binary), "filename": str(binary)})(),
                    "read": lambda _self, _address, _size: b"",
                },
            )()
            self.assertEqual(_elf_build_id(view, Endianness.LITTLE), build_id.hex())

    def test_parses_big_endian_elf64_program_notes_from_mapped_view(self) -> None:
        image = _elf_with_notes(2, ">", _note(">", b"GNU\0", b"\x10\x20\x30\x40"))
        view = _BytesView(image)
        self.assertEqual(_elf_build_id(view, Endianness.BIG), "10203040")

    def test_program_header_and_note_bounds_prevent_oversized_reads(self) -> None:
        image = bytearray(_elf_with_notes(1, "<", _note("<", b"GNU\0", b"1234")))
        # e_phnum is the final 16-bit field at offset 44 in an ELF32 header.
        struct.pack_into("<H", image, 44, 4097)
        view = _BytesView(bytes(image))
        self.assertIsNone(_elf_build_id(view, Endianness.LITTLE))
        self.assertTrue(view.reads)
        self.assertLessEqual(max(size for _address, size in view.reads), 36)

        image = bytearray(_elf_with_notes(1, "<", _note("<", b"GNU\0", b"1234")))
        # The second ELF32 program header starts at 84; p_filesz is +16.
        struct.pack_into("<I", image, 84 + 16, 1024 * 1024 + 1)
        view = _BytesView(bytes(image))
        self.assertIsNone(_elf_build_id(view, Endianness.LITTLE))
        self.assertLessEqual(max(size for _address, size in view.reads), 64)

    def test_parameter_flow_tracks_proven_register_and_stack_moves(self) -> None:
        info = lambda name: type("RegisterInfo", (), {"full_width_reg": name})()
        arch = type(
            "Architecture",
            (),
            {
                "full_width_regs": ["r0", "r1"],
                "regs": {"r0": info("r0"), "r1": info("r1")},
                "get_reg_name": lambda _self, index: {0: "r0", 1: "r1"}[index],
            },
        )()
        parameter = FakeVariable(11, "argument", "RegisterVariableSourceType", 0)
        stack = FakeVariable(12, "spill", "StackVariableSourceType", -4)

        def value(kind: str, register: str | None = None) -> object:
            return type(
                "Value",
                (),
                {
                    "type": FakeEnum(kind),
                    "reg": register,
                    "value": 0,
                    "offset": 0,
                },
            )()

        class FlowFunction:
            start = 0x1000
            name = "flow"
            parameter_vars = [parameter]
            stack_layout = [stack]

            def get_reg_value_at(self, address: int, register: str, _arch: object) -> object:
                if (address, register) == (0x1000, "r0"):
                    return value("EntryValue", "r0")
                if (address, register) == (0x1004, "r1"):
                    return value("EntryValue", "r0")
                return value("UndeterminedValue")

            def get_stack_contents_at(self, address: int, offset: int, size: int, _arch: object) -> object:
                if (address, offset, size) == (0x1008, -4, 4):
                    return value("EntryValue", "r0")
                return value("UndeterminedValue")

        function = FlowFunction()
        function.arch = arch
        machine = tuple(
            MachineInstruction(Span("text", address, address + 4))
            for address in (0x1000, 0x1004, 0x1008)
        )
        extractor = object.__new__(BinaryNinjaExtractor)
        extractor.architecture = Architecture.ARM
        extractor.diagnostics = []
        extractor._parameter_flow_cache = {}
        evidence = extractor._parameter_flow_evidence(function, machine)[str(parameter.identifier)]
        self.assertEqual(
            [(item.span.start, item.expression.kind, item.expression.register, item.expression.offset) for item in evidence],
            [
                (0x1000, "register", "r0", None),
                (0x1004, "register", "r1", None),
                (0x1008, "cfa_offset", None, -4),
            ],
        )

    def test_parameter_flow_queries_block_entries_and_register_writes(self) -> None:
        register_names = [f"r{index}" for index in range(32)]
        info = lambda name: type("RegisterInfo", (), {"full_width_reg": name})()
        arch = type(
            "Architecture",
            (),
            {
                "full_width_regs": register_names,
                "regs": {name: info(name) for name in register_names},
                "get_reg_name": lambda _self, index: register_names[index],
            },
        )()
        parameter = FakeVariable(41, "argument", "RegisterVariableSourceType", 0)

        def value(kind: str, register: str | None = None) -> object:
            return type(
                "Value",
                (),
                {
                    "type": FakeEnum(kind),
                    "reg": register,
                    "value": 0,
                    "offset": 0,
                },
            )()

        class FlowFunction:
            start = 0x4000
            name = "flow-block-cache"
            parameter_vars = [parameter]
            stack_layout: list[object] = []
            query_calls: list[tuple[int, str]] = []

            def get_regs_written_by(self, address: int, _arch: object) -> list[str]:
                return ["r1"] if address == 0x4000 else []

            def get_reg_value_at(self, address: int, register: str, _arch: object) -> object:
                self.query_calls.append((address, register))
                if register == "r0":
                    return value("EntryValue", "r0")
                if register == "r1" and address >= 0x4004:
                    return value("EntryValue", "r0")
                return value("UndeterminedValue")

            def get_stack_contents_at(
                self,
                _address: int,
                _offset: int,
                _size: int,
                _arch: object,
            ) -> object:
                raise AssertionError("there are no stack candidates")

        function = FlowFunction()
        function.arch = arch
        machine = tuple(
            MachineInstruction(Span("text", address, address + 4), block=0x4000)
            for address in (0x4000, 0x4004, 0x4008)
        )
        extractor = object.__new__(BinaryNinjaExtractor)
        extractor.architecture = Architecture.ARM
        extractor.diagnostics = []
        extractor._parameter_flow_cache = {}

        evidence = extractor._parameter_flow_evidence(function, machine)[str(parameter.identifier)]

        self.assertEqual(
            function.query_calls,
            [(0x4000, "r0"), (0x4000, "r1"), (0x4004, "r1")],
        )
        self.assertEqual(
            [(item.span.start, item.expression.register) for item in evidence],
            [
                (0x4000, "r0"),
                (0x4004, "r0"),
                (0x4004, "r1"),
                (0x4008, "r0"),
                (0x4008, "r1"),
            ],
        )

    def test_parameter_spill_evidence_requires_the_complete_width(self) -> None:
        info = lambda name: type("RegisterInfo", (), {"full_width_reg": name})()
        arch = type(
            "Architecture",
            (),
            {
                "full_width_regs": [],
                "regs": {"x0": info("x0"), "x1": info("x1")},
                "get_reg_name": lambda _self, index: {0: "x0", 1: "x1"}[index],
            },
        )()
        narrow = FakeVariable(31, "narrow", "RegisterVariableSourceType", 0)
        wide = FakeVariable(32, "wide", "RegisterVariableSourceType", 1)
        wide.type = type("WideType", (), {"width": 8})()
        stack = FakeVariable(33, "spill", "StackVariableSourceType", -8)

        def value(kind: str, register: str | None = None) -> object:
            return type(
                "Value",
                (),
                {
                    "type": FakeEnum(kind),
                    "reg": register,
                    "value": 0,
                    "offset": 0,
                },
            )()

        class FlowFunction:
            start = 0x3000
            name = "flow-width"
            parameter_vars = [narrow, wide]
            stack_layout = [stack]

            def get_reg_value_at(self, _address: int, _register: str, _arch: object) -> object:
                return value("UndeterminedValue")

            def get_stack_contents_at(
                self,
                _address: int,
                offset: int,
                size: int,
                _arch: object,
            ) -> object:
                if offset == -8 and size in {4, 8}:
                    return value("EntryValue", "x1")
                return value("UndeterminedValue")

        function = FlowFunction()
        function.arch = arch
        extractor = object.__new__(BinaryNinjaExtractor)
        extractor.architecture = Architecture.AARCH64
        extractor.diagnostics = []
        extractor._parameter_flow_cache = {}
        evidence = extractor._parameter_flow_evidence(
            function,
            [MachineInstruction(Span("text", 0x3000, 0x3004))],
        )
        self.assertFalse(evidence[str(narrow.identifier)])
        self.assertEqual(len(evidence[str(wide.identifier)]), 1)
        self.assertEqual(evidence[str(wide.identifier)][0].expression.offset, -8)

    def test_ssa_def_use_proves_constant_location_at_use(self) -> None:
        variable = FakeVariable(21, "folded", "RegisterVariableSourceType", 0)
        use = type("Use", (), {"address": 0x2004})()
        definition = type("Definition", (), {"address": 0x2000})()
        ssa_variable = type(
            "SsaVariable",
            (),
            {
                "var": variable,
                "version": 3,
                "def_site": definition,
                "use_sites": [use],
            },
        )()
        instruction = type(
            "SsaInstruction",
            (),
            {"vars_read": [ssa_variable], "vars_written": []},
        )()
        constant = type(
            "Value",
            (),
            {"type": FakeEnum("ConstantValue"), "value": 42},
        )()
        ssa = type(
            "SsaFunction",
            (),
            {
                "instructions": [instruction],
                "get_ssa_var_value": lambda _self, _variable: constant,
            },
        )()
        function = type("Function", (), {"mlil": type("Mlil", (), {"ssa_form": ssa})()})()
        indexed_ssa, index = _build_ssa_index(function)
        evidence = _ssa_constant_evidence(
            indexed_ssa,
            index[str(variable.identifier)],
            [MachineInstruction(Span("text", 0x2004, 0x2008))],
        )
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].expression.kind, "stack_value")
        self.assertEqual(evidence[0].expression.expression.value, 42)


class FakeEnum:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeIntegerType:
    type_class = FakeEnum("IntegerTypeClass")
    width = 4
    const = False
    volatile = False
    altname = "int"
    signed = True
    registered_name = None

    def get_string(self) -> str:
        return "int"


class FakeVariable:
    def __init__(self, identifier: int, name: str, source: str, storage: int) -> None:
        self.identifier = identifier
        self.index = identifier
        self.name = name
        self.source_type = FakeEnum(source)
        self.storage = storage
        self.type = FakeIntegerType()


class FakeNode:
    def __init__(self, identifier: int, operation: str, parent: object | None = None) -> None:
        self.expr_index = identifier
        self.operation = FakeEnum(operation)
        self.parent = parent
        self.instruction_operands: list[object] = []


class FakeLine:
    def __init__(self, text: str, owner: object) -> None:
        self.tokens = [type("Token", (), {"text": text})()]
        self.il_instruction = owner


class FakeFunction:
    def __init__(self, view: object) -> None:
        self.start = 0x1000
        self.name = "demo"
        self.arch = view.arch
        self.address_ranges = [type("Range", (), {"start": 0x1000, "end": 0x100C})()]
        self.instructions = [([], 0x1000), ([], 0x1004), ([], 0x1008)]
        self.is_exported = True
        self.symbol = type("Symbol", (), {"raw_name": "demo"})()
        self.parameter = FakeVariable(1, "argc", "RegisterVariableSourceType", 0)
        self.local = FakeVariable(2, "value", "StackVariableSourceType", -8)
        self.parameter_vars = [self.parameter]
        self.vars = [self.parameter, self.local]

        root = FakeNode(0, "HLIL_BLOCK")
        declaration = FakeNode(1, "HLIL_VAR_INIT", root)
        declaration.dest = self.local
        assignment = FakeNode(2, "HLIL_ASSIGN", root)
        argument = FakeNode(3, "HLIL_VAR", assignment)
        argument.var = self.parameter
        assignment.instruction_operands = [argument]
        returned = FakeNode(4, "HLIL_RET", root)
        local_ref = FakeNode(5, "HLIL_VAR", returned)
        local_ref.var = self.local
        returned.instruction_operands = [local_ref]
        root.instruction_operands = [declaration, assignment, returned]
        root.lines = [
            FakeLine("int demo(int argc)", root),
            FakeLine("{", root),
            FakeLine("    int value", declaration),
            FakeLine("    value = argc", assignment),
            FakeLine("    return value", returned),
            FakeLine("}", root),
        ]
        self.nodes = {node.expr_index: node for node in [root, declaration, assignment, argument, returned, local_ref]}
        self.hlil = type(
            "HLIL",
            (),
            {"root": root, "vars": [self.parameter, self.local], "aliased_vars": []},
        )()
        self.type = type(
            "FunctionType",
            (),
            {"return_value": FakeIntegerType(), "has_variable_arguments": False},
        )()

    def get_low_level_ils_at(self, address: int, _arch: object) -> list[object]:
        node = {0x1000: self.nodes[1], 0x1004: self.nodes[2], 0x1008: self.nodes[4]}[address]
        return [type("LLIL", (), {"hlils": [node]})()]

    def get_basic_block_at(self, _address: int) -> object:
        return type("Block", (), {"start": 0x1000})()

    def get_hlil_var_refs(self, variable: FakeVariable) -> list[object]:
        expr_id = 3 if variable is self.parameter else 5
        return [type("Reference", (), {"expr_id": expr_id})()]


class FakeView:
    def __init__(self) -> None:
        self.view_type = "ELF"
        self.arch = type(
            "Architecture",
            (),
            {"name": "x86_64", "get_reg_name": lambda _self, register: {0: "rdi"}[register]},
        )()
        self.endianness = FakeEnum("LittleEndian")
        self.entry_point = 0x1000
        self.original_image_base = 0
        self.start = 0x1000
        self.file = type("File", (), {"original_filename": "/tmp/demo"})()
        self.types = {}
        text = type(
            "Section",
            (),
            {"start": 0x1000, "end": 0x1100, "semantics": FakeEnum("ReadOnlyCodeSectionSemantics")},
        )()
        data = type(
            "Section",
            (),
            {"start": 0x2000, "end": 0x2100, "semantics": FakeEnum("ReadWriteDataSectionSemantics")},
        )()
        self.sections = {".text": text, ".data": data}
        self.functions = [FakeFunction(self)]
        symbol = type(
            "Symbol",
            (),
            {
                "type": FakeEnum("DataSymbol"),
                "binding": FakeEnum("GlobalBinding"),
                "raw_name": "global_count",
            },
        )()
        self.data_vars = {
            0x2000: type(
                "DataVariable",
                (),
                {"symbol": symbol, "name": "global_count", "type": FakeIntegerType()},
            )()
        }
        self.symbols = {}

    def get_segment_at(self, address: int) -> object:
        executable = address < 0x2000
        return type("Segment", (), {"readable": True, "writable": not executable, "executable": executable})()

    def get_instruction_length(self, _address: int, _arch: object) -> int:
        return 4


class FullFakeExtractionTests(unittest.TestCase):
    def test_extracts_scopes_lines_variables_types_and_global(self) -> None:
        document = BinaryNinjaExtractor(FakeView()).extract()
        self.assertEqual(document.binary.architecture, Architecture.X86_64)
        self.assertEqual(len(document.functions), 1)
        function = document.functions[0]
        self.assertEqual([variable.name for variable in function.parameters], ["argc"])
        self.assertEqual([variable.name for variable in function.scope.variables], ["value"])
        self.assertEqual([line.line for line in document.lines], [3, 4, 5])
        self.assertEqual(document.globals[0].name, "global_count")
        self.assertEqual(function.scope.variables[0].locations[0].expression.kind, "cfa_offset")


if __name__ == "__main__":
    unittest.main()
