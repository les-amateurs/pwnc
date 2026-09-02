from __future__ import annotations

# ruff: noqa: I001 - the plugin import must follow the test-local sys.path insertion.

import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path


PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.format_analysis import (
    AnalysisLimits,
    DEFAULT_FORMAT_REGISTRY,
    FormatAnalysisReport,
    FormatCall,
    FormatFunction,
    FormatOrigin,
    FormatRegistry,
    InferredWrapper,
    OriginAssessment,
    ResolvedCallee,
    TEEMO_FORMAT_UNPROVEN_TAG,
    TEEMO_FORMAT_WRITABLE_TAG,
    TEEMO_PRINTF_LIKE_TAG,
    analyze_format_strings,
    bootstrap_format_function_types,
    classify_format_origin,
    diagnostics_for_report,
    normalize_abi_name,
    resolve_callee,
    synchronize_auto_tags,
)


class FakeEnum:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeValue:
    def __init__(
        self,
        kind: str,
        *,
        value: int | None = None,
        values: tuple[int, ...] = (),
        mapping: dict[int, int] | None = None,
    ) -> None:
        self.type = FakeEnum(kind)
        self.value = value
        self.values = values
        self.mapping = mapping or {}


class FakeNode:
    _next_expr = 1

    def __init__(self, operation: str, **attributes: object) -> None:
        self.operation = FakeEnum(operation)
        self.expr_index = int(attributes.pop("expr_index", self._allocate_expr()))
        self.address = int(attributes.pop("address", 0))
        self.instruction_operands = list(attributes.pop("instruction_operands", ()))
        for name, value in attributes.items():
            setattr(self, name, value)

    @classmethod
    def _allocate_expr(cls) -> int:
        result = cls._next_expr
        cls._next_expr += 1
        return result


class FakeVariable:
    def __init__(self, identifier: int, source_type: str = "RegisterVariableSourceType") -> None:
        self.identifier = identifier
        self.source_type = FakeEnum(source_type)


class FakeSymbol:
    def __init__(self, name: str, symbol_type: str = "FunctionSymbol") -> None:
        self.raw_name = name
        self.type = FakeEnum(symbol_type)


class FakeSegment:
    def __init__(self, start: int, end: int, *, readable: bool = True, writable: bool = False) -> None:
        self.start = start
        self.end = end
        self.readable = readable
        self.writable = writable


class FakeSection(FakeSegment):
    def __init__(self, name: str, start: int, end: int, *, writable: bool = False) -> None:
        super().__init__(start, end, writable=writable)
        self.name = name


class FakeFunction:
    def __init__(
        self,
        start: int,
        name: str,
        calls: tuple[FakeNode, ...] = (),
        parameters: tuple[FakeVariable, ...] = (),
    ) -> None:
        self.start = start
        self.name = name
        self.parameter_vars = list(parameters)
        root = FakeNode("HLIL_BLOCK", instruction_operands=calls)
        self.hlil = type("HLIL", (), {"root": root})()
        self.arch = object()
        self._address_tags: list[tuple[object, int, FakeTag]] = []
        self._function_tags: list[FakeTag] = []
        self.view: FakeView | None = None
        self.type = type("FunctionType", (), {"parameters": []})()
        self.has_user_type = False
        self.auto_type_strings: list[str] = []
        self.caller_update_marks = 0
        self.reanalysis_requests = 0

    @property
    def tags(self) -> tuple[tuple[object, int, FakeTag], ...]:
        return tuple(self._address_tags)

    def add_tag(self, tag_type: str, data: str, addr: int | None = None, auto: bool = False) -> None:
        assert self.view is not None and self.view.get_tag_type(tag_type) is not None
        tag = FakeTag(self.view.get_tag_type(tag_type), data, auto)
        if addr is None:
            self._function_tags.append(tag)
        else:
            self._address_tags.append((self.arch, addr, tag))

    def get_tags_at(self, addr: int, arch: object | None = None, auto: bool | None = None) -> list[FakeTag]:
        del arch
        return [
            tag for _arch, address, tag in self._address_tags if address == addr and (auto is None or tag.auto is auto)
        ]

    def remove_auto_address_tag(self, addr: int, tag: FakeTag, arch: object | None = None) -> None:
        del arch
        self._address_tags = [
            item for item in self._address_tags if not (item[1] == addr and item[2] is tag and tag.auto)
        ]

    def remove_auto_address_tags_of_type(
        self,
        addr: int,
        tag_type: str,
        arch: object | None = None,
    ) -> None:
        del arch
        self._address_tags = [
            item
            for item in self._address_tags
            if not (item[1] == addr and item[2].auto and item[2].type.name == tag_type)
        ]

    def get_function_tags(self, auto: bool | None = None, tag_type: str | None = None) -> list[FakeTag]:
        return [
            tag
            for tag in self._function_tags
            if (auto is None or tag.auto is auto) and (tag_type is None or tag.type.name == tag_type)
        ]

    def remove_auto_function_tag(self, tag: FakeTag) -> None:
        self._function_tags = [item for item in self._function_tags if not (item is tag and tag.auto)]

    def remove_auto_function_tags_of_type(self, tag_type: str) -> None:
        self._function_tags = [tag for tag in self._function_tags if not (tag.auto and tag.type.name == tag_type)]

    def set_auto_type(self, prototype: str) -> None:
        self.auto_type_strings.append(prototype)
        arguments = prototype[prototype.index("(") + 1 : prototype.rindex(")")].split(",")
        parameters = [argument for argument in arguments if argument.strip() and argument.strip() != "..."]
        self.type = type("FunctionType", (), {"parameters": [object() for _argument in parameters]})()

    def mark_caller_updates_required(self) -> None:
        self.caller_update_marks += 1

    def reanalyze(self) -> None:
        self.reanalysis_requests += 1


class FakeTagType:
    def __init__(self, name: str, icon: str) -> None:
        self.name = name
        self.icon = icon


class FakeTag:
    def __init__(self, tag_type: FakeTagType, data: str, auto: bool) -> None:
        self.type = tag_type
        self.data = data
        self.auto = auto


class FakeView:
    def __init__(self) -> None:
        self.functions: list[FakeFunction] = []
        self.symbols_by_address: dict[int, list[FakeSymbol]] = {}
        self.references: dict[int, tuple[int, ...]] = {}
        self.code_references: dict[int, tuple[FakeFunction, ...]] = {}
        self.segments: list[FakeSegment] = []
        self.sections: dict[str, FakeSection] = {}
        self.memory: dict[int, bytes] = {}
        self.tag_types: dict[str, FakeTagType] = {}
        self.analysis_updates = 0

    def add_function(self, function: FakeFunction) -> None:
        function.view = self
        self.functions.append(function)

    def get_symbols(self, address: int, length: int) -> list[FakeSymbol]:
        del length
        return list(self.symbols_by_address.get(address, ()))

    def get_symbol_at(self, address: int) -> FakeSymbol | None:
        return next(iter(self.symbols_by_address.get(address, ())), None)

    def get_functions_at(self, address: int) -> list[FakeFunction]:
        return [function for function in self.functions if function.start == address]

    def get_data_refs_from(self, address: int, length: int | None = None) -> tuple[int, ...]:
        del length
        return self.references.get(address, ())

    def get_code_refs(self, address: int) -> list[object]:
        return [type("Reference", (), {"function": function})() for function in self.code_references.get(address, ())]

    def get_segment_at(self, address: int) -> FakeSegment | None:
        return next((segment for segment in self.segments if segment.start <= address < segment.end), None)

    def get_sections_at(self, address: int) -> list[FakeSection]:
        return [section for section in self.sections.values() if section.start <= address < section.end]

    def read(self, address: int, size: int) -> bytes:
        for start, data in self.memory.items():
            if start <= address < start + len(data):
                offset = address - start
                return data[offset : offset + size]
        return b""

    def get_tag_type(self, name: str) -> FakeTagType | None:
        return self.tag_types.get(name)

    def create_tag_type(self, name: str, icon: str) -> FakeTagType:
        result = FakeTagType(name, icon)
        self.tag_types[name] = result
        return result

    def update_analysis_and_wait(self) -> None:
        self.analysis_updates += 1


def const_pointer(address: int) -> FakeNode:
    return FakeNode("HLIL_CONST_PTR", constant=address)


def variable_reference(variable: FakeVariable) -> FakeNode:
    return FakeNode("HLIL_VAR", var=variable)


def call(destination: FakeNode, params: tuple[FakeNode, ...], address: int) -> FakeNode:
    return FakeNode(
        "HLIL_CALL",
        dest=destination,
        params=params,
        address=address,
        instruction_operands=(destination, *params),
    )


class RegistryTests(unittest.TestCase):
    def test_exact_narrow_wide_and_fortified_indices(self) -> None:
        expected: dict[str, tuple[int, int]] = {}
        groups = (
            (("printf", "vprintf"), 0, 1),
            (
                (
                    "fprintf",
                    "vfprintf",
                    "sprintf",
                    "vsprintf",
                    "dprintf",
                    "vdprintf",
                    "asprintf",
                    "vasprintf",
                    "obstack_printf",
                    "obstack_vprintf",
                    "syslog",
                    "vsyslog",
                ),
                1,
                1,
            ),
            (("snprintf", "vsnprintf"), 2, 1),
            (("__printf_chk", "__vprintf_chk"), 1, 1),
            (
                (
                    "__fprintf_chk",
                    "__vfprintf_chk",
                    "__dprintf_chk",
                    "__vdprintf_chk",
                    "__asprintf_chk",
                    "__vasprintf_chk",
                    "__obstack_printf_chk",
                    "__obstack_vprintf_chk",
                    "__syslog_chk",
                    "__vsyslog_chk",
                ),
                2,
                1,
            ),
            (("__sprintf_chk", "__vsprintf_chk"), 3, 1),
            (("__snprintf_chk", "__vsnprintf_chk"), 4, 1),
            (("wprintf", "vwprintf"), 0, 4),
            (("fwprintf", "vfwprintf"), 1, 4),
            (("swprintf", "vswprintf"), 2, 4),
            (("__wprintf_chk", "__vwprintf_chk"), 1, 4),
            (("__fwprintf_chk", "__vfwprintf_chk"), 2, 4),
            (("__swprintf_chk", "__vswprintf_chk"), 4, 4),
        )
        for names, index, width in groups:
            expected.update({name: (index, width) for name in names})
        for name, expected_value in expected.items():
            with self.subTest(name=name):
                entry = DEFAULT_FORMAT_REGISTRY.resolve(name)
                self.assertIsNotNone(entry)
                assert entry is not None
                self.assertEqual((entry.format_index, entry.character_width), expected_value)

    def test_normalizes_only_abi_decorations(self) -> None:
        self.assertEqual(normalize_abi_name("printf@plt"), "printf")
        self.assertEqual(normalize_abi_name("printf.plt"), "printf")
        self.assertEqual(normalize_abi_name("printf@@GLIBC_2.2.5"), "printf")
        self.assertIsNotNone(DEFAULT_FORMAT_REGISTRY.resolve("printf@GLIBC_2.2.5"))
        for name in ("my_printf", "printf_wrapper", "register_printf_function", " printf"):
            with self.subTest(name=name):
                self.assertIsNone(DEFAULT_FORMAT_REGISTRY.resolve(name))

    def test_registry_is_immutable_and_configurable(self) -> None:
        registry = FormatRegistry((FormatFunction("custom_log", 2),))
        self.assertEqual(registry.resolve("custom_log").format_index, 2)  # type: ignore[union-attr]
        with self.assertRaises(FrozenInstanceError):
            registry.entries = ()  # type: ignore[misc]
        extended = registry.extend((FormatFunction("other_log", 0),))
        self.assertIsNone(registry.resolve("other_log"))
        self.assertIsNotNone(extended.resolve("other_log"))


class ResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.view = FakeView()

    def test_resolves_direct_import_and_plt(self) -> None:
        self.view.symbols_by_address[0x1000] = [FakeSymbol("printf")]
        direct = resolve_callee(self.view, const_pointer(0x1000))
        self.assertEqual((direct.name, direct.resolution), ("printf", "direct"))  # type: ignore[union-attr]

        self.view.symbols_by_address[0x2000] = [FakeSymbol("snprintf", "ImportAddressSymbol")]
        imported = resolve_callee(self.view, FakeNode("HLIL_IMPORT", constant=0x2000))
        self.assertEqual((imported.name, imported.format_index, imported.resolution), ("snprintf", 2, "import"))  # type: ignore[union-attr]

        self.view.sections[".plt"] = FakeSection(".plt", 0x3000, 0x3100)
        self.view.references[0x3000] = (0x2000,)
        plt = resolve_callee(self.view, const_pointer(0x3000))
        self.assertEqual((plt.name, plt.resolution), ("snprintf", "plt-import-slot"))  # type: ignore[union-attr]

    def test_finite_indirect_requires_complete_consensus(self) -> None:
        self.view.symbols_by_address[0x1000] = [FakeSymbol("printf")]
        self.view.symbols_by_address[0x1100] = [FakeSymbol("__printf")]
        destination = FakeNode(
            "HLIL_VAR",
            possible_values=FakeValue("InSetOfValues", values=(0x1000, 0x1100)),
        )
        resolved = resolve_callee(self.view, destination)
        self.assertEqual((resolved.name, resolved.resolution), ("printf", "finite-indirect"))  # type: ignore[union-attr]

        self.view.symbols_by_address[0x1100] = [FakeSymbol("snprintf")]
        self.assertIsNone(resolve_callee(self.view, destination))
        capped = resolve_callee(self.view, destination, limits=AnalysisLimits(max_indirect_targets=1))
        self.assertIsNone(capped)

    def test_rejects_data_symbols_and_suffix_matches(self) -> None:
        self.view.symbols_by_address[0x1000] = [FakeSymbol("printf", "DataSymbol")]
        self.assertIsNone(resolve_callee(self.view, const_pointer(0x1000)))
        self.view.symbols_by_address[0x1000] = [FakeSymbol("my_printf")]
        self.assertIsNone(resolve_callee(self.view, const_pointer(0x1000)))

    def test_plt_recovery_is_bounded_to_one_stub_and_one_import_slot(self) -> None:
        class RangeAwareView(FakeView):
            def __init__(self) -> None:
                super().__init__()
                self.queries: list[tuple[int, int | None]] = []

            def get_data_refs_from(self, address: int, length: int | None = None) -> tuple[int, ...]:
                self.queries.append((address, length))
                return (0x4000,) if length is not None and length <= 0x10 else (0x4000, 0x4010)

        view = RangeAwareView()
        view.sections[".plt"] = FakeSection(".plt", 0x3000, 0x3100)
        view.symbols_by_address[0x4000] = [FakeSymbol("printf", "ImportAddressSymbol")]
        view.symbols_by_address[0x4010] = [FakeSymbol("printf", "ImportAddressSymbol")]
        stub = FakeFunction(0x3000, "sub_3000")
        stub.address_ranges = [type("Range", (), {"start": 0x3000, "end": 0x3010})()]
        view.add_function(stub)
        resolved = resolve_callee(view, const_pointer(0x3000))
        self.assertIsNotNone(resolved)
        self.assertEqual(view.queries, [(0x3000, 0x10)])

        del stub.address_ranges
        self.assertIsNone(resolve_callee(view, const_pointer(0x3000)))
        self.assertEqual(view.queries[-1], (0x3000, 32))


class OriginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.view = FakeView()
        self.view.segments = [
            FakeSegment(0x3000, 0x3100),
            FakeSegment(0x4000, 0x4100, writable=True),
            FakeSegment(0x5000, 0x5100, readable=False),
        ]
        self.view.sections = {
            ".rodata": FakeSection(".rodata", 0x3000, 0x3100),
            ".data": FakeSection(".data", 0x4000, 0x4100, writable=True),
        }
        self.view.memory = {
            0x3000: b"value=%s\0" + b"x" * 64,
            0x3040: b"not terminated",
            0x3080: b"%\0\0\0s\0\0\0\0\0\0\0",
            0x4000: b"%s\0",
        }

    def test_proves_read_only_and_writable_segments(self) -> None:
        read_only = classify_format_origin(self.view, const_pointer(0x3000))
        writable = classify_format_origin(self.view, const_pointer(0x4000))
        self.assertEqual(read_only.origin, FormatOrigin.READ_ONLY)
        self.assertEqual(writable.origin, FormatOrigin.WRITABLE)
        self.assertEqual(read_only.sections, (".rodata",))

    def test_stack_and_unknown_origins(self) -> None:
        stack = FakeVariable(1, "StackVariableSourceType")
        stack_value = variable_reference(stack)
        self.assertEqual(classify_format_origin(self.view, stack_value).origin, FormatOrigin.UNKNOWN)
        stack_address = FakeNode("HLIL_ADDRESS_OF", src=stack_value)
        self.assertEqual(classify_format_origin(self.view, stack_address).origin, FormatOrigin.WRITABLE)
        stack_offset = FakeNode(
            "HLIL_VAR",
            possible_values=FakeValue("StackFrameOffset"),
        )
        self.assertEqual(classify_format_origin(self.view, stack_offset).origin, FormatOrigin.WRITABLE)
        unknown = FakeNode("HLIL_VAR", possible_values=FakeValue("EntryValue"))
        self.assertEqual(classify_format_origin(self.view, unknown).origin, FormatOrigin.UNKNOWN)
        self.assertEqual(classify_format_origin(self.view, const_pointer(0x5000)).origin, FormatOrigin.UNKNOWN)
        self.assertEqual(classify_format_origin(self.view, const_pointer(0x9000)).origin, FormatOrigin.UNKNOWN)

    def test_finite_set_lattice_and_caps(self) -> None:
        mixed = FakeNode(
            "HLIL_VAR",
            possible_values=FakeValue("InSetOfValues", values=(0x3000, 0x4000)),
        )
        self.assertEqual(classify_format_origin(self.view, mixed).origin, FormatOrigin.WRITABLE)
        incomplete = FakeNode(
            "HLIL_VAR",
            possible_values=FakeValue("InSetOfValues", values=(0x3000, 0x9000)),
        )
        self.assertEqual(classify_format_origin(self.view, incomplete).origin, FormatOrigin.UNKNOWN)
        capped = classify_format_origin(
            self.view,
            mixed,
            limits=AnalysisLimits(max_indirect_targets=1),
        )
        self.assertEqual(capped.origin, FormatOrigin.UNKNOWN)

    def test_requires_bounded_terminator_and_aligned_wide_data(self) -> None:
        unterminated = classify_format_origin(
            self.view,
            const_pointer(0x3040),
            limits=AnalysisLimits(max_format_bytes=8),
        )
        self.assertEqual(unterminated.origin, FormatOrigin.UNKNOWN)
        self.assertEqual(classify_format_origin(self.view, const_pointer(0x3080), 4).origin, FormatOrigin.READ_ONLY)
        self.assertEqual(classify_format_origin(self.view, const_pointer(0x3081), 4).origin, FormatOrigin.UNKNOWN)


class SignatureBootstrapTests(unittest.TestCase):
    def test_seeds_only_under_typed_exact_imports_and_plt_with_auto_types(self) -> None:
        view = FakeView()
        view.sections[".plt"] = FakeSection(".plt", 0x1000, 0x1100)

        plt = FakeFunction(0x1000, "printf@plt")
        imported = FakeFunction(0x2000, "snprintf")
        direct = FakeFunction(0x3000, "printf")
        user_typed = FakeFunction(0x4000, "fprintf")
        user_typed.has_user_type = True
        adequate = FakeFunction(0x5000, "vprintf")
        adequate.type = type("FunctionType", (), {"parameters": [object(), object()]})()
        caller = FakeFunction(0x6000, "caller")
        for function in (plt, imported, direct, user_typed, adequate, caller):
            view.add_function(function)

        view.symbols_by_address = {
            0x1000: [FakeSymbol("printf@plt")],
            0x2000: [FakeSymbol("snprintf", "ImportedFunctionSymbol")],
            0x3000: [FakeSymbol("printf", "FunctionSymbol")],
            0x4000: [FakeSymbol("fprintf", "ExternalSymbol")],
            0x5000: [FakeSymbol("vprintf", "ExternalSymbol")],
        }
        view.code_references = {0x1000: (caller,), 0x2000: (caller,)}

        result = bootstrap_format_function_types(view)
        self.assertEqual(result.updated_functions, (0x1000, 0x2000))
        self.assertEqual(result.unchanged_functions, (0x5000,))
        self.assertEqual(result.user_typed_functions, (0x4000,))
        self.assertEqual(result.reanalyzed_callers, (0x6000,))
        self.assertTrue(result.settled)
        self.assertEqual(view.analysis_updates, 1)
        self.assertEqual((plt.caller_update_marks, imported.caller_update_marks), (1, 1))
        self.assertEqual(caller.reanalysis_requests, 1)
        self.assertEqual(direct.auto_type_strings, [])
        self.assertIn("const char *format, ...", plt.auto_type_strings[0])
        self.assertIn("void *arg0, void *arg1, const char *format, ...", imported.auto_type_strings[0])

    def test_bootstrap_is_idempotent_and_can_defer_settling(self) -> None:
        view = FakeView()
        imported = FakeFunction(0x2000, "vprintf")
        view.add_function(imported)
        view.symbols_by_address[0x2000] = [FakeSymbol("vprintf", "ImportedFunctionSymbol")]

        first = bootstrap_format_function_types(view, settle=False)
        self.assertEqual(first.updated_functions, (0x2000,))
        self.assertFalse(first.settled)
        self.assertIn("const char *format, void *arguments", imported.auto_type_strings[0])
        second = bootstrap_format_function_types(view)
        self.assertEqual(second.updated_functions, ())
        self.assertEqual(second.unchanged_functions, (0x2000,))
        self.assertEqual(view.analysis_updates, 0)

    def test_bootstrap_preserves_syslog_void_return_abi(self) -> None:
        view = FakeView()
        fortified = FakeFunction(0x2000, "__vsyslog_chk")
        view.add_function(fortified)
        view.symbols_by_address[0x2000] = [FakeSymbol("__vsyslog_chk", "ImportedFunctionSymbol")]

        result = bootstrap_format_function_types(view, settle=False)

        self.assertEqual(result.updated_functions, (0x2000,))
        self.assertTrue(fortified.auto_type_strings[0].startswith("void __teemo_printf_like("))
        self.assertIn("const char *format, void *arguments", fortified.auto_type_strings[0])


class AnalysisTests(unittest.TestCase):
    def test_analyzes_calls_and_converts_actionable_diagnostics(self) -> None:
        view = FakeView()
        view.segments = [FakeSegment(0x3000, 0x3100), FakeSegment(0x4000, 0x4100, writable=True)]
        view.memory = {0x3000: b"%s\0", 0x4000: b"%s\0"}
        view.symbols_by_address[0x1000] = [FakeSymbol("sprintf")]
        safe = call(const_pointer(0x1000), (const_pointer(0x4000), const_pointer(0x3000)), 0x2010)
        unsafe = call(const_pointer(0x1000), (const_pointer(0x4000), const_pointer(0x4000)), 0x2020)
        caller = FakeFunction(0x2000, "caller", (safe, unsafe))
        view.add_function(caller)

        report = analyze_format_strings(view)
        self.assertEqual([item.origin.origin for item in report.calls], [FormatOrigin.READ_ONLY, FormatOrigin.WRITABLE])
        self.assertEqual(len(report.findings), 1)
        diagnostics = diagnostics_for_report(report)
        self.assertEqual(diagnostics[0].code, "security-format-string-writable")
        self.assertEqual(diagnostics[0].context["format_argument_index"], 1)
        self.assertEqual(diagnostics[0].context["call_address"], 0x2020)

    def test_infers_nested_parameter_forwarding_wrappers_to_fixed_point(self) -> None:
        view = FakeView()
        view.segments = [FakeSegment(0x4000, 0x4100, writable=True)]
        view.memory[0x4000] = b"%s\0"
        view.symbols_by_address[0x1000] = [FakeSymbol("printf")]

        inner_parameter = FakeVariable(1)
        inner_call = call(const_pointer(0x1000), (variable_reference(inner_parameter),), 0x2010)
        inner = FakeFunction(0x2000, "log_message", (inner_call,), (inner_parameter,))

        outer_parameter = FakeVariable(2)
        outer_call = call(const_pointer(0x2000), (variable_reference(outer_parameter),), 0x3010)
        outer = FakeFunction(0x3000, "relay_message", (outer_call,), (outer_parameter,))

        main_call = call(const_pointer(0x3000), (const_pointer(0x4000),), 0x5010)
        main = FakeFunction(0x5000, "main", (main_call,))
        for function in (inner, outer, main):
            view.add_function(function)

        report = analyze_format_strings(view)
        self.assertEqual(
            [(wrapper.function_name, wrapper.format_parameter_index, wrapper.depth) for wrapper in report.wrappers],
            [("log_message", 0, 1), ("relay_message", 0, 2)],
        )
        propagated = next(item for item in report.calls if item.call_address == 0x5010)
        self.assertEqual(propagated.callee.name, "relay_message")
        self.assertEqual(propagated.callee.ultimate_callees, ("printf",))
        self.assertEqual(propagated.origin.origin, FormatOrigin.WRITABLE)

    def test_wrapper_conflicts_and_round_caps_fail_closed(self) -> None:
        view = FakeView()
        view.symbols_by_address[0x1000] = [FakeSymbol("printf")]
        first, second = FakeVariable(1), FakeVariable(2)
        conflicting = FakeFunction(
            0x2000,
            "ambiguous_log",
            (
                call(const_pointer(0x1000), (variable_reference(first),), 0x2010),
                call(const_pointer(0x1000), (variable_reference(second),), 0x2020),
            ),
            (first, second),
        )
        view.add_function(conflicting)
        self.assertEqual(analyze_format_strings(view).wrappers, ())

        direct_only = FakeView()
        direct_only.symbols_by_address[0x1000] = [FakeSymbol("printf")]
        parameter = FakeVariable(3)
        candidate = FakeFunction(
            0x3000,
            "one_round_log",
            (call(const_pointer(0x1000), (variable_reference(parameter),), 0x3010),),
            (parameter,),
        )
        direct_only.add_function(candidate)
        capped = analyze_format_strings(direct_only, limits=AnalysisLimits(max_wrapper_rounds=1))
        self.assertEqual(capped.wrappers, ())
        self.assertIn("format-wrapper-analysis-truncated", {issue.code for issue in capped.issues})

    def test_wrapper_flow_accepts_transparent_phi_and_ssa_copy_evidence(self) -> None:
        view = FakeView()
        view.symbols_by_address[0x1000] = [FakeSymbol("printf")]

        cast_parameter = FakeVariable(1)
        cast_value = FakeNode("HLIL_CAST", instruction_operands=(variable_reference(cast_parameter),))
        cast_wrapper = FakeFunction(
            0x2000,
            "cast_log",
            (call(const_pointer(0x1000), (cast_value,), 0x2010),),
            (cast_parameter,),
        )

        phi_parameter = FakeVariable(2)
        phi_value = FakeNode("MLIL_VAR_PHI", src=(phi_parameter, phi_parameter))
        phi_wrapper = FakeFunction(
            0x3000,
            "phi_log",
            (call(const_pointer(0x1000), (phi_value,), 0x3010),),
            (phi_parameter,),
        )

        ssa_parameter = FakeVariable(3)
        ssa_local = FakeVariable(30)
        ssa_local.def_site = FakeNode("HLIL_VAR_INIT_SSA", src=variable_reference(ssa_parameter))
        ssa_value = FakeNode("HLIL_VAR_SSA", var=ssa_local)
        ssa_wrapper = FakeFunction(
            0x4000,
            "ssa_log",
            (call(const_pointer(0x1000), (ssa_value,), 0x4010),),
            (ssa_parameter,),
        )
        for function in (cast_wrapper, phi_wrapper, ssa_wrapper):
            view.add_function(function)

        report = analyze_format_strings(view)
        self.assertEqual(
            [(wrapper.function_name, wrapper.format_parameter_index) for wrapper in report.wrappers],
            [("cast_log", 0), ("phi_log", 0), ("ssa_log", 0)],
        )

    def test_wrapper_and_final_call_failures_are_localized(self) -> None:
        class ExplodingParams:
            def __iter__(self) -> object:
                raise RuntimeError("bad params")

        view = FakeView()
        view.symbols_by_address[0x1000] = [FakeSymbol("printf")]
        parameter = FakeVariable(1)
        malformed = FakeNode(
            "HLIL_CALL",
            dest=const_pointer(0x1000),
            params=ExplodingParams(),
            address=0x2010,
        )
        valid = call(const_pointer(0x1000), (variable_reference(parameter),), 0x2020)
        wrapper = FakeFunction(0x2000, "mostly_valid_log", (malformed, valid), (parameter,))
        view.add_function(wrapper)
        report = analyze_format_strings(view)
        self.assertEqual([call_item.call_address for call_item in report.calls], [0x2020])
        self.assertEqual(
            {issue.code for issue in report.issues},
            {"format-call-analysis-failed", "format-wrapper-analysis-failed"},
        )
        self.assertEqual([item.function_name for item in report.wrappers], ["mostly_valid_log"])

    def test_missing_argument_is_unknown_without_aborting_other_calls(self) -> None:
        view = FakeView()
        view.symbols_by_address[0x1000] = [FakeSymbol("snprintf")]
        malformed = call(const_pointer(0x1000), (), 0x2010)
        malformed.expr_index = 0
        caller = FakeFunction(0x2000, "caller", (malformed,))
        view.add_function(caller)
        report = analyze_format_strings(view)
        self.assertEqual(report.calls[0].origin.origin, FormatOrigin.UNKNOWN)
        self.assertEqual(report.calls[0].expression_index, 0)
        self.assertIn("does not expose", report.calls[0].origin.reason)

    def test_does_not_report_calls_inside_printf_family_entry_stubs(self) -> None:
        view = FakeView()
        view.sections[".plt"] = FakeSection(".plt", 0x1000, 0x1100)
        view.segments = [FakeSegment(0x4000, 0x4100, writable=True)]
        view.memory[0x4000] = b"%s\0"
        view.symbols_by_address = {
            0x1000: [FakeSymbol("printf@plt")],
            0x8000: [FakeSymbol("printf", "ImportAddressSymbol")],
        }
        stub_jump = call(FakeNode("HLIL_IMPORT", constant=0x8000), (), 0x1000)
        stub = FakeFunction(0x1000, "printf@plt", (stub_jump,))
        caller_call = call(const_pointer(0x1000), (const_pointer(0x4000),), 0x2010)
        caller = FakeFunction(0x2000, "caller", (caller_call,))
        view.add_function(stub)
        view.add_function(caller)

        report = analyze_format_strings(view)
        self.assertEqual([item.call_address for item in report.calls], [0x2010])
        self.assertEqual(report.calls[0].origin.origin, FormatOrigin.WRITABLE)


class AutoTagTests(unittest.TestCase):
    def _report(self) -> FormatAnalysisReport:
        callee = ResolvedCallee("printf", 0, 1, "direct", (0x1000,), ("printf",), ("printf",))
        finding = FormatCall(
            0x2000,
            "caller",
            0x2010,
            7,
            callee,
            OriginAssessment(FormatOrigin.WRITABLE, (0x4000,), reason="writable segment"),
        )
        wrapper = InferredWrapper(0x3000, "log_message", 0, 1, 1, ("printf",), (0x3010,))
        return FormatAnalysisReport((finding,), (wrapper,))

    def test_reconciles_only_owned_auto_tags_idempotently(self) -> None:
        view = FakeView()
        caller = FakeFunction(0x2000, "caller")
        wrapper = FakeFunction(0x3000, "log_message")
        for function in (caller, wrapper):
            view.add_function(function)
        for name in (
            TEEMO_FORMAT_WRITABLE_TAG,
            TEEMO_FORMAT_UNPROVEN_TAG,
            TEEMO_PRINTF_LIKE_TAG,
            "Unrelated",
        ):
            view.create_tag_type(name, "x")

        caller.add_tag(TEEMO_FORMAT_UNPROVEN_TAG, "stale", addr=0x2020, auto=True)
        caller.add_tag(TEEMO_FORMAT_UNPROVEN_TAG, "user-owned", addr=0x2020, auto=False)
        caller.add_tag("Unrelated", "keep", addr=0x2020, auto=True)
        wrapper.add_tag(TEEMO_PRINTF_LIKE_TAG, "old", auto=True)

        first = synchronize_auto_tags(view, self._report())
        self.assertEqual((first.added, first.removed, first.issues), (2, 2, ()))
        address_tags = [tag for _arch, _address, tag in caller.tags]
        self.assertTrue(any(tag.data == "user-owned" and not tag.auto for tag in address_tags))
        self.assertTrue(any(tag.type.name == "Unrelated" for tag in address_tags))
        self.assertTrue(any(tag.type.name == TEEMO_FORMAT_WRITABLE_TAG and tag.auto for tag in address_tags))
        self.assertEqual(wrapper._function_tags[0].data, "format parameter 0 → printf")

        second = synchronize_auto_tags(view, self._report())
        self.assertEqual((second.added, second.removed, second.unchanged, second.issues), (0, 0, 2, ()))

    def test_removes_stale_owned_auto_tags_when_report_clears(self) -> None:
        view = FakeView()
        function = FakeFunction(0x2000, "caller")
        view.add_function(function)
        view.create_tag_type(TEEMO_FORMAT_WRITABLE_TAG, "x")
        function.add_tag(TEEMO_FORMAT_WRITABLE_TAG, "stale", addr=0x2010, auto=True)
        result = synchronize_auto_tags(view, FormatAnalysisReport(()))
        self.assertEqual(result.removed, 1)
        self.assertEqual(function.tags, ())


if __name__ == "__main__":
    unittest.main()
