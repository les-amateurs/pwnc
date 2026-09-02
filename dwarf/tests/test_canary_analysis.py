from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.canary_analysis import (
    AARCH64_SPEC,
    ARM_SPEC,
    TCB_TYPE_NAME,
    X86_64_SPEC,
    X86_64_TCBHEAD_T,
    X86_SPEC,
    X86_TCBHEAD_T,
    analyze_stack_canaries,
    find_canary_matches,
    target_spec_for_view,
)


def _enum(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


class FakeVariable:
    _next_identifier = 1

    def __init__(
        self,
        name: str,
        variable_type: str,
        *,
        register_name: str = "",
        storage: int | None = None,
        register: bool = False,
    ) -> None:
        self.name = name
        self.type = variable_type
        self.register_name = register_name
        self.identifier = FakeVariable._next_identifier
        FakeVariable._next_identifier += 1
        self.storage = storage
        self.index = 0
        self.source_type = _enum("RegisterVariableSourceType" if register else "StackVariableSourceType")


class FakeNode:
    def __init__(
        self,
        operation: str,
        *operands: FakeNode,
        constant: int | None = None,
        offset: int | None = None,
        size: int | None = None,
        src: FakeVariable | FakeNode | None = None,
        dest: FakeVariable | None = None,
        vars_read: tuple[FakeVariable, ...] = (),
        vars_written: tuple[FakeVariable, ...] = (),
    ) -> None:
        self.operation = _enum(operation)
        self.instruction_operands = tuple(operands)
        self.constant = constant
        self.offset = offset
        self.size = size
        self.src = src
        self.dest = dest
        self.vars_read = vars_read
        self.vars_written = vars_written


class FakeBlock(list):
    pass


class FakeArch:
    def __init__(self, name: str, address_size: int, registers: dict[int, str] | None = None) -> None:
        self.name = name
        self.address_size = address_size
        self.registers = registers or {}

    def get_reg_name(self, storage: int) -> str:
        return self.registers[storage]


class FakeFunction:
    def __init__(self, start: int, arch: FakeArch, instructions: list[FakeNode]) -> None:
        self.start = start
        self.arch = arch
        self.medium_level_il = [FakeBlock(instructions)]
        self.user_variables: set[int] = set()
        self.auto_var_calls: list[tuple[int, object, str]] = []

    def is_var_user_defined(self, variable: FakeVariable) -> bool:
        return variable.identifier in self.user_variables

    def create_auto_var(self, variable: FakeVariable, variable_type: object, name: str) -> None:
        self.auto_var_calls.append((variable.identifier, variable_type, name))
        variable.type = variable_type
        variable.name = name


class FakeView:
    def __init__(
        self,
        platform: str,
        arch: FakeArch,
        functions: list[FakeFunction],
        *,
        fail_functions: tuple[FakeFunction, ...] = (),
        guard_address: int | None = None,
    ) -> None:
        self.platform = SimpleNamespace(name=platform)
        self.arch = arch
        self.address_size = arch.address_size
        self.functions = functions
        self.fail_address = 0x700000
        self.symbols = []
        self.references: dict[int, list[SimpleNamespace]] = {}
        if fail_functions:
            self.symbols.append(SimpleNamespace(raw_name="__stack_chk_fail@GLIBC_2.4", address=self.fail_address))
            self.references[self.fail_address] = [SimpleNamespace(function=function) for function in fail_functions]
        if guard_address is not None:
            self.symbols.append(SimpleNamespace(raw_name="__stack_chk_guard", address=guard_address))
        self.types: dict[str, object] = {}
        self.type_ids: dict[str, str] = {}
        self.type_names: dict[str, str] = {}
        self.auto_types: set[str] = set()
        self.define_type_calls: list[tuple[str, str, object]] = []
        self.analysis_updates = 0

    def get_symbols(self):
        return self.symbols

    def get_code_refs(self, address: int):
        return self.references.get(address, ())

    def get_type_by_name(self, name: str):
        return self.types.get(name)

    def get_type_id(self, name: str):
        return self.type_ids.get(name)

    def get_type_name_by_id(self, type_id: str):
        return self.type_names.get(type_id)

    def is_type_auto_defined(self, name: str) -> bool:
        return name in self.auto_types

    def define_type(self, type_id: str, default_name: str, type_object: object):
        self.define_type_calls.append((type_id, default_name, type_object))
        self.types[default_name] = type_object
        self.type_ids[default_name] = type_id
        self.type_names[type_id] = default_name
        self.auto_types.add(default_name)
        return default_name

    def update_analysis_and_wait(self) -> None:
        self.analysis_updates += 1


def _var(variable: FakeVariable) -> FakeNode:
    return FakeNode("MLIL_VAR", src=variable, vars_read=(variable,))


def _constant(value: int) -> FakeNode:
    return FakeNode("MLIL_CONST_PTR", constant=value)


def _tls_load(base: FakeVariable, offset: int, size: int) -> FakeNode:
    address = FakeNode("MLIL_ADD", _var(base), _constant(offset), vars_read=(base,))
    return FakeNode("MLIL_LOAD", address, size=size, vars_read=(base,))


def _global_load(address: int, size: int, *, address_operation: str = "MLIL_CONST_PTR") -> FakeNode:
    address_node = FakeNode(address_operation, constant=address)
    return FakeNode("MLIL_LOAD", address_node, size=size)


def _assignment(destination: FakeVariable, source: FakeNode) -> FakeNode:
    return FakeNode(
        "MLIL_SET_VAR",
        source,
        src=source,
        dest=destination,
        vars_read=source.vars_read,
        vars_written=(destination,),
    )


def _guard_check(saved: FakeVariable, reload: FakeNode) -> FakeNode:
    return FakeNode(
        "MLIL_XOR",
        _var(saved),
        reload,
        vars_read=(saved, *reload.vars_read),
    )


def _tls_function(
    start: int,
    spec=X86_64_SPEC,
    *,
    offset: int | None = None,
    structural_check: bool = False,
) -> tuple[FakeFunction, FakeVariable, FakeVariable]:
    register_number = 99
    arch = FakeArch(
        "x86_64" if spec.pointer_size == 8 else "x86",
        spec.pointer_size,
        {
            register_number: spec.tls_register,
        },
    )
    base = FakeVariable(
        spec.tls_register or "tlsbase",
        "void *",
        register_name=spec.tls_register or "",
        storage=register_number,
        register=True,
    )
    canary = FakeVariable("var_18", "uint64_t" if spec.pointer_size == 8 else "uint32_t")
    guard_offset = spec.guard_offset if offset is None else offset
    instructions = [_assignment(canary, _tls_load(base, guard_offset, spec.pointer_size))]
    if structural_check:
        instructions.append(_guard_check(canary, _tls_load(base, guard_offset, spec.pointer_size)))
    return FakeFunction(start, arch, instructions), base, canary


class CanaryAnalysisTests(unittest.TestCase):
    def test_target_specs_use_exact_glibc_guard_abis(self) -> None:
        self.assertEqual((X86_64_SPEC.tls_register, X86_64_SPEC.guard_offset), ("fsbase", 0x28))
        self.assertEqual((X86_SPEC.tls_register, X86_SPEC.guard_offset), ("gsbase", 0x14))
        self.assertIn("unsigned long int stack_guard", X86_64_TCBHEAD_T)
        self.assertIn("unsigned long int stack_guard", X86_TCBHEAD_T)
        self.assertLess(
            X86_64_TCBHEAD_T.index("unsigned long int sysinfo"),
            X86_64_TCBHEAD_T.index("unsigned long int stack_guard"),
        )
        self.assertLess(
            X86_TCBHEAD_T.index("unsigned long int sysinfo"),
            X86_TCBHEAD_T.index("unsigned long int stack_guard"),
        )

    def test_target_selection_is_linux_only_and_covers_arm(self) -> None:
        cases = (
            ("linux-x86_64", "x86_64", X86_64_SPEC),
            ("linux-x86", "x86", X86_SPEC),
            ("linux-armv7", "armv7", ARM_SPEC),
            ("linux-aarch64", "aarch64", AARCH64_SPEC),
        )
        for platform, arch_name, expected in cases:
            with self.subTest(platform=platform):
                view = SimpleNamespace(
                    platform=SimpleNamespace(name=platform),
                    arch=FakeArch(arch_name, expected.pointer_size),
                )
                self.assertEqual(target_spec_for_view(view), expected)
        darwin = SimpleNamespace(
            platform=SimpleNamespace(name="mac-x86_64"),
            arch=FakeArch("x86_64", 8),
        )
        self.assertIsNone(target_spec_for_view(darwin))

    def test_x86_64_annotations_are_auto_batched_and_idempotent(self) -> None:
        first, first_base, first_canary = _tls_function(0x1000)
        second, second_base, second_canary = _tls_function(0x2000)
        view = FakeView("linux-x86_64", first.arch, [first, second], fail_functions=(first, second))

        report = analyze_stack_canaries(view)

        self.assertEqual(report.matched_functions, (0x1000, 0x2000))
        self.assertEqual(report.type_action, "created-auto")
        self.assertEqual(view.define_type_calls, [(X86_64_SPEC.type_id, TCB_TYPE_NAME, X86_64_TCBHEAD_T)])
        self.assertEqual(view.analysis_updates, 1)
        self.assertEqual((first_base.name, first_canary.name), ("tcb", "CANARY"))
        self.assertEqual((second_base.name, second_canary.name), ("tcb", "CANARY"))
        self.assertTrue(all(item.tcb_action == "created-auto" for item in report.functions))
        self.assertTrue(all(item.canary_action == "created-auto" for item in report.functions))

        again = analyze_stack_canaries(view)

        self.assertFalse(again.changed)
        self.assertEqual(again.type_action, "already-auto")
        self.assertEqual(view.analysis_updates, 1)
        self.assertEqual(len(view.define_type_calls), 1)
        self.assertEqual(len(first.auto_var_calls), 2)
        self.assertEqual(len(second.auto_var_calls), 2)

    def test_i386_uses_gsbase_and_pointer_sized_canary(self) -> None:
        function, base, canary = _tls_function(0x1234, X86_SPEC)
        view = FakeView("linux-x86", function.arch, [function], fail_functions=(function,))

        report = analyze_stack_canaries(view)

        self.assertEqual(report.target, "linux-x86")
        self.assertEqual(report.functions[0].guard_location, 0x14)
        self.assertEqual(base.type, "tcbhead_t *")
        self.assertEqual(canary.type, "uint32_t")
        self.assertEqual(view.define_type_calls[0][0], X86_SPEC.type_id)

    def test_wrong_offset_and_unqualified_load_are_rejected(self) -> None:
        wrong, _, _ = _tls_function(0x1000, offset=0x30)
        bare, _, _ = _tls_function(0x2000)
        view = FakeView("linux-x86_64", wrong.arch, [wrong, bare], fail_functions=(wrong,))

        self.assertEqual(find_canary_matches(view), ())
        report = analyze_stack_canaries(view)
        self.assertFalse(report.changed)
        self.assertEqual(view.analysis_updates, 0)

    def test_symbol_evidence_uses_exact_nonzero_names_and_addresses(self) -> None:
        function, _, _ = _tls_function(0x1000)
        view = FakeView("linux-x86_64", function.arch, [function])
        view.symbols = [SimpleNamespace(raw_name="evil__stack_chk_fail", address=0x700000)]
        view.references = {0x700000: [SimpleNamespace(function=function)]}
        self.assertEqual(find_canary_matches(view), ())

        view.symbols = [SimpleNamespace(raw_name="__stack_chk_fail_local@plt", address=0)]
        view.references = {0: [SimpleNamespace(function=function)]}
        self.assertEqual(find_canary_matches(view), ())

        view.symbols[0].address = 0x700000
        view.references = {0x700000: [SimpleNamespace(function=function)]}
        self.assertEqual(tuple(match.function_start for match in find_canary_matches(view)), (0x1000,))

        arm = FakeArch("armv7", 4)
        saved = FakeVariable("saved_guard", "uint32_t")
        arm_function = FakeFunction(0x2000, arm, [_assignment(saved, _global_load(0, 4))])
        arm_view = FakeView("linux-armv7", arm, [arm_function], fail_functions=(arm_function,), guard_address=0)
        self.assertEqual(find_canary_matches(arm_view), ())

    def test_structural_reload_check_qualifies_without_fail_reference(self) -> None:
        function, _, _ = _tls_function(0x1000, structural_check=True)
        view = FakeView("linux-x86_64", function.arch, [function])

        report = analyze_stack_canaries(view)

        self.assertEqual(report.matched_functions, (0x1000,))
        self.assertEqual(report.functions[0].qualification, ("guard-check",))

    def test_user_variables_are_never_replaced(self) -> None:
        function, base, canary = _tls_function(0x1000)
        function.user_variables.update((base.identifier, canary.identifier))
        view = FakeView("linux-x86_64", function.arch, [function], fail_functions=(function,))

        report = analyze_stack_canaries(view)

        self.assertEqual(report.type_action, "unused")
        self.assertEqual(report.functions[0].tcb_action, "skipped-user-variable")
        self.assertEqual(report.functions[0].canary_action, "skipped-user-variable")
        self.assertEqual(function.auto_var_calls, [])
        self.assertEqual(view.define_type_calls, [])
        self.assertEqual(view.analysis_updates, 0)

    def test_existing_user_type_is_left_untouched(self) -> None:
        function, base, canary = _tls_function(0x1000)
        view = FakeView("linux-x86_64", function.arch, [function], fail_functions=(function,))
        user_type = object()
        view.types[TCB_TYPE_NAME] = user_type
        view.type_ids[TCB_TYPE_NAME] = "user-owned-id"

        report = analyze_stack_canaries(view)

        self.assertEqual(report.type_action, "skipped-name-conflict")
        self.assertEqual(report.functions[0].tcb_action, "skipped-type-unavailable")
        self.assertEqual(report.functions[0].canary_action, "created-auto")
        self.assertIs(view.types[TCB_TYPE_NAME], user_type)
        self.assertEqual(base.name, "fsbase")
        self.assertEqual(canary.name, "CANARY")
        self.assertEqual(view.define_type_calls, [])
        self.assertEqual(view.analysis_updates, 1)

    def test_missing_variable_ownership_api_fails_closed(self) -> None:
        function, base, canary = _tls_function(0x1000)
        function.is_var_user_defined = None  # type: ignore[assignment]
        view = FakeView("linux-x86_64", function.arch, [function], fail_functions=(function,))

        report = analyze_stack_canaries(view)

        self.assertEqual(report.functions[0].tcb_action, "skipped-unsafe-api")
        self.assertEqual(report.functions[0].canary_action, "skipped-unsafe-api")
        self.assertEqual((base.name, canary.name), ("fsbase", "var_18"))
        self.assertEqual(view.analysis_updates, 0)

    def test_arm_and_aarch64_mark_global_guard_without_tcb(self) -> None:
        for platform, arch_name, size in (
            ("linux-armv7", "armv7", 4),
            ("linux-aarch64", "aarch64", 8),
        ):
            with self.subTest(platform=platform):
                arch = FakeArch(arch_name, size)
                canary = FakeVariable("saved_guard", "uint32_t" if size == 4 else "uint64_t")
                guard_address = 0x500000
                function = FakeFunction(
                    0x1000,
                    arch,
                    [_assignment(canary, _global_load(guard_address, size, address_operation="MLIL_IMPORT"))],
                )
                view = FakeView(platform, arch, [function], fail_functions=(function,), guard_address=guard_address)

                report = analyze_stack_canaries(view)

                self.assertEqual(report.matched_functions, (0x1000,))
                self.assertEqual(report.type_action, "not-applicable")
                self.assertEqual(report.functions[0].tcb_action, "not-applicable")
                self.assertEqual(report.functions[0].canary_action, "created-auto")
                self.assertEqual(canary.name, "CANARY")
                self.assertEqual(view.define_type_calls, [])
                self.assertEqual(view.analysis_updates, 1)


if __name__ == "__main__":
    unittest.main()
