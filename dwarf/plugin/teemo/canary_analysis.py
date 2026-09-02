"""Conservative, non-user stack-canary annotations for Binary Ninja views.

The matching half of this module intentionally uses only duck-typed MLIL
objects.  That keeps the interesting policy testable without importing Binary
Ninja and makes API drift fail closed in the (much smaller) mutation half.

This is inspired by 0CD's stack-guard pass, but annotations are analysis-owned:
``define_type`` and ``create_auto_var`` are used instead of their persistent
user counterparts.  Existing user types and variables always win.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

TCB_TYPE_NAME = "tcbhead_t"
TCB_VARIABLE_NAME = "tcb"
CANARY_VARIABLE_NAME = "CANARY"

# These are the glibc tcbhead_t layouts used by 0CD.  ``dtv`` is deliberately
# opaque: its pointee has no bearing on the ABI layout, while spelling it as
# void keeps the type self-contained in views without glibc's private dtv_t.
X86_64_TCBHEAD_T = (
    "struct __packed { void *tcb; void *dtv; void *self; "
    "int multiple_threads; int gscope_flag; unsigned long int sysinfo; "
    "unsigned long int stack_guard; unsigned long int pointer_guard; "
    "unsigned long int vgetcpu_cache[2]; unsigned int feature_1; "
    "void *__private_tm[4]; void *__private_ss; "
    "unsigned long long int ssp_base; };"
)
X86_TCBHEAD_T = (
    "struct __packed { void *tcb; void *dtv; void *self; "
    "int multiple_threads; unsigned long int sysinfo; unsigned long int stack_guard; "
    "unsigned long int pointer_guard; int gscope_flag; int private_futex; "
    "void *__private_tm[5]; };"
)


@dataclass(frozen=True)
class CanaryTargetSpec:
    """Architecture-specific source of the glibc stack guard."""

    name: str
    guard_kind: str
    pointer_size: int
    tls_register: str | None = None
    guard_offset: int | None = None
    type_id: str | None = None
    type_source: str | None = None


X86_64_SPEC = CanaryTargetSpec(
    name="linux-x86_64",
    guard_kind="tls",
    pointer_size=8,
    tls_register="fsbase",
    guard_offset=0x28,
    type_id="pwnc.teemo.glibc.tcbhead_t.linux-x86_64.v1",
    type_source=X86_64_TCBHEAD_T,
)
X86_SPEC = CanaryTargetSpec(
    name="linux-x86",
    guard_kind="tls",
    pointer_size=4,
    tls_register="gsbase",
    guard_offset=0x14,
    type_id="pwnc.teemo.glibc.tcbhead_t.linux-x86.v1",
    type_source=X86_TCBHEAD_T,
)
ARM_SPEC = CanaryTargetSpec(name="linux-arm", guard_kind="global", pointer_size=4)
AARCH64_SPEC = CanaryTargetSpec(name="linux-aarch64", guard_kind="global", pointer_size=8)


@dataclass(frozen=True)
class CanaryMatch:
    """A qualified guard load and the variables safe to consider annotating."""

    function_start: int
    guard_kind: str
    guard_location: int
    qualification: tuple[str, ...]
    function: Any = field(repr=False, compare=False)
    tcb_variable: Any | None = field(default=None, repr=False, compare=False)
    canary_variable: Any | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class CanaryFunctionReport:
    function_start: int
    guard_kind: str
    guard_location: int
    qualification: tuple[str, ...]
    tcb_action: str
    canary_action: str

    @property
    def changed(self) -> bool:
        return self.tcb_action == "created-auto" or self.canary_action == "created-auto"


@dataclass(frozen=True)
class CanaryAnalysisReport:
    target: str | None
    examined_functions: int
    type_action: str
    functions: tuple[CanaryFunctionReport, ...] = ()
    analysis_updates: int = 0
    diagnostics: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return self.type_action == "created-auto" or any(item.changed for item in self.functions)

    @property
    def matched_functions(self) -> tuple[int, ...]:
        return tuple(item.function_start for item in self.functions)


@dataclass(frozen=True)
class _GuardAssignment:
    index: int
    variable: Any
    base_variable: Any | None


_LOAD_OPERATIONS = {
    "MLIL_LOAD",
    "MLIL_LOAD_SSA",
    "MLIL_LOAD_STRUCT",
    "MLIL_LOAD_STRUCT_SSA",
}
_SET_VAR_OPERATIONS = {
    "MLIL_SET_VAR",
    "MLIL_SET_VAR_FIELD",
    "MLIL_SET_VAR_SSA",
    "MLIL_SET_VAR_SSA_FIELD",
}
_CHECK_OPERATIONS = {"MLIL_CMP_E", "MLIL_CMP_NE", "MLIL_SUB", "MLIL_XOR"}
_CONSTANT_OPERATIONS = {"MLIL_CONST", "MLIL_CONST_PTR", "MLIL_EXTERN_PTR", "MLIL_IMPORT"}
_STACK_CHK_FAIL_NAMES = {"__stack_chk_fail", "__stack_chk_fail_local"}


def target_spec_for_view(view: Any) -> CanaryTargetSpec | None:
    """Select a supported Linux guard ABI without importing Binary Ninja."""

    platform = _object_name(getattr(view, "platform", None)).lower()
    arch = _object_name(getattr(view, "arch", None)).lower()
    if not platform.startswith("linux"):
        return None
    if platform == "linux-x86_64" or arch in {"x86_64", "amd64"}:
        return X86_64_SPEC
    if platform in {"linux-x86", "linux-i386"} or arch in {"x86", "i386", "i686"}:
        return X86_SPEC
    if "aarch64" in platform or arch in {"aarch64", "arm64"}:
        return AARCH64_SPEC
    if "arm" in platform or arch.startswith(("arm", "thumb")):
        return ARM_SPEC
    return None


def find_canary_matches(
    view: Any,
    spec: CanaryTargetSpec | None = None,
) -> tuple[CanaryMatch, ...]:
    """Return high-confidence matches without changing the view."""

    selected = spec or target_spec_for_view(view)
    if selected is None:
        return ()
    fail_functions = _stack_chk_fail_function_starts(view)
    guard_addresses = _stack_chk_guard_addresses(view) if selected.guard_kind == "global" else set()
    matches: list[CanaryMatch] = []
    for function in tuple(getattr(view, "functions", ()) or ()):
        match = _match_function(function, selected, fail_functions, guard_addresses)
        if match is not None:
            matches.append(match)
    return tuple(sorted(matches, key=lambda item: item.function_start))


def analyze_stack_canaries(view: Any) -> CanaryAnalysisReport:
    """Annotate qualified stack guards and perform at most one analysis wait."""

    spec = target_spec_for_view(view)
    functions = tuple(getattr(view, "functions", ()) or ())
    if spec is None:
        return CanaryAnalysisReport(None, len(functions), "not-applicable")

    matches = find_canary_matches(view, spec)
    diagnostics: list[str] = []
    changed = False
    type_action = "not-applicable" if spec.guard_kind == "global" else "unused"

    # Do not even introduce the helper type unless at least one matched base is
    # eligible for an auto annotation.  User-variable checks fail closed.
    type_available = spec.guard_kind == "global"
    if spec.guard_kind == "tls" and any(
        match.tcb_variable is not None and _auto_variable_eligibility(match.function, match.tcb_variable) == "eligible"
        for match in matches
    ):
        type_action, type_available, type_changed, diagnostic = _ensure_auto_tcb_type(view, spec)
        changed |= type_changed
        if diagnostic:
            diagnostics.append(diagnostic)

    reports: list[CanaryFunctionReport] = []
    for match in matches:
        if spec.guard_kind == "tls":
            base_eligibility = (
                _auto_variable_eligibility(match.function, match.tcb_variable)
                if match.tcb_variable is not None
                else "skipped-no-variable"
            )
            if base_eligibility != "eligible":
                tcb_action = base_eligibility
            elif not type_available:
                tcb_action = "skipped-type-unavailable"
            else:
                tcb_action, did_change, diagnostic = _create_auto_variable(
                    match.function,
                    match.tcb_variable,
                    f"{TCB_TYPE_NAME} *",
                    TCB_VARIABLE_NAME,
                    expected_type=TCB_TYPE_NAME,
                )
                changed |= did_change
                if diagnostic:
                    diagnostics.append(diagnostic)
        else:
            tcb_action = "not-applicable"

        canary_type = getattr(match.canary_variable, "type", None)
        if canary_type is None:
            canary_action = "skipped-no-type"
        else:
            canary_action, did_change, diagnostic = _create_auto_variable(
                match.function,
                match.canary_variable,
                canary_type,
                CANARY_VARIABLE_NAME,
            )
            changed |= did_change
            if diagnostic:
                diagnostics.append(diagnostic)
        reports.append(
            CanaryFunctionReport(
                function_start=match.function_start,
                guard_kind=match.guard_kind,
                guard_location=match.guard_location,
                qualification=match.qualification,
                tcb_action=tcb_action,
                canary_action=canary_action,
            )
        )

    updates = 0
    if changed:
        updater = getattr(view, "update_analysis_and_wait", None)
        if callable(updater):
            updater()
            updates = 1
        else:
            diagnostics.append("view has no update_analysis_and_wait; annotations were not settled")
    return CanaryAnalysisReport(
        target=spec.name,
        examined_functions=len(functions),
        type_action=type_action,
        functions=tuple(reports),
        analysis_updates=updates,
        diagnostics=tuple(diagnostics),
    )


def annotate_stack_canaries(view: Any) -> CanaryAnalysisReport:
    """Compatibility spelling for :func:`analyze_stack_canaries`."""

    return analyze_stack_canaries(view)


def _match_function(
    function: Any,
    spec: CanaryTargetSpec,
    fail_functions: set[int],
    guard_addresses: set[int],
) -> CanaryMatch | None:
    instructions = tuple(_function_instructions(function))
    assignments: list[_GuardAssignment] = []
    for index, instruction in enumerate(instructions):
        matching_loads = [
            (node, _matching_tls_base(function, node, spec))
            for node in _iter_nodes(instruction)
            if _enum_name(getattr(node, "operation", "")) in _LOAD_OPERATIONS
            and _is_guard_load(function, node, spec, guard_addresses)
        ]
        if not matching_loads:
            continue
        if _enum_name(getattr(instruction, "operation", "")) in _SET_VAR_OPERATIONS:
            destination = _assignment_destination(instruction)
            if destination is not None:
                assignments.append(_GuardAssignment(index, destination, matching_loads[0][1]))

    if not assignments:
        return None
    saved = assignments[0]
    structural_check = _has_structural_guard_check(
        function, instructions, saved, assignments[1:], spec, guard_addresses
    )
    function_start = _integer(getattr(function, "start", None))
    if function_start is None:
        return None
    qualifications: list[str] = []
    if function_start in fail_functions:
        qualifications.append("stack-chk-fail-reference")
    if structural_check:
        qualifications.append("guard-check")
    if not qualifications:
        return None
    return CanaryMatch(
        function_start=function_start,
        guard_kind=spec.guard_kind,
        guard_location=int(spec.guard_offset or min(guard_addresses, default=0)),
        qualification=tuple(qualifications),
        function=function,
        tcb_variable=saved.base_variable,
        canary_variable=saved.variable,
    )


def _has_structural_guard_check(
    function: Any,
    instructions: tuple[Any, ...],
    saved: _GuardAssignment,
    later: list[_GuardAssignment],
    spec: CanaryTargetSpec,
    guard_addresses: set[int],
) -> bool:
    saved_key = _variable_key(saved.variable)
    fresh_keys = {_variable_key(item.variable) for item in later if item.index > saved.index}
    fresh_keys.discard(saved_key)
    for instruction in instructions[saved.index + 1 :]:
        for node in _iter_nodes(instruction):
            if _enum_name(getattr(node, "operation", "")) not in _CHECK_OPERATIONS:
                continue
            read_keys = {_variable_key(var) for var in _variables_read(node)}
            if saved_key not in read_keys:
                continue
            has_direct_reload = any(
                _enum_name(getattr(child, "operation", "")) in _LOAD_OPERATIONS
                and _is_guard_load(function, child, spec, guard_addresses)
                for child in _iter_nodes(node)
            )
            if has_direct_reload or bool(read_keys & fresh_keys):
                return True
    return False


def _is_guard_load(
    function: Any,
    load: Any,
    spec: CanaryTargetSpec,
    guard_addresses: set[int],
) -> bool:
    size = _integer(getattr(load, "size", None))
    if size not in {None, 0, spec.pointer_size}:
        return False
    if spec.guard_kind == "tls":
        if _matching_tls_base(function, load, spec) is None:
            return False
        constants = set(_instruction_constants(load))
        offset = _integer(getattr(load, "offset", None))
        return spec.guard_offset in constants or offset == spec.guard_offset
    if not guard_addresses:
        return False
    constants = set(_instruction_constants(load))
    return bool(constants & guard_addresses) or any(
        _variable_name(var).split("@", 1)[0] == "__stack_chk_guard" for var in _variables_read(load)
    )


def _matching_tls_base(function: Any, node: Any, spec: CanaryTargetSpec) -> Any | None:
    if spec.tls_register is None:
        return None
    for variable in _variables_read(node):
        if spec.tls_register in _register_names(function, variable):
            return _underlying_variable(variable)
    return None


def _stack_chk_fail_function_starts(view: Any) -> set[int]:
    starts: set[int] = set()
    getter = getattr(view, "get_code_refs", None)
    if not callable(getter):
        return starts
    for symbol in _symbols(view):
        if not any(_normalized_symbol_name(name) in _STACK_CHK_FAIL_NAMES for name in _symbol_names(symbol)):
            continue
        address = _integer(getattr(symbol, "address", None))
        if address is None or address == 0:
            continue
        try:
            references = tuple(getter(address) or ())
        except Exception:  # noqa: BLE001, S112 - BN exposes no stable base exception here.
            continue
        for reference in references:
            function = getattr(reference, "function", None)
            start = _integer(getattr(function, "start", None))
            if start is not None:
                starts.add(start)
    return starts


def _stack_chk_guard_addresses(view: Any) -> set[int]:
    addresses: set[int] = set()
    for symbol in _symbols(view):
        if not any(_normalized_symbol_name(name) == "__stack_chk_guard" for name in _symbol_names(symbol)):
            continue
        address = _integer(getattr(symbol, "address", None))
        if address is not None and address != 0:
            addresses.add(address)
    return addresses


def _ensure_auto_tcb_type(view: Any, spec: CanaryTargetSpec) -> tuple[str, bool, bool, str | None]:
    assert spec.type_id is not None and spec.type_source is not None
    by_name = getattr(view, "get_type_by_name", None)
    id_for_name = getattr(view, "get_type_id", None)
    name_for_id = getattr(view, "get_type_name_by_id", None)
    is_auto = getattr(view, "is_type_auto_defined", None)
    define = getattr(view, "define_type", None)
    if not all(callable(item) for item in (by_name, id_for_name, name_for_id, is_auto, define)):
        return "skipped-unsafe-api", False, False, "type ownership APIs are unavailable"
    try:
        existing_name = name_for_id(spec.type_id)
        existing_type = by_name(TCB_TYPE_NAME)
        existing_id = id_for_name(TCB_TYPE_NAME) if existing_type is not None else None
        if existing_name is not None:
            if (
                _qualified_name(existing_name) == TCB_TYPE_NAME
                and existing_id == spec.type_id
                and bool(is_auto(TCB_TYPE_NAME))
            ):
                return "already-auto", True, False, None
            return "skipped-id-conflict", False, False, "stable tcbhead_t type ID is already claimed"
        if existing_type is not None:
            return "skipped-name-conflict", False, False, "tcbhead_t already exists and was left untouched"
        actual_name = define(spec.type_id, TCB_TYPE_NAME, spec.type_source)
        if _qualified_name(actual_name) != TCB_TYPE_NAME:
            return "skipped-definition-conflict", False, True, "Binary Ninja selected a conflicting tcbhead_t name"
        return "created-auto", True, True, None
    except Exception as error:  # noqa: BLE001 - keep optional annotation failures local.
        return "skipped-definition-error", False, False, f"could not define auto tcbhead_t: {error}"


def _create_auto_variable(
    function: Any,
    variable: Any | None,
    variable_type: Any,
    name: str,
    *,
    expected_type: str | None = None,
) -> tuple[str, bool, str | None]:
    if variable is None:
        return "skipped-no-variable", False, None
    eligibility = _auto_variable_eligibility(function, variable)
    if eligibility != "eligible":
        return eligibility, False, None
    current_name = _variable_name(variable)
    if current_name == name and (expected_type is None or expected_type in str(getattr(variable, "type", ""))):
        return "already-auto", False, None
    creator = getattr(function, "create_auto_var", None)
    if not callable(creator):
        return "skipped-unsafe-api", False, "create_auto_var is unavailable"
    try:
        creator(_underlying_variable(variable), variable_type, name)
    except Exception as error:  # noqa: BLE001 - keep optional annotation failures local.
        return "skipped-create-error", False, f"could not create auto variable {name}: {error}"
    return "created-auto", True, None


def _auto_variable_eligibility(function: Any, variable: Any) -> str:
    checker = getattr(function, "is_var_user_defined", None)
    if not callable(checker):
        return "skipped-unsafe-api"
    try:
        if bool(checker(_underlying_variable(variable))):
            return "skipped-user-variable"
    except Exception:  # noqa: BLE001 - ambiguity must not overwrite user state.
        return "skipped-unsafe-api"
    return "eligible"


def _function_instructions(function: Any) -> Iterator[Any]:
    il = getattr(function, "medium_level_il", None)
    if il is None:
        return
    try:
        items = tuple(il)
    except (TypeError, AttributeError):
        return
    for item in items:
        if hasattr(item, "operation"):
            yield item
            continue
        try:
            yield from tuple(item)
        except (TypeError, AttributeError):
            continue


def _iter_nodes(root: Any) -> Iterator[Any]:
    pending = [root]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        marker = id(node)
        if marker in seen or not hasattr(node, "operation"):
            continue
        seen.add(marker)
        yield node
        try:
            operands = tuple(getattr(node, "instruction_operands", ()) or ())
        except (TypeError, AttributeError):
            operands = ()
        pending.extend(reversed(operands))


def _instruction_constants(root: Any) -> Iterator[int]:
    for node in _iter_nodes(root):
        if _enum_name(getattr(node, "operation", "")) not in _CONSTANT_OPERATIONS:
            continue
        value = _integer(getattr(node, "constant", None))
        if value is None:
            value = _integer(getattr(node, "value", None))
        if value is None:
            continue
        if _enum_name(getattr(node, "operation", "")) == "MLIL_EXTERN_PTR":
            value += _integer(getattr(node, "offset", None)) or 0
        yield value


def _variables_read(root: Any) -> tuple[Any, ...]:
    variables: list[Any] = []
    for node in _iter_nodes(root):
        try:
            candidates = tuple(getattr(node, "vars_read", ()) or ())
        except (TypeError, AttributeError):
            candidates = ()
        variables.extend(_underlying_variable(item) for item in candidates)
        operation = _enum_name(getattr(node, "operation", ""))
        if operation in {"MLIL_VAR", "MLIL_VAR_SSA", "MLIL_ADDRESS_OF"}:
            source = getattr(node, "src", getattr(node, "var", None))
            if source is not None and not hasattr(source, "operation"):
                variables.append(_underlying_variable(source))
    unique: dict[tuple[Any, ...], Any] = {}
    for variable in variables:
        unique.setdefault(_variable_key(variable), variable)
    return tuple(unique.values())


def _assignment_destination(instruction: Any) -> Any | None:
    destination = getattr(instruction, "dest", None)
    if destination is not None and not hasattr(destination, "operation"):
        return _underlying_variable(destination)
    try:
        written = tuple(getattr(instruction, "vars_written", ()) or ())
    except (TypeError, AttributeError):
        written = ()
    return _underlying_variable(written[0]) if len(written) == 1 else None


def _register_names(function: Any, variable: Any) -> set[str]:
    variable = _underlying_variable(variable)
    names = {
        _variable_name(variable).lower(),
        str(getattr(variable, "register_name", "")).lower(),
    }
    source_type = _enum_name(getattr(variable, "source_type", ""))
    storage = _integer(getattr(variable, "storage", None))
    getter = getattr(getattr(function, "arch", None), "get_reg_name", None)
    if storage is not None and callable(getter) and (not source_type or source_type == "RegisterVariableSourceType"):
        try:
            names.add(str(getter(storage)).lower())
        except Exception:  # noqa: BLE001, S110 - register rendering differs by architecture.
            pass
    names.discard("")
    return names


def _variable_key(variable: Any) -> tuple[Any, ...]:
    variable = _underlying_variable(variable)
    identifier = getattr(variable, "identifier", None)
    if identifier is not None:
        return ("identifier", identifier)
    source_type = _enum_name(getattr(variable, "source_type", ""))
    index = getattr(variable, "index", None)
    storage = getattr(variable, "storage", None)
    if source_type or index is not None or storage is not None:
        return ("location", source_type, index, storage)
    return ("object", id(variable))


def _underlying_variable(variable: Any) -> Any:
    return getattr(variable, "var", variable)


def _variable_name(variable: Any) -> str:
    return str(getattr(_underlying_variable(variable), "name", ""))


def _symbols(view: Any) -> tuple[Any, ...]:
    getter = getattr(view, "get_symbols", None)
    if callable(getter):
        try:
            return tuple(getter() or ())
        except Exception:  # noqa: BLE001 - optional analysis must remain conservative.
            return ()
    return ()


def _symbol_names(symbol: Any) -> set[str]:
    return {
        str(value)
        for value in (
            getattr(symbol, "raw_name", ""),
            getattr(symbol, "short_name", ""),
            getattr(symbol, "full_name", ""),
            getattr(symbol, "name", ""),
        )
        if value
    }


def _normalized_symbol_name(name: str) -> str:
    return name.split("@", 1)[0].removesuffix(".plt")


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value)).rsplit(".", 1)[-1]


def _object_name(value: Any) -> str:
    return str(getattr(value, "name", value or ""))


def _qualified_name(value: Any) -> str:
    return str(value)


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None
