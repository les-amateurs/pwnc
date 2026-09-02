"""Conservative, Binary Ninja-independent printf format-string analysis.

The public entry points in this module use Binary Ninja objects through duck
typing.  Importing the module therefore remains possible in ordinary CPython
unit tests and does not initialize Binary Ninja.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from .ir import Diagnostic


class FormatOrigin(str, Enum):
    """Proof state for the storage backing a format string."""

    READ_ONLY = "read_only"
    WRITABLE = "writable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, order=True)
class FormatFunction:
    """One exact printf-family ABI entry."""

    name: str
    format_index: int
    character_width: int = 1
    canonical_name: str | None = None

    def __post_init__(self) -> None:
        if not self.name or self.name != self.name.strip():
            raise ValueError("format-function names must be non-empty and unpadded")
        if self.format_index < 0:
            raise ValueError("format argument indices must be non-negative")
        if self.character_width not in {1, 2, 4, 8}:
            raise ValueError("format character widths must be 1, 2, 4, or 8 bytes")
        if self.canonical_name is None:
            object.__setattr__(self, "canonical_name", self.name)

    @property
    def signature(self) -> tuple[str, int, int]:
        return (str(self.canonical_name), self.format_index, self.character_width)


@dataclass(frozen=True, slots=True)
class FormatRegistry:
    """Immutable configurable exact-name registry."""

    entries: tuple[FormatFunction, ...]
    _by_name: Mapping[str, FormatFunction] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        by_name: dict[str, FormatFunction] = {}
        for entry in entries:
            previous = by_name.get(entry.name)
            if previous is not None and previous != entry:
                raise ValueError(f"conflicting format-function definitions for {entry.name!r}")
            by_name[entry.name] = entry
        object.__setattr__(self, "entries", tuple(sorted(by_name.values(), key=lambda item: item.name)))
        object.__setattr__(self, "_by_name", MappingProxyType(by_name))

    def resolve(self, name: str) -> FormatFunction | None:
        return self._by_name.get(normalize_abi_name(name))

    def extend(self, entries: Iterable[FormatFunction]) -> FormatRegistry:
        return FormatRegistry(self.entries + tuple(entries))

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(entry.name for entry in self.entries)


def normalize_abi_name(name: str) -> str:
    """Remove only ELF symbol-version and PLT decorations from *name*."""

    result = str(name)
    result = result.removesuffix(".plt").removesuffix("@plt")
    version = result.find("@@")
    if version > 0:
        return result[:version]
    version = result.find("@")
    if version > 0:
        return result[:version]
    return result


def _default_entries() -> tuple[FormatFunction, ...]:
    entries: list[FormatFunction] = []

    def add(names: Sequence[str], index: int, width: int = 1, canonical: str | None = None) -> None:
        for name in names:
            entries.append(FormatFunction(name, index, width, canonical or name))

    # ISO C/POSIX/GNU narrow families.  Indices are zero-based call.params indices.
    add(("printf", "vprintf"), 0)
    add(
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
        ),
        1,
    )
    add(("snprintf", "vsnprintf"), 2)
    add(("syslog", "vsyslog"), 1)

    # glibc fortified narrow entry points.
    add(("__printf_chk", "__vprintf_chk"), 1)
    add(
        (
            "__fprintf_chk",
            "__vfprintf_chk",
            "__dprintf_chk",
            "__vdprintf_chk",
            "__asprintf_chk",
            "__vasprintf_chk",
            "__obstack_printf_chk",
            "__obstack_vprintf_chk",
        ),
        2,
    )
    add(("__sprintf_chk", "__vsprintf_chk"), 3)
    add(("__snprintf_chk", "__vsnprintf_chk"), 4)
    add(("__syslog_chk", "__vsyslog_chk"), 2)

    # ISO C/POSIX wide families and their glibc fortified entry points.
    add(("wprintf", "vwprintf"), 0, 4)
    add(("fwprintf", "vfwprintf"), 1, 4)
    add(("swprintf", "vswprintf"), 2, 4)
    add(("__wprintf_chk", "__vwprintf_chk"), 1, 4)
    add(("__fwprintf_chk", "__vfwprintf_chk"), 2, 4)
    add(("__swprintf_chk", "__vswprintf_chk"), 4, 4)

    # Exported glibc aliases seen in stripped and partially stripped ELF files.
    aliases = {
        "__printf": "printf",
        "_IO_printf": "printf",
        "__vprintf": "vprintf",
        "_IO_vprintf": "vprintf",
        "__fprintf": "fprintf",
        "_IO_fprintf": "fprintf",
        "__vfprintf": "vfprintf",
        "_IO_vfprintf": "vfprintf",
        "__sprintf": "sprintf",
        "__vsprintf": "vsprintf",
        "__snprintf": "snprintf",
        "__vsnprintf": "vsnprintf",
        "__dprintf": "dprintf",
        "__vdprintf": "vdprintf",
        "__asprintf": "asprintf",
        "__vasprintf": "vasprintf",
        "__syslog": "syslog",
        "__vsyslog": "vsyslog",
        "__wprintf": "wprintf",
        "__vwprintf": "vwprintf",
        "__fwprintf": "fwprintf",
        "__vfwprintf": "vfwprintf",
        "__swprintf": "swprintf",
        "__vswprintf": "vswprintf",
    }
    base = {entry.name: entry for entry in entries}
    for alias, target in aliases.items():
        target_entry = base[target]
        entries.append(
            FormatFunction(alias, target_entry.format_index, target_entry.character_width, target_entry.canonical_name)
        )
    return tuple(entries)


DEFAULT_FORMAT_REGISTRY = FormatRegistry(_default_entries())


@dataclass(frozen=True, slots=True)
class AnalysisLimits:
    max_indirect_targets: int = 16
    max_format_bytes: int = 4096
    max_wrapper_rounds: int = 8
    max_plt_bytes: int = 256

    def __post_init__(self) -> None:
        for name in (
            "max_indirect_targets",
            "max_format_bytes",
            "max_wrapper_rounds",
            "max_plt_bytes",
        ):
            if int(getattr(self, name)) <= 0:
                raise ValueError(f"{name} must be positive")


DEFAULT_ANALYSIS_LIMITS = AnalysisLimits()


@dataclass(frozen=True, slots=True)
class ResolvedCallee:
    name: str
    format_index: int
    character_width: int
    resolution: str
    target_addresses: tuple[int, ...] = ()
    symbol_names: tuple[str, ...] = ()
    ultimate_callees: tuple[str, ...] = ()
    wrapper_addresses: tuple[int, ...] = ()

    @property
    def signature(self) -> tuple[str, int, int]:
        return (self.name, self.format_index, self.character_width)


@dataclass(frozen=True, slots=True)
class OriginAssessment:
    origin: FormatOrigin
    addresses: tuple[int, ...] = ()
    sections: tuple[str, ...] = ()
    value_states: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True, slots=True)
class FormatCall:
    caller_address: int
    caller_name: str
    call_address: int
    expression_index: int
    callee: ResolvedCallee
    origin: OriginAssessment

    @property
    def finding_id(self) -> str:
        return f"format:{self.caller_address:x}:{self.call_address:x}:{self.expression_index}:{self.callee.name}"


@dataclass(frozen=True, slots=True)
class InferredWrapper:
    function_address: int
    function_name: str
    format_parameter_index: int
    character_width: int
    depth: int
    ultimate_callees: tuple[str, ...]
    evidence_call_addresses: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AnalysisIssue:
    code: str
    message: str
    function_address: int | None = None
    call_address: int | None = None


@dataclass(frozen=True, slots=True)
class FormatAnalysisReport:
    calls: tuple[FormatCall, ...]
    wrappers: tuple[InferredWrapper, ...] = ()
    issues: tuple[AnalysisIssue, ...] = ()

    @property
    def findings(self) -> tuple[FormatCall, ...]:
        return tuple(call for call in self.calls if call.origin.origin is not FormatOrigin.READ_ONLY)


@dataclass(frozen=True, slots=True)
class AutoTagSyncResult:
    added: int = 0
    removed: int = 0
    unchanged: int = 0
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SignatureBootstrapResult:
    """Result of the opt-in auto-signature bootstrap prepass."""

    updated_functions: tuple[int, ...] = ()
    unchanged_functions: tuple[int, ...] = ()
    user_typed_functions: tuple[int, ...] = ()
    reanalyzed_callers: tuple[int, ...] = ()
    settled: bool = False
    issues: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.updated_functions)


@dataclass(frozen=True, slots=True)
class _FunctionRecord:
    value: Any = field(compare=False, repr=False)
    address: int
    name: str
    parameters: tuple[Any, ...] = field(compare=False, repr=False)
    calls: tuple[Any, ...] = field(compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class _ValueAlternatives:
    addresses: tuple[int, ...] = ()
    stack: bool = False
    complete: bool = False
    state: str = ""
    truncated: bool = False


_CALL_OPERATIONS = {
    "HLIL_CALL",
    "HLIL_CALL_SSA",
    "HLIL_TAILCALL",
    "HLIL_TAILCALL_SSA",
    "MLIL_CALL",
    "MLIL_CALL_SSA",
    "MLIL_CALL_UNTYPED",
    "MLIL_CALL_UNTYPED_SSA",
    "MLIL_TAILCALL",
    "MLIL_TAILCALL_SSA",
    "MLIL_TAILCALL_UNTYPED",
    "MLIL_TAILCALL_UNTYPED_SSA",
}
_CONSTANT_OPERATIONS = {
    "HLIL_CONST",
    "HLIL_CONST_PTR",
    "HLIL_EXTERN_PTR",
    "MLIL_CONST",
    "MLIL_CONST_PTR",
    "MLIL_EXTERN_PTR",
}
_IMPORT_OPERATIONS = {"HLIL_IMPORT", "MLIL_IMPORT"}
_VARIABLE_OPERATIONS = {"HLIL_VAR", "HLIL_VAR_SSA", "MLIL_VAR", "MLIL_VAR_SSA"}
_TRANSPARENT_OPERATIONS = {
    "HLIL_CAST",
    "HLIL_LOW_PART",
    "HLIL_SX",
    "HLIL_ZX",
    "MLIL_LOW_PART",
    "MLIL_SX",
    "MLIL_ZX",
}
_PHI_OPERATIONS = {"HLIL_VAR_PHI", "MLIL_VAR_PHI"}
_DIRECT_SYMBOL_TYPES = {
    "ExternalSymbol",
    "FunctionSymbol",
    "ImportedFunctionSymbol",
    "LibraryFunctionSymbol",
    "SymbolicFunctionSymbol",
}
_IMPORT_SYMBOL_TYPES = {"ImportAddressSymbol", "ImportedFunctionSymbol"}


def analyze_format_strings(
    view: Any,
    functions: Iterable[Any] | None = None,
    *,
    registry: FormatRegistry = DEFAULT_FORMAT_REGISTRY,
    limits: AnalysisLimits = DEFAULT_ANALYSIS_LIMITS,
) -> FormatAnalysisReport:
    """Analyze calls in *view* without retaining or mutating Binary Ninja objects."""

    issues: list[AnalysisIssue] = []
    records: list[_FunctionRecord] = []
    candidates = functions if functions is not None else _safe_attr(view, "functions", ())
    for function in tuple(candidates or ()):
        try:
            records.append(_function_record(function))
        except Exception as error:  # noqa: BLE001 - BN getter exceptions are not stable API types.
            issues.append(
                AnalysisIssue(
                    "format-function-analysis-failed",
                    f"failed to enumerate format calls: {error}",
                    _integer(_safe_attr(function, "start", None)),
                )
            )

    records.sort(key=lambda record: (record.address, record.name))
    wrappers = _infer_wrappers(view, records, registry, limits, issues)
    wrappers_by_address = {wrapper.function_address: wrapper for wrapper in wrappers}
    calls: list[FormatCall] = []
    address_cache: dict[tuple[int, int], OriginAssessment] = {}

    for record in records:
        if registry.resolve(record.name) is not None:
            continue
        for call in record.calls:
            call_address = _call_address(call, record.address)
            try:
                resolved = resolve_callee(view, _safe_attr(call, "dest", None), registry, wrappers_by_address, limits)
                if resolved is None:
                    continue
                params = tuple(_safe_attr(call, "params", ()) or ())
                if resolved.format_index >= len(params):
                    assessment = OriginAssessment(
                        FormatOrigin.UNKNOWN,
                        reason="recognized call does not expose its format argument",
                    )
                else:
                    assessment = classify_format_origin(
                        view,
                        params[resolved.format_index],
                        resolved.character_width,
                        limits=limits,
                        cache=address_cache,
                    )
                calls.append(
                    FormatCall(
                        record.address,
                        record.name,
                        call_address,
                        _expression_index(call),
                        resolved,
                        assessment,
                    )
                )
            except Exception as error:  # noqa: BLE001 - localize one malformed BN call.
                issues.append(
                    AnalysisIssue(
                        "format-call-analysis-failed",
                        f"failed to analyze one possible format call: {error}",
                        record.address,
                        call_address,
                    )
                )

    calls.sort(
        key=lambda item: (
            item.caller_address,
            item.call_address,
            item.expression_index,
            item.callee.name,
        )
    )
    issues.sort(key=lambda item: (item.function_address or -1, item.call_address or -1, item.code, item.message))
    return FormatAnalysisReport(tuple(calls), wrappers, tuple(issues))


def resolve_callee(
    view: Any,
    destination: Any,
    registry: FormatRegistry = DEFAULT_FORMAT_REGISTRY,
    wrappers: Mapping[int, InferredWrapper] | None = None,
    limits: AnalysisLimits = DEFAULT_ANALYSIS_LIMITS,
) -> ResolvedCallee | None:
    """Resolve one call destination using only exact and finite evidence."""

    wrappers = wrappers or {}
    if destination is None:
        return None
    operation = _operation(destination)
    names = _object_names(destination)
    named = _resolve_named(names, registry, "symbol-expression")
    if named is not None:
        return named

    if operation in _IMPORT_OPERATIONS:
        address = _constant_expression(destination)
        return _resolve_import(view, address, registry) if address is not None else None

    if operation in _CONSTANT_OPERATIONS:
        address = _constant_expression(destination)
        if address is None:
            return None
        return _resolve_address(view, address, registry, wrappers, limits)

    alternatives = _value_alternatives(_possible_value(destination), limits.max_indirect_targets)
    if not alternatives.complete or alternatives.truncated or not alternatives.addresses:
        return None
    resolved = [_resolve_address(view, address, registry, wrappers, limits) for address in alternatives.addresses]
    if any(item is None for item in resolved):
        return None
    concrete = [item for item in resolved if item is not None]
    signatures = {item.signature for item in concrete}
    ultimate = {item.ultimate_callees for item in concrete}
    if len(signatures) != 1 or len(ultimate) != 1:
        return None
    first = concrete[0]
    return ResolvedCallee(
        first.name,
        first.format_index,
        first.character_width,
        "finite-indirect",
        tuple(sorted(set(alternatives.addresses))),
        tuple(sorted({name for item in concrete for name in item.symbol_names})),
        first.ultimate_callees,
        tuple(sorted({address for item in concrete for address in item.wrapper_addresses})),
    )


def classify_format_origin(
    view: Any,
    expression: Any,
    character_width: int = 1,
    *,
    limits: AnalysisLimits = DEFAULT_ANALYSIS_LIMITS,
    cache: dict[tuple[int, int], OriginAssessment] | None = None,
) -> OriginAssessment:
    """Classify a format expression, returning read-only only on complete proof."""

    cache = cache if cache is not None else {}
    operation = _operation(expression)
    if _is_stack_expression(expression, operation):
        return OriginAssessment(
            FormatOrigin.WRITABLE,
            value_states=("StackFrameOffset",),
            reason="format storage is in the current stack frame",
        )

    if operation in _CONSTANT_OPERATIONS:
        address = _constant_expression(expression)
        alternatives = _ValueAlternatives(
            (address,) if address is not None else (),
            complete=address is not None,
            state=operation,
        )
    else:
        alternatives = _value_alternatives(_possible_value(expression), limits.max_indirect_targets)

    if alternatives.stack:
        return OriginAssessment(
            FormatOrigin.WRITABLE,
            value_states=(alternatives.state,),
            reason="format storage is in the current stack frame",
        )
    if alternatives.truncated:
        return OriginAssessment(
            FormatOrigin.UNKNOWN,
            value_states=(alternatives.state,),
            reason="format pointer alternatives exceed the analysis cap",
        )
    if not alternatives.complete or not alternatives.addresses:
        return OriginAssessment(
            FormatOrigin.UNKNOWN,
            value_states=(alternatives.state,) if alternatives.state else (),
            reason="format storage is not proven to be a finite set of addresses",
        )

    assessments = [
        _classify_address(view, address, character_width, limits, cache) for address in alternatives.addresses
    ]
    addresses = tuple(sorted(set(alternatives.addresses)))
    sections = tuple(sorted({section for item in assessments for section in item.sections}))
    states = tuple(sorted({alternatives.state, *(state for item in assessments for state in item.value_states)} - {""}))
    if any(item.origin is FormatOrigin.WRITABLE for item in assessments):
        return OriginAssessment(
            FormatOrigin.WRITABLE,
            addresses,
            sections,
            states,
            "at least one possible format address is writable",
        )
    if all(item.origin is FormatOrigin.READ_ONLY for item in assessments):
        return OriginAssessment(
            FormatOrigin.READ_ONLY,
            addresses,
            sections,
            states,
            "all possible format addresses are terminated in read-only mapped storage",
        )
    return OriginAssessment(
        FormatOrigin.UNKNOWN,
        addresses,
        sections,
        states,
        "at least one possible format address is not proven read-only",
    )


def diagnostics_for_report(report: FormatAnalysisReport) -> tuple[Diagnostic, ...]:
    """Convert actionable findings and localized failures to Teemo IR diagnostics."""

    diagnostics: list[Diagnostic] = []
    for call in report.findings:
        writable = call.origin.origin is FormatOrigin.WRITABLE
        code = "security-format-string-writable" if writable else "security-format-string-readonly-unproven"
        qualifier = "is writable" if writable else "is not proven read-only"
        context: dict[str, Any] = {
            "finding_id": call.finding_id,
            "caller_function": f"function:{call.caller_address:x}",
            "caller_name": call.caller_name,
            "caller_address": call.caller_address,
            "call_address": call.call_address,
            "call_expr": call.expression_index,
            "callee": call.callee.name,
            "callee_names": list(call.callee.symbol_names),
            "callee_addresses": list(call.callee.target_addresses),
            "resolution": call.callee.resolution,
            "format_argument_index": call.callee.format_index,
            "format_width": call.callee.character_width,
            "classification": call.origin.origin.value,
            "format_addresses": list(call.origin.addresses),
            "format_sections": list(call.origin.sections),
            "value_states": list(call.origin.value_states),
            "reason": call.origin.reason,
            "ultimate_callees": list(call.callee.ultimate_callees),
            "wrapper_addresses": list(call.callee.wrapper_addresses),
        }
        diagnostics.append(
            Diagnostic(
                "warning",
                code,
                f"{call.callee.name} format string {qualifier}",
                context,
            )
        )
    for issue in report.issues:
        context = {}
        if issue.function_address is not None:
            context["function_address"] = issue.function_address
        if issue.call_address is not None:
            context["call_address"] = issue.call_address
        diagnostics.append(Diagnostic("info", issue.code, issue.message, context))
    return tuple(diagnostics)


def bootstrap_format_function_types(
    view: Any,
    *,
    registry: FormatRegistry = DEFAULT_FORMAT_REGISTRY,
    limits: AnalysisLimits = DEFAULT_ANALYSIS_LIMITS,
    settle: bool = True,
) -> SignatureBootstrapResult:
    """Seed minimal auto types for exact recognized import/PLT functions.

    Binary Ninja can omit call parameters when a freestanding import has no
    prototype.  This explicit prepass uses ``Function.set_auto_type`` only; it
    skips every user-typed function and every ordinary local implementation.
    When any type changes, analysis is settled exactly once by default.  The
    caller must then run :func:`analyze_format_strings` on the refreshed IL.
    """

    updated: list[int] = []
    unchanged: list[int] = []
    user_typed: list[int] = []
    callers: dict[int, Any] = {}
    issues: list[str] = []
    functions = sorted(
        (_safe_attr(view, "functions", ()) or ()),
        key=lambda item: _integer(_safe_attr(item, "start", 0)) or 0,
    )
    eligible_resolutions = {"external-function", "import-function", "plt-import-slot", "plt-symbol"}
    for function in functions:
        address = _integer(_safe_attr(function, "start", None))
        if address is None:
            continue
        try:
            resolved = _resolve_address(view, address, registry, {}, limits)
            if resolved is None or resolved.resolution not in eligible_resolutions:
                continue
            if _boolean(_safe_attr(function, "has_user_type", False)):
                user_typed.append(address)
                continue
            required = resolved.format_index + (2 if _uses_va_list(resolved.name) else 1)
            if _function_parameter_count(function) >= required:
                unchanged.append(address)
                continue
            set_auto_type = _safe_attr(function, "set_auto_type", None)
            if not callable(set_auto_type):
                issues.append(f"recognized format function at {address:#x} has no set_auto_type API")
                continue
            set_auto_type(_minimal_format_prototype(resolved))
            updated.append(address)
            mark_callers = _safe_attr(function, "mark_caller_updates_required", None)
            if callable(mark_callers):
                mark_callers()
            else:
                issues.append(
                    f"seeded format function at {address:#x}, but mark_caller_updates_required is unavailable"
                )
            references = _safe_call(view, "get_code_refs", address)
            for reference in tuple(references or ()):
                caller = _safe_attr(reference, "function", None)
                caller_address = _integer(_safe_attr(caller, "start", None))
                if caller is not None and caller_address is not None:
                    callers[caller_address] = caller
        except Exception as error:  # noqa: BLE001 - localize one malformed BN function.
            issues.append(f"failed to seed format function at {address:#x}: {error}")

    reanalyzed: list[int] = []
    for caller_address, caller in sorted(callers.items()):
        try:
            reanalyze = _safe_attr(caller, "reanalyze", None)
            if not callable(reanalyze):
                issues.append(f"caller at {caller_address:#x} has no reanalyze API")
                continue
            reanalyze()
            reanalyzed.append(caller_address)
        except Exception as error:  # noqa: BLE001 - localize one caller reanalysis failure.
            issues.append(f"failed to queue caller reanalysis at {caller_address:#x}: {error}")

    settled = False
    if updated and settle:
        update = _safe_attr(view, "update_analysis_and_wait", None)
        if not callable(update):
            issues.append("format signatures changed but update_analysis_and_wait is unavailable")
        else:
            try:
                update()
                settled = True
            except Exception as error:  # noqa: BLE001 - analysis failures remain reportable.
                issues.append(f"failed to settle analysis after format signature bootstrap: {error}")
    return SignatureBootstrapResult(
        tuple(sorted(set(updated))),
        tuple(sorted(set(unchanged))),
        tuple(sorted(set(user_typed))),
        tuple(sorted(set(reanalyzed))),
        settled,
        tuple(issues),
    )


TEEMO_FORMAT_WRITABLE_TAG = "Teemo format writable"
TEEMO_FORMAT_UNPROVEN_TAG = "Teemo format unproven"
TEEMO_PRINTF_LIKE_TAG = "Teemo printf-like"


def synchronize_auto_tags(view: Any, report: FormatAnalysisReport) -> AutoTagSyncResult:
    """Idempotently reconcile only Teemo-owned *auto* tags with *report*.

    User tags, including user tags with a Teemo tag type, are never queried for
    removal and unrelated tag types are never touched.
    """

    issues: list[str] = []
    available: set[str] = set()
    for name, icon in (
        (TEEMO_FORMAT_WRITABLE_TAG, "⚠"),
        (TEEMO_FORMAT_UNPROVEN_TAG, "?"),
        (TEEMO_PRINTF_LIKE_TAG, "%"),
    ):
        try:
            tag_type = view.get_tag_type(name)
            if tag_type is None:
                tag_type = view.create_tag_type(name, icon)
            if tag_type is not None:
                available.add(name)
        except Exception as error:  # noqa: BLE001 - localize one BN tag failure.
            issues.append(f"failed to ensure tag type {name!r}: {error}")

    desired_addresses: dict[int, dict[tuple[int, str], str]] = {}
    grouped: dict[tuple[int, int, str], set[str]] = {}
    for call in report.findings:
        tag_type = (
            TEEMO_FORMAT_WRITABLE_TAG if call.origin.origin is FormatOrigin.WRITABLE else TEEMO_FORMAT_UNPROVEN_TAG
        )
        grouped.setdefault((call.caller_address, call.call_address, tag_type), set()).add(call.callee.name)
    for (function_address, call_address, tag_type), names in grouped.items():
        if tag_type not in available:
            continue
        label = ", ".join(sorted(names))
        state = "writable" if tag_type == TEEMO_FORMAT_WRITABLE_TAG else "not proven read-only"
        desired_addresses.setdefault(function_address, {})[(call_address, tag_type)] = f"{label} format is {state}"

    desired_functions = {
        wrapper.function_address: (
            f"format parameter {wrapper.format_parameter_index} → {', '.join(wrapper.ultimate_callees)}"
        )
        for wrapper in report.wrappers
        if TEEMO_PRINTF_LIKE_TAG in available
    }
    functions = sorted(
        (_safe_attr(view, "functions", ()) or ()),
        key=lambda item: _integer(_safe_attr(item, "start", 0)) or 0,
    )
    added = removed = unchanged = 0
    for function in functions:
        function_address = _integer(_safe_attr(function, "start", None))
        if function_address is None:
            continue
        try:
            a, r, u = _sync_function_tags(
                function,
                desired_addresses.get(function_address, {}),
                desired_functions.get(function_address),
                available,
            )
            added += a
            removed += r
            unchanged += u
        except Exception as error:  # noqa: BLE001 - localize one BN tag failure.
            issues.append(f"failed to synchronize tags for {function_address:#x}: {error}")
    return AutoTagSyncResult(added, removed, unchanged, tuple(issues))


def _function_record(function: Any) -> _FunctionRecord:
    address = _integer(_safe_attr(function, "start", None))
    if address is None:
        raise ValueError("function has no integral start address")
    name = str(_safe_attr(function, "name", f"sub_{address:x}"))
    parameters = tuple(_safe_attr(function, "parameter_vars", ()) or ())
    return _FunctionRecord(function, address, name, parameters, tuple(_function_calls(function)))


def _function_calls(function: Any) -> Iterator[Any]:
    il = _safe_attr(function, "hlil", None)
    if il is None:
        il = _safe_attr(function, "mlil", None)
    if il is None:
        return
    root = _safe_attr(il, "root", None)
    roots: list[Any] = []
    if root is not None:
        roots.append(root)
    else:
        blocks = _safe_attr(il, "basic_blocks", None)
        outer = blocks if blocks is not None else il
        try:
            for block in outer:
                try:
                    roots.extend(tuple(block))
                except TypeError:
                    roots.append(block)
        except TypeError:
            roots.append(il)
    seen: set[int] = set()
    calls: list[Any] = []
    pending = list(reversed(roots))
    while pending:
        node = pending.pop()
        marker = _expression_index(node)
        identity = marker if marker >= 0 else id(node)
        if identity in seen:
            continue
        seen.add(identity)
        if _operation(node) in _CALL_OPERATIONS:
            calls.append(node)
        operands = tuple(_safe_attr(node, "instruction_operands", ()) or ())
        pending.extend(reversed(operands))
    calls.sort(key=lambda call: (_call_address(call, 0), _expression_index(call)))
    yield from calls


def _infer_wrappers(
    view: Any,
    records: Sequence[_FunctionRecord],
    registry: FormatRegistry,
    limits: AnalysisLimits,
    issues: list[AnalysisIssue],
) -> tuple[InferredWrapper, ...]:
    wrappers: dict[int, InferredWrapper] = {}
    failed_calls: set[tuple[int, int]] = set()
    for _round in range(limits.max_wrapper_rounds):
        next_wrappers: dict[int, InferredWrapper] = {}
        for record in records:
            if registry.resolve(record.name) is not None or not record.parameters:
                continue
            evidence: list[tuple[int, int, ResolvedCallee, int]] = []
            for call in record.calls:
                call_address = _call_address(call, record.address)
                try:
                    resolved = resolve_callee(
                        view,
                        _safe_attr(call, "dest", None),
                        registry,
                        wrappers,
                        limits,
                    )
                    if resolved is None:
                        continue
                    params = tuple(_safe_attr(call, "params", ()) or ())
                    if resolved.format_index >= len(params):
                        continue
                    parameter_index = _parameter_index(params[resolved.format_index], record.parameters)
                    if parameter_index is not None:
                        evidence.append((parameter_index, resolved.character_width, resolved, call_address))
                except Exception as error:  # noqa: BLE001 - localize one malformed wrapper edge.
                    marker = (record.address, call_address)
                    if marker not in failed_calls:
                        failed_calls.add(marker)
                        issues.append(
                            AnalysisIssue(
                                "format-wrapper-analysis-failed",
                                f"failed to infer one wrapper edge: {error}",
                                record.address,
                                call_address,
                            )
                        )
            keys = {(parameter, width) for parameter, width, _resolved, _address in evidence}
            if len(keys) != 1:
                continue
            parameter, width = next(iter(keys))
            relevant = [item for item in evidence if item[0] == parameter and item[1] == width]
            depths = [
                wrappers[address].depth
                for _parameter, _width, resolved, _call_address_value in relevant
                for address in resolved.wrapper_addresses
                if address in wrappers
            ]
            next_wrappers[record.address] = InferredWrapper(
                record.address,
                record.name,
                parameter,
                width,
                1 + max(depths, default=0),
                tuple(sorted({name for _p, _w, resolved, _a in relevant for name in resolved.ultimate_callees})),
                tuple(sorted({_address for _p, _w, _resolved, _address in relevant})),
            )
        if next_wrappers == wrappers:
            return tuple(sorted(wrappers.values(), key=lambda item: (item.function_address, item.function_name)))
        wrappers = next_wrappers
    issues.append(
        AnalysisIssue(
            "format-wrapper-analysis-truncated",
            f"wrapper inference did not converge within {limits.max_wrapper_rounds} rounds",
        )
    )
    return ()


def _resolve_named(names: Iterable[str], registry: FormatRegistry, method: str) -> ResolvedCallee | None:
    pairs = [(name, registry.resolve(name)) for name in names]
    pairs = [(name, spec) for name, spec in pairs if spec is not None]
    signatures = {spec.signature for _name, spec in pairs}
    if len(signatures) != 1:
        return None
    _source_name, spec = pairs[0]
    return ResolvedCallee(
        str(spec.canonical_name),
        spec.format_index,
        spec.character_width,
        method,
        symbol_names=tuple(sorted({source for source, _spec in pairs})),
        ultimate_callees=(str(spec.canonical_name),),
    )


def _resolve_import(view: Any, address: int, registry: FormatRegistry) -> ResolvedCallee | None:
    symbols = [symbol for symbol in _symbols_at(view, address) if _symbol_type(symbol) in _IMPORT_SYMBOL_TYPES]
    resolved = _resolve_named((_symbol_name(symbol) for symbol in symbols), registry, "import")
    if resolved is None:
        return None
    return ResolvedCallee(
        resolved.name,
        resolved.format_index,
        resolved.character_width,
        "import",
        (address,),
        resolved.symbol_names,
        resolved.ultimate_callees,
    )


def _resolve_address(
    view: Any,
    address: int,
    registry: FormatRegistry,
    wrappers: Mapping[int, InferredWrapper],
    limits: AnalysisLimits,
) -> ResolvedCallee | None:
    wrapper = wrappers.get(address)
    if wrapper is not None:
        return ResolvedCallee(
            wrapper.function_name,
            wrapper.format_parameter_index,
            wrapper.character_width,
            "inferred-wrapper",
            (address,),
            (wrapper.function_name,),
            wrapper.ultimate_callees,
            (address,),
        )

    symbols = [symbol for symbol in _symbols_at(view, address) if _symbol_type(symbol) in _DIRECT_SYMBOL_TYPES]
    names = [_symbol_name(symbol) for symbol in symbols]
    functions = _functions_at(view, address)
    names.extend(str(_safe_attr(function, "name", "")) for function in functions)
    direct = _resolve_named((name for name in names if name), registry, "direct")
    if direct is not None:
        symbol_types = {_symbol_type(symbol) for symbol in symbols}
        if "ImportedFunctionSymbol" in symbol_types:
            method = "import-function"
        elif "ExternalSymbol" in symbol_types:
            method = "external-function"
        elif _looks_like_plt(view, address, names):
            method = "plt-symbol"
        else:
            method = "direct"
        return ResolvedCallee(
            direct.name,
            direct.format_index,
            direct.character_width,
            method,
            (address,),
            direct.symbol_names,
            direct.ultimate_callees,
        )

    if not _looks_like_plt(view, address, names):
        return None
    scan_size = _plt_scan_size(address, functions, limits.max_plt_bytes)
    references = _data_references_from(view, address, scan_size)
    import_slots = {
        reference
        for reference in references
        if any(_symbol_type(symbol) in _IMPORT_SYMBOL_TYPES for symbol in _symbols_at(view, reference))
    }
    if len(import_slots) != 1:
        return None
    import_slot = next(iter(import_slots))
    imported = _resolve_import(view, import_slot, registry)
    if imported is None:
        return None
    return ResolvedCallee(
        imported.name,
        imported.format_index,
        imported.character_width,
        "plt-import-slot",
        (address,),
        imported.symbol_names,
        imported.ultimate_callees,
    )


_VA_LIST_FORMAT_FUNCTIONS = {
    "vprintf",
    "vfprintf",
    "vsprintf",
    "vsnprintf",
    "vdprintf",
    "vasprintf",
    "obstack_vprintf",
    "vsyslog",
    "__vprintf_chk",
    "__vfprintf_chk",
    "__vsprintf_chk",
    "__vsnprintf_chk",
    "__vdprintf_chk",
    "__vasprintf_chk",
    "__obstack_vprintf_chk",
    "__vsyslog_chk",
    "vwprintf",
    "vfwprintf",
    "vswprintf",
    "__vwprintf_chk",
    "__vfwprintf_chk",
    "__vswprintf_chk",
}

_VOID_FORMAT_FUNCTIONS = {
    "syslog",
    "vsyslog",
    "__syslog_chk",
    "__vsyslog_chk",
}


def _uses_va_list(canonical_name: str) -> bool:
    return canonical_name in _VA_LIST_FORMAT_FUNCTIONS


def _function_parameter_count(function: Any) -> int:
    function_type = _safe_attr(function, "type", None)
    parameters = _safe_attr(function_type, "parameters", ())
    try:
        return len(tuple(parameters or ()))
    except TypeError:
        return 0


def _minimal_format_prototype(resolved: ResolvedCallee) -> str:
    arguments = [f"void *arg{index}" for index in range(resolved.format_index)]
    character_type = "char" if resolved.character_width == 1 else "unsigned int"
    arguments.append(f"const {character_type} *format")
    if _uses_va_list(resolved.name):
        arguments.append("void *arguments")
    else:
        arguments.append("...")
    return_type = "void" if resolved.name in _VOID_FORMAT_FUNCTIONS else "int"
    return f"{return_type} __teemo_printf_like({', '.join(arguments)});"


def _classify_address(
    view: Any,
    address: int,
    width: int,
    limits: AnalysisLimits,
    cache: dict[tuple[int, int], OriginAssessment],
) -> OriginAssessment:
    key = (address, width)
    cached = cache.get(key)
    if cached is not None:
        return cached
    sections = _section_names(view, address)
    if address <= 0:
        result = OriginAssessment(FormatOrigin.UNKNOWN, (address,), sections, reason="null or negative address")
        cache[key] = result
        return result
    segment = _safe_call(view, "get_segment_at", address)
    if segment is None or not _boolean(_safe_attr(segment, "readable", False)):
        result = OriginAssessment(
            FormatOrigin.UNKNOWN, (address,), sections, reason="address is not in readable mapped storage"
        )
        cache[key] = result
        return result
    if _boolean(_safe_attr(segment, "writable", False)):
        result = OriginAssessment(
            FormatOrigin.WRITABLE, (address,), sections, reason="address is in a writable segment"
        )
        cache[key] = result
        return result
    start = _integer(_safe_attr(segment, "start", address))
    end = _integer(_safe_attr(segment, "end", None))
    if start is None or end is None or not (start <= address < end):
        result = OriginAssessment(FormatOrigin.UNKNOWN, (address,), sections, reason="segment bounds are unavailable")
        cache[key] = result
        return result
    if width > 1 and address % width:
        result = OriginAssessment(
            FormatOrigin.UNKNOWN, (address,), sections, reason="wide format address is misaligned"
        )
        cache[key] = result
        return result
    size = min(limits.max_format_bytes, end - address)
    if size < width:
        result = OriginAssessment(
            FormatOrigin.UNKNOWN, (address,), sections, reason="format storage ends before one code unit"
        )
        cache[key] = result
        return result
    data = _safe_call(view, "read", address, size)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        result = OriginAssessment(FormatOrigin.UNKNOWN, (address,), sections, reason="format bytes could not be read")
        cache[key] = result
        return result
    raw = bytes(data)
    terminated = any(raw[offset : offset + width] == bytes(width) for offset in range(0, len(raw) - width + 1, width))
    if not terminated:
        result = OriginAssessment(
            FormatOrigin.UNKNOWN, (address,), sections, reason="no bounded NUL terminator was proven"
        )
        cache[key] = result
        return result
    result = OriginAssessment(
        FormatOrigin.READ_ONLY, (address,), sections, reason="bounded NUL-terminated data is in a read-only segment"
    )
    cache[key] = result
    return result


def _possible_value(expression: Any) -> Any:
    for name in ("possible_values", "value"):
        value = _safe_attr(expression, name, None)
        if value is not None:
            return value
    method = _safe_attr(expression, "get_possible_values", None)
    if callable(method):
        try:
            return method()
        except Exception:  # noqa: BLE001 - BN value-flow exceptions are not stable API types.
            return None
    return None


def _value_alternatives(value: Any, cap: int) -> _ValueAlternatives:
    if value is None:
        return _ValueAlternatives(state="UndeterminedValue")
    kind = _enum_name(_safe_attr(value, "type", ""))
    if kind in {"ConstantValue", "ConstantPointerValue"}:
        address = _integer(_safe_attr(value, "value", None))
        return _ValueAlternatives((address,) if address is not None else (), complete=address is not None, state=kind)
    if kind == "StackFrameOffset":
        return _ValueAlternatives(stack=True, complete=True, state=kind)
    if kind in {"InSetOfValues", "InSet"}:
        values = tuple(_integers(_safe_attr(value, "values", ())))
        if len(values) > cap:
            return _ValueAlternatives(state=kind, truncated=True)
        return _ValueAlternatives(tuple(sorted(set(values))), complete=bool(values), state=kind)
    if kind in {"LookupTableValue", "LookupTable"}:
        mapping = _safe_attr(value, "mapping", {}) or {}
        raw_values = mapping.values() if isinstance(mapping, Mapping) else ()
        values = tuple(_integers(raw_values))
        if len(values) > cap:
            return _ValueAlternatives(state=kind, truncated=True)
        return _ValueAlternatives(tuple(sorted(set(values))), complete=bool(values), state=kind)
    return _ValueAlternatives(state=kind or "UndeterminedValue")


def _is_stack_expression(expression: Any, operation: str) -> bool:
    if operation in {"HLIL_ADDRESS_OF", "MLIL_ADDRESS_OF"}:
        variable = _safe_attr(expression, "src", None) or _safe_attr(expression, "var", None)
        return _is_stack_variable(variable)
    return False


def _is_stack_variable(variable: Any) -> bool:
    variable = _underlying_variable(variable)
    return _enum_name(_safe_attr(variable, "source_type", "")) == "StackVariableSourceType"


def _parameter_index(expression: Any, parameters: Sequence[Any], depth: int = 0) -> int | None:
    if expression is None or depth > 8:
        return None
    operation = _operation(expression)
    if operation in _VARIABLE_OPERATIONS or not operation:
        original_variable = _safe_attr(expression, "var", expression)
        variable = _underlying_variable(original_variable)
        matches = [index for index, parameter in enumerate(parameters) if _same_variable(variable, parameter)]
        if len(matches) == 1:
            return matches[0]
        definition = _safe_attr(original_variable, "def_site", None)
        if definition is not None:
            source = _safe_attr(definition, "src", None) or _safe_attr(definition, "value", None)
            if source is not None:
                return _parameter_index(source, parameters, depth + 1)
        return None
    if operation in _TRANSPARENT_OPERATIONS:
        operands = _instruction_children(expression)
        return _parameter_index(operands[0], parameters, depth + 1) if len(operands) == 1 else None
    if operation in _PHI_OPERATIONS:
        sources = tuple(_safe_attr(expression, "src", ()) or ()) or _instruction_children(expression)
        indices = {_parameter_index(source, parameters, depth + 1) for source in sources}
        return next(iter(indices)) if len(indices) == 1 and None not in indices else None
    return None


def _same_variable(left: Any, right: Any) -> bool:
    left = _underlying_variable(left)
    right = _underlying_variable(right)
    if left is right:
        return True
    left_id = _integer(_safe_attr(left, "identifier", None))
    right_id = _integer(_safe_attr(right, "identifier", None))
    return left_id is not None and right_id is not None and left_id == right_id


def _underlying_variable(variable: Any) -> Any:
    seen: set[int] = set()
    while variable is not None and id(variable) not in seen:
        seen.add(id(variable))
        nested = _safe_attr(variable, "var", None)
        if nested is None or nested is variable:
            break
        variable = nested
    return variable


def _constant_expression(expression: Any) -> int | None:
    constant = _integer(_safe_attr(expression, "constant", None))
    if constant is None:
        constant = _integer(_safe_attr(expression, "value", None))
    offset = _integer(_safe_attr(expression, "offset", 0)) or 0
    return constant + offset if constant is not None else None


def _symbols_at(view: Any, address: int) -> tuple[Any, ...]:
    symbols: list[Any] = []
    method = _safe_attr(view, "get_symbols", None)
    if callable(method):
        try:
            symbols.extend(tuple(method(address, 1) or ()))
        except Exception:  # noqa: BLE001,S110 - fall through to the single-symbol API.
            pass
    symbol = _safe_call(view, "get_symbol_at", address)
    if symbol is not None:
        symbols.append(symbol)
    unique: dict[tuple[str, str], Any] = {}
    for item in symbols:
        unique[(_symbol_type(item), _symbol_name(item))] = item
    return tuple(unique[key] for key in sorted(unique))


def _functions_at(view: Any, address: int) -> tuple[Any, ...]:
    values = _safe_call(view, "get_functions_at", address)
    return tuple(values or ())


def _symbol_name(symbol: Any) -> str:
    for name in ("raw_name", "short_name", "full_name", "name"):
        value = _safe_attr(symbol, name, None)
        if value:
            return str(value)
    return ""


def _symbol_type(symbol: Any) -> str:
    return _enum_name(_safe_attr(symbol, "type", ""))


def _object_names(value: Any) -> tuple[str, ...]:
    result: set[str] = set()
    for attribute in ("raw_name", "name"):
        candidate = _safe_attr(value, attribute, None)
        if candidate:
            result.add(str(candidate))
    symbol = _safe_attr(value, "symbol", None)
    if symbol is not None:
        name = _symbol_name(symbol)
        if name:
            result.add(name)
    return tuple(sorted(result))


def _looks_like_plt(view: Any, address: int, names: Iterable[str]) -> bool:
    if any(_has_plt_decoration(name) for name in names):
        return True
    return any(".plt" in name or name == ".iplt" for name in _section_names(view, address))


def _has_plt_decoration(name: str) -> bool:
    return str(name).endswith("@plt") or str(name).endswith(".plt")


def _section_names(view: Any, address: int) -> tuple[str, ...]:
    names: set[str] = set()
    sections_at = _safe_call(view, "get_sections_at", address)
    for section in tuple(sections_at or ()):
        name = _safe_attr(section, "name", None)
        if name:
            names.add(str(name))
    sections = _safe_attr(view, "sections", {}) or {}
    items = sections.items() if isinstance(sections, Mapping) else ()
    for name, section in items:
        start = _integer(_safe_attr(section, "start", None))
        end = _integer(_safe_attr(section, "end", None))
        if start is not None and end is not None and start <= address < end:
            names.add(str(name))
    return tuple(sorted(names))


def _data_references_from(view: Any, address: int, size: int) -> tuple[int, ...]:
    method = _safe_attr(view, "get_data_refs_from", None)
    if not callable(method):
        return ()
    try:
        values = method(address, size)
    except TypeError:
        try:
            values = method(address)
        except Exception:  # noqa: BLE001 - tolerate the legacy one-argument API failing.
            return ()
    except Exception:  # noqa: BLE001 - BN data-reference exceptions are not stable API types.
        return ()
    return tuple(sorted(set(_integers(values or ()))))


def _plt_scan_size(address: int, functions: Sequence[Any], cap: int) -> int:
    """Bound PLT reference recovery to the containing function when available."""

    sizes: list[int] = []
    for function in functions:
        for address_range in tuple(_safe_attr(function, "address_ranges", ()) or ()):
            start = _integer(_safe_attr(address_range, "start", None))
            end = _integer(_safe_attr(address_range, "end", None))
            if start is not None and end is not None and start <= address < end:
                sizes.append(end - address)
        highest = _integer(_safe_attr(function, "highest_address", None))
        if highest is not None and highest >= address:
            sizes.append(highest - address + 1)
    # A normal ELF PLT entry is much smaller than this fallback.  Keeping the
    # no-function case at 32 bytes avoids absorbing adjacent stubs.
    return max(1, min(cap, min(sizes, default=32)))


def _sync_function_tags(
    function: Any,
    desired_addresses: Mapping[tuple[int, str], str],
    desired_function: str | None,
    available: set[str],
) -> tuple[int, int, int]:
    added = removed = unchanged = 0
    owned_address_types = {TEEMO_FORMAT_WRITABLE_TAG, TEEMO_FORMAT_UNPROVEN_TAG} & available
    current: dict[tuple[int, str], list[tuple[Any, Any]]] = {}
    seen_auto_tags: set[tuple[int, str, str]] = set()
    for item in tuple(_safe_attr(function, "tags", ()) or ()):
        arch, address, tag = _tag_reference(item)
        if address is None or tag is None:
            continue
        type_name = _tag_type_name(tag)
        if type_name not in owned_address_types:
            continue
        for auto_tag in _auto_tags_at(function, address, arch):
            if _tag_type_name(auto_tag) == type_name:
                identity = str(_safe_attr(auto_tag, "id", id(auto_tag)))
                marker = (address, type_name, identity)
                if marker in seen_auto_tags:
                    continue
                seen_auto_tags.add(marker)
                current.setdefault((address, type_name), []).append((arch, auto_tag))

    for key in sorted(set(current) | set(desired_addresses)):
        desired_data = desired_addresses.get(key)
        existing = current.get(key, [])
        kept = False
        for arch, tag in existing:
            if desired_data is not None and not kept and _tag_data(tag) == desired_data:
                kept = True
                unchanged += 1
                continue
            _remove_auto_address_tag(function, key[0], tag, arch, key[1])
            removed += 1
        if desired_data is not None and not kept:
            function.add_tag(key[1], desired_data, addr=key[0], auto=True)
            added += 1

    if TEEMO_PRINTF_LIKE_TAG in available:
        existing_function = tuple(
            _safe_call(function, "get_function_tags", auto=True, tag_type=TEEMO_PRINTF_LIKE_TAG) or ()
        )
        kept = False
        for tag in existing_function:
            if desired_function is not None and not kept and _tag_data(tag) == desired_function:
                kept = True
                unchanged += 1
                continue
            method = _safe_attr(function, "remove_auto_function_tag", None)
            if callable(method):
                method(tag)
            else:
                function.remove_auto_function_tags_of_type(TEEMO_PRINTF_LIKE_TAG)
            removed += 1
        if desired_function is not None and not kept:
            function.add_tag(TEEMO_PRINTF_LIKE_TAG, desired_function, auto=True)
            added += 1
    return added, removed, unchanged


def _auto_tags_at(function: Any, address: int, arch: Any) -> tuple[Any, ...]:
    method = _safe_attr(function, "get_tags_at", None)
    if not callable(method):
        return ()
    try:
        return tuple(method(address, arch=arch, auto=True) or ())
    except TypeError:
        try:
            return tuple(method(address, auto=True) or ())
        except Exception:  # noqa: BLE001 - tolerate a reduced duck-typed API.
            return ()
    except Exception:  # noqa: BLE001 - BN tag exceptions are not stable API types.
        return ()


def _remove_auto_address_tag(function: Any, address: int, tag: Any, arch: Any, type_name: str) -> None:
    method = _safe_attr(function, "remove_auto_address_tag", None)
    if callable(method):
        try:
            method(address, tag, arch=arch)
        except TypeError:
            method(address, tag)
        return
    function.remove_auto_address_tags_of_type(address, type_name, arch=arch)


def _tag_reference(value: Any) -> tuple[Any, int | None, Any | None]:
    try:
        parts = tuple(value)
    except TypeError:
        return None, None, None
    if len(parts) == 3:
        return parts[0], _integer(parts[1]), parts[2]
    if len(parts) == 2:
        return None, _integer(parts[0]), parts[1]
    return None, None, None


def _tag_type_name(tag: Any) -> str:
    tag_type = _safe_attr(tag, "type", "")
    return str(_safe_attr(tag_type, "name", tag_type))


def _tag_data(tag: Any) -> str:
    return str(_safe_attr(tag, "data", ""))


def _instruction_children(expression: Any) -> tuple[Any, ...]:
    children = tuple(_safe_attr(expression, "instruction_operands", ()) or ())
    if children:
        return children
    for name in ("src", "operand", "expr"):
        child = _safe_attr(expression, name, None)
        if child is not None:
            return (child,)
    return ()


def _call_address(call: Any, fallback: int) -> int:
    return _integer(_safe_attr(call, "address", None)) or fallback


def _expression_index(expression: Any) -> int:
    result = _integer(_safe_attr(expression, "expr_index", None))
    return result if result is not None else -1


def _operation(expression: Any) -> str:
    return _enum_name(_safe_attr(expression, "operation", ""))


def _enum_name(value: Any) -> str:
    return str(_safe_attr(value, "name", value))


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _integers(values: Iterable[Any]) -> Iterator[int]:
    for value in values:
        integer = _integer(value)
        if integer is not None:
            yield integer


def _boolean(value: Any) -> bool:
    return bool(_safe_attr(value, "value", value))


def _safe_attr(value: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(value, name, default)
    except Exception:  # noqa: BLE001 - BN properties may raise arbitrary core exceptions.
        return default


def _safe_call(value: Any, name: str, *args: Any, **kwargs: Any) -> Any:
    method = _safe_attr(value, name, None)
    if not callable(method):
        return None
    try:
        return method(*args, **kwargs)
    except Exception:  # noqa: BLE001 - BN methods may raise arbitrary core exceptions.
        return None
