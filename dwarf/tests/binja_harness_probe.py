#!/usr/bin/env python3
"""Exercise Teemo against the exact Binary Ninja container runtime.

This script is meant to run *inside* the repository's approved Binary Ninja
container harness. Exit status 77 means the probe could not run because the
injected license is absent or invalid; every other non-zero status is a real
compatibility or extraction failure.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import traceback
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

SKIP = 77
EXPECTED_COMMANDS = {
    "Teemo\\Export or refresh GDB debug info",
    "Teemo\\Enable live export",
    "Teemo\\Disable live export",
}
PROBE_TYPES = r"""
typedef unsigned long target_word;
typedef volatile int volatile_int;

enum Mode {
    MODE_ZERO = 0,
    MODE_ACTIVE = 7
};

union Payload {
    int number;
    unsigned char bytes[4];
};

struct Node {
    int value;
    struct Node *next;
};

struct TypeCoverage {
    bool ready;
    float ratio;
    unsigned int flags : 3;
    union Payload payload;
};

typedef int (*callback_t)(int value, char **items);

extern volatile_int global_counter;
extern volatile_int global_sink;
extern struct Node global_node;
int analyzed(int argc, char **argv, struct Node *node);
"""
EXPECTED_TYPE_KINDS = {
    "array",
    "base",
    "class",
    "enum",
    "function",
    "pointer",
    "qualified",
    "structure",
    "typedef",
    "union",
}
PROBE_MODES = {"fixture", "generic"}
GENERIC_DIAGNOSTIC_DETAIL_LIMIT = 64


def _inject_harness_files(inject_root: Path) -> None:
    """Mirror the harness entrypoint's non-secret headless setup."""

    home = Path.home() / ".binaryninja"
    home.mkdir(parents=True, exist_ok=True)
    (home / "lastrun").write_text("/opt/binaryninja\n", encoding="utf-8")
    settings = inject_root / "settings.json"
    if settings.is_file():
        shutil.copy2(settings, home / "settings.json")
    for name in ("license.dat", "license.txt"):
        candidate = inject_root / name
        if candidate.is_file():
            shutil.copy2(candidate, home / "license.dat")
            return


def _is_license_failure(error: BaseException) -> bool:
    message = str(error).lower()
    return "license is not valid" in message or ("license" in message and "valid" in message)


def _core_version(binaryninja: object) -> str:
    version = getattr(binaryninja, "core_version", None)
    return str(version() if callable(version) else version)


def _enum_name(value: object) -> str:
    return str(getattr(value, "name", value))


def _verify_x86_64_direct_got_orphan(view: object, expected_orphan: int) -> dict[str, int]:
    """Prove the stripped orphan exposes its import only through raw LLIL."""

    arch = getattr(view, "arch", None)
    if arch is None or str(getattr(arch, "name", "")) != "x86_64":
        return {}

    import binaryninja

    slots = [
        symbol
        for symbol in view.get_symbols_of_type(binaryninja.SymbolType.ImportAddressSymbol)
        if "teemo_imported_win" in str(getattr(symbol, "raw_name", ""))
    ]
    if len(slots) != 1:
        rendered = [
            (str(getattr(symbol, "raw_name", "")), int(symbol.address))
            for symbol in view.get_symbols_of_type(binaryninja.SymbolType.ImportAddressSymbol)
        ]
        raise RuntimeError(
            f"x86-64 direct-GOT fixture did not produce one teemo_imported_win ImportAddressSymbol: {rendered!r}"
        )
    slot = int(slots[0].address)
    got_sections = [section for name, section in view.sections.items() if str(name).lower() == ".got"]
    if not any(int(section.start) <= slot < int(section.end) for section in got_sections):
        raise RuntimeError(f"import slot {slot:#x} is not contained in the fixture's .got section")

    cursor = expected_orphan
    decoded: list[tuple[int, tuple[int, ...], str]] = []
    for _ in range(8):
        data = bytes(view.read(cursor, int(arch.max_instr_length)))
        info = arch.get_instruction_info(data, cursor)
        length = int(getattr(info, "length", 0)) if info is not None else 0
        if length <= 0:
            break
        instruction = arch.get_instruction_low_level_il_instruction(view, cursor)

        def constant(node: object) -> int | None:
            operation = _enum_name(getattr(node, "operation", ""))
            if operation not in {"LLIL_CONST_PTR", "LLIL_EXTERN_PTR"}:
                return None
            try:
                value = int(node.constant)
                if operation == "LLIL_EXTERN_PTR":
                    value += int(getattr(node, "offset", 0))
                return value
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None

        constants = tuple(value for value in instruction.traverse(constant) if value is not None)
        decoded.append((cursor, constants, str(instruction)))
        if slot in constants:
            return {"orphan_got_slot": slot, "orphan_got_instruction": cursor}
        cursor += length

    raise RuntimeError(f"raw x86-64 orphan LLIL did not contain import slot {slot:#x}: {decoded!r}")


def _verify_plugin_commands(binaryninja: object) -> None:
    names = {str(command.name) for command in binaryninja.PluginCommand}
    missing = sorted(EXPECTED_COMMANDS - names)
    if missing:
        raise RuntimeError(f"Binary Ninja did not register Teemo commands: {missing}")


def _verify_canary_annotations(view: object, report: object) -> dict[str, object]:
    analyzed_functions = list(view.get_functions_by_name("analyzed"))
    if len(analyzed_functions) != 1:
        raise RuntimeError("canary fixture has no unique analyzed function")
    analyzed = analyzed_functions[0]
    matched = tuple(report.matched_functions)
    if int(analyzed.start) not in matched:
        relevant_symbols = [
            (
                _enum_name(getattr(symbol, "type", "")),
                str(getattr(symbol, "raw_name", getattr(symbol, "name", ""))),
                int(symbol.address),
            )
            for symbol in view.get_symbols()
            if "stack_chk" in str(getattr(symbol, "raw_name", getattr(symbol, "name", "")))
        ]
        mlil = [
            str(instruction)
            for block in analyzed.medium_level_il
            for instruction in block
        ]
        raise RuntimeError(
            "real stack protector in analyzed was not recognized: "
            f"{report!r}; symbols={relevant_symbols!r}; mlil={mlil!r}"
        )

    named = [
        variable
        for variable in analyzed.vars
        if str(getattr(variable, "name", "")) in {"tcb", "CANARY"}
    ]
    names = {str(variable.name) for variable in named}
    if "CANARY" not in names:
        raise RuntimeError(f"matched function has no automatic CANARY variable: {names!r}")
    if any(analyzed.is_var_user_defined(variable) for variable in named):
        raise RuntimeError("Teemo canary annotation created a persistent user variable")

    architecture = str(getattr(getattr(view, "arch", None), "name", ""))
    if architecture in {"x86", "x86_64"}:
        if "tcb" not in names:
            raise RuntimeError(
                f"x86 TLS annotation has no automatic tcb variable: {names!r}; {report!r}"
            )
        if view.get_type_by_name("tcbhead_t") is None or not view.is_type_auto_defined("tcbhead_t"):
            raise RuntimeError("x86 TLS annotation did not create an analysis-owned tcbhead_t")
    elif "tcb" in names:
        raise RuntimeError(f"global-guard architecture received a fake TLS variable: {architecture}")

    return {
        "canary_matches": len(matched),
        "canary_names": sorted(names),
        "canary_target": report.target,
    }


def _verify_format_annotations(
    view: object,
    report: object,
    tag_result: object,
    signature_bootstrap: object,
) -> dict[str, object]:
    from teemo.teemo.format_analysis import (
        FormatOrigin,
        TEEMO_FORMAT_UNPROVEN_TAG,
        TEEMO_FORMAT_WRITABLE_TAG,
        TEEMO_PRINTF_LIKE_TAG,
        synchronize_auto_tags,
    )

    format_functions = list(view.get_functions_by_name("teemo_format_calls"))
    wrapper_functions = list(view.get_functions_by_name("teemo_printf_wrapper"))
    if len(format_functions) != 1 or len(wrapper_functions) != 1:
        raise RuntimeError("format fixture functions are not uniquely analyzed")
    format_function = format_functions[0]
    wrapper_function = wrapper_functions[0]
    wrapper = next(
        (item for item in report.wrappers if item.function_address == int(wrapper_function.start)),
        None,
    )
    if wrapper is None or wrapper.format_parameter_index != 0 or "printf" not in wrapper.ultimate_callees:
        hlil = str(getattr(getattr(wrapper_function, "hlil", None), "root", ""))
        mlil = [str(instruction) for block in wrapper_function.mlil for instruction in block]
        parameters = [
            (str(getattr(variable, "name", "")), str(getattr(variable, "type", "")))
            for variable in wrapper_function.parameter_vars
        ]
        targets = [
            (
                str(function.name),
                int(function.start),
                str(function.type),
                len(tuple(function.parameter_vars)),
                bool(function.has_user_type),
            )
            for name in ("printf", "snprintf")
            for function in view.get_functions_by_name(name)
        ]
        raise RuntimeError(
            "printf-like wrapper was not inferred: "
            f"{report!r}; bootstrap={signature_bootstrap!r}; targets={targets!r}; "
            f"parameters={parameters!r}; hlil={hlil!r}; mlil={mlil!r}"
        )

    fixture_calls = [item for item in report.calls if item.caller_address == int(format_function.start)]
    origins = [item.origin.origin for item in fixture_calls]
    if origins.count(FormatOrigin.WRITABLE) != 2 or origins.count(FormatOrigin.READ_ONLY) != 2:
        raise RuntimeError(
            "real format fixture classification mismatch: "
            f"calls={fixture_calls!r}; report={report!r}"
        )
    wrapper_calls = [item for item in report.calls if item.caller_address == int(wrapper_function.start)]
    if len(wrapper_calls) != 1 or wrapper_calls[0].origin.origin is not FormatOrigin.UNKNOWN:
        raise RuntimeError(f"wrapper's parameter-origin call was not marked unproven: {wrapper_calls!r}")

    if tag_result.added < 4 or tag_result.removed or tag_result.issues:
        raise RuntimeError(f"format tags were not created cleanly: {tag_result!r}")
    function_tags = wrapper_function.get_function_tags(auto=True, tag_type=TEEMO_PRINTF_LIKE_TAG)
    if len(function_tags) != 1:
        raise RuntimeError(f"printf-like wrapper has no unique automatic function tag: {function_tags!r}")
    if wrapper_function.get_function_tags(auto=False, tag_type=TEEMO_PRINTF_LIKE_TAG):
        raise RuntimeError("printf-like wrapper annotation was stored as a user tag")

    risk_types = {TEEMO_FORMAT_WRITABLE_TAG, TEEMO_FORMAT_UNPROVEN_TAG}
    risk_addresses = set()
    for function in (format_function, wrapper_function):
        for arch, address, tag in function.tags:
            if str(tag.type.name) not in risk_types:
                continue
            if tag not in function.get_tags_at(address, arch=arch, auto=True):
                raise RuntimeError("format risk annotation was stored as a user tag")
            risk_addresses.add(int(address))
    expected_risks = {item.call_address for item in report.findings}
    if risk_addresses != expected_risks:
        raise RuntimeError(f"visible format tag addresses mismatch: {risk_addresses!r} != {expected_risks!r}")

    second = synchronize_auto_tags(view, report)
    if second.added or second.removed or second.issues:
        raise RuntimeError(f"format tag synchronization is not idempotent: {second!r}")
    return {
        "format_calls": len(report.calls),
        "format_findings": len(report.findings),
        "format_tags": len(risk_addresses),
        "format_wrappers": len(report.wrappers),
    }


def _seed_probe_types(view: object) -> None:
    """Exercise the exact public 5.2 type mutation APIs before extraction."""

    parsed = view.parse_types_from_string(PROBE_TYPES)
    view.define_user_types(list(parsed.types.items()), None)

    import binaryninja

    integer = binaryninja.Type.int(4)
    base = binaryninja.TypeBuilder.class_type()
    base.append(integer, "base_value")
    view.define_user_type("TeemoHarnessBase", base)
    registered_base = view.get_type_by_name("TeemoHarnessBase")
    if registered_base is None:
        raise RuntimeError("Binary Ninja did not register the harness base class")
    derived = binaryninja.TypeBuilder.class_type()
    derived.base_structures = [binaryninja.BaseStructure(registered_base, 0)]
    derived.insert(4, integer, "derived_value")
    derived.width = 8
    view.define_user_type("TeemoHarnessDerived", derived)

    analyzed_functions = list(view.get_functions_by_name("analyzed"))
    if len(analyzed_functions) != 1:
        raise RuntimeError(f"expected one Binary Ninja function named 'analyzed', found {len(analyzed_functions)}")
    prototypes = [value for name, value in parsed.functions.items() if str(name) == "analyzed"]
    if len(prototypes) != 1:
        raise RuntimeError("Binary Ninja's type parser did not return the analyzed prototype")
    analyzed_functions[0].set_user_type(prototypes[0])

    for name, value in parsed.variables.items():
        symbol = view.get_symbol_by_raw_name(str(name))
        if symbol is not None:
            view.define_user_data_var(int(symbol.address), value)
    view.update_analysis_and_wait()


def _walk_scopes(scope: object) -> list[object]:
    result = [scope]
    for child in scope.children:
        result.extend(_walk_scopes(child))
    return result


def _verify_document(document: object, *, expected_orphan: int | None = None) -> dict[str, object]:
    document.validate()
    functions = list(document.functions)
    analyzed = next((function for function in functions if function.name == "analyzed"), None)
    if analyzed is None:
        raise RuntimeError("fixture function 'analyzed' was not extracted")
    if not document.lines:
        raise RuntimeError("real Binary Ninja extraction produced no address-to-HLIL line records")
    if not document.sources or not analyzed.ranges:
        raise RuntimeError("real Binary Ninja extraction produced incomplete function/source metadata")
    if not analyzed.parameters:
        raise RuntimeError("real Binary Ninja extraction produced no function parameters")
    if [parameter.name for parameter in analyzed.parameters] != ["argc", "argv", "node"]:
        raise RuntimeError("real Binary Ninja extraction did not preserve the seeded analyzed parameter names")

    scopes = _walk_scopes(analyzed.scope)
    if len(scopes) < 2:
        raise RuntimeError("real Binary Ninja extraction produced no nested lexical scope")
    locals_ = [variable for scope in scopes for variable in scope.variables]
    if not locals_:
        raise RuntimeError("real Binary Ninja extraction produced no local variables")
    ranged_variables = [*analyzed.parameters, *locals_]
    available_locations = [
        location
        for variable in ranged_variables
        for location in variable.locations
        if location.expression.kind != "unavailable"
    ]
    if not available_locations:
        raise RuntimeError("real Binary Ninja extraction produced no available variable locations")

    type_kinds = {str(entry.get("kind")) for entry in document.types}
    missing_type_kinds = sorted(EXPECTED_TYPE_KINDS - type_kinds)
    if missing_type_kinds:
        raise RuntimeError(f"real Binary Ninja type export is missing seeded kinds: {missing_type_kinds}")
    classes_with_bases = [entry for entry in document.types if entry.get("kind") == "class" and entry.get("bases")]
    if not classes_with_bases:
        raise RuntimeError("real Binary Ninja type export lost the seeded class inheritance")
    bitfields = [member for entry in document.types for member in entry.get("members", []) if member.get("bit_size")]
    if not bitfields:
        raise RuntimeError("real Binary Ninja type export lost the seeded bitfield metadata")
    global_names = {variable.name for variable in document.globals}
    missing_globals = sorted({"global_counter", "global_sink", "global_node"} - global_names)
    if missing_globals:
        raise RuntimeError(f"real Binary Ninja extraction is missing globals: {missing_globals}")

    function_lines = [
        line
        for line in document.lines
        if any(
            function_range.start.section == line.range.start.section
            and function_range.start.value <= line.range.start.value
            and line.range.end.value <= function_range.end.value
            for function_range in analyzed.ranges
        )
    ]
    if len({line.line for line in function_lines}) < 3:
        raise RuntimeError("real Binary Ninja extraction mapped fewer than three analyzed HLIL lines")
    recovered_orphan = None
    if expected_orphan is not None:
        recovered_orphan = next(
            (
                function
                for function in functions
                if any(
                    function_range.start.value <= expected_orphan < function_range.end.value
                    for function_range in function.ranges
                )
            ),
            None,
        )
        if recovered_orphan is None:
            raise RuntimeError(f"recovered orphan at {expected_orphan:#x} was not exported")
    return {
        "architecture": document.binary.architecture.value,
        "available_locations": len(available_locations),
        "diagnostics": len(document.diagnostics),
        "functions": len(functions),
        "lines": len(document.lines),
        "locals": len(locals_),
        "parameters": len(analyzed.parameters),
        "scopes": len(scopes),
        "sources": len(document.sources),
        "types": len(document.types),
        "type_kinds": sorted(type_kinds),
        "orphan": expected_orphan,
        "orphan_function": recovered_orphan.name if recovered_orphan is not None else None,
    }


def _generic_prepass_summary(view: object, report: object) -> dict[str, object]:
    """Render a stable, JSON-safe report without challenge-specific assertions."""

    discovery = report.discovery
    if discovery is None:
        discovery_summary: dict[str, object] | None = None
    else:
        recovered = []
        for address in discovery.added:
            function = view.get_function_at(address)
            recovered.append(
                {
                    "address": int(address),
                    "name": str(getattr(function, "name", "")) if function is not None else None,
                }
            )
        discovery_summary = {
            "scanned_bytes": int(discovery.scanned_bytes),
            "candidates": int(discovery.candidates),
            "added": [int(address) for address in discovery.added],
            "recovered": recovered,
            "rejected": [int(address) for address in discovery.rejected],
            "rejection_reasons": [
                {"address": int(address), "reason": str(reason)}
                for address, reason in discovery.rejection_reasons
            ],
            "cascaded": [int(address) for address in discovery.cascaded],
            "truncated": bool(discovery.truncated),
            "changed": bool(discovery.changed),
        }

    canary = report.canary
    canary_summary = (
        None
        if canary is None
        else {
            "target": canary.target,
            "examined_functions": int(canary.examined_functions),
            "matched_functions": [int(address) for address in canary.matched_functions],
            "matches": [
                {
                    "function": int(item.function_start),
                    "guard_kind": str(item.guard_kind),
                    "guard_location": int(item.guard_location),
                    "qualification": list(item.qualification),
                    "tcb_action": str(item.tcb_action),
                    "canary_action": str(item.canary_action),
                }
                for item in canary.functions
            ],
            "type_action": str(canary.type_action),
            "analysis_updates": int(canary.analysis_updates),
            "changed": bool(canary.changed),
            "diagnostics": list(canary.diagnostics),
        }
    )

    signatures = report.format_signatures
    signature_summary = (
        None
        if signatures is None
        else {
            "updated_functions": [int(address) for address in signatures.updated_functions],
            "unchanged_functions": [int(address) for address in signatures.unchanged_functions],
            "user_typed_functions": [int(address) for address in signatures.user_typed_functions],
            "reanalyzed_callers": [int(address) for address in signatures.reanalyzed_callers],
            "settled": bool(signatures.settled),
            "changed": bool(signatures.changed),
            "issues": list(signatures.issues),
        }
    )

    format_report = report.format_analysis
    if format_report is None:
        format_summary: dict[str, object] | None = None
    else:
        origins = Counter(item.origin.origin.value for item in format_report.calls)
        callees = Counter(item.callee.name for item in format_report.calls)
        format_summary = {
            "calls": len(format_report.calls),
            "findings": len(format_report.findings),
            "wrappers": len(format_report.wrappers),
            "issues": [
                {
                    "code": str(item.code),
                    "message": str(item.message),
                    "function_address": item.function_address,
                    "call_address": item.call_address,
                }
                for item in format_report.issues
            ],
            "origins": dict(sorted(origins.items())),
            "callees": dict(sorted(callees.items())),
            "finding_details": [
                {
                    "id": item.finding_id,
                    "caller_address": int(item.caller_address),
                    "caller_name": str(item.caller_name),
                    "call_address": int(item.call_address),
                    "callee": str(item.callee.name),
                    "origin": item.origin.origin.value,
                    "reason": str(item.origin.reason),
                    "addresses": [int(address) for address in item.origin.addresses],
                    "sections": list(item.origin.sections),
                }
                for item in format_report.findings
            ],
            "wrapper_details": [
                {
                    "function_address": int(item.function_address),
                    "function_name": str(item.function_name),
                    "format_parameter_index": int(item.format_parameter_index),
                    "character_width": int(item.character_width),
                    "depth": int(item.depth),
                    "ultimate_callees": list(item.ultimate_callees),
                }
                for item in format_report.wrappers
            ],
        }

    tags = report.tag_sync
    tag_summary = (
        None
        if tags is None
        else {
            "added": int(tags.added),
            "removed": int(tags.removed),
            "unchanged": int(tags.unchanged),
            "issues": list(tags.issues),
        }
    )
    return {
        "orphan": discovery_summary,
        "canary": canary_summary,
        "format_signatures": signature_summary,
        "format": format_summary,
        "tags": tag_summary,
        "diagnostics": len(report.diagnostics),
        "changed": bool(report.changed),
    }


def _generic_document_summary(document: object) -> dict[str, object]:
    """Validate and summarize any supported ELF Teemo document."""

    document.validate()
    severity_counts = Counter(str(item.severity) for item in document.diagnostics)
    code_counts = Counter(str(item.code) for item in document.diagnostics)
    diagnostic_details = [
        {
            "severity": str(item.severity),
            "code": str(item.code),
            "message": str(item.message),
            "context": item.context,
        }
        for item in document.diagnostics[:GENERIC_DIAGNOSTIC_DETAIL_LIMIT]
    ]
    return {
        "architecture": document.binary.architecture.value,
        "entry_point": int(document.binary.entry_point),
        "image_base": int(document.binary.image_base),
        "build_id": document.binary.build_id,
        "sections": len(document.sections),
        "types": len(document.types),
        "globals": len(document.globals),
        "functions": len(document.functions),
        "labels": len(document.labels),
        "sources": len(document.sources),
        "lines": len(document.lines),
        "diagnostics": {
            "count": len(document.diagnostics),
            "by_severity": dict(sorted(severity_counts.items())),
            "by_code": dict(sorted(code_counts.items())),
            "details": diagnostic_details,
            "details_omitted": max(0, len(document.diagnostics) - len(diagnostic_details)),
        },
        "validation": "ok",
    }


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("binaries", type=Path, nargs="+")
    parser.add_argument("--mode", choices=sorted(PROBE_MODES), default="fixture")
    parser.add_argument("--expected-version", default="5.2.8722")
    parser.add_argument(
        "--expected-architectures",
        default="x86_64,x86,arm,aarch64",
        help="comma-separated canonical Teemo architectures",
    )
    parser.add_argument("--inject-root", type=Path, default=Path("/inject"))
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args(argv)


def run_probe(
    binaries: Sequence[Path],
    *,
    expected_version: str = "5.2.8722",
    expected_architectures: str = "x86_64,x86,arm,aarch64",
    output_dir: Path | None = None,
    expected_orphans: dict[str, int] | None = None,
    mode: str = "fixture",
) -> dict[str, object]:
    """Run extraction after Binary Ninja has initialized its licensed core.

    Personal licenses intentionally cannot initialize the headless API. The
    approved container therefore calls this function from a tiny GUI plugin,
    after the normal Xvfb-backed Binary Ninja process has validated the license.
    """

    if mode not in PROBE_MODES:
        raise ValueError(f"unsupported Binary Ninja harness probe mode {mode!r}")

    import binaryninja

    version = _core_version(binaryninja)
    if expected_version not in version:
        raise RuntimeError(f"expected Binary Ninja {expected_version}, container has {version}")

    _verify_plugin_commands(binaryninja)
    from teemo.teemo.extractor import extract_document
    from teemo.teemo.prepass import run_pre_export

    summaries = []
    architectures = set()
    for binary in binaries:
        if mode == "generic":
            with binaryninja.load(str(binary), update_analysis=True) as view:
                if str(view.view_type).lower() != "elf":
                    raise RuntimeError(f"binary {binary} opened as {view.view_type!r}, not ELF")
                functions_before = len(tuple(view.functions))
                prepass_started = time.perf_counter()
                prepass = run_pre_export(view, run_orphan=True, initially_settled=True)
                prepass_seconds = time.perf_counter() - prepass_started
                prepass_summary = _generic_prepass_summary(view, prepass)
                functions_after = len(tuple(view.functions))
                extraction_started = time.perf_counter()
                document = extract_document(view)
                document.diagnostics.extend(prepass.diagnostics)
                document.validate()
                extraction_seconds = time.perf_counter() - extraction_started
            summary = _generic_document_summary(document)
            summary.update(
                {
                    "binary": binary.name,
                    "path": str(binary),
                    "functions_before_prepass": functions_before,
                    "functions_after_prepass": functions_after,
                    "prepass": prepass_summary,
                    "prepass_seconds": round(prepass_seconds, 6),
                    "extraction_seconds": round(extraction_seconds, 6),
                }
            )
            summaries.append(summary)
            architectures.add(str(summary["architecture"]))
            if output_dir is not None:
                output_dir.mkdir(parents=True, exist_ok=True)
                output = output_dir / f"{binary.name}.json"
                output.write_text(document.dumps() + "\n", encoding="utf-8")
            continue

        load_options = (
            {"analysis.linearSweep.autorun": False} if (expected_orphans or {}).get(str(binary)) is not None else None
        )
        with binaryninja.load(str(binary), options=load_options, update_analysis=True) as view:
            if str(view.view_type).lower() != "elf":
                raise RuntimeError(f"fixture {binary} opened as {view.view_type!r}, not ELF")
            _seed_probe_types(view)
            expected_orphan = (expected_orphans or {}).get(str(binary))
            direct_got = {}
            if expected_orphan is not None:
                before = list(view.get_functions_containing(expected_orphan))
                if before:
                    raise RuntimeError(
                        f"orphan fixture at {expected_orphan:#x} was already analyzed before Teemo: {before}"
                    )
                direct_got = _verify_x86_64_direct_got_orphan(view, expected_orphan)
            prepass = run_pre_export(view, run_orphan=True, initially_settled=True)
            if expected_orphan is not None:
                if prepass.discovery is None or expected_orphan not in prepass.discovery.added:
                    raise RuntimeError(
                        f"Teemo did not recover orphan {expected_orphan:#x}: {prepass.discovery}"
                    )
                recovered = view.get_function_at(expected_orphan)
                if recovered is None or bool(recovered.has_user_annotations):
                    raise RuntimeError(
                        f"recovered orphan {expected_orphan:#x} is missing or has persistent user annotations"
                    )
            if prepass.canary is None:
                raise RuntimeError(f"combined prepass produced no canary report: {prepass!r}")
            canary = _verify_canary_annotations(view, prepass.canary)
            if prepass.format_signatures is None or prepass.format_signatures.issues:
                raise RuntimeError(f"format signature bootstrap failed: {prepass.format_signatures!r}")
            if prepass.format_analysis is None or prepass.tag_sync is None:
                raise RuntimeError(f"combined prepass produced no format report/tags: {prepass!r}")
            format_summary = _verify_format_annotations(
                view,
                prepass.format_analysis,
                prepass.tag_sync,
                prepass.format_signatures,
            )
            format_summary["format_signatures"] = len(prepass.format_signatures.updated_functions)

            second = run_pre_export(view, run_orphan=True, initially_settled=True)
            if second.discovery is None or second.discovery.added or second.discovery.rejected:
                raise RuntimeError(f"orphan recovery is not idempotent: {second.discovery!r}")
            if second.canary is None or second.canary.changed or second.canary.analysis_updates:
                raise RuntimeError(f"canary annotation is not idempotent: {second.canary!r}")
            if (
                second.format_signatures is None
                or second.format_signatures.changed
                or second.format_signatures.settled
                or second.format_signatures.issues
            ):
                raise RuntimeError(
                    f"format signature bootstrap is not idempotent: {second.format_signatures!r}"
                )
            if second.tag_sync is None or second.tag_sync.added or second.tag_sync.removed or second.tag_sync.issues:
                raise RuntimeError(f"format tags are not idempotent: {second.tag_sync!r}")
            extraction_started = time.perf_counter()
            document = extract_document(view)
            document.diagnostics.extend(prepass.diagnostics)
            document.validate()
            extraction_seconds = time.perf_counter() - extraction_started
        summary = _verify_document(document, expected_orphan=expected_orphan)
        summary.update(direct_got)
        summary.update(canary)
        summary.update(format_summary)
        summary["binary"] = binary.name
        summary["extraction_seconds"] = round(extraction_seconds, 6)
        summaries.append(summary)
        architectures.add(str(summary["architecture"]))
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            output = output_dir / f"{binary.name}.json"
            output.write_text(document.dumps() + "\n", encoding="utf-8")

    if mode == "fixture":
        expected = {value for value in expected_architectures.split(",") if value}
        if architectures != expected:
            raise RuntimeError(
                f"extracted architecture set {sorted(architectures)!r} does not match {sorted(expected)!r}"
            )
    result = {"status": "ok", "version": version, "documents": summaries}
    if mode == "generic":
        result["mode"] = mode
    return result


def main(argv: list[str]) -> int:
    arguments = parse_arguments(argv)
    _inject_harness_files(arguments.inject_root)
    try:
        import binaryninja

        # Commercial/Ultimate harnesses can still use the command-line probe.
        # Personal harnesses run ``run_probe`` from the GUI plugin instead.
        binaryninja._init_plugins()
        result = run_probe(
            arguments.binaries,
            expected_version=arguments.expected_version,
            expected_architectures=arguments.expected_architectures,
            output_dir=arguments.output_dir,
            mode=arguments.mode,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:  # noqa: BLE001 - translate any licensed-core probe failure.
        if _is_license_failure(error):
            print(
                "SKIP: Binary Ninja harness license is absent, expired, or invalid; "
                "replace test-auto/inject/license.dat (or license.txt) and rerun.",
                file=sys.stderr,
            )
            return SKIP
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
