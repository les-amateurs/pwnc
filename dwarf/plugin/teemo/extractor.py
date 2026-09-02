"""Binary Ninja 5.x adapter for Teemo's versioned debug-information IR."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import struct
from typing import Any, Iterable, Sequence

from .analysis import (
    AstIndex,
    AstNode,
    LocationEvidence,
    MachineInstruction,
    RenderedLine,
    ScopePlan,
    Span,
    map_machine_to_lines,
    partition_locations,
    recover_scope_tree,
)
from .ir import (
    Address,
    AddressRange,
    Architecture,
    Binary,
    Declaration,
    Diagnostic,
    Document,
    Endianness,
    Function,
    Label,
    Line,
    LocationExpression,
    Scope,
    Section,
    Source,
    Variable,
)
from .type_export import BinjaTypeExporter


_SCOPE_OPERATIONS = {
    "HLIL_BLOCK",
    "HLIL_FOR",
    "HLIL_FOR_SSA",
    "HLIL_WHILE",
    "HLIL_WHILE_SSA",
    "HLIL_DO_WHILE",
    "HLIL_DO_WHILE_SSA",
    "HLIL_SWITCH",
    "HLIL_CASE",
}
_DECLARATION_OPERATIONS = {"HLIL_VAR_DECLARE", "HLIL_VAR_INIT", "HLIL_VAR_INIT_SSA"}
_VARIABLE_OPERATIONS = {"HLIL_VAR", "HLIL_VAR_SSA"}
_FORMATTING_LINES = {"{", "}", "};", "else", "else {", "do", "do {"}

_PT_LOAD = 1
_PT_NOTE = 4
_NT_GNU_BUILD_ID = 3
_PN_XNUM = 0xFFFF
_MAX_ELF_PROGRAM_HEADERS = 4096
_MAX_ELF_PROGRAM_HEADER_SIZE = 256
_MAX_ELF_PROGRAM_HEADER_TABLE = 1024 * 1024
_MAX_ELF_PROGRAM_HEADER_OFFSET = 16 * 1024 * 1024
_MAX_ELF_NOTE_BYTES = 1024 * 1024
_MAX_ELF_NOTE_TOTAL = 4 * 1024 * 1024


class ExtractionError(RuntimeError):
    """Raised when a view cannot be represented by the supported IR version."""


@dataclass(slots=True)
class _FunctionExport:
    function: Function
    source: Source
    lines: list[Line]
    labels: list[Label]


class _SectionIndex:
    def __init__(self, sections: Sequence[Section]) -> None:
        self.sections = sorted(sections, key=lambda section: (section.address, section.size, section.id))

    def at(self, address: int, *, allow_end: bool = False) -> Section | None:
        candidates = [
            section
            for section in self.sections
            if section.address <= address < section.end
            or (allow_end and address == section.end and section.size != 0)
        ]
        return min(candidates, key=lambda section: (section.size, section.id), default=None)

    def address(self, value: int, *, allow_end: bool = False) -> Address | None:
        section = self.at(value, allow_end=allow_end)
        return Address(value, section.id) if section is not None else None

    def ranges(self, start: int, end: int) -> list[AddressRange]:
        if end <= start:
            return []
        result = []
        cursor = start
        while cursor < end:
            section = self.at(cursor)
            if section is None:
                next_start = min((item.address for item in self.sections if item.address > cursor), default=end)
                cursor = min(next_start, end)
                continue
            piece_end = min(end, section.end)
            result.append(AddressRange(Address(cursor, section.id), Address(piece_end, section.id)))
            cursor = piece_end
        return result

    def spans(self, ranges: Iterable[Any]) -> list[Span]:
        result = []
        for value in ranges:
            for address_range in self.ranges(int(value.start), int(value.end)):
                result.append(Span.from_ir(address_range))
        return result


class BinaryNinjaExtractor:
    """Extract one analyzed BinaryView without retaining any Binary Ninja objects."""

    def __init__(self, binary_view: Any) -> None:
        self.bv = binary_view
        self.architecture = _architecture(getattr(getattr(binary_view, "arch", None), "name", ""))
        self.endianness = _endianness(getattr(binary_view, "endianness", ""))
        self.diagnostics: list[Diagnostic] = []
        self.sections = self._extract_sections()
        self.section_index = _SectionIndex(self.sections)
        self.types = BinjaTypeExporter(binary_view)
        self._parameter_flow_cache: dict[int, dict[str, list[LocationEvidence]]] = {}
        self._ssa_cache: dict[int, tuple[Any | None, dict[str, tuple[Any, ...]]]] = {}

    def extract(self) -> Document:
        if str(getattr(self.bv, "view_type", "")).lower() != "elf":
            raise ExtractionError(f"Teemo currently supports ELF views, not {getattr(self.bv, 'view_type', None)!r}")
        if not self.sections:
            raise ExtractionError("the BinaryView has no mapped ELF sections")

        self.types.export_named_types()
        functions: list[Function] = []
        sources: list[Source] = []
        lines: list[Line] = []
        labels: list[Label] = []
        for bn_function in sorted(getattr(self.bv, "functions", ()), key=lambda function: int(function.start)):
            try:
                exported = self._extract_function(bn_function)
            except Exception as error:
                self._warn(
                    "function-export-failed",
                    f"failed to export function at {int(bn_function.start):#x}: {error}",
                    address=int(bn_function.start),
                )
                continue
            if exported is None:
                continue
            functions.append(exported.function)
            sources.append(exported.source)
            lines.extend(exported.lines)
            labels.extend(exported.labels)

        globals_ = self._extract_globals()
        labels.extend(self._extract_symbol_labels(functions, sources, lines))
        labels = _deduplicate_labels(labels)
        self.diagnostics.extend(self.types.diagnostics)

        original_filename = _original_filename(self.bv)
        document = Document(
            producer=f"Teemo Binary Ninja extractor ({_core_version()})",
            binary=Binary(
                filename=os.path.basename(original_filename) or "binary",
                architecture=self.architecture,
                endianness=self.endianness,
                entry_point=int(getattr(self.bv, "entry_point", 0)),
                image_base=int(getattr(self.bv, "original_image_base", getattr(self.bv, "start", 0))),
                build_id=_elf_build_id(self.bv, self.endianness),
            ),
            sections=self.sections,
            types=self.types.finish(),
            globals=globals_,
            functions=functions,
            labels=labels,
            sources=sources,
            lines=sorted(
                lines,
                key=lambda line: (
                    line.range.start.section or "",
                    line.range.start.value,
                    line.discriminator,
                ),
            ),
            diagnostics=self.diagnostics,
        )
        document.validate()
        return document

    def _extract_sections(self) -> list[Section]:
        sections = []
        used_names: set[str] = set()
        for index, (name, bn_section) in enumerate(
            sorted(getattr(self.bv, "sections", {}).items(), key=lambda item: (int(item[1].start), item[0]))
        ):
            start = int(bn_section.start)
            end = int(bn_section.end)
            if end <= start or not name:
                continue
            segment = getattr(self.bv, "get_segment_at", lambda _address: None)(start)
            semantics = _enum_name(getattr(bn_section, "semantics", ""))
            # Sections not backed by a loadable segment cannot be rebased by
            # add-symbol-file and are not valid address targets.
            if segment is None:
                self._warn(
                    "unmapped-section-omitted",
                    f"omitting ELF section {name!r} because it has no mapped segment",
                )
                continue
            readable = bool(getattr(segment, "readable", True))
            writable = bool(getattr(segment, "writable", "ReadWrite" in semantics))
            executable = bool(getattr(segment, "executable", "Code" in semantics))
            output_name = str(name)
            if output_name in used_names:
                self._warn("duplicate-section-name", f"omitting duplicate ELF section {output_name!r}")
                continue
            used_names.add(output_name)
            sections.append(
                Section(
                    id=f"section:{index}:{_sanitize_component(output_name, 'section')}",
                    name=output_name,
                    address=start,
                    size=end - start,
                    readable=readable,
                    writable=writable,
                    executable=executable,
                )
            )
        return sections

    def _extract_function(self, bn_function: Any) -> _FunctionExport | None:
        function_id = f"function:{int(bn_function.start):x}"
        ranges = [span.to_ir() for span in self.section_index.spans(getattr(bn_function, "address_ranges", ()))]
        if not ranges:
            self._warn(
                "function-outside-sections",
                f"omitting function {getattr(bn_function, 'name', function_id)!r} outside mapped sections",
            )
            return None

        source_id = f"source:{int(bn_function.start):x}"
        hlil = getattr(bn_function, "hlil", None)
        root = getattr(hlil, "root", None) if hlil is not None else None
        if root is None:
            return self._extract_function_without_hlil(bn_function, function_id, source_id, ranges)

        actual_nodes, normalized_nodes = _normalize_ast(root)
        rendered = _render_lines(root)
        source = Source(
            id=source_id,
            path=f"teemo/{_sanitize_component(str(getattr(bn_function, 'name', 'function')), 'function')}_{int(bn_function.start):x}.c",
            language="c",
            generated=True,
            contents="\n".join(line.text.rstrip("\n") for line in rendered) + "\n",
        )
        machine = self._machine_instructions(bn_function)
        mapping = map_machine_to_lines(normalized_nodes, rendered, machine)
        if mapping.unmapped:
            self._warn(
                "unmapped-machine-instructions",
                f"{len(mapping.unmapped)} machine instructions in {getattr(bn_function, 'name', function_id)!r} have no HLIL line",
                function=function_id,
                count=len(mapping.unmapped),
            )
        ambiguous_count = sum(assignment.ambiguous for assignment in mapping.assignments)
        if ambiguous_count:
            self._warn(
                "ambiguous-line-mappings",
                f"{ambiguous_count} machine ranges in {getattr(bn_function, 'name', function_id)!r} "
                "map to multiple HLIL owners; Teemo selected a deterministic common owner",
                function=function_id,
                count=ambiguous_count,
            )
        lines = [
            Line(
                range=assignment.span.to_ir(),
                source_id=source_id,
                line=assignment.source_line,
                column=1,
                statement=assignment.statement,
                discriminator=assignment.discriminator,
            )
            for assignment in mapping.assignments
        ]

        variables = _collect_variables(bn_function, hlil)
        parameters = _parameter_ids(bn_function)
        declarations, references, reference_nodes = _variable_nodes(bn_function, hlil, actual_nodes, variables)
        local_keys = {key for key in variables if key not in parameters}
        local_declarations = {key: node for key, node in declarations.items() if key in local_keys}
        local_references = {key: references.get(key, ()) for key in local_keys}
        root_id = int(root.expr_index)
        scope_plan = recover_scope_tree(
            normalized_nodes,
            root_id,
            [Span.from_ir(value) for value in ranges],
            machine,
            local_declarations,
            local_references,
        )
        scope_by_variable = {
            variable_id: plan
            for plan in scope_plan.walk()
            for variable_id in plan.variable_ids
        }
        rendered_by_owner = {line.owner: line for line in rendered if line.owner is not None and line.statement}
        ast = AstIndex(normalized_nodes)
        ir_variables: dict[str, Variable] = {}
        for key, bn_variable in variables.items():
            is_parameter = key in parameters
            scope_ranges = [Span.from_ir(value) for value in ranges] if is_parameter else scope_by_variable.get(key, scope_plan).ranges
            declaration_node = declarations.get(key)
            declaration = _declaration_for_node(declaration_node, source_id, rendered_by_owner, ast)
            evidence = self._variable_evidence(
                bn_function,
                bn_variable,
                machine,
                reference_nodes.get(key, ()),
                actual_nodes,
                ast,
                is_parameter=is_parameter,
            )
            locations = self._variable_locations(bn_function, bn_variable, scope_ranges, evidence)
            ir_id = _variable_ir_id(int(bn_function.start), key)
            ir_variables[key] = Variable(
                id=ir_id,
                name=str(getattr(bn_variable, "name", "")) or f"var_{key}",
                kind="parameter" if is_parameter else "local",
                type_id=self.types.export(getattr(bn_variable, "type", None)),
                locations=locations,
                declaration=declaration,
            )

        parameter_variables = [
            ir_variables[key]
            for key in parameters
            if key in ir_variables
        ]
        scope = _materialize_scope(scope_plan, int(bn_function.start), ir_variables)
        function_type = getattr(bn_function, "type", None)
        return_type = self.types.export(getattr(function_type, "return_value", None))
        symbol = getattr(bn_function, "symbol", None)
        name = str(getattr(bn_function, "name", "")) or function_id
        linkage_name = str(getattr(symbol, "raw_name", "")) or None
        if linkage_name == name:
            linkage_name = None
        declaration_line = rendered[0].number if rendered else 1
        function = Function(
            id=function_id,
            name=name,
            ranges=ranges,
            return_type=return_type,
            parameters=parameter_variables,
            scope=scope,
            variadic=_confidence_bool(getattr(function_type, "has_variable_arguments", False)),
            external=bool(getattr(bn_function, "is_exported", True)),
            linkage_name=linkage_name,
            declaration=Declaration(source_id, declaration_line, 1),
            calling_convention=getattr(getattr(function_type, "calling_convention", None), "name", None),
        )
        labels = self._extract_hlil_labels(
            function_id,
            source_id,
            actual_nodes,
            machine,
            rendered_by_owner,
            ast,
        )
        return _FunctionExport(function, source, lines, labels)

    def _extract_function_without_hlil(
        self,
        bn_function: Any,
        function_id: str,
        source_id: str,
        ranges: list[AddressRange],
    ) -> _FunctionExport:
        name = str(getattr(bn_function, "name", "")) or function_id
        source = Source(
            id=source_id,
            path=f"teemo/{_sanitize_component(name, 'function')}_{int(bn_function.start):x}.c",
            language="c",
            generated=True,
            contents=f"/* HLIL unavailable for {name} at {int(bn_function.start):#x}. */\n",
        )
        function_type = getattr(bn_function, "type", None)
        machine = self._machine_instructions(bn_function)
        parameters = []
        for bn_variable in getattr(bn_function, "parameter_vars", ()):
            key = _variable_key(bn_variable)
            spans = [Span.from_ir(value) for value in ranges]
            evidence = self._variable_evidence(bn_function, bn_variable, machine, (), {}, None, is_parameter=True)
            parameters.append(
                Variable(
                    id=_variable_ir_id(int(bn_function.start), key),
                    name=str(getattr(bn_variable, "name", "")) or f"arg_{key}",
                    kind="parameter",
                    type_id=self.types.export(getattr(bn_variable, "type", None)),
                    locations=self._variable_locations(bn_function, bn_variable, spans, evidence),
                    declaration=Declaration(source_id, 1, 1),
                )
            )
        scope = Scope(f"scope:{int(bn_function.start):x}:root", ranges)
        self._warn("hlil-unavailable", f"HLIL is unavailable for function {name!r}", function=function_id)
        return _FunctionExport(
            Function(
                id=function_id,
                name=name,
                ranges=ranges,
                return_type=self.types.export(getattr(function_type, "return_value", None)),
                parameters=parameters,
                scope=scope,
                variadic=_confidence_bool(getattr(function_type, "has_variable_arguments", False)),
                external=bool(getattr(bn_function, "is_exported", True)),
                declaration=Declaration(source_id, 1, 1),
                calling_convention=getattr(getattr(function_type, "calling_convention", None), "name", None),
            ),
            source,
            [],
            [],
        )

    def _machine_instructions(self, bn_function: Any) -> tuple[MachineInstruction, ...]:
        by_span: dict[Span, set[int]] = {}
        block_by_span: dict[Span, int | None] = {}
        for _tokens, address in getattr(bn_function, "instructions", ()):
            address = int(address)
            length = int(getattr(self.bv, "get_instruction_length")(address, getattr(bn_function, "arch", None)))
            if length <= 0:
                self._warn("invalid-instruction-length", f"instruction at {address:#x} has length {length}")
                continue
            section = self.section_index.at(address)
            if section is None:
                continue
            end = min(address + length, section.end)
            if end <= address:
                continue
            span = Span(section.id, address, end)
            candidates = by_span.setdefault(span, set())
            try:
                llils = bn_function.get_low_level_ils_at(address, getattr(bn_function, "arch", None))
            except Exception:
                llils = ()
            for llil in llils or ():
                try:
                    hlils = llil.hlils
                except Exception:
                    hlils = ()
                for hlil in hlils or ():
                    try:
                        non_ssa = getattr(hlil, "non_ssa_form", None)
                        candidates.add(int((non_ssa or hlil).expr_index))
                    except Exception:
                        continue
            block = getattr(bn_function, "get_basic_block_at", lambda _address: None)(address)
            block_by_span[span] = int(block.start) if block is not None else None
        return tuple(
            MachineInstruction(span, tuple(sorted(nodes)), block_by_span.get(span))
            for span, nodes in sorted(by_span.items(), key=lambda item: item[0])
        )

    def _variable_evidence(
        self,
        bn_function: Any,
        bn_variable: Any,
        machine: Sequence[MachineInstruction],
        reference_nodes: Sequence[int],
        actual_nodes: dict[int, Any],
        ast: AstIndex | None,
        *,
        is_parameter: bool,
    ) -> list[LocationEvidence]:
        source_type = _enum_name(getattr(bn_variable, "source_type", ""))
        if source_type != "RegisterVariableSourceType":
            return []
        variable_width = _variable_width(bn_variable)
        if variable_width > self.architecture.address_size:
            self._warn(
                "unsupported-composite-register-location",
                f"variable {getattr(bn_variable, 'name', '')!r} is {variable_width} bytes wide "
                f"but one {self.architecture.value} register is only "
                f"{self.architecture.address_size} bytes",
            )
            return []
        try:
            register = str(bn_function.arch.get_reg_name(int(bn_variable.storage)))
        except Exception as error:
            self._warn(
                "unknown-register-variable",
                f"cannot resolve register for variable {getattr(bn_variable, 'name', '')!r}: {error}",
            )
            return []
        register_expression = LocationExpression.register_location(register)
        result = []
        reference_set = set(reference_nodes)
        if is_parameter:
            flow = self._parameter_flow_evidence(bn_function, machine)
            result.extend(flow.get(_variable_key(bn_variable), ()))
            if not result and machine:
                # The ABI location is known at the entry instruction even when
                # the data-flow query cannot run (for example incomplete IL).
                first = min(machine, key=lambda instruction: instruction.span.start)
                result.append(LocationEvidence(first.span, register_expression, priority=20))
        else:
            ssa, ssa_variables = self._ssa_variables(bn_function, bn_variable)
            reference_addresses = _variable_reference_addresses(
                bn_function,
                bn_variable,
                ssa_variables,
            )
            for instruction in machine:
                mapped = instruction.span.start in reference_addresses
                if not mapped and ast is not None:
                    mapped = any(
                        ast.is_descendant(reference, candidate) or ast.is_descendant(candidate, reference)
                        for reference in reference_set
                        for candidate in instruction.hlil_nodes
                        if reference in ast.nodes and candidate in ast.nodes
                    )
                if mapped:
                    result.append(LocationEvidence(instruction.span, register_expression, priority=1))

        for reference in reference_set:
            node = actual_nodes.get(reference)
            if node is None:
                continue
            value = _constant_value(getattr(node, "value", None))
            if value is None:
                continue
            expression = LocationExpression(
                kind="stack_value",
                expression=LocationExpression(kind="constant", value=value),
            )
            for instruction in machine:
                if ast is not None and any(
                    ast.is_descendant(reference, candidate) or ast.is_descendant(candidate, reference)
                    for candidate in instruction.hlil_nodes
                    if candidate in ast.nodes
                ):
                    result.append(LocationEvidence(instruction.span, expression, priority=10))
        if is_parameter:
            ssa, ssa_variables = self._ssa_variables(bn_function, bn_variable)
        result.extend(_ssa_constant_evidence(ssa, ssa_variables, machine))
        return result

    def _ssa_variables(self, bn_function: Any, variable: Any) -> tuple[Any | None, tuple[Any, ...]]:
        function_start = int(bn_function.start)
        cached = self._ssa_cache.get(function_start)
        if cached is None:
            ssa, index = _build_ssa_index(bn_function)
            cached = (ssa, index)
            self._ssa_cache[function_start] = cached
        return cached[0], cached[1].get(_variable_key(_underlying_variable(variable)), ())

    def _parameter_flow_evidence(
        self,
        bn_function: Any,
        machine: Sequence[MachineInstruction],
    ) -> dict[str, list[LocationEvidence]]:
        """Find current registers and stack slots that provably hold entry arguments."""

        function_start = int(bn_function.start)
        if function_start in self._parameter_flow_cache:
            return self._parameter_flow_cache[function_start]

        result: dict[str, list[LocationEvidence]] = {}
        arch = getattr(bn_function, "arch", None)
        by_entry_register: dict[str, list[tuple[str, int]]] = {}
        for parameter in getattr(bn_function, "parameter_vars", ()):
            parameter = _underlying_variable(parameter)
            if _enum_name(getattr(parameter, "source_type", "")) != "RegisterVariableSourceType":
                continue
            try:
                register = str(arch.get_reg_name(int(parameter.storage)))
                register = _full_width_register(arch, register)
            except Exception:
                continue
            key = _variable_key(parameter)
            result.setdefault(key, [])
            width = _variable_width(parameter) or self.architecture.address_size
            if width > self.architecture.address_size:
                continue
            by_entry_register.setdefault(register, []).append((key, width))

        if not by_entry_register or arch is None:
            self._parameter_flow_cache[function_start] = result
            return result

        register_plan = _register_flow_plan(
            bn_function,
            machine,
            arch,
            set(by_entry_register),
        )
        if register_plan is None:
            try:
                candidate_registers = tuple(
                    sorted(set(str(value) for value in arch.full_width_regs))
                )
            except Exception:
                candidate_registers = tuple(sorted(by_entry_register))
            writes_by_address = None
        else:
            candidate_registers, writes_by_address = register_plan
        candidate_priorities = {
            register: 50_000 - index
            for index, register in enumerate(candidate_registers)
        }
        parameter_sizes = {
            width
            for parameters in by_entry_register.values()
            for _key, width in parameters
        }
        stack_candidates = _stack_flow_candidates(bn_function, parameter_sizes)
        query_failures = 0
        query_successes = 0
        register_state: dict[str, str] = {}
        previous_instruction: MachineInstruction | None = None
        for instruction in machine:
            address = instruction.span.start
            if (
                writes_by_address is None
                or previous_instruction is None
                or instruction.block is None
                or instruction.block != previous_instruction.block
            ):
                register_state.clear()
                query_registers = candidate_registers
            else:
                query_registers = tuple(
                    register
                    for register in writes_by_address.get(
                        previous_instruction.span.start,
                        (),
                    )
                    if register in candidate_priorities
                )
            for candidate in query_registers:
                try:
                    value = bn_function.get_reg_value_at(address, candidate, arch)
                    query_successes += 1
                except Exception:
                    query_failures += 1
                    register_state.pop(candidate, None)
                    continue
                entry_register = _entry_register_name(value, arch)
                if entry_register is None or int(getattr(value, "offset", 0)) != 0:
                    register_state.pop(candidate, None)
                    continue
                register_state[candidate] = entry_register
            for candidate, entry_register in register_state.items():
                for key, _width in by_entry_register.get(entry_register, ()):
                    result[key].append(
                        LocationEvidence(
                            instruction.span,
                            LocationExpression.register_location(candidate),
                            priority=candidate_priorities[candidate],
                        )
                    )
            for stack_index, (stack_offset, size) in enumerate(stack_candidates):
                try:
                    value = bn_function.get_stack_contents_at(address, stack_offset, size, arch)
                    query_successes += 1
                except Exception:
                    query_failures += 1
                    continue
                entry_register = _entry_register_name(value, arch)
                if entry_register is None or int(getattr(value, "offset", 0)) != 0:
                    continue
                for key, width in by_entry_register.get(entry_register, ()):
                    if width != size:
                        continue
                    result[key].append(
                        LocationEvidence(
                            instruction.span,
                            LocationExpression.cfa_offset(
                                _stack_cfa_offset(self.architecture, stack_offset)
                            ),
                            priority=60_000 - stack_index,
                        )
                    )
            previous_instruction = instruction
        if query_failures and not query_successes:
            self._warn(
                "parameter-flow-unavailable",
                f"Binary Ninja value-flow queries failed for all parameters in {getattr(bn_function, 'name', function_start)!r}",
                function=function_start,
            )
        self._parameter_flow_cache[function_start] = result
        return result

    def _variable_locations(
        self,
        bn_function: Any,
        bn_variable: Any,
        scope_ranges: Sequence[Span],
        evidence: Sequence[LocationEvidence],
    ) -> list[Any]:
        source_type = _enum_name(getattr(bn_variable, "source_type", ""))
        if source_type == "StackVariableSourceType":
            expression = LocationExpression.cfa_offset(
                _stack_cfa_offset(self.architecture, int(getattr(bn_variable, "storage", 0)))
            )
            evidence = [LocationEvidence(span, expression, priority=100) for span in scope_ranges]
        elif source_type == "FlagVariableSourceType":
            self._warn(
                "unsupported-flag-location",
                f"flag variable {getattr(bn_variable, 'name', '')!r} has no portable DWARF location",
            )
            evidence = []
        elif source_type != "RegisterVariableSourceType":
            self._warn(
                "unsupported-variable-location",
                f"variable {getattr(bn_variable, 'name', '')!r} uses unknown source type {source_type!r}",
            )
            evidence = []
        return partition_locations(scope_ranges, evidence)

    def _extract_globals(self) -> list[Variable]:
        result = []
        for address, data_variable in sorted(getattr(self.bv, "data_vars", {}).items()):
            address = int(address)
            section = self.section_index.at(address)
            symbol = getattr(data_variable, "symbol", None)
            name = str(getattr(data_variable, "name", "") or "")
            if section is None or symbol is None or not name:
                continue
            symbol_type = _enum_name(getattr(symbol, "type", ""))
            if symbol_type not in {"DataSymbol", "ImportedDataSymbol"}:
                continue
            if symbol_type == "ImportedDataSymbol":
                continue
            raw_name = str(getattr(symbol, "raw_name", "")) or None
            if raw_name == name:
                raw_name = None
            binding = _enum_name(getattr(symbol, "binding", ""))
            result.append(
                Variable(
                    id=f"global:{address:x}:{_sanitize_component(name, 'data')}",
                    name=name,
                    kind="global",
                    type_id=self.types.export(getattr(data_variable, "type", None)),
                    static_location=LocationExpression(kind="address", address=Address(address, section.id)),
                    linkage_name=raw_name,
                    external=binding in {"GlobalBinding", "WeakBinding"},
                )
            )
        return result

    def _extract_hlil_labels(
        self,
        function_id: str,
        source_id: str,
        actual_nodes: dict[int, Any],
        machine: Sequence[MachineInstruction],
        rendered_by_owner: dict[int, RenderedLine],
        ast: AstIndex,
    ) -> list[Label]:
        result = []
        for node_id, node in actual_nodes.items():
            if _enum_name(getattr(node, "operation", "")) != "HLIL_LABEL":
                continue
            spans = [
                instruction.span
                for instruction in machine
                if any(
                    ast.is_descendant(node_id, candidate) or ast.is_descendant(candidate, node_id)
                    for candidate in instruction.hlil_nodes
                    if candidate in ast.nodes
                )
            ]
            if not spans:
                continue
            target = getattr(node, "target", None)
            name = str(getattr(target, "name", "") or target or f"label_{node_id}")
            span = min(spans, key=lambda value: (value.start, value.end))
            declaration = _declaration_for_node(node_id, source_id, rendered_by_owner, ast)
            result.append(
                Label(
                    id=f"label:{function_id}:{node_id}",
                    name=name,
                    address=Address(span.start, span.section),
                    function_id=function_id,
                    declaration=declaration,
                )
            )
        return result

    def _extract_symbol_labels(
        self,
        functions: Sequence[Function],
        sources: Sequence[Source],
        lines: Sequence[Line],
    ) -> list[Label]:
        source_ids = {source.id for source in sources}
        result = []
        seen: set[tuple[int, str]] = set()
        symbol_mapping = getattr(self.bv, "symbols", {})
        values = symbol_mapping.values() if hasattr(symbol_mapping, "values") else ()
        for symbols in values:
            for symbol in symbols:
                if _enum_name(getattr(symbol, "type", "")) != "LocalLabelSymbol":
                    continue
                address = int(symbol.address)
                name = str(getattr(symbol, "name", ""))
                if not name or (address, name) in seen:
                    continue
                seen.add((address, name))
                ir_address = self.section_index.address(address)
                if ir_address is None:
                    continue
                function = next(
                    (
                        candidate
                        for candidate in functions
                        if any(value.start.value <= address < value.end.value for value in candidate.ranges)
                    ),
                    None,
                )
                declaration = None
                if function is not None:
                    line = next(
                        (
                            candidate
                            for candidate in lines
                            if candidate.range.start.value <= address < candidate.range.end.value
                            and candidate.source_id in source_ids
                        ),
                        None,
                    )
                    if line is not None:
                        declaration = Declaration(line.source_id, line.line, line.column)
                result.append(
                    Label(
                        id=f"label:symbol:{address:x}:{_sanitize_component(name, 'label')}",
                        name=name,
                        address=ir_address,
                        function_id=function.id if function is not None else None,
                        declaration=declaration,
                    )
                )
        return result

    def _warn(self, code: str, message: str, **context: Any) -> None:
        self.diagnostics.append(Diagnostic("warning", code, message, context))


def extract_document(binary_view: Any) -> Document:
    """Convenience entry point used by the Binary Ninja command and tests."""

    return BinaryNinjaExtractor(binary_view).extract()


def _normalize_ast(root: Any) -> tuple[dict[int, Any], list[AstNode]]:
    actual: dict[int, Any] = {}
    pending = [root]
    while pending:
        node = pending.pop()
        node_id = int(node.expr_index)
        if node_id in actual:
            continue
        actual[node_id] = node
        pending.extend(reversed(tuple(getattr(node, "instruction_operands", ()))))
    normalized = []
    for node_id, node in actual.items():
        parent = getattr(node, "parent", None)
        parent_id = int(parent.expr_index) if parent is not None and int(parent.expr_index) in actual else None
        operation = _enum_name(getattr(node, "operation", ""))
        normalized.append(AstNode(node_id, parent_id, operation, operation in _SCOPE_OPERATIONS))
    return actual, normalized


def _render_lines(root: Any) -> list[RenderedLine]:
    result = []
    for number, line in enumerate(getattr(root, "lines", ()), start=1):
        text = "".join(str(getattr(token, "text", token)) for token in getattr(line, "tokens", ()))
        owner = getattr(line, "il_instruction", None)
        if owner is not None:
            try:
                owner = getattr(owner, "non_ssa_form", None) or owner
                owner_id = int(owner.expr_index)
                operation = _enum_name(getattr(owner, "operation", ""))
            except Exception:
                owner_id = None
                operation = ""
        else:
            owner_id = None
            operation = ""
        stripped = text.strip()
        statement = bool(
            owner_id is not None
            and operation != "HLIL_BLOCK"
            and stripped not in _FORMATTING_LINES
            and not stripped.startswith("/*")
        )
        result.append(RenderedLine(number, text, owner_id, statement))
    if not result:
        result.append(RenderedLine(1, "/* empty HLIL */", int(root.expr_index), False))
    return result


def _collect_variables(bn_function: Any, hlil: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    groups = (
        getattr(bn_function, "parameter_vars", ()),
        getattr(hlil, "vars", ()),
        getattr(hlil, "aliased_vars", ()),
        getattr(bn_function, "vars", ()),
    )
    for group in groups:
        for variable in group or ():
            variable = _underlying_variable(variable)
            result.setdefault(_variable_key(variable), variable)
    return result


def _parameter_ids(bn_function: Any) -> list[str]:
    return [_variable_key(_underlying_variable(value)) for value in getattr(bn_function, "parameter_vars", ())]


def _variable_nodes(
    bn_function: Any,
    hlil: Any,
    actual_nodes: dict[int, Any],
    variables: dict[str, Any],
) -> tuple[dict[str, int], dict[str, tuple[int, ...]], dict[str, tuple[int, ...]]]:
    declarations: dict[str, int] = {}
    references: dict[str, set[int]] = {key: set() for key in variables}
    reference_nodes: dict[str, set[int]] = {key: set() for key in variables}
    for node_id, node in actual_nodes.items():
        operation = _enum_name(getattr(node, "operation", ""))
        variable = None
        if operation == "HLIL_VAR_DECLARE":
            variable = getattr(node, "var", None)
        elif operation in {"HLIL_VAR_INIT", "HLIL_VAR_INIT_SSA"}:
            variable = getattr(node, "dest", None)
        if variable is not None:
            key = _variable_key(_underlying_variable(variable))
            declarations.setdefault(key, node_id)
            references.setdefault(key, set()).add(node_id)
        if operation in _VARIABLE_OPERATIONS:
            variable = getattr(node, "var", None)
            if variable is not None:
                key = _variable_key(_underlying_variable(variable))
                references.setdefault(key, set()).add(node_id)
                reference_nodes.setdefault(key, set()).add(node_id)

    for key, variable in variables.items():
        try:
            refs = bn_function.get_hlil_var_refs(variable)
        except Exception:
            refs = ()
        for reference in refs or ():
            expr_id = int(getattr(reference, "expr_id", -1))
            if expr_id in actual_nodes:
                references.setdefault(key, set()).add(expr_id)
                reference_nodes.setdefault(key, set()).add(expr_id)
    return (
        declarations,
        {key: tuple(sorted(value)) for key, value in references.items()},
        {key: tuple(sorted(value)) for key, value in reference_nodes.items()},
    )


def _materialize_scope(plan: ScopePlan, function_start: int, variables: dict[str, Variable]) -> Scope:
    return Scope(
        id=f"scope:{function_start:x}:{plan.node}",
        ranges=[span.to_ir() for span in plan.ranges],
        variables=[variables[key] for key in plan.variable_ids if key in variables and variables[key].kind == "local"],
        children=[_materialize_scope(child, function_start, variables) for child in plan.children],
    )


def _declaration_for_node(
    node_id: int | None,
    source_id: str,
    rendered_by_owner: dict[int, RenderedLine],
    ast: AstIndex,
) -> Declaration | None:
    if node_id is None:
        return None
    owner = ast.nearest_ancestor(node_id, set(rendered_by_owner))
    if owner is None:
        return None
    rendered = rendered_by_owner[owner]
    return Declaration(source_id, rendered.number, 1)


def _architecture(name: str) -> Architecture:
    normalized = name.lower().replace("-", "_")
    if normalized in {"x86_64", "amd64"}:
        return Architecture.X86_64
    if normalized in {"x86", "i386", "i486", "i586", "i686"}:
        return Architecture.X86
    if normalized.startswith("aarch64") or normalized.startswith("arm64"):
        return Architecture.AARCH64
    if normalized.startswith("arm") or normalized.startswith("thumb"):
        return Architecture.ARM
    raise ExtractionError(f"unsupported Binary Ninja architecture {name!r}")


def _endianness(value: Any) -> Endianness:
    name = _enum_name(value).lower()
    if "little" in name:
        return Endianness.LITTLE
    if "big" in name:
        return Endianness.BIG
    raise ExtractionError(f"unsupported Binary Ninja endianness {value!r}")


def _stack_cfa_offset(architecture: Architecture, storage: int) -> int:
    # Binary Ninja stack storage is relative to SP at function entry. x86 CALL
    # places a return address on that stack; link-register ABIs do not.
    if architecture in {Architecture.X86, Architecture.X86_64}:
        return storage - architecture.address_size
    return storage


def _constant_value(value: Any) -> int | None:
    kind = _enum_name(getattr(value, "type", ""))
    if kind not in {"ConstantValue", "ConstantPointerValue"}:
        return None
    try:
        result = int(value.value)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    return result if -(1 << 63) <= result < (1 << 63) else None


def _underlying_variable(variable: Any) -> Any:
    return getattr(variable, "var", variable)


def _variable_reference_addresses(
    bn_function: Any,
    variable: Any,
    ssa_variables: Sequence[Any] = (),
) -> set[int]:
    result: set[int] = set()
    for method_name in ("get_mlil_var_refs", "get_hlil_var_refs"):
        try:
            references = getattr(bn_function, method_name)(variable)
        except Exception:
            continue
        for reference in references or ():
            try:
                result.add(int(reference.address))
            except (AttributeError, TypeError, ValueError, OverflowError):
                continue
    for ssa_variable in ssa_variables:
        sites = []
        try:
            definition = ssa_variable.def_site
            if definition is not None:
                sites.append(definition)
        except Exception:
            pass
        try:
            sites.extend(ssa_variable.use_sites or ())
        except Exception:
            pass
        for site in sites:
            try:
                result.add(int(site.address))
            except (AttributeError, TypeError, ValueError, OverflowError):
                continue
    return result


def _build_ssa_index(bn_function: Any) -> tuple[Any | None, dict[str, tuple[Any, ...]]]:
    try:
        mlil = getattr(bn_function, "mlil", None) or getattr(bn_function, "medium_level_il", None)
        ssa = mlil.ssa_form
        instructions = ssa.instructions
    except Exception:
        return None, {}
    result: dict[str, dict[int, Any]] = {}
    try:
        for instruction in instructions:
            candidates = tuple(getattr(instruction, "vars_read", ())) + tuple(
                getattr(instruction, "vars_written", ())
            )
            for candidate in candidates:
                underlying = _underlying_variable(candidate)
                key = _variable_key(underlying)
                try:
                    version = int(candidate.version)
                except (AttributeError, TypeError, ValueError, OverflowError):
                    continue
                result.setdefault(key, {}).setdefault(version, candidate)
    except Exception:
        return None, {}
    return ssa, {
        key: tuple(versions[version] for version in sorted(versions))
        for key, versions in result.items()
    }


def _ssa_constant_evidence(
    ssa: Any | None,
    versions: Sequence[Any],
    machine: Sequence[MachineInstruction],
) -> list[LocationEvidence]:
    if ssa is None or not versions:
        return []
    machine_by_address = {instruction.span.start: instruction for instruction in machine}
    result = []
    for ssa_variable in versions:
        try:
            value = ssa.get_ssa_var_value(ssa_variable)
        except Exception:
            try:
                value = ssa_variable.def_site.value
            except Exception:
                continue
        constant = _constant_value(value)
        if constant is None:
            continue
        expression = LocationExpression(
            kind="stack_value",
            expression=LocationExpression(kind="constant", value=constant),
        )
        try:
            sites = ssa_variable.use_sites or ()
        except Exception:
            sites = ()
        for site in sites:
            try:
                instruction = machine_by_address.get(int(site.address))
            except (AttributeError, TypeError, ValueError, OverflowError):
                instruction = None
            if instruction is not None:
                result.append(LocationEvidence(instruction.span, expression, priority=100_000))
    return result


def _full_width_register(arch: Any, register: str) -> str:
    try:
        info = arch.regs[register]
        return str(info.full_width_reg)
    except Exception:
        return str(register)


def _register_flow_plan(
    bn_function: Any,
    machine: Sequence[MachineInstruction],
    arch: Any,
    entry_registers: set[str],
) -> tuple[tuple[str, ...], dict[int, frozenset[str]]] | None:
    """Find register state transition points for parameter-flow queries.

    A register's value cannot change within a straight-line basic block unless
    an instruction writes it. Query every candidate at block entry, then only
    refresh registers written by the preceding instruction. If Binary Ninja
    cannot provide a complete write set, callers fall back to querying every
    architectural register at every instruction.
    """

    get_written = getattr(bn_function, "get_regs_written_by", None)
    if not callable(get_written):
        return None
    try:
        architectural = {
            str(value)
            for value in arch.full_width_regs
        }
    except Exception:
        return None

    candidates = {
        _full_width_register(arch, register)
        for register in entry_registers
    }
    allowed = architectural | candidates
    writes_by_address: dict[int, frozenset[str]] = {}
    try:
        for instruction in machine:
            written = {
                _full_width_register(arch, str(register))
                for register in get_written(instruction.span.start, arch)
            }
            written.intersection_update(allowed)
            writes_by_address[instruction.span.start] = frozenset(written)
            candidates.update(written)
    except Exception:
        return None
    return tuple(sorted(candidates)), writes_by_address


def _entry_register_name(value: Any, arch: Any) -> str | None:
    if _enum_name(getattr(value, "type", "")) != "EntryValue":
        return None
    register = getattr(value, "reg", None)
    if register is None:
        try:
            register = arch.get_reg_name(int(value.value))
        except Exception:
            return None
    return _full_width_register(arch, str(register))


def _stack_flow_candidates(
    bn_function: Any,
    parameter_sizes: set[int],
) -> tuple[tuple[int, int], ...]:
    offsets = set()
    for variable in getattr(bn_function, "stack_layout", ()):
        variable = _underlying_variable(variable)
        if _enum_name(getattr(variable, "source_type", "")) != "StackVariableSourceType":
            continue
        try:
            offsets.add(int(variable.storage))
        except (AttributeError, TypeError, ValueError, OverflowError):
            continue
    return tuple(sorted((offset, size) for offset in offsets for size in parameter_sizes))


def _variable_width(variable: Any) -> int:
    try:
        width = int(getattr(getattr(variable, "type", None), "width", 0))
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, width)


def _variable_key(variable: Any) -> str:
    try:
        return str(int(variable.identifier))
    except Exception:
        return f"{_enum_name(getattr(variable, 'source_type', 'unknown'))}:{int(getattr(variable, 'index', 0))}:{int(getattr(variable, 'storage', 0))}"


def _variable_ir_id(function_start: int, variable_key: str) -> str:
    return f"variable:{function_start:x}:{_sanitize_component(variable_key, 'variable')}"


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value))


def _confidence_bool(value: Any) -> bool:
    return bool(getattr(value, "value", value))


def _sanitize_component(value: str, fallback: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return (result or fallback)[:120]


def _original_filename(binary_view: Any) -> str:
    file_metadata = getattr(binary_view, "file", None)
    return str(
        getattr(file_metadata, "original_filename", "")
        or getattr(file_metadata, "filename", "")
        or getattr(binary_view, "name", "binary")
    )


def _core_version() -> str:
    try:
        import binaryninja  # type: ignore

        return str(binaryninja.core_version())
    except Exception:
        return "unknown Binary Ninja"


def _elf_build_id(binary_view: Any, endianness: Endianness) -> str | None:
    """Recover the GNU build ID without trusting one Binary Ninja section name.

    Binary Ninja versions and loaders do not consistently expose
    ``.note.gnu.build-id`` as a named section. Prefer bounded note-section
    reads from the analyzed view, then parse ``PT_NOTE`` records from the
    original ELF, and finally use mapped ELF headers when no readable original
    file exists. Every path accepts only a complete GNU ``NT_GNU_BUILD_ID``
    note and places hard caps on table and note reads.
    """

    order = "<" if endianness == Endianness.LITTLE else ">"
    result = _build_id_from_view_note_sections(binary_view, order)
    if result is not None:
        return result

    result = _build_id_from_elf_file(Path(_original_filename(binary_view)), order)
    if result is not None:
        return result
    return _build_id_from_mapped_elf(binary_view, order)


def _gnu_build_id_from_notes(notes: bytes, order: str) -> str | None:
    """Return one complete GNU build ID from a bounded ELF note stream."""

    if order not in {"<", ">"} or len(notes) > _MAX_ELF_NOTE_BYTES:
        return None
    offset = 0
    while offset < len(notes):
        remaining = len(notes) - offset
        if remaining < 12:
            return None
        try:
            name_size, description_size, note_type = struct.unpack_from(order + "III", notes, offset)
        except struct.error:
            return None
        offset += 12
        name_end = offset + name_size
        description_offset = _align_up(name_end, 4)
        description_end = description_offset + description_size
        next_offset = _align_up(description_end, 4)
        if (
            name_end > len(notes)
            or description_offset > len(notes)
            or description_end > len(notes)
            or next_offset > len(notes)
        ):
            return None
        name = notes[offset:name_end].rstrip(b"\0")
        if note_type == _NT_GNU_BUILD_ID and name == b"GNU" and description_size:
            return notes[description_offset:description_end].hex()
        if next_offset <= offset:
            return None
        offset = next_offset
    return None


def _build_id_from_view_note_sections(binary_view: Any, order: str) -> str | None:
    try:
        sections = dict(getattr(binary_view, "sections", {}) or {})
    except (TypeError, ValueError):
        return None
    names = sorted(
        (str(name) for name in sections if str(name).lower().startswith(".note")),
        key=lambda name: (name != ".note.gnu.build-id", name),
    )
    consumed = 0
    for name in names:
        section = sections.get(name)
        try:
            start = int(section.start)
            size = int(section.end) - start
        except (AttributeError, TypeError, ValueError, OverflowError):
            continue
        if size <= 0 or size > _MAX_ELF_NOTE_BYTES or consumed + size > _MAX_ELF_NOTE_TOTAL:
            continue
        consumed += size
        data = _read_view_exact(binary_view, start, size)
        if data is None:
            continue
        result = _gnu_build_id_from_notes(data, order)
        if result is not None:
            return result
    return None


def _build_id_from_elf_file(path: Path, expected_order: str) -> str | None:
    try:
        with path.open("rb") as stream:
            file_size = os.fstat(stream.fileno()).st_size

            def read_at(offset: int, size: int) -> bytes | None:
                if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
                    return None
                stream.seek(offset)
                data = stream.read(size)
                return data if len(data) == size else None

            entries = _elf_program_headers(read_at, 0, expected_order)
            if entries is None:
                return None
            consumed = 0
            for kind, offset, _virtual_address, size in entries:
                if kind != _PT_NOTE or not size:
                    continue
                if size > _MAX_ELF_NOTE_BYTES or consumed + size > _MAX_ELF_NOTE_TOTAL:
                    return None
                consumed += size
                notes = read_at(offset, size)
                if notes is None:
                    return None
                result = _gnu_build_id_from_notes(notes, expected_order)
                if result is not None:
                    return result
    except (OSError, ValueError, OverflowError):
        return None
    return None


def _build_id_from_mapped_elf(binary_view: Any, expected_order: str) -> str | None:
    bases: list[int] = []

    def add_base(value: Any) -> None:
        try:
            address = int(value)
        except (TypeError, ValueError, OverflowError):
            return
        if address >= 0 and address not in bases:
            bases.append(address)

    add_base(getattr(binary_view, "original_image_base", None))
    for segment in tuple(getattr(binary_view, "segments", ()) or ()):
        if getattr(segment, "data_offset", None) == 0:
            add_base(getattr(segment, "start", None))
    section_starts = []
    for section in getattr(binary_view, "sections", {}).values():
        try:
            section_starts.append(int(section.start))
        except (AttributeError, TypeError, ValueError, OverflowError):
            pass
    if section_starts:
        add_base(min(section_starts) & ~0xFFF)
    add_base(getattr(binary_view, "start", None))

    for base in bases:
        entries = _elf_program_headers(
            lambda offset, size, base=base: _read_view_exact(binary_view, base + offset, size),
            0,
            expected_order,
        )
        if entries is None:
            continue
        load_zero = next(
            (
                (virtual_address, offset)
                for kind, offset, virtual_address, size in entries
                if kind == _PT_LOAD and offset == 0 and size
            ),
            None,
        )
        delta = base - load_zero[0] if load_zero is not None else 0
        consumed = 0
        for kind, file_offset, virtual_address, size in entries:
            if kind != _PT_NOTE or not size:
                continue
            if size > _MAX_ELF_NOTE_BYTES or consumed + size > _MAX_ELF_NOTE_TOTAL:
                break
            consumed += size
            candidates: list[int] = []
            mapper = getattr(binary_view, "get_address_for_data_offset", None)
            if callable(mapper):
                try:
                    mapped = mapper(file_offset)
                except Exception:  # noqa: BLE001 - Binary Ninja API exceptions are not stable.
                    mapped = None
                if mapped is not None:
                    try:
                        candidates.append(int(mapped))
                    except (TypeError, ValueError, OverflowError):
                        pass
            candidates.extend((virtual_address + delta, base + file_offset))
            for address in dict.fromkeys(candidates):
                notes = _read_view_exact(binary_view, address, size)
                if notes is None:
                    continue
                result = _gnu_build_id_from_notes(notes, expected_order)
                if result is not None:
                    return result
    return None


def _elf_program_headers(
    read_at: Any,
    header_offset: int,
    expected_order: str,
) -> tuple[tuple[int, int, int, int], ...] | None:
    ident = read_at(header_offset, 16)
    if ident is None or ident[:4] != b"\x7fELF" or ident[6] != 1:
        return None
    elf_class = ident[4]
    data_encoding = ident[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2}:
        return None
    order = "<" if data_encoding == 1 else ">"
    if order != expected_order:
        return None
    header_format = order + ("HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH")
    header_size = struct.calcsize(header_format)
    raw_header = read_at(header_offset + 16, header_size)
    if raw_header is None:
        return None
    try:
        header = struct.unpack(header_format, raw_header)
    except struct.error:
        return None
    program_offset = int(header[4])
    elf_header_size = int(header[7])
    entry_size = int(header[8])
    entry_count = int(header[9])
    expected_entry_size = struct.calcsize(order + ("IIIIIIII" if elf_class == 1 else "IIQQQQQQ"))
    if (
        elf_header_size < 16 + header_size
        or program_offset < elf_header_size
        or program_offset > _MAX_ELF_PROGRAM_HEADER_OFFSET
        or not 0 < entry_count < _PN_XNUM
        or entry_count > _MAX_ELF_PROGRAM_HEADERS
        or entry_size < expected_entry_size
        or entry_size > _MAX_ELF_PROGRAM_HEADER_SIZE
    ):
        return None
    table_size = entry_size * entry_count
    if table_size > _MAX_ELF_PROGRAM_HEADER_TABLE:
        return None
    table = read_at(header_offset + program_offset, table_size)
    if table is None:
        return None
    entries = []
    for index in range(entry_count):
        offset = index * entry_size
        try:
            if elf_class == 1:
                kind, file_offset, virtual_address, _physical, file_size, _memory_size, _flags, _alignment = (
                    struct.unpack_from(order + "IIIIIIII", table, offset)
                )
            else:
                kind, _flags, file_offset, virtual_address, _physical, file_size, _memory_size, _alignment = (
                    struct.unpack_from(order + "IIQQQQQQ", table, offset)
                )
        except struct.error:
            return None
        entries.append((int(kind), int(file_offset), int(virtual_address), int(file_size)))
    return tuple(entries)


def _read_view_exact(binary_view: Any, address: int, size: int) -> bytes | None:
    if address < 0 or size < 0 or size > _MAX_ELF_PROGRAM_HEADER_TABLE:
        return None
    try:
        data = bytes(binary_view.read(address, size))
    except Exception:  # noqa: BLE001 - Binary Ninja API exceptions are not stable.
        return None
    return data if len(data) == size else None


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _deduplicate_labels(labels: Iterable[Label]) -> list[Label]:
    by_location: dict[tuple[int, str], Label] = {}
    for label in sorted(labels, key=lambda item: (item.address.value, item.name, item.id)):
        key = (label.address.value, label.name)
        existing = by_location.get(key)
        if existing is None or (existing.declaration is None and label.declaration is not None):
            by_location[key] = label
    return list(by_location.values())
