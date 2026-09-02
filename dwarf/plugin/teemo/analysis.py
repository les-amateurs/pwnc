"""Binary Ninja-independent analysis helpers used by the Teemo extractor.

Binary Ninja's HLIL is an AST while machine code is a collection of possibly
disjoint address ranges.  Keeping the interval and tree logic in this module
makes the difficult decisions deterministic and testable without a licensed
Binary Ninja installation.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import heapq
from typing import Hashable, Iterable, Mapping, Sequence

from .ir import Address, AddressRange, Location, LocationExpression


NodeId = Hashable


@dataclass(frozen=True, slots=True, order=True)
class Span:
    """A non-empty half-open address interval within one input section."""

    section: str | None
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError(f"invalid span [{self.start:#x}, {self.end:#x})")

    def intersects(self, other: Span) -> bool:
        return self.section == other.section and self.start < other.end and other.start < self.end

    def intersection(self, other: Span) -> Span | None:
        if not self.intersects(other):
            return None
        return Span(self.section, max(self.start, other.start), min(self.end, other.end))

    def contains(self, other: Span) -> bool:
        return self.section == other.section and self.start <= other.start and other.end <= self.end

    def to_ir(self) -> AddressRange:
        return AddressRange(Address(self.start, self.section), Address(self.end, self.section))

    @classmethod
    def from_ir(cls, value: AddressRange) -> Span:
        if value.start.section != value.end.section:
            raise ValueError("an analysis span cannot cross sections")
        return cls(value.start.section, value.start.value, value.end.value)


@dataclass(frozen=True, slots=True)
class AstNode:
    """The small portion of a decompiler AST needed for mapping and scopes."""

    id: NodeId
    parent: NodeId | None
    operation: str
    starts_scope: bool = False


@dataclass(frozen=True, slots=True)
class RenderedLine:
    """One generated pseudocode line and the HLIL expression that owns it."""

    number: int
    text: str
    owner: NodeId | None
    statement: bool = True


@dataclass(frozen=True, slots=True)
class MachineInstruction:
    """A decoded machine instruction and its zero or more HLIL mappings."""

    span: Span
    hlil_nodes: tuple[NodeId, ...] = ()
    block: Hashable | None = None


@dataclass(frozen=True, slots=True)
class LineAssignment:
    span: Span
    source_line: int
    owner: NodeId
    statement: bool
    discriminator: int = 0
    ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class LineMappingResult:
    assignments: tuple[LineAssignment, ...]
    unmapped: tuple[MachineInstruction, ...]


class AstIndex:
    """Validated ancestry queries over normalized AST nodes."""

    def __init__(self, nodes: Iterable[AstNode]) -> None:
        self.nodes: dict[NodeId, AstNode] = {}
        self.children: dict[NodeId, list[NodeId]] = defaultdict(list)
        for node in nodes:
            if node.id in self.nodes:
                raise ValueError(f"duplicate AST node id {node.id!r}")
            self.nodes[node.id] = node
        if not self.nodes:
            raise ValueError("AST must contain at least one node")
        for node in self.nodes.values():
            if node.parent is not None:
                if node.parent not in self.nodes:
                    raise ValueError(f"AST node {node.id!r} has missing parent {node.parent!r}")
                self.children[node.parent].append(node.id)
        self._depth: dict[NodeId, int] = {}
        for node_id in self.nodes:
            self._compute_depth(node_id, set())
        for children in self.children.values():
            children.sort(key=_stable_key)
        self._ancestors: dict[NodeId, tuple[NodeId, ...]] = {}
        self._preorder: dict[NodeId, int] = {}
        self._subtree_end: dict[NodeId, int] = {}
        next_index = 0

        def index_subtree(node_id: NodeId) -> None:
            nonlocal next_index
            self._preorder[node_id] = next_index
            next_index += 1
            for child in self.children.get(node_id, ()):
                index_subtree(child)
            self._subtree_end[node_id] = next_index

        for root in sorted(
            (node.id for node in self.nodes.values() if node.parent is None),
            key=_stable_key,
        ):
            index_subtree(root)

    def _compute_depth(self, node_id: NodeId, visiting: set[NodeId]) -> int:
        if node_id in self._depth:
            return self._depth[node_id]
        if node_id in visiting:
            raise ValueError(f"cycle in AST at node {node_id!r}")
        visiting.add(node_id)
        parent = self.nodes[node_id].parent
        depth = 0 if parent is None else self._compute_depth(parent, visiting) + 1
        visiting.remove(node_id)
        self._depth[node_id] = depth
        return depth

    def depth(self, node_id: NodeId) -> int:
        return self._depth[node_id]

    def ancestors(self, node_id: NodeId, *, include_self: bool = True) -> tuple[NodeId, ...]:
        if node_id not in self.nodes:
            return ()
        result = self._ancestors.get(node_id)
        if result is None:
            values = []
            current: NodeId | None = node_id
            while current is not None:
                values.append(current)
                current = self.nodes[current].parent
            result = tuple(values)
            self._ancestors[node_id] = result
        return result if include_self else result[1:]

    def is_descendant(self, node_id: NodeId, ancestor: NodeId) -> bool:
        if node_id not in self.nodes or ancestor not in self.nodes:
            return False
        return (
            self._preorder[ancestor]
            <= self._preorder[node_id]
            < self._subtree_end[ancestor]
        )

    def nearest_ancestor(self, node_id: NodeId, candidates: set[NodeId]) -> NodeId | None:
        return next((ancestor for ancestor in self.ancestors(node_id) if ancestor in candidates), None)

    def lowest_common_ancestor(self, node_ids: Sequence[NodeId]) -> NodeId | None:
        known = [node_id for node_id in node_ids if node_id in self.nodes]
        if not known:
            return None
        other_ancestors = [set(self.ancestors(node_id)) for node_id in known[1:]]
        for candidate in self.ancestors(known[0]):
            if all(candidate in ancestors for ancestors in other_ancestors):
                return candidate
        return None


def map_machine_to_lines(
    nodes: Iterable[AstNode],
    rendered_lines: Iterable[RenderedLine],
    instructions: Iterable[MachineInstruction],
) -> LineMappingResult:
    """Map every machine instruction to the most specific rendered HLIL line.

    LLIL instructions can map to multiple HLIL expressions.  We first search
    for a rendered owner at their common ancestor.  If that owner is merely a
    formatting line (for example the function signature), the deepest mapped
    candidate wins with source order as the stable tie breaker.
    """

    ast = AstIndex(nodes)
    lines = sorted(rendered_lines, key=lambda line: line.number)
    if any(line.number < 1 for line in lines):
        raise ValueError("source line numbers are one-based")
    owner_lines: dict[NodeId, list[RenderedLine]] = defaultdict(list)
    for line in lines:
        if line.owner in ast.nodes:
            owner_lines[line.owner].append(line)

    def preferred_line(owner: NodeId, *, require_statement: bool = False) -> RenderedLine | None:
        choices = owner_lines.get(owner, ())
        if require_statement:
            return next((line for line in choices if line.statement), None)
        return next((line for line in choices if line.statement), choices[0] if choices else None)

    rendered_owners = set(owner_lines)
    raw: list[LineAssignment] = []
    unmapped: list[MachineInstruction] = []
    ordered_instructions = sorted(
        instructions,
        key=lambda instruction: (
            instruction.span.section or "",
            instruction.span.start,
            instruction.span.end,
        ),
    )
    for instruction in ordered_instructions:
        candidates = tuple(dict.fromkeys(node for node in instruction.hlil_nodes if node in ast.nodes))
        mapped: list[tuple[NodeId, RenderedLine]] = []
        for candidate in candidates:
            owner = ast.nearest_ancestor(candidate, rendered_owners)
            if owner is not None and (line := preferred_line(owner)) is not None:
                mapped.append((owner, line))
        if not mapped:
            unmapped.append(instruction)
            continue

        unique_owners = {owner for owner, _ in mapped}
        ambiguous = len(unique_owners) > 1
        selected: tuple[NodeId, RenderedLine] | None = None
        common = ast.lowest_common_ancestor(candidates)
        if common is not None:
            common_owner = ast.nearest_ancestor(common, rendered_owners)
            if common_owner is not None:
                common_line = preferred_line(common_owner, require_statement=True)
                if common_line is not None:
                    selected = (common_owner, common_line)
        if selected is None:
            selected = min(
                mapped,
                key=lambda item: (-ast.depth(item[0]), item[1].number, _stable_key(item[0])),
            )
        owner, line = selected
        raw.append(
            LineAssignment(
                span=instruction.span,
                source_line=line.number,
                owner=owner,
                statement=line.statement,
                ambiguous=ambiguous,
            )
        )

    coalesced = _coalesce_assignments(raw)
    runs_by_line: dict[int, int] = defaultdict(int)
    result = []
    for assignment in coalesced:
        discriminator = runs_by_line[assignment.source_line]
        runs_by_line[assignment.source_line] += 1
        result.append(
            LineAssignment(
                span=assignment.span,
                source_line=assignment.source_line,
                owner=assignment.owner,
                statement=assignment.statement,
                discriminator=discriminator,
                ambiguous=assignment.ambiguous,
            )
        )
    return LineMappingResult(tuple(result), tuple(unmapped))


def _coalesce_assignments(assignments: Sequence[LineAssignment]) -> list[LineAssignment]:
    result: list[LineAssignment] = []
    for assignment in assignments:
        if result:
            previous = result[-1]
            if (
                previous.span.section == assignment.span.section
                and previous.span.end == assignment.span.start
                and previous.source_line == assignment.source_line
                and previous.owner == assignment.owner
                and previous.statement == assignment.statement
                and previous.ambiguous == assignment.ambiguous
            ):
                result[-1] = LineAssignment(
                    Span(previous.span.section, previous.span.start, assignment.span.end),
                    previous.source_line,
                    previous.owner,
                    previous.statement,
                    ambiguous=previous.ambiguous,
                )
                continue
        result.append(assignment)
    return result


@dataclass(slots=True)
class ScopePlan:
    node: NodeId
    ranges: list[Span]
    variable_ids: list[str] = field(default_factory=list)
    children: list[ScopePlan] = field(default_factory=list)

    def walk(self) -> Iterable[ScopePlan]:
        yield self
        for child in self.children:
            yield from child.walk()


def recover_scope_tree(
    nodes: Iterable[AstNode],
    root: NodeId,
    function_ranges: Iterable[Span],
    instructions: Iterable[MachineInstruction],
    declarations: Mapping[str, NodeId],
    references: Mapping[str, Sequence[NodeId]] | None = None,
) -> ScopePlan:
    """Recover lexical blocks and assign declarations to the nearest block.

    Nested AST scopes without machine code are collapsed into their nearest
    materialized ancestor because DWARF lexical blocks require a PC range.
    """

    ast = AstIndex(nodes)
    if root not in ast.nodes:
        raise ValueError(f"missing root AST node {root!r}")
    roots = [node.id for node in ast.nodes.values() if node.parent is None]
    if roots != [root]:
        raise ValueError(f"expected one AST root {root!r}, found {roots!r}")
    function_ranges = coalesce_spans(function_ranges)
    instructions = tuple(instructions)
    scope_nodes = {node.id for node in ast.nodes.values() if node.starts_scope}
    scope_nodes.add(root)

    ranges_by_scope: dict[NodeId, list[Span]] = {
        scope: ([] if scope != root else list(function_ranges))
        for scope in scope_nodes
    }
    nested_scopes = scope_nodes - {root}
    for instruction in instructions:
        candidate_scopes = tuple(
            dict.fromkeys(
                scope
                for candidate in instruction.hlil_nodes
                if candidate in ast.nodes
                if (scope := ast.nearest_ancestor(candidate, scope_nodes)) is not None
            )
        )
        if not candidate_scopes:
            continue
        # One machine instruction can map to multiple HLIL expressions.  When
        # those expressions live in different sibling blocks, assigning the
        # bytes to every candidate manufactures overlapping sibling lexical
        # scopes, which is invalid DWARF.  Attribute the instruction to the
        # candidates' common lexical ancestor instead, then include only that
        # ancestor's containing scope chain.  Parent/child overlap remains
        # intentional; sibling overlap cannot be introduced by ambiguous IL.
        common = ast.lowest_common_ancestor(candidate_scopes)
        owner = ast.nearest_ancestor(common, scope_nodes) if common is not None else root
        containing_scopes = {
            ancestor
            for ancestor in ast.ancestors(owner or root)
            if ancestor in nested_scopes
        }
        if not containing_scopes:
            continue
        clipped_spans = [
            clipped
            for function_range in function_ranges
            if (clipped := instruction.span.intersection(function_range)) is not None
        ]
        for scope_node in containing_scopes:
            ranges_by_scope[scope_node].extend(clipped_spans)
    for scope_node in nested_scopes:
        ranges_by_scope[scope_node] = coalesce_spans(ranges_by_scope[scope_node])

    materialized = {scope for scope, ranges in ranges_by_scope.items() if ranges}
    parent_scope: dict[NodeId, NodeId] = {}
    for scope_node in materialized - {root}:
        parent = ast.nodes[scope_node].parent
        while parent is not None and parent not in materialized:
            parent = ast.nodes[parent].parent
        parent_scope[scope_node] = root if parent is None else parent

    plans = {node: ScopePlan(node, list(ranges_by_scope[node])) for node in materialized}
    for node in sorted(materialized - {root}, key=lambda item: (ast.depth(item), _stable_key(item))):
        plans[parent_scope[node]].children.append(plans[node])

    for plan in plans.values():
        plan.children.sort(key=lambda child: (child.ranges[0], _stable_key(child.node)))

    references = references or {}
    for variable_id in sorted(set(declarations) | set(references)):
        declaration = declarations.get(variable_id)
        if declaration in ast.nodes:
            scope = ast.nearest_ancestor(declaration, materialized)
        else:
            scope = None
        if scope is None:
            ref_nodes = [node for node in references.get(variable_id, ()) if node in ast.nodes]
            common = ast.lowest_common_ancestor(ref_nodes)
            scope = ast.nearest_ancestor(common, materialized) if common is not None else root
        plans[scope or root].variable_ids.append(variable_id)
    return plans[root]


def coalesce_spans(spans: Iterable[Span]) -> list[Span]:
    """Sort, deduplicate, and merge touching or overlapping same-section spans."""

    ordered = sorted(set(spans), key=lambda span: (span.section or "", span.start, span.end))
    result: list[Span] = []
    for span in ordered:
        if result and result[-1].section == span.section and span.start <= result[-1].end:
            previous = result[-1]
            result[-1] = Span(previous.section, previous.start, max(previous.end, span.end))
        else:
            result.append(span)
    return result


@dataclass(frozen=True, slots=True)
class LocationEvidence:
    span: Span
    expression: LocationExpression
    priority: int = 0


def partition_locations(
    scope_ranges: Iterable[Span],
    evidence: Iterable[LocationEvidence],
    *,
    unavailable_reason: str = "no proven storage at this PC",
) -> list[Location]:
    """Partition scope ranges into available and explicit unavailable locations.

    Higher-priority evidence wins.  Equal-priority conflicts are treated as
    unavailable rather than guessing.  Every byte in every scope range appears
    exactly once in the returned location list.
    """

    scope_ranges = coalesce_spans(scope_ranges)
    evidence = tuple(evidence)
    result: list[tuple[Span, LocationExpression]] = []
    unavailable = LocationExpression.unavailable(unavailable_reason)
    for scope in scope_ranges:
        starts: dict[int, list[LocationEvidence]] = defaultdict(list)
        ends: dict[int, list[LocationEvidence]] = defaultdict(list)
        boundaries = {scope.start, scope.end}
        for item in evidence:
            intersection = scope.intersection(item.span)
            if intersection is None:
                continue
            clipped = LocationEvidence(intersection, item.expression, item.priority)
            starts[intersection.start].append(clipped)
            ends[intersection.end].append(clipped)
            boundaries.update((intersection.start, intersection.end))

        active: dict[int, Counter[LocationExpression]] = {}
        priorities: list[int] = []
        ordered = sorted(boundaries)
        for start, end in zip(ordered, ordered[1:]):
            if start == end:
                continue
            for item in ends.get(start, ()):
                expressions = active.get(item.priority)
                if expressions is None:
                    continue
                expressions[item.expression] -= 1
                if expressions[item.expression] <= 0:
                    del expressions[item.expression]
                if not expressions:
                    del active[item.priority]
            for item in starts.get(start, ()):
                expressions = active.get(item.priority)
                if expressions is None:
                    expressions = Counter()
                    active[item.priority] = expressions
                    heapq.heappush(priorities, -item.priority)
                expressions[item.expression] += 1
            while priorities and -priorities[0] not in active:
                heapq.heappop(priorities)

            expression = unavailable
            if priorities:
                best = active[-priorities[0]]
                if len(best) == 1:
                    expression = next(iter(best))
            span = Span(scope.section, start, end)
            if result and result[-1][0].section == span.section and result[-1][0].end == start and result[-1][1] == expression:
                previous, _ = result[-1]
                result[-1] = (Span(span.section, previous.start, end), expression)
            else:
                result.append((span, expression))
    return [Location(span.to_ir(), expression) for span, expression in result]


def _stable_key(value: Hashable) -> tuple[str, str]:
    return type(value).__name__, repr(value)
