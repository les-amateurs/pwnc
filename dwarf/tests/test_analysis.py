from __future__ import annotations

import random
import unittest
from pathlib import Path
import sys

PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.analysis import (  # noqa: E402
    AstNode,
    LocationEvidence,
    MachineInstruction,
    RenderedLine,
    Span,
    map_machine_to_lines,
    partition_locations,
    recover_scope_tree,
)
from teemo.ir import LocationExpression  # noqa: E402


class LineMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.nodes = [
            AstNode(0, None, "HLIL_BLOCK", starts_scope=True),
            AstNode(1, 0, "HLIL_IF"),
            AstNode(2, 1, "HLIL_CMP_NE"),
            AstNode(3, 1, "HLIL_BLOCK", starts_scope=True),
            AstNode(4, 3, "HLIL_ASSIGN"),
            AstNode(5, 4, "HLIL_ADD"),
            AstNode(6, 0, "HLIL_RET"),
        ]
        self.lines = [
            RenderedLine(1, "int f(int x)", 0, statement=False),
            RenderedLine(2, "{", 0, statement=False),
            RenderedLine(3, "    if (x != 0)", 1),
            RenderedLine(4, "    {", 3, statement=False),
            RenderedLine(5, "        x = x + 1", 4),
            RenderedLine(6, "    }", 3, statement=False),
            RenderedLine(7, "    return x", 6),
            RenderedLine(8, "}", 0, statement=False),
        ]

    def test_maps_through_ancestors_and_coalesces(self) -> None:
        result = map_machine_to_lines(
            self.nodes,
            self.lines,
            [
                MachineInstruction(Span("text", 0x1000, 0x1002), (2,)),
                MachineInstruction(Span("text", 0x1002, 0x1005), (5,)),
                MachineInstruction(Span("text", 0x1005, 0x1007), (4,)),
                MachineInstruction(Span("text", 0x1007, 0x1008), (6,)),
            ],
        )
        self.assertEqual([(item.source_line, item.span.start, item.span.end) for item in result.assignments], [
            (3, 0x1000, 0x1002),
            (5, 0x1002, 0x1007),
            (7, 0x1007, 0x1008),
        ])
        self.assertFalse(result.unmapped)

    def test_multi_expression_mapping_uses_statement_common_ancestor(self) -> None:
        result = map_machine_to_lines(
            self.nodes,
            self.lines,
            [MachineInstruction(Span("text", 0x1000, 0x1004), (2, 3))],
        )
        self.assertEqual(result.assignments[0].source_line, 3)
        self.assertTrue(result.assignments[0].ambiguous)

    def test_disjoint_runs_get_stable_discriminators(self) -> None:
        result = map_machine_to_lines(
            self.nodes,
            self.lines,
            [
                MachineInstruction(Span("text", 0x1000, 0x1002), (4,)),
                MachineInstruction(Span("text", 0x1010, 0x1012), (5,)),
            ],
        )
        self.assertEqual([item.discriminator for item in result.assignments], [0, 1])

    def test_unmapped_machine_code_is_reported(self) -> None:
        result = map_machine_to_lines(
            self.nodes,
            self.lines,
            [MachineInstruction(Span("text", 0x1000, 0x1001), ())],
        )
        self.assertFalse(result.assignments)
        self.assertEqual(len(result.unmapped), 1)


class ScopeRecoveryTests(unittest.TestCase):
    def test_nested_disjoint_scope_and_shadowed_variables(self) -> None:
        nodes = [
            AstNode("root", None, "HLIL_BLOCK", starts_scope=True),
            AstNode("if", "root", "HLIL_IF"),
            AstNode("then", "if", "HLIL_BLOCK", starts_scope=True),
            AstNode("outer-decl", "root", "HLIL_VAR_INIT"),
            AstNode("inner-decl", "then", "HLIL_VAR_INIT"),
            AstNode("inner-use-a", "then", "HLIL_VAR"),
            AstNode("inner-use-b", "then", "HLIL_VAR"),
        ]
        instructions = [
            MachineInstruction(Span("text", 0x1000, 0x1004), ("outer-decl",)),
            MachineInstruction(Span("text", 0x1010, 0x1014), ("inner-decl",)),
            MachineInstruction(Span("text", 0x1014, 0x1018), ("inner-use-a",)),
            MachineInstruction(Span("text", 0x1020, 0x1024), ("inner-use-b",)),
        ]
        scope = recover_scope_tree(
            nodes,
            "root",
            [Span("text", 0x1000, 0x1030)],
            instructions,
            {"outer-value": "outer-decl", "inner-value": "inner-decl"},
        )
        self.assertEqual(scope.variable_ids, ["outer-value"])
        self.assertEqual(len(scope.children), 1)
        child = scope.children[0]
        self.assertEqual(child.variable_ids, ["inner-value"])
        self.assertEqual(child.ranges, [
            Span("text", 0x1010, 0x1018),
            Span("text", 0x1020, 0x1024),
        ])

    def test_empty_scope_collapses_to_materialized_parent(self) -> None:
        nodes = [
            AstNode(0, None, "HLIL_BLOCK", starts_scope=True),
            AstNode(1, 0, "HLIL_BLOCK", starts_scope=True),
            AstNode(2, 1, "HLIL_VAR_DECLARE"),
        ]
        scope = recover_scope_tree(nodes, 0, [Span(None, 1, 4)], [], {"optimized-out": 2})
        self.assertEqual(scope.variable_ids, ["optimized-out"])
        self.assertFalse(scope.children)

    def test_ambiguous_instruction_does_not_overlap_sibling_scopes(self) -> None:
        nodes = [
            AstNode("root", None, "HLIL_BLOCK", starts_scope=True),
            AstNode("if", "root", "HLIL_IF"),
            AstNode("then", "if", "HLIL_BLOCK", starts_scope=True),
            AstNode("then-value", "then", "HLIL_ASSIGN"),
            AstNode("else", "if", "HLIL_BLOCK", starts_scope=True),
            AstNode("else-value", "else", "HLIL_ASSIGN"),
        ]
        scope = recover_scope_tree(
            nodes,
            "root",
            [Span("text", 0x1000, 0x1040)],
            [
                MachineInstruction(Span("text", 0x1010, 0x1014), ("then-value",)),
                MachineInstruction(Span("text", 0x1020, 0x1024), ("else-value",)),
                MachineInstruction(
                    Span("text", 0x1030, 0x1034),
                    ("then-value", "else-value"),
                ),
            ],
            {"then-local": "then-value", "else-local": "else-value"},
        )

        self.assertEqual(len(scope.children), 2)
        children = {child.node: child for child in scope.children}
        self.assertEqual(children["then"].ranges, [Span("text", 0x1010, 0x1014)])
        self.assertEqual(children["else"].ranges, [Span("text", 0x1020, 0x1024)])
        self.assertFalse(children["then"].ranges[0].intersects(children["else"].ranges[0]))


class LocationPartitionTests(unittest.TestCase):
    def test_fills_unavailable_gaps_and_merges_evidence(self) -> None:
        register = LocationExpression.register_location("rdi")
        locations = partition_locations(
            [Span("text", 0x1000, 0x1010)],
            [
                LocationEvidence(Span("text", 0x1000, 0x1004), register),
                LocationEvidence(Span("text", 0x1004, 0x1008), register),
            ],
        )
        self.assertEqual([(item.range.start.value, item.range.end.value) for item in locations], [
            (0x1000, 0x1008),
            (0x1008, 0x1010),
        ])
        self.assertEqual(locations[0].expression, register)
        self.assertEqual(locations[1].expression.kind, "unavailable")

    def test_equal_priority_conflict_is_unavailable(self) -> None:
        locations = partition_locations(
            [Span(None, 1, 5)],
            [
                LocationEvidence(Span(None, 1, 5), LocationExpression.register_location("r0")),
                LocationEvidence(Span(None, 2, 4), LocationExpression.register_location("r1")),
            ],
        )
        self.assertEqual([item.expression.kind for item in locations], ["register", "unavailable", "register"])

    def test_higher_priority_evidence_wins(self) -> None:
        locations = partition_locations(
            [Span(None, 1, 5)],
            [
                LocationEvidence(Span(None, 1, 5), LocationExpression.register_location("r0")),
                LocationEvidence(Span(None, 2, 4), LocationExpression.register_location("r1"), priority=1),
            ],
        )
        self.assertEqual([item.expression.register for item in locations], ["r0", "r1", "r0"])

    def test_sweep_partition_matches_pointwise_priority_semantics(self) -> None:
        rng = random.Random(0x5445454D4F)
        expressions = [
            LocationExpression.register_location(f"r{index}")
            for index in range(5)
        ]
        unavailable = LocationExpression.unavailable("no proven storage at this PC")
        for _trial in range(40):
            evidence = []
            for _item in range(120):
                start = rng.randrange(0, 63)
                end = rng.randrange(start + 1, 65)
                evidence.append(
                    LocationEvidence(
                        Span("text", start, end),
                        rng.choice(expressions),
                        priority=rng.randrange(-2, 5),
                    )
                )

            locations = partition_locations([Span("text", 0, 64)], evidence)
            actual = {}
            for location in locations:
                for address in range(location.range.start.value, location.range.end.value):
                    self.assertNotIn(address, actual)
                    actual[address] = location.expression

            expected = {}
            for address in range(64):
                covering = [
                    item
                    for item in evidence
                    if item.span.start <= address < item.span.end
                ]
                expression = unavailable
                if covering:
                    priority = max(item.priority for item in covering)
                    best = {
                        item.expression
                        for item in covering
                        if item.priority == priority
                    }
                    if len(best) == 1:
                        expression = next(iter(best))
                expected[address] = expression
            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
