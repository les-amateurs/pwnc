from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.discovery import (
    AddressSpan,
    RecoveryLimits,
    build_import_target_index,
    build_unclaimed_code_ranges,
    collect_candidate_seeds,
    prepare_view_for_export,
)


def _enum(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


class FakeNode:
    def __init__(self, operation: str, constant: int = 0, offset: int = 0) -> None:
        self.operation = _enum(operation)
        self.constant = constant
        self.offset = offset


class FakeIl:
    def __init__(self, constants: tuple[int, ...] = ()) -> None:
        self.nodes = tuple(FakeNode("LLIL_CONST_PTR", value) for value in constants)

    def traverse(self, callback):
        for node in self.nodes:
            value = callback(node)
            if value is not None:
                yield value


class FakeArch:
    max_instr_length = 4
    instr_alignment = 1
    address_size = 8

    def __init__(self, instructions: dict[int, dict[str, object]]) -> None:
        self.instructions = instructions

    def get_associated_arch_by_address(self, address: int):
        return self, address

    def get_instruction_info(self, _data: bytes, address: int):
        record = self.instructions.get(address)
        if record is None:
            return None
        branches = [
            SimpleNamespace(type=_enum(kind), target=target, arch=None) for kind, target in record.get("branches", ())
        ]
        return SimpleNamespace(length=record.get("length", 1), branches=branches)

    def get_instruction_text(self, _data: bytes, address: int):
        record = self.instructions[address]
        token = SimpleNamespace(type=_enum("InstructionToken"), text=record.get("mnemonic", "mov"))
        return [token], record.get("length", 1)

    def get_instruction_low_level_il_instruction(self, _view, address: int):
        return FakeIl(tuple(self.instructions[address].get("constants", ())))


class FakeSection:
    def __init__(self, name: str, start: int, end: int, semantics: str) -> None:
        self.name = name
        self.start = start
        self.end = end
        self.semantics = _enum(semantics)


class FakeFunction:
    def __init__(
        self,
        start: int,
        end: int,
        *,
        auto: bool = True,
        platform: str = "linux-test",
        valid: bool = True,
    ) -> None:
        self.start = start
        self.auto = auto
        self.platform = SimpleNamespace(name=platform)
        self.address_ranges = [SimpleNamespace(start=start, end=end)]
        self.analysis_skipped = not valid
        self.too_large = False
        self.basic_blocks = [SimpleNamespace(start=start, end=end)] if valid else []
        self.llil = [object()] if valid else []


class FakeView:
    view_type = "ELF"
    address_size = 8
    platform = SimpleNamespace(name="linux-test")

    def __init__(self, *, invalid_starts: set[int] | None = None) -> None:
        self.sections = {
            ".text": FakeSection(".text", 0x1000, 0x1020, "ReadOnlyCodeSectionSemantics"),
            ".plt": FakeSection(".plt", 0x2000, 0x2010, "ReadOnlyCodeSectionSemantics"),
            ".got.plt": FakeSection(".got.plt", 0x3000, 0x3020, "ReadWriteDataSectionSemantics"),
        }
        self.instructions = {
            0x1004: {"mnemonic": "nop"},
            0x1005: {"mnemonic": "push"},
            0x1006: {"mnemonic": "call", "branches": (("CallDestination", 0x2008),)},
            0x1007: {"mnemonic": "ret", "branches": (("FunctionReturn", 0),)},
            0x1008: {"mnemonic": "nop"},
            0x1009: {"mnemonic": "mov", "constants": (0x3010,)},
            0x100A: {"mnemonic": "ret", "branches": (("FunctionReturn", 0),)},
            0x100B: {"mnemonic": "xor"},
            0x100C: {"mnemonic": "ret", "branches": (("FunctionReturn", 0),)},
            0x100D: {"mnemonic": "jmp", "branches": (("UnconditionalBranch", 0x2008),)},
        }
        self.arch = FakeArch(self.instructions)
        self.functions = [FakeFunction(0x1000, 0x1004)]
        self.data_vars = {}
        self.symbols = [
            SimpleNamespace(address=0x3010, type=_enum("ImportAddressSymbol"), raw_name="import_slot"),
            SimpleNamespace(address=0x2008, type=_enum("ImportedFunctionSymbol"), raw_name="puts@plt"),
        ]
        self.invalid_starts = invalid_starts or set()
        self.pending: list[FakeFunction] = []
        self.added: list[tuple[int, bool]] = []
        self.removed: list[tuple[int, bool]] = []
        self.analysis_updates = 0

    def read(self, _address: int, length: int) -> bytes:
        return b"\x90" * length

    def is_offset_executable(self, address: int) -> bool:
        return 0x1000 <= address < 0x2010

    def is_offset_code_semantics(self, address: int) -> bool:
        return 0x1000 <= address < 0x2010

    def is_offset_writable(self, _address: int) -> bool:
        return False

    def get_symbols(self):
        return self.symbols

    def get_function_at(self, address: int):
        return next((function for function in self.functions if function.start == address), None)

    def add_function(self, address: int, *, auto_discovered: bool):
        self.added.append((address, auto_discovered))
        ends = {0x1005: 0x1008, 0x1009: 0x100B, 0x100D: 0x100E}
        end = ends[address]
        if address in self.invalid_starts:
            end = 0x1021
        function = FakeFunction(address, end)
        self.pending.append(function)
        return function

    def update_analysis_and_wait(self) -> None:
        self.analysis_updates += 1
        self.functions.extend(self.pending)
        self.pending.clear()

    def remove_function(self, function: FakeFunction, *, update_refs: bool) -> None:
        self.removed.append((function.start, update_refs))
        self.functions.remove(function)


class DiscoveryTests(unittest.TestCase):
    def test_import_index_includes_sections_and_import_symbols(self) -> None:
        index = build_import_target_index(FakeView())
        self.assertTrue(index.is_got(0x3001))
        self.assertTrue(index.is_got(0x3010))
        self.assertTrue(index.is_import_target(0x2008))
        self.assertFalse(index.is_import_target(0x1000))

    def test_unclaimed_ranges_subtract_existing_functions(self) -> None:
        gaps = build_unclaimed_code_ranges(FakeView())
        self.assertEqual(gaps, (AddressSpan(0x1004, 0x1020),))

    def test_unclaimed_ranges_preserve_adjacent_section_boundaries(self) -> None:
        view = FakeView()
        view.sections[".orphan"] = FakeSection(
            ".orphan",
            0x1020,
            0x1030,
            "ReadOnlyCodeSectionSemantics",
        )
        self.assertEqual(
            build_unclaimed_code_ranges(view),
            (AddressSpan(0x1004, 0x1020), AddressSpan(0x1020, 0x1030)),
        )

    def test_candidate_collection_accepts_plt_got_and_tail_call_islands(self) -> None:
        view = FakeView()
        imports = build_import_target_index(view)
        candidates, scanned, truncated = collect_candidate_seeds(
            view,
            build_unclaimed_code_ranges(view),
            imports,
        )
        self.assertEqual([candidate.start for candidate in candidates], [0x1005, 0x1009, 0x100D])
        self.assertEqual(
            [[evidence.kind for evidence in candidate.evidence] for candidate in candidates],
            [["plt-call"], ["got-reference"], ["plt-tail-call"]],
        )
        self.assertEqual(scanned, 0x1C)
        self.assertFalse(truncated)

    def test_prepare_batches_auto_functions_and_is_idempotent(self) -> None:
        view = FakeView()
        report = prepare_view_for_export(view, initially_settled=False)
        self.assertEqual(report.added, (0x1005, 0x1009, 0x100D))
        self.assertEqual(view.added, [(0x1005, False), (0x1009, False), (0x100D, False)])
        self.assertEqual(view.analysis_updates, 2)

        second = prepare_view_for_export(view, initially_settled=True)
        self.assertEqual(second.added, ())
        self.assertEqual(view.analysis_updates, 2)

    def test_invalid_candidate_is_removed_with_reference_update(self) -> None:
        view = FakeView(invalid_starts={0x1009})
        report = prepare_view_for_export(view, initially_settled=True)
        self.assertEqual(report.added, (0x1005, 0x100D))
        self.assertEqual(report.rejected, (0x1009,))
        self.assertEqual(view.removed, [(0x1009, True)])
        self.assertEqual(view.analysis_updates, 2)

    def test_scan_limit_fails_closed_and_reports_truncation(self) -> None:
        view = FakeView()
        candidates, scanned, truncated = collect_candidate_seeds(
            view,
            build_unclaimed_code_ranges(view),
            build_import_target_index(view),
            limits=RecoveryLimits(max_scan_bytes=2, max_candidate_bytes=64, max_candidates=8),
        )
        self.assertEqual(candidates, ())
        self.assertEqual(scanned, 2)
        self.assertTrue(truncated)

    def test_overlong_island_does_not_restart_from_its_interior(self) -> None:
        view = FakeView()
        view.instructions = {
            0x1004: {"mnemonic": "mov", "constants": (0x3010,)},
            0x1005: {"mnemonic": "xor"},
            0x1006: {
                "mnemonic": "call",
                "branches": (("CallDestination", 0x2008),),
            },
            0x1007: {"mnemonic": "ret", "branches": (("FunctionReturn", 0),)},
        }
        view.arch = FakeArch(view.instructions)
        candidates, _scanned, _truncated = collect_candidate_seeds(
            view,
            (AddressSpan(0x1004, 0x1008),),
            build_import_target_index(view),
            limits=RecoveryLimits(
                max_scan_bytes=64,
                max_candidate_bytes=2,
                max_candidates=8,
            ),
        )
        self.assertEqual(candidates, ())

    def test_validation_redecodes_import_evidence_after_analysis(self) -> None:
        class MutatingView(FakeView):
            def update_analysis_and_wait(self) -> None:
                super().update_analysis_and_wait()
                self.instructions[0x1006] = {
                    "mnemonic": "call",
                    "branches": (("CallDestination", 0x1010),),
                }

        view = MutatingView()
        report = prepare_view_for_export(view, initially_settled=True)
        self.assertNotIn(0x1005, report.added)
        self.assertIn(0x1005, report.rejected)
        self.assertIn(
            (0x1005, "the analyzed CFG does not contain current import evidence"),
            report.rejection_reasons,
        )


if __name__ == "__main__":
    unittest.main()
