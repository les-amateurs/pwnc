from __future__ import annotations

import importlib
import sys
import unittest
from enum import IntFlag
from pathlib import Path
from types import ModuleType

TESTS_DIR = Path(__file__).parent
PLUGIN_DIR = TESTS_DIR.parent / "plugin"
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(PLUGIN_DIR))

from teemo.discovery import (
    AddressSpan,
    build_import_target_index,
    collect_candidate_seeds,
    prepare_view_for_export,
)
from test_discovery import FakeArch, FakeFunction, FakeNode, FakeView


class _PlainConstantIl:
    def __init__(self, constants: tuple[int, ...]) -> None:
        self.nodes = tuple(FakeNode("LLIL_CONST", value) for value in constants)

    def traverse(self, callback):
        for node in self.nodes:
            value = callback(node)
            if value is not None:
                yield value


class _PlainConstantArch(FakeArch):
    def get_instruction_low_level_il_instruction(self, _view, address: int):
        constants = tuple(self.instructions[address].get("constants", ()))
        return _PlainConstantIl(constants)


class _FixedWidthArch(FakeArch):
    max_instr_length = 4
    instr_alignment = 4


class CandidateEdgeCaseTests(unittest.TestCase):
    def test_plain_integer_equal_to_got_address_is_not_import_evidence(self) -> None:
        view = FakeView()
        view.instructions = {
            0x1004: {"mnemonic": "mov", "constants": (0x3010,)},
            0x1005: {"mnemonic": "ret", "branches": (("FunctionReturn", 0),)},
        }
        view.arch = _PlainConstantArch(view.instructions)

        candidates, _scanned, _truncated = collect_candidate_seeds(
            view,
            (AddressSpan(0x1004, 0x1006),),
            build_import_target_index(view),
        )

        self.assertEqual(candidates, ())

    def test_candidate_never_spans_non_import_unconditional_branch(self) -> None:
        view = FakeView()
        view.instructions = {
            0x1004: {
                "mnemonic": "jmp",
                "branches": (("UnconditionalBranch", 0x1010),),
            },
            0x1005: {
                "mnemonic": "call",
                "branches": (("CallDestination", 0x2008),),
            },
            0x1006: {"mnemonic": "ret", "branches": (("FunctionReturn", 0),)},
        }
        view.arch = FakeArch(view.instructions)

        candidates, _scanned, _truncated = collect_candidate_seeds(
            view,
            (AddressSpan(0x1004, 0x1007),),
            build_import_target_index(view),
        )

        self.assertNotIn(0x1004, [candidate.start for candidate in candidates])

    def test_invalid_fixed_width_address_advances_to_next_alignment_boundary(self) -> None:
        view = FakeView()
        view.instructions = {
            0x1004: {
                "length": 4,
                "mnemonic": "bl",
                "branches": (("CallDestination", 0x2008),),
            },
            0x1008: {
                "length": 4,
                "mnemonic": "ret",
                "branches": (("FunctionReturn", 0),),
            },
        }
        view.arch = _FixedWidthArch(view.instructions)

        candidates, _scanned, _truncated = collect_candidate_seeds(
            view,
            (AddressSpan(0x1002, 0x100C),),
            build_import_target_index(view),
        )

        self.assertEqual([candidate.start for candidate in candidates], [0x1004])


class RollbackEdgeCaseTests(unittest.TestCase):
    def test_exception_rollback_preserves_concurrent_user_function(self) -> None:
        class ConcurrentMutationView(FakeView):
            def __init__(self) -> None:
                super().__init__()
                self.concurrent_user_function = FakeFunction(
                    0x4000,
                    0x4004,
                    auto=False,
                )

            def update_analysis_and_wait(self) -> None:
                self.analysis_updates += 1
                if self.analysis_updates == 1:
                    self.functions.extend(self.pending)
                    self.pending.clear()
                    self.functions.append(self.concurrent_user_function)
                    raise RuntimeError("analysis failed")

        view = ConcurrentMutationView()

        with self.assertRaisesRegex(RuntimeError, "analysis failed"):
            prepare_view_for_export(view, initially_settled=True)

        self.assertIn(view.concurrent_user_function, view.functions)
        self.assertNotIn(
            view.concurrent_user_function.start,
            [address for address, _update_refs in view.removed],
        )

    def test_incomplete_rollback_is_reported(self) -> None:
        class FailedRollbackView(FakeView):
            def update_analysis_and_wait(self) -> None:
                self.analysis_updates += 1
                if self.pending:
                    self.functions.extend(self.pending)
                    self.pending.clear()
                    raise RuntimeError("analysis failed")

            def remove_function(self, function: FakeFunction, *, update_refs: bool) -> None:
                raise RuntimeError("remove failed")

        view = FailedRollbackView()
        with self.assertRaisesRegex(RuntimeError, "rollback was incomplete"):
            prepare_view_for_export(view, initially_settled=True)


class _NotificationType(IntFlag):
    NotificationBarrier = 1 << 0
    BinaryDataUpdates = 1 << 1
    FunctionUpdates = 1 << 2
    DataVariableUpdates = 1 << 3
    DataMetadataUpdated = 1 << 4
    SymbolUpdates = 1 << 5
    TypeUpdates = 1 << 6
    SegmentUpdates = 1 << 7
    SectionUpdates = 1 << 8
    Rebased = 1 << 9


class _BinaryDataNotification:
    def __init__(self, notifications: _NotificationType) -> None:
        self.notifications = notifications


class LiveDiscoveryConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._saved_modules = {
            name: sys.modules.get(name) for name in ("teemo.commands", "binaryninja", "binaryninja.mainthread")
        }
        binaryninja = ModuleType("binaryninja")
        binaryninja.BinaryDataNotification = _BinaryDataNotification
        binaryninja.NotificationType = _NotificationType
        binaryninja.log_info = lambda _message: None
        binaryninja.log_alert = lambda _message: None
        binaryninja.log_error = lambda _message: None
        mainthread = ModuleType("binaryninja.mainthread")
        mainthread.worker_interactive_enqueue = lambda _callback, _name: None
        sys.modules["binaryninja"] = binaryninja
        sys.modules["binaryninja.mainthread"] = mainthread
        sys.modules.pop("teemo.commands", None)
        cls.commands = importlib.import_module("teemo.commands")

    @classmethod
    def tearDownClass(cls) -> None:
        for name, module in cls._saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    def test_function_removal_requests_rediscovery(self) -> None:
        notification = self.commands.LiveExportNotification(object())

        notification.function_removed(object(), object())

        self.assertTrue(notification._discovery_dirty)

    def test_symbol_update_requests_rediscovery(self) -> None:
        notification = self.commands.LiveExportNotification(object())

        notification.symbol_updated(object(), object())

        self.assertTrue(notification._discovery_dirty)


if __name__ == "__main__":
    unittest.main()
