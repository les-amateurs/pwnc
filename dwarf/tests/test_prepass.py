from __future__ import annotations

import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))

from teemo import prepass
from teemo.canary_analysis import CanaryAnalysisReport
from teemo.discovery import DiscoveryReport
from teemo.format_analysis import AutoTagSyncResult, FormatAnalysisReport, SignatureBootstrapResult
from teemo.ir import Diagnostic


class MinimalView:
    """Only the baseline wait is part of the prepass's view contract."""

    def __init__(self, events: list[object]) -> None:
        self.events = events
        self.analysis_updates = 0

    def update_analysis_and_wait(self) -> None:
        self.events.append("settle")
        self.analysis_updates += 1

    def __getattr__(self, name: str):
        if "user" in name.lower():
            raise AssertionError(f"prepass queried persistent user state through {name}")
        raise AttributeError(name)


def _canary(*, diagnostics: tuple[str, ...] = ()) -> CanaryAnalysisReport:
    return CanaryAnalysisReport(
        target="linux-x86_64",
        examined_functions=3,
        type_action="already-auto",
        diagnostics=diagnostics,
    )


class PreExportTests(unittest.TestCase):
    def test_runs_all_stages_in_order_without_redundant_settle(self) -> None:
        events: list[object] = []
        view = MinimalView(events)
        discovery = DiscoveryReport(scanned_bytes=10)
        canary = _canary()
        signatures = SignatureBootstrapResult(unchanged_functions=(0x1000,))
        format_analysis = FormatAnalysisReport(())
        tag_sync = AutoTagSyncResult(unchanged=2)
        security_diagnostic = Diagnostic("warning", "security-test", "finding")

        def recover(_view, *, initially_settled):
            events.append(("orphan", initially_settled))
            return discovery

        def analyze_canary(_view):
            events.append("canary")
            return canary

        def analyze_format(_view):
            events.append("format")
            return format_analysis

        def bootstrap(_view):
            events.append("signatures")
            return signatures

        def convert(report):
            self.assertIs(report, format_analysis)
            events.append("diagnostics")
            return (security_diagnostic,)

        def sync(_view, report):
            self.assertIs(report, format_analysis)
            events.append("tags")
            return tag_sync

        with (
            patch.object(prepass, "prepare_view_for_export", side_effect=recover),
            patch.object(prepass, "analyze_stack_canaries", side_effect=analyze_canary),
            patch.object(prepass, "bootstrap_format_function_types", side_effect=bootstrap),
            patch.object(prepass, "analyze_format_strings", side_effect=analyze_format),
            patch.object(prepass, "diagnostics_for_report", side_effect=convert),
            patch.object(prepass, "synchronize_auto_tags", side_effect=sync),
        ):
            report = prepass.run_pre_export(view, run_orphan=True, initially_settled=False)

        self.assertEqual(
            events,
            [("orphan", False), "signatures", "canary", "format", "diagnostics", "tags"],
        )
        self.assertEqual(view.analysis_updates, 0)
        self.assertIs(report.discovery, discovery)
        self.assertIs(report.canary, canary)
        self.assertIs(report.format_signatures, signatures)
        self.assertIs(report.format_analysis, format_analysis)
        self.assertIs(report.format, format_analysis)
        self.assertIs(report.tag_sync, tag_sync)
        self.assertIs(report.tags, tag_sync)
        self.assertEqual(report.diagnostics, (security_diagnostic,))

    def test_skipping_orphans_owns_exactly_one_initial_settle(self) -> None:
        events: list[object] = []
        view = MinimalView(events)
        format_analysis = FormatAnalysisReport(())

        with (
            patch.object(prepass, "prepare_view_for_export") as recover,
            patch.object(
                prepass,
                "analyze_stack_canaries",
                side_effect=lambda _view: events.append("canary") or _canary(),
            ),
            patch.object(
                prepass,
                "analyze_format_strings",
                side_effect=lambda _view: events.append("format") or format_analysis,
            ),
            patch.object(
                prepass,
                "diagnostics_for_report",
                side_effect=lambda _report: events.append("diagnostics") or (),
            ),
            patch.object(
                prepass,
                "synchronize_auto_tags",
                side_effect=lambda _view, _report: events.append("tags") or AutoTagSyncResult(),
            ),
        ):
            report = prepass.run_pre_export(view, run_orphan=False, initially_settled=False)

        recover.assert_not_called()
        self.assertIsNone(report.discovery)
        self.assertEqual(view.analysis_updates, 1)
        self.assertEqual(events, ["settle", "canary", "format", "diagnostics", "tags"])

    def test_already_settled_skipped_orphan_path_does_not_wait(self) -> None:
        events: list[object] = []
        view = MinimalView(events)
        with (
            patch.object(prepass, "analyze_stack_canaries", return_value=_canary()),
            patch.object(prepass, "analyze_format_strings", return_value=FormatAnalysisReport(())),
            patch.object(prepass, "diagnostics_for_report", return_value=()),
            patch.object(prepass, "synchronize_auto_tags", return_value=AutoTagSyncResult()),
        ):
            prepass.run_pre_export(view, run_orphan=False, initially_settled=True)
        self.assertEqual(events, [])
        self.assertEqual(view.analysis_updates, 0)

    def test_optional_stage_failures_are_diagnostics_and_do_not_abort(self) -> None:
        events: list[object] = []
        view = MinimalView(events)
        format_analysis = FormatAnalysisReport(())

        def fail_canary(_view):
            events.append("canary")
            raise RuntimeError("canary unavailable")

        def analyze_format(_view):
            events.append("format")
            return format_analysis

        def fail_diagnostics(_report):
            events.append("diagnostics")
            raise ValueError("diagnostic conversion unavailable")

        def fail_tags(_view, _report):
            events.append("tags")
            raise LookupError("tag API unavailable")

        with (
            patch.object(prepass, "analyze_stack_canaries", side_effect=fail_canary),
            patch.object(prepass, "analyze_format_strings", side_effect=analyze_format),
            patch.object(prepass, "diagnostics_for_report", side_effect=fail_diagnostics),
            patch.object(prepass, "synchronize_auto_tags", side_effect=fail_tags),
        ):
            report = prepass.run_pre_export(view, run_orphan=False, initially_settled=True)

        self.assertEqual(events, ["canary", "format", "diagnostics", "tags"])
        self.assertIsNone(report.canary)
        self.assertIs(report.format_analysis, format_analysis)
        self.assertIsNone(report.tag_sync)
        self.assertEqual(
            tuple(item.code for item in report.diagnostics),
            (
                "prepass-canary-analysis-failed",
                "prepass-format-diagnostics-failed",
                "prepass-format-tag-sync-failed",
            ),
        )

    def test_format_failure_does_not_reconcile_tags_from_an_empty_report(self) -> None:
        events: list[object] = []
        view = MinimalView(events)

        def fail_format(_view):
            events.append("format")
            raise RuntimeError("IL unavailable")

        with (
            patch.object(
                prepass,
                "analyze_stack_canaries",
                side_effect=lambda _view: events.append("canary") or _canary(),
            ),
            patch.object(prepass, "analyze_format_strings", side_effect=fail_format),
            patch.object(prepass, "diagnostics_for_report") as convert,
            patch.object(prepass, "synchronize_auto_tags") as sync,
        ):
            report = prepass.run_pre_export(view, run_orphan=False, initially_settled=True)

        self.assertEqual(events, ["canary", "format"])
        self.assertIsNone(report.format_analysis)
        self.assertIsNone(report.tag_sync)
        self.assertEqual(report.diagnostics[0].code, "prepass-format-analysis-failed")
        convert.assert_not_called()
        sync.assert_not_called()

    def test_report_notes_and_tag_issues_are_promoted_to_diagnostics(self) -> None:
        events: list[object] = []
        view = MinimalView(events)
        format_analysis = FormatAnalysisReport(())
        finding = Diagnostic("warning", "security-format-string-writable", "writable")
        with (
            patch.object(prepass, "analyze_stack_canaries", return_value=_canary(diagnostics=("type conflict",))),
            patch.object(prepass, "analyze_format_strings", return_value=format_analysis),
            patch.object(prepass, "diagnostics_for_report", return_value=(finding,)),
            patch.object(
                prepass,
                "synchronize_auto_tags",
                return_value=AutoTagSyncResult(issues=("tag type unavailable",)),
            ),
        ):
            report = prepass.run_pre_export(view, run_orphan=False, initially_settled=True)

        self.assertEqual(
            tuple(item.code for item in report.diagnostics),
            (
                "prepass-canary-analysis-note",
                "security-format-string-writable",
                "prepass-format-tag-sync-issue",
            ),
        )

    def test_orphan_recovery_and_initial_settle_remain_fail_closed(self) -> None:
        view = MinimalView([])
        with (
            patch.object(prepass, "prepare_view_for_export", side_effect=RuntimeError("rollback failed")),
            patch.object(prepass, "analyze_stack_canaries") as canary,
            patch.object(prepass, "analyze_format_strings") as format_analysis,
            self.assertRaisesRegex(RuntimeError, "rollback failed"),
        ):
            prepass.run_pre_export(view, run_orphan=True, initially_settled=False)
        canary.assert_not_called()
        format_analysis.assert_not_called()

        class BrokenSettleView(MinimalView):
            def update_analysis_and_wait(self) -> None:
                raise RuntimeError("settle failed")

        broken = BrokenSettleView([])
        with (
            patch.object(prepass, "analyze_stack_canaries") as canary,
            self.assertRaisesRegex(RuntimeError, "settle failed"),
        ):
            prepass.run_pre_export(broken, run_orphan=False, initially_settled=False)
        canary.assert_not_called()

    def test_combined_report_is_immutable_and_requires_no_user_state(self) -> None:
        view = MinimalView([])
        with (
            patch.object(prepass, "analyze_stack_canaries", return_value=_canary()),
            patch.object(prepass, "analyze_format_strings", return_value=FormatAnalysisReport(())),
            patch.object(prepass, "diagnostics_for_report", return_value=()),
            patch.object(prepass, "synchronize_auto_tags", return_value=AutoTagSyncResult()),
        ):
            report = prepass.run_pre_export(view, run_orphan=False, initially_settled=True)

        with self.assertRaises(FrozenInstanceError):
            report.discovery = DiscoveryReport()  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
