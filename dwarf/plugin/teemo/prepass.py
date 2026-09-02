"""One ordered, failure-isolated pre-export analysis pass.

Orphan recovery establishes the function-analysis baseline and is deliberately
fail-closed.  Canary and format-string enrichment are optional improvements:
their failures are reported as Teemo diagnostics without preventing export.
This module owns no Binary Ninja user state and performs no persistent user
annotations itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canary_analysis import CanaryAnalysisReport, analyze_stack_canaries
from .discovery import DiscoveryReport, prepare_view_for_export
from .format_analysis import (
    AutoTagSyncResult,
    FormatAnalysisReport,
    SignatureBootstrapResult,
    analyze_format_strings,
    bootstrap_format_function_types,
    diagnostics_for_report,
    synchronize_auto_tags,
)
from .ir import Diagnostic


@dataclass(frozen=True, slots=True)
class PreExportReport:
    """Results from every completed pre-export stage."""

    discovery: DiscoveryReport | None
    canary: CanaryAnalysisReport | None
    format_signatures: SignatureBootstrapResult | None
    format_analysis: FormatAnalysisReport | None
    tag_sync: AutoTagSyncResult | None
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def format(self) -> FormatAnalysisReport | None:
        """Short spelling for consumers presenting the combined report."""

        return self.format_analysis

    @property
    def tags(self) -> AutoTagSyncResult | None:
        """Short spelling for consumers presenting the combined report."""

        return self.tag_sync

    @property
    def changed(self) -> bool:
        discovery_changed = bool(self.discovery is not None and self.discovery.changed)
        canary_changed = bool(self.canary is not None and self.canary.changed)
        signature_changed = bool(self.format_signatures is not None and self.format_signatures.changed)
        tags_changed = bool(self.tag_sync is not None and (self.tag_sync.added or self.tag_sync.removed))
        return discovery_changed or canary_changed or signature_changed or tags_changed


def run_pre_export(
    view: Any,
    *,
    run_orphan: bool = True,
    initially_settled: bool = False,
) -> PreExportReport:
    """Prepare *view* for export and collect optional security enrichment.

    ``prepare_view_for_export`` and the initial analysis wait are intentionally
    outside optional-stage exception boundaries.  A failed or unsettled
    function baseline must not be exported.  Once that baseline exists, each
    security stage is isolated so one unavailable Binary Ninja API does not
    suppress the other results.
    """

    discovery: DiscoveryReport | None = None
    if run_orphan:
        # This call owns any initial wait it needs as well as all waits needed
        # to validate speculative orphan functions.
        discovery = prepare_view_for_export(view, initially_settled=initially_settled)
    elif not initially_settled:
        # Without orphan recovery there is no other owner for the baseline
        # wait.  Canary analysis may later perform its own, mutation-triggered
        # batch wait; that is a distinct operation and must not be duplicated.
        view.update_analysis_and_wait()

    diagnostics: list[Diagnostic] = []
    format_signatures: SignatureBootstrapResult | None
    try:
        format_signatures = bootstrap_format_function_types(view)
    except Exception as error:  # noqa: BLE001 - optional enrichment is fail-soft.
        format_signatures = None
        diagnostics.append(_stage_failure("format-signature-bootstrap", error))
    else:
        diagnostics.extend(_signature_diagnostics(format_signatures))

    # Signature bootstrap can explicitly reanalyze printf-like callers.  Run
    # the auto-variable annotation pass afterwards so that Binary Ninja does
    # not discard freshly-created CANARY/tcb identities while rebuilding
    # those callers' IL.
    canary: CanaryAnalysisReport | None
    try:
        canary = analyze_stack_canaries(view)
    except Exception as error:  # noqa: BLE001 - optional enrichment is fail-soft.
        canary = None
        diagnostics.append(_stage_failure("canary-analysis", error))
    else:
        diagnostics.extend(_canary_diagnostics(canary))

    format_analysis: FormatAnalysisReport | None
    try:
        format_analysis = analyze_format_strings(view)
    except Exception as error:  # noqa: BLE001 - optional enrichment is fail-soft.
        format_analysis = None
        diagnostics.append(_stage_failure("format-analysis", error))

    tag_sync: AutoTagSyncResult | None = None
    if format_analysis is not None:
        try:
            diagnostics.extend(diagnostics_for_report(format_analysis))
        except Exception as error:  # noqa: BLE001 - diagnostic rendering is optional.
            diagnostics.append(_stage_failure("format-diagnostics", error))

        try:
            tag_sync = synchronize_auto_tags(view, format_analysis)
        except Exception as error:  # noqa: BLE001 - auto tags must never block export.
            diagnostics.append(_stage_failure("format-tag-sync", error))
        else:
            diagnostics.extend(_tag_diagnostics(tag_sync))

    return PreExportReport(
        discovery=discovery,
        canary=canary,
        format_signatures=format_signatures,
        format_analysis=format_analysis,
        tag_sync=tag_sync,
        diagnostics=tuple(diagnostics),
    )


def _stage_failure(stage: str, error: Exception) -> Diagnostic:
    return Diagnostic(
        "warning",
        f"prepass-{stage}-failed",
        f"optional {stage.replace('-', ' ')} failed: {error}",
        {"stage": stage, "exception_type": type(error).__name__},
    )


def _canary_diagnostics(report: CanaryAnalysisReport) -> tuple[Diagnostic, ...]:
    return tuple(
        Diagnostic(
            "info",
            "prepass-canary-analysis-note",
            message,
            {"stage": "canary-analysis", "target": report.target},
        )
        for message in report.diagnostics
    )


def _tag_diagnostics(result: AutoTagSyncResult) -> tuple[Diagnostic, ...]:
    return tuple(
        Diagnostic(
            "info",
            "prepass-format-tag-sync-issue",
            message,
            {"stage": "format-tag-sync"},
        )
        for message in result.issues
    )


def _signature_diagnostics(result: SignatureBootstrapResult) -> tuple[Diagnostic, ...]:
    return tuple(
        Diagnostic(
            "info",
            "prepass-format-signature-bootstrap-issue",
            message,
            {"stage": "format-signature-bootstrap"},
        )
        for message in result.issues
    )
