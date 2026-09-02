"""Binary Ninja UI commands and debounced live export lifecycle."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import binaryninja
from binaryninja import BinaryDataNotification, NotificationType
from binaryninja.mainthread import worker_interactive_enqueue

from .artifacts import ArtifactStore
from .extractor import extract_document
from .prepass import run_pre_export

METADATA_KEY = "pwnc.teemo.current_manifest"
_store = ArtifactStore()
_view_locks: defaultdict[int, threading.Lock] = defaultdict(threading.Lock)
_live: dict[int, LiveExportNotification] = {}


def _view_key(view: Any) -> int:
    return int(view.file.session_id)


def _binary_path(view: Any) -> Path:
    filename = (
        getattr(view.file, "original_filename", "")
        or getattr(view.file, "filename", "")
        or getattr(view, "name", "binary")
    )
    return Path(str(filename)).expanduser().resolve(strict=False)


def publish_view(
    view: Any,
    *,
    wait_for_analysis: bool,
    announce: bool,
    should_publish: Callable[[], bool] | None = None,
    run_discovery: bool = True,
) -> Path | None:
    """Extract, emit, and publish one complete generation for ``view``."""

    started = time.perf_counter()
    analysis_seconds = 0.0
    with _view_locks[_view_key(view)]:
        analysis_started = time.perf_counter()
        prepass = run_pre_export(
            view,
            run_orphan=run_discovery,
            initially_settled=not wait_for_analysis,
        )
        analysis_seconds = time.perf_counter() - analysis_started
        discovery = prepass.discovery
        if discovery is not None:
            if discovery.candidates or discovery.truncated:
                binaryninja.log_info(
                    "Teemo orphan recovery: "
                    f"scanned={discovery.scanned_bytes}, candidates={discovery.candidates}, "
                    f"added={len(discovery.added)}, rejected={len(discovery.rejected)}, "
                    f"cascaded={len(discovery.cascaded)}, truncated={discovery.truncated}"
                )
        if prepass.canary is not None and prepass.canary.functions:
            binaryninja.log_info(
                "Teemo canary annotations: "
                f"target={prepass.canary.target}, matched={len(prepass.canary.functions)}, "
                f"changed={prepass.canary.changed}"
            )
        if prepass.format_analysis is not None and (
            prepass.format_analysis.calls or prepass.format_analysis.issues
        ):
            tag_sync = prepass.tag_sync
            tag_counts = (
                "unavailable"
                if tag_sync is None
                else f"+{tag_sync.added}/-{tag_sync.removed}/={tag_sync.unchanged}"
            )
            binaryninja.log_info(
                "Teemo format analysis: "
                f"calls={len(prepass.format_analysis.calls)}, "
                f"findings={len(prepass.format_analysis.findings)}, "
                f"wrappers={len(prepass.format_analysis.wrappers)}, tags={tag_counts}"
            )
        if should_publish is not None and not should_publish():
            binaryninja.log_info("Teemo discarded an analysis generation superseded during pre-export analysis")
            return None
        extraction_started = time.perf_counter()
        document = extract_document(view)
        if prepass.diagnostics:
            document.diagnostics.extend(prepass.diagnostics)
            document.validate()
        extraction_seconds = time.perf_counter() - extraction_started
        if should_publish is not None and not should_publish():
            binaryninja.log_info(
                f"Teemo discarded an analysis generation superseded during extraction ({extraction_seconds:.3f}s)"
            )
            return None
        publication_timings: dict[str, float] = {}
        manifest = _store.publish(
            document,
            _binary_path(view),
            timings=publication_timings,
        )
        current = _store.state_root / manifest.view_id / "current.json"
        view.store_metadata(METADATA_KEY, str(current), isAuto=False)
    message = f"Teemo epoch {manifest.epoch} published: {current}"
    binaryninja.log_info(message)
    timing_parts = []
    timing_parts.append(f"analysis={analysis_seconds:.3f}s")
    timing_parts.append(f"extract={extraction_seconds:.3f}s")
    for label, key in (
        ("prepare", "prepare"),
        ("lock", "lock_wait"),
        ("emit", "emit"),
        ("sync", "durability"),
        ("notify", "notification"),
        ("cleanup", "cleanup"),
    ):
        if key in publication_timings:
            timing_parts.append(f"{label}={publication_timings[key]:.3f}s")
    timing_parts.append(f"total={time.perf_counter() - started:.3f}s")
    binaryninja.log_info("Teemo timing: " + ", ".join(timing_parts))
    if announce:
        binaryninja.log_alert(message)
    return current


def schedule_export(view: Any) -> None:
    """Run explicit export on Binary Ninja's interactive worker queue."""

    def run() -> None:
        try:
            publish_view(view, wait_for_analysis=True, announce=True)
        except Exception as error:  # noqa: BLE001 - this is the UI task error boundary.
            binaryninja.log_error(f"Teemo export failed: {error}")

    worker_interactive_enqueue(run, "Teemo export")


class LiveExportNotification(BinaryDataNotification):
    """Coalesce analysis changes and publish only complete settled snapshots."""

    DEBOUNCE_SECONDS = 0.35

    def __init__(self, view: Any) -> None:
        notifications = (
            NotificationType.NotificationBarrier
            | NotificationType.BinaryDataUpdates
            | NotificationType.FunctionUpdates
            | NotificationType.DataVariableUpdates
            | NotificationType.SymbolUpdates
            | NotificationType.TypeUpdates
            | NotificationType.SegmentUpdates
            | NotificationType.SectionUpdates
            | NotificationType.Rebased
        )
        super().__init__(notifications)
        self.view = view
        self._state_lock = threading.Lock()
        self._dirty = False
        self._discovery_dirty = False
        self._publishing = False
        self._enabled = True
        self._last_change = 0.0

    def changed(self, *_arguments: Any) -> None:
        with self._state_lock:
            if not self._enabled:
                return
            self._dirty = True
            self._last_change = time.monotonic()

    function_added = changed
    function_updated = changed
    data_var_added = changed
    data_var_removed = changed
    data_var_updated = changed

    def code_changed(self, *_arguments: Any) -> None:
        with self._state_lock:
            if not self._enabled:
                return
            self._dirty = True
            self._discovery_dirty = True
            self._last_change = time.monotonic()

    data_written = code_changed
    data_inserted = code_changed
    data_removed = code_changed
    function_removed = code_changed
    symbol_added = code_changed
    symbol_removed = code_changed
    symbol_updated = code_changed
    type_defined = changed
    type_undefined = changed
    type_ref_changed = changed
    type_field_ref_changed = changed
    segment_added = code_changed
    segment_removed = code_changed
    segment_updated = code_changed
    section_added = code_changed
    section_removed = code_changed
    section_updated = code_changed

    def rebased(self, old_view: Any, new_view: Any) -> None:
        """Move live export to the replacement BinaryView created by rebase."""

        with self._state_lock:
            if not self._enabled:
                return
            self.view = new_view
            self._dirty = True
            self._discovery_dirty = True
            self._last_change = time.monotonic()

        old_key = _view_key(old_view)
        new_key = _view_key(new_view)
        if _live.get(old_key) is self and old_key != new_key:
            _live.pop(old_key, None)
        _live[new_key] = self
        try:
            new_view.register_notification(self)
        except Exception:
            self.stop()
            _live.pop(new_key, None)
            raise
        old_view.unregister_notification(self)

    def notification_barrier(self, view: Any) -> int:
        with self._state_lock:
            if not self._enabled or not self._dirty:
                return 0
            elapsed = time.monotonic() - self._last_change
            if elapsed < self.DEBOUNCE_SECONDS:
                return max(1, int((self.DEBOUNCE_SECONDS - elapsed) * 1000))
            if self._publishing:
                return int(self.DEBOUNCE_SECONDS * 1000)
            self._dirty = False
            self._publishing = True
        worker_interactive_enqueue(self._publish, "Teemo live export")
        return 0

    def stop(self) -> None:
        """Prevent a queued/in-flight publication from re-registering itself."""

        with self._state_lock:
            self._enabled = False
            self._dirty = False

    def _publish(self) -> None:
        with self._state_lock:
            view = self.view
            run_discovery = self._discovery_dirty
            self._discovery_dirty = False
        try:
            publish_view(
                view,
                wait_for_analysis=False,
                announce=False,
                should_publish=lambda: self._is_settled(view),
                run_discovery=run_discovery,
            )
        except Exception as error:  # noqa: BLE001 - this is the live task error boundary.
            binaryninja.log_error(f"Teemo live export failed: {error}")
        finally:
            with self._state_lock:
                self._publishing = False
                reschedule = self._enabled and self._dirty
                current_view = self.view
            if reschedule:
                # Re-registering the same object intentionally requests a fresh
                # notification barrier without duplicating the registration.
                current_view.register_notification(self)

    def _is_settled(self, view: Any | None = None) -> bool:
        with self._state_lock:
            return self._enabled and not self._dirty and (view is None or self.view is view)


def enable_live_export(view: Any) -> None:
    key = _view_key(view)
    if key in _live:
        binaryninja.log_info("Teemo live export is already enabled for this view")
        return
    notification = LiveExportNotification(view)
    _live[key] = notification
    view.register_notification(notification)
    schedule_export(view)
    binaryninja.log_alert("Teemo live export enabled")


def disable_live_export(view: Any) -> None:
    notification = _live.pop(_view_key(view), None)
    if notification is None:
        binaryninja.log_info("Teemo live export is not enabled for this view")
        return
    notification.stop()
    view.unregister_notification(notification)
    binaryninja.log_alert("Teemo live export disabled")


def is_supported_view(view: Any) -> bool:
    return str(getattr(view, "view_type", "")).lower() == "elf"
