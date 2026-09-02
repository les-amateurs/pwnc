from __future__ import annotations

import importlib
import sys
import unittest
from enum import IntFlag
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIR))


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


class _FakeView:
    def __init__(self, session_id: int = 41) -> None:
        self.file = SimpleNamespace(
            session_id=session_id,
            original_filename="/tmp/fixture",
            filename="/tmp/fixture",
        )
        self.view_type = "ELF"
        self.registered: list[object] = []
        self.unregistered: list[object] = []
        self.metadata: list[tuple[str, str, bool]] = []
        self.analysis_updates = 0

    def register_notification(self, notification: object) -> None:
        self.registered.append(notification)

    def unregister_notification(self, notification: object) -> None:
        self.unregistered.append(notification)

    def update_analysis_and_wait(self) -> None:
        self.analysis_updates += 1

    def store_metadata(self, key: str, value: str, *, isAuto: bool) -> None:
        self.metadata.append((key, value, isAuto))


class CommandLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.queued: list[tuple[object, str]] = []
        cls.logs: list[tuple[str, str]] = []
        binaryninja = ModuleType("binaryninja")
        binaryninja.BinaryDataNotification = _BinaryDataNotification
        binaryninja.NotificationType = _NotificationType
        binaryninja.log_info = lambda message: cls.logs.append(("info", message))
        binaryninja.log_alert = lambda message: cls.logs.append(("alert", message))
        binaryninja.log_error = lambda message: cls.logs.append(("error", message))
        mainthread = ModuleType("binaryninja.mainthread")
        mainthread.worker_interactive_enqueue = lambda callback, name: cls.queued.append((callback, name))
        sys.modules["binaryninja"] = binaryninja
        sys.modules["binaryninja.mainthread"] = mainthread
        sys.modules.pop("teemo.commands", None)
        cls.commands = importlib.import_module("teemo.commands")

    @classmethod
    def tearDownClass(cls) -> None:
        sys.modules.pop("teemo.commands", None)
        sys.modules.pop("binaryninja.mainthread", None)
        sys.modules.pop("binaryninja", None)

    def setUp(self) -> None:
        self.queued.clear()
        self.logs.clear()
        self.commands._live.clear()
        self.commands._view_locks.clear()

    def test_enable_disable_is_idempotent_and_schedules_initial_export(self) -> None:
        view = _FakeView()
        self.commands.enable_live_export(view)
        self.assertEqual(len(view.registered), 1)
        self.assertEqual([name for _callback, name in self.queued], ["Teemo export"])
        notification = view.registered[0]

        self.commands.enable_live_export(view)
        self.assertEqual(view.registered, [notification])
        self.assertEqual(len(self.queued), 1)

        self.commands.disable_live_export(view)
        self.assertEqual(view.unregistered, [notification])
        self.commands.disable_live_export(view)
        self.assertEqual(view.unregistered, [notification])

    def test_notification_barrier_coalesces_and_reschedules_dirty_publish(self) -> None:
        view = _FakeView()
        notification = self.commands.LiveExportNotification(view)
        self.assertFalse(notification.notifications & _NotificationType.DataMetadataUpdated)
        notification.DEBOUNCE_SECONDS = 0
        notification.changed()
        self.assertEqual(notification.notification_barrier(view), 0)
        self.assertEqual([name for _callback, name in self.queued], ["Teemo live export"])

        notification.changed()
        with patch.object(self.commands, "publish_view") as publish:
            callback, _name = self.queued.pop()
            callback()
            publish.assert_called_once()
            called_view = publish.call_args.args[0]
            called_options = publish.call_args.kwargs
            self.assertIs(called_view, view)
            self.assertFalse(called_options["wait_for_analysis"])
            self.assertFalse(called_options["announce"])
            self.assertTrue(callable(called_options["should_publish"]))
            self.assertFalse(called_options["run_discovery"])
        self.assertEqual(view.registered, [notification])
        self.assertFalse(notification._publishing)

    def test_code_change_runs_discovery_on_next_live_publish(self) -> None:
        view = _FakeView()
        notification = self.commands.LiveExportNotification(view)
        notification.DEBOUNCE_SECONDS = 0
        notification.data_written()
        self.assertEqual(notification.notification_barrier(view), 0)

        with patch.object(self.commands, "publish_view") as publish:
            callback, _name = self.queued.pop()
            callback()

        self.assertTrue(publish.call_args.kwargs["run_discovery"])

    def test_disable_during_publish_does_not_reregister(self) -> None:
        view = _FakeView()
        notification = self.commands.LiveExportNotification(view)
        notification.DEBOUNCE_SECONDS = 0
        notification.changed()
        self.assertEqual(notification.notification_barrier(view), 0)
        notification.changed()
        notification.stop()
        with patch.object(self.commands, "publish_view"):
            callback, _name = self.queued.pop()
            callback()
        self.assertFalse(notification._enabled)
        self.assertFalse(view.registered)

    def test_rebase_moves_live_registration_and_discards_old_view(self) -> None:
        old_view = _FakeView(41)
        new_view = _FakeView(42)
        notification = self.commands.LiveExportNotification(old_view)
        self.commands._live[41] = notification

        notification.rebased(old_view, new_view)

        self.assertIs(notification.view, new_view)
        self.assertEqual(old_view.unregistered, [notification])
        self.assertEqual(new_view.registered, [notification])
        self.assertNotIn(41, self.commands._live)
        self.assertIs(self.commands._live[42], notification)
        self.assertTrue(notification._dirty)

        self.commands.disable_live_export(new_view)
        self.assertEqual(new_view.unregistered, [notification])

    def test_publish_waits_for_analysis_and_records_current_manifest(self) -> None:
        view = _FakeView()
        document = object()
        manifest = SimpleNamespace(epoch=7, view_id="view-id")

        class Store:
            state_root = Path("/state")

            def publish(
                self,
                actual_document: object,
                binary_path: Path,
                *,
                timings: dict[str, float] | None = None,
            ) -> object:
                self.document = actual_document
                self.binary_path = binary_path
                if timings is not None:
                    timings.update({"prepare": 0.01, "emit": 0.02, "durability": 0.03})
                return manifest

        store = Store()
        prepass = SimpleNamespace(
            discovery=None,
            canary=None,
            format_analysis=None,
            tag_sync=None,
            diagnostics=(),
        )
        with (
            patch.object(self.commands, "_store", store),
            patch.object(self.commands, "run_pre_export", return_value=prepass) as run_pre_export,
            patch.object(self.commands, "extract_document", return_value=document),
        ):
            current = self.commands.publish_view(view, wait_for_analysis=True, announce=False)
        run_pre_export.assert_called_once_with(view, run_orphan=True, initially_settled=False)
        self.assertEqual(view.analysis_updates, 0)
        self.assertIs(store.document, document)
        self.assertEqual(store.binary_path, Path("/tmp/fixture"))
        self.assertEqual(current, Path("/state/view-id/current.json"))
        self.assertEqual(
            view.metadata,
            [(self.commands.METADATA_KEY, "/state/view-id/current.json", False)],
        )
        timing_logs = [message for level, message in self.logs if level == "info" and "Teemo timing:" in message]
        self.assertEqual(len(timing_logs), 1)
        self.assertIn("emit=0.020s", timing_logs[0])

    def test_stale_live_snapshot_is_discarded_before_artifact_publish(self) -> None:
        view = _FakeView()

        class Store:
            state_root = Path("/state")
            called = False

            def publish(self, _document: object, _binary_path: Path) -> object:
                self.called = True
                raise AssertionError("stale document must not be published")

        store = Store()
        prepass = SimpleNamespace(
            discovery=None,
            canary=None,
            format_analysis=None,
            tag_sync=None,
            diagnostics=(),
        )
        with (
            patch.object(self.commands, "_store", store),
            patch.object(self.commands, "run_pre_export", return_value=prepass),
            patch.object(self.commands, "extract_document", return_value=object()),
        ):
            current = self.commands.publish_view(
                view,
                wait_for_analysis=False,
                announce=False,
                should_publish=lambda: False,
            )
        self.assertIsNone(current)
        self.assertFalse(store.called)
        self.assertFalse(view.metadata)

    def test_prepass_diagnostics_are_appended_and_revalidated_before_publish(self) -> None:
        view = _FakeView()

        class Document:
            def __init__(self) -> None:
                self.diagnostics: list[object] = []
                self.validations = 0

            def validate(self) -> None:
                self.validations += 1

        class Store:
            state_root = Path("/state")

            def publish(self, document: object, _binary_path: Path, *, timings=None) -> object:
                self.document = document
                return SimpleNamespace(epoch=1, view_id="view-id")

        diagnostic = object()
        prepass = SimpleNamespace(
            discovery=None,
            canary=None,
            format_analysis=None,
            tag_sync=None,
            diagnostics=(diagnostic,),
        )
        document = Document()
        store = Store()
        with (
            patch.object(self.commands, "_store", store),
            patch.object(self.commands, "run_pre_export", return_value=prepass),
            patch.object(self.commands, "extract_document", return_value=document),
        ):
            self.commands.publish_view(view, wait_for_analysis=False, announce=False)

        self.assertEqual(document.diagnostics, [diagnostic])
        self.assertEqual(document.validations, 1)
        self.assertIs(store.document, document)


if __name__ == "__main__":
    unittest.main()
