from __future__ import annotations

import errno
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch


PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
GDB_DIR = Path(__file__).parents[1] / "gdb"
sys.path.insert(0, str(PLUGIN_DIR))
sys.path.insert(0, str(GDB_DIR))

from teemo.artifacts import (  # noqa: E402
    NOTIFICATION_SCHEMA,
    SUBSCRIBER_SCHEMA,
    ArtifactStore,
    Manifest,
    _process_start_ticks,
    view_identifier,
)
from loader_core import find_manifest  # noqa: E402
from test_ir import valid_document  # noqa: E402


def fake_emitter(ir_path: Path, output: Path) -> None:
    assert json.loads(ir_path.read_text())["schema"] == "pwnc.teemo.ir"
    output.write_bytes(b"ELF debug fixture")
    source_root = output.parent / "teemo.sources"
    source_root.mkdir()
    (source_root / "main.c").write_text("int main(void) {}\n")


class ArtifactStoreTests(unittest.TestCase):
    def test_published_build_id_supports_renamed_target_lookup(self) -> None:
        document = valid_document()
        document.binary = replace(
            document.binary,
            build_id="1a79fe02cc88ebf72a858a91b59c8d17c29a59fb",
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(temporary, emitter=fake_emitter)
            published = store.publish(document, "/tmp/original-challenge")
            current_path = Path(temporary) / published.view_id / "current.json"
            current = Manifest.load(current_path)
            self.assertEqual(current.build_id, document.binary.build_id)
            self.assertEqual(
                find_manifest(
                    temporary,
                    "/tmp/renamed-challenge",
                    build_id=document.binary.build_id.upper(),
                ),
                current_path.resolve(),
            )

    def test_publishes_atomic_monotonic_generations(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(temporary, emitter=fake_emitter, retain_generations=2)
            timings: dict[str, float] = {}
            manifests = [
                store.publish(
                    document,
                    "/tmp/fixture",
                    timings=timings if index == 3 else None,
                )
                for index in range(4)
            ]
            self.assertEqual([manifest.epoch for manifest in manifests], [1, 2, 3, 4])
            self.assertTrue(
                {"prepare", "lock_wait", "stage", "emit", "durability", "notification", "cleanup", "total"}
                <= timings.keys()
            )
            current_path = Path(temporary) / manifests[-1].view_id / "current.json"
            current = Manifest.load(current_path)
            self.assertEqual(current.epoch, 4)
            self.assertTrue(Path(current.debug_object).is_file())
            generations = current_path.parent / "generations"
            self.assertEqual(sorted(path.name for path in generations.iterdir()), ["3", "4"])

    def test_failed_publish_keeps_previous_current_generation(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(temporary, emitter=fake_emitter)
            first = store.publish(document, "/tmp/fixture")

            def fail(_ir: Path, _output: Path) -> None:
                raise RuntimeError("planned failure")

            store.emitter = fail
            with self.assertRaisesRegex(RuntimeError, "planned failure"):
                store.publish(document, "/tmp/fixture")
            current = Manifest.load(Path(temporary) / first.view_id / "current.json")
            self.assertEqual(current.epoch, 1)
            self.assertTrue(Path(current.debug_object).is_file())

    def test_view_identity_is_architecture_and_path_specific(self) -> None:
        document = valid_document()
        first = view_identifier(document, "/tmp/first")
        second = view_identifier(document, "/tmp/second")
        self.assertNotEqual(first, second)
        self.assertEqual(first, view_identifier(document, "/tmp/first"))

    def test_live_lease_retains_an_old_generation(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(temporary, emitter=fake_emitter, retain_generations=2)
            first = store.publish(document, "/tmp/fixture")
            view_root = Path(temporary) / first.view_id
            leases = view_root / "leases"
            leases.mkdir()
            (leases / "test.json").write_text(
                json.dumps(
                    {
                        "schema": "pwnc.teemo.lease",
                        "version": 1,
                        "pid": os.getpid(),
                        "epoch": first.epoch,
                    }
                )
            )
            for _ in range(4):
                store.publish(document, "/tmp/fixture")
            generations = view_root / "generations"
            self.assertTrue((generations / str(first.epoch)).is_dir())
            self.assertEqual(
                sorted(int(path.name) for path in generations.iterdir()),
                [first.epoch, 4, 5],
            )

    def test_publish_removes_stale_staging_and_skips_orphan_epoch(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(temporary, emitter=fake_emitter)
            first = store.publish(document, "/tmp/fixture")
            view_root = Path(temporary) / first.view_id
            stale = view_root / ".staging-abandoned"
            stale.mkdir()
            orphan = view_root / "generations" / "7"
            orphan.mkdir()
            second = store.publish(document, "/tmp/fixture")
            self.assertEqual(second.epoch, 8)
            self.assertFalse(stale.exists())

    def test_publish_notifies_every_live_unix_socket_subscriber(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = ArtifactStore(root, emitter=fake_emitter)
            first = store.publish(document, "/tmp/fixture")
            view_root = root / first.view_id
            subscribers = view_root / "subscribers"
            subscribers.mkdir()
            start_ticks = _process_start_ticks(os.getpid())
            self.assertIsNotNone(start_ticks)
            receivers: list[tuple[socket.socket, Path]] = []
            try:
                for index in range(2):
                    socket_path = root / f"receiver-{index}.sock"
                    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                    receiver.bind(str(socket_path))
                    receiver.settimeout(1)
                    receivers.append((receiver, socket_path))
                    (subscribers / f"subscriber-{index}.json").write_text(
                        json.dumps(
                            {
                                "schema": SUBSCRIBER_SCHEMA,
                                "version": 1,
                                "pid": os.getpid(),
                                "uid": os.getuid(),
                                "process_start_ticks": start_ticks,
                                "view_id": first.view_id,
                                "socket_path": str(socket_path),
                            }
                        )
                    )

                second = store.publish(document, "/tmp/fixture")
                self.assertEqual(Manifest.load(view_root / "current.json").epoch, second.epoch)
                for receiver, _socket_path in receivers:
                    message = json.loads(receiver.recv(4096))
                    self.assertEqual(message["schema"], NOTIFICATION_SCHEMA)
                    self.assertEqual(message["view_id"], first.view_id)
                    self.assertEqual(message["epoch"], second.epoch)
            finally:
                for receiver, socket_path in receivers:
                    receiver.close()
                    socket_path.unlink(missing_ok=True)

    def test_notification_precedes_retention_cleanup(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = ArtifactStore(root, emitter=fake_emitter)
            first = store.publish(document, "/tmp/fixture")
            view_root = root / first.view_id
            subscribers = view_root / "subscribers"
            subscribers.mkdir()
            socket_path = root / "receiver.sock"
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.bind(str(socket_path))
            receiver.settimeout(1)
            descriptor = subscribers / "subscriber.json"
            descriptor.write_text(
                json.dumps(
                    {
                        "schema": SUBSCRIBER_SCHEMA,
                        "version": 1,
                        "pid": os.getpid(),
                        "uid": os.getuid(),
                        "process_start_ticks": _process_start_ticks(os.getpid()),
                        "view_id": first.view_id,
                        "socket_path": str(socket_path),
                    }
                )
            )
            original_cleanup = store._cleanup

            def cleanup(generations: Path, epoch: int) -> None:
                message = json.loads(receiver.recv(4096))
                self.assertEqual(message["epoch"], epoch)
                self.assertEqual(Manifest.load(view_root / "current.json").epoch, epoch)
                original_cleanup(generations, epoch)

            try:
                with patch.object(store, "_cleanup", side_effect=cleanup):
                    second = store.publish(document, "/tmp/fixture")
                self.assertEqual(second.epoch, first.epoch + 1)
            finally:
                receiver.close()
                socket_path.unlink(missing_ok=True)

    def test_full_subscriber_queue_drops_nonblocking_wakeup(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = ArtifactStore(root, emitter=fake_emitter)
            first = store.publish(document, "/tmp/fixture")
            view_root = root / first.view_id
            subscribers = view_root / "subscribers"
            subscribers.mkdir()
            socket_path = root / "receiver.sock"
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.bind(str(socket_path))
            descriptor = subscribers / "subscriber.json"
            descriptor.write_text(
                json.dumps(
                    {
                        "schema": SUBSCRIBER_SCHEMA,
                        "version": 1,
                        "pid": os.getpid(),
                        "uid": os.getuid(),
                        "process_start_ticks": _process_start_ticks(os.getpid()),
                        "view_id": first.view_id,
                        "socket_path": str(socket_path),
                    }
                )
            )

            class FullNotifier:
                blocking: bool | None = None

                def __enter__(self) -> FullNotifier:
                    return self

                def __exit__(self, *_arguments: object) -> None:
                    pass

                def setblocking(self, value: bool) -> None:
                    self.blocking = value

                def sendto(self, _payload: bytes, _path: str) -> None:
                    raise BlockingIOError(errno.EAGAIN, "queue full")

            notifier = FullNotifier()
            try:
                with patch("teemo.artifacts.socket.socket", return_value=notifier):
                    second = store.publish(document, "/tmp/fixture")
                self.assertFalse(notifier.blocking)
                self.assertTrue(descriptor.is_file())
                self.assertEqual(Manifest.load(view_root / "current.json").epoch, second.epoch)
            finally:
                receiver.close()
                socket_path.unlink(missing_ok=True)

    def test_publish_removes_stale_socket_subscriber_without_failing(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = ArtifactStore(root, emitter=fake_emitter)
            first = store.publish(document, "/tmp/fixture")
            subscribers = root / first.view_id / "subscribers"
            subscribers.mkdir()
            descriptor = subscribers / "stale.json"
            descriptor.write_text(
                json.dumps(
                    {
                        "schema": SUBSCRIBER_SCHEMA,
                        "version": 1,
                        "pid": os.getpid(),
                        "uid": os.getuid(),
                        "process_start_ticks": _process_start_ticks(os.getpid()),
                        "view_id": first.view_id,
                        "socket_path": str(root / "missing.sock"),
                    }
                )
            )

            second = store.publish(document, "/tmp/fixture")

            self.assertEqual(second.epoch, first.epoch + 1)
            self.assertFalse(descriptor.exists())

    def test_publish_unlinks_socket_owned_by_a_dead_subscriber(self) -> None:
        document = valid_document()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = ArtifactStore(root, emitter=fake_emitter)
            first = store.publish(document, "/tmp/fixture")
            subscribers = root / first.view_id / "subscribers"
            subscribers.mkdir()
            socket_path = root / "dead.sock"
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.bind(str(socket_path))
            try:
                descriptor = subscribers / "dead.json"
                descriptor.write_text(
                    json.dumps(
                        {
                            "schema": SUBSCRIBER_SCHEMA,
                            "version": 1,
                            "pid": 2**31 - 1,
                            "uid": os.getuid(),
                            "process_start_ticks": 1,
                            "view_id": first.view_id,
                            "socket_path": str(socket_path),
                        }
                    )
                )

                store.publish(document, "/tmp/fixture")

                self.assertFalse(descriptor.exists())
                self.assertFalse(socket_path.exists())
            finally:
                receiver.close()
                socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
