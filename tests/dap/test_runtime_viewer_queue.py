"""Deterministic backpressure tests for the runtime-viewer publisher."""

from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from pwnc.gdb.dap.inspector import (
    RuntimeViewer,
    ViewerConnectionError,
    _OutboundItem,
    _OutboundQueue,
)


class _EmptyHistory:
    def subscribe(self, _callback):
        return lambda: None

    def __iter__(self):
        return iter(())


class _EmptyRuntime:
    history = _EmptyHistory()


def test_control_messages_survive_event_and_snapshot_pressure() -> None:
    queue = _OutboundQueue(2)
    hello = _OutboundItem("hello", None)
    first_snapshot = _OutboundItem("snapshot", object())
    second_snapshot = _OutboundItem("snapshot", object())

    assert queue.put(hello)
    assert queue.put(_OutboundItem("event", object()))
    assert queue.put(first_snapshot)
    assert queue.dropped_events == 1
    assert queue.put(second_snapshot)
    assert queue.dropped_snapshots == 1

    assert queue.get() == hello
    assert queue.get() == second_snapshot


def test_new_events_are_dropped_without_displacing_retained_state() -> None:
    queue = _OutboundQueue(2)
    hello = _OutboundItem("hello", None)
    snapshot = _OutboundItem("snapshot", object())
    assert queue.put(hello)
    assert queue.put(snapshot)

    assert not queue.put(_OutboundItem("event", object()))
    assert queue.dropped_events == 1
    assert queue.get() == hello
    assert queue.get() == snapshot


def test_snapshot_cannot_evict_the_only_control_message() -> None:
    queue = _OutboundQueue(1)
    hello = _OutboundItem("hello", None)
    assert queue.put(hello)
    assert not queue.put(_OutboundItem("snapshot", object()))
    assert queue.dropped_snapshots == 1
    assert queue.get() == hello


@pytest.mark.parametrize("kind", ["missing", "stale"])
def test_runtime_viewer_connection_errors_include_source_and_remediation(tmp_path, kind):
    path = tmp_path / "runtime-viewer.sock"
    if kind == "stale":
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(path))
        listener.close()

    viewer = RuntimeViewer(_EmptyRuntime())
    try:
        with pytest.raises(ViewerConnectionError) as caught:
            viewer.connect(path, capture=False)
        message = str(caught.value)
        assert os.fspath(path) in message
        assert "explicit socket_path argument" in message
        assert "[Errno" not in message
        if kind == "missing":
            assert "viewer.open()" in message
        else:
            assert "may be stale" in message
    finally:
        viewer.close()
