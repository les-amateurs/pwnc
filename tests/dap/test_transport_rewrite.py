"""Production regression tests for the reader-isolated DAP transport."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
from concurrent.futures import CancelledError, Future, wait

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap.transport import DapError, DapTimeout, DapTransport, _Inbound


TIMEOUT = 15.0


def _require_gdb() -> None:
    if not shutil.which("gdb"):
        pytest.skip("live GDB is required")


def _initialize(transport: DapTransport) -> dict:
    capabilities = transport.request(
        "initialize",
        {
            "clientID": "pwnc-transport-test",
            "adapterID": "gdb",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "pathFormat": "path",
        },
        timeout=TIMEOUT,
    )
    transport.wait_initialized(TIMEOUT)
    return capabilities


def _recording_fake_gdb(tmp_path):
    log_path = tmp_path / "messages.json"
    fake_gdb = tmp_path / "recording-gdb"
    fake_gdb.write_text(
        f"#!{sys.executable}\n"
        "import json\n"
        "import pathlib\n"
        "import sys\n"
        "import time\n"
        "stream = sys.stdin.buffer\n"
        "def receive():\n"
        "    length = None\n"
        "    while True:\n"
        "        line = stream.readline()\n"
        "        if not line:\n"
        "            raise EOFError\n"
        "        if line in (b'\\n', b'\\r\\n'):\n"
        "            break\n"
        "        if line.lower().startswith(b'content-length:'):\n"
        "            length = int(line.split(b':', 1)[1])\n"
        "    return json.loads(stream.read(length))\n"
        "messages = [receive(), receive()]\n"
        "pathlib.Path(sys.argv[-1]).write_text(json.dumps(messages))\n"
        "time.sleep(30)\n"
    )
    fake_gdb.chmod(0o755)
    return fake_gdb, log_path


def _wait_for_path(path) -> None:
    deadline = time.monotonic() + TIMEOUT
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {path}")
        time.sleep(0.01)


def test_send_remains_future_compatible_and_returns_raw_response() -> None:
    _require_gdb()
    transport = DapTransport(init=False)
    try:
        _initialize(transport)
        pending = transport.send(
            "evaluate",
            {"expression": "show version", "context": "repl"},
        )
        assert isinstance(pending, Future)
        assert callable(pending.done)
        raw = pending.result(TIMEOUT)
        assert raw["type"] == "response"
        assert raw["command"] == "evaluate"
        assert raw["success"] is True
        assert "GNU gdb" in raw["body"]["result"]
        assert pending.done() is True
    finally:
        transport.close()


def test_early_and_late_future_callbacks_can_reenter_gdb_synchronously() -> None:
    _require_gdb()
    transport = DapTransport(init=False)
    caller_thread = threading.get_ident()
    callback_threads: list[int] = []
    callback_results: list[str] = []
    early_done = threading.Event()
    late_done = threading.Event()

    def nested_request(done: Future, completed: threading.Event) -> None:
        assert done.result()["success"] is True
        callback_threads.append(threading.get_ident())
        body = transport.request(
            "evaluate",
            {"expression": "show pagination", "context": "repl"},
            timeout=TIMEOUT,
        )
        callback_results.append(body["result"])
        completed.set()

    try:
        _initialize(transport)
        early = transport.send(
            "evaluate",
            {"expression": "show version", "context": "repl"},
        )
        early.add_done_callback(lambda done: nested_request(done, early_done))
        assert early.result(TIMEOUT)["success"] is True
        assert early_done.wait(TIMEOUT)

        late = transport.send(
            "evaluate",
            {"expression": "show version", "context": "repl"},
        )
        assert late.result(TIMEOUT)["success"] is True
        late.add_done_callback(lambda done: nested_request(done, late_done))
        assert late_done.wait(TIMEOUT)

        assert len(callback_threads) == 2
        infrastructure = {
            caller_thread,
            transport.reader_thread_id,
            transport.router_thread_id,
            transport.writer_thread_id,
            transport.event_thread_id,
        }
        assert set(callback_threads).isdisjoint(infrastructure)
        assert all("pagination" in result.lower() for result in callback_results)
        assert not transport.worker_errors
    finally:
        transport.close()


def test_initialized_handler_finishes_before_wait_initialized_returns() -> None:
    _require_gdb()
    transport = DapTransport(init=False)
    observations: list[tuple[int, str]] = []

    def initialized(_body: dict) -> None:
        nested = transport.request(
            "evaluate",
            {"expression": "show confirm", "context": "repl"},
            timeout=TIMEOUT,
        )
        observations.append((threading.get_ident(), nested["result"]))

    try:
        transport.on("initialized", initialized)
        transport.request(
            "initialize",
            {
                "clientID": "pwnc-init-handler-test",
                "adapterID": "gdb",
                "linesStartAt1": True,
                "columnsStartAt1": True,
                "pathFormat": "path",
            },
            timeout=TIMEOUT,
        )
        transport.wait_initialized(TIMEOUT)
        assert len(observations) == 1
        assert observations[0][0] == transport.event_thread_id
        assert "confirm" in observations[0][1].lower()
    finally:
        transport.close()


def test_passive_event_handlers_preserve_wire_order() -> None:
    _require_gdb()
    transport = DapTransport(init=False)
    received: list[int] = []
    all_received = threading.Event()

    def handler(body: dict) -> None:
        received.append(body["index"])
        if len(received) == 64:
            all_received.set()

    try:
        _initialize(transport)
        transport.on("pwncSyntheticOrder", handler)
        for index in range(64):
            payload = json.dumps(
                {
                    "seq": 100_000 + index,
                    "type": "event",
                    "event": "pwncSyntheticOrder",
                    "body": {"index": index},
                }
            ).encode()
            assert transport._queue_inbound(_Inbound("frame", payload))
        assert all_received.wait(TIMEOUT)
        assert received == list(range(64))
    finally:
        transport.close()


def test_partial_writes_are_completed_exactly() -> None:
    class ShortStream:
        def __init__(self):
            self.data = bytearray()
            self.calls = 0
            self.flushed = False

        def write(self, data):
            self.calls += 1
            count = min(3, len(data))
            self.data.extend(data[:count])
            return count

        def flush(self):
            self.flushed = True

    message = {
        "type": "request",
        "command": "evaluate",
        "arguments": {"expression": "show version"},
    }
    encoded = DapTransport._encode_without_seq(message)
    frame = DapTransport._frame_encoded(7, encoded)
    stream = ShortStream()
    DapTransport._write_all(stream, frame)
    assert bytes(stream.data) == frame
    assert stream.calls > 1
    assert stream.flushed is True


def test_future_cancel_is_future_compatible_and_sends_dap_cancel(tmp_path) -> None:
    fake_gdb, log_path = _recording_fake_gdb(tmp_path)
    transport = DapTransport(str(fake_gdb), [str(log_path)])
    try:
        pending = transport.send("evaluate", {"expression": "slow"})
        assert pending.cancel() is True
        assert pending.cancel() is True
        assert pending.cancelled() is True
        assert pending.done() is True
        done, not_done = wait([pending], timeout=0)
        assert done == {pending}
        assert not not_done
        with pytest.raises(CancelledError):
            pending.result()
        _wait_for_path(log_path)
        messages = json.loads(log_path.read_text())
        assert [message["command"] for message in messages] == [
            "evaluate",
            "cancel",
        ]
        assert messages[1]["arguments"]["requestId"] == messages[0]["seq"]
        assert transport.pending_count == 0
    finally:
        transport.close()


def test_request_timeout_sends_best_effort_dap_cancel(tmp_path) -> None:
    fake_gdb, log_path = _recording_fake_gdb(tmp_path)
    transport = DapTransport(str(fake_gdb), [str(log_path)])
    try:
        pending = transport.send("evaluate", {"expression": "slow"})
        with pytest.raises(DapTimeout, match="evaluate"):
            transport.result(pending, timeout=0.02)
        _wait_for_path(log_path)
        messages = json.loads(log_path.read_text())
        assert [message["command"] for message in messages] == [
            "evaluate",
            "cancel",
        ]
        assert messages[1]["arguments"]["requestId"] == messages[0]["seq"]
        assert transport.pending_count == 0
    finally:
        transport.close()


def test_external_stderr_is_drained_and_bounded(tmp_path) -> None:
    fake_gdb = tmp_path / "fake-gdb"
    fake_gdb.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "import time\n"
        "os.write(2, b'S' * 1048576 + b'DONE\\n')\n"
        "time.sleep(30)\n"
    )
    fake_gdb.chmod(0o755)
    transport = DapTransport(
        gdb_path=str(fake_gdb),
        stderr_tail_bytes=4096,
    )
    try:
        deadline = time.monotonic() + TIMEOUT
        while not transport.stderr_tail.endswith(b"DONE\n"):
            if time.monotonic() >= deadline:
                raise TimeoutError("fake GDB did not finish its stderr flood")
            time.sleep(0.01)
        assert len(transport.stderr_tail) == 4096
        assert transport.proc.poll() is None
    finally:
        transport.close()


def test_writer_failure_fails_pending_and_terminates_acceptance() -> None:
    _require_gdb()
    transport = DapTransport(init=False)
    original_write_all = transport._write_all

    def fail_write(_stream, _data):
        raise OSError("injected production writer failure")

    try:
        _initialize(transport)
        transport._write_all = fail_write
        pending = transport.send(
            "evaluate",
            {"expression": "show version", "context": "repl"},
        )
        with pytest.raises(DapError, match="injected production writer failure"):
            pending.result(TIMEOUT)
        assert transport.pending_count == 0
        with pytest.raises(DapError):
            transport.send("threads")
    finally:
        transport._write_all = original_write_all
        transport.close()


def test_clean_disconnect_then_close_still_reaps_process_and_threads() -> None:
    _require_gdb()
    transport = DapTransport(init=False)
    _initialize(transport)
    transport.request(
        "disconnect",
        {"terminateDebuggee": False},
        timeout=TIMEOUT,
    )
    transport.close()
    assert transport.proc.poll() is not None
    assert not transport._reader.is_alive()
    assert not transport._router.is_alive()
    assert not transport._writer.is_alive()
    assert not transport._stderr_reader.is_alive()
    assert not transport._event_worker.is_alive()
