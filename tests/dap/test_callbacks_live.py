"""Live production callback coverage with byte-identical bata24 GEF."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import (
    CallbackAdmissionError,
    DapTimeout,
    Gdb,
    OperationFailed,
)
from pwnc.gdb.dap.transport import DapTransport


TIMEOUT = 30.0
RECURSION_DEPTH = 8
DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
FIXTURES = Path(__file__).with_name("fixtures")
EXPERIMENTS = Path(__file__).with_name("experiments")
GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")


def _gdb_available() -> bool:
    return shutil.which(GDB_PATH) is not None or (os.path.isfile(GDB_PATH) and os.access(GDB_PATH, os.X_OK))


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source(gdb: Gdb, path: Path) -> str:
    return gdb.execute("source " + str(path.resolve()))


def _assert_nested_result(result: dict, max_depth: int) -> None:
    current = result
    for depth in range(max_depth + 1):
        assert current["depth"] == depth
        assert "pagination" in current["before"].lower()
        assert "confirm" in current["after"].lower()
        value = current["value"]
        assert value["fromDepth"] == depth
        if depth == max_depth:
            assert value["leaf"] is True
        else:
            current = value["child"]


def run_production_callback_probe(
    gdb_path=GDB_PATH,
    *,
    gef_path=DEFAULT_GEF,
    inject_before_gef=True,
    max_depth=RECURSION_DEPTH,
):
    gef_path = Path(gef_path).resolve()
    if not gef_path.is_file():
        raise RuntimeError(f"bata24 GEF source is required: {gef_path}")
    digest_before = _digest(gef_path)
    if digest_before != EXPECTED_GEF_SHA256:
        raise RuntimeError(f"unexpected bata24 GEF source hash: expected {EXPECTED_GEF_SHA256}, got {digest_before}")
    stat_before = gef_path.stat()

    transport = DapTransport(gdb_path, init=False)
    gdb = Gdb(transport)
    callback_threads: dict[int, int] = {}
    gef_outputs = []

    def callback(depth, *, max_depth):
        callback_threads[depth] = threading.get_ident()
        gef_outputs.append(gdb.execute("history -n"))
        if depth < max_depth:
            child = gdb.run_operation(
                "pwnc.test.recursive",
                {"depth": depth + 1, "max_depth": max_depth},
                callbacks={"pwnc.test.callback": callback},
                timeout=TIMEOUT,
            )
            return {"fromDepth": depth, "child": child}
        return {"fromDepth": depth, "leaf": True}

    try:
        gdb._initialize()
        injection = EXPERIMENTS / "gef_injection_ext.py"
        if inject_before_gef:
            _source(gdb, injection)
            _source(gdb, gef_path)
        else:
            _source(gdb, gef_path)
            _source(gdb, injection)

        version = gdb.execute("gef version")
        assert "gef" in version.lower()
        _source(gdb, FIXTURES / "callback_operations.py")

        result = gdb.run_operation(
            "pwnc.test.recursive",
            {"depth": 0, "max_depth": max_depth},
            callbacks={"pwnc.test.callback": callback},
            timeout=TIMEOUT,
        )
        _assert_nested_result(result, max_depth)

        trace = gdb.run_operation("pwnc.test.snapshot", timeout=TIMEOUT)
        operation_threads = {
            item["threadId"] for item in trace if item["kind"] in {"operation-enter", "operation-return"}
        }
        assert len(operation_threads) == 1
        assert len(callback_threads) == max_depth + 1
        assert len(set(callback_threads.values())) == max_depth + 1
        assert set(callback_threads.values()).isdisjoint(operation_threads)
        assert set(callback_threads.values()).isdisjoint(
            {
                transport.reader_thread_id,
                transport.router_thread_id,
                transport.writer_thread_id,
                transport.event_thread_id,
            }
        )

        gef_snapshot = transport.request("pwncGefInjectionSnapshot", timeout=TIMEOUT)
        history_enters = [
            event
            for event in gef_snapshot["events"]
            if event["kind"] == "execute-enter" and event["command"] == "history -n"
        ]
        nested_history = [
            event
            for event in gef_snapshot["events"]
            if event["kind"] == "execute-enter" and event["depth"] >= 1 and event["command"].startswith("show commands")
        ]
        assert len(history_enters) == max_depth + 1
        assert len(nested_history) >= max_depth + 1
        assert {event["threadId"] for event in history_enters + nested_history} == operation_threads
        assert len(gef_outputs) == max_depth + 1
        assert not gdb.operations.errors

        operation_snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert operation_snapshot["activeCount"] == 0
        assert operation_snapshot["tombstoneCount"] == (max_depth + 1) + 1
        return {
            "gdbVersion": transport.request(
                "evaluate",
                {"expression": "show version", "context": "repl"},
                timeout=TIMEOUT,
            )["result"].splitlines()[0],
            "injectionOrder": "before" if inject_before_gef else "after",
            "maxDepth": max_depth,
            "callbackThreads": len(set(callback_threads.values())),
            "gdbMainThread": next(iter(operation_threads)),
        }
    finally:
        gdb.close()
        stat_after = gef_path.stat()
        assert _digest(gef_path) == digest_before
        assert stat_after.st_size == stat_before.st_size
        assert stat_after.st_mtime_ns == stat_before.st_mtime_ns


@pytest.mark.parametrize("inject_before_gef", [True, False])
def test_production_recursive_callbacks_with_unmodified_bata24_gef(
    inject_before_gef,
) -> None:
    if not _gdb_available():
        pytest.skip("live GDB is required")
    if not DEFAULT_GEF.is_file():
        pytest.skip("exact bata24 GEF fixture is not installed")
    evidence = run_production_callback_probe(
        gdb_path=GDB_PATH,
        inject_before_gef=inject_before_gef,
    )
    assert evidence["maxDepth"] == RECURSION_DEPTH
    assert evidence["callbackThreads"] == RECURSION_DEPTH + 1


def test_callable_api_alternates_host_and_gdb_with_native_values() -> None:
    if not _gdb_available():
        pytest.skip("live GDB is required")
    transport = DapTransport(GDB_PATH, init=False)
    gdb = Gdb(transport)
    callback_threads = []
    exported_sync_callbacks = []

    def host_callback(depth, sync_callback, recursive_callback, *, max_depth, binary):
        callback_threads.append(threading.get_ident())
        exported_sync_callbacks.append(sync_callback)
        assert binary == (b"pwnc", b"callback")
        assert sync_callback(depth, increment=100) == depth + 100
        if depth == max_depth:
            return {"depth": depth, "leaf": binary}
        return {
            "depth": depth,
            "child": recursive_callback(depth + 1),
        }

    try:
        gdb._initialize()
        _source(gdb, FIXTURES / "callback_operations.py")
        result = gdb.call(
            "pwnc.test.capabilities",
            host_callback,
            0,
            max_depth=RECURSION_DEPTH,
        )

        current = result
        for depth in range(RECURSION_DEPTH + 1):
            assert current["depth"] == depth
            if depth == RECURSION_DEPTH:
                assert current["leaf"] == (b"pwnc", b"callback")
            else:
                current = current["child"]
        assert len(callback_threads) == RECURSION_DEPTH + 1
        assert len(set(callback_threads)) == RECURSION_DEPTH + 1
        assert not gdb.operations.errors

        # Root-scoped callbacks cannot silently turn into session-global object
        # handles after the call that introduced them has completed.
        with pytest.raises(CallbackAdmissionError, match="active host callback"):
            exported_sync_callbacks[0](1)
    finally:
        gdb.close()


def test_callable_api_timeout_cascades_to_active_descendant() -> None:
    if not _gdb_available():
        pytest.skip("live GDB is required")
    transport = DapTransport(GDB_PATH, init=False)
    gdb = Gdb(transport)
    descendant_callback_entered = threading.Event()
    descendant_callback_finished = threading.Event()
    never_released = threading.Event()
    descendant_work_seconds = 3.0

    def host_callback(depth, sync_callback, recursive_callback, *, max_depth, binary):
        assert max_depth == 1
        assert binary == (b"pwnc", b"callback")
        assert sync_callback(depth, increment=100) == depth + 100
        if depth == 0:
            return recursive_callback(1)

        assert depth == 1
        descendant_callback_entered.set()
        assert not never_released.wait(descendant_work_seconds)
        descendant_callback_finished.set()
        return {"depth": depth}

    try:
        gdb._initialize()
        _source(gdb, FIXTURES / "callback_operations.py")
        with pytest.raises(DapTimeout, match="pwnc.test.capabilities"):
            gdb.use(timeout=1.0).call(
                "pwnc.test.capabilities",
                host_callback,
                0,
                max_depth=1,
            )

        assert descendant_callback_entered.is_set()

        # The operation tree must be cancelled while the ordinary host callback
        # is still running. Its bounded wait ends on its own; the test never
        # releases it to make operation cleanup succeed.
        operation_deadline = time.monotonic() + 1.0
        while True:
            snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
            if snapshot["activeCount"] == 0 or time.monotonic() >= operation_deadline:
                break
            time.sleep(0.01)
        assert snapshot["activeCount"] == 0
        assert not descendant_callback_finished.is_set()

        assert descendant_callback_finished.wait(descendant_work_seconds + TIMEOUT)
        host_deadline = time.monotonic() + TIMEOUT
        while (
            gdb.operations.active_operations or gdb.operations.active_callbacks or gdb.operations._capability_scopes
        ) and time.monotonic() < host_deadline:
            time.sleep(0.01)
        assert gdb.operations.active_operations == 0
        assert gdb.operations.active_callbacks == 0
        assert not gdb.operations._capability_scopes
        snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
    finally:
        descendant_callback_finished.wait(descendant_work_seconds + TIMEOUT)
        gdb.close()


def test_callable_api_propagates_exceptions_in_both_directions() -> None:
    if not _gdb_available():
        pytest.skip("live GDB is required")
    transport = DapTransport(GDB_PATH, init=False)
    gdb = Gdb(transport)

    class LiveHostFailure(RuntimeError):
        pass

    def host_callback(gdb_failure, *, mode):
        if mode == "gdb":
            with pytest.raises(OperationFailed, match="GDB callback failure: roundtrip") as caught:
                gdb_failure("roundtrip")
            return {
                "caught": type(caught.value).__name__,
                "binary": (b"exception", b"roundtrip"),
            }
        raise LiveHostFailure("host callback failure")

    try:
        gdb._initialize()
        _source(gdb, FIXTURES / "callback_operations.py")

        gdb_caught = gdb.call(
            "pwnc.test.capability-errors",
            host_callback,
            mode="gdb",
        )
        assert gdb_caught == {
            "caught": "OperationFailed",
            "binary": (b"exception", b"roundtrip"),
        }

        host_caught = gdb.call(
            "pwnc.test.capability-errors",
            host_callback,
            mode="host",
        )
        assert host_caught["caught"] == "HostCallbackError"
        assert "LiveHostFailure: host callback failure" in host_caught["message"]
        assert not gdb.operations.errors
    finally:
        gdb.close()


def test_callable_api_timeout_runs_automatic_cleanup_invocations() -> None:
    if not _gdb_available():
        pytest.skip("live GDB is required")
    transport = DapTransport(GDB_PATH, init=False)
    gdb = Gdb(transport)
    hold_entered = threading.Event()
    release_hold = threading.Event()
    hold_threads = []
    cleanup_calls = []

    def host_callback(phase, *, token, cleanup_index=None):
        assert token == "capability-cleanup"
        if phase == "hold":
            assert cleanup_index is None
            hold_threads.append(threading.get_ident())
            hold_entered.set()
            assert release_hold.wait(TIMEOUT)
            return {"released": True}
        assert phase == "cleanup"
        cleanup_calls.append((cleanup_index, threading.get_ident()))
        return {"cleanupIndex": cleanup_index}

    try:
        gdb._initialize()
        _source(gdb, FIXTURES / "callback_operations.py")
        with pytest.raises(DapTimeout, match="pwnc.test.capability-cleanup"):
            gdb.use(timeout=0.2).call(
                "pwnc.test.capability-cleanup",
                host_callback,
                token="capability-cleanup",
            )
        assert hold_entered.is_set()
        assert [index for index, _thread in cleanup_calls] == [1, 2]
        assert len(hold_threads) == 1
        assert all(thread != hold_threads[0] for _index, thread in cleanup_calls)
        snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
        assert list(snapshot["tombstones"].values())[-1]["outcome"] == "cancelled"
    finally:
        release_hold.set()
        deadline = time.monotonic() + TIMEOUT
        while gdb.operations.active_callbacks and time.monotonic() < deadline:
            time.sleep(0.01)
        gdb.close()


def test_timeout_cancellation_runs_reserved_cleanup_callbacks() -> None:
    if not _gdb_available():
        pytest.skip("live GDB is required")
    transport = DapTransport(GDB_PATH, init=False)
    gdb = Gdb(transport)
    hold_entered = threading.Event()
    release_hold = threading.Event()
    cleanup_calls = []

    def hold(token):
        assert token == "live-cleanup"
        hold_entered.set()
        assert release_hold.wait(TIMEOUT)
        return {"released": True}

    def cleanup(token, *, cleanup_index):
        assert token == "live-cleanup"
        cleanup_calls.append((cleanup_index, threading.get_ident()))
        return {"cleanupIndex": cleanup_index, "cleaned": True}

    try:
        gdb._initialize()
        _source(gdb, FIXTURES / "callback_operations.py")
        with pytest.raises(DapTimeout, match="pwnc.test.cleanup"):
            gdb.run_operation(
                "pwnc.test.cleanup",
                {"token": "live-cleanup"},
                callbacks={
                    "pwnc.test.hold": hold,
                    "pwnc.test.cleanup": cleanup,
                },
                cleanup_callbacks={"pwnc.test.cleanup"},
                timeout=0.2,
                cancel_timeout=TIMEOUT,
            )
        assert hold_entered.is_set()
        assert [index for index, _thread in cleanup_calls] == [1, 2]
        snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
        assert list(snapshot["tombstones"].values())[-1]["outcome"] == "cancelled"
    finally:
        release_hold.set()
        deadline = time.monotonic() + TIMEOUT
        while gdb.operations.active_callbacks and time.monotonic() < deadline:
            time.sleep(0.01)
        gdb.close()


def test_dispatcher_close_keeps_cleanup_delivery_alive() -> None:
    if not _gdb_available():
        pytest.skip("live GDB is required")
    transport = DapTransport(GDB_PATH, init=False)
    gdb = Gdb(transport)
    hold_entered = threading.Event()
    release_hold = threading.Event()
    cleanup_calls = []
    outcome = {}

    def hold(token):
        assert token == "close-cleanup"
        hold_entered.set()
        assert release_hold.wait(TIMEOUT)
        return {"released": True}

    def cleanup(token, *, cleanup_index):
        assert token == "close-cleanup"
        cleanup_calls.append(cleanup_index)
        return {"cleanupIndex": cleanup_index}

    def run_operation():
        try:
            outcome["value"] = gdb.run_operation(
                "pwnc.test.cleanup",
                {"token": "close-cleanup"},
                callbacks={
                    "pwnc.test.hold": hold,
                    "pwnc.test.cleanup": cleanup,
                },
                cleanup_callbacks={"pwnc.test.cleanup"},
                timeout=None,
            )
        except BaseException as error:  # noqa: BLE001 - sync API observation
            outcome["error"] = error

    runner = threading.Thread(target=run_operation, name="live-close-cleanup")
    runner_started = False
    try:
        gdb._initialize()
        _source(gdb, FIXTURES / "callback_operations.py")
        runner.start()
        runner_started = True
        assert hold_entered.wait(TIMEOUT)
        survivors = gdb.operations.close(timeout=2.0)
        assert cleanup_calls == [1, 2]
        assert any(name.startswith("pwnc-gdb-callback-") for name in survivors)
        snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
        assert list(snapshot["tombstones"].values())[-1]["outcome"] == "cancelled"
        runner.join(TIMEOUT)
        assert not runner.is_alive()
        assert "dispatcher closed" in str(outcome["error"])
    finally:
        release_hold.set()
        if runner_started:
            runner.join(TIMEOUT)
        deadline = time.monotonic() + TIMEOUT
        while gdb.operations.active_callbacks and time.monotonic() < deadline:
            time.sleep(0.01)
        gdb.close()
