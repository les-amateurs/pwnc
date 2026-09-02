"""Run untouched bata24 GEF inside the no-pump recursive DAP callback probe.

GEF is sourced byte-for-byte from the supplied path.  A separate injection
layer observes its dynamic ``gdb.execute`` calls and can be installed before
plugin loading so later captures see the wrapper.  Changing or substituting
the agreed GEF source is forbidden and guarded by an exact SHA-256 check.
"""

import argparse
import hashlib
import os
import shutil
import sys
import threading
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path

EXPERIMENTS = os.path.abspath(os.path.dirname(__file__))
REPOSITORY = os.path.abspath(os.path.join(EXPERIMENTS, "..", "..", ".."))
sys.path.insert(0, EXPERIMENTS)
sys.path.insert(0, REPOSITORY)

from rpc_probe import (
    DEADLOCK_TIMEOUT,
    TIMEOUT,
    _HostDispatcher,
    _initialize,
)

from pwnc.gdb.dap.transport import DapTransport

DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_DEFAULT_GEF_SHA256 = (
    "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
)
DEFAULT_DEPTH = 8


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _GefHostDispatcher(_HostDispatcher):
    """Use a real synchronous GEF command as each host callback's GDB work."""

    def _run_callback(self, callback):
        operation_id = callback["operationId"]
        callback_id = callback["callbackId"]
        depth = callback["depth"]
        try:
            assert callback["method"] == "probe.callback"
            assert callback["payload"] == {
                "depth": depth,
                "operationId": operation_id,
            }
            self.record_host(
                "host-callback-enter",
                operationId=operation_id,
                callbackId=callback_id,
                depth=depth,
            )

            # Native DAP reaches GEF's ordinary synchronous invoke stack while
            # the parent lowered GDB operation is suspended.  HistoryCommand
            # recursively calls gdb.execute("show commands ...") internally.
            evaluated = self.transport.request(
                "evaluate",
                {"expression": "history -n", "context": "repl"},
                timeout=TIMEOUT,
            )
            assert isinstance(evaluated["result"], str)
            self.record_host(
                "host-gef-history-returned",
                operationId=operation_id,
                depth=depth,
            )

            if depth < self.max_depth:
                nested_id, nested_future = self.start_operation(
                    depth + 1,
                    parent_operation_id=operation_id,
                )
                self.record_host(
                    "host-worker-waiting-on-child-future",
                    operationId=operation_id,
                    childOperationId=nested_id,
                    depth=depth,
                )
                nested_result = nested_future.result(timeout=DEADLOCK_TIMEOUT)
                callback_value = {"fromDepth": depth, "nested": nested_result}
            else:
                callback_value = {"fromDepth": depth, "leaf": True}

            self.record_host(
                "host-callback-reply",
                operationId=operation_id,
                callbackId=callback_id,
                depth=depth,
            )
            reply = self.transport.request(
                "rpcProbeReply",
                {
                    "operationId": operation_id,
                    "callbackId": callback_id,
                    "value": callback_value,
                },
                timeout=TIMEOUT,
            )
            assert reply["status"] == "resume-queued"
            self.record_host(
                "host-callback-return",
                operationId=operation_id,
                callbackId=callback_id,
                depth=depth,
            )
        except BaseException as error:
            with self.state_lock:
                self.callback_errors.append(error)
                pending = list(self.operation_futures.values())
            for future in pending:
                if not future.done():
                    future.set_exception(error)
            raise


def _source(transport, path):
    return transport.request(
        "evaluate",
        {"expression": "source " + os.path.abspath(path), "context": "repl"},
        timeout=TIMEOUT,
    )


def _assert_result_shape(result, max_depth):
    operation_ids = []
    current = result
    for depth in range(max_depth + 1):
        assert current["depth"] == depth
        assert current["callbackResult"]["fromDepth"] == depth
        operation_ids.append(current["operationId"])
        if depth == max_depth:
            assert current["callbackResult"] == {
                "fromDepth": depth,
                "leaf": True,
            }
        else:
            current = current["callbackResult"]["nested"]
    return operation_ids


def _assert_gef_events(events, expected_calls, gdb_thread_id):
    history_enters = [
        event
        for event in events
        if event["kind"] == "execute-enter" and event["command"] == "history -n"
    ]
    assert len(history_enters) == expected_calls
    assert all(event["depth"] == 0 for event in history_enters)

    history_returns = [
        event
        for event in events
        if event["kind"] == "execute-return" and event["command"] == "history -n"
    ]
    assert len(history_returns) == expected_calls

    nested = [
        event
        for event in events
        if event["kind"] == "execute-enter"
        and event["command"].startswith("show commands ")
    ]
    assert len(nested) >= expected_calls
    assert all(event["depth"] == 1 for event in nested)
    assert not [event for event in events if event["kind"] == "execute-error"]

    relevant = history_enters + history_returns + nested
    assert {event["threadId"] for event in relevant} == {gdb_thread_id}

    # For every untouched GEF invocation, at least one nested show-commands
    # dispatch occurs strictly inside its outer gdb.execute call.
    for entered in history_enters:
        returned = next(
            event
            for event in history_returns
            if event["seq"] > entered["seq"]
        )
        assert any(
            entered["seq"] < child["seq"] < returned["seq"]
            for child in nested
        )


def run_probe(
    gdb_path="gdb",
    gef_path=DEFAULT_GEF,
    max_depth=DEFAULT_DEPTH,
    *,
    inject_before_plugin=False,
):
    gef_path = Path(gef_path).resolve()
    if not gef_path.is_file():
        raise RuntimeError(f"bata24 GEF source is required: {gef_path}")
    if not shutil.which(gdb_path) and not os.path.isfile(gdb_path):
        raise RuntimeError("GDB is required for the live GEF RPC probe")
    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")

    digest_before = _sha256(gef_path)
    assert digest_before == EXPECTED_DEFAULT_GEF_SHA256, (
        "the GEF fixture is not the agreed bata24 source: "
        f"expected {EXPECTED_DEFAULT_GEF_SHA256}, got {digest_before}"
    )
    transport = DapTransport(gdb_path)
    dispatcher = None
    try:
        _initialize(transport)
        injection = Path(__file__).with_name("gef_injection_ext.py")
        if inject_before_plugin:
            _source(transport, injection)
            _source(transport, gef_path)
        else:
            _source(transport, gef_path)
            _source(transport, injection)

        dispatcher = _GefHostDispatcher(transport, max_depth)
        operation_id, outer_future = dispatcher.start_operation(0)
        dispatcher.record_host(
            "host-main-waiting-on-outer-future",
            operationId=operation_id,
            depth=0,
        )
        try:
            result = outer_future.result(timeout=DEADLOCK_TIMEOUT)
        except FutureTimeout as error:
            raise TimeoutError(
                "GEF callback operation did not finish; possible deadlock"
            ) from error
        dispatcher.record_host(
            "host-main-outer-future-done",
            operationId=operation_id,
            depth=0,
        )
        dispatcher.finish_workers()

        snapshot = transport.request("rpcProbeSnapshot", timeout=TIMEOUT)
        injection_snapshot = transport.request(
            "pwncGefInjectionSnapshot", timeout=TIMEOUT
        )
        operation_ids = _assert_result_shape(result, max_depth)
        assert len(snapshot["operations"]) == max_depth + 1
        assert all(
            operation["status"] == "done"
            for operation in snapshot["operations"].values()
        )
        assert not dispatcher.callback_errors

        gdb_thread_ids = {
            event["threadId"]
            for event in snapshot["trace"]
            if event["kind"] in {
                "operation-enter",
                "callback-emitted",
                "operation-resumed",
                "operation-done",
            }
        }
        assert len(gdb_thread_ids) == 1
        gdb_thread_id = next(iter(gdb_thread_ids))
        _assert_gef_events(
            injection_snapshot["events"],
            expected_calls=max_depth + 1,
            gdb_thread_id=gdb_thread_id,
        )
        assert injection_snapshot["installed"] is True

        callback_entries = [
            event
            for event in dispatcher.host_trace
            if event["kind"] == "host-callback-enter"
        ]
        callback_thread_ids = {event["threadId"] for event in callback_entries}
        assert len(callback_entries) == max_depth + 1
        assert len(callback_thread_ids) == max_depth + 1
        assert callback_thread_ids.isdisjoint(dispatcher.reader_thread_ids)
        assert threading.get_ident() not in callback_thread_ids
        assert dispatcher.worker_threads_alive_after_shutdown == []

        gdb_version = transport.request(
            "evaluate",
            {"expression": "show version", "context": "repl"},
            timeout=TIMEOUT,
        )["result"].splitlines()[0]
    finally:
        if dispatcher is not None:
            dispatcher.abort()
        transport.close()

    digest_after = _sha256(gef_path)
    assert digest_after == digest_before, "the GEF source changed during the probe"
    return {
        "callbackWorkers": max_depth + 1,
        "gefPath": str(gef_path),
        "gefSha256": digest_before,
        "gdbThreadId": gdb_thread_id,
        "gdbVersion": gdb_version,
        "injectionOrder": "before-plugin" if inject_before_plugin else "after-plugin",
        "maxDepth": max_depth,
        "nestedOperations": len(operation_ids),
        "sourceUnmodified": True,
    }


def test_unmodified_bata24_gef_inside_recursive_callbacks():
    if not DEFAULT_GEF.is_file() or not shutil.which("gdb"):
        import pytest

        pytest.skip("live GDB and bata24 GEF fixture are required")
    evidence = run_probe(max_depth=DEFAULT_DEPTH)
    assert evidence["sourceUnmodified"] is True
    assert evidence["nestedOperations"] == DEFAULT_DEPTH + 1


def test_runtime_injection_can_precede_unmodified_bata24_gef():
    if not DEFAULT_GEF.is_file() or not shutil.which("gdb"):
        import pytest

        pytest.skip("live GDB and bata24 GEF fixture are required")
    evidence = run_probe(max_depth=2, inject_before_plugin=True)
    assert evidence["injectionOrder"] == "before-plugin"
    assert evidence["sourceUnmodified"] is True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    parser.add_argument("--inject-before-plugin", action="store_true")
    arguments = parser.parse_args()
    found = run_probe(
        arguments.gdb,
        arguments.gef,
        arguments.depth,
        inject_before_plugin=arguments.inject_before_plugin,
    )
    print("PASS unmodified bata24 GEF recursive callback probe")
    for key in sorted(found):
        print(f"{key}: {found[key]}")
