"""Live proof of recursively re-entrant host callbacks over GDB DAP.

Run directly::

    python3 tests/dap/experiments/rpc_probe.py

or with pytest::

    pytest -q -s tests/dap/experiments/rpc_probe.py

The probe intentionally uses a real GDB, native DAP ``evaluate`` requests,
and a synchronous Python ``gdb.Command``.  No inferior or mock is involved.
The host uses no recursive message pump: its DAP reader only routes messages,
while normal synchronous callback bodies run on managed worker threads and
block only on Futures.

Boundary: this proves synchronous plugin execution can interleave atomically
between lowered operation suspension points.  It does not claim that an
unmodified, already-active plugin ``invoke`` frame can itself be suspended.
"""

import argparse
import os
import shutil
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout


REPOSITORY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
sys.path.insert(0, REPOSITORY)

from pwnc.gdb.dap.transport import DapTransport


TIMEOUT = 15.0
DEADLOCK_TIMEOUT = 30.0
DEFAULT_MAX_DEPTH = 32


class _HostDispatcher:
    """Route events without pumping and run every callback on a fresh worker.

    A callback worker may synchronously block on a child operation's Future.
    The DAP reader continues routing, and the child's callback is submitted to
    another worker.  Thus no blocked thread recursively reads or dispatches DAP
    messages, and no callback ever runs on the transport reader thread.
    """

    def __init__(self, transport, max_depth):
        self.transport = transport
        self.max_depth = max_depth
        self.trace = []
        self.trace_lock = threading.Lock()
        self.reader_thread_ids = set()
        self.host_trace = []
        self.host_trace_lock = threading.Lock()
        self.operation_futures = {}
        self.early_operation_events = {}
        self.state_lock = threading.RLock()
        self.callback_futures = []
        self.callback_errors = []
        self.closed = False
        self.worker_threads_alive_after_shutdown = None
        # Every ancestor callback remains blocked on its child's Future, so
        # depth N requires N+1 simultaneously live callback workers.
        self.executor = ThreadPoolExecutor(
            max_workers=max_depth + 2,
            thread_name_prefix="rpc-probe-callback",
        )

        transport.on("rpcProbeCallback", self._route_callback)
        transport.on("rpcProbeDone", self._route_done)
        transport.on("rpcProbeFailed", self._route_failed)
        transport.on("rpcProbeTrace", self._record_remote_trace)

    def _record_remote_trace(self, body):
        self.reader_thread_ids.add(threading.get_ident())
        with self.trace_lock:
            self.trace.append(body)

    def record_host(self, kind, **fields):
        with self.host_trace_lock:
            item = {
                "seq": len(self.host_trace) + 1,
                "kind": kind,
                "threadId": threading.get_ident(),
                "threadName": threading.current_thread().name,
            }
            item.update(fields)
            self.host_trace.append(item)
        return item

    def _route_callback(self, body):
        """DAP reader handler: submit and return; never execute or wait."""
        self.reader_thread_ids.add(threading.get_ident())
        with self.state_lock:
            if self.closed:
                return
            worker = self.executor.submit(self._run_callback, body)
            self.callback_futures.append(worker)

    def _resolve_operation(self, event, body):
        operation_id = body["operationId"]
        with self.state_lock:
            future = self.operation_futures.get(operation_id)
            if future is None:
                self.early_operation_events[operation_id] = (event, body)
                return
        if future.done():
            return
        if event == "done":
            future.set_result(body["result"])
        else:
            future.set_exception(
                AssertionError("GDB operation failed: %s" % body["error"])
            )

    def _route_done(self, body):
        self.reader_thread_ids.add(threading.get_ident())
        self._resolve_operation("done", body)

    def _route_failed(self, body):
        self.reader_thread_ids.add(threading.get_ident())
        self._resolve_operation("failed", body)

    def start_operation(self, depth, parent_operation_id=None):
        started = self.transport.request(
            "rpcProbeStart",
            {"depth": depth, "parentOperationId": parent_operation_id},
            timeout=TIMEOUT,
        )
        operation_id = started["operationId"]
        future = Future()
        with self.state_lock:
            if operation_id in self.operation_futures:
                raise AssertionError("duplicate operation id %d" % operation_id)
            self.operation_futures[operation_id] = future
            early = self.early_operation_events.pop(operation_id, None)
        if early is not None:
            self._resolve_operation(*early)
        self.record_host(
            "host-operation-started",
            operationId=operation_id,
            parentOperationId=parent_operation_id,
            depth=depth,
        )
        return operation_id, future

    def _run_callback(self, callback):
        """One normal synchronous callback body on one managed worker."""
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

            # Native DAP evaluate reaches the ordinary sync plugin while this
            # callback's parent GDB operation remains suspended.  The plugin
            # itself synchronously calls gdb.execute again.
            evaluated = self.transport.request(
                "evaluate",
                {
                    "expression": "rpc-probe-plugin host-evaluate-%d" % depth,
                    "context": "repl",
                },
                timeout=TIMEOUT,
            )
            assert "RPC_PROBE_PLUGIN host-evaluate-%d" % depth in evaluated["result"]
            self.record_host(
                "host-native-evaluate-returned",
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
                # This is a plain blocking Future wait, not a message pump.
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

    def finish_workers(self, timeout=DEADLOCK_TIMEOUT):
        """Join all callback work and prove the managed pool cleaned up."""
        deadline = time.monotonic() + timeout
        seen = 0
        while True:
            with self.state_lock:
                workers = list(self.callback_futures)
            for worker in workers[seen:]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("callback worker cleanup timed out")
                worker.result(timeout=remaining)
            seen = len(workers)
            # No new callback can be submitted once the outer operation is
            # done, but take the lock again to make that invariant observable.
            with self.state_lock:
                if len(self.callback_futures) == seen:
                    self.closed = True
                    break
        threads = list(self.executor._threads)  # experiment-only cleanup proof
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.worker_threads_alive_after_shutdown = [
            thread.name for thread in threads if thread.is_alive()
        ]
        if self.worker_threads_alive_after_shutdown:
            raise AssertionError(
                "callback workers survived shutdown: %r"
                % self.worker_threads_alive_after_shutdown
            )

    def abort(self):
        """Bounded failure cleanup; active waits are released before GDB closes."""
        with self.state_lock:
            if self.closed:
                return
            self.closed = True
            pending = list(self.operation_futures.values())
        error = RuntimeError("RPC probe dispatcher aborted")
        for future in pending:
            if not future.done():
                future.set_exception(error)
        self.executor.shutdown(wait=False, cancel_futures=True)


def _initialize(transport):
    transport.request(
        "initialize",
        {
            "clientID": "pwnc-rpc-probe",
            "adapterID": "gdb",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "pathFormat": "path",
        },
        timeout=TIMEOUT,
    )
    transport.wait_initialized(timeout=TIMEOUT)
    extension = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "rpc_probe_ext.py")
    )
    loaded = transport.request(
        "evaluate",
        {"expression": "source " + extension, "context": "repl"},
        timeout=TIMEOUT,
    )
    assert loaded["variablesReference"] == 0


def _index(trace, kind, operation_id=None, label=None):
    for index, item in enumerate(trace):
        if item["kind"] != kind:
            continue
        if operation_id is not None and item.get("operationId") != operation_id:
            continue
        if label is not None and item.get("label") != label:
            continue
        return index
    raise AssertionError(
        "missing trace item kind=%r operation=%r label=%r"
        % (kind, operation_id, label)
    )


def _assert_evidence(dispatcher, snapshot, result, max_depth):
    trace = snapshot["trace"]
    assert snapshot["lowering"] == {
        "sourceUsesAsyncDef": True,
        "sourceUsesAwait": True,
        "resultIsGeneratorFunction": True,
        "resultIsCoroutineFunction": False,
    }
    assert len(snapshot["operations"]) == max_depth + 1
    assert all(op["status"] == "done" for op in snapshot["operations"].values())

    # The nested result shape proves the host callback Python stack recursively
    # entered further GDB operations before replying to the outer one.  Each
    # link was produced by a worker blocked only on its child Future.
    results = []
    current = result
    for depth in range(max_depth + 1):
        assert current["depth"] == depth
        assert current["callbackResult"]["fromDepth"] == depth
        assert "RPC_PROBE_PLUGIN operation-before-%d" % depth in current["before"]
        assert "RPC_PROBE_PLUGIN operation-after-%d" % depth in current["after"]
        results.append(current)
        if depth < max_depth:
            current = current["callbackResult"]["nested"]
        else:
            assert current["callbackResult"] == {"fromDepth": depth, "leaf": True}

    # All GDB API work, including synchronous plugin invocations reached both
    # directly and through native DAP evaluate, ran on one GDB main thread.
    gdb_kinds = {
        "lowered-task-created",
        "operation-enter",
        "plugin-enter",
        "plugin-nested-execute",
        "plugin-return",
        "operation-before-returned",
        "callback-emitted",
        "callback-resume-dispatched",
        "operation-resumed",
        "operation-after-returned",
        "operation-done",
    }
    gdb_thread_ids = {item["threadId"] for item in trace if item["kind"] in gdb_kinds}
    dap_thread_ids = {
        item["threadId"]
        for item in trace
        if item["kind"] in {"dap-start-accepted", "dap-reply-accepted"}
    }
    assert len(gdb_thread_ids) == 1
    assert len(dap_thread_ids) == 1
    assert gdb_thread_ids.isdisjoint(dap_thread_ids)

    # Event handlers only routed messages.  Callback bodies ran synchronously
    # on managed workers, never on the reader or test-main thread.
    assert len(dispatcher.reader_thread_ids) == 1
    callback_entries = [
        item
        for item in dispatcher.host_trace
        if item["kind"] == "host-callback-enter"
    ]
    callback_thread_ids = {item["threadId"] for item in callback_entries}
    assert len(callback_entries) == max_depth + 1
    # Every ancestor worker is blocked on a Future when its descendant starts,
    # so a successful depth-N run must have one distinct worker per callback.
    assert len(callback_thread_ids) == max_depth + 1
    assert callback_thread_ids.isdisjoint(dispatcher.reader_thread_ids)
    assert threading.get_ident() not in callback_thread_ids
    assert dispatcher.worker_threads_alive_after_shutdown == []
    assert not dispatcher.callback_errors
    for item in callback_entries:
        assert item["threadName"].startswith("rpc-probe-callback")

    callback_threads_by_depth = {
        depth: {
            item["threadId"]
            for item in callback_entries
            if item["depth"] == depth
        }
        for depth in range(max_depth + 1)
    }
    assert all(len(ids) == 1 for ids in callback_threads_by_depth.values())

    operation_ids = [entry["operationId"] for entry in results]
    for depth, operation_id in enumerate(operation_ids):
        emitted = _index(trace, "callback-emitted", operation_id=operation_id)
        resumed = _index(trace, "operation-resumed", operation_id=operation_id)
        host_plugin_entered = _index(
            trace, "plugin-enter", label="host-evaluate-%d" % depth
        )
        assert emitted < host_plugin_entered < resumed

        # All plugin paths really performed their internal nested gdb.execute.
        for label in (
            "operation-before-%d" % depth,
            "host-evaluate-%d" % depth,
            "operation-after-%d" % depth,
        ):
            entered = _index(trace, "plugin-enter", label=label)
            nested = _index(trace, "plugin-nested-execute", label=label)
            returned = _index(trace, "plugin-return", label=label)
            assert entered < nested < returned

    # Every child completes before its blocked parent worker sends the value
    # which resumes the parent operation.
    for parent_index in range(len(operation_ids) - 1):
        child_id = operation_ids[parent_index + 1]
        parent_id = operation_ids[parent_index]
        assert _index(trace, "operation-done", child_id) < _index(
            trace, "operation-resumed", parent_id
        )

    return {
        "gdbThreadId": next(iter(gdb_thread_ids)),
        "dapThreadId": next(iter(dap_thread_ids)),
        "hostReaderThreadId": next(iter(dispatcher.reader_thread_ids)),
        "hostMainThreadId": threading.get_ident(),
        "hostCallbackWorkerCount": len(callback_thread_ids),
        "callbackWorkersCleanedUp": True,
        "maxDepth": max_depth,
        "operationIds": operation_ids,
        "gdbTraceEntries": len(trace),
        "hostTraceEntries": len(dispatcher.host_trace),
        "operationSourceLowered": True,
    }


def run_probe(gdb_path="gdb", max_depth=DEFAULT_MAX_DEPTH):
    if not shutil.which(gdb_path):
        raise RuntimeError("GDB is required for the live RPC probe")
    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")
    transport = DapTransport(gdb_path)
    dispatcher = None
    try:
        _initialize(transport)
        dispatcher = _HostDispatcher(transport, max_depth)
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
                "outer operation did not finish; possible DAP/GDB deadlock"
            ) from error
        dispatcher.record_host(
            "host-main-outer-future-done",
            operationId=operation_id,
            depth=0,
        )
        dispatcher.finish_workers()
        snapshot = transport.request("rpcProbeSnapshot", timeout=TIMEOUT)
        evidence = _assert_evidence(dispatcher, snapshot, result, max_depth)
        evidence["gdbVersion"] = transport.request(
            "evaluate",
            {"expression": "show version", "context": "repl"},
            timeout=TIMEOUT,
        )["result"].splitlines()[0]
        return evidence
    finally:
        if dispatcher is not None:
            dispatcher.abort()
        transport.close()


def test_live_recursive_rpc_probe():
    if not shutil.which("gdb"):
        try:
            import pytest

            pytest.skip("GDB is required for the live RPC probe")
        except ImportError:
            return
    evidence = run_probe(max_depth=DEFAULT_MAX_DEPTH)
    assert evidence["operationIds"] == list(range(1, DEFAULT_MAX_DEPTH + 2))
    assert evidence["hostCallbackWorkerCount"] == DEFAULT_MAX_DEPTH + 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--depth", type=int, default=DEFAULT_MAX_DEPTH)
    arguments = parser.parse_args()
    found = run_probe(arguments.gdb, arguments.depth)
    print("PASS recursive DAP/GDB callback probe")
    for key in sorted(found):
        print("%s: %s" % (key, found[key]))
