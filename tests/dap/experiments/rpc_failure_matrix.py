"""Live GDB DAP concurrency, failure, and cleanup matrix.

This probe has no asyncio, greenlet, or recursive message pump.  Transport
event handlers only update protocol state or condition-backed completion
cells; they never run arbitrary completion callbacks.  Each admitted
synchronous callback gets a dedicated ordinary OS thread, so an ancestor may
block on a child completion without starving unrelated roots or descendants.

The workload is deliberately bounded.  This probe applies explicit, atomic
depth/active-callback admission limits when configured; its diagnostic trace
lists remain intentionally unbounded even though its active-operation registry
and protocol tombstones are lifecycle-checked here.

Run with the repository's real GEF fixture required::

    python3 tests/dap/experiments/rpc_failure_matrix.py --require-gef
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any

try:
    import pytest
except ImportError:  # Direct probe execution does not require pytest.
    pytest = None


REPOSITORY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, REPOSITORY)

from pwnc.gdb.dap.transport import DapError, DapTransport

DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_GEF_SHA256 = (
    "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
)
REQUEST_TIMEOUT = 15.0
DEADLOCK_TIMEOUT = 45.0
CONCURRENT_ROOTS = 6
CONCURRENT_MAX_DEPTH = 5
FAILURE_MAX_DEPTH = 4
ADMISSION_ACTIVE_LIMIT = 3
ADMISSION_OVERFLOW_COUNT = 4
ADMISSION_DEPTH_LIMIT = 1
# Two sequential cleanup effects can briefly have overlapping host workers:
# GDB may emit the second effect after accepting the first reply but before the
# first worker has observed that response and returned. Reserve both slots so
# cancellation cleanup remains bounded without depending on thread scheduling.
ADMISSION_CLEANUP_RESERVE = 2


class MatrixOperationFailed(RuntimeError):
    def __init__(self, body: dict[str, Any]):
        self.body = body
        detail = body["error"]
        super().__init__(
            "operation {} failed: {}: {}".format(
                body["operationId"],
                detail.get("type", "Error"),
                detail.get("message", ""),
            )
        )


class MatrixOperationCancelled(RuntimeError):
    def __init__(self, body: dict[str, Any]):
        self.body = body
        super().__init__("operation {} was cancelled".format(body["operationId"]))


class InjectedCallbackFailure(RuntimeError):
    pass


class CompletionCell:
    """Condition-only completion with no inline callback execution surface."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._done = False
        self._result: Any = None
        self._exception: BaseException | None = None
        self.waiter_thread_ids: set[int] = set()

    def done(self) -> bool:
        with self._condition:
            return self._done

    def result(self, timeout: float | None = None) -> Any:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while not self._done:
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FutureTimeout()
                self._condition.wait(remaining)
            self.waiter_thread_ids.add(threading.get_ident())
            if self._exception is not None:
                raise self._exception
            return self._result

    def set_result(self, result: Any) -> bool:
        return self._complete(result=result)

    def set_exception(self, exception: BaseException) -> bool:
        return self._complete(exception=exception)

    def _complete(
        self,
        *,
        result: Any = None,
        exception: BaseException | None = None,
    ) -> bool:
        with self._condition:
            if self._done:
                return False
            self._done = True
            self._result = result
            self._exception = exception
            self._condition.notify_all()
            return True


class _ReplyOnce:
    """Select exactly one value/error outcome for one host callback."""

    def __init__(self, dispatcher: DynamicCallbackDispatcher, body: dict[str, Any]):
        self.dispatcher = dispatcher
        self.body = body
        self._lock = threading.Lock()
        self._selected: str | None = None

    @property
    def selected(self) -> str | None:
        with self._lock:
            return self._selected

    def _claim(self, kind: str) -> None:
        with self._lock:
            if self._selected is not None:
                raise AssertionError(
                    f"callback {self.body['callbackId']} already selected "
                    f"{self._selected}"
                )
            self._selected = kind
        self.dispatcher.record_host(
            "reply-selected",
            operationId=self.body["operationId"],
            callbackId=self.body["callbackId"],
            rootToken=self.body["rootToken"],
            depth=self.body["depth"],
            replyKind=kind,
        )

    def value(self, value: Any) -> dict[str, Any]:
        self._claim("value")
        return self.dispatcher.transport.request(
            "rpcMatrixReply",
            {
                "operationId": self.body["operationId"],
                "callbackId": self.body["callbackId"],
                "kind": "value",
                "value": value,
            },
            timeout=REQUEST_TIMEOUT,
        )

    def error(self, error: BaseException) -> dict[str, Any]:
        self._claim("error")
        return self.dispatcher.transport.request(
            "rpcMatrixReply",
            {
                "operationId": self.body["operationId"],
                "callbackId": self.body["callbackId"],
                "kind": "error",
                "error": {
                    "type": type(error).__name__,
                    "module": type(error).__module__,
                    "message": str(error),
                },
            },
            timeout=REQUEST_TIMEOUT,
        )


class DynamicCallbackDispatcher:
    """One-thread-per-admitted-callback synchronous dispatcher.

    The reader atomically reserves an active slot before constructing a worker.
    Rejections use :meth:`DapTransport.send` and therefore never wait for their
    error reply on the transport reader thread.
    """

    def __init__(
        self,
        transport: DapTransport,
        *,
        max_active_callbacks: int | None = None,
        max_callback_depth: int | None = None,
        cleanup_callback_reserve: int = ADMISSION_CLEANUP_RESERVE,
        thread_factory: Callable[..., threading.Thread] = threading.Thread,
    ):
        if max_active_callbacks is not None and (
            isinstance(max_active_callbacks, bool) or max_active_callbacks < 1
        ):
            raise ValueError("max_active_callbacks must be positive or None")
        if max_callback_depth is not None and (
            isinstance(max_callback_depth, bool) or max_callback_depth < 0
        ):
            raise ValueError("max_callback_depth must be nonnegative or None")
        if (
            isinstance(cleanup_callback_reserve, bool)
            or cleanup_callback_reserve < 0
        ):
            raise ValueError("cleanup_callback_reserve must be nonnegative")
        self.transport = transport
        self.max_active_callbacks = max_active_callbacks
        self.max_callback_depth = max_callback_depth
        self.cleanup_callback_reserve = cleanup_callback_reserve
        self.thread_factory = thread_factory
        self.lock = threading.RLock()
        self.callback_condition = threading.Condition(self.lock)
        self.callback_context = threading.local()
        self.closed = False
        self.reader_thread_ids: set[int] = set()
        self.operation_futures: dict[int, CompletionCell] = {}
        self.operation_cells: list[CompletionCell] = []
        self.early_outcomes: dict[int, tuple[str, dict[str, Any]]] = {}
        self.completed: dict[int, tuple[str, dict[str, Any]]] = {}
        self.callbacks: list[dict[str, Any]] = []
        self.callbacks_by_root: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.callback_seen: dict[str, threading.Event] = defaultdict(threading.Event)
        self.threads: list[threading.Thread] = []
        self.active_workers = 0
        self.active_ordinary_workers = 0
        self.active_cleanup_workers = 0
        self.peak_active_workers = 0
        self.peak_active_ordinary_workers = 0
        self.peak_active_cleanup_workers = 0
        self.worker_entries: list[dict[str, Any]] = []
        self.worker_start_failures: list[dict[str, Any]] = []
        self.lineage_rejections: list[dict[str, Any]] = []
        self.reply_guards: dict[int, _ReplyOnce] = {}
        self.reply_results: list[dict[str, Any]] = []
        self.admission_rejections: list[dict[str, Any]] = []
        self.admission_reply_futures: list[tuple[dict[str, Any], Future]] = []
        self.collected_admission_reply_ids: set[int] = set()
        self.admission_reply_responses: list[dict[str, Any]] = []
        self.intentional_rejections: list[dict[str, Any]] = []
        self.fatal_errors: list[BaseException] = []
        self.host_trace: list[dict[str, Any]] = []
        self.remote_trace: list[dict[str, Any]] = []
        self.barriers: dict[str, threading.Barrier] = {}
        self.hold_releases: dict[str, threading.Event] = defaultdict(threading.Event)
        self.cleanup_releases: dict[tuple[str, int], threading.Event] = defaultdict(
            threading.Event
        )
        self.cleanup_post_reply_releases: dict[str, threading.Event] = defaultdict(
            threading.Event
        )
        self.gef_results: list[dict[str, Any]] = []

        transport.on("rpcMatrixCallback", self._route_callback)
        transport.on("rpcMatrixDone", lambda body: self._route_outcome("done", body))
        transport.on(
            "rpcMatrixFailed", lambda body: self._route_outcome("failed", body)
        )
        transport.on(
            "rpcMatrixCancelled",
            lambda body: self._route_outcome("cancelled", body),
        )
        transport.on("rpcMatrixTrace", self._route_trace)

    def record_host(self, kind: str, **fields: Any) -> dict[str, Any]:
        with self.lock:
            item = {
                "seq": len(self.host_trace) + 1,
                "kind": kind,
                "threadId": threading.get_ident(),
                "threadName": threading.current_thread().name,
            }
            item.update(fields)
            self.host_trace.append(item)
            return item

    def _mark_reader(self) -> None:
        with self.lock:
            self.reader_thread_ids.add(threading.get_ident())

    def _route_trace(self, body: dict[str, Any]) -> None:
        self._mark_reader()
        with self.lock:
            self.remote_trace.append(body)

    def _route_callback(self, body: dict[str, Any]) -> None:
        """Reader handler: atomically admit or queue an error reply and return."""
        self._mark_reader()
        thread: threading.Thread | None = None
        worker_class = "cleanup" if body.get("method") == "matrix.cleanup" else "ordinary"
        with self.lock:
            if self.closed:
                return
            callback = dict(body)
            self.callbacks.append(callback)
            self.callbacks_by_root[callback["rootToken"]].append(callback)
            self.callback_seen[callback["rootToken"]].set()
            if callback["method"] == "matrix.cleanup":
                cleanup_index = int(callback["payload"]["cleanupIndex"])
                self.cleanup_releases[(callback["rootToken"], cleanup_index)]
            elif callback["mode"] in {
                "admission-hold",
                "cancel-cleanup",
                "cancel-cleanup-overlap",
                "hold-cancel",
                "malformed-hold",
            }:
                self.hold_releases[callback["rootToken"]]
            self.callback_condition.notify_all()

            rejection_kind: str | None = None
            rejection_reason: str | None = None
            depth = int(callback["depth"])
            if depth < 0:
                rejection_kind = "depth"
                rejection_reason = f"callback depth {depth} must be nonnegative"
            elif (
                self.max_callback_depth is not None
                and depth > self.max_callback_depth
            ):
                rejection_kind = "depth"
                rejection_reason = (
                    f"callback depth {depth} exceeds configured maximum "
                    f"{self.max_callback_depth}"
                )
            elif worker_class == "cleanup" and (
                self.cleanup_callback_reserve == 0
                or self.active_cleanup_workers >= self.cleanup_callback_reserve
            ):
                rejection_kind = "cleanup"
                rejection_reason = (
                    "cleanup callback reserve "
                    f"{self.cleanup_callback_reserve} exhausted"
                )
            elif worker_class == "ordinary" and (
                self.max_active_callbacks is not None
                and self.active_ordinary_workers >= self.max_active_callbacks
            ):
                rejection_kind = "active"
                rejection_reason = (
                    f"active callback limit {self.max_active_callbacks} reached"
                )

            if rejection_kind is not None:
                rejection = {
                    "kind": rejection_kind,
                    "reason": rejection_reason,
                    "operationId": callback["operationId"],
                    "callbackId": callback["callbackId"],
                    "rootToken": callback["rootToken"],
                    "depth": depth,
                    "activeAtRejection": self.active_workers,
                    "activeOrdinaryAtRejection": self.active_ordinary_workers,
                    "activeCleanupAtRejection": self.active_cleanup_workers,
                    "threadCountAtRejection": len(self.threads),
                    "readerThreadId": threading.get_ident(),
                }
                self.admission_rejections.append(rejection)
            else:
                # The lock covers the capacity check, construction, and
                # reservation. A constructor failure therefore cannot leak a
                # slot, and no competing route can cross the configured cap.
                try:
                    thread = self.thread_factory(
                        target=self._run_callback,
                        args=(callback, worker_class),
                        name=f"rpc-matrix-callback-{callback['callbackId']}",
                        daemon=True,
                    )
                except BaseException as error:  # noqa: BLE001 - injected factories
                    rejection_kind = "worker"
                    rejection_reason = f"callback worker construction failed: {error}"
                    self.worker_start_failures.append(
                        {
                            "phase": "construction",
                            "operationId": callback["operationId"],
                            "callbackId": callback["callbackId"],
                            "error": repr(error),
                        }
                    )
                else:
                    self._reserve_worker_slot_locked(worker_class)
                    self.threads.append(thread)

        if rejection_kind is not None:
            assert rejection_reason is not None
            self.record_host(
                "admission-rejected",
                operationId=callback["operationId"],
                callbackId=callback["callbackId"],
                rootToken=callback["rootToken"],
                depth=callback["depth"],
                rejectionKind=rejection_kind,
            )
            self._send_admission_error(
                callback,
                rejection_reason,
                error_type=(
                    "CallbackWorkerError"
                    if rejection_kind == "worker"
                    else "CallbackAdmissionError"
                ),
            )
            return

        assert thread is not None
        try:
            thread.start()
        except BaseException as error:  # noqa: BLE001 - do not strand reservation
            with self.lock:
                # Standard Thread.start failures occur before a thread owns the
                # target. If a custom factory did start it despite raising, the
                # worker remains responsible for its own reservation.
                if thread.ident is None:
                    self.threads.remove(thread)
                    self._release_worker_slot_locked(worker_class)
                self.worker_start_failures.append(
                    {
                        "phase": "start",
                        "operationId": callback["operationId"],
                        "callbackId": callback["callbackId"],
                        "error": repr(error),
                    }
                )
            self._send_admission_error(
                callback,
                f"callback worker could not start: {error}",
                error_type="CallbackWorkerError",
            )

    def _reserve_worker_slot_locked(self, worker_class: str) -> None:
        self.active_workers += 1
        self.peak_active_workers = max(self.peak_active_workers, self.active_workers)
        if worker_class == "cleanup":
            self.active_cleanup_workers += 1
            self.peak_active_cleanup_workers = max(
                self.peak_active_cleanup_workers,
                self.active_cleanup_workers,
            )
        else:
            self.active_ordinary_workers += 1
            self.peak_active_ordinary_workers = max(
                self.peak_active_ordinary_workers,
                self.active_ordinary_workers,
            )

    def _release_worker_slot_locked(self, worker_class: str) -> None:
        self.active_workers -= 1
        if worker_class == "cleanup":
            self.active_cleanup_workers -= 1
        else:
            self.active_ordinary_workers -= 1
        if min(
            self.active_workers,
            self.active_ordinary_workers,
            self.active_cleanup_workers,
        ) < 0:
            raise AssertionError("callback worker reservation underflow")

    def _send_admission_error(
        self,
        callback: dict[str, Any],
        reason: str,
        *,
        error_type: str = "CallbackAdmissionError",
    ) -> None:
        """Queue a host error without blocking or creating a callback worker."""
        try:
            future = self.transport.send(
                "rpcMatrixReply",
                {
                    "operationId": callback["operationId"],
                    "callbackId": callback["callbackId"],
                    "kind": "error",
                    "error": {
                        "type": error_type,
                        "module": __name__,
                        "message": reason,
                    },
                },
            )
        except BaseException as error:  # noqa: BLE001 - contain reader failures
            self._record_fatal(error)
            return
        with self.lock:
            self.admission_reply_futures.append((dict(callback), future))

    def _route_outcome(self, outcome: str, body: dict[str, Any]) -> None:
        self._mark_reader()
        operation_id = body["operationId"]
        with self.lock:
            future = self.operation_futures.pop(operation_id, None)
            self.completed[operation_id] = (outcome, body)
            if future is None:
                if not self.closed:
                    self.early_outcomes[operation_id] = (outcome, body)
                return
        self._complete_future(future, outcome, body)

    @staticmethod
    def _complete_future(
        future: CompletionCell,
        outcome: str,
        body: dict[str, Any],
    ) -> None:
        if future.done():
            return
        if outcome == "done":
            future.set_result(body["result"])
        elif outcome == "cancelled":
            future.set_exception(MatrixOperationCancelled(body))
        else:
            future.set_exception(MatrixOperationFailed(body))

    def start_operation(
        self,
        *,
        root_token: str,
        depth: int | None = None,
        max_depth: int = 0,
        parent_operation_id: int | None = None,
        mode: str = "success",
        failure_depth: int | None = None,
        run_gef: bool = False,
        barrier_token: str | None = None,
    ) -> tuple[int, CompletionCell]:
        callback_parent = getattr(self.callback_context, "body", None)
        if callback_parent is None:
            if parent_operation_id is not None:
                raise ValueError("a root operation cannot claim a callback parent")
            if depth not in {None, 0}:
                raise ValueError("root operation depth must be zero")
            derived_depth = 0
        else:
            expected_parent_id = int(callback_parent["operationId"])
            expected_depth = int(callback_parent["depth"]) + 1
            if parent_operation_id not in {None, expected_parent_id}:
                raise ValueError("child operation parent does not match callback lineage")
            if depth not in {None, expected_depth}:
                raise ValueError("child operation depth does not match callback lineage")
            if root_token != callback_parent["rootToken"]:
                raise ValueError("child operation root token does not match parent")
            if max_depth != int(callback_parent["maxDepth"]):
                raise ValueError("child operation max depth does not match parent")
            if mode != callback_parent["mode"]:
                raise ValueError("child operation mode does not match parent")
            if failure_depth != callback_parent.get("failureDepth"):
                raise ValueError("child operation failure depth does not match parent")
            if run_gef != bool(callback_parent.get("runGef", False)):
                raise ValueError("child operation GEF setting does not match parent")
            if barrier_token != callback_parent.get("barrierToken"):
                raise ValueError("child operation barrier does not match parent")
            parent_operation_id = expected_parent_id
            derived_depth = expected_depth

        body = self.transport.request(
            "rpcMatrixStart",
            {
                "rootToken": root_token,
                "depth": derived_depth,
                "maxDepth": max_depth,
                "parentOperationId": parent_operation_id,
                "mode": mode,
                "failureDepth": failure_depth,
                "runGef": run_gef,
                "barrierToken": barrier_token,
            },
            timeout=REQUEST_TIMEOUT,
        )
        operation_id = body["operationId"]
        future = CompletionCell()
        with self.lock:
            if operation_id in self.operation_futures:
                raise AssertionError(f"duplicate operation id {operation_id}")
            self.operation_futures[operation_id] = future
            self.operation_cells.append(future)
            early = self.early_outcomes.pop(operation_id, None)
        if early is not None:
            with self.lock:
                self.operation_futures.pop(operation_id, None)
            self._complete_future(future, *early)
        self.record_host(
            "operation-started",
            operationId=operation_id,
            parentOperationId=parent_operation_id,
            rootToken=root_token,
            depth=derived_depth,
        )
        return operation_id, future

    def _run_callback(self, body: dict[str, Any], worker_class: str) -> None:
        callback_id = body["callbackId"]
        guard = _ReplyOnce(self, body)
        with self.lock:
            self.reply_guards[callback_id] = guard
            self.worker_entries.append(
                {
                    "callbackId": callback_id,
                    "operationId": body["operationId"],
                    "rootToken": body["rootToken"],
                    "depth": body["depth"],
                    "workerClass": worker_class,
                    "threadId": threading.get_ident(),
                    "threadName": threading.current_thread().name,
                }
            )
        self.record_host(
            "callback-enter",
            operationId=body["operationId"],
            callbackId=callback_id,
            rootToken=body["rootToken"],
            depth=body["depth"],
        )
        try:
            self.callback_context.body = body
            try:
                value = self._callback_value(body)
            except BaseException as error:  # noqa: BLE001 - callback errors cross RPC
                reply = guard.error(error)
            else:
                reply = guard.value(value)
            assert reply["status"] == "resume-queued"
            assert reply["kind"] == guard.selected
            with self.lock:
                self.reply_results.append(reply)

            if (
                body["mode"] == "cancel-cleanup-overlap"
                and body["method"] == "matrix.cleanup"
                and body["payload"]["cleanupIndex"] == 1
            ):
                self.record_host(
                    "cleanup-post-reply-held",
                    operationId=body["operationId"],
                    callbackId=callback_id,
                    rootToken=body["rootToken"],
                )
                if not self.cleanup_post_reply_releases[body["rootToken"]].wait(
                    DEADLOCK_TIMEOUT
                ):
                    raise TimeoutError("cleanup post-reply worker was not released")

            if body["mode"] == "duplicate" and body["depth"] == 0:
                self._assert_raw_reply_rejected(body, "duplicate")
        except DapError as error:
            # A held callback is deliberately invalidated by cancellation; a
            # disconnect deliberately closes the transport underneath it.
            with self.lock:
                cancelled_origin = (
                    body["mode"] in {"cancel-cleanup", "cancel-cleanup-overlap"}
                    and body["method"] == "matrix.callback"
                )
                expected = (
                    self.closed
                    or body["mode"] == "hold-cancel"
                    or cancelled_origin
                )
            if expected:
                with self.lock:
                    self.intentional_rejections.append(
                        {
                            "kind": "cancel-or-disconnect",
                            "operationId": body["operationId"],
                            "callbackId": callback_id,
                            "message": str(error),
                        }
                    )
            else:
                self._record_fatal(error)
        except BaseException as error:  # noqa: BLE001 - worker must release waiters
            self._record_fatal(error)
        finally:
            self.callback_context.body = None
            self.record_host(
                "callback-return",
                operationId=body["operationId"],
                callbackId=callback_id,
                rootToken=body["rootToken"],
                depth=body["depth"],
                replyKind=guard.selected,
            )
            with self.lock:
                self._release_worker_slot_locked(worker_class)
                self.callback_condition.notify_all()

    def _callback_value(self, body: dict[str, Any]) -> dict[str, Any]:
        if body["method"] == "matrix.cleanup":
            payload = body["payload"]
            cleanup_index = payload.get("cleanupIndex")
            if payload != {
                "operationId": body["operationId"],
                "rootToken": body["rootToken"],
                "depth": body["depth"],
                "cleanupIndex": cleanup_index,
            } or cleanup_index not in {1, 2}:
                raise AssertionError("cleanup callback payload does not match envelope")
            self.record_host(
                "cleanup-held",
                operationId=body["operationId"],
                callbackId=body["callbackId"],
                rootToken=body["rootToken"],
                cleanupIndex=cleanup_index,
            )
            release = self.cleanup_releases[(body["rootToken"], cleanup_index)]
            if not release.wait(DEADLOCK_TIMEOUT):
                raise TimeoutError("cleanup callback was not released")
            self.record_host(
                "cleanup-returning",
                operationId=body["operationId"],
                callbackId=body["callbackId"],
                rootToken=body["rootToken"],
                cleanupIndex=cleanup_index,
            )
            return {"cleanupIndex": cleanup_index, "cleaned": True}

        if body["method"] != "matrix.callback":
            raise AssertionError(
                "unexpected callback method {!r}".format(body["method"])
            )
        if body["payload"] != {
            "operationId": body["operationId"],
            "rootToken": body["rootToken"],
            "depth": body["depth"],
        }:
            raise AssertionError("callback payload does not match envelope")

        depth = body["depth"]
        if body["runGef"] and depth == 0:
            evaluated = self.transport.request(
                "evaluate",
                {"expression": "history -n", "context": "repl"},
                timeout=REQUEST_TIMEOUT,
            )
            with self.lock:
                self.gef_results.append(evaluated)
            self.record_host(
                "gef-command-returned",
                operationId=body["operationId"],
                callbackId=body["callbackId"],
            )

        if body["mode"] in {
            "admission-hold",
            "cancel-cleanup",
            "cancel-cleanup-overlap",
            "hold-cancel",
            "malformed-hold",
        }:
            release = self.hold_releases[body["rootToken"]]
            self.record_host(
                "callback-held",
                operationId=body["operationId"],
                callbackId=body["callbackId"],
            )
            if not release.wait(DEADLOCK_TIMEOUT):
                raise TimeoutError("held callback was not released")
            return {"held": True}

        failure_depth = body.get("failureDepth")
        if body["mode"] == "lineage-reset" and depth == 0:
            try:
                self.start_operation(
                    root_token=body["rootToken"],
                    depth=0,
                    max_depth=body["maxDepth"],
                    parent_operation_id=None,
                    mode=body["mode"],
                    failure_depth=failure_depth,
                    run_gef=bool(body["runGef"]),
                    barrier_token=body.get("barrierToken"),
                )
            except ValueError as error:
                with self.lock:
                    self.lineage_rejections.append(
                        {
                            "operationId": body["operationId"],
                            "callbackId": body["callbackId"],
                            "message": str(error),
                        }
                    )
                return {"lineageResetRejected": True}
            raise AssertionError("callback lineage reset was unexpectedly accepted")

        if body["mode"] == "failure" and depth == failure_depth:
            raise InjectedCallbackFailure(
                f"injected failure at {body['rootToken']} depth {depth}"
            )

        if depth < body["maxDepth"]:
            child_id, child_future = self.start_operation(
                root_token=body["rootToken"],
                depth=depth + 1,
                max_depth=body["maxDepth"],
                parent_operation_id=body["operationId"],
                mode=body["mode"],
                failure_depth=failure_depth,
                run_gef=bool(body["runGef"]),
                barrier_token=body.get("barrierToken"),
            )
            self.record_host(
                "callback-waiting-child",
                operationId=body["operationId"],
                childOperationId=child_id,
                rootToken=body["rootToken"],
                depth=depth,
            )
            child_result = child_future.result(timeout=DEADLOCK_TIMEOUT)
            return {"fromDepth": depth, "child": child_result}

        barrier_token = body.get("barrierToken")
        if barrier_token is not None:
            barrier = self.barriers[barrier_token]
            self.record_host(
                "leaf-barrier-enter",
                operationId=body["operationId"],
                rootToken=body["rootToken"],
                depth=depth,
            )
            barrier.wait(timeout=DEADLOCK_TIMEOUT)
            self.record_host(
                "leaf-barrier-return",
                operationId=body["operationId"],
                rootToken=body["rootToken"],
                depth=depth,
            )
        return {"fromDepth": depth, "leaf": True}

    def _assert_raw_reply_rejected(
        self,
        body: dict[str, Any],
        rejection_kind: str,
        *,
        malformed_error: bool = False,
    ) -> DapError:
        arguments: dict[str, Any] = {
            "operationId": body["operationId"],
            "callbackId": body["callbackId"],
            "kind": "value",
            "value": {"should": "be rejected"},
        }
        if malformed_error:
            arguments = {
                "operationId": body["operationId"],
                "callbackId": body["callbackId"],
                "kind": "error",
                "error": "not-an-object",
            }
        try:
            self.transport.request(
                "rpcMatrixReply",
                arguments,
                timeout=REQUEST_TIMEOUT,
            )
        except DapError as error:
            with self.lock:
                self.intentional_rejections.append(
                    {
                        "kind": rejection_kind,
                        "operationId": body["operationId"],
                        "callbackId": body["callbackId"],
                        "message": str(error),
                    }
                )
            return error
        raise AssertionError(f"{rejection_kind} reply was unexpectedly accepted")

    def wait_for_callback(
        self,
        root_token: str,
        timeout: float = REQUEST_TIMEOUT,
    ) -> dict[str, Any]:
        return self.wait_for_matching_callback(root_token, timeout=timeout)

    def wait_for_matching_callback(
        self,
        root_token: str,
        *,
        method: str | None = None,
        cleanup_index: int | None = None,
        timeout: float = REQUEST_TIMEOUT,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        with self.callback_condition:
            while True:
                for callback in self.callbacks_by_root[root_token]:
                    if method is not None and callback["method"] != method:
                        continue
                    if cleanup_index is not None and (
                        callback.get("payload", {}).get("cleanupIndex")
                        != cleanup_index
                    ):
                        continue
                    return dict(callback)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"callback {root_token!r} was not emitted")
                self.callback_condition.wait(remaining)

    def release_hold(self, root_token: str) -> None:
        self.hold_releases[root_token].set()

    def release_cleanup(self, root_token: str, cleanup_index: int) -> None:
        self.cleanup_releases[(root_token, cleanup_index)].set()

    def release_cleanup_post_reply(self, root_token: str) -> None:
        self.cleanup_post_reply_releases[root_token].set()

    def wait_for_active_workers(
        self,
        expected: int,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                if self.active_workers == expected:
                    return
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"active callback count did not become {expected}"
                )
            time.sleep(0.005)

    def wait_admission_replies(self, timeout: float = REQUEST_TIMEOUT) -> None:
        with self.lock:
            pending = list(self.admission_reply_futures)
        deadline = time.monotonic() + timeout
        for callback, future in pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("admission error reply timed out")
            response = future.result(timeout=remaining)
            assert response["success"] is True
            future_id = id(future)
            with self.callback_condition:
                if future_id in self.collected_admission_reply_ids:
                    continue
                self.collected_admission_reply_ids.add(future_id)
                self.admission_reply_responses.append(
                    {
                        "operationId": callback["operationId"],
                        "callbackId": callback["callbackId"],
                        "threadId": threading.get_ident(),
                        "threadName": threading.current_thread().name,
                        "response": response,
                    }
                )
                self.callback_condition.notify_all()

    def _record_fatal(self, error: BaseException) -> None:
        with self.lock:
            self.fatal_errors.append(error)
            futures = list(self.operation_futures.values())
        for future in futures:
            if not future.done():
                future.set_exception(error)

    def wait_workers_idle(self, timeout: float = DEADLOCK_TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        seen = 0
        while True:
            with self.lock:
                threads = list(self.threads)
            for thread in threads[seen:]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("callback worker cleanup timed out")
                thread.join(remaining)
                if thread.is_alive():
                    raise TimeoutError(f"callback worker {thread.name} did not stop")
            seen = len(threads)
            with self.lock:
                if len(self.threads) == seen and self.active_workers == 0:
                    return

    def abort(self, reason: str = "dispatcher aborted") -> None:
        with self.lock:
            self.closed = True
            releases = list(self.hold_releases.values())
            cleanup_releases = list(self.cleanup_releases.values())
            cleanup_post_reply_releases = list(
                self.cleanup_post_reply_releases.values()
            )
            futures = list(self.operation_futures.values())
            self.operation_futures.clear()
            self.early_outcomes.clear()
        for release in releases:
            release.set()
        for release in cleanup_releases:
            release.set()
        for release in cleanup_post_reply_releases:
            release.set()
        error = RuntimeError(reason)
        for future in futures:
            if not future.done():
                future.set_exception(error)
        self.wait_workers_idle(timeout=REQUEST_TIMEOUT)


def _gdb_source_expression(path: Path) -> str:
    # GDB's ``source`` treats quote characters as part of the filename.  Its
    # CLI lexer accepts backslash-escaped whitespace instead.
    escaped = str(path).replace("\\", "\\\\").replace(" ", "\\ ")
    return "source " + escaped


def _initialize(
    transport: DapTransport,
    *,
    gef_path: Path | None = None,
) -> None:
    transport.request(
        "initialize",
        {
            "clientID": "pwnc-rpc-failure-matrix",
            "adapterID": "gdb",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "pathFormat": "path",
        },
        timeout=REQUEST_TIMEOUT,
    )
    transport.wait_initialized(timeout=REQUEST_TIMEOUT)
    if gef_path is not None:
        transport.request(
            "evaluate",
            {
                "expression": _gdb_source_expression(gef_path),
                "context": "repl",
            },
            timeout=DEADLOCK_TIMEOUT,
        )
    extension = Path(__file__).with_name("rpc_failure_matrix_ext.py").resolve()
    transport.request(
        "evaluate",
        {
            "expression": _gdb_source_expression(extension),
            "context": "repl",
        },
        timeout=REQUEST_TIMEOUT,
    )


def _await(future: CompletionCell, label: str) -> Any:
    try:
        return future.result(timeout=DEADLOCK_TIMEOUT)
    except FutureTimeout as error:
        raise TimeoutError(f"{label} timed out; possible callback deadlock") from error


def _assert_nested_result(result: dict[str, Any], max_depth: int) -> list[int]:
    operation_ids = []
    current = result
    for depth in range(max_depth + 1):
        assert current["depth"] == depth
        assert "pagination" in current["pagination"].lower()
        operation_ids.append(current["operationId"])
        value = current["value"]
        assert value["fromDepth"] == depth
        if depth == max_depth:
            assert value["leaf"] is True
        else:
            current = value["child"]
    return operation_ids


def _first_trace_index(
    trace: list[dict[str, Any]],
    kind: str,
    *,
    operation_id: int | None = None,
    command_prefix: str | None = None,
) -> int:
    for index, item in enumerate(trace):
        if item["kind"] != kind:
            continue
        if operation_id is not None and item.get("operationId") != operation_id:
            continue
        if command_prefix is not None and not item.get("command", "").startswith(
            command_prefix
        ):
            continue
        return index
    raise AssertionError(
        f"missing trace kind={kind!r} operation={operation_id!r} command={command_prefix!r}"
    )


def _verify_suite(
    dispatcher: DynamicCallbackDispatcher,
    snapshot: dict[str, Any],
    concurrent_results: list[dict[str, Any]],
    concurrent_operation_ids: list[list[int]],
    failure_root_id: int,
    duplicate_body: dict[str, Any],
    cancel_id: int,
    cancel_initial_body: dict[str, Any],
    cancel_cleanup_bodies: list[dict[str, Any]],
    gef_loaded: bool,
) -> dict[str, Any]:
    trace = snapshot["trace"]
    callbacks = list(dispatcher.callbacks)
    terminal = [item for item in trace if item["kind"] == "operation-terminal"]
    accepted = [item for item in trace if item["kind"] == "reply-accepted"]

    assert snapshot["activeCount"] == 0
    assert not snapshot["active"]
    assert snapshot["tombstoneCount"] == snapshot["tombstoneLimit"] == 32
    assert len(terminal) > snapshot["tombstoneCount"]
    assert all(item["finallyRuns"] == 1 for item in terminal)
    assert len({item["operationId"] for item in terminal}) == len(terminal)
    assert len(accepted) == len(callbacks) - 1  # cancelled callback has no reply
    assert all(item["acceptedReplies"] in {0, 1, 2} for item in terminal)
    assert sum(item["acceptedReplies"] for item in terminal) == len(accepted)
    assert sum(item["outcome"] == "cancelled" for item in terminal) == 1
    cancel_terminal = next(
        item for item in terminal if item["operationId"] == cancel_id
    )
    assert cancel_terminal["acceptedReplies"] == 2
    assert cancel_terminal["cleanupEffectsCompleted"] == 2
    cancel_tombstone = snapshot["tombstones"][str(cancel_id)]
    assert cancel_tombstone["outcome"] == "cancelled"
    assert cancel_tombstone["cancelRequested"] is True
    assert cancel_tombstone["cancelDispatches"] == 1
    assert cancel_tombstone["duplicateCancelRequests"] == 2
    assert cancel_tombstone["cleanupResults"] == [
        {"cleanupIndex": 1, "cleaned": True},
        {"cleanupIndex": 2, "cleaned": True},
    ]
    assert [body["method"] for body in cancel_cleanup_bodies] == [
        "matrix.cleanup",
        "matrix.cleanup",
    ]
    assert [body["payload"]["cleanupIndex"] for body in cancel_cleanup_bodies] == [
        1,
        2,
    ]
    assert cancel_initial_body["method"] == "matrix.callback"

    guards = list(dispatcher.reply_guards.values())
    replied_guards = [
        guard
        for guard in guards
        if not (
            guard.body["mode"] == "cancel-cleanup"
            and guard.body["method"] == "matrix.callback"
        )
    ]
    assert all(guard.selected in {"value", "error"} for guard in replied_guards)
    assert len(dispatcher.reply_results) == len(replied_guards)
    assert not dispatcher.fatal_errors
    assert not dispatcher.operation_futures
    assert not dispatcher.early_outcomes

    expected_concurrent_workers = CONCURRENT_ROOTS * (CONCURRENT_MAX_DEPTH + 1)
    concurrent_entries = [
        item
        for item in dispatcher.worker_entries
        if item["rootToken"].startswith("concurrent-")
    ]
    assert len(concurrent_entries) == expected_concurrent_workers
    assert len({item["threadId"] for item in concurrent_entries}) == len(
        concurrent_entries
    )
    assert dispatcher.peak_active_workers >= expected_concurrent_workers
    assert len(dispatcher.reader_thread_ids) == 1
    callback_thread_ids = {item["threadId"] for item in dispatcher.worker_entries}
    assert callback_thread_ids.isdisjoint(dispatcher.reader_thread_ids)
    assert threading.get_ident() not in callback_thread_ids
    assert all(not hasattr(cell, "add_done_callback") for cell in dispatcher.operation_cells)
    completion_waiter_thread_ids = {
        thread_id
        for cell in dispatcher.operation_cells
        for thread_id in cell.waiter_thread_ids
    }
    assert completion_waiter_thread_ids
    assert completion_waiter_thread_ids.isdisjoint(dispatcher.reader_thread_ids)
    assert not hasattr(dispatcher, "executor")
    assert all(not thread.is_alive() for thread in dispatcher.threads)

    for result, operation_ids in zip(concurrent_results, concurrent_operation_ids):
        assert _assert_nested_result(result, CONCURRENT_MAX_DEPTH) == operation_ids

    failure_callbacks = [
        item for item in callbacks if item["rootToken"] == "failure-root"
    ]
    assert len(failure_callbacks) == FAILURE_MAX_DEPTH + 1
    failure_ids = {item["operationId"] for item in failure_callbacks}
    assert failure_root_id in failure_ids
    failed_terminal = [item for item in terminal if item["operationId"] in failure_ids]
    assert len(failed_terminal) == FAILURE_MAX_DEPTH + 1
    assert all(item["outcome"] == "failed" for item in failed_terminal)
    failure_replies = [
        item for item in accepted if item.get("rootToken") == "failure-root"
    ]
    assert len(failure_replies) == FAILURE_MAX_DEPTH + 1
    assert all(item["replyKind"] == "error" for item in failure_replies)

    rejection_kinds = {item["kind"] for item in dispatcher.intentional_rejections}
    assert {"duplicate", "late", "malformed", "cancel-or-disconnect"} <= rejection_kinds
    duplicate_accepts = [
        item
        for item in accepted
        if item["operationId"] == duplicate_body["operationId"]
    ]
    assert len(duplicate_accepts) == 1
    remote_rejections = [item for item in trace if item["kind"] == "reply-rejected"]
    assert len(remote_rejections) >= 4

    cleanup_trace = [
        item for item in trace if item.get("operationId") == cancel_id
    ]
    cleanup_sequence = [
        (item["kind"], item.get("cleanupIndex"))
        for item in cleanup_trace
        if item["kind"]
        in {
            "cancel-dispatched",
            "cleanup-await",
            "cleanup-resumed",
            "operation-finally",
            "operation-terminal",
        }
    ]
    assert cleanup_sequence == [
        ("cancel-dispatched", None),
        ("cleanup-await", 1),
        ("cleanup-resumed", 1),
        ("cleanup-await", 2),
        ("cleanup-resumed", 2),
        ("operation-finally", None),
        ("operation-terminal", None),
    ]
    assert sum(item["kind"] == "cancel-dispatched" for item in cleanup_trace) == 1
    assert sum(item["kind"] == "cancel-idempotent" for item in cleanup_trace) == 2

    gdb_work_kinds = {
        "operation-enter",
        "callback-resume-dispatched",
        "operation-resumed",
        "operation-finally-enter",
        "operation-finally",
        "operation-terminal",
        "cancel-dispatched",
        "cleanup-await",
        "cleanup-resumed",
        "execute-enter",
        "execute-return",
        "execute-error",
    }
    gdb_thread_ids = {
        item["threadId"] for item in trace if item["kind"] in gdb_work_kinds
    }
    assert len(gdb_thread_ids) == 1
    assert gdb_thread_ids.isdisjoint(dispatcher.reader_thread_ids)

    if gef_loaded:
        assert len(dispatcher.gef_results) == 1
        gef_root_id = concurrent_operation_ids[0][0]
        emitted = _first_trace_index(
            trace, "callback-emitted", operation_id=gef_root_id
        )
        history = _first_trace_index(
            trace, "execute-enter", command_prefix="history -n"
        )
        nested = _first_trace_index(
            trace, "execute-enter", command_prefix="show commands"
        )
        resumed = _first_trace_index(
            trace, "operation-resumed", operation_id=gef_root_id
        )
        assert emitted < history < nested < resumed
        history_entry = trace[history]
        nested_entry = trace[nested]
        assert history_entry["executeDepth"] == 0
        assert nested_entry["executeDepth"] == 1
        assert history_entry["threadId"] == nested_entry["threadId"]

    return {
        "callbackCount": len(callbacks),
        "concurrentRootCount": CONCURRENT_ROOTS,
        "concurrentCallbacks": expected_concurrent_workers,
        "peakActiveCallbackThreads": dispatcher.peak_active_workers,
        "uniqueConcurrentCallbackThreads": len(
            {item["threadId"] for item in concurrent_entries}
        ),
        "terminalOperationCount": len(terminal),
        "acceptedReplyCount": len(accepted),
        "failureChainLength": len(failure_callbacks),
        "tombstoneCount": snapshot["tombstoneCount"],
        "tombstoneLimit": snapshot["tombstoneLimit"],
        "duplicateLateMalformedRejected": True,
        "cancelAwaitedCleanupEffects": 2,
        "cancelTerminalAfterCleanup": True,
        "duplicateCancelDidNotReinject": True,
        "operationCellsHaveNoInlineCallbacks": True,
        "dynamicThreadsNoExecutor": True,
        "gdbThreadId": next(iter(gdb_thread_ids)),
        "hostReaderThreadId": next(iter(dispatcher.reader_thread_ids)),
        "gefNestedExecuteProved": gef_loaded,
    }


def run_matrix(
    gdb_path: str = "gdb",
    *,
    gef_path: Path = DEFAULT_GEF,
    require_gef: bool = False,
) -> dict[str, Any]:
    if not shutil.which(gdb_path) and not Path(gdb_path).is_file():
        raise RuntimeError("GDB is required for the live failure matrix")

    gef = gef_path.resolve()
    if require_gef and not gef.is_file():
        raise RuntimeError(f"required GEF fixture is unavailable: {gef}")
    loaded_gef = gef if gef.is_file() else None
    gef_before = hashlib.sha256(gef.read_bytes()).hexdigest() if loaded_gef else None
    if loaded_gef and gef_before != EXPECTED_GEF_SHA256:
        raise RuntimeError(
            "GEF fixture does not match the pinned unmodified bata24 source: "
            f"expected {EXPECTED_GEF_SHA256}, got {gef_before}"
        )

    transport = DapTransport(gdb_path)
    dispatcher: DynamicCallbackDispatcher | None = None
    try:
        _initialize(transport, gef_path=loaded_gef)
        dispatcher = DynamicCallbackDispatcher(transport)

        barrier_token = "all-concurrent-leaves"
        dispatcher.barriers[barrier_token] = threading.Barrier(CONCURRENT_ROOTS)
        concurrent: list[tuple[int, CompletionCell]] = []
        for root_index in range(CONCURRENT_ROOTS):
            concurrent.append(
                dispatcher.start_operation(
                    root_token=f"concurrent-{root_index}",
                    max_depth=CONCURRENT_MAX_DEPTH,
                    barrier_token=barrier_token,
                    run_gef=loaded_gef is not None and root_index == 0,
                )
            )
        concurrent_results = [
            _await(future, f"concurrent root {index}")
            for index, (_operation_id, future) in enumerate(concurrent)
        ]
        concurrent_operation_ids = [
            _assert_nested_result(result, CONCURRENT_MAX_DEPTH)
            for result in concurrent_results
        ]

        duplicate_id, duplicate_future = dispatcher.start_operation(
            root_token="duplicate-root",
            mode="duplicate",
        )
        duplicate_result = _await(duplicate_future, "duplicate root")
        assert duplicate_result["operationId"] == duplicate_id
        duplicate_body = dispatcher.wait_for_callback("duplicate-root")
        dispatcher._assert_raw_reply_rejected(duplicate_body, "late")

        # Invalid error shapes must be rejected before claiming the callback;
        # a valid value afterwards must still complete it.
        malformed_id, malformed_future = dispatcher.start_operation(
            root_token="malformed-root",
            mode="malformed-hold",
        )
        malformed_body = dispatcher.wait_for_callback("malformed-root")
        dispatcher._assert_raw_reply_rejected(
            malformed_body,
            "malformed",
            malformed_error=True,
        )
        dispatcher.release_hold("malformed-root")
        # Rejection must not consume the callback's sole reply slot.  The
        # worker's valid value afterwards completes instead of stranding the
        # task in resume-queued.
        malformed_result = _await(malformed_future, "malformed root")
        assert malformed_result["operationId"] == malformed_id

        failure_root_id, failure_future = dispatcher.start_operation(
            root_token="failure-root",
            max_depth=FAILURE_MAX_DEPTH,
            mode="failure",
            failure_depth=FAILURE_MAX_DEPTH,
        )
        try:
            _await(failure_future, "failure root")
        except MatrixOperationFailed as error:
            assert error.body["operationId"] == failure_root_id
        else:
            raise AssertionError("nested callback failure did not reach root")

        cancel_id, cancel_future = dispatcher.start_operation(
            root_token="cancel-root",
            mode="cancel-cleanup",
        )
        cancel_initial_body = dispatcher.wait_for_matching_callback(
            "cancel-root",
            method="matrix.callback",
        )
        cancelled = transport.request(
            "rpcMatrixCancel",
            {"operationId": cancel_id},
            timeout=REQUEST_TIMEOUT,
        )
        assert cancelled["status"] == "cancel-queued"
        cleanup_one = dispatcher.wait_for_matching_callback(
            "cancel-root",
            method="matrix.cleanup",
            cleanup_index=1,
        )
        assert not cancel_future.done()
        duplicate_cancel_one = transport.request(
            "rpcMatrixCancel",
            {"operationId": cancel_id},
            timeout=REQUEST_TIMEOUT,
        )
        assert duplicate_cancel_one["status"] == "cancel-in-progress"
        assert not cancel_future.done()
        dispatcher.release_cleanup("cancel-root", 1)
        cleanup_two = dispatcher.wait_for_matching_callback(
            "cancel-root",
            method="matrix.cleanup",
            cleanup_index=2,
        )
        assert not cancel_future.done()
        duplicate_cancel_two = transport.request(
            "rpcMatrixCancel",
            {"operationId": cancel_id},
            timeout=REQUEST_TIMEOUT,
        )
        assert duplicate_cancel_two["status"] == "cancel-in-progress"
        assert not cancel_future.done()
        dispatcher.release_cleanup("cancel-root", 2)
        try:
            _await(cancel_future, "cancel root")
        except MatrixOperationCancelled as error:
            assert error.body["operationId"] == cancel_id
        else:
            raise AssertionError("cancelled operation unexpectedly completed")
        # The initially held callback is now stale.  Let its worker observe the
        # bounded late-reply rejection only after cooperative cleanup finished.
        dispatcher.release_hold("cancel-root")

        dispatcher.wait_workers_idle()
        snapshot = transport.request("rpcMatrixSnapshot", timeout=REQUEST_TIMEOUT)
        evidence = _verify_suite(
            dispatcher,
            snapshot,
            concurrent_results,
            concurrent_operation_ids,
            failure_root_id,
            duplicate_body,
            cancel_id,
            cancel_initial_body,
            [cleanup_one, cleanup_two],
            loaded_gef is not None,
        )
        evidence["gdbVersion"] = transport.request(
            "evaluate",
            {"expression": "show version", "context": "repl"},
            timeout=REQUEST_TIMEOUT,
        )["result"].splitlines()[0]
        evidence["gefPath"] = str(loaded_gef) if loaded_gef else None
        evidence["gefSha256Before"] = gef_before
        gef_after = hashlib.sha256(gef.read_bytes()).hexdigest() if loaded_gef else None
        evidence["gefSha256After"] = gef_after
        evidence["gefBytesUnmodified"] = gef_before == gef_after
        assert evidence["gefBytesUnmodified"]
        return evidence
    finally:
        if dispatcher is not None:
            dispatcher.abort()
        transport.close()


def _expect_operation_failed(
    future: CompletionCell,
    label: str,
) -> dict[str, Any]:
    try:
        _await(future, label)
    except MatrixOperationFailed as error:
        return error.body
    raise AssertionError(f"{label} unexpectedly completed")


def _expect_operation_cancelled(
    future: CompletionCell,
    label: str,
) -> dict[str, Any]:
    try:
        _await(future, label)
    except MatrixOperationCancelled as error:
        return error.body
    raise AssertionError(f"{label} unexpectedly completed")


def _expect_dap_error(
    transport: DapTransport,
    command: str,
    arguments: dict[str, Any],
    message_fragment: str,
) -> DapError:
    try:
        transport.request(command, arguments, timeout=REQUEST_TIMEOUT)
    except DapError as error:
        assert message_fragment.lower() in str(error).lower()
        return error
    raise AssertionError(f"{command} unexpectedly accepted invalid arguments")


def _run_depth_admission_probe(gdb_path: str) -> dict[str, Any]:
    transport = DapTransport(gdb_path)
    dispatcher: DynamicCallbackDispatcher | None = None
    try:
        _initialize(transport)
        dispatcher = DynamicCallbackDispatcher(
            transport,
            max_callback_depth=ADMISSION_DEPTH_LIMIT,
        )
        root_id, root_future = dispatcher.start_operation(
            root_token="depth-limit-root",
            max_depth=ADMISSION_DEPTH_LIMIT + 2,
        )
        failure = _expect_operation_failed(root_future, "depth-limited root")
        assert failure["operationId"] == root_id
        dispatcher.wait_admission_replies()
        dispatcher.wait_workers_idle()

        rejections = list(dispatcher.admission_rejections)
        assert len(rejections) == 1
        rejection = rejections[0]
        assert rejection["kind"] == "depth"
        assert rejection["depth"] == ADMISSION_DEPTH_LIMIT + 1
        # Only depths 0 and 1 were admitted.  The rejected depth-2 event was
        # answered before a third Thread object could be constructed.
        assert len(dispatcher.callbacks) == ADMISSION_DEPTH_LIMIT + 2
        assert len(dispatcher.threads) == ADMISSION_DEPTH_LIMIT + 1
        assert rejection["threadCountAtRejection"] == len(dispatcher.threads)
        assert sorted(entry["depth"] for entry in dispatcher.worker_entries) == [
            0,
            1,
        ]
        assert len(dispatcher.admission_reply_responses) == 1
        assert {
            response["threadId"]
            for response in dispatcher.admission_reply_responses
        }.isdisjoint(dispatcher.reader_thread_ids)
        assert not dispatcher.fatal_errors
        assert not dispatcher.operation_futures

        root_arguments = {
            "rootToken": "negative-depth-root",
            "depth": -1,
            "maxDepth": 1,
            "parentOperationId": None,
            "mode": "success",
            "failureDepth": None,
            "runGef": False,
            "barrierToken": None,
        }
        _expect_dap_error(
            transport,
            "rpcMatrixStart",
            root_arguments,
            "root operation depth",
        )

        parent_id, parent_future = dispatcher.start_operation(
            root_token="lineage-parent",
            max_depth=3,
            mode="admission-hold",
        )
        dispatcher.wait_for_matching_callback(
            "lineage-parent",
            method="matrix.callback",
        )
        child_arguments = {
            "rootToken": "lineage-parent",
            "depth": 0,
            "maxDepth": 3,
            "parentOperationId": parent_id,
            "mode": "admission-hold",
            "failureDepth": None,
            "runGef": False,
            "barrierToken": None,
        }
        _expect_dap_error(
            transport,
            "rpcMatrixStart",
            child_arguments,
            "lineage depth",
        )
        child_arguments["depth"] = 1
        child_arguments["rootToken"] = "reset-root-token"
        _expect_dap_error(
            transport,
            "rpcMatrixStart",
            child_arguments,
            "rootToken",
        )
        dispatcher.release_hold("lineage-parent")
        parent_result = _await(parent_future, "lineage validation parent")
        assert parent_result["operationId"] == parent_id

        reset_id, reset_future = dispatcher.start_operation(
            root_token="host-lineage-reset",
            max_depth=1,
            mode="lineage-reset",
        )
        reset_result = _await(reset_future, "host lineage reset")
        assert reset_result["operationId"] == reset_id
        assert reset_result["value"] == {"lineageResetRejected": True}
        assert len(dispatcher.lineage_rejections) == 1
        dispatcher.wait_workers_idle()

        snapshot = transport.request("rpcMatrixSnapshot", timeout=REQUEST_TIMEOUT)
        assert snapshot["activeCount"] == 0
        return {
            "limit": ADMISSION_DEPTH_LIMIT,
            "rejections": len(rejections),
            "callbacksReceived": len(dispatcher.callbacks),
            "callbackThreadsConstructed": len(dispatcher.threads),
            "rejectedBeforeThreadCreation": True,
            "readerRanNoReplyCompletionCallback": True,
            "rootFailedWithoutDeadlock": True,
            "negativeRootDepthRejected": True,
            "childDepthResetRejected": True,
            "childFieldMismatchRejected": True,
            "hostCallbackCannotResetLineage": True,
        }
    finally:
        if dispatcher is not None:
            dispatcher.abort("depth admission probe cleanup")
        transport.close()


def _run_active_admission_probe(gdb_path: str) -> dict[str, Any]:
    transport = DapTransport(gdb_path)
    dispatcher: DynamicCallbackDispatcher | None = None
    try:
        _initialize(transport)
        dispatcher = DynamicCallbackDispatcher(
            transport,
            max_active_callbacks=ADMISSION_ACTIVE_LIMIT,
            max_callback_depth=8,
        )

        admitted: list[tuple[str, int, CompletionCell]] = []
        for index in range(ADMISSION_ACTIVE_LIMIT):
            root_token = f"active-held-{index}"
            operation_id, future = dispatcher.start_operation(
                root_token=root_token,
                mode="admission-hold",
            )
            dispatcher.wait_for_matching_callback(
                root_token,
                method="matrix.callback",
            )
            admitted.append((root_token, operation_id, future))
        dispatcher.wait_for_active_workers(ADMISSION_ACTIVE_LIMIT)
        assert len(dispatcher.threads) == ADMISSION_ACTIVE_LIMIT

        overflow: list[tuple[int, CompletionCell]] = []
        for index in range(ADMISSION_OVERFLOW_COUNT):
            overflow.append(
                dispatcher.start_operation(root_token=f"active-overflow-{index}")
            )
        overflow_failures = [
            _expect_operation_failed(future, f"active overflow {index}")
            for index, (_operation_id, future) in enumerate(overflow)
        ]
        dispatcher.wait_admission_replies()

        # All original callbacks are still synchronously blocked.  Overflow
        # failures nevertheless reached the main thread, proving that neither
        # the reader nor a fixed worker pool was starved by the cap.
        assert dispatcher.active_workers == ADMISSION_ACTIVE_LIMIT
        assert len(dispatcher.threads) == ADMISSION_ACTIVE_LIMIT
        assert all(
            failure["operationId"] == operation_id
            for failure, (operation_id, _future) in zip(
                overflow_failures,
                overflow,
            )
        )
        rejections = list(dispatcher.admission_rejections)
        assert len(rejections) == ADMISSION_OVERFLOW_COUNT
        assert all(rejection["kind"] == "active" for rejection in rejections)
        assert all(
            rejection["activeAtRejection"] == ADMISSION_ACTIVE_LIMIT
            for rejection in rejections
        )
        assert all(
            rejection["threadCountAtRejection"] == ADMISSION_ACTIVE_LIMIT
            for rejection in rejections
        )
        assert len(dispatcher.admission_reply_responses) == len(rejections)
        assert {
            response["threadId"]
            for response in dispatcher.admission_reply_responses
        }.isdisjoint(dispatcher.reader_thread_ids)

        for root_token, _operation_id, _future in admitted:
            dispatcher.release_hold(root_token)
        for root_token, operation_id, future in admitted:
            result = _await(future, root_token)
            assert result["operationId"] == operation_id
        dispatcher.wait_workers_idle()

        # A released reservation is reusable; a subsequent callback is
        # admitted and completes instead of remaining permanently rejected.
        recovery_id, recovery_future = dispatcher.start_operation(
            root_token="active-recovery"
        )
        recovery = _await(recovery_future, "active-cap recovery")
        assert recovery["operationId"] == recovery_id
        dispatcher.wait_workers_idle()
        assert len(dispatcher.threads) == ADMISSION_ACTIVE_LIMIT + 1
        assert len(dispatcher.admission_rejections) == ADMISSION_OVERFLOW_COUNT
        assert not dispatcher.fatal_errors
        assert not dispatcher.operation_futures
        snapshot = transport.request("rpcMatrixSnapshot", timeout=REQUEST_TIMEOUT)
        assert snapshot["activeCount"] == 0
        return {
            "limit": ADMISSION_ACTIVE_LIMIT,
            "overflowRejections": len(rejections),
            "threadsBeforeRecovery": ADMISSION_ACTIVE_LIMIT,
            "threadsAfterRecovery": len(dispatcher.threads),
            "rejectedBeforeThreadCreation": True,
            "readerRanNoReplyCompletionCallbacks": True,
            "heldCallbacksDidNotStarveRejections": True,
            "capacityReusable": True,
        }
    finally:
        if dispatcher is not None:
            dispatcher.abort("active admission probe cleanup")
        transport.close()


def _run_cleanup_reserve_probe(gdb_path: str) -> dict[str, Any]:
    transport = DapTransport(gdb_path)
    dispatcher: DynamicCallbackDispatcher | None = None
    try:
        _initialize(transport)
        dispatcher = DynamicCallbackDispatcher(
            transport,
            max_active_callbacks=1,
            cleanup_callback_reserve=ADMISSION_CLEANUP_RESERVE,
        )
        operation_id, future = dispatcher.start_operation(
            root_token="cleanup-reserve-root",
            mode="cancel-cleanup-overlap",
        )
        dispatcher.wait_for_matching_callback(
            "cleanup-reserve-root",
            method="matrix.callback",
        )
        dispatcher.wait_for_active_workers(1)
        assert dispatcher.active_ordinary_workers == 1
        assert dispatcher.active_cleanup_workers == 0

        cancelled = transport.request(
            "rpcMatrixCancel",
            {"operationId": operation_id},
            timeout=REQUEST_TIMEOUT,
        )
        assert cancelled["status"] == "cancel-queued"

        dispatcher.wait_for_matching_callback(
            "cleanup-reserve-root",
            method="matrix.cleanup",
            cleanup_index=1,
        )
        dispatcher.wait_for_active_workers(2)
        assert dispatcher.active_ordinary_workers == 1
        assert dispatcher.active_cleanup_workers == 1
        assert not future.done()
        dispatcher.release_cleanup("cleanup-reserve-root", 1)

        dispatcher.wait_for_matching_callback(
            "cleanup-reserve-root",
            method="matrix.cleanup",
            cleanup_index=2,
        )
        dispatcher.wait_for_active_workers(3)
        assert dispatcher.active_ordinary_workers == 1
        assert dispatcher.active_cleanup_workers == 2
        assert not future.done()
        dispatcher.release_cleanup_post_reply("cleanup-reserve-root")
        dispatcher.release_cleanup("cleanup-reserve-root", 2)

        terminal = _expect_operation_cancelled(future, "cleanup reserve cancellation")
        tombstone = terminal["tombstone"]
        assert tombstone["outcome"] == "cancelled"
        assert tombstone["cleanupResults"] == [
            {"cleanupIndex": 1, "cleaned": True},
            {"cleanupIndex": 2, "cleaned": True},
        ]
        assert tombstone["cancelDispatches"] == 1
        dispatcher.release_hold("cleanup-reserve-root")
        dispatcher.wait_workers_idle()

        assert dispatcher.peak_active_ordinary_workers == 1
        assert dispatcher.peak_active_cleanup_workers == ADMISSION_CLEANUP_RESERVE
        assert dispatcher.peak_active_workers == 1 + ADMISSION_CLEANUP_RESERVE
        assert not dispatcher.admission_rejections
        assert not dispatcher.fatal_errors
        assert not dispatcher.operation_futures
        snapshot = transport.request("rpcMatrixSnapshot", timeout=REQUEST_TIMEOUT)
        assert snapshot["activeCount"] == 0
        return {
            "ordinaryLimit": 1,
            "cleanupReserve": ADMISSION_CLEANUP_RESERVE,
            "boundedTotalLimit": 1 + ADMISSION_CLEANUP_RESERVE,
            "peakTotalWorkers": dispatcher.peak_active_workers,
            "bothCleanupEffectsCompleted": True,
            "terminalCancelled": True,
        }
    finally:
        if dispatcher is not None:
            dispatcher.abort("cleanup reserve probe cleanup")
        transport.close()


def _run_thread_factory_failure_case(
    gdb_path: str,
    *,
    phase: str,
    thread_factory: Callable[..., threading.Thread],
) -> dict[str, Any]:
    transport = DapTransport(gdb_path)
    dispatcher: DynamicCallbackDispatcher | None = None
    try:
        _initialize(transport)
        dispatcher = DynamicCallbackDispatcher(
            transport,
            max_active_callbacks=1,
            thread_factory=thread_factory,
        )
        operation_id, future = dispatcher.start_operation(
            root_token=f"thread-{phase}-failure"
        )
        failure = _expect_operation_failed(future, f"thread {phase} failure")
        assert failure["operationId"] == operation_id
        assert failure["error"]["type"] == "HostCallbackError"
        assert "CallbackWorkerError" in failure["error"]["message"]
        dispatcher.wait_admission_replies()
        dispatcher.wait_workers_idle()

        assert dispatcher.active_workers == 0
        assert dispatcher.active_ordinary_workers == 0
        assert dispatcher.active_cleanup_workers == 0
        assert not dispatcher.threads
        assert len(dispatcher.worker_start_failures) == 1
        assert dispatcher.worker_start_failures[0]["phase"] == phase
        assert not dispatcher.fatal_errors
        assert not dispatcher.operation_futures
        assert {
            response["threadId"]
            for response in dispatcher.admission_reply_responses
        }.isdisjoint(dispatcher.reader_thread_ids)
        snapshot = transport.request("rpcMatrixSnapshot", timeout=REQUEST_TIMEOUT)
        assert snapshot["activeCount"] == 0
        return {
            "phase": phase,
            "reservationRolledBack": True,
            "unstartedThreadsRetained": 0,
            "operationFailedWithoutDeadlock": True,
        }
    finally:
        if dispatcher is not None:
            dispatcher.abort(f"thread {phase} failure probe cleanup")
        transport.close()


def _run_thread_factory_failure_probe(gdb_path: str) -> dict[str, Any]:
    def construction_failure(**_kwargs: Any) -> threading.Thread:
        raise RuntimeError("injected callback Thread construction failure")

    class StartFailingThread(threading.Thread):
        def start(self) -> None:
            raise RuntimeError("injected callback Thread.start failure")

    return {
        "construction": _run_thread_factory_failure_case(
            gdb_path,
            phase="construction",
            thread_factory=construction_failure,
        ),
        "start": _run_thread_factory_failure_case(
            gdb_path,
            phase="start",
            thread_factory=StartFailingThread,
        ),
    }


def run_admission_probe(gdb_path: str = "gdb") -> dict[str, Any]:
    """Exercise depth and global-active admission against separate live GDBs."""
    return {
        "depth": _run_depth_admission_probe(gdb_path),
        "active": _run_active_admission_probe(gdb_path),
        "cleanup": _run_cleanup_reserve_probe(gdb_path),
        "worker": _run_thread_factory_failure_probe(gdb_path),
    }


def run_disconnect_probe(gdb_path: str = "gdb") -> dict[str, Any]:
    """Close DAP beneath a held sync callback and prove bounded host cleanup."""
    transport = DapTransport(gdb_path)
    dispatcher: DynamicCallbackDispatcher | None = None
    started_at = time.monotonic()
    try:
        _initialize(transport)
        dispatcher = DynamicCallbackDispatcher(transport)
        operation_id, future = dispatcher.start_operation(
            root_token="disconnect-root",
            mode="hold-cancel",
        )
        dispatcher.wait_for_callback("disconnect-root")
        transport.close()
        dispatcher.abort("transport disconnected")
        assert not dispatcher.operation_futures
        assert not dispatcher.early_outcomes
        assert future.done()
        try:
            future.result()
        except RuntimeError as error:
            assert "disconnected" in str(error)
        else:
            raise AssertionError("disconnect did not fail pending operation")
        assert all(not thread.is_alive() for thread in dispatcher.threads)
        assert transport.proc.poll() is not None
        elapsed = time.monotonic() - started_at
        assert elapsed < REQUEST_TIMEOUT
        return {
            "operationId": operation_id,
            "cleanupSeconds": round(elapsed, 3),
            "callbackThreadsCleaned": len(dispatcher.threads),
            "gdbExited": True,
        }
    finally:
        if dispatcher is not None:
            dispatcher.abort("disconnect probe cleanup")
        transport.close()


def test_live_rpc_failure_matrix() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("GDB is required")
        return
    evidence = run_matrix(require_gef=DEFAULT_GEF.is_file())
    assert evidence["peakActiveCallbackThreads"] >= (
        CONCURRENT_ROOTS * (CONCURRENT_MAX_DEPTH + 1)
    )


def test_live_rpc_disconnect_cleanup() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("GDB is required")
        return
    evidence = run_disconnect_probe()
    assert evidence["gdbExited"] is True


def test_live_rpc_callback_admission_limits() -> None:
    if not shutil.which("gdb"):
        if pytest is not None:
            pytest.skip("GDB is required")
        return
    evidence = run_admission_probe()
    assert evidence["depth"]["rejectedBeforeThreadCreation"] is True
    assert evidence["active"]["capacityReusable"] is True
    assert evidence["cleanup"]["bothCleanupEffectsCompleted"] is True
    assert evidence["worker"]["construction"]["reservationRolledBack"] is True
    assert evidence["worker"]["start"]["reservationRolledBack"] is True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument("--require-gef", action="store_true")
    parser.add_argument("--skip-disconnect", action="store_true")
    parser.add_argument("--skip-admission", action="store_true")
    arguments = parser.parse_args()

    evidence = run_matrix(
        arguments.gdb,
        gef_path=arguments.gef,
        require_gef=arguments.require_gef,
    )
    print("PASS live GDB DAP failure/concurrency matrix")
    for key in sorted(evidence):
        print(f"{key}: {evidence[key]}")
    if not arguments.skip_admission:
        admission = run_admission_probe(arguments.gdb)
        print("PASS atomic callback admission limits")
        for scope, scoped_evidence in admission.items():
            for key in sorted(scoped_evidence):
                print(f"admission.{scope}.{key}: {scoped_evidence[key]}")
    if not arguments.skip_disconnect:
        disconnect = run_disconnect_probe(arguments.gdb)
        print("PASS bounded host/process disconnect teardown")
        for key in sorted(disconnect):
            print(f"disconnect.{key}: {disconnect[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
