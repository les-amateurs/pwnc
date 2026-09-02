"""GDB-side protocol state machine for the live RPC failure matrix.

This is sourced by :mod:`rpc_failure_matrix` into a real
``gdb --interpreter=dap`` process.  Every DAP request handler runs on GDB's
DAP thread and only mutates protocol state plus ``gdb.post_event``.  Lowered
operation continuations and every ``gdb.execute`` run on GDB's main thread.

The extension deliberately releases terminal operations from ``_active`` and
retains only a bounded tombstone.  That makes duplicate/late replies
diagnosable without turning the operation registry into an unbounded leak.
"""

import importlib.util
import itertools
import os
import sys
import threading
from collections import OrderedDict

import gdb
from gdb.dap.server import request, send_event

_lock = threading.RLock()
_operation_ids = itertools.count(1)
_callback_ids = itertools.count(1)
_trace_ids = itertools.count(1)
_active = {}
_tombstones = OrderedDict()
_trace_log = []
_execute_log = []
_TOMBSTONE_LIMIT = 32
_NO_VALUE = object()


def _load_lowering_runtime():
    module_name = "_pwnc_rpc_failure_matrix_ast_runtime"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "ast_lowering_runtime.py",
    )
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load AST lowering runtime from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


_lowering = _load_lowering_runtime()


class HostCallbackError(RuntimeError):
    """Error value delivered by the host for a suspended callback."""

    def __init__(self, error_type, message):
        super().__init__(f"{error_type}: {message}")
        self.error_type = error_type
        self.remote_message = message


def _trace(kind, **fields):
    with _lock:
        item = {
            "seq": next(_trace_ids),
            "kind": kind,
            "threadId": threading.get_ident(),
            "threadName": threading.current_thread().name,
        }
        item.update(fields)
        _trace_log.append(item)
    send_event("rpcMatrixTrace", item)
    return item


# Source real plugins before this extension.  Wrapping the module attribute at
# runtime leaves their bytes untouched and lets the probe observe conventional
# plugin -> gdb.execute nesting.
_original_gdb_execute = gdb.execute
_execute_depth = 0


def _instrumented_gdb_execute(command, *args, **kwargs):
    global _execute_depth

    depth = _execute_depth
    entered = _trace("execute-enter", command=command, executeDepth=depth)
    with _lock:
        _execute_log.append(entered)
    _execute_depth += 1
    try:
        result = _original_gdb_execute(command, *args, **kwargs)
        returned = _trace(
            "execute-return",
            command=command,
            executeDepth=depth,
            resultType=type(result).__name__,
        )
        with _lock:
            _execute_log.append(returned)
        return result
    except BaseException as error:
        failed = _trace(
            "execute-error",
            command=command,
            executeDepth=depth,
            errorType=type(error).__name__,
            error=str(error),
        )
        with _lock:
            _execute_log.append(failed)
        raise
    finally:
        _execute_depth -= 1


gdb.execute = _instrumented_gdb_execute


_OPERATION_SOURCE = r"""
async def _matrix_operation(state):
    operation_id = state["id"]
    _trace(
        "operation-enter",
        operationId=operation_id,
        rootToken=state["rootToken"],
        depth=state["depth"],
    )
    try:
        value = await effect(
            "matrix.callback",
            payload={
                "operationId": operation_id,
                "rootToken": state["rootToken"],
                "depth": state["depth"],
            },
        )
        _trace(
            "operation-resumed",
            operationId=operation_id,
            rootToken=state["rootToken"],
            depth=state["depth"],
        )
        # Exercise a real synchronous GDB call after the continuation resumes.
        pagination = gdb.execute(
            "show pagination",
            from_tty=False,
            to_string=True,
        )
        return {
            "operationId": operation_id,
            "rootToken": state["rootToken"],
            "depth": state["depth"],
            "value": value,
            "pagination": pagination.strip(),
        }
    finally:
        state["finallyRuns"] += 1
        _trace(
            "operation-finally-enter",
            operationId=operation_id,
            rootToken=state["rootToken"],
            depth=state["depth"],
            finallyRuns=state["finallyRuns"],
        )
        if state["mode"] in {"cancel-cleanup", "cancel-cleanup-overlap"}:
            for cleanup_index in (1, 2):
                _trace(
                    "cleanup-await",
                    operationId=operation_id,
                    rootToken=state["rootToken"],
                    depth=state["depth"],
                    cleanupIndex=cleanup_index,
                )
                cleanup_result = await effect(
                    "matrix.cleanup",
                    payload={
                        "operationId": operation_id,
                        "rootToken": state["rootToken"],
                        "depth": state["depth"],
                        "cleanupIndex": cleanup_index,
                    },
                )
                state["cleanupResults"].append(cleanup_result)
                _trace(
                    "cleanup-resumed",
                    operationId=operation_id,
                    rootToken=state["rootToken"],
                    depth=state["depth"],
                    cleanupIndex=cleanup_index,
                )
        _trace(
            "operation-finally",
            operationId=operation_id,
            rootToken=state["rootToken"],
            depth=state["depth"],
            finallyRuns=state["finallyRuns"],
        )
"""

_operation_namespace = {
    "gdb": gdb,
    "_trace": _trace,
}
_lowering.exec_lowered(
    _OPERATION_SOURCE,
    namespace=_operation_namespace,
    filename="<rpc-failure-matrix-operation>",
)
_matrix_operation = _operation_namespace["_matrix_operation"]


def _serialize_error(error):
    return {
        "type": type(error).__name__,
        "module": type(error).__module__,
        "message": str(error),
    }


def _remember_tombstone(state, outcome, detail=None):
    tombstone = {
        "operationId": state["id"],
        "parentOperationId": state["parentOperationId"],
        "rootToken": state["rootToken"],
        "depth": state["depth"],
        "callbackId": state["callbackId"],
        "outcome": outcome,
        "finallyRuns": state["finallyRuns"],
        "acceptedReplies": state["acceptedReplies"],
        "cleanupResults": list(state["cleanupResults"]),
        "cancelRequested": state["cancelRequested"],
        "cancelDispatches": state["cancelDispatches"],
        "duplicateCancelRequests": state["duplicateCancelRequests"],
        "detail": detail,
    }
    _tombstones[state["id"]] = tombstone
    _tombstones.move_to_end(state["id"])
    while len(_tombstones) > _TOMBSTONE_LIMIT:
        _tombstones.popitem(last=False)
    return tombstone


def _finish(state, outcome, detail=None):
    operation_id = state["id"]
    with _lock:
        current = _active.get(operation_id)
        if current is not state:
            return
        state["status"] = outcome
        del _active[operation_id]
        tombstone = _remember_tombstone(state, outcome, detail)

    _trace(
        "operation-terminal",
        operationId=operation_id,
        rootToken=state["rootToken"],
        depth=state["depth"],
        outcome=outcome,
        finallyRuns=state["finallyRuns"],
        acceptedReplies=state["acceptedReplies"],
        cleanupEffectsCompleted=len(state["cleanupResults"]),
    )
    body = {
        "operationId": operation_id,
        "parentOperationId": state["parentOperationId"],
        "rootToken": state["rootToken"],
        "depth": state["depth"],
        "tombstone": tombstone,
    }
    if outcome == "done":
        body["result"] = detail
        event = "rpcMatrixDone"
    elif outcome == "cancelled":
        body["error"] = detail
        event = "rpcMatrixCancelled"
    else:
        body["error"] = detail
        event = "rpcMatrixFailed"
    send_event(event, body)


def _finish_from_task(state):
    task = state["task"]
    if task.state is _lowering.TaskState.DONE:
        _finish(state, "done", task.result)
    elif task.state is _lowering.TaskState.CANCELLED:
        _finish(state, "cancelled", _serialize_error(task.exception))
    elif task.state in {
        _lowering.TaskState.FAILED,
        _lowering.TaskState.CLOSED,
    }:
        error = task.exception or RuntimeError(
            f"task terminated in {task.state.name.lower()}"
        )
        _finish(state, "failed", _serialize_error(error))
    else:
        raise RuntimeError(f"task is not terminal: {task.state.name}")


def _route_yielded_effect(state, yielded):
    task = state["task"]
    if task.terminal:
        _finish_from_task(state)
        return
    if task.state is not _lowering.TaskState.WAITING:
        task.close()
        _finish(
            state,
            "failed",
            _serialize_error(RuntimeError("task did not wait or terminate")),
        )
        return
    if yielded is None or yielded.name not in {"matrix.callback", "matrix.cleanup"}:
        task.close()
        _finish(
            state,
            "failed",
            _serialize_error(RuntimeError("operation yielded an invalid effect")),
        )
        return

    callback_id = next(_callback_ids)
    effect_kwargs = yielded.call_kwargs()
    with _lock:
        state["status"] = "waiting-host"
        state["callbackId"] = callback_id
    _trace(
        "callback-emitted",
        operationId=state["id"],
        callbackId=callback_id,
        rootToken=state["rootToken"],
        depth=state["depth"],
        method=yielded.name,
    )
    send_event(
        "rpcMatrixCallback",
        {
            "operationId": state["id"],
            "parentOperationId": state["parentOperationId"],
            "callbackId": callback_id,
            "method": yielded.name,
            "payload": effect_kwargs.get("payload"),
            "rootToken": state["rootToken"],
            "depth": state["depth"],
            "maxDepth": state["maxDepth"],
            "failureDepth": state["failureDepth"],
            "mode": state["mode"],
            "runGef": state["runGef"],
            "barrierToken": state["barrierToken"],
        },
    )


def _drive(state, value=_NO_VALUE, error=None):
    task = state["task"]
    with _lock:
        state["status"] = "running"
    if error is not None:
        yielded = task.resume(error=error)
    elif value is _NO_VALUE:
        yielded = task.resume()
    else:
        yielded = task.resume(value=value)
    _route_yielded_effect(state, yielded)


def _start_on_gdb_thread(operation_id):
    with _lock:
        state = _active.get(operation_id)
    if state is None:
        return
    try:
        state["task"] = _lowering.Task(_matrix_operation(state))
        _drive(state)
    except BaseException as error:  # noqa: BLE001 - contain all task failures
        _finish(state, "failed", _serialize_error(error))


def _resume_on_gdb_thread(operation_id, callback_id, kind, payload):
    with _lock:
        state = _active.get(operation_id)
        if state is None:
            return
        if state["status"] != "resume-queued" or state["callbackId"] != callback_id:
            return
    _trace(
        "callback-resume-dispatched",
        operationId=operation_id,
        callbackId=callback_id,
        rootToken=state["rootToken"],
        depth=state["depth"],
        replyKind=kind,
    )
    try:
        if kind == "value":
            _drive(state, value=payload)
        else:
            _drive(
                state,
                error=HostCallbackError(
                    payload.get("type", "HostError"),
                    payload.get("message", "host callback failed"),
                ),
            )
    except BaseException as error:  # noqa: BLE001 - never strand claimed replies
        # A malformed continuation must never strand a claimed reply in
        # resume-queued.  Validation normally rejects it on the DAP thread;
        # this is the final main-thread containment boundary.
        _finish(state, "failed", _serialize_error(error))


def _cancel_on_gdb_thread(operation_id, callback_id):
    with _lock:
        state = _active.get(operation_id)
        if state is None:
            return
        if state["status"] != "cancel-queued":
            return
        if state["callbackId"] != callback_id:
            return
    _trace(
        "cancel-dispatched",
        operationId=operation_id,
        callbackId=callback_id,
        rootToken=state["rootToken"],
        depth=state["depth"],
    )
    try:
        with _lock:
            state["cancelDispatches"] += 1
        task = state["task"]
        yielded = task.cancel()
        _route_yielded_effect(state, yielded)
    except BaseException as error:  # noqa: BLE001 - never strand cancel-queued
        _finish(state, "failed", _serialize_error(error))


def _reject_reply(operation_id, callback_id, reason):
    _trace(
        "reply-rejected",
        operationId=operation_id,
        callbackId=callback_id,
        reason=reason,
    )
    raise RuntimeError(reason)


@request("rpcMatrixStart", on_dap_thread=True, expect_stopped=False)
def rpc_matrix_start(**args):
    supplied_depth = int(args.get("depth", 0))
    supplied_max_depth = int(args.get("maxDepth", supplied_depth))
    failure_depth = args.get("failureDepth")
    if failure_depth is not None:
        failure_depth = int(failure_depth)
    supplied_parent = args.get("parentOperationId")
    supplied_root_token = str(args.get("rootToken", "root"))
    supplied_mode = str(args.get("mode", "success"))
    supplied_run_gef = bool(args.get("runGef", False))
    supplied_barrier_token = args.get("barrierToken")
    with _lock:
        if supplied_parent is None:
            if supplied_depth != 0:
                raise RuntimeError("root operation depth must be exactly zero")
            if supplied_max_depth < 0:
                raise RuntimeError("root operation max depth must be nonnegative")
            parent = None
            depth = 0
            max_depth = supplied_max_depth
            root_token = supplied_root_token
            mode = supplied_mode
            run_gef = supplied_run_gef
            barrier_token = supplied_barrier_token
        else:
            parent = int(supplied_parent)
            parent_state = _active.get(parent)
            if parent_state is None:
                raise RuntimeError("child operation parent is not active")
            if parent_state["status"] != "waiting-host":
                raise RuntimeError(
                    "child operation parent is not waiting for its host callback"
                )
            depth = parent_state["depth"] + 1
            if supplied_depth != depth:
                raise RuntimeError(
                    f"child depth {supplied_depth} does not match lineage depth {depth}"
                )
            if depth > parent_state["maxDepth"]:
                raise RuntimeError("child operation exceeds its parent max depth")
            consistency = {
                "rootToken": (supplied_root_token, parent_state["rootToken"]),
                "maxDepth": (supplied_max_depth, parent_state["maxDepth"]),
                "mode": (supplied_mode, parent_state["mode"]),
                "failureDepth": (failure_depth, parent_state["failureDepth"]),
                "runGef": (supplied_run_gef, parent_state["runGef"]),
                "barrierToken": (
                    supplied_barrier_token,
                    parent_state["barrierToken"],
                ),
            }
            for field, (supplied, inherited) in consistency.items():
                if supplied != inherited:
                    raise RuntimeError(
                        f"child {field} does not match its parent operation"
                    )
            max_depth = parent_state["maxDepth"]
            root_token = parent_state["rootToken"]
            mode = parent_state["mode"]
            failure_depth = parent_state["failureDepth"]
            run_gef = parent_state["runGef"]
            barrier_token = parent_state["barrierToken"]

        operation_id = next(_operation_ids)
        state = {
            "id": operation_id,
            "parentOperationId": parent,
            "rootToken": root_token,
            "depth": depth,
            "maxDepth": max_depth,
            "failureDepth": failure_depth,
            "mode": mode,
            "runGef": run_gef,
            "barrierToken": barrier_token,
            "status": "start-queued",
            "callbackId": None,
            "task": None,
            "finallyRuns": 0,
            "acceptedReplies": 0,
            "cleanupResults": [],
            "cancelRequested": False,
            "cancelDispatches": 0,
            "duplicateCancelRequests": 0,
        }
        _active[operation_id] = state
    _trace(
        "start-accepted",
        operationId=operation_id,
        parentOperationId=parent,
        rootToken=root_token,
        depth=depth,
    )
    gdb.post_event(lambda: _start_on_gdb_thread(operation_id))
    return {"operationId": operation_id, "status": "start-queued"}


@request("rpcMatrixReply", on_dap_thread=True, expect_stopped=False)
def rpc_matrix_reply(**args):
    operation_id = int(args["operationId"])
    callback_id = int(args["callbackId"])
    kind = str(args.get("kind", ""))
    if kind not in {"value", "error"}:
        return _reject_reply(
            operation_id,
            callback_id,
            "reply kind must be exactly 'value' or 'error'",
        )
    has_value = "value" in args
    has_error = "error" in args
    if (kind == "value") != has_value or (kind == "error") != has_error:
        return _reject_reply(
            operation_id,
            callback_id,
            "reply must contain exactly the payload selected by kind",
        )
    if kind == "error" and not isinstance(args["error"], dict):
        return _reject_reply(
            operation_id,
            callback_id,
            "error reply payload must be an object",
        )
    with _lock:
        state = _active.get(operation_id)
        if state is None:
            tombstone = _tombstones.get(operation_id)
            if tombstone is not None:
                return _reject_reply(
                    operation_id,
                    callback_id,
                    f"late reply for terminal operation {operation_id} "
                    f"({tombstone['outcome']})",
                )
            return _reject_reply(
                operation_id,
                callback_id,
                f"reply for unknown or expired operation {operation_id}",
            )
        if state["callbackId"] != callback_id:
            return _reject_reply(
                operation_id,
                callback_id,
                f"callback mismatch for operation {operation_id}",
            )
        if state["status"] != "waiting-host":
            return _reject_reply(
                operation_id,
                callback_id,
                f"duplicate reply for operation {operation_id} "
                f"in state {state['status']}",
            )
        state["status"] = "resume-queued"
        state["acceptedReplies"] += 1
        payload = args["value"] if kind == "value" else args["error"]
    _trace(
        "reply-accepted",
        operationId=operation_id,
        callbackId=callback_id,
        rootToken=state["rootToken"],
        depth=state["depth"],
        replyKind=kind,
    )
    gdb.post_event(
        lambda: _resume_on_gdb_thread(
            operation_id,
            callback_id,
            kind,
            payload,
        )
    )
    return {
        "operationId": operation_id,
        "callbackId": callback_id,
        "status": "resume-queued",
        "kind": kind,
    }


@request("rpcMatrixCancel", on_dap_thread=True, expect_stopped=False)
def rpc_matrix_cancel(**args):
    operation_id = int(args["operationId"])
    duplicate = False
    with _lock:
        state = _active.get(operation_id)
        if state is None:
            tombstone = _tombstones.get(operation_id)
            if tombstone is not None:
                raise RuntimeError(
                    f"late cancel for terminal operation {operation_id} "
                    f"({tombstone['outcome']})"
                )
            raise RuntimeError(
                f"cancel for unknown or expired operation {operation_id}"
            )
        if state["cancelRequested"]:
            state["duplicateCancelRequests"] += 1
            callback_id = state["callbackId"]
            duplicate = True
        elif state["status"] != "waiting-host":
            raise RuntimeError(
                f"operation {operation_id} cannot be cancelled "
                f"in state {state['status']}"
            )
        else:
            state["cancelRequested"] = True
            state["status"] = "cancel-queued"
            callback_id = state["callbackId"]
        root_token = state["rootToken"]
        depth = state["depth"]
        status = state["status"]
    if duplicate:
        _trace(
            "cancel-idempotent",
            operationId=operation_id,
            callbackId=callback_id,
            rootToken=root_token,
            depth=depth,
            status=status,
        )
        return {
            "operationId": operation_id,
            "status": "cancel-in-progress",
            "callbackId": callback_id,
        }
    _trace(
        "cancel-accepted",
        operationId=operation_id,
        callbackId=callback_id,
        rootToken=root_token,
        depth=depth,
    )
    gdb.post_event(lambda: _cancel_on_gdb_thread(operation_id, callback_id))
    return {"operationId": operation_id, "status": "cancel-queued"}


@request("rpcMatrixSnapshot", on_dap_thread=True, expect_stopped=False)
def rpc_matrix_snapshot(**args):
    with _lock:
        active = {
            str(operation_id): {
                "status": state["status"],
                "rootToken": state["rootToken"],
                "depth": state["depth"],
                "callbackId": state["callbackId"],
                "acceptedReplies": state["acceptedReplies"],
                "finallyRuns": state["finallyRuns"],
                "cleanupResults": list(state["cleanupResults"]),
                "cancelRequested": state["cancelRequested"],
                "cancelDispatches": state["cancelDispatches"],
                "duplicateCancelRequests": state["duplicateCancelRequests"],
            }
            for operation_id, state in _active.items()
        }
        tombstones = {
            str(operation_id): dict(tombstone)
            for operation_id, tombstone in _tombstones.items()
        }
        trace = list(_trace_log)
        execute_log = list(_execute_log)
    return {
        "active": active,
        "activeCount": len(active),
        "tombstones": tombstones,
        "tombstoneCount": len(tombstones),
        "tombstoneLimit": _TOMBSTONE_LIMIT,
        "trace": trace,
        "executeLog": execute_log,
    }
