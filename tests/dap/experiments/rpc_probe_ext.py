"""GDB-side half of the recursive DAP callback experiment.

This file is sourced into a real ``gdb --interpreter=dap`` process.  It uses
only APIs present in GDB 14 through 17:

* ``@request(..., on_dap_thread=True)`` to acknowledge control messages
  without occupying GDB's DAP dispatcher;
* ``gdb.post_event`` to run short steps on GDB's main thread; and
* custom DAP events to ask the host for a callback result.

The operation is written as an ordinary-looking ``async def``/``await`` source
string, then lowered by the sibling ``ast_lowering_runtime`` experiment into a
plain generator.  Nothing waits on GDB's main thread while the host owns a
callback.  Synchronous GDB commands remain synchronous: ``rpc-probe-plugin`` is
a normal ``gdb.Command`` and calls ``gdb.execute`` recursively from ``invoke``.

This proves that synchronous plugin execution can happen atomically between
lowered suspension points.  It does *not* suspend an already-active arbitrary
plugin ``invoke`` stack; a plugin that initiates a host callback would itself
need a cooperative/lowered boundary at that call site.
"""

import importlib.util
import inspect
import itertools
import os
import sys
import threading

import gdb
from gdb.dap.server import request, send_event


_lock = threading.RLock()
_operation_ids = itertools.count(1)
_callback_ids = itertools.count(1)
_trace_ids = itertools.count(1)
_operations = {}
_trace_log = []
_NO_VALUE = object()


def _load_lowering_runtime():
    """Load the adjacent experiment without mutating GDB's import path."""
    module_name = "_pwnc_rpc_probe_ast_lowering_runtime"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "ast_lowering_runtime.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load AST lowering runtime from %s" % path)
    module = importlib.util.module_from_spec(spec)
    # Dataclasses and postponed annotations expect the defining module to be
    # visible while its code executes.
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


_lowering = _load_lowering_runtime()


def _trace(kind, **fields):
    """Record and publish one trace entry from either GDB-owned thread."""
    with _lock:
        item = {
            "seq": next(_trace_ids),
            "kind": kind,
            "threadId": threading.get_ident(),
            "threadName": threading.current_thread().name,
        }
        item.update(fields)
        _trace_log.append(item)
    # GDB's send_event is documented as not requiring a particular thread.
    send_event("rpcProbeTrace", item)
    return item


class _RpcProbeCommand(gdb.Command):
    """A conventional synchronous plugin command used by the experiment."""

    def __init__(self):
        super().__init__("rpc-probe-plugin", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        label = argument.strip()
        _trace("plugin-enter", label=label, fromTty=bool(from_tty))

        # This is the important nested synchronous call: DAP evaluate invokes
        # this command through gdb.execute, and the plugin itself invokes
        # another GDB command through gdb.execute before returning.
        nested = gdb.execute("show pagination", from_tty=False, to_string=True)
        _trace(
            "plugin-nested-execute",
            label=label,
            nestedOutput=nested.strip(),
        )
        gdb.write("RPC_PROBE_PLUGIN %s\n" % label, gdb.STDOUT)
        _trace("plugin-return", label=label)


_RpcProbeCommand()


_OPERATION_SOURCE = r'''
async def _operation(state):
    """Async-looking source lowered to a stackless generator before use."""
    op_id = state["id"]
    depth = state["depth"]
    _trace("operation-enter", operationId=op_id, depth=depth)

    before_label = "operation-before-%d" % depth
    before = gdb.execute(
        "rpc-probe-plugin %s" % before_label,
        from_tty=False,
        to_string=True,
    )
    _trace(
        "operation-before-returned",
        operationId=op_id,
        depth=depth,
        output=before.strip(),
    )

    callback_result = await effect(
        "probe.callback",
        payload={"depth": depth, "operationId": op_id},
    )

    _trace(
        "operation-resumed",
        operationId=op_id,
        depth=depth,
        callbackResult=callback_result,
    )
    after_label = "operation-after-%d" % depth
    after = gdb.execute(
        "rpc-probe-plugin %s" % after_label,
        from_tty=False,
        to_string=True,
    )
    _trace(
        "operation-after-returned",
        operationId=op_id,
        depth=depth,
        output=after.strip(),
    )
    return {
        "operationId": op_id,
        "depth": depth,
        "callbackResult": callback_result,
        "before": before.strip(),
        "after": after.strip(),
    }
'''

_operation_namespace = {"gdb": gdb, "_trace": _trace}
_lowering.exec_lowered(
    _OPERATION_SOURCE,
    namespace=_operation_namespace,
    filename="<rpc-probe-lowered-operation>",
)
_operation = _operation_namespace["_operation"]
if not inspect.isgeneratorfunction(_operation) or inspect.iscoroutinefunction(_operation):
    raise RuntimeError("AST lowering did not produce a plain generator function")


def _fail_operation(state, error):
    with _lock:
        state["status"] = "failed"
        state["error"] = "%s: %s" % (type(error).__name__, error)
    _trace(
        "operation-failed",
        operationId=state["id"],
        depth=state["depth"],
        error=state["error"],
    )
    send_event(
        "rpcProbeFailed",
        {
            "operationId": state["id"],
            "depth": state["depth"],
            "error": state["error"],
        },
    )


def _drive(state, value=_NO_VALUE):
    """Advance one lowered Task step, always on GDB's main thread."""
    with _lock:
        state["status"] = "running"
    task = state["task"]
    if value is _NO_VALUE:
        yielded = task.resume()
    else:
        yielded = task.resume(value=value)

    if task.state is _lowering.TaskState.DONE:
        result = task.result
        with _lock:
            state["status"] = "done"
            state["result"] = result
        _trace(
            "operation-done",
            operationId=state["id"],
            depth=state["depth"],
            result=result,
        )
        send_event(
            "rpcProbeDone",
            {
                "operationId": state["id"],
                "depth": state["depth"],
                "result": result,
            },
        )
        return
    if task.state is not _lowering.TaskState.WAITING:
        _fail_operation(
            state,
            task.exception or RuntimeError("lowered task stopped unexpectedly"),
        )
        return
    if yielded.name != "probe.callback":
        task.close()
        _fail_operation(state, RuntimeError("operation yielded an invalid effect"))
        return

    effect_kwargs = yielded.call_kwargs()

    with _lock:
        callback_id = next(_callback_ids)
        state["status"] = "waiting-host"
        state["callbackId"] = callback_id
    _trace(
        "callback-emitted",
        operationId=state["id"],
        callbackId=callback_id,
        depth=state["depth"],
    )
    send_event(
        "rpcProbeCallback",
        {
            "operationId": state["id"],
            "parentOperationId": state["parentOperationId"],
            "callbackId": callback_id,
            "method": yielded.name,
            "payload": effect_kwargs.get("payload"),
            "depth": state["depth"],
        },
    )


def _start_on_gdb_thread(operation_id):
    state = _operations[operation_id]
    try:
        state["task"] = _lowering.Task(_operation(state))
        _trace(
            "lowered-task-created",
            operationId=operation_id,
            depth=state["depth"],
        )
        _drive(state)
    except BaseException as error:
        _fail_operation(state, error)


def _resume_on_gdb_thread(operation_id, callback_id, value):
    state = _operations[operation_id]
    with _lock:
        if state["status"] != "resume-queued":
            _fail_operation(state, RuntimeError("resume reached an invalid state"))
            return
        if state["callbackId"] != callback_id:
            _fail_operation(state, RuntimeError("resume callback id changed"))
            return
    _trace(
        "callback-resume-dispatched",
        operationId=operation_id,
        callbackId=callback_id,
        depth=state["depth"],
    )
    _drive(state, value)


@request("rpcProbeStart", on_dap_thread=True, expect_stopped=False)
def rpc_probe_start(**args):
    depth = int(args.get("depth", 0))
    parent = args.get("parentOperationId")
    with _lock:
        operation_id = next(_operation_ids)
        state = {
            "id": operation_id,
            "depth": depth,
            "parentOperationId": parent,
            "status": "start-queued",
            "callbackId": None,
            "task": None,
        }
        _operations[operation_id] = state
    _trace(
        "dap-start-accepted",
        operationId=operation_id,
        parentOperationId=parent,
        depth=depth,
    )
    gdb.post_event(lambda: _start_on_gdb_thread(operation_id))
    return {"operationId": operation_id, "status": "start-queued"}


@request("rpcProbeReply", on_dap_thread=True, expect_stopped=False)
def rpc_probe_reply(**args):
    operation_id = int(args["operationId"])
    callback_id = int(args["callbackId"])
    value = args.get("value")
    with _lock:
        state = _operations.get(operation_id)
        if state is None:
            raise RuntimeError("unknown operation %d" % operation_id)
        if state["status"] != "waiting-host":
            raise RuntimeError(
                "operation %d is %s, not waiting-host"
                % (operation_id, state["status"])
            )
        if state["callbackId"] != callback_id:
            raise RuntimeError(
                "callback mismatch for operation %d: expected %d, got %d"
                % (operation_id, state["callbackId"], callback_id)
            )
        state["status"] = "resume-queued"
    _trace(
        "dap-reply-accepted",
        operationId=operation_id,
        callbackId=callback_id,
        depth=state["depth"],
    )
    gdb.post_event(
        lambda: _resume_on_gdb_thread(operation_id, callback_id, value)
    )
    return {"operationId": operation_id, "status": "resume-queued"}


@request("rpcProbeSnapshot", on_dap_thread=True, expect_stopped=False)
def rpc_probe_snapshot(**args):
    with _lock:
        operations = {
            str(op_id): {
                "depth": state["depth"],
                "parentOperationId": state["parentOperationId"],
                "status": state["status"],
                "callbackId": state["callbackId"],
            }
            for op_id, state in _operations.items()
        }
        trace = list(_trace_log)
    return {
        "operations": operations,
        "trace": trace,
        "lowering": {
            "sourceUsesAsyncDef": "async def _operation" in _OPERATION_SOURCE,
            "sourceUsesAwait": "await effect" in _OPERATION_SOURCE,
            "resultIsGeneratorFunction": inspect.isgeneratorfunction(_operation),
            "resultIsCoroutineFunction": inspect.iscoroutinefunction(_operation),
        },
    }
