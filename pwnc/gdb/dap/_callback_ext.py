"""Stackless callback operations for GDB's DAP interpreter.

This file is sourced inside ``gdb --interpreter=dap``.  It intentionally does
not import :mod:`pwnc`: the adjacent lowering runtime is loaded directly by
file path so the embedded Python only needs its standard library and ``gdb``.

DAP request handlers execute on GDB's DAP thread.  They only validate data,
claim protocol state transitions, and queue work with :func:`gdb.post_event`.
Operation factories and every :class:`Task` step execute on GDB's main thread.
When a lowered operation yields an effect, its Python stack is retained as a
plain generator and GDB's main thread returns to the event loop.  A host can
then run ordinary synchronous GDB/plugin commands before replying and causing
the next generator step to be posted.
"""

# ruff: noqa: BLE001, I001, S110, UP031 -- embedded-GDB compatibility and guards

import importlib.util
import inspect
import itertools
import json
import math
import os
import sys
import threading
from collections import OrderedDict

import gdb
from gdb.dap.server import request, send_event


_LOWERING_MODULE = "_pwnc_gdb_dap_lowering"
_CAPABILITIES_MODULE = "_pwnc_gdb_dap_capabilities"
_INVOKE_EFFECT = "__pwnc_invoke_capability_v1__"
_MAX_ACTIVE_OPERATIONS = 1024
_MAX_OPERATION_DEPTH = 256
_TOMBSTONE_LIMIT = 256
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 100000
_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_NAME_CHARS = 256
_MAX_ERROR_CHARS = 16384
_MISSING = object()
_NO_VALUE = object()


def _load_adjacent_runtime(module_name, filename):
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load pwnc DAP runtime from %s" % path)
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


_lowering = _load_adjacent_runtime(_LOWERING_MODULE, "_lowering.py")
_capabilities = _load_adjacent_runtime(_CAPABILITIES_MODULE, "_capabilities.py")
_lock = threading.RLock()
_operation_ids = itertools.count(1)
_callback_ids = itertools.count(1)
_operations = {}
_active = {}
_root_scopes = {}
_tombstones = OrderedDict()
_gdb_main_thread_id = None


class HostCallbackError(RuntimeError):
    """A structured exception returned by a synchronous host callback."""

    def __init__(self, detail):
        self.detail = dict(detail)
        self.remote_type = str(detail.get("type") or "HostCallbackError")
        self.remote_module = str(detail.get("module") or "")
        self.remote_message = str(detail.get("message") or "")
        label = self.remote_type
        if self.remote_module:
            label = "%s.%s" % (self.remote_module, label)
        RuntimeError.__init__(self, "%s: %s" % (label, self.remote_message))


class _HostCallable:
    """Opaque GDB-side proxy for a callable owned by the host process.

    Calling into the host is a suspension point, so operation source must use
    ``await invoke(proxy, ...)``.  Keeping this object deliberately
    non-callable also prevents an ordinary GDB/plugin frame from accidentally
    pretending that it can block on the DAP thread.
    """

    __slots__ = ("reference",)

    def __init__(self, reference):
        self.reference = reference

    def __repr__(self):
        return "<pwnc host callable %s>" % getattr(self.reference, "capability_id", "?")

    def __call__(self, *_args, **_kwargs):
        raise TypeError("host callable proxies are suspension points; use await invoke(callback, ...)")


class _RootScope:
    """Capability namespace shared by one root operation and its children."""

    __slots__ = ("codec", "gdb_owner", "host_owner", "root_token")

    def __init__(self, root_token, host_owner):
        self.root_token = root_token
        self.host_owner = host_owner
        self.gdb_owner = _capabilities.new_token()
        self.codec = _capabilities.CapabilityCodec(
            owner=self.gdb_owner,
            root=root_token,
            peer_owner=host_owner,
            proxy_factory=_HostCallable,
        )

    def close(self):
        self.codec.close()


def _invoke(callback, *args, **kwargs):
    """Construct the effect used by ``await invoke(host_callback, ...)``."""

    if not isinstance(callback, _HostCallable):
        raise TypeError("invoke() target must be a host callable received through gdb.call()")
    return _lowering.Effect(
        name=_INVOKE_EFFECT,
        args=(callback,) + tuple(args),
        kwargs=kwargs,
    )


def _require_int(value, field):
    if type(value) is not int or value < 0:
        raise ValueError("%s must be a non-negative integer" % field)
    return value


def _require_name(value, field):
    if not isinstance(value, str) or not value or len(value) > _MAX_NAME_CHARS:
        raise ValueError("%s must be non-empty text of at most %d characters" % (field, _MAX_NAME_CHARS))
    return value


def _bounded_text(value):
    try:
        text = str(value)
    except BaseException as stringify_error:
        try:
            detail = repr(stringify_error)
        except BaseException:
            detail = "<unprintable stringification error>"
        text = "<%s while formatting error: %s>" % (
            type(stringify_error).__name__,
            detail,
        )
    if len(text) > _MAX_ERROR_CHARS:
        return text[:_MAX_ERROR_CHARS] + "..."
    return text


def _serialize_error(error):
    return {
        "type": _bounded_text(type(error).__name__),
        "module": _bounded_text(type(error).__module__),
        "message": _bounded_text(error),
    }


def _normalize_json(value, field="value"):
    """Return a JSON-native copy and reject cycles or unsafe values early."""

    remaining = [_MAX_JSON_NODES]
    ancestors = set()

    def visit(item, depth, path):
        remaining[0] -= 1
        if remaining[0] < 0:
            raise ValueError("%s exceeds the JSON node limit" % field)
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("%s exceeds the JSON nesting limit" % field)

        if item is None or type(item) in (bool, int, str):
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError("%s contains a non-finite float at %s" % (field, path))
            return item

        if type(item) in (list, tuple):
            identity = id(item)
            if identity in ancestors:
                raise ValueError("%s contains a cycle at %s" % (field, path))
            ancestors.add(identity)
            try:
                return [visit(child, depth + 1, "%s[%d]" % (path, index)) for index, child in enumerate(item)]
            finally:
                ancestors.remove(identity)

        if type(item) is dict:
            identity = id(item)
            if identity in ancestors:
                raise ValueError("%s contains a cycle at %s" % (field, path))
            ancestors.add(identity)
            try:
                result = {}
                for key, child in item.items():
                    if type(key) is not str:
                        raise TypeError("%s contains a non-text key at %s" % (field, path))
                    result[key] = visit(child, depth + 1, "%s.%s" % (path, key))
                return result
            finally:
                ancestors.remove(identity)

        raise TypeError("%s contains non-JSON value %s at %s" % (field, type(item).__name__, path))

    normalized = visit(value, 0, field)
    encoded = json.dumps(
        normalized,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("%s encodes to %d bytes; limit is %d" % (field, len(encoded), _MAX_JSON_BYTES))
    return normalized


def _decode_value(scope, value, field):
    if scope is None:
        return _normalize_json(value, field)
    return scope.codec.decode(value, field=field)


def _encode_value(scope, value, field):
    if scope is None:
        return _normalize_json(value, field)
    return scope.codec.encode(value, field=field)


def _register_operation(name, factory=None, replace=False):
    """Register a lowered generator factory, directly or as a decorator."""

    name = _require_name(name, "operation name")
    if factory is None:

        def decorate(candidate):
            _register_operation(name, candidate, replace=replace)
            return candidate

        return decorate
    if not callable(factory):
        raise TypeError("operation factory must be callable")
    if inspect.iscoroutinefunction(factory):
        raise TypeError("operation factory is a native coroutine function; register its lowered generator instead")
    with _lock:
        if name in _operations and not replace:
            raise ValueError("operation %r is already registered" % name)
        if name not in _operations and len(_operations) >= _MAX_ACTIVE_OPERATIONS:
            raise RuntimeError("operation registry limit reached")
        _operations[name] = factory
    return factory


def _unregister_operation(name):
    name = _require_name(name, "operation name")
    with _lock:
        if any(state["name"] == name for state in _active.values()):
            raise RuntimeError("operation %r is active" % name)
        return _operations.pop(name, None) is not None


def _exec_lowered(source, namespace=None, filename="<pwnc-gdb-operation>"):
    if namespace is None:
        namespace = {}
    namespace.setdefault("gdb", gdb)
    namespace.setdefault("invoke", _invoke)
    return _lowering.exec_lowered(source, namespace=namespace, filename=filename)


def _assert_gdb_main(action):
    global _gdb_main_thread_id

    current = threading.get_ident()
    with _lock:
        if _gdb_main_thread_id is None:
            _gdb_main_thread_id = current
        elif _gdb_main_thread_id != current:
            raise AssertionError("%s did not execute on GDB's main thread" % action)


def _operation_summary(state):
    summary = {
        "operationId": state["id"],
        "operationName": state["name"],
        "parentOperationId": state["parentOperationId"],
        "parentCallbackId": state["parentCallbackId"],
        "rootToken": state["rootToken"],
        "depth": state["depth"],
        "callbackId": state["callbackId"],
        "status": state["status"],
        "cancelRequested": state["cancelRequested"],
        "cancelDispatched": state["cancelDispatched"],
        "acceptedReplies": state["acceptedReplies"],
    }
    if state["scope"] is not None:
        summary["gdbOwner"] = state["scope"].gdb_owner
    return summary


def _remember_tombstone(state, outcome, detail):
    tombstone = _operation_summary(state)
    tombstone["outcome"] = outcome
    if outcome != "done":
        tombstone["error"] = detail
    _tombstones[state["id"]] = tombstone
    _tombstones.move_to_end(state["id"])
    while len(_tombstones) > _TOMBSTONE_LIMIT:
        _tombstones.popitem(last=False)
    return tombstone


def _finish(state, outcome, detail):
    _assert_gdb_main("operation completion")
    scope_to_close = None
    with _lock:
        if _active.get(state["id"]) is not state:
            return
        state["status"] = outcome
        del _active[state["id"]]
        tombstone = _remember_tombstone(state, outcome, detail)
        scope = state["scope"]
        if (
            scope is not None
            and not any(candidate["rootToken"] == state["rootToken"] for candidate in _active.values())
            and _root_scopes.get(state["rootToken"]) is scope
        ):
            scope_to_close = _root_scopes.pop(state["rootToken"])

    body = _operation_summary(state)
    body["tombstone"] = tombstone
    if outcome == "done":
        body["result"] = detail
        event = "pwncOperationDone"
    elif outcome == "cancelled":
        body["error"] = detail
        event = "pwncOperationCancelled"
    else:
        body["error"] = detail
        event = "pwncOperationFailed"
    try:
        send_event(event, body)
    finally:
        if scope_to_close is not None:
            scope_to_close.close()


def _finish_from_task(state):
    task = state["task"]
    if task.state is _lowering.TaskState.DONE:
        try:
            result = _encode_value(state["scope"], task.result, "operation result")
        except BaseException as error:
            _finish(state, "failed", _serialize_error(error))
        else:
            _finish(state, "done", result)
        return
    if task.state is _lowering.TaskState.CANCELLED:
        _finish(state, "cancelled", _serialize_error(task.exception))
        return
    error = task.exception or RuntimeError("operation task terminated in state %s" % task.state.name.lower())
    _finish(state, "failed", _serialize_error(error))


def _fail_state(state, error):
    task = state.get("task")
    if task is not None and not task.terminal:
        try:
            task.force_close()
        except BaseException:
            pass
    _finish(state, "failed", _serialize_error(error))


def _prepare_effect(state, yielded):
    if not isinstance(yielded, _lowering.Effect):
        raise _lowering.EffectProtocolError("operation yielded %s instead of an Effect" % type(yielded).__name__)
    method = _require_name(yielded.name, "effect name")
    invoke_target = None
    effect_args = list(yielded.args)
    if method == _INVOKE_EFFECT:
        if state["scope"] is None:
            raise RuntimeError("invoke() requires a capability-enabled gdb.call()")
        if not effect_args or not isinstance(effect_args[0], _HostCallable):
            raise _lowering.EffectProtocolError("invoke effect is missing its host callable target")
        host_callable = effect_args.pop(0)
        reference = host_callable.reference
        if reference.root != state["rootToken"]:
            raise RuntimeError("host callable belongs to a different root operation")
        if reference.owner != state["scope"].host_owner:
            raise RuntimeError("host callable owner does not match this operation")
        invoke_target = state["scope"].codec.encode(host_callable, field="invoke target")

    payload = _encode_value(
        state["scope"],
        {
            "args": effect_args,
            "kwargs": yielded.call_kwargs(),
        },
        "effect payload",
    )
    with _lock:
        if _active.get(state["id"]) is not state:
            return None
        callback_id = next(_callback_ids)
        state["callbackId"] = callback_id
        state["status"] = "waiting-host"
        cancelling = bool(state["cancelRequested"])
    body = _operation_summary(state)
    body.update(
        {
            "callbackId": callback_id,
            "args": payload["args"],
            "kwargs": payload["kwargs"],
            "cancelling": cancelling,
        }
    )
    if invoke_target is None:
        body["method"] = method
    else:
        body["target"] = invoke_target
    return body


def _call_as_generator(factory, args, kwargs):
    """Adapt both ordinary and lowered callables to :class:`Task`'s protocol."""

    result = factory(*args, **kwargs)
    if inspect.iscoroutine(result):
        result.close()
        raise TypeError("GDB callable returned a native coroutine; lower it with gdb.pwnc_exec_lowered")
    if inspect.isgenerator(result):
        return (yield from result)
    return result


def _drive(state, value=_NO_VALUE, error=None):
    """Advance one operation until it suspends or terminates on GDB main."""

    _assert_gdb_main("operation task step")
    task = state["task"]
    protocol_failures = 0
    while True:
        with _lock:
            if _active.get(state["id"]) is not state:
                return
            state["status"] = "running"
            inject_cancel = state["cancelRequested"] and not state["cancelDispatched"]
            if inject_cancel:
                state["cancelDispatched"] = True

        if inject_cancel:
            yielded = task.cancel()
        elif error is not None:
            yielded = task.resume(error=error)
            error = None
        elif value is _NO_VALUE:
            yielded = task.resume()
        else:
            yielded = task.resume(value=value)
            value = _NO_VALUE

        if task.terminal:
            _finish_from_task(state)
            return

        # Cancellation can be accepted on the DAP thread while this main-thread
        # step is running. Inject it before publishing the newly yielded effect.
        with _lock:
            cancel_after_step = state["cancelRequested"] and not state["cancelDispatched"]
            if cancel_after_step:
                state["cancelDispatched"] = True
        if cancel_after_step:
            yielded = task.cancel()
            if task.terminal:
                _finish_from_task(state)
                return

        try:
            body = _prepare_effect(state, yielded)
        except BaseException as protocol_error:
            protocol_failures += 1
            if protocol_failures > 16:
                _fail_state(
                    state,
                    RuntimeError("operation repeatedly produced invalid effects"),
                )
                return
            error = protocol_error
            continue
        if body is None:
            return
        try:
            send_event("pwncOperationCallback", body)
        except BaseException as send_error:
            _fail_state(state, send_error)
        return


def _start_on_gdb_main(operation_id):
    _assert_gdb_main("operation start")
    with _lock:
        state = _active.get(operation_id)
    if state is None:
        return
    try:
        generator = _call_as_generator(state["factory"], state["args"], state["kwargs"])
        state["task"] = _lowering.Task(generator)
        _drive(state)
    except BaseException as error:
        _fail_state(state, error)


def _resume_on_gdb_main(operation_id, callback_id, kind, payload):
    _assert_gdb_main("operation resume")
    with _lock:
        state = _active.get(operation_id)
        if state is None:
            return
        if state["callbackId"] != callback_id:
            return
        if state["status"] != "resume-queued":
            # Cancellation may claim the state after a reply was accepted but
            # before this posted continuation runs. The cancellation event owns
            # the next task step in that case.
            return
    if kind == "value":
        _drive(state, value=payload)
    else:
        _drive(state, error=HostCallbackError(payload))


def _cancel_on_gdb_main(operation_id):
    _assert_gdb_main("operation cancellation")
    with _lock:
        state = _active.get(operation_id)
        if state is None or not state["cancelRequested"]:
            return
        if state["cancelDispatched"]:
            return
        # If start has not constructed the Task yet, its earlier posted event
        # will observe cancelRequested and inject cancellation before first use.
        if state["task"] is None:
            return
    _drive(state)


def _terminal_lookup(operation_id, action):
    tombstone = _tombstones.get(operation_id)
    if tombstone is not None:
        raise RuntimeError("%s for terminal operation %d (%s)" % (action, operation_id, tombstone["outcome"]))
    raise RuntimeError("%s for unknown or expired operation %d" % (action, operation_id))


@request("pwncOperationStart", on_dap_thread=True, expect_stopped=False)
def pwnc_operation_start(**request_args):
    has_name = request_args.get("name") is not None
    has_target = request_args.get("target") is not None
    if has_name == has_target:
        raise ValueError("operation start requires exactly one of name or target")
    name = _require_name(request_args.get("name"), "operation name") if has_name else None
    supplied_target = request_args.get("target")
    supplied_args = request_args.get("args", [])
    supplied_kwargs = request_args.get("kwargs", {})
    if type(supplied_args) is not list:
        raise TypeError("operation args must be a list")
    if type(supplied_kwargs) is not dict:
        raise TypeError("operation kwargs must be an object")

    parent_id = request_args.get("parentOperationId")
    parent_callback_id = request_args.get("parentCallbackId")
    supplied_depth = request_args.get("depth")
    supplied_root = request_args.get("rootToken")
    supplied_host_owner = request_args.get("hostOwner")

    if supplied_depth is not None:
        supplied_depth = _require_int(supplied_depth, "depth")
    if supplied_root is not None:
        supplied_root = _require_name(supplied_root, "rootToken")
    if supplied_host_owner is not None:
        supplied_host_owner = _require_name(supplied_host_owner, "hostOwner")

    if parent_id is not None:
        parent_id = _require_int(parent_id, "parentOperationId")
        parent_callback_id = _require_int(
            parent_callback_id,
            "parentCallbackId",
        )
    elif parent_callback_id is not None:
        raise ValueError("a root operation cannot specify parentCallbackId")

    new_scope = None
    try:
        with _lock:
            if len(_active) >= _MAX_ACTIVE_OPERATIONS:
                raise RuntimeError("active operation limit %d reached" % _MAX_ACTIVE_OPERATIONS)
            operation_id = next(_operation_ids)

            if parent_id is None:
                depth = 0
                if supplied_depth is not None and supplied_depth != depth:
                    raise ValueError("root operation depth must be exactly zero")
                root_token = supplied_root or "operation-%d" % operation_id
                if supplied_host_owner is None:
                    if has_target:
                        raise ValueError("callable target requires hostOwner capability negotiation")
                    scope = None
                else:
                    if root_token in _root_scopes:
                        raise RuntimeError("rootToken %r is already active" % root_token)
                    new_scope = _RootScope(root_token, supplied_host_owner)
                    scope = new_scope
            else:
                parent = _active.get(parent_id)
                if parent is None:
                    _terminal_lookup(parent_id, "child start")
                if parent["status"] != "waiting-host":
                    raise RuntimeError(
                        "child operation parent %d is %s, not waiting-host" % (parent_id, parent["status"])
                    )
                if parent["callbackId"] != parent_callback_id:
                    raise RuntimeError("child operation parent callback does not match the active callback")
                depth = parent["depth"] + 1
                if supplied_depth is not None and supplied_depth != depth:
                    raise ValueError(
                        "child operation depth %r does not match lineage depth %d" % (supplied_depth, depth)
                    )
                root_token = parent["rootToken"]
                if supplied_root is not None and supplied_root != root_token:
                    raise ValueError("child operation rootToken does not match its parent")
                scope = parent["scope"]
                if scope is None:
                    if supplied_host_owner is not None or has_target:
                        raise ValueError("legacy operation lineage cannot use callable capabilities")
                elif supplied_host_owner != scope.host_owner:
                    raise ValueError("child operation hostOwner does not match its parent")

            if depth > _MAX_OPERATION_DEPTH:
                raise RuntimeError("operation depth %d exceeds limit %d" % (depth, _MAX_OPERATION_DEPTH))

            if has_name:
                factory = _operations.get(name)
                if factory is None:
                    raise RuntimeError("unknown pwnc operation %r" % name)
            else:
                factory = scope.codec.decode(supplied_target, field="operation target")
                if isinstance(factory, _HostCallable) or not callable(factory):
                    raise TypeError("operation target does not identify a GDB callable")
                name = "<gdb-callable>"

            call = _decode_value(
                scope,
                {"args": supplied_args, "kwargs": supplied_kwargs},
                "operation arguments",
            )
            if type(call) is not dict or type(call.get("args")) is not list or type(call.get("kwargs")) is not dict:
                raise TypeError("decoded operation args/kwargs have invalid types")

            state = {
                "id": operation_id,
                "name": name,
                "factory": factory,
                "args": call["args"],
                "kwargs": call["kwargs"],
                "parentOperationId": parent_id,
                "parentCallbackId": parent_callback_id,
                "rootToken": root_token,
                "depth": depth,
                "scope": scope,
                "status": "start-queued",
                "callbackId": None,
                "task": None,
                "cancelRequested": False,
                "cancelDispatched": False,
                "acceptedReplies": 0,
            }
            if new_scope is not None:
                _root_scopes[root_token] = new_scope
            _active[operation_id] = state
    except BaseException:
        if new_scope is not None:
            with _lock:
                if not any(candidate.get("scope") is new_scope for candidate in _active.values()):
                    if _root_scopes.get(new_scope.root_token) is new_scope:
                        _root_scopes.pop(new_scope.root_token, None)
                    new_scope.close()
        raise

    try:
        gdb.post_event(lambda: _start_on_gdb_main(operation_id))
    except BaseException:
        with _lock:
            _active.pop(operation_id, None)
            if new_scope is not None:
                _root_scopes.pop(root_token, None)
                new_scope.close()
        raise
    response = {
        "operationId": operation_id,
        "operationName": name,
        "parentOperationId": parent_id,
        "parentCallbackId": parent_callback_id,
        "rootToken": root_token,
        "depth": depth,
        "status": "start-queued",
    }
    if scope is not None:
        response["gdbOwner"] = scope.gdb_owner
    return response


@request("pwncOperationReply", on_dap_thread=True, expect_stopped=False)
def pwnc_operation_reply(**request_args):
    operation_id = _require_int(request_args.get("operationId"), "operationId")
    callback_id = _require_int(request_args.get("callbackId"), "callbackId")
    kind = request_args.get("kind")
    if kind not in ("value", "error"):
        raise ValueError("reply kind must be exactly 'value' or 'error'")
    has_value = "value" in request_args
    has_error = "error" in request_args
    if (kind == "value") != has_value or (kind == "error") != has_error:
        raise ValueError("reply must contain exactly the payload selected by kind")
    if kind == "error" and type(request_args["error"]) is not dict:
        raise TypeError("error reply payload must be an object")

    with _lock:
        state = _active.get(operation_id)
        if state is None:
            _terminal_lookup(operation_id, "reply")
        if state["callbackId"] != callback_id:
            raise RuntimeError(
                "callback mismatch for operation %d: expected %r, got %d"
                % (operation_id, state["callbackId"], callback_id)
            )
        if state["status"] != "waiting-host":
            raise RuntimeError(
                "duplicate or invalid reply for operation %d in state %s" % (operation_id, state["status"])
            )
        scope = state["scope"]

    if kind == "value":
        payload = _decode_value(scope, request_args["value"], "callback value")
    else:
        payload = _normalize_json(request_args["error"], "callback error")

    with _lock:
        state = _active.get(operation_id)
        if state is None:
            _terminal_lookup(operation_id, "reply")
        if state["callbackId"] != callback_id:
            raise RuntimeError(
                "callback mismatch for operation %d: expected %r, got %d"
                % (operation_id, state["callbackId"], callback_id)
            )
        if state["status"] != "waiting-host":
            raise RuntimeError(
                "duplicate or invalid reply for operation %d in state %s" % (operation_id, state["status"])
            )
        state["status"] = "resume-queued"
        state["acceptedReplies"] += 1

    try:
        gdb.post_event(
            lambda: _resume_on_gdb_main(
                operation_id,
                callback_id,
                kind,
                payload,
            )
        )
    except BaseException:
        with _lock:
            if _active.get(operation_id) is state:
                state["status"] = "waiting-host"
                state["acceptedReplies"] -= 1
        raise
    return {
        "operationId": operation_id,
        "callbackId": callback_id,
        "kind": kind,
        "status": "resume-queued",
    }


@request("pwncOperationCancel", on_dap_thread=True, expect_stopped=False)
def pwnc_operation_cancel(**request_args):
    operation_id = _require_int(request_args.get("operationId"), "operationId")
    with _lock:
        state = _active.get(operation_id)
        if state is None:
            _terminal_lookup(operation_id, "cancel")
        if state["cancelRequested"]:
            return {
                "operationId": operation_id,
                "callbackId": state["callbackId"],
                "status": "cancel-in-progress",
            }
        previous_status = state["status"]
        state["cancelRequested"] = True
        state["status"] = "cancel-queued"
        callback_id = state["callbackId"]

    try:
        gdb.post_event(lambda: _cancel_on_gdb_main(operation_id))
    except BaseException:
        with _lock:
            if _active.get(operation_id) is state:
                state["cancelRequested"] = False
                state["status"] = previous_status
        raise
    return {
        "operationId": operation_id,
        "callbackId": callback_id,
        "status": "cancel-queued",
    }


@request("pwncOperationSnapshot", on_dap_thread=True, expect_stopped=False)
def pwnc_operation_snapshot(**request_args):
    with _lock:
        active = {str(operation_id): _operation_summary(state) for operation_id, state in _active.items()}
        tombstones = {str(operation_id): dict(tombstone) for operation_id, tombstone in _tombstones.items()}
        operation_names = sorted(_operations)
        main_thread_id = _gdb_main_thread_id
    return {
        "active": active,
        "activeCount": len(active),
        "tombstones": tombstones,
        "tombstoneCount": len(tombstones),
        "operationNames": operation_names,
        "gdbMainThreadId": main_thread_id,
        "limits": {
            "activeOperations": _MAX_ACTIVE_OPERATIONS,
            "operationDepth": _MAX_OPERATION_DEPTH,
            "tombstones": _TOMBSTONE_LIMIT,
            "jsonBytes": _MAX_JSON_BYTES,
        },
    }


# Runtime-only hooks for pwnc-owned operation sources and test/plugin injection.
# They are module attributes rather than imports so an injected source can use
# them without putting the pwnc checkout on GDB's Python import path.
gdb.pwnc_register_operation = _register_operation
gdb.pwnc_unregister_operation = _unregister_operation
gdb.pwnc_exec_lowered = _exec_lowered
gdb.pwnc_effect = _lowering.effect
gdb.pwnc_invoke = _invoke
gdb.pwnc_lowering = _lowering
