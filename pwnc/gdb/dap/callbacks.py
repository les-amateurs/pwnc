"""Stackless synchronous callback operations over GDB DAP.

The public side of this module contains no coroutine API.  A GDB-side lowered
operation may yield an effect, at which point GDB's main thread returns to its
event loop.  The host runs the matching ordinary Python callback on a fresh OS
thread; that callback may synchronously execute GDB/plugin commands or start a
child operation.  Completion is condition-based, so no waiting thread reads or
dispatches DAP messages recursively.
"""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from concurrent.futures import CancelledError
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any

from ._capabilities import CapabilityCodec, CapabilityRef, new_token
from .transport import CONTROL_TIMEOUT, DapError, DapTimeout, DapTransport

DEFAULT_MAX_ACTIVE_CALLBACKS = 256
DEFAULT_MAX_CALLBACK_DEPTH = 64
DEFAULT_CLEANUP_CALLBACK_RESERVE = 8
DEFAULT_MAX_OPERATIONS = 4096
DEFAULT_HISTORY = 256
MAX_CALLBACK_JSON_BYTES = 4 * 1024 * 1024
MAX_CALLBACK_ERROR_CHARS = 16 * 1024


class OperationError(DapError):
    """Base class for a terminal GDB-side operation failure."""

    def __init__(self, message, body=None):
        super().__init__(message, command="pwncOperationStart", body=body)
        self.operation_body = body


class OperationFailed(OperationError):
    """The lowered GDB-side operation raised an exception."""


class OperationCancelled(OperationError):
    """The lowered GDB-side operation completed cooperative cancellation."""


class CallbackAdmissionError(OperationError):
    """The host could not safely admit a synchronous callback."""


class _CompletionCell:
    """A completion primitive with no inline callback execution surface."""

    def __init__(self):
        self._condition = threading.Condition()
        self._done = False
        self._result = None
        self._exception = None

    def done(self):
        with self._condition:
            return self._done

    def result(self, timeout=None):
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
            if self._exception is not None:
                raise self._exception
            return self._result

    def set_result(self, value):
        return self._finish(result=value)

    def set_exception(self, error):
        return self._finish(exception=error)

    def _finish(self, result=None, exception=None):
        with self._condition:
            if self._done:
                return False
            self._done = True
            self._result = result
            self._exception = exception
            self._condition.notify_all()
            return True


@dataclass(slots=True)
class _Operation:
    operation_id: int
    name: str
    callbacks: dict[str, Callable[..., Any]]
    cleanup_callbacks: frozenset[str]
    parent_operation_id: int | None
    parent_callback_id: int | None
    depth: int
    scope: _CapabilityScope | None = None
    cell: _CompletionCell = field(default_factory=_CompletionCell)
    cancel_started: bool = False
    cancel_requested: bool = False
    cancel_inflight: bool = False
    orphaned: bool = False
    last_callback_id: int = 0


@dataclass(slots=True)
class _CapabilityScope:
    root_token: str
    codec: CapabilityCodec | None = None
    proxy_factory: Callable[[CapabilityRef], Any] | None = None
    peer_owner: str | None = None
    starts: int = 0
    operations: int = 0
    workers: int = 0
    root_terminal: bool = False
    abandoned: bool = False


@dataclass(slots=True)
class _StartSpec:
    name: str
    callbacks: dict[str, Callable[..., Any]]
    cleanup_callbacks: frozenset[str]
    parent_operation_id: int | None
    parent_callback_id: int | None
    depth: int
    scope: _CapabilityScope | None = None


class RemoteCallable:
    """A synchronous, call-only proxy for a callable owned by GDB.

    Proxies deliberately have no remote attribute access.  They are valid only
    while an ordinary host callback is active in the same root operation; a
    call starts a child GDB operation and blocks this worker until it completes.
    """

    __slots__ = ("_dispatcher", "_ref", "_scope")

    def __init__(self, dispatcher, scope, ref: CapabilityRef):
        self._dispatcher = dispatcher
        self._scope = scope
        self._ref = ref

    def __call__(self, *args, **kwargs):
        return self._dispatcher._call_remote(self, args, kwargs)

    def __repr__(self):
        return f"<GDB callable {self._ref.capability_id}>"


class _ReplyOnce:
    def __init__(self, dispatcher, body):
        self._dispatcher = dispatcher
        self._body = body
        self._lock = threading.Lock()
        self._selected = None

    @property
    def selected(self):
        with self._lock:
            return self._selected

    def _claim(self, kind):
        with self._lock:
            if self._selected is not None:
                raise RuntimeError(f"callback {self._body['callbackId']} already selected {self._selected}")
            self._selected = kind

    def value(self, value):
        self._claim("value")
        return self._dispatcher._reply(
            self._body,
            kind="value",
            payload=value,
        )

    def error(self, error):
        self._claim("error")
        return self._dispatcher._reply(
            self._body,
            kind="error",
            payload=self._dispatcher._serialize_error(error),
        )


class OperationDispatcher:
    """Route lowered effects to ordinary synchronous host callbacks.

    Callback workers are deliberately not a fixed pool: an ancestor callback
    may synchronously wait for a child operation, so each admitted descendant
    needs a fresh stack.  Admission is atomic and rejection is replied to GDB as
    an explicit error, never silently dropped.
    """

    def __init__(
        self,
        transport: DapTransport,
        *,
        max_active_callbacks=DEFAULT_MAX_ACTIVE_CALLBACKS,
        max_callback_depth=DEFAULT_MAX_CALLBACK_DEPTH,
        cleanup_callback_reserve=DEFAULT_CLEANUP_CALLBACK_RESERVE,
        max_operations=DEFAULT_MAX_OPERATIONS,
        history=DEFAULT_HISTORY,
        thread_factory=threading.Thread,
    ):
        if max_active_callbacks is not None and (isinstance(max_active_callbacks, bool) or max_active_callbacks <= 0):
            raise ValueError("max_active_callbacks must be positive or None")
        if max_callback_depth is not None and (isinstance(max_callback_depth, bool) or max_callback_depth < 0):
            raise ValueError("max_callback_depth must be nonnegative or None")
        if isinstance(cleanup_callback_reserve, bool) or cleanup_callback_reserve < 0:
            raise ValueError("cleanup_callback_reserve must be nonnegative")
        if max_operations <= 0:
            raise ValueError("max_operations must be positive")
        if history <= 0:
            raise ValueError("history must be positive")

        self.transport = transport
        self.max_active_callbacks = max_active_callbacks
        self.max_callback_depth = max_callback_depth
        self.cleanup_callback_reserve = cleanup_callback_reserve
        self.max_operations = max_operations
        self.thread_factory = thread_factory

        self._condition = threading.Condition(threading.RLock())
        self._callback_context = threading.local()
        self._operations = {}
        self._owner_token = new_token()
        self._capability_scopes = {}
        self._starting_operations = 0
        self._start_cells = set()
        self._early_callbacks = OrderedDict()
        self._early_outcomes = OrderedDict()
        self._workers = {}
        self._worker_numbers = 0
        self._active_ordinary = 0
        self._active_cleanup = 0
        self._peak_active = 0
        self._closed = False
        self._close_started = False
        self._fatal_error = None
        self._terminal_error = None
        self._history_limit = history
        self._early_limit = max_operations
        self._completed = deque(maxlen=history)
        self._errors = deque(maxlen=history)
        self._rejections = deque(maxlen=history)
        self._reply_futures = set()
        self._subscriptions_active = True
        self._terminal_unsubscribe = None

        self._subscriptions = (
            ("pwncOperationCallback", self._on_callback),
            ("pwncOperationDone", self._on_done),
            ("pwncOperationFailed", self._on_failed),
            ("pwncOperationCancelled", self._on_cancelled),
        )
        for event, handler in self._subscriptions:
            transport.on(event, handler)
        try:
            terminal_unsubscribe = transport.add_terminal_listener(self._on_transport_terminal)
        except BaseException:
            for event, handler in self._subscriptions:
                transport.off(event, handler)
            raise
        with self._condition:
            if self._subscriptions_active:
                self._terminal_unsubscribe = terminal_unsubscribe
                terminal_unsubscribe = None
        if terminal_unsubscribe is not None:
            terminal_unsubscribe()

    @property
    def active_operations(self):
        with self._condition:
            return len(self._operations)

    @property
    def active_callbacks(self):
        with self._condition:
            return self._active_ordinary + self._active_cleanup

    @property
    def errors(self):
        with self._condition:
            return list(self._errors)

    @property
    def rejections(self):
        with self._condition:
            return list(self._rejections)

    @property
    def peak_active_callbacks(self):
        with self._condition:
            return self._peak_active

    @staticmethod
    def _remaining(deadline):
        if deadline is None:
            return None
        return max(0.0, deadline - time.monotonic())

    @staticmethod
    def _serialize_error(error):
        try:
            message = str(error)
        except BaseException as stringify_error:  # noqa: BLE001 - error boundary
            try:
                detail = repr(stringify_error)
            except BaseException:  # noqa: BLE001 - final error boundary
                detail = "<unprintable stringification error>"
            message = f"<error stringification failed: {detail}>"
        return {
            "type": type(error).__name__[:MAX_CALLBACK_ERROR_CHARS],
            "module": type(error).__module__[:MAX_CALLBACK_ERROR_CHARS],
            "message": message[:MAX_CALLBACK_ERROR_CHARS],
        }

    @staticmethod
    def _validate_callback_value(value):
        try:
            encoded = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            raise TypeError(f"callback returned a non-JSON value: {error}") from error
        if len(encoded) > MAX_CALLBACK_JSON_BYTES:
            raise ValueError(f"callback result is {len(encoded)} bytes; limit is {MAX_CALLBACK_JSON_BYTES}")
        return value

    @staticmethod
    def _remote_error(body):
        detail = body.get("error") or {}
        return "{}: {}".format(
            detail.get("type", "Error"),
            detail.get("message", ""),
        )

    def _new_capability_scope(self):
        root_token = new_token()
        scope = _CapabilityScope(root_token=root_token)
        scope.proxy_factory = lambda ref: RemoteCallable(self, scope, ref)
        scope.codec = CapabilityCodec(
            owner=self._owner_token,
            root=root_token,
        )
        with self._condition:
            if self._closed:
                scope.codec.close()
                raise DapError("operation dispatcher is closed")
            self._capability_scopes[root_token] = scope
        return scope

    def _bind_capability_peer(self, scope, peer_owner):
        if not isinstance(peer_owner, str) or not peer_owner:
            raise TypeError("GDB capability owner must be nonempty text")
        with self._condition:
            current = scope.peer_owner
            if current is not None and current != peer_owner:
                raise ValueError("GDB capability owner changed within an operation root")
        if current is None:
            scope.codec.bind_peer(peer_owner, scope.proxy_factory)
            with self._condition:
                if scope.peer_owner not in {None, peer_owner}:
                    raise ValueError("GDB capability owner changed while it was being bound")
                scope.peer_owner = peer_owner

    def _retire_scope_if_quiescent(self, scope):
        codec = None
        with self._condition:
            if (
                scope.root_terminal
                and scope.starts == 0
                and scope.operations == 0
                and scope.workers == 0
                and self._capability_scopes.get(scope.root_token) is scope
            ):
                self._capability_scopes.pop(scope.root_token, None)
                codec = scope.codec
        if codec is not None:
            codec.close()

    @staticmethod
    def _contains_remote_callable(value):
        remaining = [MAX_CALLBACK_JSON_BYTES]
        seen = set()

        def visit(item):
            remaining[0] -= 1
            if remaining[0] < 0:
                return False
            if isinstance(item, RemoteCallable):
                return True
            if type(item) in (list, tuple):
                identity = id(item)
                if identity in seen:
                    return False
                seen.add(identity)
                try:
                    return any(visit(child) for child in item)
                finally:
                    seen.remove(identity)
            if type(item) is dict:
                identity = id(item)
                if identity in seen:
                    return False
                seen.add(identity)
                try:
                    return any(visit(child) for child in item.values())
                finally:
                    seen.remove(identity)
            return False

        return visit(value)

    def call(self, name, /, *args, **kwargs):
        """Synchronously call a registered GDB operation with Python arguments."""

        return self._call(name, args, kwargs, timeout=None)

    def _call(
        self,
        name,
        args,
        kwargs,
        *,
        timeout,
        cancel_timeout=CONTROL_TIMEOUT,
    ):
        """Configured-call entry point used by :class:`Gdb` views.

        ``args`` and ``kwargs`` are separate here so execution controls never
        consume a keyword intended for the remote operation.
        """

        if not isinstance(name, str) or not name:
            raise TypeError("operation name must be nonempty text")
        return self._call_capability_target(
            name=name,
            target=None,
            args=tuple(args),
            kwargs=dict(kwargs),
            timeout=timeout,
            cancel_timeout=cancel_timeout,
        )

    def _call_remote(self, proxy, args, kwargs):
        parent_body = getattr(self._callback_context, "body", None)
        parent_operation = getattr(self._callback_context, "operation", None)
        if parent_body is None or parent_operation is None:
            raise CallbackAdmissionError(
                "a GDB callable may only be invoked synchronously from its active host callback"
            )
        with self._condition:
            parent_is_active = self._operations.get(int(parent_body["operationId"])) is parent_operation
        if not parent_is_active:
            raise CallbackAdmissionError("the host callback's parent GDB operation is no longer active")
        if parent_operation.scope is not proxy._scope:
            raise CallbackAdmissionError("GDB callable belongs to a different operation root")
        if proxy._scope.root_terminal:
            raise CallbackAdmissionError("GDB callable belongs to a completed operation root")
        if proxy._scope.abandoned:
            raise CallbackAdmissionError("GDB callable belongs to an abandoned operation root")
        target = proxy._scope.codec.encode(proxy, field="GDB callable target")
        return self._call_capability_target(
            name="<gdb-callable>",
            target=target,
            args=tuple(args),
            kwargs=dict(kwargs),
            timeout=None,
            cancel_timeout=CONTROL_TIMEOUT,
        )

    def _call_capability_target(
        self,
        *,
        name,
        target,
        args,
        kwargs,
        timeout,
        cancel_timeout,
    ):
        if timeout is not None and timeout < 0:
            raise ValueError("timeout cannot be negative")
        if cancel_timeout < 0:
            raise ValueError("cancel_timeout cannot be negative")
        parent_body = getattr(self._callback_context, "body", None)
        parent_operation = getattr(self._callback_context, "operation", None)
        if parent_body is None:
            if target is not None:
                raise CallbackAdmissionError("a GDB callable cannot escape its active operation root")
            scope = self._new_capability_scope()
            parent_id = None
            parent_callback_id = None
            depth = 0
        else:
            if parent_operation is None or parent_operation.scope is None:
                raise CallbackAdmissionError(
                    "the callable API cannot be introduced inside a legacy named-callback operation"
                )
            with self._condition:
                parent_is_active = self._operations.get(int(parent_body["operationId"])) is parent_operation
            if not parent_is_active:
                raise CallbackAdmissionError("host callback parent operation is no longer active")
            scope = parent_operation.scope
            if scope.root_terminal:
                raise CallbackAdmissionError("operation root is already complete")
            if scope.abandoned:
                raise CallbackAdmissionError("operation root has been abandoned")
            parent_id = int(parent_body["operationId"])
            parent_callback_id = int(parent_body["callbackId"])
            depth = int(parent_body["depth"]) + 1
            if parent_body.get("rootToken") not in {None, scope.root_token}:
                raise CallbackAdmissionError("host callback root lineage does not match its capability scope")

        try:
            wire_args = scope.codec.encode(list(args), field="operation args")
            wire_kwargs = scope.codec.encode(kwargs, field="operation kwargs")
        except BaseException:
            if depth == 0:
                with self._condition:
                    scope.root_terminal = True
                self._retire_scope_if_quiescent(scope)
            raise
        start_arguments = {
            "args": wire_args,
            "kwargs": wire_kwargs,
            "parentOperationId": parent_id,
            "parentCallbackId": parent_callback_id,
            "rootToken": scope.root_token,
            "hostOwner": self._owner_token,
            "depth": depth,
        }
        if target is None:
            start_arguments["name"] = name
        else:
            start_arguments["target"] = target
        spec = _StartSpec(
            name=name,
            callbacks={},
            cleanup_callbacks=frozenset(),
            parent_operation_id=parent_id,
            parent_callback_id=parent_callback_id,
            depth=depth,
            scope=scope,
        )
        return self._execute_start(
            spec,
            start_arguments,
            timeout=timeout,
            cancel_timeout=cancel_timeout,
        )

    def run(
        self,
        name,
        arguments=None,
        *,
        callbacks: Mapping[str, Callable[..., Any]] | None = None,
        cleanup_callbacks=(),
        timeout=None,
        cancel_timeout=CONTROL_TIMEOUT,
    ):
        """Compatibility API for legacy named-effect operations."""

        if not isinstance(name, str) or not name:
            raise TypeError("operation name must be nonempty text")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise TypeError("operation arguments must be a mapping")
        callback_map = dict(callbacks or {})
        for method, handler in callback_map.items():
            if not isinstance(method, str) or not method:
                raise TypeError("callback names must be nonempty text")
            if not callable(handler):
                raise TypeError("callback handlers must be callable")
        cleanup = frozenset(cleanup_callbacks)
        if not cleanup.issubset(callback_map):
            missing = sorted(cleanup.difference(callback_map))
            raise ValueError(f"cleanup callbacks have no handler: {missing!r}")
        if timeout is not None and timeout < 0:
            raise ValueError("timeout cannot be negative")
        if cancel_timeout < 0:
            raise ValueError("cancel_timeout cannot be negative")
        parent_body = getattr(self._callback_context, "body", None)
        parent_id = None if parent_body is None else int(parent_body["operationId"])
        parent_callback_id = None if parent_body is None else int(parent_body["callbackId"])
        depth = 0 if parent_body is None else int(parent_body["depth"]) + 1
        spec = _StartSpec(
            name=name,
            callbacks=callback_map,
            cleanup_callbacks=cleanup,
            parent_operation_id=parent_id,
            parent_callback_id=parent_callback_id,
            depth=depth,
        )
        return self._execute_start(
            spec,
            {
                "name": name,
                "args": [],
                "kwargs": dict(arguments),
                "parentOperationId": parent_id,
                "parentCallbackId": parent_callback_id,
                "depth": depth,
            },
            timeout=timeout,
            cancel_timeout=cancel_timeout,
        )

    def _execute_start(self, spec, start_arguments, *, timeout, cancel_timeout):
        operation_deadline = None if timeout is None else time.monotonic() + timeout
        retire_scope = None
        start_cell = _CompletionCell()
        with self._condition:
            if self._terminal_error is not None:
                admission_error = self._terminal_error
            elif self._closed:
                admission_error = DapError("operation dispatcher is closed")
            elif self._fatal_error is not None:
                admission_error = DapError(str(self._fatal_error))
            elif len(self._operations) + self._starting_operations >= self.max_operations:
                admission_error = CallbackAdmissionError(f"active operation limit {self.max_operations} reached")
            else:
                admission_error = None
                self._starting_operations += 1
                self._start_cells.add(start_cell)
                if spec.scope is not None:
                    spec.scope.starts += 1
            if admission_error is not None and spec.scope is not None and spec.depth == 0:
                spec.scope.root_terminal = True
                retire_scope = spec.scope
        if retire_scope is not None:
            self._retire_scope_if_quiescent(retire_scope)
        if admission_error is not None:
            raise admission_error
        try:
            start_future = self.transport.send(
                "pwncOperationStart",
                start_arguments,
            )
        except BaseException:
            with self._condition:
                self._start_cells.discard(start_cell)
                self._starting_operations -= 1
                if spec.scope is not None:
                    spec.scope.starts -= 1
                    if spec.depth == 0:
                        spec.scope.root_terminal = True
                self._discard_terminal_early_if_quiescent_locked()
                self._condition.notify_all()
            if spec.scope is not None:
                self._retire_scope_if_quiescent(spec.scope)
            raise

        start_deadline = time.monotonic() + CONTROL_TIMEOUT
        if operation_deadline is not None:
            start_deadline = min(start_deadline, operation_deadline)
        add_inline_done_callback = getattr(
            start_future,
            "_add_inline_done_callback",
            start_future.add_done_callback,
        )
        add_inline_done_callback(start_cell.set_result)
        try:
            ready_future = start_cell.result(max(0.0, start_deadline - time.monotonic()))
        except FutureTimeout as timeout_error:
            start_future.add_done_callback(lambda done: self._finish_timed_out_start(done, spec))
            raise DapTimeout(
                f"timed out starting GDB operation {spec.name!r}",
                command="pwncOperationStart",
            ) from timeout_error
        except BaseException:
            start_future.add_done_callback(lambda done: self._finish_abandoned_start(done, spec))
            raise
        finally:
            with self._condition:
                self._start_cells.discard(start_cell)

        try:
            started = self.transport.result(ready_future, timeout=0)
        except BaseException:
            self._release_failed_start(spec)
            raise
        operation = self._accept_started_operation(
            started,
            spec,
        )

        try:
            return self._wait_operation(operation, operation_deadline)
        except FutureTimeout as timeout_error:
            abandoned = self._abandon_operation_tree(operation)
            for candidate in sorted(abandoned, key=lambda item: item.depth, reverse=True):
                self._cancel_unobserved(candidate)
            cancel_deadline = time.monotonic() + cancel_timeout
            for candidate in sorted(abandoned, key=lambda item: item.depth, reverse=True):
                try:
                    candidate.cell.result(max(0.0, cancel_deadline - time.monotonic()))
                except (OperationCancelled, OperationFailed, FutureTimeout, DapError):
                    pass
            raise DapTimeout(
                f"timed out waiting for GDB operation {spec.name!r}",
                command="pwncOperationStart",
            ) from timeout_error

    def _abandon_operation_tree(self, operation):
        """Atomically revoke ordinary work and return the active subtree.

        Capability calls share one root scope, including children whose start
        response is still in flight.  Marking the scope makes those late starts
        self-cancel when they are registered.
        """

        with self._condition:
            if operation.scope is not None:
                operation.scope.abandoned = True
                abandoned = [candidate for candidate in self._operations.values() if candidate.scope is operation.scope]
            else:
                operation_ids = {operation.operation_id}
                while True:
                    descendants = {
                        candidate.operation_id
                        for candidate in self._operations.values()
                        if candidate.parent_operation_id in operation_ids
                    }
                    if descendants.issubset(operation_ids):
                        break
                    operation_ids.update(descendants)
                abandoned = [
                    candidate for candidate in self._operations.values() if candidate.operation_id in operation_ids
                ]
            for candidate in abandoned:
                candidate.orphaned = True
            self._condition.notify_all()
        return abandoned

    def _finish_abandoned_start(
        self,
        future,
        spec,
    ):
        try:
            started = self.transport.result(future, timeout=0)
        except BaseException as error:  # noqa: BLE001 - completion containment
            self._release_failed_start(spec)
            self._record_error(error)
            self._unsubscribe_if_quiescent()
            return
        try:
            self._accept_started_operation(
                started,
                spec,
                orphaned=True,
            )
        except BaseException as error:  # noqa: BLE001 - completion containment
            self._set_fatal(error)
            self._unsubscribe_if_quiescent()

    def _finish_timed_out_start(
        self,
        future,
        spec,
    ):
        try:
            started = self.transport.result(future, timeout=0)
        except BaseException as error:  # noqa: BLE001 - completion containment
            self._release_failed_start(spec)
            self._record_error(error)
            return
        try:
            self._accept_started_operation(
                started,
                spec,
                orphaned=True,
            )
        except BaseException as error:  # noqa: BLE001 - completion containment
            self._set_fatal(error)

    def _discard_terminal_early_if_quiescent_locked(self):
        """Drop unmatched early events once no start response can claim them."""
        if self._terminal_error is not None and self._starting_operations == 0:
            self._early_callbacks.clear()
            self._early_outcomes.clear()

    def _release_failed_start(self, spec):
        scope = spec.scope
        with self._condition:
            self._starting_operations -= 1
            if scope is not None:
                scope.starts -= 1
                if spec.depth == 0:
                    scope.root_terminal = True
            self._discard_terminal_early_if_quiescent_locked()
            self._condition.notify_all()
        if scope is not None:
            self._retire_scope_if_quiescent(scope)

    def _accept_started_operation(
        self,
        started,
        spec,
        *,
        orphaned=False,
    ):
        try:
            operation_id = started["operationId"]
            if type(operation_id) is not int or operation_id < 0:
                raise TypeError("operationId is not a nonnegative integer")
            operation_name = started.get("operationName", spec.name)
            if not isinstance(operation_name, str) or not operation_name:
                raise TypeError("operationName is not nonempty text")
            if spec.scope is not None:
                if started["operationName"] != spec.name:
                    raise ValueError("operationName does not match the request")
                if started["parentOperationId"] != spec.parent_operation_id:
                    raise ValueError("parentOperationId does not match the request")
                if started["parentCallbackId"] != spec.parent_callback_id:
                    raise ValueError("parentCallbackId does not match the request")
                if started["depth"] != spec.depth:
                    raise ValueError("operation depth does not match the request")
                if started["status"] != "start-queued":
                    raise ValueError("operation start status is not 'start-queued'")
                if started["rootToken"] != spec.scope.root_token:
                    raise ValueError("operation rootToken does not match the request")
                self._bind_capability_peer(spec.scope, started["gdbOwner"])
            operation = _Operation(
                operation_id=operation_id,
                name=operation_name,
                callbacks=spec.callbacks,
                cleanup_callbacks=spec.cleanup_callbacks,
                parent_operation_id=spec.parent_operation_id,
                parent_callback_id=spec.parent_callback_id,
                depth=spec.depth,
                scope=spec.scope,
                orphaned=orphaned or bool(spec.scope is not None and spec.scope.abandoned),
            )
        except (KeyError, TypeError, ValueError) as error:
            self._release_failed_start(spec)
            raise DapError(f"malformed pwncOperationStart response: {error}") from error

        with self._condition:
            # A completion event can legitimately beat the host thread which
            # consumes the start response.  Claim it before decrementing the
            # final in-flight start so terminal cleanup cannot discard it.
            early_callbacks = self._early_callbacks.pop(operation_id, [])
            early_outcome = self._early_outcomes.pop(operation_id, None)
            self._starting_operations -= 1
            if spec.scope is not None:
                spec.scope.starts -= 1
            registration_error = None
            closing = self._closed
            terminal_error = self._terminal_error
            completed_before_terminal = (
                terminal_error is not None
                and early_outcome is not None
                and not early_callbacks
            )
            if operation_id in self._operations:
                registration_error = DapError(f"duplicate operation id {operation_id}")
                operation.cell.set_exception(registration_error)
                if spec.scope is not None and spec.depth == 0:
                    spec.scope.root_terminal = True
                registered = False
            elif terminal_error is not None and not completed_before_terminal:
                operation.orphaned = True
                operation.cell.set_exception(terminal_error)
                if spec.scope is not None:
                    spec.scope.root_terminal = True
                registered = False
            else:
                self._operations[operation_id] = operation
                if spec.scope is not None:
                    spec.scope.operations += 1
                registered = True
                if closing and not completed_before_terminal:
                    operation.orphaned = True
                    operation.cell.set_exception(DapError("operation dispatcher closed"))
                elif self._fatal_error is not None:
                    operation.cell.set_exception(self._fatal_error)
            self._discard_terminal_early_if_quiescent_locked()
            self._condition.notify_all()

        if registration_error is not None:
            self._set_fatal(registration_error)
            if spec.scope is not None:
                self._retire_scope_if_quiescent(spec.scope)
        if terminal_error is not None and not registered:
            if spec.scope is not None:
                self._retire_scope_if_quiescent(spec.scope)
            self._unsubscribe_if_quiescent()
            return operation
        if registered:
            if operation.orphaned and early_outcome is None:
                self._cancel_unobserved(operation)
            for callback in early_callbacks:
                self._route_callback(operation, callback)
            if early_outcome is not None:
                self._complete_operation(*early_outcome)
            if closing and early_outcome is None:
                self._cancel_unobserved(operation)
        else:
            try:
                self.transport.send(
                    "pwncOperationCancel",
                    {"operationId": operation_id},
                )
            except DapError:
                pass
        return operation

    def _wait_operation(self, operation, deadline):
        return operation.cell.result(self._remaining(deadline))

    def cancel(self, operation_id, *, timeout=CONTROL_TIMEOUT):
        operation_id = int(operation_id)
        if timeout is not None and timeout < 0:
            raise ValueError("timeout cannot be negative")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while True:
                operation = self._operations.get(operation_id)
                if operation is None:
                    return False
                if operation.cancel_requested:
                    return True
                if not operation.cancel_inflight:
                    operation.cancel_started = True
                    operation.cancel_inflight = True
                    break
                remaining = self._remaining(deadline)
                if remaining is not None and remaining <= 0:
                    raise DapTimeout(
                        f"timed out waiting to cancel GDB operation {operation_id}",
                        command="pwncOperationCancel",
                    )
                self._condition.wait(remaining)
        try:
            self.transport.request(
                "pwncOperationCancel",
                {"operationId": operation_id},
                timeout=self._remaining(deadline),
            )
        except BaseException:
            with self._condition:
                operation.cancel_inflight = False
                self._condition.notify_all()
            raise
        with self._condition:
            operation.cancel_requested = True
            operation.cancel_inflight = False
            self._condition.notify_all()
        return True

    def _on_callback(self, body):
        try:
            operation_id = body["operationId"]
            callback_id = body["callbackId"]
            if type(operation_id) is not int or operation_id < 0:
                raise TypeError("operationId is not a nonnegative integer")
            if type(callback_id) is not int or callback_id < 0:
                raise TypeError("callbackId is not a nonnegative integer")
        except (KeyError, TypeError, ValueError) as error:
            self._set_fatal(DapError(f"malformed operation callback: {error}"))
            return

        callback = dict(body)
        fatal_error = None
        rejection = None
        with self._condition:
            operation = self._operations.get(operation_id)
            if operation is None:
                if self._closed and self._starting_operations == 0:
                    rejection = "operation dispatcher is closed"
                elif any(completed["operationId"] == operation_id for _outcome, completed in self._completed):
                    fatal_error = DapError(f"late callback for completed operation {operation_id}")
                elif operation_id in self._early_outcomes:
                    fatal_error = DapError(f"callback after terminal outcome for operation {operation_id}")
                else:
                    callbacks = self._early_callbacks.get(operation_id)
                    if callbacks is None and len(self._early_callbacks) >= self._early_limit:
                        fatal_error = DapError("early callback operation limit reached")
                    elif callbacks is not None and len(callbacks) >= self._history_limit:
                        fatal_error = DapError(f"too many early callbacks for operation {operation_id}")
                    else:
                        if callbacks is None:
                            callbacks = []
                            self._early_callbacks[operation_id] = callbacks
                        callbacks.append(callback)
                        return

        if fatal_error is not None:
            self._set_fatal(fatal_error)
            return
        if rejection is not None:
            self._reject(callback, rejection)
            return
        self._route_callback(operation, callback)

    def _route_callback(self, operation, body):
        method = body.get("method")
        has_target = "target" in body
        depth = body.get("depth")
        callback_id = body.get("callbackId")
        if has_target == (method is not None):
            self._set_fatal(DapError("operation callback must select exactly one method or callable target"))
            return
        if not has_target and (not isinstance(method, str) or not method):
            self._set_fatal(DapError("operation callback method is not text"))
            return
        if type(callback_id) is not int or callback_id < 0:
            self._set_fatal(DapError("operation callbackId is invalid"))
            return
        if type(depth) is not int or depth < 0:
            self._reject(body, "callback depth must be a nonnegative integer")
            return
        if depth != operation.depth:
            self._reject(body, "callback depth does not match its operation")
            return
        if operation.scope is None and body.get("operationName") not in {None, operation.name}:
            self._set_fatal(DapError("callback operation name does not match"))
            return
        if operation.scope is not None and body.get("operationName") != operation.name:
            self._set_fatal(DapError("callback operation name does not match"))
            return
        if body.get("parentOperationId") != operation.parent_operation_id:
            self._set_fatal(DapError("callback parent lineage does not match"))
            return
        if operation.scope is not None and body.get("rootToken") != operation.scope.root_token:
            self._set_fatal(DapError("callback capability root does not match its operation"))
            return
        if operation.scope is not None:
            if "parentOperationId" not in body:
                self._set_fatal(DapError("callback parent operation lineage is missing"))
                return
            if "parentCallbackId" not in body or body["parentCallbackId"] != operation.parent_callback_id:
                self._set_fatal(DapError("callback parent callback lineage does not match"))
                return
            if body.get("status") != "waiting-host":
                self._set_fatal(DapError("callback status is not 'waiting-host'"))
                return
            if body.get("gdbOwner") != operation.scope.peer_owner:
                self._set_fatal(DapError("callback GDB capability owner does not match"))
                return
        with self._condition:
            if callback_id <= operation.last_callback_id:
                duplicate_error = DapError(
                    f"duplicate or reordered callback id {callback_id} for operation {operation.operation_id}"
                )
            else:
                operation.last_callback_id = callback_id
                duplicate_error = None
        if duplicate_error is not None:
            self._set_fatal(duplicate_error)
            return
        cancelling = body.get("cancelling", False)
        if type(cancelling) is not bool:
            self._reject(body, "callback cancelling flag must be boolean")
            return
        if cancelling and not operation.cancel_started and not self._closed:
            self._reject(body, "callback claimed cancellation cleanup before cancellation began")
            return
        cleanup = cancelling or method in operation.cleanup_callbacks

        if has_target:
            if operation.scope is None:
                self._reject(body, "callable callback target requires a capability operation")
                return
            try:
                handler = operation.scope.codec.decode(
                    body["target"],
                    field="callback target",
                )
            except BaseException as error:  # noqa: BLE001 - protocol boundary
                self._reject(body, f"invalid host callable target: {error}")
                return
            if isinstance(handler, RemoteCallable) or not callable(handler):
                self._reject(body, "callback target is not a host-owned callable")
                return
        else:
            handler = operation.callbacks.get(method)
            if handler is None:
                self._reject(body, f"no host handler for callback {method!r}")
                return

        rejection = None
        worker = None
        with self._condition:
            if (operation.orphaned or operation.cancel_started) and not cleanup:
                rejection = "operation caller stopped accepting ordinary callbacks"
            elif self._closed and not cleanup:
                rejection = "operation dispatcher is closed"
            elif self.max_callback_depth is not None and depth > self.max_callback_depth:
                rejection = f"callback depth {depth} exceeds configured maximum {self.max_callback_depth}"
            elif cleanup and self._active_cleanup >= self.cleanup_callback_reserve:
                rejection = f"cleanup callback reserve {self.cleanup_callback_reserve} exhausted"
            elif (
                not cleanup
                and self.max_active_callbacks is not None
                and self._active_ordinary >= self.max_active_callbacks
            ):
                rejection = f"active callback limit {self.max_active_callbacks} reached"
            else:
                self._worker_numbers += 1
                number = self._worker_numbers
                try:
                    worker = self.thread_factory(
                        target=self._run_callback,
                        args=(operation, body, handler, cleanup),
                        name=f"pwnc-gdb-callback-{number}",
                        daemon=True,
                    )
                except BaseException as error:  # noqa: BLE001 - injected factory
                    rejection = f"callback worker construction failed: {error}"
                else:
                    self._workers[number] = worker
                    if operation.scope is not None:
                        operation.scope.workers += 1
                    if cleanup:
                        self._active_cleanup += 1
                    else:
                        self._active_ordinary += 1
                    self._peak_active = max(
                        self._peak_active,
                        self._active_ordinary + self._active_cleanup,
                    )
        if rejection is not None:
            self._reject(body, rejection)
            return

        try:
            worker.start()
        except BaseException as error:  # noqa: BLE001 - Thread.start guard
            with self._condition:
                never_started = worker.ident is None
                if never_started:
                    self._workers.pop(number, None)
                    if operation.scope is not None:
                        operation.scope.workers -= 1
                    if cleanup:
                        self._active_cleanup -= 1
                    else:
                        self._active_ordinary -= 1
                self._condition.notify_all()
            if never_started:
                if operation.scope is not None:
                    self._retire_scope_if_quiescent(operation.scope)
                self._reject(body, f"callback worker could not start: {error}")
            else:
                self._record_error(error)

    def _run_callback(self, operation, body, handler, cleanup):
        number = None
        with self._condition:
            current = threading.current_thread()
            for candidate, worker in self._workers.items():
                if worker is current:
                    number = candidate
                    break
        guard = _ReplyOnce(self, body)
        previous = getattr(self._callback_context, "body", None)
        previous_operation = getattr(self._callback_context, "operation", None)
        self._callback_context.body = body
        self._callback_context.operation = operation
        try:
            args = body.get("args", [])
            kwargs = body.get("kwargs", {})
            if operation.scope is not None:
                args = operation.scope.codec.decode(args, field="callback args")
                kwargs = operation.scope.codec.decode(kwargs, field="callback kwargs")
            if not isinstance(args, list) or not isinstance(kwargs, dict):
                raise TypeError("callback args/kwargs have invalid wire types")
            try:
                with self._condition:
                    revoked_before_start = (
                        operation.orphaned or operation.cancel_started or self._closed
                    ) and not cleanup
                if revoked_before_start:
                    raise CallbackAdmissionError("operation stopped accepting ordinary callbacks before execution")
                value = handler(*args, **kwargs)
                if operation.scope is None:
                    value = self._validate_callback_value(value)
                else:
                    value = operation.scope.codec.encode(value, field="callback result")
            except BaseException as error:  # noqa: BLE001 - crosses RPC boundary
                guard.error(error)
            else:
                guard.value(value)
        except DapError as error:
            # Cancellation can terminally invalidate the callback being
            # unwound.  Preserve unexpected failures as diagnostics.
            if not operation.cancel_started and not self._closed:
                self._set_fatal(error)
        except BaseException as error:  # noqa: BLE001 - worker containment
            self._set_fatal(error)
            if guard.selected is None:
                try:
                    guard.error(error)
                except BaseException as reply_error:  # noqa: BLE001
                    self._set_fatal(reply_error)
        finally:
            self._callback_context.body = previous
            self._callback_context.operation = previous_operation
            with self._condition:
                if number is not None:
                    self._workers.pop(number, None)
                if cleanup:
                    self._active_cleanup -= 1
                else:
                    self._active_ordinary -= 1
                if operation.scope is not None:
                    operation.scope.workers -= 1
                self._condition.notify_all()
            if operation.scope is not None:
                self._retire_scope_if_quiescent(operation.scope)

    def _reply(self, body, *, kind, payload):
        arguments = {
            "operationId": int(body["operationId"]),
            "callbackId": int(body["callbackId"]),
            "kind": kind,
        }
        arguments["value" if kind == "value" else "error"] = payload
        return self.transport.request(
            "pwncOperationReply",
            arguments,
            timeout=CONTROL_TIMEOUT,
        )

    def _reject(self, body, reason):
        rejection = {
            "operationId": body.get("operationId"),
            "callbackId": body.get("callbackId"),
            "reason": reason,
        }
        with self._condition:
            self._rejections.append(rejection)
        try:
            future = self.transport.send(
                "pwncOperationReply",
                {
                    "operationId": int(body["operationId"]),
                    "callbackId": int(body["callbackId"]),
                    "kind": "error",
                    "error": {
                        "type": "CallbackAdmissionError",
                        "module": __name__,
                        "message": reason,
                    },
                },
            )
        except BaseException as error:  # noqa: BLE001 - event-lane containment
            self._set_fatal(error)
            return
        with self._condition:
            self._reply_futures.add(future)

        def collect(done):
            with self._condition:
                self._reply_futures.discard(done)
            try:
                self.transport.result(done, timeout=0)
            except (DapError, CancelledError) as error:
                self._set_fatal(error)

        future.add_done_callback(collect)

    def _on_done(self, body):
        self._complete_operation("done", dict(body))

    def _on_failed(self, body):
        self._complete_operation("failed", dict(body))

    def _on_cancelled(self, body):
        self._complete_operation("cancelled", dict(body))

    def _complete_operation(self, outcome, body):
        try:
            operation_id = body["operationId"]
            if type(operation_id) is not int or operation_id < 0:
                raise TypeError("operationId is not a nonnegative integer")
            if outcome in {"failed", "cancelled"}:
                detail = body.get("error")
                if not isinstance(detail, Mapping):
                    raise TypeError(f"{outcome} outcome error is not an object")
                for key in ("type", "module", "message"):
                    if key in detail and not isinstance(detail[key], str):
                        raise TypeError(f"{outcome} outcome error {key} is not text")
        except (KeyError, TypeError, ValueError) as error:
            self._set_fatal(DapError(f"malformed operation outcome: {error}"))
            return
        with self._condition:
            operation = self._operations.pop(operation_id, None)
            if operation is None:
                if self._closed and self._starting_operations == 0:
                    return
                if any(completed["operationId"] == operation_id for _prior, completed in self._completed):
                    duplicate_error = DapError(f"duplicate outcome for operation {operation_id}")
                else:
                    duplicate_error = None
                if duplicate_error is not None:
                    self._set_fatal(duplicate_error)
                    return
                if operation_id in self._early_outcomes:
                    self._set_fatal(DapError(f"duplicate outcome for operation {operation_id}"))
                    return
                if len(self._early_outcomes) >= self._early_limit:
                    self._set_fatal(DapError("early outcome operation limit reached"))
                    return
                self._early_outcomes[operation_id] = (outcome, body)
                return
            self._completed.append((outcome, body))
            self._condition.notify_all()
        scope = operation.scope
        try:
            if scope is None:
                if body.get("operationName") not in {None, operation.name}:
                    raise DapError("operation outcome name does not match its start response")
            else:
                if body["operationName"] != operation.name:
                    raise DapError("operation outcome name does not match its start response")
                if body["parentOperationId"] != operation.parent_operation_id:
                    raise DapError("operation outcome parent lineage does not match")
                if body["parentCallbackId"] != operation.parent_callback_id:
                    raise DapError("operation outcome parent callback lineage does not match")
                if body["depth"] != operation.depth:
                    raise DapError("operation outcome depth does not match")
                if body["rootToken"] != scope.root_token:
                    raise DapError("operation outcome capability root does not match")
                if body["gdbOwner"] != scope.peer_owner:
                    raise DapError("operation outcome GDB capability owner does not match")
                if body["status"] != outcome:
                    raise DapError("operation outcome status does not match its event")
            if outcome == "done":
                result = body.get("result") if scope is None else body["result"]
                if scope is not None:
                    result = scope.codec.decode(result, field="operation result")
                    if operation.depth == 0 and self._contains_remote_callable(result):
                        raise TypeError(
                            "a GDB callable cannot escape the completed root operation; "
                            "persistent callbacks require an explicit lifetime API"
                        )
                operation.cell.set_result(result)
            elif outcome == "cancelled":
                operation.cell.set_exception(
                    OperationCancelled(
                        f"GDB operation {operation_id} was cancelled",
                        body=body,
                    )
                )
            else:
                operation.cell.set_exception(
                    OperationFailed(
                        f"GDB operation {operation_id} failed: {self._remote_error(body)}",
                        body=body,
                    )
                )
        except BaseException as error:  # noqa: BLE001 - terminal wire boundary
            operation.cell.set_exception(
                OperationFailed(
                    f"GDB operation {operation_id} returned an invalid result: {error}",
                    body=body,
                )
            )
        finally:
            if scope is not None:
                with self._condition:
                    scope.operations -= 1
                    if operation.depth == 0:
                        scope.root_terminal = True
                    self._condition.notify_all()
                self._retire_scope_if_quiescent(scope)
        self._unsubscribe_if_quiescent()

    def _record_error(self, error):
        with self._condition:
            self._errors.append(error)

    def _on_transport_terminal(self, reason):
        """Atomically terminate every waiter when the DAP channel dies."""
        if not isinstance(reason, str) or not reason:
            reason = "GDB DAP channel closed during operation"
        error = DapError(reason)
        with self._condition:
            if self._terminal_error is not None:
                return
            self._terminal_error = error
            self._closed = True
            start_cells = list(self._start_cells)
            operations = list(self._operations.values())
            self._operations.clear()
            scopes = list(self._capability_scopes.values())
            for operation in operations:
                operation.orphaned = True
                if operation.scope is not None:
                    operation.scope.operations -= 1
            for scope in scopes:
                scope.root_terminal = True
            # Keep outcomes which arrived before EOF long enough for an
            # already-received start response to claim them.  Failed/pending
            # starts discard the unmatched remainder when the count reaches 0.
            self._discard_terminal_early_if_quiescent_locked()
            self._condition.notify_all()
        for start_cell in start_cells:
            start_cell.set_exception(error)
        for operation in operations:
            operation.cell.set_exception(error)
        for scope in scopes:
            self._retire_scope_if_quiescent(scope)
        self._unsubscribe_if_quiescent()

    def _set_fatal(self, error):
        with self._condition:
            if self._fatal_error is None:
                self._fatal_error = error
            self._errors.append(error)
            operations = list(self._operations.values())
            start_cells = list(self._start_cells)
            self._condition.notify_all()
        for start_cell in start_cells:
            start_cell.set_exception(error)
        for operation in operations:
            operation.cell.set_exception(error)

    def _unsubscribe_if_quiescent(self):
        with self._condition:
            if not self._subscriptions_active or not self._closed:
                return False
            if self._starting_operations or self._operations or self._active_cleanup:
                return False
            self._subscriptions_active = False
            terminal_unsubscribe = self._terminal_unsubscribe
            self._terminal_unsubscribe = None
        for event, handler in self._subscriptions:
            self.transport.off(event, handler)
        if terminal_unsubscribe is not None:
            terminal_unsubscribe()
        return True

    def _cancel_unobserved(self, operation):
        """Queue cancellation for an operation whose caller no longer waits."""
        with self._condition:
            if self._operations.get(operation.operation_id) is not operation:
                return False
            if operation.cancel_started:
                return False
            operation.cancel_started = True
            operation.cancel_requested = True
            operation.cancel_inflight = True
        try:
            future = self.transport.send(
                "pwncOperationCancel",
                {"operationId": operation.operation_id},
            )
        except BaseException as error:  # noqa: BLE001 - close is best effort
            with self._condition:
                operation.cancel_inflight = False
                self._condition.notify_all()
            self._record_error(error)
            return False

        with self._condition:
            self._reply_futures.add(future)

        def collect(done):
            with self._condition:
                self._reply_futures.discard(done)
                operation.cancel_inflight = False
                self._condition.notify_all()
            try:
                self.transport.result(done, timeout=0)
            except (DapError, CancelledError) as error:
                # Completion may win the race with this queued cancellation.
                # Closing is already terminal to host callers, so retain the
                # diagnostic without poisoning callback cleanup delivery.
                self._record_error(error)

        future.add_done_callback(collect)
        return True

    def close(self, timeout=CONTROL_TIMEOUT):
        """Cooperatively cancel operations and boundedly join callback workers."""
        if timeout is None or timeout < 0:
            raise ValueError("timeout must be a nonnegative number")
        deadline = time.monotonic() + timeout
        with self._condition:
            if self._close_started:
                return self._close_survivors_locked(threading.current_thread())
            self._close_started = True
            self._closed = True
            operations = list(self._operations.values())
            start_cells = list(self._start_cells)
            scopes = list(self._capability_scopes.values())
            for scope in scopes:
                scope.root_terminal = True
            self._condition.notify_all()
        for scope in scopes:
            self._retire_scope_if_quiescent(scope)
        closed_error = DapError("operation dispatcher closed")
        start_error = DapError("operation dispatcher closed while operation was starting")
        for start_cell in start_cells:
            start_cell.set_exception(start_error)
        for operation in operations:
            operation.cell.set_exception(closed_error)
            self._cancel_unobserved(operation)

        # Keep the subscriptions alive while cancellation unwinds lowered
        # ``finally`` blocks.  Those blocks may yield explicitly designated
        # cleanup callbacks, which use the reserved callback capacity.
        with self._condition:
            while self._starting_operations or self._operations or self._active_cleanup:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)

        self._unsubscribe_if_quiescent()

        current = threading.current_thread()
        with self._condition:
            while any(worker is not current for worker in self._workers.values()):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            return self._close_survivors_locked(current)

    def _close_survivors_locked(self, current):
        survivors = [worker.name for worker in self._workers.values() if worker is not current]
        survivors.extend(f"pwnc-gdb-operation-{operation_id}" for operation_id in sorted(self._operations))
        if self._starting_operations:
            survivors.append(f"pwnc-gdb-operation-start({self._starting_operations})")
        return survivors
