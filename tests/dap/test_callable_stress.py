"""Adversarial host-side tests for scoped callable operations.

These tests deliberately model only the DAP operation wire.  They exercise
the host dispatcher's state machine without depending on a live GDB, so races
can be held at exact protocol boundaries.
"""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import os
import sys
import threading
import time
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap._capabilities import WIRE_TAG, CapabilityCodec, new_token
from pwnc.gdb.dap.callbacks import (
    CallbackAdmissionError,
    OperationDispatcher,
    OperationFailed,
)
from pwnc.gdb.dap.transport import DapError, DapTimeout


TIMEOUT = 3.0


def _wait_until(predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


def _run_in_thread(function, *, name):
    outcome = {}
    finished = threading.Event()

    def run():
        try:
            outcome["value"] = function()
        except BaseException as error:  # noqa: BLE001 - exercise sync boundary
            outcome["error"] = error
        finally:
            finished.set()

    thread = threading.Thread(target=run, name=name)
    thread.start()
    return thread, outcome, finished


class _WireTransport:
    """Thread-safe operation transport with controllable protocol hooks."""

    def __init__(self):
        self._lock = threading.RLock()
        self._handlers = {}
        self._terminal_listeners = []
        self._next_operation_id = 1
        self._next_seq = 1
        self._closed = False
        self._terminal_reason = None
        self.starts = []
        self.requests = []
        self.sent = []
        self.on_start = None
        self.on_reply = None
        self.on_cancel = None

    @property
    def closed(self):
        with self._lock:
            return self._closed

    @property
    def terminal_reason(self):
        with self._lock:
            return self._terminal_reason

    def add_terminal_listener(self, listener):
        with self._lock:
            if self._closed:
                reason = self._terminal_reason
            else:
                self._terminal_listeners.append(listener)
                reason = None

        def unsubscribe():
            with self._lock:
                self._terminal_listeners = [
                    candidate for candidate in self._terminal_listeners if candidate is not listener
                ]

        if reason is not None:
            listener(reason)
        return unsubscribe

    def on(self, event, handler, *, reentrant=False):
        assert reentrant is False
        with self._lock:
            self._handlers.setdefault(event, []).append(handler)
        return handler

    def off(self, event, handler):
        with self._lock:
            handlers = self._handlers.get(event, [])
            kept = [candidate for candidate in handlers if candidate is not handler]
            if kept:
                self._handlers[event] = kept
            else:
                self._handlers.pop(event, None)
            return len(handlers) - len(kept)

    def emit(self, event, body):
        with self._lock:
            handlers = list(self._handlers.get(event, ()))
        for handler in handlers:
            handler(dict(body))

    def _allocate(self, command, arguments):
        with self._lock:
            operation_id = self._next_operation_id
            self._next_operation_id += 1
            self.starts.append((operation_id, dict(arguments), threading.get_ident()))
        return operation_id

    def request(self, command, arguments=None, timeout=None):
        arguments = dict(arguments or {})
        with self._lock:
            self.requests.append((command, arguments, timeout, threading.get_ident()))
        if command == "pwncOperationReply":
            if self.on_reply is not None:
                self.on_reply(self, arguments, "request")
            return {"status": "accepted"}
        if command == "pwncOperationCancel":
            if self.on_cancel is not None:
                result = self.on_cancel(self, arguments, "request")
                if result is not None:
                    return result
            return {"status": "accepted"}
        raise AssertionError(f"unexpected request {command!r}")

    def send(self, command, arguments=None):
        arguments = dict(arguments or {})
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            if command != "pwncOperationStart":
                self.sent.append((command, arguments, threading.get_ident()))
        future = Future()

        def finish(body=None):
            future.set_result(
                {
                    "seq": 100_000 + seq,
                    "type": "response",
                    "request_seq": seq,
                    "success": True,
                    "command": command,
                    "body": {} if body is None else body,
                }
            )

        if command == "pwncOperationStart":
            operation_id = self._allocate(command, arguments)

            def complete_start():
                try:
                    result = None
                    if self.on_start is not None:
                        result = self.on_start(self, operation_id, arguments)
                    finish({"operationId": operation_id} if result is None else result)
                except BaseException as error:  # noqa: BLE001 - test boundary
                    future.set_exception(error)

            threading.Thread(
                target=complete_start,
                name=f"callable-stress-start-{operation_id}",
                daemon=True,
            ).start()
            return future

        try:
            if command == "pwncOperationReply" and self.on_reply is not None:
                self.on_reply(self, arguments, "send")
            elif command == "pwncOperationCancel" and self.on_cancel is not None:
                self.on_cancel(self, arguments, "send")
            finish({"status": "queued"})
        except BaseException as error:  # noqa: BLE001 - test boundary
            future.set_exception(error)
        return future

    @staticmethod
    def result(future, timeout=None):
        try:
            response = future.result(timeout)
        except FutureTimeout as error:
            raise DapTimeout("fake request timed out") from error
        if not response.get("success", False):
            raise DapError(response.get("message") or "fake request failed")
        return response.get("body")


class _HostProxy:
    """Callable marker created when the fake GDB decodes a host capability."""

    def __init__(self, reference):
        self.reference = reference

    def __call__(self, *_args, **_kwargs):
        raise AssertionError("fake GDB must emit an invoke event")


class _PeerRoot:
    """The fake GDB half of one root capability namespace."""

    def __init__(self, start):
        self.start = dict(start)
        self.root = start["rootToken"]
        self.owner = new_token()
        self.codec = CapabilityCodec(
            self.owner,
            self.root,
            peer_owner=start["hostOwner"],
            proxy_factory=_HostProxy,
        )
        self.callback_id = 0
        self.operations = {}

    def _remember(self, operation_id, name, start=None):
        if start is None:
            entry = self.operations.get(operation_id)
            if entry is not None:
                return entry
            start = self.start
        entry = (name, dict(start))
        self.operations[operation_id] = entry
        return entry

    def started(self, operation_id, name, start=None):
        name, start = self._remember(operation_id, name, start)
        return {
            "operationId": operation_id,
            "operationName": name,
            "parentOperationId": start["parentOperationId"],
            "parentCallbackId": start["parentCallbackId"],
            "rootToken": self.root,
            "depth": start["depth"],
            "status": "start-queued",
            "gdbOwner": self.owner,
        }

    def callback(self, transport, operation_id, start, target, *args, cancelling=False, **kwargs):
        name = start.get("name", "<gdb-callable>")
        self._remember(operation_id, name, start)
        self.callback_id += 1
        transport.emit(
            "pwncOperationCallback",
            {
                "operationId": operation_id,
                "operationName": name,
                "callbackId": self.callback_id,
                "target": self.codec.encode(target),
                "args": self.codec.encode(list(args)),
                "kwargs": self.codec.encode(kwargs),
                "depth": start["depth"],
                "parentOperationId": start["parentOperationId"],
                "parentCallbackId": start["parentCallbackId"],
                "rootToken": self.root,
                "gdbOwner": self.owner,
                "status": "waiting-host",
                "cancelling": cancelling,
            },
        )

    def _outcome(self, transport, event, status, operation_id, name, detail, start=None):
        name, start = self._remember(operation_id, name, start)
        body = {
            "operationId": operation_id,
            "operationName": name,
            "parentOperationId": start["parentOperationId"],
            "parentCallbackId": start["parentCallbackId"],
            "rootToken": self.root,
            "gdbOwner": self.owner,
            "depth": start["depth"],
            "status": status,
        }
        body["result" if status == "done" else "error"] = detail
        transport.emit(event, body)

    def done(self, transport, operation_id, name, result, start=None):
        self._outcome(
            transport,
            "pwncOperationDone",
            "done",
            operation_id,
            name,
            self.codec.encode(result),
            start,
        )

    def failed(self, transport, operation_id, name, message, start=None):
        self._outcome(
            transport,
            "pwncOperationFailed",
            "failed",
            operation_id,
            name,
            {
                "type": "RuntimeError",
                "module": "fake_gdb",
                "message": message,
            },
            start,
        )

    def cancelled(self, transport, operation_id, name, message="cancelled", start=None):
        self._outcome(
            transport,
            "pwncOperationCancelled",
            "cancelled",
            operation_id,
            name,
            {
                "type": "CancelledError",
                "module": "builtins",
                "message": message,
            },
            start,
        )


def test_early_callable_callback_before_start_response_is_delivered_once() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    callback_calls = []
    state = {}

    def start(fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state["peer"] = peer
        callback = peer.codec.decode(arguments["args"])[0]
        peer.callback(fake, operation_id, arguments, callback, b"early")
        return peer.started(operation_id, arguments["name"])

    def reply(fake, arguments, _via):
        peer = state["peer"]
        assert arguments["kind"] == "value"
        value = peer.codec.decode(arguments["value"])
        peer.done(fake, arguments["operationId"], "early-callable", value)

    transport.on_start = start
    transport.on_reply = reply
    try:
        result = dispatcher.call(
            "early-callable",
            lambda value: callback_calls.append(value) or (value, b"reply"),
        )
        assert result == (b"early", b"reply")
        assert callback_calls == [b"early"]
        assert dispatcher.active_operations == 0
        assert dispatcher.active_callbacks == 0
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_early_callable_outcome_before_start_response_retires_scope() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)

    def start(fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        peer.done(fake, operation_id, arguments["name"], (b"early", 7))
        return peer.started(operation_id, arguments["name"])

    transport.on_start = start
    try:
        assert dispatcher.call("early-outcome", lambda: None) == (b"early", 7)
        assert dispatcher.active_operations == 0
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_early_callback_then_terminal_outcome_keeps_scope_until_worker_exits() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    callback_entered = threading.Event()
    release_callback = threading.Event()
    callback_finished = threading.Event()
    state = {}

    def start(fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state["peer"] = peer
        callback = peer.codec.decode(arguments["args"])[0]

        def remote():
            raise AssertionError("terminal root must reject recursive invocation")

        peer.callback(fake, operation_id, arguments, callback, remote)
        peer.done(fake, operation_id, arguments["name"], "already-terminal")
        return peer.started(operation_id, arguments["name"])

    def callback(remote):
        callback_entered.set()
        assert release_callback.wait(TIMEOUT)
        try:
            remote()
        except BaseException as error:  # noqa: BLE001 - capture worker result
            state["remote_error"] = error
        callback_finished.set()
        return "ignored-late-reply"

    transport.on_start = start
    try:
        assert dispatcher.call("early-callback-and-outcome", callback) == "already-terminal"
        assert callback_entered.wait(TIMEOUT)
        with dispatcher._condition:
            scope = next(iter(dispatcher._capability_scopes.values()))
            assert scope.root_terminal is True
            assert scope.workers == 1
            assert scope.codec.closed is False

        release_callback.set()
        assert callback_finished.wait(TIMEOUT)
        assert isinstance(state.get("remote_error"), CallbackAdmissionError)
        assert "no longer active" in str(state["remote_error"])
        assert _wait_until(lambda: dispatcher.active_callbacks == 0)
        assert dispatcher._capability_scopes == {}
        assert scope.codec.closed is True
    finally:
        release_callback.set()
        dispatcher.close()


_START_RESPONSE_FIELDS = (
    "operationName",
    "parentOperationId",
    "parentCallbackId",
    "depth",
    "status",
)


def _damage_start_response(response, field, damage):
    if damage == "missing":
        response.pop(field)
        return
    replacements = {
        "operationName": "wrong-operation",
        "parentOperationId": 0xBAD,
        "parentCallbackId": 0xBAD,
        "depth": 0xBAD,
        "status": "running",
    }
    response[field] = replacements[field]


@pytest.mark.parametrize("field", _START_RESPONSE_FIELDS)
@pytest.mark.parametrize("damage", ("missing", "mismatched"))
def test_root_capability_start_response_requires_exact_correlation(field, damage) -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    state = {}

    def start(_fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state.update(peer=peer, operation_id=operation_id, name=arguments["name"])
        response = peer.started(operation_id, arguments["name"])
        _damage_start_response(response, field, damage)
        return response

    def cancel(fake, arguments, _via):
        # This path is reached only if a malformed response was accidentally
        # accepted and the short watchdog timeout has to unwind it.
        state["peer"].cancelled(
            fake,
            arguments["operationId"],
            state["name"],
            "watchdog",
        )
        return {"status": "accepted"}

    transport.on_start = start
    transport.on_cancel = cancel
    try:
        with pytest.raises(DapError, match="malformed pwncOperationStart response"):
            dispatcher._call(
                "strict-root-start",
                (),
                {},
                timeout=0.05,
                cancel_timeout=0.1,
            )
        assert dispatcher.active_operations == 0
        assert dispatcher._starting_operations == 0
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


@pytest.mark.parametrize("field", _START_RESPONSE_FIELDS)
@pytest.mark.parametrize("damage", ("missing", "mismatched"))
def test_child_capability_start_response_requires_exact_correlation(field, damage) -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    state = {"operations": {}}

    def start(fake, operation_id, arguments):
        if "name" in arguments:
            peer = _PeerRoot(arguments)
            state["peer"] = peer
            callback = peer.codec.decode(arguments["args"])[0]

            def gdb_callback():
                raise AssertionError("fake GDB invokes this through child operation routing")

            state["gdb_callback"] = gdb_callback
            state["operations"][operation_id] = (peer, arguments["name"])
            peer.callback(fake, operation_id, arguments, callback, gdb_callback)
            return peer.started(operation_id, arguments["name"])

        peer = state["peer"]
        assert peer.codec.decode(arguments["target"]) is state["gdb_callback"]
        state["operations"][operation_id] = (peer, "<gdb-callable>")
        response = peer.started(operation_id, "<gdb-callable>", arguments)
        _damage_start_response(response, field, damage)

        def finish_if_malformed_response_was_accepted():
            assert _wait_until(lambda: dispatcher._starting_operations == 0)
            with dispatcher._condition:
                accepted = operation_id in dispatcher._operations
            if accepted:
                peer.done(fake, operation_id, "<gdb-callable>", "unexpectedly-accepted")

        threading.Thread(
            target=finish_if_malformed_response_was_accepted,
            name=f"strict-child-watchdog-{operation_id}",
            daemon=True,
        ).start()
        return response

    def reply(fake, arguments, _via):
        peer, name = state["operations"][arguments["operationId"]]
        result = (
            peer.codec.decode(arguments["value"]) if arguments["kind"] == "value" else {"hostError": arguments["error"]}
        )
        peer.done(fake, arguments["operationId"], name, result)

    def invoke_child(remote):
        try:
            remote()
        except BaseException as error:  # noqa: BLE001 - capture worker-side API failure
            state["child_error"] = error
        return "parent-finished"

    transport.on_start = start
    transport.on_reply = reply
    try:
        assert dispatcher.call("strict-child-start", invoke_child) == "parent-finished"
        assert isinstance(state.get("child_error"), DapError)
        assert "malformed pwncOperationStart response" in str(state["child_error"])
        assert dispatcher.active_operations == 0
        assert dispatcher.active_callbacks == 0
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda descriptor: descriptor[WIRE_TAG].__setitem__("id", "forged-id"),
        lambda descriptor: descriptor[WIRE_TAG].__setitem__("root", "another-root"),
        lambda descriptor: descriptor[WIRE_TAG].__setitem__("owner", "third-party"),
    ],
    ids=("unknown-id", "cross-root", "foreign-owner"),
)
def test_forged_host_callback_target_is_rejected_without_running_user_code(mutate) -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    user_code_ran = threading.Event()
    state = {}

    def start(fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state["peer"] = peer
        callback = peer.codec.decode(arguments["args"])[0]
        descriptor = peer.codec.encode(callback)
        mutate(descriptor)
        peer.callback_id += 1
        fake.emit(
            "pwncOperationCallback",
            {
                "operationId": operation_id,
                "operationName": arguments["name"],
                "callbackId": peer.callback_id,
                "target": descriptor,
                "args": [],
                "kwargs": {},
                "depth": 0,
                "parentOperationId": None,
                "parentCallbackId": None,
                "rootToken": peer.root,
                "gdbOwner": peer.owner,
                "status": "waiting-host",
                "cancelling": False,
            },
        )
        return peer.started(operation_id, arguments["name"])

    def reply(fake, arguments, _via):
        assert arguments["kind"] == "error"
        assert arguments["error"]["type"] == "CallbackAdmissionError"
        state["peer"].done(
            fake,
            arguments["operationId"],
            "forged-target",
            {"hostError": arguments["error"]},
        )

    transport.on_start = start
    transport.on_reply = reply
    try:
        result = dispatcher.call("forged-target", lambda: user_code_ran.set())
        assert "invalid host callable target" in result["hostError"]["message"]
        assert not user_code_ran.is_set()
        assert dispatcher._fatal_error is None
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_released_host_callback_target_is_rejected_as_stale() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    state = {}

    def callback():
        raise AssertionError("released callback must not execute")

    def start(fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state["peer"] = peer
        host_proxy = peer.codec.decode(arguments["args"])[0]
        descriptor = peer.codec.encode(host_proxy)
        with dispatcher._condition:
            host_scope = dispatcher._capability_scopes[peer.root]
        assert host_scope.codec.release_local(callback) is True
        peer.callback_id += 1
        fake.emit(
            "pwncOperationCallback",
            {
                "operationId": operation_id,
                "operationName": arguments["name"],
                "callbackId": peer.callback_id,
                "target": descriptor,
                "args": [],
                "kwargs": {},
                "depth": 0,
                "parentOperationId": None,
                "parentCallbackId": None,
                "rootToken": peer.root,
                "gdbOwner": peer.owner,
                "status": "waiting-host",
                "cancelling": False,
            },
        )
        return peer.started(operation_id, arguments["name"])

    def reply(fake, arguments, _via):
        state["peer"].done(
            fake,
            arguments["operationId"],
            "stale-target",
            {"hostError": arguments["error"]},
        )

    transport.on_start = start
    transport.on_reply = reply
    try:
        result = dispatcher.call("stale-target", callback)
        assert "released" in result["hostError"]["message"]
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_gdb_callable_cannot_be_invoked_from_another_active_root() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport, max_active_callbacks=4)
    roots = {}
    operations = {}
    proxy_ready = threading.Event()
    release_first = threading.Event()
    saved_proxy = []

    def start(fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        roots[peer.root] = peer
        operations[operation_id] = (peer, arguments)
        callback = peer.codec.decode(arguments["args"])[0]

        def gdb_callback():
            raise AssertionError("cross-root callable must not start a child operation")

        peer.callback(fake, operation_id, arguments, callback, gdb_callback)
        return peer.started(operation_id, arguments["name"])

    def reply(fake, arguments, _via):
        peer, start_arguments = operations[arguments["operationId"]]
        assert arguments["kind"] == "value"
        peer.done(
            fake,
            arguments["operationId"],
            start_arguments["name"],
            peer.codec.decode(arguments["value"]),
        )

    def hold_first(remote):
        saved_proxy.append(remote)
        proxy_ready.set()
        assert release_first.wait(TIMEOUT)
        return "first-finished"

    def use_from_second(_its_own_remote):
        with pytest.raises(CallbackAdmissionError, match="different operation root"):
            saved_proxy[0]()
        return "roots-isolated"

    transport.on_start = start
    transport.on_reply = reply
    first_thread, first_outcome, first_finished = _run_in_thread(
        lambda: dispatcher.call("root-one", hold_first),
        name="callable-root-one",
    )
    try:
        assert proxy_ready.wait(TIMEOUT)
        assert dispatcher.call("root-two", use_from_second) == "roots-isolated"
        assert len(transport.starts) == 2
        release_first.set()
        assert first_finished.wait(TIMEOUT)
        first_thread.join(TIMEOUT)
        assert first_outcome == {"value": "first-finished"}
        assert _wait_until(lambda: dispatcher._capability_scopes == {})
    finally:
        release_first.set()
        first_thread.join(TIMEOUT)
        dispatcher.close()


def test_callback_capacity_exhaustion_fails_recursive_child_without_deadlock() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport, max_active_callbacks=1)
    state = {"operations": {}}

    def start(fake, operation_id, arguments):
        if "name" in arguments:
            peer = _PeerRoot(arguments)
            state["peer"] = peer
            callback = peer.codec.decode(arguments["args"])[0]

            def gdb_callback():
                raise AssertionError("fake GDB invokes this through child operation routing")

            state["gdb_callback"] = gdb_callback
            state["operations"][operation_id] = (peer, arguments, arguments["name"])
            peer.callback(fake, operation_id, arguments, callback, gdb_callback)
            return peer.started(operation_id, arguments["name"])

        peer = state["peer"]
        assert peer.codec.decode(arguments["target"]) is state["gdb_callback"]
        state["operations"][operation_id] = (peer, arguments, "<gdb-callable>")
        callback = peer.codec.decode(arguments["args"])[0]
        peer.callback(fake, operation_id, arguments, callback)
        return peer.started(operation_id, "<gdb-callable>", arguments)

    def reply(fake, arguments, _via):
        peer, _start_arguments, name = state["operations"][arguments["operationId"]]
        result = (
            peer.codec.decode(arguments["value"]) if arguments["kind"] == "value" else {"hostError": arguments["error"]}
        )
        peer.done(fake, arguments["operationId"], name, result)

    def recurse(remote):
        return remote(lambda: "must-not-run")

    transport.on_start = start
    transport.on_reply = reply
    try:
        result = dispatcher.call("exhaust-recursion", recurse)
        assert "active callback limit 1 reached" in result["hostError"]["message"]
        assert dispatcher.peak_active_callbacks == 1
        assert dispatcher.active_callbacks == 0
        assert dispatcher.active_operations == 0
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_early_recursive_child_failure_unwinds_parent_and_retires_scope() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    state = {"operations": {}}

    def start(fake, operation_id, arguments):
        if "name" in arguments:
            peer = _PeerRoot(arguments)
            state["peer"] = peer
            callback = peer.codec.decode(arguments["args"])[0]

            def gdb_callback():
                raise AssertionError("fake GDB invokes this through child operation routing")

            state["gdb_callback"] = gdb_callback
            state["operations"][operation_id] = (peer, arguments["name"])
            peer.callback(fake, operation_id, arguments, callback, gdb_callback)
            return peer.started(operation_id, arguments["name"])

        peer = state["peer"]
        assert peer.codec.decode(arguments["target"]) is state["gdb_callback"]
        state["operations"][operation_id] = (peer, "<gdb-callable>")
        peer.failed(
            fake,
            operation_id,
            "<gdb-callable>",
            "child exploded",
            arguments,
        )
        return peer.started(operation_id, "<gdb-callable>", arguments)

    def reply(fake, arguments, _via):
        peer, name = state["operations"][arguments["operationId"]]
        assert name == "recursive-failure"
        assert arguments["kind"] == "error"
        assert arguments["error"]["type"] == "OperationFailed"
        peer.failed(fake, arguments["operationId"], name, arguments["error"]["message"])

    transport.on_start = start
    transport.on_reply = reply
    try:
        with pytest.raises(OperationFailed, match="child exploded"):
            dispatcher.call("recursive-failure", lambda remote: remote())
        assert dispatcher.active_callbacks == 0
        assert dispatcher.active_operations == 0
        assert dispatcher._fatal_error is None
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_callback_after_timed_out_call_is_not_admitted_as_ordinary_work() -> None:
    """A returned call must not leave an ordinary host capability executable."""

    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    state = {}
    user_code_ran = threading.Event()

    def start(_fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state.update(peer=peer, operation_id=operation_id, arguments=arguments)
        state["callback"] = peer.codec.decode(arguments["args"])[0]
        return peer.started(operation_id, arguments["name"])

    transport.on_start = start
    transport.on_cancel = lambda _fake, _arguments, _via: {"status": "accepted"}
    try:
        with pytest.raises(DapTimeout, match="timed out waiting"):
            dispatcher._call(
                "timeout-root",
                (lambda: user_code_ran.set(),),
                {},
                timeout=0.02,
                cancel_timeout=0.02,
            )

        peer = state["peer"]
        peer.callback(
            transport,
            state["operation_id"],
            state["arguments"],
            state["callback"],
            cancelling=False,
        )
        assert _wait_until(
            lambda: (
                bool(dispatcher.rejections)
                or user_code_ran.is_set()
                or any(command == "pwncOperationReply" for command, _arguments, _thread in transport.sent)
            )
        )
        assert dispatcher.rejections
        assert not user_code_ran.is_set()
        orphan_replies = [
            arguments for command, arguments, _thread in transport.sent if command == "pwncOperationReply"
        ]
        assert len(orphan_replies) == 1
        assert orphan_replies[0]["kind"] == "error"
        assert orphan_replies[0]["error"]["type"] == "CallbackAdmissionError"
        assert "stopped accepting ordinary callbacks" in orphan_replies[0]["error"]["message"]
    finally:
        if "peer" in state:
            state["peer"].failed(
                transport,
                state["operation_id"],
                "timeout-root",
                "late terminal cleanup",
            )
        dispatcher.close()


def test_root_timeout_abandons_and_cancels_active_descendant_scope() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport, max_active_callbacks=4)
    state = {"operations": {}, "cancelled": []}
    child_started = threading.Event()

    def start(fake, operation_id, arguments):
        if "name" in arguments:
            peer = _PeerRoot(arguments)
            state["peer"] = peer
            callback = peer.codec.decode(arguments["args"])[0]

            def gdb_callback():
                raise AssertionError("fake GDB invokes this through child operation routing")

            state["gdb_callback"] = gdb_callback
            state["operations"][operation_id] = (arguments["name"], arguments)
            peer.callback(fake, operation_id, arguments, callback, gdb_callback)
            return peer.started(operation_id, arguments["name"])

        peer = state["peer"]
        assert peer.codec.decode(arguments["target"]) is state["gdb_callback"]
        state["operations"][operation_id] = ("<gdb-callable>", arguments)
        child_started.set()
        return peer.started(operation_id, "<gdb-callable>", arguments)

    def cancel(fake, arguments, _via):
        operation_id = arguments["operationId"]
        with dispatcher._condition:
            operation = dispatcher._operations[operation_id]
            state["cancelled"].append((operation_id, operation.depth, operation.orphaned))
            state.setdefault("scope", operation.scope)
        name, start_arguments = state["operations"][operation_id]
        state["peer"].cancelled(
            fake,
            operation_id,
            name,
            "scope abandoned",
            start_arguments,
        )
        return {"status": "accepted"}

    transport.on_start = start
    transport.on_cancel = cancel
    try:
        with pytest.raises(DapTimeout, match="timed out waiting"):
            dispatcher._call(
                "timeout-with-descendant",
                (lambda remote: remote(),),
                {},
                timeout=0.15,
                cancel_timeout=0.5,
            )

        assert child_started.is_set()
        assert [(operation_id, depth) for operation_id, depth, _orphaned in state["cancelled"]] == [
            (2, 1),
            (1, 0),
        ]
        assert all(orphaned for _operation_id, _depth, orphaned in state["cancelled"])
        assert state["scope"].abandoned is True
        assert _wait_until(lambda: dispatcher.active_operations == 0)
        assert _wait_until(lambda: dispatcher.active_callbacks == 0)
        assert state["scope"].operations == 0
        assert state["scope"].workers == 0
        assert state["scope"].codec.closed is True
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_timeout_still_admits_explicit_cancelling_cleanup_callback() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport, cleanup_callback_reserve=1)
    state = {}
    cleanup_calls = []

    def start(_fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state.update(peer=peer, operation_id=operation_id, arguments=arguments)
        state["callback"] = peer.codec.decode(arguments["args"])[0]
        return peer.started(operation_id, arguments["name"])

    def cancel(fake, arguments, _via):
        peer = state["peer"]
        peer.callback(
            fake,
            arguments["operationId"],
            state["arguments"],
            state["callback"],
            "cleanup",
            cancelling=True,
        )
        return {"status": "accepted"}

    def reply(fake, arguments, _via):
        assert arguments["kind"] == "value"
        assert state["peer"].codec.decode(arguments["value"]) == "cleanup-finished"
        state["peer"].cancelled(
            fake,
            arguments["operationId"],
            "timeout-cleanup",
        )

    transport.on_start = start
    transport.on_cancel = cancel
    transport.on_reply = reply
    try:
        with pytest.raises(DapTimeout, match="timed out waiting"):
            dispatcher._call(
                "timeout-cleanup",
                (lambda marker: cleanup_calls.append(marker) or "cleanup-finished",),
                {},
                timeout=0.02,
                cancel_timeout=0.5,
            )
        assert cleanup_calls == ["cleanup"]
        assert dispatcher.active_operations == 0
        assert _wait_until(lambda: dispatcher.active_callbacks == 0)
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_operation_limit_rejection_retires_new_root_scope_without_disturbing_owner() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport, max_operations=1)
    first_started = threading.Event()
    state = {}

    def start(_fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state[operation_id] = (peer, arguments)
        first_started.set()
        return peer.started(operation_id, arguments["name"])

    transport.on_start = start
    owner, owner_outcome, owner_finished = _run_in_thread(
        lambda: dispatcher.call("operation-limit-owner", lambda: None),
        name="callable-operation-limit-owner",
    )
    try:
        assert first_started.wait(TIMEOUT)
        assert _wait_until(lambda: dispatcher.active_operations == 1)
        with pytest.raises(CallbackAdmissionError, match="active operation limit 1 reached"):
            dispatcher.call("operation-limit-rejected", lambda: None)
        with dispatcher._condition:
            assert len(dispatcher._capability_scopes) == 1
            owner_scope = next(iter(dispatcher._capability_scopes.values()))
            assert owner_scope.root_token == state[1][0].root

        peer, arguments = state[1]
        peer.done(transport, 1, arguments["name"], "owner-finished")
        assert owner_finished.wait(TIMEOUT)
        owner.join(TIMEOUT)
        assert owner_outcome == {"value": "owner-finished"}
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()
        owner.join(TIMEOUT)


def test_close_during_callable_start_retires_scope_after_late_cancel_outcome() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    start_entered = threading.Event()
    release_start = threading.Event()
    state = {}

    def start(_fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state.update(peer=peer, operation_id=operation_id, arguments=arguments)
        start_entered.set()
        assert release_start.wait(TIMEOUT)
        return peer.started(operation_id, arguments["name"])

    transport.on_start = start
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.call("close-during-callable-start", lambda: None),
        name="close-during-callable-start",
    )
    try:
        assert start_entered.wait(TIMEOUT)
        survivors = dispatcher.close(timeout=0.05)
        assert "pwnc-gdb-operation-start(1)" in survivors
        assert finished.wait(TIMEOUT)
        assert isinstance(outcome.get("error"), DapError)
        assert "closed while operation was starting" in str(outcome["error"])

        release_start.set()
        assert _wait_until(lambda: dispatcher._starting_operations == 0)
        assert _wait_until(lambda: dispatcher.active_operations == 1)
        assert any(command == "pwncOperationCancel" for command, _arguments, _thread in transport.sent)
        state["peer"].failed(
            transport,
            state["operation_id"],
            state["arguments"]["name"],
            "late cancellation outcome",
        )
        assert _wait_until(lambda: dispatcher.active_operations == 0)
        assert dispatcher._capability_scopes == {}
    finally:
        release_start.set()
        dispatcher.close()
        runner.join(TIMEOUT)


def test_close_from_active_callable_callback_is_bounded_and_scope_safe() -> None:
    transport = _WireTransport()
    dispatcher = OperationDispatcher(transport)
    state = {}
    callback_entered = threading.Event()

    def start(fake, operation_id, arguments):
        peer = _PeerRoot(arguments)
        state.update(peer=peer, operation_id=operation_id, arguments=arguments)
        callback = peer.codec.decode(arguments["args"])[0]

        def remote():
            raise AssertionError("closed root must reject child invocation")

        peer.callback(fake, operation_id, arguments, callback, remote)
        return peer.started(operation_id, arguments["name"])

    def cancel(fake, arguments, _via):
        state["peer"].failed(
            fake,
            arguments["operationId"],
            "close-inside-callback",
            "cancelled during close",
        )
        return {"status": "accepted"}

    def close_inside(remote):
        callback_entered.set()
        started = time.monotonic()
        survivors = dispatcher.close(timeout=0.1)
        assert time.monotonic() - started < 0.5
        assert not any(name.startswith("pwnc-gdb-callback-") for name in survivors)
        with pytest.raises(CallbackAdmissionError, match="completed operation root"):
            remote()
        return "closed"

    transport.on_start = start
    transport.on_cancel = cancel
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.call("close-inside-callback", close_inside),
        name="callable-close-caller",
    )
    try:
        assert callback_entered.wait(TIMEOUT)
        assert finished.wait(TIMEOUT)
        runner.join(TIMEOUT)
        assert isinstance(outcome.get("error"), DapError)
        assert _wait_until(lambda: dispatcher.active_callbacks == 0)
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()
        runner.join(TIMEOUT)
