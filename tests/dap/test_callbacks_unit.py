"""Deterministic host-side tests for synchronous callback operations."""

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

from pwnc.gdb.dap.callbacks import OperationDispatcher, OperationFailed
from pwnc.gdb.dap._capabilities import CapabilityCodec, new_token
from pwnc.gdb.dap.transport import DapError, DapTimeout


TIMEOUT = 3.0


class FakeTransport:
    """A synchronous, thread-safe operation-protocol test double."""

    def __init__(self):
        self._lock = threading.RLock()
        self._handlers = {}
        self._terminal_listeners = []
        self._closed = False
        self._terminal_reason = None
        self._next_operation_id = 1
        self._next_seq = 1
        self.requests = []
        self.sent = []
        self.on_calls = []
        self.off_calls = []
        self.starts = []
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

    def disconnect(self, reason="fake transport disconnected"):
        with self._lock:
            if self._closed:
                return
            self._terminal_reason = reason
            self._closed = True
            listeners = list(self._terminal_listeners)
        for listener in listeners:
            listener(reason)

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
        with self._lock:
            self._handlers.setdefault(event, []).append(handler)
            self.on_calls.append((event, handler, reentrant))
        return handler

    def off(self, event, handler):
        with self._lock:
            entries = self._handlers.get(event, [])
            kept = [entry for entry in entries if entry is not handler]
            removed = len(entries) - len(kept)
            if kept:
                self._handlers[event] = kept
            else:
                self._handlers.pop(event, None)
            self.off_calls.append((event, handler))
            return removed

    def emit(self, event, body):
        with self._lock:
            handlers = list(self._handlers.get(event, ()))
        for handler in handlers:
            handler(dict(body))

    def request(self, command, arguments=None, timeout=None):
        arguments = dict(arguments or {})
        with self._lock:
            self.requests.append((command, arguments, timeout, threading.get_ident()))
        if command == "pwncOperationStart":
            with self._lock:
                operation_id = self._next_operation_id
                self._next_operation_id += 1
                self.starts.append((operation_id, arguments, threading.get_ident()))
            if self.on_start is not None:
                result = self.on_start(self, operation_id, arguments)
                if result is not None:
                    return result
            return {"operationId": operation_id}
        if command == "pwncOperationReply":
            if self.on_reply is not None:
                self.on_reply(self, arguments, "request")
            return {"status": "reply-accepted"}
        if command == "pwncOperationCancel":
            if self.on_cancel is not None:
                return self.on_cancel(self, arguments)
            return {"status": "cancel-accepted"}
        raise AssertionError(f"unexpected fake request {command!r}")

    def send(self, command, arguments=None):
        arguments = dict(arguments or {})
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            if command != "pwncOperationStart":
                self.sent.append((command, arguments, threading.get_ident()))
        future = Future()

        if command == "pwncOperationStart":
            with self._lock:
                operation_id = self._next_operation_id
                self._next_operation_id += 1
                self.starts.append((operation_id, arguments, threading.get_ident()))

            def complete_start():
                try:
                    result = None
                    if self.on_start is not None:
                        result = self.on_start(self, operation_id, arguments)
                    if result is None:
                        result = {"operationId": operation_id}
                    future.set_result(
                        {
                            "seq": 100_000 + seq,
                            "type": "response",
                            "request_seq": seq,
                            "success": True,
                            "command": command,
                            "body": result,
                        }
                    )
                except BaseException as error:  # noqa: BLE001 - test double
                    future.set_exception(error)

            threading.Thread(
                target=complete_start,
                name=f"fake-start-{operation_id}",
                daemon=True,
            ).start()
            return future

        try:
            if command == "pwncOperationReply" and self.on_reply is not None:
                self.on_reply(self, arguments, "send")
            future.set_result(
                {
                    "seq": 100_000 + seq,
                    "type": "response",
                    "request_seq": seq,
                    "success": True,
                    "command": command,
                    "body": {"status": "queued"},
                }
            )
        except BaseException as error:  # noqa: BLE001 - Future test double
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


def _callback_body(
    operation_id,
    callback_id,
    method,
    depth,
    *,
    args=None,
    kwargs=None,
    parent_operation_id=None,
):
    return {
        "operationId": operation_id,
        "callbackId": callback_id,
        "method": method,
        "args": [] if args is None else args,
        "kwargs": {} if kwargs is None else kwargs,
        "depth": depth,
        "parentOperationId": parent_operation_id,
    }


def _done_body(operation_id, result):
    return {"operationId": operation_id, "result": result}


def _wait_until(predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


def _run_in_thread(function, *, name="operation-runner"):
    outcome = {}
    finished = threading.Event()

    def run():
        try:
            outcome["value"] = function()
        except BaseException as error:  # noqa: BLE001 - observe sync API
            outcome["error"] = error
        finally:
            finished.set()

    thread = threading.Thread(target=run, name=name)
    thread.start()
    return thread, outcome, finished


def _complete_operation_on_reply(fake, arguments, _via):
    if arguments["kind"] == "value":
        result = arguments["value"]
    else:
        result = {"hostError": arguments["error"]}
    fake.emit(
        "pwncOperationDone",
        _done_body(arguments["operationId"], result),
    )


class _FakeHostCallable:
    """Marker produced when the fake GDB decodes a host capability."""

    def __init__(self, reference):
        self.reference = reference

    def __call__(self, *_args, **_kwargs):
        raise AssertionError("fake GDB must route host callables through a callback event")


class _CapabilityPeer:
    """Small protocol peer used to exercise the host callable dispatcher."""

    def __init__(self, transport, *, recursive_depth=0):
        self.transport = transport
        self.recursive_depth = recursive_depth
        self.codec = None
        self.root = None
        self.owner = new_token()
        self.operation_names = {}
        self.operation_starts = {}
        self.callback_ids = 20_000
        self.gdb_callback_threads = []

    def _callback(self, operation_id, start, target, *args):
        self.callback_ids += 1
        self.transport.emit(
            "pwncOperationCallback",
            {
                "operationId": operation_id,
                "operationName": self.operation_names[operation_id],
                "callbackId": self.callback_ids,
                "target": self.codec.encode(target),
                "args": self.codec.encode(list(args)),
                "kwargs": self.codec.encode({}),
                "depth": start["depth"],
                "parentOperationId": start["parentOperationId"],
                "parentCallbackId": start["parentCallbackId"],
                "rootToken": self.root,
                "gdbOwner": self.owner,
                "status": "waiting-host",
                "cancelling": False,
            },
        )

    def start(self, fake, operation_id, start):
        self.operation_starts[operation_id] = start
        if self.codec is None:
            self.root = start["rootToken"]
            self.codec = CapabilityCodec(
                self.owner,
                self.root,
                peer_owner=start["hostOwner"],
                proxy_factory=_FakeHostCallable,
            )
        else:
            assert start["rootToken"] == self.root
            assert start["hostOwner"] == self.codec.peer_owner

        args = self.codec.decode(start["args"])
        kwargs = self.codec.decode(start["kwargs"])
        if "name" in start:
            name = start["name"]
            assert name == "pwnc.test.callables"
            host_callback = args[0]
            assert args[1:] == ["positional"]

            def gdb_callback(next_host_callback, depth, *, payload):
                raise AssertionError("the fake invokes this through operation-start routing")

            self.gdb_callback = gdb_callback
            self.operation_names[operation_id] = name
            self._callback(
                operation_id,
                start,
                host_callback,
                self.gdb_callback,
                kwargs["depth"],
                kwargs["payload"],
            )
        else:
            self.operation_names[operation_id] = "<gdb-callable>"
            target = self.codec.decode(start["target"])
            assert target is self.gdb_callback
            next_host_callback, depth = args
            payload = kwargs["payload"]
            self.gdb_callback_threads.append(threading.get_ident())
            if depth == 0:
                fake.emit(
                    "pwncOperationDone",
                    {
                        "operationId": operation_id,
                        "operationName": "<gdb-callable>",
                        "parentOperationId": start["parentOperationId"],
                        "parentCallbackId": start["parentCallbackId"],
                        "rootToken": self.root,
                        "gdbOwner": self.owner,
                        "depth": start["depth"],
                        "status": "done",
                        "result": self.codec.encode({"payload": payload, "depth": depth}),
                    },
                )
            else:
                self._callback(
                    operation_id,
                    start,
                    next_host_callback,
                    self.gdb_callback,
                    depth - 1,
                    payload,
                )

        return {
            "operationId": operation_id,
            "operationName": self.operation_names[operation_id],
            "rootToken": self.root,
            "gdbOwner": self.owner,
            "parentOperationId": start["parentOperationId"],
            "parentCallbackId": start["parentCallbackId"],
            "depth": start["depth"],
            "status": "start-queued",
        }

    def reply(self, fake, reply, _via):
        if reply["kind"] == "error":
            result = {"hostError": reply["error"]}
        else:
            result = self.codec.decode(reply["value"])
        start = self.operation_starts[reply["operationId"]]
        fake.emit(
            "pwncOperationDone",
            {
                "operationId": reply["operationId"],
                "operationName": self.operation_names[reply["operationId"]],
                "parentOperationId": start["parentOperationId"],
                "parentCallbackId": start["parentCallbackId"],
                "rootToken": self.root,
                "gdbOwner": self.owner,
                "depth": start["depth"],
                "status": "done",
                "result": self.codec.encode(result),
            },
        )


def test_call_marshals_args_kwargs_bytes_and_alternating_callable_recursion() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(
        transport,
        max_active_callbacks=32,
        max_callback_depth=32,
    )
    peer = _CapabilityPeer(transport, recursive_depth=8)
    host_threads = []
    remote_callbacks = []
    payload = (b"raw\x00bytes", {"__pwnc_capability_v1__": "literal user data"})

    def host_callback(gdb_callback, depth, callback_payload):
        host_threads.append(threading.get_ident())
        remote_callbacks.append(gdb_callback)
        assert callback_payload == payload
        return gdb_callback(
            host_callback,
            depth,
            payload=callback_payload,
        )

    transport.on_start = peer.start
    transport.on_reply = peer.reply
    try:
        result = dispatcher.call(
            "pwnc.test.callables",
            host_callback,
            "positional",
            depth=peer.recursive_depth,
            payload=payload,
        )
        assert result == {"payload": payload, "depth": 0}
        assert len(host_threads) == peer.recursive_depth + 1
        assert len(set(host_threads)) == len(host_threads)
        assert remote_callbacks
        assert all(candidate is remote_callbacks[0] for candidate in remote_callbacks)
        assert dispatcher.peak_active_callbacks >= peer.recursive_depth + 1
        assert dispatcher.active_operations == 0
        assert dispatcher._capability_scopes == {}

        with pytest.raises(DapError, match="active host callback"):
            remote_callbacks[0](host_callback, 0, payload=payload)
    finally:
        dispatcher.close()


def test_call_callback_exception_crosses_capability_boundary() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    peer = _CapabilityPeer(transport)

    def explode(*_args):
        raise ValueError("capability callback exploded")

    transport.on_start = peer.start
    transport.on_reply = peer.reply
    try:
        result = dispatcher.call(
            "pwnc.test.callables",
            explode,
            "positional",
            depth=0,
            payload=b"payload",
        )
        assert result["hostError"] == {
            "type": "ValueError",
            "module": "builtins",
            "message": "capability callback exploded",
        }
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_call_rejects_gdb_callable_escaping_terminal_root_result() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    def start(fake, operation_id, arguments):
        root = arguments["rootToken"]
        owner = new_token()
        codec = CapabilityCodec(
            owner,
            root,
            peer_owner=arguments["hostOwner"],
            proxy_factory=_FakeHostCallable,
        )

        def escaped():
            return None

        fake.emit(
            "pwncOperationDone",
            {
                "operationId": operation_id,
                "operationName": arguments["name"],
                "parentOperationId": arguments["parentOperationId"],
                "parentCallbackId": arguments["parentCallbackId"],
                "rootToken": root,
                "gdbOwner": owner,
                "depth": arguments["depth"],
                "status": "done",
                "result": codec.encode(escaped),
            },
        )
        return {
            "operationId": operation_id,
            "operationName": arguments["name"],
            "parentOperationId": arguments["parentOperationId"],
            "parentCallbackId": arguments["parentCallbackId"],
            "rootToken": root,
            "gdbOwner": owner,
            "depth": arguments["depth"],
            "status": "start-queued",
        }

    transport.on_start = start
    try:
        with pytest.raises(OperationFailed, match="cannot escape"):
            dispatcher.call("pwnc.test.escape")
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_failed_capability_start_releases_root_scope() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    def fail_start(_fake, _operation_id, _arguments):
        raise RuntimeError("injected start failure")

    transport.on_start = fail_start
    try:
        with pytest.raises(RuntimeError, match="injected start failure"):
            dispatcher.call("pwnc.test.start-failure", lambda: None)
        assert dispatcher._capability_scopes == {}
    finally:
        dispatcher.close()


def test_callback_and_outcome_before_start_response_are_not_lost() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    callback_called = threading.Event()

    def early_start(fake, operation_id, arguments):
        assert arguments == {
            "name": "early-race",
            "args": [],
            "kwargs": {"input": 7},
            "parentOperationId": None,
            "parentCallbackId": None,
            "depth": 0,
        }
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 101, "early", 0),
        )
        fake.emit(
            "pwncOperationDone",
            _done_body(operation_id, "early-outcome"),
        )

    def callback():
        callback_called.set()
        return "callback-result"

    transport.on_start = early_start
    try:
        assert (
            dispatcher.run(
                "early-race",
                {"input": 7},
                callbacks={"early": callback},
            )
            == "early-outcome"
        )
        assert callback_called.wait(TIMEOUT)
        assert _wait_until(lambda: dispatcher.active_callbacks == 0)
        assert dispatcher.active_operations == 0
        assert _wait_until(
            lambda: any(
                command == "pwncOperationReply" for command, _arguments, _timeout, _thread in transport.requests
            )
        )
    finally:
        dispatcher.close()


def test_recursive_sync_operations_use_distinct_blocked_stacks_and_lineage() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(
        transport,
        max_active_callbacks=16,
        max_callback_depth=16,
    )
    target_depth = 8
    callback_threads = {}
    active_at_leaf = []

    def callback_start(fake, operation_id, arguments):
        callback_id = 10_000 + operation_id
        fake.emit(
            "pwncOperationCallback",
            _callback_body(
                operation_id,
                callback_id,
                "step",
                arguments["depth"],
                kwargs={"wire_depth": arguments["depth"]},
                parent_operation_id=arguments["parentOperationId"],
            ),
        )

    def step(*, wire_depth):
        callback_threads[wire_depth] = threading.get_ident()
        if wire_depth == target_depth:
            active_at_leaf.append(dispatcher.active_callbacks)
            return {"leaf": wire_depth}
        return dispatcher.run(
            "recursive",
            {"requestedBy": wire_depth},
            callbacks={"step": step},
        )

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    try:
        result = dispatcher.run(
            "recursive",
            {"root": True},
            callbacks={"step": step},
        )
        assert result == {"leaf": target_depth}
        assert sorted(callback_threads) == list(range(target_depth + 1))
        assert len(set(callback_threads.values())) == target_depth + 1
        assert active_at_leaf == [target_depth + 1]
        assert dispatcher.peak_active_callbacks >= target_depth + 1

        starts = sorted(transport.starts)
        assert len(starts) == target_depth + 1
        for index, (operation_id, arguments, _thread_id) in enumerate(starts):
            assert operation_id == index + 1
            assert arguments["args"] == []
            assert arguments["depth"] == index
            if index == 0:
                assert arguments["kwargs"] == {"root": True}
                assert arguments["parentOperationId"] is None
                assert arguments["parentCallbackId"] is None
            else:
                assert arguments["kwargs"] == {"requestedBy": index - 1}
                assert arguments["parentOperationId"] == operation_id - 1
                assert arguments["parentCallbackId"] == 10_000 + operation_id - 1
    finally:
        dispatcher.close()


def test_callback_exception_crosses_as_error_reply_and_unblocks_run() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 201, "explode", arguments["depth"]),
        )

    def explode():
        raise ValueError("host callback exploded")

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    try:
        result = dispatcher.run(
            "exception-crossing",
            callbacks={"explode": explode},
        )
        error = result["hostError"]
        assert error == {
            "type": "ValueError",
            "module": "builtins",
            "message": "host callback exploded",
        }
        replies = [
            arguments for command, arguments, _timeout, _thread in transport.requests if command == "pwncOperationReply"
        ]
        assert len(replies) == 1
        assert replies[0]["kind"] == "error"
        assert dispatcher.active_operations == 0
    finally:
        dispatcher.close()


def test_missing_handler_sends_explicit_error_reply_and_unblocks() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 301, "missing", arguments["depth"]),
        )

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    try:
        result = dispatcher.run("missing-handler")
        assert "no host handler" in result["hostError"]["message"]
        assert len(transport.sent) == 1
        command, reply, _thread_id = transport.sent[0]
        assert command == "pwncOperationReply"
        assert reply["kind"] == "error"
        assert reply["error"]["type"] == "CallbackAdmissionError"
        assert reply["operationId"] == 1
        assert reply["callbackId"] == 301
    finally:
        dispatcher.close()


def test_active_callback_limit_sends_explicit_error_reply() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport, max_active_callbacks=1)
    first_entered = threading.Event()
    release_first = threading.Event()

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(
                operation_id,
                400 + operation_id,
                "hold",
                arguments["depth"],
            ),
        )

    def hold():
        first_entered.set()
        assert release_first.wait(TIMEOUT)
        return "released"

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    runner, first_outcome, first_finished = _run_in_thread(
        lambda: dispatcher.run("occupy-slot", callbacks={"hold": hold}),
        name="active-limit-owner",
    )
    try:
        assert first_entered.wait(TIMEOUT)
        rejected = dispatcher.run(
            "rejected-at-active-limit",
            callbacks={"hold": hold},
        )
        assert "active callback limit 1 reached" in rejected["hostError"]["message"]
        rejection_replies = [
            arguments for command, arguments, _thread in transport.sent if command == "pwncOperationReply"
        ]
        assert len(rejection_replies) == 1
        assert "active callback limit 1 reached" in rejection_replies[0]["error"]["message"]

        release_first.set()
        assert first_finished.wait(TIMEOUT)
        runner.join(TIMEOUT)
        assert first_outcome == {"value": "released"}
    finally:
        release_first.set()
        runner.join(TIMEOUT)
        dispatcher.close()


def test_callback_depth_limit_sends_explicit_error_reply() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport, max_callback_depth=0)

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(
                operation_id,
                500 + operation_id,
                "step",
                arguments["depth"],
                kwargs={"wire_depth": arguments["depth"]},
                parent_operation_id=arguments["parentOperationId"],
            ),
        )

    def step(*, wire_depth):
        if wire_depth == 0:
            return dispatcher.run(
                "depth-one",
                callbacks={"step": step},
            )
        raise AssertionError("depth-one handler must be rejected before execution")

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    try:
        result = dispatcher.run("depth-zero", callbacks={"step": step})
        assert "callback depth 1 exceeds configured maximum 0" in result["hostError"]["message"]
        assert len(transport.sent) == 1
        _command, reply, _thread = transport.sent[0]
        assert reply["operationId"] == 2
        assert reply["callbackId"] == 502
        assert reply["kind"] == "error"
        assert "configured maximum 0" in reply["error"]["message"]
    finally:
        dispatcher.close()


class _StartFailingThread:
    ident = None

    def __init__(self, *, target, args, name, daemon):
        self.name = name

    @staticmethod
    def start():
        raise RuntimeError("injected thread start failure")

    @staticmethod
    def is_alive():
        return False


@pytest.mark.parametrize(
    ("thread_factory", "expected"),
    [
        (
            lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("injected thread construction failure")),
            "callback worker construction failed",
        ),
        (_StartFailingThread, "callback worker could not start"),
    ],
    ids=("construction", "start"),
)
def test_callback_thread_failure_sends_explicit_error_reply(
    thread_factory,
    expected,
) -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport, thread_factory=thread_factory)

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 601, "never-runs", arguments["depth"]),
        )

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    try:
        result = dispatcher.run(
            "thread-failure",
            callbacks={"never-runs": lambda: None},
        )
        assert expected in result["hostError"]["message"]
        assert dispatcher.active_callbacks == 0
        assert len(transport.sent) == 1
        _command, reply, _thread = transport.sent[0]
        assert reply["kind"] == "error"
        assert expected in reply["error"]["message"]
    finally:
        dispatcher.close()


def test_transport_disconnect_wakes_timeout_none_waiter() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.run("wait-forever", timeout=None),
        name="disconnect-waiter",
    )
    try:
        assert _wait_until(lambda: dispatcher.active_operations == 1)
        transport.disconnect("injected DAP disconnect")
        assert finished.wait(1.0)
        runner.join(TIMEOUT)
        assert isinstance(outcome.get("error"), DapError)
        assert "injected DAP disconnect" in str(outcome["error"])
    finally:
        dispatcher.close()
        runner.join(TIMEOUT)


def test_transport_disconnect_wakes_inflight_start_without_response() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    start_entered = threading.Event()
    release_start = threading.Event()

    def hold_start(_fake, _operation_id, _arguments):
        start_entered.set()
        assert release_start.wait(TIMEOUT)

    transport.on_start = hold_start
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.run("disconnect-during-start", timeout=None),
        name="disconnect-during-start",
    )
    try:
        assert start_entered.wait(TIMEOUT)
        transport.disconnect("start channel disconnected")
        assert finished.wait(1.0)
        runner.join(TIMEOUT)
        assert isinstance(outcome.get("error"), DapError)
        assert "start channel disconnected" in str(outcome["error"])
        assert dispatcher._starting_operations == 1

        release_start.set()
        assert _wait_until(lambda: dispatcher._starting_operations == 0)
        assert dispatcher.active_operations == 0
        with transport._lock:
            assert not transport._terminal_listeners
    finally:
        release_start.set()
        dispatcher.close()
        runner.join(TIMEOUT)


def test_dispatcher_created_after_transport_terminal_is_already_closed() -> None:
    transport = FakeTransport()
    transport.disconnect("transport was already terminal")

    dispatcher = OperationDispatcher(transport)
    with pytest.raises(DapError, match="already terminal"):
        dispatcher.run("cannot-start")
    assert dispatcher.close() == []
    with transport._lock:
        assert not transport._handlers
        assert not transport._terminal_listeners


def test_close_releases_waiter_and_boundedly_reports_blocked_worker() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    callback_entered = threading.Event()
    release_callback = threading.Event()

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 701, "block", arguments["depth"]),
        )

    def block():
        callback_entered.set()
        assert release_callback.wait(TIMEOUT)
        return "released-after-close"

    transport.on_start = callback_start
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.run(
            "close-with-blocked-callback",
            callbacks={"block": block},
            timeout=None,
        ),
        name="close-waiter",
    )
    try:
        assert callback_entered.wait(TIMEOUT)
        started = time.monotonic()
        survivors = dispatcher.close(timeout=0.05)
        elapsed = time.monotonic() - started

        assert elapsed < 0.5
        assert any(name.startswith("pwnc-gdb-callback-") for name in survivors)
        assert "pwnc-gdb-operation-1" in survivors
        assert finished.wait(1.0)
        assert isinstance(outcome.get("error"), DapError)
        assert "dispatcher closed" in str(outcome["error"])
    finally:
        release_callback.set()
        runner.join(TIMEOUT)
        assert _wait_until(lambda: dispatcher.active_callbacks == 0)


def test_close_removes_exact_dispatcher_subscriptions_only() -> None:
    transport = FakeTransport()

    def unrelated(_body):
        return None

    transport.on("pwncOperationDone", unrelated)
    dispatcher = OperationDispatcher(transport)
    subscriptions = list(dispatcher._subscriptions)
    assert len(subscriptions) == 4
    assert all(reentrant is False for _event, _handler, reentrant in transport.on_calls)

    assert dispatcher.close() == []
    assert len(transport.off_calls) == len(subscriptions)
    for removed, expected in zip(transport.off_calls, subscriptions, strict=True):
        assert removed[0] == expected[0]
        assert removed[1] is expected[1]
    with transport._lock:
        assert transport._handlers == {"pwncOperationDone": [unrelated]}
        assert not transport._terminal_listeners


@pytest.mark.parametrize(
    ("value", "error_type"),
    [
        ({"not-json"}, "TypeError"),
        (float("nan"), "TypeError"),
        ("x" * (4 * 1024 * 1024), "ValueError"),
    ],
    ids=("set", "nan", "oversized"),
)
def test_callback_return_must_be_bounded_strict_json(value, error_type) -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 801, "value", arguments["depth"]),
        )

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    try:
        result = dispatcher.run("json-result", callbacks={"value": lambda: value})
        assert result["hostError"]["type"] == error_type
        assert dispatcher.active_operations == 0
    finally:
        dispatcher.close()


def test_callback_exception_with_broken_text_and_repr_is_still_replied() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    class UnprintableError(RuntimeError):
        def __str__(self):
            raise self

        def __repr__(self):
            raise self

    def callback_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 850, "explode", arguments["depth"]),
        )

    def explode():
        raise UnprintableError()

    transport.on_start = callback_start
    transport.on_reply = _complete_operation_on_reply
    try:
        result = dispatcher.run("unprintable-host-error", callbacks={"explode": explode})
        assert result["hostError"]["type"] == "UnprintableError"
        assert "stringification failed" in result["hostError"]["message"]
        assert dispatcher.active_operations == 0
    finally:
        dispatcher.close()


def test_malformed_failed_outcome_wakes_waiter_with_protocol_error() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.run("malformed-failure", timeout=None),
        name="malformed-failure-waiter",
    )
    try:
        assert _wait_until(lambda: dispatcher.active_operations == 1)
        transport.emit(
            "pwncOperationFailed",
            {"operationId": 1, "error": "not-an-error-object"},
        )
        assert finished.wait(1.0)
        runner.join(TIMEOUT)
        assert isinstance(outcome.get("error"), DapError)
        assert "failed outcome error is not an object" in str(outcome["error"])
    finally:
        dispatcher.close()
        runner.join(TIMEOUT)


def test_concurrent_cancel_does_not_report_false_success_after_wire_failure() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    first_cancel_entered = threading.Event()
    release_first_cancel = threading.Event()
    cancel_calls = 0
    cancel_lock = threading.Lock()

    def on_cancel(_fake, _arguments):
        nonlocal cancel_calls
        with cancel_lock:
            cancel_calls += 1
            call = cancel_calls
        if call == 1:
            first_cancel_entered.set()
            assert release_first_cancel.wait(TIMEOUT)
            raise DapError("injected cancel failure")
        return {"status": "cancel-accepted"}

    transport.on_cancel = on_cancel
    operation_runner, _operation_outcome, operation_finished = _run_in_thread(
        lambda: dispatcher.run("cancel-race", timeout=None),
        name="cancel-race-operation",
    )
    first_runner = second_runner = None
    try:
        assert _wait_until(lambda: dispatcher.active_operations == 1)
        first_runner, first_outcome, first_finished = _run_in_thread(
            lambda: dispatcher.cancel(1),
            name="cancel-race-first",
        )
        assert first_cancel_entered.wait(TIMEOUT)
        second_runner, second_outcome, second_finished = _run_in_thread(
            lambda: dispatcher.cancel(1),
            name="cancel-race-second",
        )
        time.sleep(0.05)
        assert not second_finished.is_set()
        assert cancel_calls == 1

        release_first_cancel.set()
        assert first_finished.wait(TIMEOUT)
        assert second_finished.wait(TIMEOUT)
        first_runner.join(TIMEOUT)
        second_runner.join(TIMEOUT)
        assert isinstance(first_outcome.get("error"), DapError)
        assert second_outcome == {"value": True}
        assert cancel_calls == 2
    finally:
        release_first_cancel.set()
        dispatcher.close()
        operation_runner.join(TIMEOUT)
        if first_runner is not None:
            first_runner.join(TIMEOUT)
        if second_runner is not None:
            second_runner.join(TIMEOUT)
        assert operation_finished.is_set()


def test_early_callback_capacity_covers_every_admitted_start() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(
        transport,
        history=2,
        max_operations=3,
    )
    all_starts_entered = threading.Event()
    release_starts = threading.Event()
    start_count = 0
    start_lock = threading.Lock()

    def on_start(fake, operation_id, arguments):
        nonlocal start_count
        fake.emit(
            "pwncOperationCallback",
            _callback_body(
                operation_id,
                900 + operation_id,
                "early",
                arguments["depth"],
                kwargs={"operation_id": operation_id},
            ),
        )
        with start_lock:
            start_count += 1
            if start_count == 3:
                all_starts_entered.set()
        assert release_starts.wait(TIMEOUT)

    transport.on_start = on_start
    transport.on_reply = _complete_operation_on_reply
    runners = []
    try:
        for index in range(3):
            runners.append(
                _run_in_thread(
                    lambda: dispatcher.run(
                        "early-capacity",
                        callbacks={"early": lambda operation_id: operation_id},
                    ),
                    name=f"early-capacity-{index}",
                )
            )
        assert all_starts_entered.wait(TIMEOUT)
        with dispatcher._condition:
            assert set(dispatcher._early_callbacks) == {1, 2, 3}
        release_starts.set()
        for runner, outcome, finished in runners:
            assert finished.wait(TIMEOUT)
            runner.join(TIMEOUT)
            assert outcome["value"] in {1, 2, 3}
        assert dispatcher.active_operations == 0
    finally:
        release_starts.set()
        dispatcher.close()
        for runner, _outcome, _finished in runners:
            runner.join(TIMEOUT)


def test_duplicate_early_terminal_outcome_is_protocol_fatal() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    def on_start(fake, operation_id, _arguments):
        fake.emit("pwncOperationDone", _done_body(operation_id, "first"))
        fake.emit("pwncOperationDone", _done_body(operation_id, "second"))

    transport.on_start = on_start
    try:
        with pytest.raises(DapError, match="duplicate outcome"):
            dispatcher.run("duplicate-early-outcome")
        assert any("duplicate outcome" in str(error) for error in dispatcher.errors)
    finally:
        dispatcher.close()


def test_cancel_intent_makes_terminal_late_reply_nonfatal() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    callback_entered = threading.Event()
    release_callback = threading.Event()
    cancel_entered = threading.Event()
    release_cancel = threading.Event()

    def on_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 1001, "hold", arguments["depth"]),
        )

    def hold():
        callback_entered.set()
        assert release_callback.wait(TIMEOUT)
        return "late-value"

    def on_cancel(_fake, arguments):
        cancel_entered.set()
        assert release_cancel.wait(TIMEOUT)
        return {"status": "cancel-accepted", "operationId": arguments["operationId"]}

    def reject_late_reply(_fake, _arguments, _via):
        raise DapError("reply for terminal operation")

    transport.on_start = on_start
    transport.on_cancel = on_cancel
    transport.on_reply = reject_late_reply
    operation_runner, operation_outcome, operation_finished = _run_in_thread(
        lambda: dispatcher.run("cancel-late-reply", callbacks={"hold": hold}),
        name="cancel-late-reply-operation",
    )
    cancel_runner = None
    try:
        assert callback_entered.wait(TIMEOUT)
        cancel_runner, cancel_outcome, cancel_finished = _run_in_thread(
            lambda: dispatcher.cancel(1),
            name="cancel-late-reply-canceller",
        )
        assert cancel_entered.wait(TIMEOUT)
        transport.emit(
            "pwncOperationCancelled",
            {"operationId": 1, "error": {"type": "CancelledError"}},
        )
        release_callback.set()
        assert operation_finished.wait(TIMEOUT)
        release_cancel.set()
        assert cancel_finished.wait(TIMEOUT)
        operation_runner.join(TIMEOUT)
        cancel_runner.join(TIMEOUT)
        assert operation_outcome["error"].__class__.__name__ == "OperationCancelled"
        assert cancel_outcome == {"value": True}
        assert not dispatcher.errors
    finally:
        release_callback.set()
        release_cancel.set()
        dispatcher.close()
        operation_runner.join(TIMEOUT)
        if cancel_runner is not None:
            cancel_runner.join(TIMEOUT)


def test_close_releases_caller_while_start_response_is_in_flight() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    start_entered = threading.Event()
    release_start = threading.Event()

    def on_start(_fake, _operation_id, _arguments):
        start_entered.set()
        assert release_start.wait(TIMEOUT)

    transport.on_start = on_start
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.run("close-during-start", timeout=None),
        name="close-during-start-runner",
    )
    try:
        assert start_entered.wait(TIMEOUT)
        survivors = dispatcher.close(timeout=0.2)
        assert finished.wait(1.0)
        runner.join(TIMEOUT)
        assert isinstance(outcome.get("error"), DapError)
        assert "closed while operation was starting" in str(outcome["error"])
        assert "pwnc-gdb-operation-start(1)" in survivors

        release_start.set()
        assert _wait_until(lambda: dispatcher._starting_operations == 0)
        assert _wait_until(
            lambda: any(command == "pwncOperationCancel" for command, _arguments, _thread in transport.sent)
        )
        assert dispatcher.active_operations == 1
        transport.emit(
            "pwncOperationCancelled",
            {"operationId": 1, "error": {"type": "CancelledError"}},
        )
        assert dispatcher.active_operations == 0
        with transport._lock:
            assert not any(event.startswith("pwncOperation") for event in transport._handlers)
    finally:
        release_start.set()
        runner.join(TIMEOUT)


def test_callback_admitted_before_close_cannot_start_user_code_after_close() -> None:
    transport = FakeTransport()
    start_called = threading.Event()
    allow_thread_start = threading.Event()
    user_handler_called = threading.Event()

    class GatedThread(threading.Thread):
        def start(self):
            start_called.set()
            assert allow_thread_start.wait(TIMEOUT)
            return super().start()

    dispatcher = OperationDispatcher(transport, thread_factory=GatedThread)

    def on_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 1101, "must-not-run", arguments["depth"]),
        )

    transport.on_start = on_start
    runner, outcome, finished = _run_in_thread(
        lambda: dispatcher.run(
            "close-before-worker-start",
            callbacks={"must-not-run": user_handler_called.set},
        ),
        name="close-before-worker-start-runner",
    )
    try:
        assert start_called.wait(TIMEOUT)
        survivors = dispatcher.close(timeout=0.1)
        assert any(name.startswith("pwnc-gdb-callback-") for name in survivors)
        allow_thread_start.set()
        assert finished.wait(TIMEOUT)
        runner.join(TIMEOUT)
        assert isinstance(outcome.get("error"), DapError)
        assert _wait_until(lambda: dispatcher.active_callbacks == 0)
        assert not user_handler_called.is_set()
    finally:
        allow_thread_start.set()
        runner.join(TIMEOUT)


def test_operation_timeout_also_bounds_start_request() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)
    start_entered = threading.Event()
    release_start = threading.Event()
    handler_called = threading.Event()

    def on_start(fake, operation_id, arguments):
        fake.emit(
            "pwncOperationCallback",
            _callback_body(operation_id, 1201, "body", arguments["depth"]),
        )
        start_entered.set()
        assert release_start.wait(TIMEOUT)

    transport.on_start = on_start
    started = time.monotonic()
    try:
        with pytest.raises(DapTimeout, match="timed out starting"):
            dispatcher.run(
                "bounded-start",
                callbacks={"body": handler_called.set},
                timeout=0.1,
            )
        assert time.monotonic() - started < 0.5
        assert start_entered.is_set()
        assert dispatcher._starting_operations == 1
        with dispatcher._condition:
            assert set(dispatcher._early_callbacks) == {1}

        release_start.set()
        assert _wait_until(lambda: dispatcher._starting_operations == 0)
        assert _wait_until(lambda: dispatcher.active_operations == 1)
        assert _wait_until(
            lambda: any(command == "pwncOperationCancel" for command, _arguments, _thread in transport.sent)
        )
        assert not handler_called.is_set()
        with dispatcher._condition:
            assert not dispatcher._early_callbacks
        transport.emit(
            "pwncOperationCancelled",
            {"operationId": 1, "error": {"type": "CancelledError"}},
        )
        assert dispatcher.active_operations == 0
    finally:
        release_start.set()
        dispatcher.close()


def test_close_deadline_is_shared_across_all_worker_joins() -> None:
    transport = FakeTransport()
    dispatcher = OperationDispatcher(transport)

    class SlowWorker:
        def __init__(self, number):
            self.name = f"slow-worker-{number}"

        @staticmethod
        def is_alive():
            return True

        @staticmethod
        def join(timeout):
            time.sleep(timeout)

    with dispatcher._condition:
        dispatcher._workers = {index: SlowWorker(index) for index in range(12)}
    started = time.monotonic()
    survivors = dispatcher.close(timeout=0.1)
    elapsed = time.monotonic() - started
    assert elapsed < 0.2
    assert len(survivors) == 12
