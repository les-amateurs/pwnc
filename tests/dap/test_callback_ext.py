"""Isolated state-machine tests for the in-GDB callback extension."""

# ruff: noqa: I001 -- the fake gdb modules are installed after pytest imports.

import importlib.util
import sys
import types
from collections import deque
from pathlib import Path

import pytest


CALLBACK_EXT = Path(__file__).resolve().parents[2] / "pwnc" / "gdb" / "dap" / "_callback_ext.py"


class CallbackHarness:
    def __init__(self, gdb_module, requests, events, posted, module):
        self.gdb = gdb_module
        self.requests = requests
        self.events = events
        self.posted = posted
        self.module = module

    def request(self, request_name, **arguments):
        return self.requests[request_name][0](**arguments)

    def drain(self, count=None):
        completed = 0
        while self.posted and (count is None or completed < count):
            self.posted.popleft()()
            completed += 1
        return completed

    def event(self, name, index=0):
        matches = [body for event, body in self.events if event == name]
        return matches[index]

    def register(self, name, source, factory_name=None):
        namespace = self.gdb.pwnc_exec_lowered(
            source,
            filename=f"<callback-extension-test-{name}>",
        )
        if factory_name is None:
            factory_name = name.replace("-", "_")
        self.gdb.pwnc_register_operation(name, namespace[factory_name])
        return namespace[factory_name]


@pytest.fixture
def harness(monkeypatch):
    requests = {}
    events = []
    posted = deque()

    gdb_module = types.ModuleType("gdb")
    dap_module = types.ModuleType("gdb.dap")
    server_module = types.ModuleType("gdb.dap.server")

    def request(name, **options):
        def decorate(function):
            requests[name] = (function, options)
            return function

        return decorate

    def send_event(name, body):
        events.append((name, body))

    gdb_module.post_event = posted.append
    gdb_module.dap = dap_module
    dap_module.server = server_module
    server_module.request = request
    server_module.send_event = send_event
    monkeypatch.setitem(sys.modules, "gdb", gdb_module)
    monkeypatch.setitem(sys.modules, "gdb.dap", dap_module)
    monkeypatch.setitem(sys.modules, "gdb.dap.server", server_module)

    module_name = f"_pwnc_callback_ext_test_{id(gdb_module):x}"
    spec = importlib.util.spec_from_file_location(module_name, CALLBACK_EXT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return CallbackHarness(gdb_module, requests, events, posted, module)


def test_runtime_hooks_requests_value_reply_and_exactly_once(harness):
    assert set(harness.requests) == {
        "pwncOperationStart",
        "pwncOperationReply",
        "pwncOperationCancel",
        "pwncOperationSnapshot",
    }
    for _function, options in harness.requests.values():
        assert options == {"on_dap_thread": True, "expect_stopped": False}
    for hook in (
        "pwnc_register_operation",
        "pwnc_unregister_operation",
        "pwnc_exec_lowered",
        "pwnc_effect",
        "pwnc_invoke",
        "pwnc_lowering",
    ):
        assert hasattr(harness.gdb, hook)

    factory = harness.register(
        "echo",
        """
async def echo(value, increment=0):
    answer = await effect("ask", value, marker={"nested": [True, None]})
    return {"answer": answer, "total": value + increment}
""",
    )
    with pytest.raises(ValueError, match="already registered"):
        harness.gdb.pwnc_register_operation("echo", factory)

    started = harness.request(
        "pwncOperationStart",
        name="echo",
        args=[7],
        kwargs={"increment": 4},
        rootToken="root-echo",
    )
    assert started["status"] == "start-queued"
    assert harness.events == []
    assert harness.drain(1) == 1

    callback = harness.event("pwncOperationCallback")
    assert callback["method"] == "ask"
    assert callback["args"] == [7]
    assert callback["kwargs"] == {"marker": {"nested": [True, None]}}
    assert callback["depth"] == 0
    assert callback["rootToken"] == "root-echo"
    assert callback["cancelling"] is False

    acknowledged = harness.request(
        "pwncOperationReply",
        operationId=callback["operationId"],
        callbackId=callback["callbackId"],
        kind="value",
        value={"accepted": True},
    )
    assert acknowledged["status"] == "resume-queued"
    with pytest.raises(RuntimeError, match="duplicate or invalid reply"):
        harness.request(
            "pwncOperationReply",
            operationId=callback["operationId"],
            callbackId=callback["callbackId"],
            kind="value",
            value="duplicate",
        )

    harness.drain()
    done = harness.event("pwncOperationDone")
    assert done["result"] == {
        "answer": {"accepted": True},
        "total": 11,
    }
    snapshot = harness.request("pwncOperationSnapshot")
    assert snapshot["activeCount"] == 0
    assert snapshot["tombstones"][str(done["operationId"])]["outcome"] == "done"


def test_structured_callback_error_is_injected_at_await(harness):
    harness.register(
        "recover",
        """
async def recover():
    try:
        await effect("explode")
    except RuntimeError as error:
        return {"caught": type(error).__name__, "message": str(error)}
""",
    )
    started = harness.request("pwncOperationStart", name="recover")
    harness.drain()
    callback = harness.event("pwncOperationCallback")

    harness.request(
        "pwncOperationReply",
        operationId=started["operationId"],
        callbackId=callback["callbackId"],
        kind="error",
        error={
            "type": "InjectedFailure",
            "module": "fixture",
            "message": "host failed",
            "metadata": {"json": True},
        },
    )
    harness.drain()
    assert harness.event("pwncOperationDone")["result"] == {
        "caught": "HostCallbackError",
        "message": "fixture.InjectedFailure: host failed",
    }


def _capability_call(harness, operation, *args, root=None, **kwargs):
    capabilities = harness.module._capabilities
    root = root or capabilities.new_token()
    owner = capabilities.new_token()
    codec = capabilities.CapabilityCodec(owner=owner, root=root)
    encoded = codec.encode({"args": list(args), "kwargs": kwargs})
    started = harness.request(
        "pwncOperationStart",
        name=operation,
        args=encoded["args"],
        kwargs=encoded["kwargs"],
        rootToken=root,
        hostOwner=owner,
    )
    codec.bind_peer(
        started["gdbOwner"],
        lambda reference: lambda *_args, **_kwargs: reference,
    )
    return codec, started


def test_invoke_uses_callable_target_and_capability_codec(harness):
    harness.register(
        "capability-echo",
        """
async def capability_echo(host_callback, value):
    answer = await invoke(host_callback, value, marker=(b"\\x00", b"two"))
    return (answer, b"done")
""",
    )
    host_callback = lambda *args, **kwargs: (args, kwargs)
    codec, started = _capability_call(
        harness,
        "capability-echo",
        host_callback,
        b"payload",
    )
    harness.drain()

    callback = harness.event("pwncOperationCallback")
    assert "method" not in callback
    assert codec.decode(callback["target"]) is host_callback
    assert codec.decode(callback["args"]) == [b"payload"]
    assert codec.decode(callback["kwargs"]) == {"marker": (b"\x00", b"two")}

    harness.request(
        "pwncOperationReply",
        operationId=started["operationId"],
        callbackId=callback["callbackId"],
        kind="value",
        value=codec.encode((b"host", 7)),
    )
    harness.drain()
    result = codec.decode(harness.event("pwncOperationDone")["result"])
    assert result == ((b"host", 7), b"done")
    assert harness.module._root_scopes == {}


def test_gdb_callable_targets_support_sync_lowered_and_recursive_invoke(harness):
    harness.register(
        "export-callables",
        """
async def export_callables(host_callback):
    def sync_callback(value, increment=0):
        return value + increment

    async def lowered_callback(value):
        return await invoke(host_callback, "nested", value=value)

    return await invoke(host_callback, sync_callback, lowered_callback)
""",
    )
    host_callback = lambda *_args: None
    codec, parent = _capability_call(harness, "export-callables", host_callback)
    harness.drain()
    exported = harness.event("pwncOperationCallback")
    sync_target, lowered_target = exported["args"]

    with pytest.raises(TypeError, match="GDB callable"):
        harness.request(
            "pwncOperationStart",
            target=exported["target"],
            parentOperationId=parent["operationId"],
            parentCallbackId=exported["callbackId"],
            depth=1,
            rootToken=parent["rootToken"],
            hostOwner=codec.owner,
        )

    sync_child = harness.request(
        "pwncOperationStart",
        target=sync_target,
        args=[7],
        kwargs={"increment": 4},
        parentOperationId=parent["operationId"],
        parentCallbackId=exported["callbackId"],
        depth=1,
        rootToken=parent["rootToken"],
        hostOwner=codec.owner,
    )
    harness.drain()
    sync_done = next(
        body
        for name, body in harness.events
        if name == "pwncOperationDone" and body["operationId"] == sync_child["operationId"]
    )
    assert sync_done["result"] == 11

    lowered_child = harness.request(
        "pwncOperationStart",
        target=lowered_target,
        args=[9],
        parentOperationId=parent["operationId"],
        parentCallbackId=exported["callbackId"],
        depth=1,
        rootToken=parent["rootToken"],
        hostOwner=codec.owner,
    )
    harness.drain()
    nested = next(
        body
        for name, body in harness.events
        if name == "pwncOperationCallback" and body["operationId"] == lowered_child["operationId"]
    )
    assert codec.decode(nested["target"]) is host_callback
    assert nested["args"] == ["nested"]
    assert nested["kwargs"] == {"value": 9}
    harness.request(
        "pwncOperationReply",
        operationId=lowered_child["operationId"],
        callbackId=nested["callbackId"],
        kind="value",
        value="nested-result",
    )
    harness.drain()
    lowered_done = next(
        body
        for name, body in harness.events
        if name == "pwncOperationDone" and body["operationId"] == lowered_child["operationId"]
    )
    assert lowered_done["result"] == "nested-result"

    harness.request(
        "pwncOperationReply",
        operationId=parent["operationId"],
        callbackId=exported["callbackId"],
        kind="value",
        value="accepted",
    )
    harness.drain()
    parent_done = next(
        body
        for name, body in harness.events
        if name == "pwncOperationDone" and body["operationId"] == parent["operationId"]
    )
    assert parent_done["result"] == "accepted"
    assert harness.module._root_scopes == {}


def test_cancelled_invoke_is_automatically_classified_for_cleanup(harness):
    harness.register(
        "capability-cleanup",
        """
async def capability_cleanup(host_callback):
    try:
        await invoke(host_callback, "hold")
    finally:
        await invoke(host_callback, "cleanup")
""",
    )
    codec, started = _capability_call(harness, "capability-cleanup", lambda *_args: None)
    harness.drain()
    original = harness.event("pwncOperationCallback")
    assert original["cancelling"] is False

    harness.request("pwncOperationCancel", operationId=started["operationId"])
    harness.drain()
    cleanup = harness.event("pwncOperationCallback", 1)
    assert cleanup["cancelling"] is True
    assert cleanup["args"] == ["cleanup"]
    harness.request(
        "pwncOperationReply",
        operationId=started["operationId"],
        callbackId=cleanup["callbackId"],
        kind="value",
        value=codec.encode(None),
    )
    harness.drain()
    assert harness.event("pwncOperationCancelled")["operationId"] == started["operationId"]
    assert harness.module._root_scopes == {}


def test_cooperative_cancel_drives_all_yielded_cleanup_effects(harness):
    harness.register(
        "cancellable",
        """
async def cancellable():
    try:
        await effect("hold", phase="body")
    finally:
        first = await effect("cleanup", 1)
        await effect("cleanup", 2, previous=first)
""",
    )
    started = harness.request("pwncOperationStart", name="cancellable")
    harness.drain()
    original = harness.event("pwncOperationCallback")

    accepted = harness.request(
        "pwncOperationCancel",
        operationId=started["operationId"],
    )
    assert accepted["status"] == "cancel-queued"
    duplicate = harness.request(
        "pwncOperationCancel",
        operationId=started["operationId"],
    )
    assert duplicate["status"] == "cancel-in-progress"
    harness.drain()

    cleanup_one = harness.event("pwncOperationCallback", 1)
    assert cleanup_one["method"] == "cleanup"
    assert cleanup_one["args"] == [1]
    assert cleanup_one["cancelling"] is True
    harness.request(
        "pwncOperationReply",
        operationId=started["operationId"],
        callbackId=cleanup_one["callbackId"],
        kind="value",
        value="first-cleaned",
    )
    harness.drain()

    cleanup_two = harness.event("pwncOperationCallback", 2)
    assert cleanup_two["args"] == [2]
    assert cleanup_two["kwargs"] == {"previous": "first-cleaned"}
    assert cleanup_two["cancelling"] is True
    harness.request(
        "pwncOperationReply",
        operationId=started["operationId"],
        callbackId=cleanup_two["callbackId"],
        kind="value",
        value="second-cleaned",
    )
    harness.drain()

    cancelled = harness.event("pwncOperationCancelled")
    assert cancelled["operationId"] == started["operationId"]
    assert cancelled["tombstone"]["acceptedReplies"] == 2
    with pytest.raises(RuntimeError, match="terminal operation"):
        harness.request(
            "pwncOperationReply",
            operationId=started["operationId"],
            callbackId=original["callbackId"],
            kind="value",
            value="late",
        )


def test_parent_lineage_active_limit_and_bounded_tombstones(harness, monkeypatch):
    harness.register(
        "parent",
        """
async def parent():
    return await effect("parent-callback")
""",
    )
    harness.register(
        "pure",
        """
async def pure(value=None):
    return value
""",
    )

    parent = harness.request("pwncOperationStart", name="parent", rootToken="lineage")
    harness.drain()
    callback = harness.event("pwncOperationCallback")
    with pytest.raises(RuntimeError, match="parent callback"):
        harness.request(
            "pwncOperationStart",
            name="pure",
            parentOperationId=parent["operationId"],
            parentCallbackId=callback["callbackId"] + 1,
        )
    with pytest.raises(ValueError, match="non-negative integer"):
        harness.request(
            "pwncOperationStart",
            name="pure",
            parentOperationId=parent["operationId"],
            parentCallbackId=callback["callbackId"],
            depth=True,
        )
    with pytest.raises(ValueError, match="rootToken"):
        harness.request(
            "pwncOperationStart",
            name="pure",
            parentOperationId=parent["operationId"],
            parentCallbackId=callback["callbackId"],
            rootToken="reset",
        )

    child = harness.request(
        "pwncOperationStart",
        name="pure",
        args=["child-result"],
        parentOperationId=parent["operationId"],
        parentCallbackId=callback["callbackId"],
        depth=1,
        rootToken="lineage",
    )
    harness.drain()
    child_done = next(
        body
        for name, body in harness.events
        if name == "pwncOperationDone" and body["operationId"] == child["operationId"]
    )
    assert child_done["result"] == "child-result"

    monkeypatch.setattr(harness.module, "_MAX_ACTIVE_OPERATIONS", 1)
    with pytest.raises(RuntimeError, match="active operation limit"):
        harness.request("pwncOperationStart", name="pure")

    harness.request(
        "pwncOperationReply",
        operationId=parent["operationId"],
        callbackId=callback["callbackId"],
        kind="value",
        value="parent-result",
    )
    harness.drain()

    monkeypatch.setattr(harness.module, "_TOMBSTONE_LIMIT", 3)
    for index in range(5):
        harness.request("pwncOperationStart", name="pure", args=[index])
        harness.drain()
    snapshot = harness.request("pwncOperationSnapshot")
    assert snapshot["activeCount"] == 0
    assert snapshot["tombstoneCount"] == 3


def test_non_json_effect_and_result_fail_without_stranding_active_state(harness):
    harness.register(
        "bad-effect",
        """
async def bad_effect():
    await effect("bad", object())
""",
    )
    harness.register(
        "bad-result",
        """
async def bad_result():
    return {object()}
""",
    )

    harness.request("pwncOperationStart", name="bad-effect")
    harness.drain()
    harness.request("pwncOperationStart", name="bad-result")
    harness.drain()

    failures = [body for name, body in harness.events if name == "pwncOperationFailed"]
    assert [failure["error"]["type"] for failure in failures] == [
        "TypeError",
        "TypeError",
    ]
    assert harness.request("pwncOperationSnapshot")["activeCount"] == 0


def test_exception_with_broken_stringification_still_finishes_operation(harness):
    harness.register(
        "broken-error-text",
        """
class RecursiveStringError(RuntimeError):
    def __str__(self):
        raise self

async def broken_error_text():
    raise RecursiveStringError()
""",
    )

    started = harness.request("pwncOperationStart", name="broken-error-text")
    harness.drain()
    failed = harness.event("pwncOperationFailed")
    assert failed["operationId"] == started["operationId"]
    assert failed["error"]["type"] == "RecursiveStringError"
    assert "while formatting error" in failed["error"]["message"]
    assert harness.request("pwncOperationSnapshot")["activeCount"] == 0
