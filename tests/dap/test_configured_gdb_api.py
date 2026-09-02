"""Focused tests for Gdb.use() defaults and the public call() surface."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import base64
import os
import queue
import sys
import threading

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import Gdb, Registers, SymbolAccessor
from pwnc.types.provider import ByteOrder


_OMITTED = object()


class _Transport:
    def __init__(self):
        self.calls = []
        self.closed = False
        self.terminal_reason = None
        self.symbol_variable = False

    def request(self, command, arguments=None, *, timeout=_OMITTED):
        self.calls.append((command, arguments, timeout))
        if command == "pwncResolveSymbol" and self.symbol_variable:
            return {
                "found": True,
                "kind": "variable",
                "address": 0x402000,
                "type": {
                    "root": {"kind": "int", "bits": 32, "signed": False},
                    "types": {},
                },
            }
        if command == "readMemory" and self.symbol_variable:
            return {"data": base64.b64encode(b"\x07\x00\x00\x00").decode("ascii")}
        responses = {
            "continue": {},
            "evaluate": {"result": "ok"},
            "pwncEval": {"value": 7},
            "pwncSkip": {"pc": 0x401000},
            "readMemory": {"data": base64.b64encode(b"abc").decode("ascii")},
            "writeMemory": {"bytesWritten": 3},
            "pwncBreakpoint": {"number": 4},
            "pwncDeleteBreakpoint": {},
            "stackTrace": {"stackFrames": []},
            "threads": {"threads": [{"id": 11}]},
            "pwncReadRegister": {"value": 0x1234},
            "pwncWriteRegister": {},
            "pwncReadRegisters": {"registers": {"rip": 0x1234}},
            "pwncResolveSymbol": {
                "found": True,
                "kind": "function",
                "address": 0x401000,
            },
        }
        return responses[command]


class _Operations:
    def __init__(self):
        self.calls = []

    def _call(self, operation, args, kwargs, *, timeout):
        record = (operation, args, kwargs, timeout)
        self.calls.append(record)
        return record


def _controller():
    gdb = object.__new__(Gdb)
    gdb.transport = _Transport()
    gdb.operations = _Operations()
    gdb.target = object()
    gdb._closed = False
    gdb._cur_thread = 11
    gdb._stops = queue.Queue()
    gdb._wait_lock = threading.Lock()
    gdb._bp_callbacks = {}
    gdb._byteorder = ByteOrder.Little
    gdb._ptrbits = 64
    gdb._sym_type_cache = {}
    gdb.sym = SymbolAccessor(gdb)
    gdb.reg = Registers(gdb)
    return gdb


def test_use_returns_immutable_shared_session_views() -> None:
    gdb = _controller()
    slow = gdb.use(timeout=30)
    fast = slow.use(timeout=2)

    assert isinstance(slow, Gdb)
    assert slow is not gdb
    assert slow.transport is gdb.transport
    assert slow.operations is gdb.operations
    assert slow.target is gdb.target
    assert slow._use_settings["timeout"] == 30
    assert fast._use_settings["timeout"] == 2
    assert slow._use_settings["timeout"] == 30
    with pytest.raises(TypeError):
        slow._use_settings["timeout"] = 1
    with pytest.raises(AttributeError, match="immutable"):
        slow._use_settings = {}

    marker = object()
    slow.target = marker
    assert gdb.target is marker


@pytest.mark.parametrize(
    ("settings", "error"),
    [
        ({"deadline": 1}, TypeError),
        ({"timeout": "soon"}, TypeError),
        ({"timeout": True}, TypeError),
        ({"timeout": -0.1}, ValueError),
        ({"timeout": float("nan")}, ValueError),
        ({"timeout": float("inf")}, ValueError),
    ],
)
def test_use_rejects_unknown_or_invalid_settings(settings, error) -> None:
    with pytest.raises(error):
        _controller().use(**settings)


def test_configured_timeout_reaches_request_backed_helpers() -> None:
    gdb = _controller()
    configured = gdb.use(timeout=12)

    assert configured.execute("show version") == "ok"
    assert configured.eval("1 + 6") == 7
    assert configured.skip() == 0x401000
    assert configured.read(0x400000, 3) == b"abc"
    configured.write(0x400000, b"abc")
    bp = configured.bp("main")
    bp.delete()
    assert configured.frame() is None
    assert configured.threads() == [{"id": 11}]
    assert configured.reg.rip == 0x1234
    configured.reg.rip = 0x5678
    assert configured.reg() == {"rip": 0x1234}
    assert int(configured.sym.main) == 0x401000

    assert gdb.transport.calls
    assert all(timeout == 12 for _command, _arguments, timeout in gdb.transport.calls)


def test_configured_timeout_is_retained_by_typed_symbol_memory_provider() -> None:
    gdb = _controller()
    gdb.transport.symbol_variable = True

    value = gdb.use(timeout=12).sym.counter
    assert int(value) == 7

    assert [call[0] for call in gdb.transport.calls] == ["pwncResolveSymbol", "readMemory"]
    assert [call[2] for call in gdb.transport.calls] == [12, 12]


def test_explicit_method_timeout_overrides_view_without_mutating_it() -> None:
    gdb = _controller()
    configured = gdb.use(timeout=12)

    configured.execute("first", timeout=3)
    configured.execute("second", timeout=None)
    configured.execute("third")
    gdb.execute("root")

    assert [call[2] for call in gdb.transport.calls] == [3, None, 12, _OMITTED]
    assert configured._use_settings["timeout"] == 12


def test_run_remains_inferior_control_and_uses_configured_timeout() -> None:
    gdb = _controller()
    configured = gdb.use(timeout=9)
    gdb._stops.put({"reason": "breakpoint"})

    assert configured.run() == {"reason": "breakpoint"}
    assert gdb.transport.calls == [("continue", {"threadId": 11}, 9)]


def test_call_forwards_all_args_and_kwargs_separately_from_host_timeout() -> None:
    gdb = _controller()

    def callback(value):
        return value

    result = gdb.use(timeout=30).call(
        "example.operation",
        callback,
        7,
        timeout=123,
        cancel_timeout=456,
    )

    assert result == (
        "example.operation",
        (callback, 7),
        {"timeout": 123, "cancel_timeout": 456},
        30,
    )


def test_none_configures_no_deadline_for_call_and_requests() -> None:
    gdb = _controller()
    configured = gdb.use(timeout=1).use(timeout=None)

    configured.execute("show version")
    configured.call("example.operation")

    assert gdb.transport.calls[-1][2] is None
    assert gdb.operations.calls[-1][-1] is None
