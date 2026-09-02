"""Public targetless-GDB lifecycle and one-shot binding regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from collections import defaultdict

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pwnc.gdb.dap as dap
from pwnc.gdb.dap import ConsoleConfig, DapError, Gdb, GdbState, start


TIMEOUT = 15.0
GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")


class _FakeTransport:
    """Small synchronous transport for lifecycle tests, not protocol tests."""

    def __init__(self, *, fail_initialize=False):
        self.fail_initialize = fail_initialize
        self.requests = []
        self.sent = []
        self._handlers = defaultdict(list)
        self._terminal_listeners = []
        self._closed_event = threading.Event()
        self.terminal_reason = None

    @property
    def closed(self):
        return self._closed_event.is_set()

    def on(self, event, handler, *, reentrant=False):
        self._handlers[event].append((handler, reentrant))

    def off(self, event, handler):
        entries = self._handlers.get(event, [])
        for entry in list(entries):
            if entry[0] is handler:
                entries.remove(entry)

    def add_terminal_listener(self, callback):
        if self.closed:
            callback(self.terminal_reason or "transport closed")
            return lambda: False
        self._terminal_listeners.append(callback)

        def unsubscribe():
            try:
                self._terminal_listeners.remove(callback)
            except ValueError:
                return False
            return True

        return unsubscribe

    def request(self, command, arguments=None, timeout=None):
        if self.closed:
            raise DapError(self.terminal_reason or "transport closed")
        self.requests.append((command, arguments, timeout))
        if command == "initialize" and self.fail_initialize:
            raise DapError("synthetic initialization failure")
        if command == "pwncArch":
            return {"byteorder": "little", "ptrbits": 64}
        if command == "threads":
            return {"threads": []}
        if command == "evaluate":
            return {"result": "ok"}
        if command == "disconnect":
            self.terminate("synthetic disconnect")
        return {}

    def send(self, command, arguments=None):
        if self.closed:
            raise DapError(self.terminal_reason or "transport closed")
        future = (command, arguments, len(self.sent))
        self.sent.append(future)
        return future

    def result(self, _future, timeout=None):
        if self.closed:
            raise DapError(self.terminal_reason or "transport closed")
        return {}

    def wait_initialized(self, timeout=None):
        if self.closed:
            raise DapError(self.terminal_reason or "transport closed")

    def wait_closed(self, timeout=None):
        return self._closed_event.wait(timeout)

    def terminate(self, reason="synthetic transport death"):
        if self.closed:
            return
        self.terminal_reason = reason
        self._closed_event.set()
        listeners = list(self._terminal_listeners)
        self._terminal_listeners.clear()
        for listener in listeners:
            listener(reason)

    def close(self, timeout=None):
        self.terminate("synthetic close")


def _prepared():
    transport = _FakeTransport()
    gdb = Gdb(transport)
    gdb._initialize()
    assert gdb.state is GdbState.PREPARED
    return gdb, transport


def test_prepared_state_and_transport_death_are_public_and_event_backed():
    transport = _FakeTransport()
    gdb = Gdb(transport)
    try:
        assert gdb.state is GdbState.NEW
        assert not gdb.closed
        gdb._initialize()
        assert gdb.state is GdbState.PREPARED

        transport.terminate("user quit GDB")
        assert gdb.wait_closed(0)
        assert gdb.closed
        assert gdb.state is GdbState.CLOSED
    finally:
        gdb.close()


def test_public_launch_is_one_shot_and_empty_connect_validation_is_non_consuming():
    gdb, transport = _prepared()
    try:
        with pytest.raises(ValueError, match="cannot be empty"):
            gdb.connect("")
        assert gdb.state is GdbState.PREPARED

        assert gdb.launch("relative-program", "one", 2, stop_at_main=False) is gdb
        assert gdb.state is GdbState.BOUND
        command, arguments, _number = transport.sent[-1]
        assert command == "launch"
        assert arguments == {
            "program": os.path.abspath("relative-program"),
            "args": ["one", "2"],
            "stopAtBeginningOfMainSubprogram": False,
        }
        with pytest.raises(DapError, match="already has a target"):
            gdb.launch("other", stop_at_main=False)
    finally:
        gdb.close()


def test_configured_timeout_applies_to_public_binding_requests():
    gdb, transport = _prepared()
    transport.requests.clear()
    configured = gdb.use(timeout=2.5)
    try:
        assert configured.launch("program", stop_at_main=False) is configured
        binding_requests = [
            (command, timeout)
            for command, _arguments, timeout in transport.requests
            if command in {"configurationDone", "pwncArch", "threads"}
        ]
        assert binding_requests == [
            ("configurationDone", 2.5),
            ("pwncArch", 2.5),
            ("threads", 2.5),
        ]
    finally:
        gdb.close()


def test_public_attach_connect_and_debug_forward_without_argument_maps(monkeypatch):
    calls = []

    gdb, _transport = _prepared()
    monkeypatch.setattr(gdb, "_connect_pid", lambda pid, program: calls.append(("attach", pid, program)))
    try:
        assert gdb.attach(1234, b"./prog") is gdb
        assert calls == [("attach", 1234, "./prog")]
    finally:
        gdb.close()

    gdb, _transport = _prepared()
    monkeypatch.setattr(
        gdb,
        "_connect_remote",
        lambda program, target: calls.append(("connect", target, program)),
    )
    try:
        assert gdb.connect("localhost:31337", program="./prog") is gdb
        assert calls[-1] == ("connect", "localhost:31337", "./prog")
    finally:
        gdb.close()

    gdb, _transport = _prepared()
    monkeypatch.setattr(
        dap,
        "_debug_prepared",
        lambda session, program, args, env: calls.append(
            ("debug", session, program, args, env)
        ),
    )
    try:
        assert gdb.debug("./prog", "a", env={"X": "1"}) is gdb
        assert calls[-1] == (
            "debug",
            gdb,
            os.path.abspath("./prog"),
            ("a",),
            {"X": "1"},
        )
    finally:
        gdb.close()


def test_concurrent_binding_has_one_winner(monkeypatch):
    gdb, _transport = _prepared()
    entered = threading.Event()
    release = threading.Event()
    outcomes = []

    def blocked_launch(*_args):
        entered.set()
        assert release.wait(TIMEOUT)

    monkeypatch.setattr(gdb, "_launch", blocked_launch)

    def bind():
        try:
            outcomes.append(gdb.launch("first", stop_at_main=False))
        except BaseException as error:  # noqa: BLE001 - relay thread outcome
            outcomes.append(error)

    thread = threading.Thread(target=bind)
    thread.start()
    try:
        assert entered.wait(TIMEOUT)
        assert gdb.state is GdbState.BINDING
        with pytest.raises(DapError, match="already binding"):
            gdb.connect("localhost:1")
        release.set()
        thread.join(TIMEOUT)
        assert not thread.is_alive()
        assert outcomes == [gdb]
        assert gdb.state is GdbState.BOUND
    finally:
        release.set()
        thread.join(TIMEOUT)
        gdb.close()


def test_bind_failure_closes_and_reaps_the_prepared_session(monkeypatch):
    gdb, transport = _prepared()

    def fail(*_args):
        raise RuntimeError("synthetic bind failure")

    monkeypatch.setattr(gdb, "_launch", fail)
    with pytest.raises(RuntimeError, match="synthetic bind failure"):
        gdb.launch("broken", stop_at_main=False)

    assert gdb.state is GdbState.CLOSED
    assert gdb.closed
    assert transport.closed
    assert gdb.wait_closed(0)


def test_close_wins_a_race_with_binding(monkeypatch):
    gdb, transport = _prepared()
    entered = threading.Event()
    release = threading.Event()
    outcomes = []

    def blocked_launch(*_args):
        entered.set()
        assert release.wait(TIMEOUT)

    monkeypatch.setattr(gdb, "_launch", blocked_launch)

    def bind():
        try:
            gdb.launch("race", stop_at_main=False)
        except BaseException as error:  # noqa: BLE001 - relay thread outcome
            outcomes.append(error)

    thread = threading.Thread(target=bind)
    thread.start()
    assert entered.wait(TIMEOUT)
    gdb.close()
    release.set()
    thread.join(TIMEOUT)

    assert not thread.is_alive()
    assert len(outcomes) == 1
    assert isinstance(outcomes[0], DapError)
    assert "closed while binding" in str(outcomes[0])
    assert transport.closed
    assert gdb.state is GdbState.CLOSED


def test_public_start_cleans_up_initialization_failure(monkeypatch):
    transport = _FakeTransport(fail_initialize=True)
    options = {}

    def make_transport(**kwargs):
        options.update(kwargs)
        return transport

    monkeypatch.setattr(dap, "DapTransport", make_transport)

    with pytest.raises(DapError, match="synthetic initialization failure"):
        dap.start(init=False)

    assert transport.closed
    assert options["init"] is False


def test_public_target_constructors_forward_init(monkeypatch):
    calls = []

    class Prepared:
        def debug(self, *args, **kwargs):
            calls.append(("debug", args, kwargs))

        def attach(self, *args, **kwargs):
            calls.append(("attach", args, kwargs))

        def launch(self, *args, **kwargs):
            calls.append(("launch", args, kwargs))

        def close(self):
            calls.append(("close", (), {}))

    starts = []

    def fake_start(**kwargs):
        starts.append(kwargs)
        return Prepared()

    monkeypatch.setattr(dap, "start", fake_start)
    monkeypatch.setattr(dap, "_resolve_pid", lambda _value: 31337)

    assert isinstance(dap.debug("debug-target", init=False), Prepared)
    assert isinstance(dap.attach("named-target", init=False), Prepared)
    assert isinstance(dap.launch("launch-target", init=False), Prepared)

    assert [options["init"] for options in starts] == [False, False, False]
    assert [kind for kind, _args, _kwargs in calls] == ["debug", "attach", "launch"]


@pytest.fixture
def native_binary(tmp_path):
    if not shutil.which(GDB_PATH) and not os.path.isfile(GDB_PATH):
        pytest.skip("GDB with DAP is required")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc is required")
    source = tmp_path / "targetless.c"
    binary = tmp_path / "targetless"
    source.write_text("int marker = 7; int main(void) { return marker; }\n")
    subprocess.run(
        [compiler, "-g", "-O0", "-no-pie", "-o", str(binary), str(source)],
        check=True,
        capture_output=True,
    )
    return binary


def test_live_start_has_no_target_then_launches_with_the_same_gdb(native_binary):
    gdb = start(
        gdb_path=GDB_PATH,
        init=False,
        console=ConsoleConfig.owned(initial_size=(31, 109)),
    )
    pid = gdb.transport.proc.pid
    try:
        assert gdb.state is GdbState.PREPARED
        assert gdb.target is None
        assert gdb.transport.proc.poll() is None
        assert "gdb" in gdb.execute("show version").lower()
        assert gdb._console is not None
        assert gdb._console.endpoint_alive
        assert not gdb._console.viewer_connected

        assert gdb.launch(str(native_binary)) is gdb
        assert gdb.state is GdbState.BOUND
        assert gdb.transport.proc.pid == pid
        assert int(gdb.sym.marker) == 7
    finally:
        gdb.close()

    assert gdb.wait_closed(TIMEOUT)
    assert gdb.closed
    assert gdb.state is GdbState.CLOSED
