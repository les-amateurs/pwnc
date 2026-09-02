"""Lifecycle and wait-state regressions for the synchronous DAP controller."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import gc
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import weakref

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import DapError, DapTimeout, Gdb, launch


TIMEOUT = 15.0


@pytest.fixture
def lifecycle_binary(tmp_path):
    if not shutil.which("gdb") or not shutil.which("gcc"):
        pytest.skip("live GDB and GCC are required")
    source = tmp_path / "lifecycle.c"
    binary = tmp_path / "lifecycle"
    source.write_text(
        "__attribute__((noinline)) void tick(int value) { "
        "asm volatile(\"\" : : \"r\"(value) : \"memory\"); }\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc > 1) while (1) tick(argc);\n"
        "    for (int i = 0; i < 100; ++i) tick(i);\n"
        "    return 0;\n"
        "}\n"
    )
    subprocess.run(
        ["gcc", "-g", "-O0", "-no-pie", "-o", str(binary), str(source)],
        check=True,
    )
    return binary


def _wait_until(predicate, label, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {label}")
        time.sleep(0.01)


def test_stop_wait_blocks_until_an_explicit_terminal_notification() -> None:
    class ObservedQueue(queue.Queue):
        def __init__(self):
            super().__init__()
            self.blocking_get_entered = threading.Event()
            self.get_calls = []

        def get(self, block=True, timeout=None):
            self.get_calls.append((block, timeout))
            if block:
                self.blocking_get_entered.set()
            return super().get(block=block, timeout=timeout)

    class OpenTransport:
        closed = False
        terminal_reason = None

    gdb = object.__new__(Gdb)
    gdb._stops = ObservedQueue()
    gdb._closed = False
    gdb._event_state_lock = threading.Lock()
    gdb._wait_terminal_queued = False
    gdb._wait_terminal_reason = None
    gdb.transport = OpenTransport()
    outcome = []

    def wait_for_stop():
        try:
            outcome.append(gdb._next_stop(None))
        except BaseException as error:  # noqa: BLE001 - relay the waiter result
            outcome.append(error)

    waiter = threading.Thread(target=wait_for_stop)
    waiter.start()
    assert gdb._stops.blocking_get_entered.wait(1.0)
    gdb._queue_wait_terminal("transport lost")
    waiter.join(1.0)

    assert not waiter.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], DapError)
    assert "transport lost" in str(outcome[0])
    assert gdb._stops.get_calls == [(False, None), (True, None)]


def test_stop_queued_before_transport_terminal_is_not_overtaken() -> None:
    gdb = object.__new__(Gdb)
    gdb._stops = queue.Queue()
    gdb._closed = False
    gdb._event_state_lock = threading.Lock()
    gdb._terminal_stop_queued = False
    gdb._wait_terminal_queued = False
    gdb._wait_terminal_reason = None
    gdb._cur_thread = None

    stop = {"reason": "breakpoint", "threadId": 7}
    gdb._on_stopped(stop)
    gdb._on_transport_terminal("transport lost")

    assert gdb._next_stop(None) == stop
    with pytest.raises(DapError, match="transport lost"):
        gdb._next_stop(None)


def test_execution_request_discards_only_pre_barrier_nonterminal_stops() -> None:
    """A compound plugin command cannot poison the next public resume."""

    calls = []

    class BarrierTransport:
        closed = False
        terminal_reason = None

        def drain_events(self, timeout):
            calls.append(("barrier", timeout))

        def request(self, command, arguments=None, *, timeout=None):
            calls.append((command, arguments, timeout))
            # This is the genuinely new stop produced by the public continue.
            gdb._stops.put(
                {
                    "reason": "breakpoint",
                    "threadId": 9,
                    "hitBreakpointIds": [],
                }
            )
            return {}

    gdb = object.__new__(Gdb)
    gdb.transport = BarrierTransport()
    gdb._stops = queue.Queue()
    gdb._stops.put({"reason": "step", "threadId": 9})
    gdb._stops.put({"reason": "step", "threadId": 9})
    gdb._discarded_internal_stops = 0
    gdb._closed = False
    gdb._cur_thread = 9
    gdb._wait_lock = threading.Lock()
    gdb._event_state_lock = threading.Lock()
    gdb._wait_terminal_reason = None
    gdb._bp_callbacks = {}

    stop = gdb.cont(timeout=1.25)

    assert stop["reason"] == "breakpoint"
    assert gdb._discarded_internal_stops == 2
    assert calls == [
        ("barrier", 1.25),
        ("continue", {"threadId": 9}, 1.25),
    ]


def test_execution_request_barrier_preserves_terminal_stop() -> None:
    class BarrierTransport:
        def drain_events(self, timeout):
            assert timeout == 2.0

    gdb = object.__new__(Gdb)
    gdb.transport = BarrierTransport()
    gdb._stops = queue.Queue()
    gdb._stops.put({"reason": "step", "threadId": 3})
    terminal = {"reason": "exited", "exitCode": 0}
    gdb._stops.put(terminal)
    gdb._discarded_internal_stops = 0

    assert gdb._prepare_execution_request(2.0) == 1
    assert gdb._discarded_internal_stops == 1
    assert gdb._stops.get_nowait() is terminal
    with pytest.raises(queue.Empty):
        gdb._stops.get_nowait()


def test_stop_at_main_false_returns_without_blind_ten_second_wait(lifecycle_binary) -> None:
    started = time.monotonic()
    gdb = launch(str(lifecycle_binary), "spin", init=False, stop_at_main=False)
    try:
        assert time.monotonic() - started < 5.0
        gdb.interrupt()
        stop = gdb.wait(TIMEOUT)
        assert stop["reason"] not in {"exited", "terminated"}
    finally:
        gdb.close()


def test_close_wakes_a_thread_blocked_in_wait(lifecycle_binary) -> None:
    gdb = launch(str(lifecycle_binary), "spin", init=False)
    outcome = []

    def waiter():
        try:
            outcome.append(gdb.wait())
        except BaseException as error:  # noqa: BLE001 - relay exact waiter result
            outcome.append(error)

    thread = threading.Thread(target=waiter)
    try:
        gdb.cont_nowait()
        thread.start()
        _wait_until(gdb._wait_lock.locked, "wait ownership")
        gdb.close()
        thread.join(2.0)
        assert not thread.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], (DapError, dict))
    finally:
        gdb.close()
        if thread.ident is not None:
            thread.join(2.0)


def test_concurrent_wait_is_rejected_instead_of_racing(lifecycle_binary) -> None:
    gdb = launch(str(lifecycle_binary), "spin", init=False)
    first_outcome = []

    def first_waiter():
        try:
            first_outcome.append(gdb.wait(TIMEOUT))
        except BaseException as error:  # noqa: BLE001 - relay exact waiter result
            first_outcome.append(error)

    thread = threading.Thread(target=first_waiter)
    try:
        gdb.cont_nowait()
        thread.start()
        _wait_until(gdb._wait_lock.locked, "first wait ownership")
        with pytest.raises(DapError, match="another thread"):
            gdb.wait(0.1)
        gdb.interrupt()
        thread.join(TIMEOUT)
        assert not thread.is_alive()
        assert len(first_outcome) == 1
    finally:
        gdb.close()
        if thread.ident is not None:
            thread.join(2.0)


def test_wait_timeout_is_one_deadline_across_auto_continue_callbacks(
    lifecycle_binary,
) -> None:
    gdb = launch(str(lifecycle_binary), init=False)
    hits = []

    def slow_callback(_gdb):
        hits.append(time.monotonic())
        time.sleep(0.08)

    try:
        gdb.bp("tick", callback=slow_callback)
        started = time.monotonic()
        with pytest.raises(DapTimeout):
            gdb.cont(timeout=0.18)
        elapsed = time.monotonic() - started
        assert 1 <= len(hits) < 10
        assert elapsed < 1.0
    finally:
        gdb.close()


def test_exited_and_terminated_produce_one_terminal_stop(lifecycle_binary) -> None:
    gdb = launch(str(lifecycle_binary), init=False)
    try:
        stop = gdb.cont(timeout=TIMEOUT)
        assert stop["reason"] in {"exited", "terminated"}
        with pytest.raises(DapTimeout):
            gdb.wait(timeout=0.2)
    finally:
        gdb.close()


def test_close_unregisters_atexit_reference(lifecycle_binary) -> None:
    gdb = launch(str(lifecycle_binary), "spin", init=False)
    reference = weakref.ref(gdb)
    gdb.close()
    del gdb
    for _ in range(3):
        gc.collect()
    assert reference() is None


def test_failed_constructor_reaps_started_gdb(lifecycle_binary, tmp_path) -> None:
    real_gdb = shutil.which("gdb")
    assert real_gdb is not None
    pid_path = tmp_path / "gdb.pid"
    wrapper = tmp_path / "record-gdb-pid"
    wrapper.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        "pathlib.Path(os.environ['PWNC_TEST_GDB_PID']).write_text(str(os.getpid()))\n"
        f"os.execv({real_gdb!r}, [{real_gdb!r}, *sys.argv[1:]])\n"
    )
    wrapper.chmod(0o755)
    environment = dict(os.environ)
    environment["PWNC_TEST_GDB_PID"] = str(pid_path)

    with pytest.raises(DapError):
        launch(
            str(lifecycle_binary),
            gdb_path=str(wrapper),
            gdb_args=["-ex", "quit"],
            env=environment,
            init=False,
        )
    _wait_until(pid_path.is_file, "recorded GDB pid")
    pid = int(pid_path.read_text())
    _wait_until(lambda: not os.path.exists(f"/proc/{pid}"), "failed GDB reap")
