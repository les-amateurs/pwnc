"""Production callback coverage against a live inferior and exact bata24 GEF."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import Gdb, launch


TIMEOUT = 30.0
GEF_PATH = Path("/home/ctf/bata24-gef/gef.py")
GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
FIXTURES = Path(__file__).with_name("fixtures")
EXPERIMENTS = Path(__file__).with_name("experiments")
GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")

INFERIOR_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>

volatile void *pwnc_gef_allocation;

__attribute__((noinline)) void pwnc_gef_marker(void) {
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline)) void pwnc_gef_marker_after_callback(void) {
    __asm__ volatile("" ::: "memory");
}

int main(void) {
    pwnc_gef_allocation = malloc(0x90);
    puts("pwnc GEF callback fixture");
    pwnc_gef_marker();
    pwnc_gef_marker_after_callback();
    free((void *)pwnc_gef_allocation);
    return 0;
}
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_stat(path: Path) -> tuple[int, ...]:
    """Metadata that must not change when a source file is only read.

    Access time is deliberately excluded because reading the fixture may update
    it on filesystems that are not mounted with ``noatime``.
    """

    stat = path.stat()
    return (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )


@pytest.fixture
def exact_gef() -> Path:
    if not GEF_PATH.is_file():
        pytest.skip("exact bata24 GEF fixture is not installed")

    digest_before = _sha256(GEF_PATH)
    assert digest_before == GEF_SHA256, (
        "the installed GEF fixture is not the agreed unmodified bata24 source: "
        f"expected {GEF_SHA256}, got {digest_before}"
    )
    stat_before = _stable_stat(GEF_PATH)
    try:
        yield GEF_PATH
    finally:
        assert _sha256(GEF_PATH) == digest_before
        assert _stable_stat(GEF_PATH) == stat_before


def _build_inferior(tmp_path: Path) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc is required for the native live-inferior test")

    source = tmp_path / "gef-callback-inferior.c"
    binary = tmp_path / "gef-callback-inferior"
    source.write_text(INFERIOR_SOURCE, encoding="utf-8")
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-g3",
            "-O0",
            "-fno-omit-frame-pointer",
            "-fno-pie",
            "-no-pie",
            "-Wl,-z,relro",
            "-o",
            os.fspath(binary),
            os.fspath(source),
        ],
        check=True,
        capture_output=True,
        timeout=TIMEOUT,
    )
    return binary


def _source(gdb: Gdb, path: Path) -> str:
    return gdb.execute("source " + os.fspath(path.resolve()))


def _assert_command_window(events: list[dict], command: str) -> tuple[dict, dict, list[dict]]:
    enters = [
        event
        for event in events
        if event["kind"] == "execute-enter" and event["depth"] == 0 and event["command"] == command
    ]
    returns = [
        event
        for event in events
        if event["kind"] == "execute-return" and event["depth"] == 0 and event["command"] == command
    ]
    assert len(enters) == 1, (command, enters)
    assert len(returns) == 1, (command, returns)
    enter, returned = enters[0], returns[0]
    assert enter["seq"] < returned["seq"]
    nested = [
        event
        for event in events
        if event["kind"] == "execute-enter" and event["depth"] > 0 and enter["seq"] < event["seq"] < returned["seq"]
    ]
    return enter, returned, nested


def test_run_operation_executes_unmodified_gef_on_live_native_inferior(
    exact_gef: Path,
    tmp_path: Path,
) -> None:
    """A sync host callback can enter process-aware GEF without deadlocking."""

    if shutil.which(GDB_PATH) is None and not os.path.isfile(GDB_PATH):
        pytest.skip("native GDB with DAP support is required")

    binary = _build_inferior(tmp_path)
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    environment = os.environ.copy()
    environment["HOME"] = os.fspath(isolated_home)
    environment["TMPDIR"] = os.fspath(tmp_path)
    environment.setdefault("TERM", "xterm")

    gdb = launch(binary, env=environment, gdb_path=GDB_PATH, init=False)
    commands = [
        "gef version",
        "checksec -f " + os.fspath(binary),
        "vmmap",
        "xinfo $pc",
        "got -n",
        "context regs stack code",
        "heap chunks -n",
    ]
    outputs: dict[str, str] = {}
    callback_thread_ids: list[int] = []

    try:
        # Install observation before sourcing GEF so nested calls made during
        # plugin initialization and command execution are visible.  This only
        # replaces ``gdb.execute`` in the live interpreter; GEF stays untouched.
        _source(gdb, EXPERIMENTS / "gef_injection_ext.py")
        _source(gdb, exact_gef)
        _source(gdb, FIXTURES / "callback_operations.py")
        gdb.execute("set pagination off")
        gdb.execute("set confirm off")
        gdb.execute("gef config gef.disable_color True")
        gdb.execute('gef config context.layout ""')

        gdb.bp("pwnc_gef_marker")
        stop = gdb.cont(timeout=TIMEOUT)
        assert stop["reason"] == "breakpoint"

        def invoke_gef(depth: int, *, max_depth: int) -> dict:
            assert (depth, max_depth) == (0, 0)
            callback_thread_ids.append(threading.get_ident())
            for command in commands:
                output = gdb.execute(command)
                assert isinstance(output, str)
                assert output.strip(), f"GEF returned no output for {command!r}"
                outputs[command] = output
            return {"commandCount": len(outputs), "marker": "host-callback-returned"}

        result = gdb.run_operation(
            "pwnc.test.recursive",
            {"depth": 0, "max_depth": 0},
            callbacks={"pwnc.test.callback": invoke_gef},
            timeout=TIMEOUT,
        )
        assert result["depth"] == 0
        assert result["value"] == {
            "commandCount": len(commands),
            "marker": "host-callback-returned",
        }
        assert "pagination is off" in result["before"].lower()
        assert "confirm" in result["after"].lower()

        # These checks deliberately use stable semantic fragments rather than
        # addresses, library versions, or terminal-width-dependent decoration.
        assert all(part in outputs["gef version"] for part in ("GEF:", "gdb:", "python:"))
        assert all(part in outputs[commands[1]] for part in ("Canary", "NX", "PIE", "RELRO"))
        assert os.fspath(binary) in outputs["vmmap"]
        assert "[heap]" in outputs["vmmap"]
        assert "pwnc_gef_marker" in outputs["xinfo $pc"]
        assert all(part in outputs["got -n"] for part in ("PLT / GOT", "malloc", "free"))
        context_output = outputs["context regs stack code"].lower()
        assert all(part in context_output for part in ("registers", "stack", "code"))
        assert "pwnc_gef_marker" in context_output
        assert "Chunk(" in outputs["heap chunks -n"]
        assert "top" in outputs["heap chunks -n"]

        operation_trace = gdb.run_operation("pwnc.test.snapshot", timeout=TIMEOUT)
        operation_thread_ids = {
            event["threadId"] for event in operation_trace if event["kind"] in {"operation-enter", "operation-return"}
        }
        assert len(operation_thread_ids) == 1
        gdb_main_thread_id = next(iter(operation_thread_ids))
        assert len(callback_thread_ids) == 1
        callback_thread_id = callback_thread_ids[0]
        assert callback_thread_id != gdb_main_thread_id
        assert callback_thread_id not in {
            gdb.transport.reader_thread_id,
            gdb.transport.router_thread_id,
            gdb.transport.writer_thread_id,
            gdb.transport.event_thread_id,
        }

        injection = gdb.transport.request("pwncGefInjectionSnapshot", timeout=TIMEOUT)
        assert injection["installed"] is True
        command_windows = {command: _assert_command_window(injection["events"], command) for command in commands}
        outer_events = [event for enter, returned, _nested in command_windows.values() for event in (enter, returned)]
        assert {event["threadId"] for event in outer_events} == {gdb_main_thread_id}

        # Untouched GEF performs synchronous nested dispatch for these commands.
        # Context is the strongest case: each requested pane is dispatched
        # through a separate nested plugin command before the outer call returns.
        for command in (
            "gef version",
            commands[1],
            "xinfo $pc",
            "got -n",
            "context regs stack code",
            "heap chunks -n",
        ):
            nested = command_windows[command][2]
            assert nested, f"GEF command did not make a nested gdb.execute call: {command}"
            assert {event["threadId"] for event in nested} == {gdb_main_thread_id}

        context_nested = command_windows["context regs stack code"][2]
        for pane in ("context-regs", "context-stack", "context-code"):
            assert any(event["command"].startswith(pane) for event in context_nested)

        operation_snapshot = gdb.transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert operation_snapshot["activeCount"] == 0
        assert all(tombstone["outcome"] == "done" for tombstone in operation_snapshot["tombstones"].values())
        assert not gdb.operations.errors
    finally:
        gdb.close()


def test_host_callback_can_run_bata24_next_ret_and_resume_operation(
    exact_gef: Path,
    tmp_path: Path,
) -> None:
    """Untouched Bata24 may synchronously drive execution inside a callback."""

    if shutil.which(GDB_PATH) is None and not os.path.isfile(GDB_PATH):
        pytest.skip("native GDB with DAP support is required")

    binary = _build_inferior(tmp_path)
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    environment = os.environ.copy()
    environment["HOME"] = os.fspath(isolated_home)
    environment["TMPDIR"] = os.fspath(tmp_path)
    environment.setdefault("TERM", "xterm")

    gdb = launch(binary, env=environment, gdb_path=GDB_PATH, init=False)
    callback_threads: list[int] = []
    next_ret_outputs: list[str] = []

    try:
        _source(gdb, exact_gef)
        _source(gdb, FIXTURES / "callback_operations.py")
        gdb.execute("set pagination off")
        gdb.execute("set confirm off")
        gdb.execute("gef config gef.disable_color True")
        gdb.execute('gef config context.layout "regs stack code"')

        gdb.bp("pwnc_gef_marker")
        gdb.bp("pwnc_gef_marker_after_callback")
        first_stop = gdb.cont(timeout=TIMEOUT)
        assert first_stop["reason"] == "breakpoint"
        assert "pwnc_gef_marker" in gdb.execute("frame")

        def next_ret_from_callback(depth: int, *, max_depth: int) -> dict:
            assert (depth, max_depth) == (0, 0)
            callback_threads.append(threading.get_ident())
            output = gdb.execute("next-ret -n", timeout=TIMEOUT)
            next_ret_outputs.append(output)
            lowered = output.lower()
            assert all(fragment in lowered for fragment in ("registers", "stack", "code"))
            assert "ret" in gdb.execute("x/i $pc").lower()
            return {
                "nextRet": True,
                "context": True,
            }

        result = gdb.run_operation(
            "pwnc.test.recursive",
            {"depth": 0, "max_depth": 0},
            callbacks={"pwnc.test.callback": next_ret_from_callback},
            timeout=TIMEOUT,
        )
        assert result["value"] == {
            "nextRet": True,
            "context": True,
        }
        assert len(callback_threads) == 1
        assert len(next_ret_outputs) == 1
        assert callback_threads[0] not in {
            gdb.transport.reader_thread_id,
            gdb.transport.router_thread_id,
            gdb.transport.writer_thread_id,
            gdb.transport.event_thread_id,
        }

        # A later public execution request must consume its own new stop, not
        # one of next-ret's internal instruction-step events.
        post_callback_stop = gdb.cont(timeout=TIMEOUT)
        assert post_callback_stop["reason"] == "breakpoint"
        assert "pwnc_gef_marker_after_callback" in gdb.execute("frame")
        snapshot = gdb.transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
        assert not gdb.operations.errors
    finally:
        gdb.close()


@pytest.mark.parametrize(
    "inject_before_gef",
    [True, False],
    ids=["injection-before-gef", "injection-after-gef"],
)
def test_call_invokes_unmodified_gef_and_gdb_callback_on_live_inferior(
    exact_gef: Path,
    tmp_path: Path,
    inject_before_gef: bool,
) -> None:
    """The callable-capability path composes with untouched process-aware GEF."""

    if shutil.which(GDB_PATH) is None and not os.path.isfile(GDB_PATH):
        pytest.skip("native GDB with DAP support is required")

    binary = _build_inferior(tmp_path)
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    environment = os.environ.copy()
    environment["HOME"] = os.fspath(isolated_home)
    environment["TMPDIR"] = os.fspath(tmp_path)
    environment.setdefault("TERM", "xterm")

    gdb = launch(binary, env=environment, gdb_path=GDB_PATH, init=False)
    commands = [
        "gef version",
        "vmmap",
        "xinfo $pc",
        "heap chunks -n",
    ]
    outputs: dict[str, str] = {}
    callback_thread_ids: list[int] = []

    try:
        injection = EXPERIMENTS / "gef_injection_ext.py"
        if inject_before_gef:
            _source(gdb, injection)
            _source(gdb, exact_gef)
        else:
            _source(gdb, exact_gef)
            _source(gdb, injection)
        _source(gdb, FIXTURES / "callback_operations.py")
        gdb.execute("set pagination off")
        gdb.execute("set confirm off")
        gdb.execute("gef config gef.disable_color True")
        gdb.execute('gef config context.layout ""')

        gdb.bp("pwnc_gef_marker")
        stop = gdb.cont(timeout=TIMEOUT)
        assert stop["reason"] == "breakpoint"

        def invoke_gef(
            depth,
            sync_callback,
            _recursive_callback,
            *,
            max_depth,
            binary,
        ):
            assert (depth, max_depth) == (0, 0)
            assert binary == (b"pwnc", b"callback")
            callback_thread_ids.append(threading.get_ident())
            for command in commands:
                output = gdb.execute(command)
                assert output.strip(), f"GEF returned no output for {command!r}"
                outputs[command] = output
            return {
                "syncResult": sync_callback(40, increment=2),
                "binary": binary,
            }

        result = gdb.call(
            "pwnc.test.capabilities",
            invoke_gef,
            0,
            max_depth=0,
        )
        assert result == {
            "syncResult": 42,
            "binary": (b"pwnc", b"callback"),
        }
        assert all(part in outputs["gef version"] for part in ("GEF:", "gdb:", "python:"))
        assert os.fspath(binary) in outputs["vmmap"]
        assert "[heap]" in outputs["vmmap"]
        assert "pwnc_gef_marker" in outputs["xinfo $pc"]
        assert "Chunk(" in outputs["heap chunks -n"]

        trace = gdb.run_operation("pwnc.test.snapshot", timeout=TIMEOUT)
        capability_events = [
            event
            for event in trace
            if event["kind"]
            in {
                "capability-operation-enter",
                "capability-sync",
                "capability-operation-return",
            }
        ]
        assert [event["kind"] for event in capability_events] == [
            "capability-operation-enter",
            "capability-sync",
            "capability-operation-return",
        ]
        gdb_thread_ids = {event["threadId"] for event in capability_events}
        assert len(gdb_thread_ids) == 1
        assert len(callback_thread_ids) == 1
        assert callback_thread_ids[0] not in gdb_thread_ids
        assert callback_thread_ids[0] not in {
            gdb.transport.reader_thread_id,
            gdb.transport.router_thread_id,
            gdb.transport.writer_thread_id,
            gdb.transport.event_thread_id,
        }

        injection_snapshot = gdb.transport.request("pwncGefInjectionSnapshot", timeout=TIMEOUT)
        command_windows = {
            command: _assert_command_window(injection_snapshot["events"], command) for command in commands
        }
        outer_events = [event for enter, returned, _nested in command_windows.values() for event in (enter, returned)]
        assert {event["threadId"] for event in outer_events} == gdb_thread_ids
        assert all(command_windows[command][2] for command in ("gef version", "xinfo $pc", "heap chunks -n"))

        assert "pwnc_gef_marker" in gdb.execute("frame")
        operation_snapshot = gdb.transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert operation_snapshot["activeCount"] == 0
        assert not gdb.operations.errors
    finally:
        gdb.close()
