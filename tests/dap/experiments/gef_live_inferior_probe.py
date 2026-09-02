"""Exercise untouched bata24 GEF commands from a synchronous host callback.

The recursive callback probe already proves that GEF's ``history`` command and
its nested ``gdb.execute`` call work at every recursion level.  This companion
starts a real native inferior, stops after a heap allocation, and invokes a
representative set of process-aware GEF commands from the outer callback.  GEF
is sourced from the agreed fixture without edits; only the separate runtime
``gdb.execute`` instrumentation is injected.
"""

import argparse
import os
import queue
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

EXPERIMENTS = os.path.abspath(os.path.dirname(__file__))
REPOSITORY = os.path.abspath(os.path.join(EXPERIMENTS, "..", "..", ".."))
sys.path.insert(0, EXPERIMENTS)
sys.path.insert(0, REPOSITORY)

# Runtime path bootstrapping above deliberately keeps experiment-local modules
# ahead of the repository package when this file is run directly.
from rpc_gef_probe import (  # noqa: I001
    DEFAULT_GEF,
    EXPECTED_DEFAULT_GEF_SHA256,
    _GefHostDispatcher,
    _assert_gef_events,
    _assert_result_shape,
    _sha256,
    _source,
)
from rpc_probe import DEADLOCK_TIMEOUT, TIMEOUT, _initialize

from pwnc.gdb.dap.transport import DapTransport


DEFAULT_DEPTH = 3
_FIXTURE_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>

volatile void *pwnc_gef_allocation;

__attribute__((noinline)) void pwnc_gef_marker(void) {
    __asm__ volatile("" ::: "memory");
}

int main(void) {
    pwnc_gef_allocation = malloc(0x90);
    puts("pwnc GEF callback fixture");
    pwnc_gef_marker();
    free((void *)pwnc_gef_allocation);
    return 0;
}
"""


def _build_fixture():
    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("gcc is required for the live-inferior GEF probe")
    directory = Path(tempfile.mkdtemp(prefix="pwnc-gef-live-"))
    source = directory / "fixture.c"
    binary = directory / "fixture"
    source.write_text(_FIXTURE_SOURCE)
    subprocess.run(
        [
            compiler,
            "-g",
            "-O0",
            "-fno-omit-frame-pointer",
            "-no-pie",
            "-o",
            os.fspath(binary),
            os.fspath(source),
        ],
        check=True,
    )
    return directory, binary


def _evaluate(transport, expression):
    return transport.request(
        "evaluate",
        {"expression": expression, "context": "repl"},
        timeout=TIMEOUT,
    )


def _launch_to_marker(transport, binary):
    stops = queue.Queue()
    transport.on("stopped", stops.put)

    # Keep GEF's automatic stop hook enabled, but make its automatic layout
    # empty.  The probe invokes context panes explicitly from the callback.
    _evaluate(transport, "set pagination off")
    _evaluate(transport, "gef config gef.disable_color True")
    _evaluate(transport, 'gef config context.layout ""')

    pending = transport.send(
        "launch",
        {
            "program": os.fspath(binary),
            "stopAtBeginningOfMainSubprogram": True,
        },
    )
    transport.request("configurationDone", timeout=TIMEOUT)
    transport.result(pending, timeout=TIMEOUT)
    initial = stops.get(timeout=TIMEOUT)
    assert initial.get("reason") not in {"exited", "terminated"}

    _evaluate(transport, "break pwnc_gef_marker")
    transport.request(
        "continue",
        {"threadId": initial.get("threadId", 1)},
        timeout=TIMEOUT,
    )
    marker = stops.get(timeout=TIMEOUT)
    assert marker.get("reason") not in {"exited", "terminated"}
    frame = transport.request(
        "stackTrace",
        {"threadId": marker.get("threadId", 1), "startFrame": 0, "levels": 1},
        timeout=TIMEOUT,
    )["stackFrames"][0]
    assert "pwnc_gef_marker" in frame["name"]
    return marker


class _LiveGefDispatcher(_GefHostDispatcher):
    """Run process-aware GEF commands before the ordinary recursive probe."""

    def __init__(self, transport, max_depth, binary):
        super().__init__(transport, max_depth)
        self.binary = binary
        self.live_command_results = []

    def _run_callback(self, callback):
        if callback["depth"] == 0:
            commands = [
                "gef version",
                "checksec -f " + os.fspath(self.binary),
                "vmmap",
                "xinfo $pc",
                "got -n",
                "context regs stack code",
                "heap chunks -n",
            ]
            for command in commands:
                result = _evaluate(self.transport, command)
                assert result["variablesReference"] == 0
                assert isinstance(result["result"], str)
                assert result["result"].strip(), (
                    f"GEF command returned no observable output: {command}"
                )
                self.live_command_results.append({"command": command, "resultLength": len(result["result"])})
                self.record_host(
                    "host-live-gef-command-returned",
                    operationId=callback["operationId"],
                    depth=0,
                    command=command,
                )
        return super()._run_callback(callback)


def _assert_live_command_events(events, commands, gdb_thread_id):
    windows = {}
    for command in commands:
        enters = [event for event in events if event["kind"] == "execute-enter" and event["command"] == command]
        returns = [event for event in events if event["kind"] == "execute-return" and event["command"] == command]
        assert len(enters) == 1, (command, enters)
        assert len(returns) == 1, (command, returns)
        assert enters[0]["seq"] < returns[0]["seq"]
        assert enters[0]["depth"] == returns[0]["depth"] == 0
        assert enters[0]["threadId"] == returns[0]["threadId"] == gdb_thread_id
        windows[command] = (enters[0]["seq"], returns[0]["seq"])

    # The real ContextCommand dispatches each requested pane through a nested
    # synchronous gdb.execute call.  Prove those untouched plugin frames stay
    # inside the outer context invocation and on GDB's main thread.
    context_start, context_end = windows["context regs stack code"]
    context_children = [
        event
        for event in events
        if event["kind"] == "execute-enter"
        and event["depth"] == 1
        and context_start < event["seq"] < context_end
        and event["command"].startswith("context-")
    ]
    for pane in ("context-regs", "context-stack", "context-code"):
        assert any(event["command"].startswith(pane) for event in context_children)
    assert {event["threadId"] for event in context_children} == {gdb_thread_id}


def run_probe(gdb_path="gdb", gef_path=DEFAULT_GEF, max_depth=DEFAULT_DEPTH):
    gef_path = Path(gef_path).resolve()
    if not gef_path.is_file():
        raise RuntimeError(f"bata24 GEF source is required: {gef_path}")
    if not shutil.which(gdb_path) and not os.path.isfile(gdb_path):
        raise RuntimeError("GDB is required for the live-inferior GEF probe")
    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")

    digest_before = _sha256(gef_path)
    assert digest_before == EXPECTED_DEFAULT_GEF_SHA256, (
        "the GEF fixture is not the agreed bata24 source: "
        f"expected {EXPECTED_DEFAULT_GEF_SHA256}, got {digest_before}"
    )

    fixture_directory, binary = _build_fixture()
    transport = DapTransport(gdb_path)
    dispatcher = None
    try:
        _initialize(transport)
        _source(transport, gef_path)
        _source(transport, Path(__file__).with_name("gef_injection_ext.py"))
        marker = _launch_to_marker(transport, binary)

        dispatcher = _LiveGefDispatcher(transport, max_depth, binary)
        _operation_id, outer_future = dispatcher.start_operation(0)
        result = outer_future.result(timeout=DEADLOCK_TIMEOUT)
        dispatcher.finish_workers()

        snapshot = transport.request("rpcProbeSnapshot", timeout=TIMEOUT)
        injected = transport.request("pwncGefInjectionSnapshot", timeout=TIMEOUT)
        operation_ids = _assert_result_shape(result, max_depth)
        assert len(snapshot["operations"]) == max_depth + 1
        assert all(operation["status"] == "done" for operation in snapshot["operations"].values())
        assert not dispatcher.callback_errors

        gdb_thread_ids = {
            event["threadId"]
            for event in snapshot["trace"]
            if event["kind"]
            in {
                "operation-enter",
                "callback-emitted",
                "operation-resumed",
                "operation-done",
            }
        }
        assert len(gdb_thread_ids) == 1
        gdb_thread_id = next(iter(gdb_thread_ids))
        _assert_gef_events(
            injected["events"],
            expected_calls=max_depth + 1,
            gdb_thread_id=gdb_thread_id,
        )
        commands = [item["command"] for item in dispatcher.live_command_results]
        _assert_live_command_events(injected["events"], commands, gdb_thread_id)
        assert commands == [
            "gef version",
            "checksec -f " + os.fspath(binary),
            "vmmap",
            "xinfo $pc",
            "got -n",
            "context regs stack code",
            "heap chunks -n",
        ]
        assert injected["installed"] is True
        assert dispatcher.worker_threads_alive_after_shutdown == []

        gdb_version = _evaluate(transport, "show version")["result"].splitlines()[0]
    finally:
        if dispatcher is not None:
            dispatcher.abort()
        transport.close()
        shutil.rmtree(fixture_directory)

    assert _sha256(gef_path) == digest_before
    return {
        "callbackWorkers": max_depth + 1,
        "gefCommands": commands,
        "gefPath": os.fspath(gef_path),
        "gefSha256": digest_before,
        "gdbThreadId": gdb_thread_id,
        "gdbVersion": gdb_version,
        "inferiorStopReason": marker["reason"],
        "nestedOperations": len(operation_ids),
        "sourceUnmodified": True,
    }


def test_unmodified_bata24_gef_live_inferior_commands_inside_callback():
    if not DEFAULT_GEF.is_file() or not shutil.which("gdb") or not shutil.which("gcc"):
        import pytest

        pytest.skip("live GDB, gcc, and bata24 GEF fixture are required")
    evidence = run_probe()
    assert evidence["sourceUnmodified"] is True
    assert len(evidence["gefCommands"]) == 7


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    arguments = parser.parse_args()
    found = run_probe(arguments.gdb, arguments.gef, arguments.depth)
    print("PASS unmodified bata24 GEF live-inferior callback probe")
    for key in sorted(found):
        print(f"{key}: {found[key]}")
