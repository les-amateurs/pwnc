"""Executable acceptance probes for active-frame GEF callback re-entry.

The suite uses the exact bata24 GEF fixture and checks its hash before and
after every run.  Invoke it directly with ``--gdb PATH`` for a particular GDB
build, or let pytest use the host ``gdb``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

EXPERIMENTS = Path(__file__).resolve().parent
REPOSITORY = EXPERIMENTS.parents[2]
sys.path.insert(0, str(REPOSITORY))

from pwnc.gdb.dap.transport import DapTransport

DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
# Importing the full unmodified GEF source and shutting its embedded Python
# interpreter down can cross 15 seconds under an aggregate GDB stress run.
# Keep the probe bounded without making ordinary successful runs wait longer.
TIMEOUT = 30.0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_inputs(gdb_path: str, gef_path: Path) -> None:
    if not shutil.which(gdb_path) and not os.path.isfile(gdb_path):
        raise RuntimeError(f"GDB is unavailable: {gdb_path}")
    if not gef_path.is_file():
        raise RuntimeError(f"bata24 GEF is unavailable: {gef_path}")
    digest = _sha256(gef_path)
    if digest != EXPECTED_GEF_SHA256:
        raise AssertionError(
            f"the GEF fixture is not the agreed unmodified bata24 source: expected {EXPECTED_GEF_SHA256}, got {digest}"
        )


def _run_batch(
    gdb_path: str,
    commands: list[str],
    *,
    environment: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if environment:
        env.update(environment)
    argv = [gdb_path, "-q", "-nx", "-batch"]
    for command in commands:
        argv.extend(("-ex", command))
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        errors="replace",
        env=env,
        timeout=TIMEOUT,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(
            f"GDB exited {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _marked_reports(output: str, marker: str) -> list[dict]:
    reports = [json.loads(line.removeprefix(marker)) for line in output.splitlines() if line.startswith(marker)]
    if not reports:
        raise AssertionError(f"missing report marker {marker!r} in:\n{output}")
    return reports


def _source_commands(gef_path: Path, probe: str) -> list[str]:
    return [
        f"source {gef_path}",
        f"source {EXPERIMENTS / probe}",
    ]


def _initialize(transport: DapTransport) -> None:
    transport.request(
        "initialize",
        {
            "clientID": "pwnc-gef-transform-probe",
            "adapterID": "gdb",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "pathFormat": "path",
        },
        timeout=TIMEOUT,
    )
    transport.wait_initialized(timeout=TIMEOUT)


def _source_dap(transport: DapTransport, path: Path) -> None:
    transport.request(
        "evaluate",
        {"expression": f"source {path.resolve()}", "context": "repl"},
        timeout=TIMEOUT,
    )


def _event_kinds(report: dict) -> list[str]:
    return [event["kind"] for event in report["events"]]


def _probe_loader_hooks(gdb_path: str, gef_path: Path) -> dict:
    probe = EXPERIMENTS / "gef_transform_loader_probe.py"
    completed = _run_batch(
        gdb_path,
        [
            f"source {probe}",
            f"source {gef_path}",
            "gef-transform-loader-report",
        ],
        environment={"PWNC_GEF_TRANSFORM_GEF": str(gef_path)},
    )
    report = _marked_reports(
        completed.stdout + completed.stderr,
        "PWNC_GEF_TRANSFORM_LOADER_REPORT=",
    )[-1]
    assert report["builtinCompileCalls"] == []
    assert report["metaPathFindCalls"] == []
    assert len(report["auditCompileCalls"]) == 1
    assert report["compileWrapperStillInstalled"] is True
    assert report["metaFinderStillInstalled"] is True
    return report


def _probe_inline_and_worker_threads(gdb_path: str, gef_path: Path) -> dict:
    commands = _source_commands(gef_path, "gef_transform_thread_probe.py")
    marker = "PWNC_GEF_TRANSFORM_THREAD_REPORT="
    reports = {}
    for mode in ("inline", "worker-direct", "gdb-thread-direct"):
        completed = _run_batch(
            gdb_path,
            commands + [f"gef-transform-probe {mode}", "gef-transform-report"],
        )
        report = _marked_reports(completed.stdout + completed.stderr, marker)[-1]
        kinds = _event_kinds(report)
        assert report["intercepted"] is True
        if mode == "inline":
            assert kinds.index("inline-return") < kinds.index("gef-return")
            assert {event["threadId"] for event in report["events"]} == {report["commandThreadId"]}
        else:
            # This happens to work for a trivial read-only command, but the
            # state-changing test below proves it is not a usable escape.
            assert report["completedWhileGefActive"] is True
            worker_threads = {
                event["threadId"] for event in report["events"] if event["kind"].startswith("worker-direct-")
            }
            assert len(worker_threads) == 1
            assert report["commandThreadId"] not in worker_threads
        reports[mode] = report

    source = REPOSITORY / "pwnc/gdb/mi/examples/target.c"
    compiler = shutil.which("cc")
    if compiler is None or not source.is_file():
        raise RuntimeError("a C compiler and native target fixture are required")
    with tempfile.TemporaryDirectory(prefix="pwnc-gef-transform-") as directory:
        target = Path(directory) / "target"
        subprocess.run(
            [compiler, "-g", "-O0", str(source), "-o", str(target)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=True,
        )
        failed = _run_batch(
            gdb_path,
            commands
            + [
                "gef-transform-probe gdb-thread-custom",
                "gef-transform-report",
            ],
            environment={"PWNC_GEF_TRANSFORM_WORKER_COMMAND": f"file {target}"},
            check=False,
        )
    failure_output = failed.stdout + failed.stderr
    assert failed.returncode != 0, failure_output
    assert (
        "internal problem" in failure_output.lower()
        or "internal_error" in failure_output.lower()
        or "extension.c" in failure_output.lower()
    ), failure_output
    reports["worker-state-changing-failure"] = {
        "returnCode": failed.returncode,
        "internalFailureObserved": True,
    }
    return reports


def _probe_post_event(gdb_path: str, gef_path: Path) -> dict:
    transport = DapTransport(gdb_path)
    try:
        _initialize(transport)
        _source_dap(transport, gef_path)
        _source_dap(transport, EXPERIMENTS / "gef_transform_thread_probe.py")
        transport.request(
            "evaluate",
            {
                "expression": "gef-transform-probe post-event",
                "context": "repl",
            },
            timeout=TIMEOUT,
        )
        # The callback was queued only after the active command unwound.  Give
        # the GDB event loop a turn before requesting the report.
        time.sleep(0.05)
        output = transport.request(
            "evaluate",
            {"expression": "gef-transform-report", "context": "repl"},
            timeout=TIMEOUT,
        )["result"]
    finally:
        transport.close()
    report = _marked_reports(output, "PWNC_GEF_TRANSFORM_THREAD_REPORT=")[-1]
    kinds = _event_kinds(report)
    assert report["completedWhileGefActive"] is False
    assert kinds.index("gef-return") < kinds.index("post-event-enter")
    assert kinds.index("post-event-enter") < kinds.index("post-event-return")
    return report


def _probe_external_host_reentry(gdb_path: str, gef_path: Path) -> dict:
    transport = DapTransport(gdb_path)
    callback = threading.Event()
    fuse_returned = threading.Event()
    gef_returned = threading.Event()
    nested = []

    def on_callback(body: dict) -> None:
        nested.append(
            transport.send(
                "evaluate",
                {"expression": "show pagination", "context": "repl"},
            )
        )
        callback.set()

    transport.on("gefTransformHostCallback", on_callback)
    transport.on("gefTransformFuseReturned", lambda body: fuse_returned.set())
    transport.on("gefTransformGefReturned", lambda body: gef_returned.set())
    try:
        _initialize(transport)
        _source_dap(transport, gef_path)
        _source_dap(transport, EXPERIMENTS / "gef_transform_dap_ext.py")
        started = transport.request("gefTransformStart", timeout=TIMEOUT)
        assert started["queued"] is True
        assert callback.wait(TIMEOUT)
        assert len(nested) == 1
        assert not nested[0].done()
        time.sleep(0.2)
        assert not nested[0].done(), "nested GDB work ran inside active GEF"
        assert fuse_returned.wait(TIMEOUT)
        assert gef_returned.wait(TIMEOUT)
        result = transport.result(nested[0], timeout=TIMEOUT)
        assert "pagination" in result["result"].lower()
        snapshot = transport.request("gefTransformSnapshot", timeout=TIMEOUT)
    finally:
        transport.close()

    kinds = _event_kinds(snapshot)
    assert kinds.index("host-callback-emitted") < kinds.index("host-callback-fuse-returned")
    assert kinds.index("host-callback-fuse-returned") < kinds.index("gef-return")
    assert len({event["threadId"] for event in snapshot["events"]}) == 1
    return {
        "events": snapshot["events"],
        "nestedRequestCompletedOnlyAfterGefReturned": True,
        "fuseSeconds": started["fuseSeconds"],
    }


def _probe_trace_and_code(gdb_path: str, gef_path: Path) -> dict:
    commands = _source_commands(gef_path, "gef_transform_trace_probe.py")
    marker = "PWNC_GEF_TRANSFORM_TRACE_REPORT="
    reports = {}
    for mode in ("inline", "unwind", "replace-code"):
        completed = _run_batch(
            gdb_path,
            commands
            + [
                f"gef-transform-trace-probe {mode}",
                "gef-transform-trace-report",
            ],
        )
        report = _marked_reports(completed.stdout + completed.stderr, marker)[-1]
        assert report["traceFired"] is True
        assert report["activeFrameCount"] == 1
        assert report["frameIsGenerator"] is False
        assert report["frameHasSend"] is False
        assert report["frameHasThrow"] is False
        assert report["externalLineJump"]["type"] == "ValueError"
        reports[mode] = report

    inline_kinds = _event_kinds(reports["inline"])
    assert inline_kinds.index("trace-inline-execute-return") < inline_kinds.index("gef-return")
    assert reports["unwind"]["nestedOriginalExecuteCount"] == 0
    assert "get_history" in reports["unwind"]["retainedTracebackFrames"]
    replace = reports["replace-code"]
    replace_event = next(event for event in replace["events"] if event["kind"] == "trace-replaced-function-code")
    assert replace_event["activeFrameStillOriginal"] is True
    assert replace_event["functionNowReplacement"] is True
    assert replace["nestedOriginalExecuteCount"] >= 1
    assert replace["futureCallResult"] == ["replacement-result"]
    return reports


def _probe_targeted_cps(gdb_path: str, gef_path: Path) -> dict:
    loader = EXPERIMENTS / "gef_transform_cps_loader.py"
    marker = "PWNC_GEF_TRANSFORM_CPS_REPORT="
    common_environment = {"PWNC_GEF_TRANSFORM_GEF": str(gef_path)}

    inline = _run_batch(
        gdb_path,
        [
            f"source {loader}",
            "gef-transform-cps-run",
            "gef-transform-cps-report",
        ],
        environment={
            **common_environment,
            "PWNC_GEF_TRANSFORM_CPS_MODE": "inline",
        },
    )
    inline_report = _marked_reports(inline.stdout + inline.stderr, marker)[-1]
    inline_kinds = _event_kinds(inline_report)
    assert inline_report["pending"] is False
    assert inline_kinds.index("command-generator-complete") < inline_kinds.index("outer-gdb-execute-return")

    deferred = _run_batch(
        gdb_path,
        [
            f"source {loader}",
            "gef-transform-cps-run",
            "gef-transform-cps-report",
            "gef-transform-cps-resume",
            "gef-transform-cps-report",
        ],
        environment={
            **common_environment,
            "PWNC_GEF_TRANSFORM_CPS_MODE": "defer",
        },
    )
    deferred_reports = _marked_reports(deferred.stdout + deferred.stderr, marker)
    assert len(deferred_reports) == 2
    suspended, resumed = deferred_reports
    suspended_kinds = _event_kinds(suspended)
    assert suspended["pending"] is True
    assert suspended_kinds.index("command-suspended") < suspended_kinds.index("outer-gdb-execute-return")
    assert resumed["pending"] is False
    resumed_kinds = _event_kinds(resumed)
    assert resumed_kinds.index("outer-gdb-execute-return") < resumed_kinds.index("intervening-gdb-work-enter")
    assert resumed_kinds.index("intervening-gdb-work-return") < resumed_kinds.index(
        "deferred-command-resumed-to-completion"
    )
    for report in (inline_report, suspended, resumed):
        assert report["gefSha256"] == EXPECTED_GEF_SHA256
        assert report["transformed"] == {
            "genericInvoke": 1,
            "historyDoInvoke": 1,
            "historyExecuteCalls": 1,
        }
    return {
        "inline": inline_report,
        "deferredBeforeResume": suspended,
        "deferredAfterResume": resumed,
    }


def run_suite(gdb_path: str = "gdb", gef_path: Path = DEFAULT_GEF) -> dict:
    gef_path = gef_path.resolve()
    _require_inputs(gdb_path, gef_path)
    before = gef_path.stat()
    digest_before = _sha256(gef_path)
    results = {
        "loaderHooks": _probe_loader_hooks(gdb_path, gef_path),
        "directThreads": _probe_inline_and_worker_threads(gdb_path, gef_path),
        "postEvent": _probe_post_event(gdb_path, gef_path),
        "externalHostReentry": _probe_external_host_reentry(gdb_path, gef_path),
        "traceAndCode": _probe_trace_and_code(gdb_path, gef_path),
        "targetedCps": _probe_targeted_cps(gdb_path, gef_path),
    }
    after = gef_path.stat()
    assert _sha256(gef_path) == digest_before == EXPECTED_GEF_SHA256
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns

    version = _run_batch(gdb_path, ["show version"]).stdout.splitlines()[0]
    return {
        "gdbVersion": version,
        "gefPath": str(gef_path),
        "gefSha256": digest_before,
        "sourceUnmodified": True,
        "results": results,
    }


def test_active_gef_transform_feasibility() -> None:
    if not DEFAULT_GEF.is_file() or not shutil.which("gdb"):
        import pytest

        pytest.skip("live GDB and exact bata24 GEF fixture are required")
    result = run_suite()
    assert result["sourceUnmodified"] is True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_suite(args.gdb, args.gef)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"PASS: {result['gdbVersion']}, exact GEF {result['gefSha256']}; active-frame mechanisms characterized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
