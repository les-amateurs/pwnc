#!/usr/bin/env python3
"""Launch the execute-interception probe in a real GDB and validate it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import BinaryIO


MARKER = "PWNC_EXECUTE_INTERCEPT_REPORT="


def extract_report(output: str) -> dict[str, object]:
    marked_lines = [
        line.removeprefix(MARKER)
        for line in output.splitlines()
        if line.startswith(MARKER)
    ]
    if len(marked_lines) != 1:
        raise RuntimeError("probe did not emit exactly one report")
    return json.loads(marked_lines[0])


def send_dap(stream: BinaryIO, message: dict[str, object]) -> None:
    data = json.dumps(message).encode()
    stream.write(f"Content-Length: {len(data)}\r\n\r\n".encode() + data)
    stream.flush()


def receive_dap(stream: BinaryIO) -> dict[str, object]:
    length = None
    while True:
        line = stream.readline()
        if not line:
            raise EOFError("GDB closed its DAP output")
        if line in (b"\r\n", b"\n"):
            break
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"content-length":
            length = int(value.strip())
    if length is None:
        raise RuntimeError("DAP message had no Content-Length")
    data = stream.read(length)
    if len(data) != length:
        raise EOFError("short DAP message body")
    return json.loads(data)


def dap_request(
    stdin: BinaryIO,
    stdout: BinaryIO,
    seq: int,
    command: str,
    arguments: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    send_dap(
        stdin,
        {
            "seq": seq,
            "type": "request",
            "command": command,
            "arguments": arguments,
        },
    )
    side_messages = []
    while True:
        message = receive_dap(stdout)
        if message.get("type") == "response" and message.get("request_seq") == seq:
            if not message.get("success"):
                raise RuntimeError(
                    f"DAP {command!r} failed: {message.get('message', message)!r}"
                )
            return message, side_messages
        side_messages.append(message)


def run_batch(gdb_path: str, probe: Path) -> dict[str, object]:
    command = [gdb_path, "-q", "-nx", "-batch", "-ex", f"source {probe}"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError(
            f"batch GDB exited {completed.returncode}\n"
            + completed.stdout
            + completed.stderr
        )
    try:
        return extract_report(completed.stdout)
    except RuntimeError as error:
        raise RuntimeError(
            str(error) + "\n" + completed.stdout + completed.stderr
        ) from error


def run_dap(gdb_path: str, probe: Path) -> dict[str, object]:
    process = subprocess.Popen(
        [gdb_path, "-q", "-nx", "--interpreter=dap"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        _, initialize_side_messages = dap_request(
            process.stdin,
            process.stdout,
            1,
            "initialize",
            {
                "clientID": "pwnc-execute-intercept-probe",
                "adapterID": "gdb",
                "linesStartAt1": True,
                "columnsStartAt1": True,
                "pathFormat": "path",
            },
        )
        if not any(
            message.get("type") == "event"
            and message.get("event") == "initialized"
            for message in initialize_side_messages
        ):
            # GDB 15 currently emits initialized before its response.  Keep the
            # experiment correct if another supported release reverses those.
            while True:
                message = receive_dap(process.stdout)
                if (
                    message.get("type") == "event"
                    and message.get("event") == "initialized"
                ):
                    break

        response, _ = dap_request(
            process.stdin,
            process.stdout,
            2,
            "evaluate",
            {"expression": f"source {probe}", "context": "repl"},
        )
        body = response.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("result"), str):
            raise RuntimeError(f"unexpected evaluate response: {response!r}")
        return extract_report(body["result"])
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def execute_commands(events: list[dict[str, object]]) -> list[str]:
    return [
        str(event["command"])
        for event in events
        if event["kind"] == "execute-enter"
    ]


def check(report: dict[str, object]) -> None:
    monkeypatch = report["monkeypatch"]
    assert isinstance(monkeypatch, dict)
    assert monkeypatch["assignment_error"] is None
    assert monkeypatch["installed"] is True
    assert monkeypatch["module_lookup_is_wrapper"] is True
    assert monkeypatch["captured_reference_is_original"] is True
    assert monkeypatch["dynamic_value"] == 11
    assert monkeypatch["captured_value"] == 22
    assert execute_commands(monkeypatch["dynamic_events"]) == [
        "set $pwnc_probe_dynamic = 11"
    ]
    assert execute_commands(monkeypatch["captured_events"]) == []

    nesting = report["nesting"]
    assert isinstance(nesting, dict)
    assert execute_commands(nesting["dynamic"]) == [
        "pwnc-probe-outer top",
        "pwnc-probe-inner dynamic-child",
        "set $pwnc_probe_nested = 33",
    ]
    # Calling the captured C function bypasses only the top dispatch.  The
    # command's later module lookup still reaches the replacement.
    assert execute_commands(nesting["captured_top"]) == [
        "pwnc-probe-inner dynamic-child",
        "set $pwnc_probe_nested = 33",
    ]
    # Conversely, a plugin that captured gdb.execute before interception can
    # hide its child dispatch, though dynamic calls made by that child remain.
    assert execute_commands(nesting["captured_child"]) == [
        "pwnc-probe-captured-outer top",
        "set $pwnc_probe_nested = 33",
    ]
    assert nesting["nested_value"] == 33

    invoke_shapes = report["invoke_shapes"]
    assert isinstance(invoke_shapes, dict)
    assert invoke_shapes["generator_is_generator_function"] is True
    assert invoke_shapes["generator_error"] is None
    assert invoke_shapes["generator_body_started"] is False
    assert invoke_shapes["generator_body_resumed"] is False
    assert invoke_shapes["async_is_coroutine_function"] is True
    assert invoke_shapes["async_error"] is None
    assert invoke_shapes["async_body_started"] is False
    assert invoke_shapes["async_body_resumed"] is False
    assert any(
        warning["category"] == "RuntimeWarning"
        and "was never awaited" in warning["message"]
        for warning in invoke_shapes["async_warnings"]
    )

    replay = report["exception_replay"]
    assert isinstance(replay, dict)
    assert len(replay["errors"]) == 2
    assert all(error["type"] == "error" for error in replay["errors"])
    assert replay["outer_prefix_count"] == 2
    assert replay["inner_prefix_count"] == 2
    assert replay["outer_suffix_count"] == 0
    assert replay["inner_suffix_count"] == 0
    assert replay["catching_error"] is None
    assert replay["catching_exception"]["type"] == "PauseSignal"
    assert replay["catching_prefix_count"] == 1
    assert replay["catching_suffix_count"] == 1

    # All command bodies and wrapper calls in this batch experiment execute on
    # GDB's single Python/main thread, including every level of nesting.
    assert len(report["all_threads"]) == 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb", help="GDB executable to probe")
    parser.add_argument(
        "--mode",
        choices=("batch", "dap", "both"),
        default="both",
        help="entry path to exercise (default: both)",
    )
    parser.add_argument(
        "--json", action="store_true", help="print the complete JSON report"
    )
    args = parser.parse_args()

    probe = Path(__file__).with_name("execute_intercept_probe.py").resolve()
    modes = ("batch", "dap") if args.mode == "both" else (args.mode,)
    reports = {}
    try:
        for mode in modes:
            report = (
                run_batch(args.gdb, probe)
                if mode == "batch"
                else run_dap(args.gdb, probe)
            )
            check(report)
            reports[mode] = report
    except (EOFError, OSError, RuntimeError, AssertionError) as error:
        sys.stderr.write(f"FAIL: {error}\n")
        return 1

    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    else:
        versions = sorted({str(report["gdb_version"]) for report in reports.values()})
        print(
            "PASS: GDB "
            + ", ".join(versions)
            + " execute interception semantics matched expectations via "
            + ", ".join(reports)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
