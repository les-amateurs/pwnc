"""Optional real-GEF smoke test for dynamic ``gdb.execute`` interception."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

MARKER = "PWNC_EXECUTE_INTERCEPT_GEF_REPORT="
DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_GEF_SHA256 = (
    "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument(
        "--require", action="store_true", help="fail instead of skip if GEF is absent"
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    gef = args.gef.resolve()
    if not gef.is_file():
        message = f"GEF fixture is unavailable: {gef}"
        if args.require:
            sys.stderr.write("FAIL: " + message + "\n")
            return 1
        print("SKIP: " + message)
        return 0

    digest_before = hashlib.sha256(gef.read_bytes()).hexdigest()
    if digest_before != EXPECTED_GEF_SHA256:
        sys.stderr.write(
            "FAIL: the GEF fixture is not the agreed unmodified bata24 source: "
            f"expected {EXPECTED_GEF_SHA256}, got {digest_before}\n"
        )
        return 1

    probe = Path(__file__).with_name("execute_intercept_gef_probe.py").resolve()
    command = [
        args.gdb,
        "-q",
        "-nx",
        "-batch",
        "-ex",
        f"source {gef}",
        "-ex",
        f"source {probe}",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        return completed.returncode

    marked = [
        line.removeprefix(MARKER)
        for line in completed.stdout.splitlines()
        if line.startswith(MARKER)
    ]
    if len(marked) != 1:
        sys.stderr.write("FAIL: GEF probe did not emit exactly one report\n")
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        return 1

    report = json.loads(marked[0])
    commands = [
        event["command"] for event in report["events"] if event["kind"] == "enter"
    ]
    # This probe is intentionally reusable across the supported GDB 14--17
    # matrix; pinning the host's 15.1 version made valid cross-version runs
    # fail in the test harness rather than in GEF.
    assert report["gdb_version"], report["gdb_version"]
    assert report["error"] is None, report["error"]
    assert report["output_type"] == "str"
    assert commands[0] == "history -n"
    assert commands.count("show commands 0") >= 1
    assert all(
        event["depth"] == 1
        for event in report["events"]
        if event["kind"] == "enter" and event["command"] == "show commands 0"
    )
    assert len(report["threads"]) == 1

    digest = hashlib.sha256(gef.read_bytes()).hexdigest()
    assert digest == digest_before, "the GEF source changed during the probe"
    if args.json:
        print(
            json.dumps(
                {"gef_path": str(gef), "gef_sha256": digest, "report": report},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            f"PASS: GDB {report['gdb_version']} sourced GEF {digest}; "
            f"intercepted {commands!r} on one thread"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
