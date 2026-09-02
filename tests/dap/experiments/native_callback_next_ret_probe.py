#!/usr/bin/env python3
"""Exercise unmodified Bata24 ``next-ret -n`` in a real host callback.

Unlike ``primary_cli_side_dap_probe.py``, this uses GDB's native DAP
interpreter.  It proves both compound plugin-command re-entrancy and pwnc's
ownership of the intermediate stop events emitted by Bata24's internal ``ni``
loop.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.fspath(REPOSITORY))
sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

from primary_cli_side_dap_probe import (  # noqa: E402
    DEFAULT_GEF,
    EXPECTED_GEF_SHA256,
    _write_fixture,
)
from pwnc.gdb.dap import launch  # noqa: E402


TIMEOUT = 30.0
CALLBACK_OPERATIONS = REPOSITORY / "tests/dap/fixtures/callback_operations.py"


class ProbeFailure(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_probe(gdb_path: str, gef_path: Path = DEFAULT_GEF) -> dict:
    resolved_gdb = shutil.which(gdb_path) if os.path.sep not in gdb_path else gdb_path
    if resolved_gdb is None or not os.access(resolved_gdb, os.X_OK):
        raise ProbeFailure("GDB is not executable: %s" % gdb_path)
    gef_path = gef_path.resolve()
    digest_before = _sha256(gef_path)
    if digest_before != EXPECTED_GEF_SHA256:
        raise ProbeFailure("unexpected Bata24 GEF SHA-256: %s" % digest_before)

    with tempfile.TemporaryDirectory(prefix="pwnc-native-callback-next-ret-") as temporary:
        root = Path(temporary)
        binary = _write_fixture(root)
        environment = dict(os.environ)
        environment.update(
            {
                "HOME": temporary,
                "TMPDIR": temporary,
                "TERM": "xterm-256color",
            }
        )
        controller = launch(
            binary,
            gdb_path=os.fspath(resolved_gdb),
            env=environment,
            init=False,
            headless=True,
        )
        callback_threads = []
        context_bytes = 0
        try:
            version = controller.execute("show version").splitlines()[0]
            for command in (
                "set pagination off",
                "set confirm off",
                "source " + os.fspath(gef_path),
                "gef config gef.disable_color True",
                'gef config context.layout "regs stack code"',
                "source " + os.fspath(CALLBACK_OPERATIONS),
            ):
                controller.execute(command, timeout=TIMEOUT)

            controller.bp("pwnc_marker_one")
            controller.bp("pwnc_marker_two")
            first = controller.cont(timeout=TIMEOUT)
            if first.get("reason") != "breakpoint":
                raise ProbeFailure("unexpected first stop: %r" % first)

            def next_ret_from_callback(depth: int, *, max_depth: int):
                nonlocal context_bytes
                if (depth, max_depth) != (0, 0):
                    raise ProbeFailure("unexpected callback arguments")
                callback_threads.append(threading.get_ident())
                output = controller.execute("next-ret -n", timeout=TIMEOUT)
                context_bytes = len(output.encode("utf-8", "replace"))
                lowered = output.lower()
                if not all(part in lowered for part in ("registers", "stack", "code")):
                    raise ProbeFailure("next-ret returned no GEF context")
                instruction = controller.execute("x/i $pc").lower()
                if "ret" not in instruction:
                    raise ProbeFailure("next-ret did not reach a return: %r" % instruction)
                return {"context": True, "nextRet": True}

            result = controller.run_operation(
                "pwnc.test.recursive",
                {"depth": 0, "max_depth": 0},
                callbacks={"pwnc.test.callback": next_ret_from_callback},
                timeout=TIMEOUT,
            )
            if result.get("value") != {"context": True, "nextRet": True}:
                raise ProbeFailure("callback operation returned an invalid result: %r" % result)

            queued_before_resume = controller._stops.qsize()
            discarded_before = controller._discarded_internal_stops
            second = controller.cont(timeout=TIMEOUT)
            discarded = controller._discarded_internal_stops - discarded_before
            if second.get("reason") != "breakpoint":
                raise ProbeFailure("post-callback continue consumed a stale stop: %r" % second)
            frame = controller.execute("frame")
            if "pwnc_marker_two" not in frame:
                raise ProbeFailure("post-callback frame is incoherent: %r" % frame)
            if discarded <= 0:
                raise ProbeFailure("next-ret produced no internal stops to classify")
            if len(callback_threads) != 1:
                raise ProbeFailure("callback did not run exactly once")
            callback_thread = callback_threads[0]
            transport_threads = {
                controller.transport.reader_thread_id,
                controller.transport.router_thread_id,
                controller.transport.writer_thread_id,
                controller.transport.event_thread_id,
            }
            if callback_thread in transport_threads:
                raise ProbeFailure("host callback captured a transport thread")

            return {
                "callbackContextBytes": context_bytes,
                "callbackThreadIsolated": True,
                "discardedInternalStops": discarded,
                "gdbVersion": version,
                "gefSha256": digest_before,
                "nativeDap": True,
                "nextRet": True,
                "postCallbackContinue": True,
                "postCallbackFrame": "pwnc_marker_two",
                "queuedBeforeResume": queued_before_resume,
            }
        finally:
            controller.close()
            if _sha256(gef_path) != digest_before:
                raise ProbeFailure("Bata24 GEF changed during the probe")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = run_probe(args.gdb, args.gef)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("PASS native DAP callback + Bata24 next-ret")
        for key in sorted(result):
            print("%s: %s" % (key, result[key]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
