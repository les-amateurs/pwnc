"""Repeatable runtime/viewer performance benchmark.

This is a benchmark executable rather than a pytest test so ordinary test runs
do not encode host-speed assumptions.  It exits nonzero only for deliberately
wide regression ceilings and prints machine-readable JSON.
"""

from __future__ import annotations

import json
import math
import os
import select
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import MappingProxyType

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import CapturedMark, MarkKind, RuntimeSnapshot, launch
from pwnc.gdb.dap.inspector import RuntimeViewer


ROOT = Path(__file__).parents[2]
VIEWER = ROOT / "native" / "runtime_viewer" / "build" / "pwnc-runtime-viewer"
SOURCE = r"""
#include <stdint.h>

volatile uint64_t benchmark_word = 0x1020304050607080ULL;

__attribute__((noinline)) void benchmark_marker(unsigned iteration) {
    volatile uint64_t scoped = benchmark_word + iteration;
    __asm__ volatile("" : "+r"(scoped) :: "memory");
}

int main(void) {
    for (unsigned iteration = 0; iteration < 96; ++iteration)
        benchmark_marker(iteration);
    return 0;
}
"""


def _measure(operation, count: int) -> list[float]:
    values = []
    for _ in range(count):
        started = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - started) / 1_000_000.0)
    return values


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)]
    return {
        "count": len(values),
        "mean_ms": statistics.fmean(values),
        "p50_ms": statistics.median(values),
        "p95_ms": p95,
        "max_ms": max(values),
    }


def _empty_snapshot(sequence: int, *, marks=()) -> RuntimeSnapshot:
    return RuntimeSnapshot(
        sequence,
        f"benchmark-{sequence}",
        time.time_ns(),
        0,
        (),
        (),
        (),
        tuple(marks),
        (),
        (),
        (),
        MappingProxyType({}),
    )


class _EmptyHistory:
    def __iter__(self):
        return iter(())

    def subscribe(self, _listener):
        return lambda: None


class _SyntheticRuntime:
    history = _EmptyHistory()
    main = None

    @staticmethod
    def _info():
        return {
            "inferior": {"number": 1, "pid": os.getpid()},
            "architecture": "synthetic",
            "bata24": {"available": False},
        }


def _start_headless(path: Path, snapshots: int, model_path: Path):
    ready_read, ready_write = os.pipe()
    process = subprocess.Popen(
        [
            VIEWER,
            "--headless",
            "--socket",
            path,
            "--ready-fd",
            str(ready_write),
            "--exit-after-snapshots",
            str(snapshots),
            "--model-out",
            model_path,
        ],
        pass_fds=(ready_write,),
    )
    os.close(ready_write)
    try:
        if not select.select([ready_read], [], [], 10.0)[0] or os.read(ready_read, 1) != b"R":
            raise RuntimeError("native viewer did not become ready")
    finally:
        os.close(ready_read)
    return process


def _viewer_idle_cpu_ticks(directory: Path) -> int:
    process = _start_headless(directory / "idle.sock", 1, directory / "idle.json")
    try:
        fields = Path(f"/proc/{process.pid}/stat").read_text(encoding="ascii").split()
        before = int(fields[13]) + int(fields[14])
        select.select([], [], [], 0.75)
        fields = Path(f"/proc/{process.pid}/stat").read_text(encoding="ascii").split()
        return int(fields[13]) + int(fields[14]) - before
    finally:
        process.terminate()
        process.wait(10.0)


def _delivery(directory: Path, count: int = 100) -> dict[str, float]:
    process = _start_headless(directory / "delivery.sock", count, directory / "delivery.json")
    publisher = RuntimeViewer(_SyntheticRuntime())
    try:
        publisher.connect(directory / "delivery.sock", capture=False)
        started = time.perf_counter_ns()
        for sequence in range(count):
            publisher.publish(_empty_snapshot(sequence))
        assert process.wait(20.0) == 0
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        model = json.loads((directory / "delivery.json").read_text(encoding="utf-8"))
        assert len(model["sessions"][0]["snapshots"]) == count
        return {"count": count, "total_ms": elapsed_ms, "per_snapshot_ms": elapsed_ms / count}
    finally:
        publisher.close()
        if process.poll() is None:
            process.terminate()
            process.wait(10.0)


def _large_diff(count: int = 10_000) -> dict[str, float | int]:
    before_marks = []
    after_marks = []
    for index in range(count):
        initial = index.to_bytes(8, "little")
        changed = (index + 1).to_bytes(8, "little") if index % 100 == 0 else initial
        arguments = (f"m{index}", f"mark-{index}", MarkKind.MEMORY, 0x100000 + index * 8, 8)
        before_marks.append(CapturedMark(*arguments, initial, None, None, None, None, None))
        after_marks.append(CapturedMark(*arguments, changed, None, None, None, None, None))
    before = _empty_snapshot(0, marks=before_marks)
    after = _empty_snapshot(1, marks=after_marks)
    started = time.perf_counter_ns()
    difference = before.diff(after)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    assert len(difference.marks_changed) == count // 100
    return {"marks": count, "changed_marks": len(difference.marks_changed), "total_ms": elapsed_ms}


def main() -> int:
    if shutil.which("gcc") is None or shutil.which("gdb") is None:
        raise RuntimeError("gcc and GDB 14+ are required")
    if not os.access(VIEWER, os.X_OK):
        raise RuntimeError("build native/runtime_viewer before benchmarking")

    with tempfile.TemporaryDirectory(prefix="pwnc-runtime-benchmark-") as temporary:
        directory = Path(temporary)
        source = directory / "benchmark.c"
        binary = directory / "benchmark"
        source.write_text(SOURCE, encoding="utf-8")
        subprocess.run(
            ["gcc", "-g3", "-O0", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-o", binary, source],
            check=True,
            capture_output=True,
        )

        gdb = launch(binary, init=False)
        try:
            idle_threads = int(gdb.viewer._worker is not None)
            cold = _measure(gdb.runtime.to_json, 1)
            warm = _measure(gdb.runtime.to_json, 100)
            facts = _measure(lambda: gdb.thread_facts(frames=4, libc=False), 20)
            gdb.bp("benchmark_marker")
            stops = _measure(lambda: gdb.cont(timeout=10.0), 32)
            selective = _measure(
                lambda: gdb.snapshot(modules=False, maps=False, threads=False, marks=False, verifications=False),
                30,
            )
            full = _measure(lambda: gdb.snapshot(frames=4, libc=False), 10)
        finally:
            gdb.close()

        report = {
            "schema_version": 1,
            "platform": os.uname().machine,
            "python": sys.version.split()[0],
            "idle": {
                "python_viewer_threads_before_connect": idle_threads,
                "native_headless_cpu_ticks_over_750ms": _viewer_idle_cpu_ticks(directory),
                "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            },
            "runtime_info_cold": _summary(cold),
            "runtime_info_cached": _summary(warm),
            "thread_facts": _summary(facts),
            "breakpoint_stop_roundtrip": _summary(stops),
            "selective_snapshot": _summary(selective),
            "full_snapshot": _summary(full),
            "viewer_delivery": _delivery(directory),
            "large_history_diff": _large_diff(),
        }

    ceilings = {
        "runtime_info_cached.p95_ms": (report["runtime_info_cached"]["p95_ms"], 10.0),
        "thread_facts.p95_ms": (report["thread_facts"]["p95_ms"], 250.0),
        "breakpoint_stop_roundtrip.p95_ms": (report["breakpoint_stop_roundtrip"]["p95_ms"], 500.0),
        "selective_snapshot.p95_ms": (report["selective_snapshot"]["p95_ms"], 100.0),
        "full_snapshot.p95_ms": (report["full_snapshot"]["p95_ms"], 500.0),
        "viewer_delivery.per_snapshot_ms": (report["viewer_delivery"]["per_snapshot_ms"], 50.0),
        "large_history_diff.total_ms": (report["large_history_diff"]["total_ms"], 1500.0),
        "idle.native_ticks": (report["idle"]["native_headless_cpu_ticks_over_750ms"], 1.0),
        "idle.python_threads": (report["idle"]["python_viewer_threads_before_connect"], 0.0),
    }
    failures = {
        name: {"observed": observed, "ceiling": ceiling}
        for name, (observed, ceiling) in ceilings.items()
        if observed > ceiling
    }
    report["ceilings"] = {name: ceiling for name, (_observed, ceiling) in ceilings.items()}
    report["failures"] = failures
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
