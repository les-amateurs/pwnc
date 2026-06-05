#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import os
import pstats
import re
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


IMPORTTIME_RE = re.compile(r"^import time:\s+(\d+)\s+\|\s+(\d+)\s+\|\s+(.*)$")


@dataclass(frozen=True)
class ImportRecord:
    self_us: int
    cumulative_us: int
    module: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_command(root: Path) -> list[str]:
    return [sys.executable, str(root / "bin" / "pwncli.py"), "--help"]


def command_env(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(root) if not pythonpath else f"{root}{os.pathsep}{pythonpath}"
    return env


def run_command(command: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        env=command_env(root),
        text=True,
        capture_output=True,
        check=False,
    )


def time_startup(command: list[str], root: Path, warmups: int, iterations: int) -> tuple[list[float], subprocess.CompletedProcess[str]]:
    last = run_command(command, root)
    if last.returncode != 0:
        return [], last

    for _ in range(warmups):
        last = run_command(command, root)
        if last.returncode != 0:
            return [], last

    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        last = run_command(command, root)
        elapsed = time.perf_counter() - start
        if last.returncode != 0:
            return samples, last
        samples.append(elapsed)

    return samples, last


def percentile(samples: list[float], percent: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    index = round((len(ordered) - 1) * percent)
    return ordered[index]


def timing_summary(samples: list[float]) -> dict[str, float | int]:
    if not samples:
        return {"iterations": 0}
    return {
        "iterations": len(samples),
        "min_ms": min(samples) * 1000,
        "mean_ms": statistics.fmean(samples) * 1000,
        "median_ms": statistics.median(samples) * 1000,
        "p90_ms": percentile(samples, 0.90) * 1000,
        "max_ms": max(samples) * 1000,
        "stdev_ms": statistics.stdev(samples) * 1000 if len(samples) > 1 else 0.0,
    }


def run_importtime(command: list[str], root: Path, output: Path) -> list[ImportRecord]:
    if command[0] != sys.executable:
        raise ValueError("import-time profiling needs the command to use this Python interpreter")

    profiled = [sys.executable, "-X", "importtime", *command[1:]]
    result = run_command(profiled, root)
    output.write_text(result.stderr, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(f"import-time command failed with exit code {result.returncode}")

    records = []
    for line in result.stderr.splitlines():
        match = IMPORTTIME_RE.match(line)
        if not match:
            continue
        self_us, cumulative_us, module = match.groups()
        records.append(
            ImportRecord(
                self_us=int(self_us),
                cumulative_us=int(cumulative_us),
                module=module.strip(),
            )
        )
    return records


def write_importtime_top(records: list[ImportRecord], output: Path, limit: int) -> None:
    lines = ["Slowest imports by cumulative time", ""]
    for record in sorted(records, key=lambda item: item.cumulative_us, reverse=True)[:limit]:
        lines.append(f"{record.cumulative_us / 1000:9.3f} ms cumulative  {record.self_us / 1000:9.3f} ms self  {record.module}")

    lines.extend(["", "Slowest imports by self time", ""])
    for record in sorted(records, key=lambda item: item.self_us, reverse=True)[:limit]:
        lines.append(f"{record.self_us / 1000:9.3f} ms self        {record.cumulative_us / 1000:9.3f} ms cumulative  {record.module}")

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_cprofile(command: list[str], root: Path, profile_output: Path, text_output: Path, limit: int) -> None:
    if command[0] != sys.executable:
        raise ValueError("cProfile profiling needs the command to use this Python interpreter")

    profiled = [sys.executable, "-m", "cProfile", "-o", str(profile_output), *command[1:]]
    result = run_command(profiled, root)
    if result.returncode != 0:
        raise RuntimeError(f"cProfile command failed with exit code {result.returncode}")

    stream = io.StringIO()
    stats = pstats.Stats(str(profile_output), stream=stream)
    stats.strip_dirs().sort_stats("cumulative").print_stats(limit)
    text_output.write_text(stream.getvalue(), encoding="utf-8")


def format_ms(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.2f} ms"


def write_summary(
    output: Path,
    command: list[str],
    timing: dict[str, float | int],
    records: list[ImportRecord],
    top_limit: int,
) -> None:
    cumulative = sorted(records, key=lambda item: item.cumulative_us, reverse=True)[:top_limit]
    self_time = sorted(records, key=lambda item: item.self_us, reverse=True)[:top_limit]

    lines = [
        "# pwnc startup profile",
        "",
        f"- generated_at: {datetime.now(timezone.utc).isoformat()}",
        f"- command: `{' '.join(command)}`",
        f"- iterations: {timing.get('iterations', 0)}",
        f"- min: {format_ms(timing.get('min_ms'))}",
        f"- mean: {format_ms(timing.get('mean_ms'))}",
        f"- median: {format_ms(timing.get('median_ms'))}",
        f"- p90: {format_ms(timing.get('p90_ms'))}",
        f"- max: {format_ms(timing.get('max_ms'))}",
        f"- stdev: {format_ms(timing.get('stdev_ms'))}",
        "",
        "## Slowest imports by cumulative time",
        "",
        "| cumulative | self | module |",
        "| ---: | ---: | --- |",
    ]
    for record in cumulative:
        lines.append(f"| {record.cumulative_us / 1000:.3f} ms | {record.self_us / 1000:.3f} ms | `{record.module}` |")

    lines.extend(
        [
            "",
            "## Slowest imports by self time",
            "",
            "| self | cumulative | module |",
            "| ---: | ---: | --- |",
        ]
    )
    for record in self_time:
        lines.append(f"| {record.self_us / 1000:.3f} ms | {record.cumulative_us / 1000:.3f} ms | `{record.module}` |")

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Profile pwnc CLI startup and imports.")
    parser.add_argument("--iterations", type=int, default=20, help="timed startup runs")
    parser.add_argument("--warmups", type=int, default=5, help="untimed warmup runs before measurement")
    parser.add_argument("--top", type=int, default=25, help="number of slow imports/profile entries to report")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=repo_root() / "tests" / "profiling" / "results" / "latest",
        help="directory for generated profiling artifacts",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="optional command after --; defaults to this interpreter running bin/pwncli.py --help",
    )
    return parser.parse_args()


def normalize_command(args: argparse.Namespace, root: Path) -> list[str]:
    if not args.command:
        return default_command(root)
    if args.command[0] == "--":
        return args.command[1:]
    return args.command


def python_profile_command(command: list[str], root: Path) -> list[str]:
    executable = command[0]
    args = command[1:]
    if executable == sys.executable:
        return command

    resolved = None
    if os.sep in executable:
        resolved = (root / executable).resolve() if not Path(executable).is_absolute() else Path(executable).resolve()

    local_wrappers = {
        (root / "bin" / "pwnc").resolve(),
        (root / "bin" / "pwncli.py").resolve(),
    }
    if executable == "pwnc" or resolved in local_wrappers:
        return [sys.executable, str(root / "bin" / "pwncli.py"), *args]

    raise ValueError(
        "import-time and cProfile profiling need a Python script command; "
        "use the default command or pass `-- python3 bin/pwncli.py --help`"
    )


def main() -> int:
    args = parse_args()
    root = repo_root()
    command = normalize_command(args, root)
    profiled_command = python_profile_command(command, root)
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    samples, last = time_startup(command, root, args.warmups, args.iterations)
    (output_dir / "command_stdout.txt").write_text(last.stdout, encoding="utf-8")
    (output_dir / "command_stderr.txt").write_text(last.stderr, encoding="utf-8")
    if last.returncode != 0:
        print(f"startup command failed with exit code {last.returncode}", file=sys.stderr)
        return last.returncode

    timing = timing_summary(samples)
    (output_dir / "startup_timing.json").write_text(
        json.dumps(
            {
                "command": command,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "warmups": args.warmups,
                "samples_ms": [sample * 1000 for sample in samples],
                "summary": timing,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    records = run_importtime(profiled_command, root, output_dir / "importtime.log")
    write_importtime_top(records, output_dir / "importtime_top.txt", args.top)
    run_cprofile(profiled_command, root, output_dir / "startup.cprofile", output_dir / "cprofile_top.txt", args.top)
    write_summary(output_dir / "summary.md", command, timing, records, 10)

    print(f"Wrote profiling artifacts to {output_dir}")
    print(f"Mean startup: {format_ms(timing.get('mean_ms'))}; median: {format_ms(timing.get('median_ms'))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
