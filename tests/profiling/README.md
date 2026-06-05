# pwnc startup profiling

This directory keeps the profiling harness for checking CLI startup time and
library import cost.

Run the baseline profiler from the repository root:

```sh
python3 tests/profiling/profile_pwnc_startup.py
```

Useful options:

```sh
python3 tests/profiling/profile_pwnc_startup.py --iterations 50
python3 tests/profiling/profile_pwnc_startup.py --output-dir tests/profiling/results/after-change
python3 tests/profiling/profile_pwnc_startup.py -- ./bin/pwnc --help
```

The default command is equivalent to:

```sh
python3 bin/pwncli.py --help
```

Generated artifacts are written under `tests/profiling/results/latest/` by
default:

- `summary.md`: human-readable timing and import summary.
- `startup_timing.json`: raw timing samples and command metadata.
- `importtime.log`: raw `python -X importtime` output.
- `importtime_top.txt`: slowest imports by cumulative and self time.
- `startup.cprofile`: raw cProfile data.
- `cprofile_top.txt`: top cProfile entries sorted by cumulative time.
- `command_stdout.txt` / `command_stderr.txt`: captured output from a timed run.
