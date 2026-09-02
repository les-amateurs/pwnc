# Runtime and viewer performance

These numbers are a local regression baseline, not a cross-machine service
guarantee. They were recorded on 2026-08-04 in the repository container on
x86-64 with Python 3.12.3, GDB DAP, an `-O0 -g3` non-PIE fixture, and the
release-optimized native viewer build.

| Operation | Samples | Median | p95 | Maximum |
|---|---:|---:|---:|---:|
| Cold runtime/module/map capture | 1 | 292.632 ms | 292.632 ms | 292.632 ms |
| Cached runtime export | 100 | 0.125 ms | 0.246 ms | 0.314 ms |
| Four-frame thread facts | 20 | 1.059 ms | 1.520 ms | 2.220 ms |
| Breakpoint stop round trip | 32 | 1.138 ms | 1.296 ms | 1.335 ms |
| Metadata-only selective snapshot | 30 | 0.007 ms | 0.015 ms | 0.047 ms |
| Four-frame full snapshot | 10 | 1.352 ms | 6.502 ms | 6.502 ms |

Additional results:

- 100 snapshots crossed the JSON/Unix-socket boundary and entered the compiled
  C++ retained model in 12.022 ms total, or 0.120 ms per snapshot.
- A semantic diff across 10,000 marked objects with 100 changed objects took
  74.466 ms.
- The disconnected Python runtime started zero viewer worker threads.
- The headless native viewer accumulated zero scheduler CPU ticks over a
  750 ms idle interval (`CLK_TCK=100`).

The cold runtime cost includes the initial GDB request, map/module discovery,
and local ELF inspection. Subsequent calls within the same stop generation use
the runtime cache, while parsed ELF profiles survive stop invalidation. The
breakpoint measurement is the complete continue-to-stop DAP round trip; stop
handling itself only invalidates a generation and appends one bounded event.

Explicit captures execute through GDB's request thread, as debugger state must.
The API does not perform them automatically on stops. Frame count, variable
enumeration, number of marked byte ranges, and requested heap work therefore
remain direct caller-controlled cost knobs. The publisher's serialization and
socket I/O run off the DAP callback thread.

## Repeat and regression ceilings

Run:

```sh
make -C native/runtime_viewer -j2 all test
uv run --with pwntools --with toml python tests/dap/benchmark_runtime.py
```

The benchmark emits JSON and fails only on wide ceilings intended to detect a
hang, accidentally uncached path, spin loop, or catastrophic complexity
regression:

| Check | Ceiling |
|---|---:|
| Cached runtime p95 | 10 ms |
| Thread facts p95 | 250 ms |
| Stop round trip p95 | 500 ms |
| Selective snapshot p95 | 100 ms |
| Full snapshot p95 | 500 ms |
| Viewer delivery | 50 ms/snapshot |
| 10,000-mark diff | 1,500 ms |
| Native idle CPU over 750 ms | 1 tick |
| Python viewer threads before connect | 0 |

These ceilings intentionally tolerate loaded CI hosts. Performance work should
compare the emitted distributions and not tune behavior merely to the ceiling.
