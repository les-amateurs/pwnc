# pwnc runtime viewer

`pwnc-runtime-viewer` is a standalone Linux C++20 Dear ImGui inspector for one
or more structured GDB runtime sessions. It does not embed Python and its
render loop does not run in GDB, Binary Ninja, or an exploit process. The only
cross-process representation is versioned JSON over a Unix-domain socket.

## Build

The reproducible build pins source commits and archive SHA-256 values in
[`deps.lock`](deps.lock). `fetch_deps.sh` downloads and verifies Dear ImGui,
SDL2, and nlohmann/json; the dependency tree and build products stay ignored.
SDL2 is linked statically, while the executable uses the host OpenGL/windowing
libraries.

On Debian-family systems, the practical prerequisites are a C++20 compiler,
GNU make, curl, tar, sha256sum, pkg-config, and OpenGL/X11 development files.
Then run:

```sh
make -C native/runtime_viewer -j2 all test
```

Useful targets are `deps`, `all`, `test`, `clean`, and `distclean`.
`PWNC_VIEWER_JOBS` controls the inner SDL build parallelism. The result is:

```text
native/runtime_viewer/build/pwnc-runtime-viewer
```

`make -C native/runtime_viewer install PREFIX=/usr/local` installs the binary,
schema, and dependency notices. `g.viewer.open()` checks the source-tree build,
then `$PATH`; `$PWNC_RUNTIME_VIEWER` is an exact executable override.

The copied third-party notices are in [`licenses/`](licenses/). They match the
license files from the exact pinned dependency sources.

## Run and connect

Run an independently managed viewer:

```sh
native/runtime_viewer/build/pwnc-runtime-viewer \
  --socket /tmp/pwnc-runtime-viewer.sock
```

Then, from any number of Python-controlled GDB sessions:

```python
g.viewer.connect("/tmp/pwnc-runtime-viewer.sock")
g.snapshot("initial", heap=g.heap.available)
```

With no `--socket`, the viewer uses `$PWNC_RUNTIME_VIEWER_SOCKET`, then
`$XDG_RUNTIME_DIR/pwnc-runtime-viewer-<uid>.sock`, then `/tmp`. The Python side
uses the same resolution. `g.viewer.open()` starts the bundled executable with
a private temporary socket and waits once on a readiness pipe before
connecting. The viewer is optional: constructing or using a headless `Gdb`
does not load or start native UI code.

Command-line test options are:

```text
--ready-fd FD
--headless --exit-after-snapshots N --model-out FILE
--exit-after-frames N
```

Headless mode uses the same socket server and retained C++ model, making it the
end-to-end protocol test surface. Its model output retains snapshots and their
same-index `diff_from_previous` entries in `snapshots` and `diffs`. A GUI smoke
test can run under Xvfb:

```sh
xvfb-run -a native/runtime_viewer/build/pwnc-runtime-viewer \
  --socket /tmp/pwnc-viewer-smoke.sock --exit-after-frames 1
```

## UI

The left pane selects a runtime session by its UUID and exact main-image
identity. Each session retains connection state, bounded events, and bounded
snapshots after disconnect or publisher failure. The main tabs provide:

- an event and snapshot timeline;
- loaded modules and mappings;
- per-thread registers, frames, scoped arguments/locals, and libc facts;
- marked typed memory, a clipped hexdump, and payload semantic spans;
- a zoomable/pannable, clipped heap-chunk canvas with state coloring and LOD;
- verification results; and
- an A/B semantic diff for modules, maps, threads, marks, heap arenas/chunks,
  and verification results.

Tables and timelines use `ImGuiListClipper`. The heap canvas rejects off-screen
chunks before drawing and emits text only above a useful pixel width.

## Wire protocol

The stream consists of newline-delimited UTF-8 JSON objects. Every envelope
contains:

```json
{
  "protocol": "pwnc-runtime",
  "version": 1,
  "type": "hello",
  "session_id": "a UUID",
  "session": {}
}
```

Message types are `hello`, `event`, `snapshot`, and `goodbye`. A connection
must send `hello` first, and the session ID inside its descriptor must match the
envelope. A reconnect keeps the same UUID and replays retained snapshots;
snapshot sequence numbers make replay idempotent. The maximum line is 16 MiB.
The normative shape is [`protocol-v1.schema.json`](protocol-v1.schema.json).

This protocol deliberately carries semantic runtime facts—not rendered text,
GDB handles, Python class tags, pickles, or bata24 command output. Python domain
objects have explicit `to_json()` adapters at this boundary. The C++ model is
renderer-independent, so another UI can consume the same schema without
linking Dear ImGui.

Protocol changes that break a v1 consumer require a new integer version and a
new schema. Additive optional fields may be introduced only when both parser
and schema remain compatible. The current native model rejects unknown
protocol versions, data before `hello`, mismatched session identity, malformed
snapshot sequences, and oversized input.

## Event-driven architecture and backpressure

There are no sleep or timed polling loops in the viewer path:

```text
GDB/DAP event -> bounded Python enqueue -> blocking sender
    -> AF_UNIX stream -> poll(..., -1) socket thread
    -> bounded native enqueue -> SDL_PushEvent
    -> SDL_WaitEvent UI thread -> one rendered frame
```

The Python DAP callback performs only the bounded enqueue. Serialization and
`sendall()` happen on its sender thread. Under pressure, events are discarded
before snapshots; connection-control messages survive, and the newest
snapshots replace older queued snapshots. The native ingress queue applies the
same priority. Retained C++ history is independently bounded to 4096 events and
128 snapshots per session by default.

The GUI does not continuously render while idle. The socket thread blocks in
`poll` with an infinite timeout and wakes the UI with a registered SDL event.
Headless mode blocks on a condition variable. Shutdown uses a wake pipe.

## Socket ownership

The listener:

- creates the socket with mode `0600` under umask `0077`;
- accepts only same-UID Linux peers using `SO_PEERCRED`;
- refuses to replace a non-socket, a foreign-owned path, or a live viewer;
- removes only a same-UID stale socket; and
- records the created inode/device and unlinks only that exact socket at exit.

The trust boundary is the local Unix account. An explicitly supplied shared
path should live in a directory other users cannot replace or traverse.

## Tests and performance

The native model test covers version and ordering validation, bounded retained
state, duplicate replay, disconnect state, and semantic diffs including heap
objects. Python integration tests cover event-driven publication, bounded
backpressure, reconnect, two simultaneous GDB sessions with different main
build IDs, and typed fields, payload annotations, snapshots, and Python-side
semantic diffs reaching the compiled C++ model.

Run the repeatable performance benchmark with:

```sh
uv run --with pwntools --with toml python tests/dap/benchmark_runtime.py
```

It measures idle native CPU ticks, cached/cold runtime facts, per-thread
capture, stop round trips, selective/full snapshots, native JSON delivery, and
a 10,000-mark semantic diff. Current results and the intentionally broad
regression ceilings are recorded in [`PERFORMANCE.md`](PERFORMANCE.md).
