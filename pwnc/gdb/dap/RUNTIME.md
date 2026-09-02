# Structured GDB runtime and native inspector

The runtime API is the exploit-script-facing view of one stopped inferior. It
uses ordinary Python objects: modules have attributes and symbol tables,
registers support attribute access, typed memory is a `pwnc.types` value tree,
and snapshots have a real `diff()` method. JSON is not the scripting model. It
is produced only by explicit `to_json()` methods at the Unix-socket boundary to
the standalone C++ viewer.

## Runtime facts

Every `Gdb` has these views:

```python
g.main                         # exact main Module
g.libc                         # uniquely selected libc Module, or None
g.loader                       # dynamic loader Module, or None
g.modules                      # all loaded/map-backed Modules
g.maps                         # MemoryMap sequence
g.layout                       # immutable payloads.RuntimeLayout
g.arch                         # exact payloads.Target

g.main.sym.main                # relocated symbol address
g.libc.sym.system
g.main.got.puts
g.main.plt.puts
g.modules.at(g.reg.pc)
g.maps.require(g.reg.sp)
```

Runtime facts are cached for one stop generation. A stop, exit, or termination
invalidates that lightweight cache; ELF inspection is separately cached by
canonical path, mtime, and size. Modules prefer build-ID identity. When GDB or a
remote stub does not provide a build ID, the exact mapped artifact path is the
identity fallback. File-backed maps are merged with `gdb.objfiles()`, which is
important for QEMU-user sessions where GDB may not load symbols for every
mapped shared object.

Thread summaries are lazy. `capture()` performs one coherent GDB request for
the selected thread and returns normal immutable objects:

```python
facts = g.thread_facts(frames=8, libc=True)

facts.reg.pc                   # canonical aliases: pc, sp, fp, lr
facts.reg.rip                  # architecture-native names remain available
facts.top.name
facts.top.arguments
facts.top.locals
facts.top.variable("request")
facts.libc.tls
facts.libc.canary
facts.libc.errno
facts.libc.tcache
facts.libc.arena

for thread in g.thread_views:
    other = thread.capture(frames=4)
```

Arguments and locals come from the active DWARF lexical blocks. Each
`ScopedVariable` retains its scope depth, type spelling, availability,
optimized-out state, display value, address, and pointer value when relevant.
Optimized code and missing debug information naturally limit what GDB can
recover; unavailable values remain explicit instead of being guessed.

## Typed memory

Live views preserve the existing ergonomic `pwnc.types` API. Captures read the
entire range once, so every field comes from one coherent byte image:

```python
point = g.memory.view(g.main.sym.point, "struct Point")
print(int(point.x), int(point.y))
point.x = 0x1337

captured = g.memory.capture(g.main.sym.point, "struct Point")
assert captured.data == captured.value.bytes

point_mark = g.mark(captured.value, label="current point")
```

A typed mark records primitive leaf paths, offsets, types, values, displays,
and pointer values without following pointers. That purpose-built typed-memory
projection powers field-level snapshot diffs and the native typed inspector;
it is not a universal Python serializer.

## Heap facts and allocation identity

Heap analysis calls bata24's Python objects directly inside GDB. No formatted
GEF command output is parsed. The adapter is capability-checked and the test
lane verifies the pinned, unmodified bata24 source. Without bata24,
`g.heap.available` is false, `try_chunk()` returns `None`, and strict heap
queries raise `HeapUnavailableError`; every non-heap runtime feature continues
to work.

```python
if g.heap.available:
    chunk = g.heap.chunk(leaked_user_pointer)
    print(chunk.base, chunk.size, chunk.state, chunk.bins)
    victim = chunk.mark("victim")

    for arena in g.heap.arenas():
        print(arena.name, arena.top, arena.system_mem)
```

An allocation ID is `arena:chunk-base:generation`. A free-to-allocated reuse or
observed size change advances the generation, so a recycled address is not
conflated with the old object. Explicit heap queries emit allocation, free,
reuse, resize, and state-transition events when they observe a transition.
There is no automatic heap traversal on stops and no background heap polling.

## Marks and semantic payload writes

Marks are retained handles for ranges worth following:

```python
raw = g.mark(address, 0x80, "input buffer", tags=("network",))
typed = g.mark(g.sym.request, label="request")
chunk = g.heap.chunk(pointer).mark("unsorted victim")

raw.rename("decoded input").tag("parsed")
raw.capture()
raw.view()                       # typed marks only
```

Writing a `Payload`, `ROPChain`, lowered libc ROP, staged payload, or `FSOPWrite`
materializes the payload and returns a payload mark:

```python
placed = g.write(destination, chain)
assert placed.payload.description == chain.description
assert g.verify.mark(placed).require().ok
```

Payload marks preserve expected bytes, target architecture, provenance
metadata, word roles, pointer kinds, and expressions. Ordinary byte writes keep
the existing return behavior and still create a cheap `memory-write` history
event.

## Verification

Verification never invents the exploit-side answer. Every check requires the
caller to supply the value, identity, bytes, or state derived outside GDB:

```python
g.verify.base("libc", leaked_libc_base).require()
g.verify.leak(remote_puts, "libc", symbol="puts").require()
g.verify.symbol("main", "win", calculated_win).require()
g.verify.identity("libc", build_id=expected_build_id)
g.verify.memory(destination, expected_bytes).require()
g.verify.typed(address, "struct Point", {"x": 1, "y": 2}).require()
g.verify.heap(chunk, state="tcache", generation=0)
```

Results are retained in a bounded log and snapshots. Failures are history
events with kind `verification-failed` even when the caller does not invoke
`require()`; `require()` raises `VerificationError` with the complete result.

## Snapshots, history, and diffs

Snapshots are selective and named:

```python
before = g.snapshot(
    "before-trigger",
    frames=8,
    variables=True,
    libc=True,
    marks=[point_mark, victim],
    heap=True,
)

# interact with the target

after = g.snapshot("after-trigger", frames=8, heap=True)
delta = before.diff(after)
assert delta.changed
```

Capture switches are `modules`, `maps`, `threads`, `frames`, `variables`,
`libc`, `marks`, `heap`, and `verifications`. History retains 128 snapshots and
4096 cheap events by default. Diffs cover module and map lifecycle, threads,
registers, scoped variables and pointer values, byte ranges, typed fields,
payload/mark metadata, heap arenas, allocation-aware chunks and bins, and new
verification results.

## Standalone native viewer

The optional viewer is a separate C++20 Dear ImGui process. Headless pwnc use
does not start a thread, open a socket, import a GUI binding, or require the
native executable.

```python
# Spawn the bundled viewer, wait once on its readiness pipe, then connect.
g.viewer.open()

# Or connect to an independently managed multi-session viewer.
g.viewer.connect("/run/user/1000/pwnc-runtime.sock")

g.snapshot("parsed request", heap=True)
print(g.viewer.stats)

g.viewer.disconnect()
g.viewer.reconnect()             # same session ID; retained snapshots replay
g.viewer.stop_viewer()           # only terminates a process opened by this Gdb
```

The publisher sends versioned NDJSON over an AF_UNIX stream. Its bounded queue
drops events first, retains control messages and the newest snapshots, and
serializes on a dedicated sender thread. The DAP event callback only appends a
small object to the bounded queue. A disconnected sender blocks on an event;
the native socket thread blocks in `poll(..., -1)`; the GUI blocks in
`SDL_WaitEvent`. There are no retry sleeps, timer polling loops, or continuous
render loop. Multiple publishers are keyed by UUID plus exact main identity,
and the viewer retains their bounded histories after disconnect or crash.

See [the native viewer README](../../../native/runtime_viewer/README.md) for
the build, UI, transport, and extension contract. The wire format is
[`protocol-v1.schema.json`](../../../native/runtime_viewer/protocol-v1.schema.json).

## Compatibility and cost model

The tested core matrix is x86-64, i386, ARM/AArch32, and AArch64, including
native and QEMU-user sessions, PIE/non-PIE images, exact remote libc routing,
and multiple concurrent viewer sessions. Endianness and word size come from
GDB and resolve to an exact `payloads.Target`.

Stop handling itself only advances a generation and appends a bounded event on
the host; it does not ask GDB for maps, frames, variables, or heap state. Calls
such as `thread_facts()` and `snapshot()` are explicit synchronous captures and
therefore occupy GDB's request thread for the requested work. Keep frame counts
and selected marks proportional to what the script needs. The current measured
numbers and repeatable regression ceilings are in
[`native/runtime_viewer/PERFORMANCE.md`](../../../native/runtime_viewer/PERFORMANCE.md).

## Extension rules

- Add scripting behavior as a normal domain class or method first.
- Add an explicit `to_json()` projection only when the native viewer needs it.
- Evolve the wire format by adding a new protocol version and schema; do not
  send Python pickles, class tags, debugger handles, or formatted CLI text.
- Keep provider calls structured and capability-tested. A missing optional
  provider must produce an unavailable fact or domain error, not disable the
  rest of the runtime.
- Keep stop listeners constant-time. Expensive capture belongs behind an
  explicit method or snapshot option.
