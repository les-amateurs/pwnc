# pwnc.gdb.dap — drive gdb from python over DAP

A reimplementation of `pwnc.gdb.mi` built on gdb's native **Debug Adapter
Protocol** interpreter (`gdb --interpreter=dap`, GDB 14+). Native DAP provides
the control plane (run/step/break, memory, registers, stacks) over one framed,
request-id-correlated JSON channel; a small in-gdb extension adds the pieces DAP
omits — most importantly structural `gdb.Type` layout — which the client
reconstructs into typed `pwnc.types` Values.

## Why DAP instead of MI

The mi bridge tunneled a base64-pickle RPC through gdb's *console stream* and
scraped a marker out of it, over a shared racy buffer with a lost-wakeup stop
model, an `id()`-keyed object store, and pickle across a trust boundary. gdb's
DAP server already is the robust version of that: framed JSON-RPC, `seq`
correlation, gdb-thread marshalling, event-driven stops, cancellation, and
handles scoped to the stop. We keep mi's ergonomics and inherit that.

## Usage

```python
from pwnc.gdb.dap import debug

g = debug("./binary")          # gdbserver + tube for clean IO; gdb attaches over DAP
g.bp("main")
stop = g.run()                 # run/cont/stepi/... resume AND wait; return the stop dict

g.sym.counter                  # typed pwnc.types Value over live memory
g.sym.origin.x                 # struct fields, bitfields, pointers, arrays
g.reg.rip; g.reg.rip = 0x401000
g.read(addr, 64); g.write(addr, b"\x90")
g.stepi(); g.nexti(); g.skip(); stop = g.cont()

bp = g.bp("update_origin", callback=lambda g: print(int(g.sym.counter)))
stop = g.cont()                # callback runs each hit; return False to stop

# async control: resume without waiting, break in, then collect the stop
g.cont_nowait()
g.interrupt()
stop = g.wait()

g.close()
```

`attach(pid_or_name)` attaches to a running process.

### Structured runtime and ImGui inspector

Every session also exposes ergonomic modules/maps, per-thread facts, coherent
typed memory, direct bata24 heap facts, allocation-aware marks, verification,
named snapshots, semantic diffs, and an optional standalone C++ Dear ImGui
viewer. User-authored Python remains normal object-oriented Python; JSON exists
only at the viewer's Unix-socket boundary.

```python
print(g.main.sym.main, g.libc.sym.system, g.arch)
facts = g.thread_facts(frames=8)
request = g.mark(g.sym.request, label="request")
before = g.snapshot("before", marks=[request])

g.sym.request.length = 0x400
after = g.snapshot("after", marks=[request])
print(before.diff(after).marks_changed)

g.viewer.open()                    # optional separate native process
g.snapshot("viewer state", heap=g.heap.available)
```

See [RUNTIME.md](RUNTIME.md) for the complete scripting API, performance and
threading model, architecture matrix, viewer lifecycle, and extension rules.

### Foreign Linux ELFs and qemu-user

`debug()` and `launch()` inspect ELF metadata with pwntools. On a foreign
architecture they select the matching `qemu-ARCH`, start its GDB stub on a
private mode-0700 Unix-socket directory, and use `gdb-multiarch` automatically
when the convenience constructors still have their default `gdb_path`. Both
constructors return while the guest is stopped before its first instruction;
QEMU's stdin/stdout remain available through the ordinary `g.target` pwntools
tube. The native `launch()` behavior remains unchanged and stops at `main` by
default.

```python
from pwnc.gdb.dap import debug

g = debug(
    "./aarch64-challenge",
    "argument with spaces",
    env={"FLAG_PATH": "/flag"},
    sysroot="./sysroots/aarch64",
    qemu_aslr=False,             # stable guest PIE/libs/stack/heap layout
    host_aslr=True,              # independent host process setting
)
assert g.target is not None
g.run()
print(g.target.recvall())
```

`qemu="/path/to/qemu-aarch64"` overrides emulator discovery. `sysroot` is
passed to QEMU and is reapplied to GDB after remote target creation, together
with the inferred shared-library search path. The executable is selected before
attach, then a PIE is verified against the stopped guest and reloaded at the
exact bias from QEMU's RSP `qOffsets` reply. A missing or inconsistent bias is
an attach error, never a silent link-time-symbol fallback. The verified facts
are available as `g.qemu_user_relocation`.

Remote image verification first compares the exact mapped ELF and program
header layout. When an immutable file-backed GNU build-ID note is present, its
complete note record is compared and `qemu_user_relocation["identity"]` is
`"gnu-build-id+immutable-load-segments"`. Every byte of every non-writable
file-backed `PT_LOAD` is also mandatory, including at least one executable
segment, with a 64 MiB safety cap. A build-ID-less ELF reports
`"immutable-load-segments"` for that same comparison. Malformed notes or
dynamic metadata, text relocations, writable-executable loads, unreadable
ranges, and over-limit images fail closed. Immutable-load identity proves the
mapped code/read-only content needed for symbol rebasing, not full-file
identity; ordinary writable initial-data differences are outside its evidence.
Both modes use only the stopped guest through RSP and never host `/proc`
mappings.

`qemu_aslr=False` selects a fixed guest reservation and stabilizes the
guest-visible PIE, shared-library, heap, and stack mappings; host QEMU mappings
are deliberately irrelevant. `qemu_aslr=True` chooses a fresh randomized guest
reservation, while `None` preserves upstream QEMU behavior. `host_aslr`
independently controls the host process that runs the inferior (QEMU for a
foreign ELF, the native inferior otherwise). The instance methods on a prepared
`Gdb` accept the same keywords. For a manually managed stub, `connect()` also
accepts explicit `sysroot=` and `solib_search_path=`; pass `qemu_user=True` to
enable the same mandatory PIE verification and rebasing.

The shared layout planner refuses to pretend an ineffective knob is ASLR.
In particular, `qemu-x86_64` cannot use a nonzero `-R` reservation around its
fixed vsyscall page, so either explicit ASLR value raises `GuestLayoutError` for
that emulator; use `qemu_aslr=None` there. On `qemu-i386`, a fixed reservation
does stabilize all four mapping classes, but randomized reservations provide
only partial variance because QEMU retains fixed guest PIE/heap placement.
Tests cover fixed-layout equality with a real dynamically linked glibc process
and keep host ASLR varied independently.

### Prepared GDBs and a persistent viewer pool

`start()` initializes GDB and the pwnc extension without selecting a target.
The returned session is `GdbState.PREPARED`; it may be configured first and
then bound exactly once with the instance `attach()`, `connect()`, `launch()`,
or `debug()` method:

```python
from pwnc.gdb.dap import ConsoleConfig, GdbState, start

g = start(console=ConsoleConfig.owned())
assert g.state is GdbState.PREPARED
g.execute("source /opt/gef/gef.py")
g.execute("set pagination off")
g.launch("./challenge")
```

GDB loads its normal system and user initialization files by default, including
`~/.gdbinit`. Pass `init=False` to `start()`, `debug()`, `attach()`, or
`launch()` for deterministic `-nx` startup. Pools expose the same choice as
`GdbPool(init=False, ...)`; their `setup` callback still runs afterwards, once
per prepared GDB. If a setup callback explicitly sources `~/.gdbinit`, select
`init=False` to avoid loading it twice.

`GdbPool` keeps targetless, fully configured GDBs warm and places one durable
viewer in front of them. `size` is the number of ready spares, in addition to
the GDB currently displayed. One serial spawn lane runs the synchronous
`setup` hook exactly once per GDB, after GDB and its owned PTY are initialized.
The hook must return with the GDB still targetless and its endpoint alive and
unleased before that GDB can be published:

```python
from pwnc.gdb.dap import (
    ArgvTerminalLauncher,
    GdbPool,
    ViewerConfig,
)

def configure(gdb):
    gdb.execute("source /path/to/gef.py")
    gdb.execute("set pagination off")

pool = GdbPool(size=2, setup=configure).start(timeout=30)
viewer = pool.console(
    ViewerConfig.external(
        ArgvTerminalLauncher(["xterm", "-e", "{command}"]),
        reconnect=True,
    ),
    timeout=30,
)

selection = viewer.selection
selection.gdb.launch("./challenge")

# If that GDB process exits, the same terminal and bridge process switch to a
# prepared replacement. Bind the new target from the host when desired.
selection = viewer.wait_changed(selection.generation, timeout=None)
selection.gdb.launch("./challenge")

viewer.close()
pool.close()
```

The pool manager and terminal viewer may instead be independent programs.
`serve()` publishes the pool listener and returns without waiting for a viewer;
the first compatible viewer selects a prepared GDB. The same socket keeps its
selected endpoint across an ordinary viewer disconnect/reconnect, and if that
GDB dies while no viewer is attached, its warm replacement is preserved until a
fresh viewer connects:

```python
# manager.py
from pwnc.gdb.dap import GdbPool

def configure(gdb):
    gdb.execute("source /path/to/gef.py")

pool = GdbPool(size=2, setup=configure).start(timeout=30)
console = pool.serve(name="default", timeout=30)
print(console.socket_path)       # useful as a manual fallback

selection = console.wait_selected(timeout=None)  # waits for `pwnc gdb view`
selection.gdb.launch("./challenge")
```

```sh
# A separate process, from the same project tree:
pwnc gdb view

# Explicit fallbacks do not require or touch pwnc.toml:
pwnc gdb view --socket /path/to/pool.sock
pwnc gdb view --config /path/to/project/pwnc.toml --name default
pwnc gdb view --tty /dev/pts/12

# Opt into keeping this viewer alive across selected-GDB exits:
pwnc gdb view --reconnect
```

The equivalent blocking Python entry point is `pwnc.gdb.dap.view()`.  It
supervises the actual terminal bridge, so killing that child still restores the
terminal's termios and blocking flags.  `SIGINT`, `SIGTERM`, and `SIGHUP` sent to
the supervisor are forwarded and also take the restoration path.  On Linux the
bridge also arms a parent-death signal, so even `SIGKILL` of the supervisor makes
the bridge exit through its own restoration block instead of becoming orphaned.

Lookup failures raise `PoolDiscoveryError`; a resolved path which is missing or
is not a Unix socket raises `PoolConnectionError` before terminal state changes.
Both errors identify the pool, resolution source, and path and retain the
low-level exception as `__cause__`. The CLI prints the same contextual diagnosis
without a traceback or a bare errno. A connect-time race or stale socket is
reported by the bridge with the endpoint and a start/restart/check-path hint.

Pool discovery is deliberately lazy.  Importing the DAP package and unrelated
commands do not require a project config.  The first manager-side `serve()`
without an explicit socket finds the nearest `pwnc.toml` (or creates one in the
current directory) and atomically persists a random 128-bit `[pwnc].seed`
immediately, rather than deferring creation to process exit.  Viewer discovery
is read-only and requires that existing file.  Both sides hash the canonical
config path, seed, logical pool name, and discovery version to derive the same
Unix-socket name.  Consequently copying a config to another path does not make
the two projects collide.

Derived sockets and seed locks live under the deterministic per-user directory
`/tmp/pwnc-<uid>`; they deliberately do not depend on `XDG_RUNTIME_DIR`, so a
service and terminal with different environments still converge.  The directory
is mode `0700`; socket and lease files are mode `0600`.  The seed is a stable
identifier, not a secret or authentication credential: access to the unique
socket path in that private directory is the trust boundary.  For a manually
chosen stable address, use:

```toml
[gdb.pool]
socket = ".pwnc-gdb.sock"  # relative to this pwnc.toml
```

An API-level `socket_path=`/CLI `--socket` is a complete override and bypasses
config discovery.  The manager holds an exclusive namespace lease for its
lifetime, rejects a second live manager, and removes only the exact socket inode
it created.  For derived addresses, different `name=`/`--name` values identify
independent pools in the same project; one manually configured socket is an exact
address and therefore overrides name-based derivation.

The durable viewer has three display modes. `ViewerConfig.current()` inherits
the caller's current terminal, `ViewerConfig.target("/dev/pts/12")` (or a TTY
fd) attaches the bridge directly to an existing terminal, and
`ViewerConfig.external(...)` asks a shell-free custom launcher to create or
select the terminal. Target mode does not invoke a terminal emulator or shell;
the supplied path/fd is privately opened or duplicated, verified as a TTY, and
its terminal state is restored when the bridge exits or is killed. Resize
tracking is event driven: the bridge/watcher receives kernel `SIGWINCH` by
joining a same-session foreground group or claiming an otherwise unowned PTY.
Pwnc never steals a controlling terminal from an unrelated session; for that
case the initial size is still honored, and the terminal owner must relay
`SIGWINCH` to the viewer bridge (or to the host for a directly borrowed
console) after later resizes. There is no timed geometry scan fallback.

Automatic failover is opt-in through `ViewerConfig.*(reconnect=True)`,
`view(reconnect=True)`, or `pwnc gdb view --reconnect`. Without it, actual DAP
transport termination closes that viewer and preserves the pool listener and
warm spare for a newly launched viewer. `keep_open` is independent: it only
holds the terminal open after the bridge closes and never enables failover.

Neither mode inspects terminal bytes or treats a literal `^C` as process death.
If only the console routing endpoint disappears while DAP remains live, the
view reports `viewer.error` and preserves that GDB instead of silently killing
it or consuming a spare. In that degraded state, `viewer.current` is `None`
because there is no route, while `pool.current` remains the still-live GDB; its
DAP API continues to work. If that process later dies, the queued
transport-terminal event either closes the viewer or authorizes the opted-in
warm handoff. The pool installs a GDB-side
`hook-quit` before `setup` so `q` in GDB's secondary DAP console causes a real
process exit on GDB versions where that UI would otherwise disappear without
terminating the DAP process. A setup hook may replace it intentionally. Use
host-side `g.close()` when clean quit-time history persistence matters.

An independent terminal viewer disconnect is less severe than that upstream
endpoint loss: the router and selected GDB remain connected, `console.current`
continues to identify that GDB, and a later `pwnc gdb view` resumes it without a
generation change. `console.viewer_connected` exposes the terminal connection;
`console.wait_viewer_connected(timeout)` and
`console.wait_viewer_disconnected(timeout)` provide event-driven synchronization
without property polling. `console.viewer_process` is intentionally `None`
because the manager does not own the separate viewer program.

With reconnect enabled, the viewer bridge PID and terminal mode remain stable
across generations. A protocol barrier prevents input queued for the old
generation from reaching the replacement; boundary input may be discarded
rather than misdelivered.
There are no timed polling or sleep loops: process death, switching, reserve
refill, public waits, and bounded child teardown are driven by transport
notifications, selector/pidfd readiness, blocking waitpid monitors, queues,
events, and conditions. If reserve creation or a healthy-endpoint route fails
after the pool has started, automatic retries stop to avoid process churn;
inspect `pool.last_error`, fix the cause, call `pool.replenish()`, and then
`pool.wait_ready()`. A failure during the initial `start()` fill closes that
pool, so retry initial construction with a new `GdbPool`.

`setup` is ordinary synchronous Python. `pool.close()` immediately closes the
GDB owned by a setup that is still running, but Python cannot preempt arbitrary
user code that never returns; such a setup worker may remain until the hook
cooperates or exits.

For manual routing without reserve management, `ViewerRouter(viewer).start()`
is public and its `switch(owned_endpoint)` method retargets the same bridge.
One `GdbPool` owns one durable viewer at a time; close its `PoolConsole` before
opening another.

`Gdb.use()` creates a cheap immutable view of the same session with defaults
for blocking operations.  An explicit method timeout wins over the view's
default, and deriving another view does not mutate either earlier object:

```python
timed = g.use(timeout=30)
timed.execute("info registers")
stop = timed.run()                    # run() still controls the inferior
quick = timed.use(timeout=2)
unbounded = timed.use(timeout=None)    # explicitly disable the deadline
```

## Synchronous recursive callbacks

`Gdb.call()` runs a pwnc-owned operation registered inside GDB.  Positional and
keyword arguments are forwarded as ordinary Python arguments, including
callables.  Callback handlers are normal synchronous functions and may call
back into the same session, including unmodified plugin commands, or
recursively start a child operation:

```python
def bridge(action, *values):
    # This is an ordinary function, on its own native thread stack.
    print(g.execute("history -n"))       # normal GEF command
    if action == "resolve":
        return int(g.eval("&" + values[0]))
    classify, address = values           # GDB passed us a callable
    return classify(address, label="main")

result = g.use(timeout=30).call(
    "example.scan",
    bridge,
    start=0x400000,
)
```

The corresponding GDB-side operation may synchronously invoke host callables
with `await invoke(...)`, and it may pass ordinary GDB-side callables back to
the host.  Registration is explicit and the source string is the only code
that is lowered; plugin source remains untouched:

```python
# sourced inside GDB after pwnc's DAP extension
source = r"""
async def scan(host_bridge, start=0):
    def classify(address, *, label=None):
        return {"address": address, "label": label}

    resolved = await invoke(host_bridge, "resolve", "main")
    return await invoke(host_bridge, "classify", classify, start + resolved)
"""

namespace = {}
gdb.pwnc_exec_lowered(source, namespace=namespace, filename="<my-operations>")
gdb.pwnc_register_operation("example.scan", namespace["scan"])
```

On the host, `classify` arrives as a normal synchronous callable proxy.  It is
valid while its root call is active and can be called from the active host
callback with positional and keyword arguments.  Callback identities are
stable within that root; bytes, tuples, nested containers, and exceptions are
preserved in both directions.  Returning a GDB callable from the root is an
error because persistent callbacks need a separate explicit lifetime API.
If the configured root deadline expires, ordinary work is revoked atomically
across every active descendant and cancellation is queued deepest-first;
lowered `finally` blocks may still invoke callbacks marked as cleanup.

All `call()` keywords belong to the GDB-side operation, even names such as
`timeout`.  Host-side deadlines therefore come from `use(timeout=...)`.
`run_operation()` remains available for the legacy arguments/callback maps.

Operation source can use `async def`/`await` as private authoring notation, but
`gdb.pwnc_exec_lowered()` rewrites only that registered source into plain
generators before execution.  The public API is entirely synchronous: there is
no asyncio requirement, greenlet dependency, or recursive DAP message pump.
When an operation yields an effect, GDB's main thread returns to its event loop;
the host callback runs on a fresh OS thread and the continuation is posted back
to GDB's main thread after the reply.  Depth and active-worker limits reject
work with an explicit error reply, so a suspended operation is never abandoned
silently.  Cooperative cancellation reserves separate cleanup-callback slots.

The boundary is intentional: pwnc-owned lowered operations can suspend and then
run arbitrary untouched GEF/pwndbg/plugin commands during that suspension.  An
already-active, unmodified synchronous plugin frame cannot itself be frozen and
synchronously re-enter the same GDB before returning without transforming that
plugin, using a stackful continuation, or recursively pumping messages.  pwnc
does none of those.

## Interactive console

Console allocation is explicit and independent of the inferior.  Sessions are
headless by default; the four modes are `none`, `current`, `target`, and
`owned`:

```python
from pwnc.gdb.dap import (
    ArgvTerminalLauncher,
    ConsoleConfig,
    ViewerConfig,
    launch,
)

# Choose one configuration per GDB session:
ConsoleConfig.none()                             # no console / no PTY
ConsoleConfig.current()                          # GDB directly borrows fd 0's TTY
ConsoleConfig.target("/dev/pts/12")              # or a supplied TTY path/fd

# An owned endpoint has a stable private PTY and may initially have no viewer.
g = launch("./bin")
endpoint = g.console(ConsoleConfig.owned())
endpoint.attach_viewer(ViewerConfig.current())
# Or display the same owned endpoint in an existing TTY without spawning a
# terminal emulator:
# endpoint.attach_viewer(ViewerConfig.target("/dev/pts/12"))

# Any shell-free terminal launcher can display an owned endpoint.  The exact
# {command} item is replaced by the bridge argv.
external = ConsoleConfig.owned(
    viewer=ViewerConfig.external(
        ArgvTerminalLauncher(["xterm", "-e", "{command}"])
    ),
)
# Equivalent constructor form for a new session:
# g = launch("./bin", console=external)
```

The console and the script **share one gdb/inferior**: type gdb commands in the
terminal (`run`/`continue`/`break`/`stepi`/`print`/…) and the script's breakpoint
callbacks still fire — driving from the console produces stops the script
receives via `g.wait()`. To hand control to the console and let callbacks fire as
you drive:

```python
g.bp("target", callback=my_cb)
while g.wait().get("reason") not in ("exited", "terminated"):
    pass                              # callbacks fire on each console-driven stop
```

- **Terminal launchers:** there is no Kitty assumption.  A launcher may be an
  `ArgvTerminalLauncher`, a callable, or an object with `spawn(bridge_argv)`.
  Legacy `headless=False`, `console=<argv>`, `$PWNC_DAP_TERMINAL`, and terminal
  discovery remain compatibility shims.
- **Owned endpoints:** a bounded broker continuously drains the PTY, retains a
  bounded reconnect backlog, and authenticates bridge clients over a private
  Unix socket.  If a viewer exits, the endpoint stays alive; another
  `g.console(...)` call or `endpoint.attach_viewer(...)` reconnects it.  This is
  one endpoint per GDB session; `ViewerRouter`/`GdbPool` provide the separate
  stable terminal-to-endpoint switching layer.
- **ANSI integrity:** live PTY output remains an opaque ordered byte stream;
  reads, socket frames, and terminal writes may split a control sequence and
  are forwarded immediately.  ANSI parsing occurs only when a bounded startup
  or reconnect backlog actually discards its prefix.  That cutoff drops whole
  control sequences and replay prepends a terminal reset, so it cannot begin
  with a visible fragment such as bare `36m`.
- **Resize:** current/target modes observe their borrowed TTY; the standalone
  owned bridge forwards initial geometry and `SIGWINCH`.  Sizes are applied
  synchronously before `new-ui` and on reconnect, so width-aware GEF/pwndbg
  output does not begin with stale dimensions.
- **Startup transcript:** native-DAP output produced before the secondary UI
  exists—including `.gdbinit`/Bata24 logs and errors, raw stdout/stderr, and
  captured CLI command results—is retained in a bounded 4 MiB transcript and
  replayed exactly once before the first `(gdb)` prompt.  An output-pipe marker
  provides an event-driven flush boundary; there is no polling or sleep.  The
  administrative `New UI allocated` confirmation is suppressed, and a failed
  UI attachment restores the transcript for the next attempt.
- **Plugin compatibility:** after native DAP has retained its protocol streams,
  pwnc binds process fd 0 and fd 1 to the selected console PTY.  Unmodified
  plugins which use `os.get_terminal_size()` or raw `/proc/self/fd/{0,1}` I/O
  therefore see the real terminal.  If Bata24 GEF is loaded—either directly
  sourced or imported as a module by a wrapper—its existing `context.redirect`
  setting is pointed at that PTY before automatic stop context runs, including
  when GEF is loaded after the console is opened.  This also keeps GEF's
  context writer ordered ahead of the new-UI prompt instead of letting a
  block-buffered fd-1 flush splice the prompt into an ANSI control sequence.
- **Native DAP semantics:** a CLI prompt normally leaves GDB's global current
  UI on the secondary console, whose prompt state changes nested execution.
  The console's `before_prompt` event uses GDB's built-in no-op SIGQUIT event to
  hand affinity back to the native DAP UI before the next event-loop item.  It
  is event-driven (no polling or sleeps), and untouched synchronous commands
  such as Bata24 `next-ret -n` retain their normal behavior.
- **Lifecycle:** `g.console_close()` closes the owned viewer and gracefully lets
  the bridge restore terminal state before bounded TERM/KILL fallback.  The
  history-bearing PTY/UI remains attached and drained until GDB exits, and can
  accept another viewer in the meantime.  A borrowed GDB UI cannot be removed
  by GDB, so `console_close()` raises instead of pretending it detached; close
  the GDB session to release it.  Set `keep_open=True` on `ViewerConfig` to
  leave a viewer up after GDB exits.
- **History:** opening a console explicitly enables gdb history saving, so
  commands typed in the console are written to gdb's history file when the
  *session* exits cleanly through `g.close()`, even when `init=False`. gdb's
  `quit` is process-wide, so there is no way to save
  history while keeping the session — it is persisted at clean session exit.
  If the inferior is running, close performs one bounded, event-driven pause so
  native DAP can unwind its active output-capture frame before GDB saves that
  history.

## Testing

The callable tests use real GDB DAP processes.  Set `PWNC_TEST_GDB` to exercise
a particular build; the GEF tests require the exact unmodified bata24 source at
`/home/ctf/bata24-gef/gef.py` and verify its hash and metadata before and after:

```sh
PWNC_TEST_GDB=/path/to/gdb \
  uv run --python /usr/bin/python3 --with pytest --with pwntools \
  python -m pytest -q \
  tests/dap/test_callbacks_live.py \
  tests/dap/test_callbacks_gef_inferior.py

# Full non-GUI DAP suite, then real terminal/viewer coverage under Xvfb.
uv run --python /usr/bin/python3 --with pytest --with pwntools \
  python -m pytest -q tests/dap --ignore=tests/dap/test_console.py
xvfb-run -a uv run --python /usr/bin/python3 --with pytest --with pwntools \
  python -m pytest -q tests/dap/test_console.py
```

The bata24-specific stress suite exercises 16 concurrent callback roots,
depth-16 public callable recursion, legacy recursive host/GDB alternation at
both sides of the JSON-depth boundary, and exact thread/fd cleanup across
repeated sessions.  The longer ten-session soak is opt-in:

```sh
uv run --with pytest --with pwntools python -m pytest -q \
  tests/dap/test_bata24_stress.py

PWNC_GEF_STRESS_TESTS=1 PWNC_GEF_STRESS_CYCLES=10 \
  uv run --with pytest --with pwntools python -m pytest -q \
  tests/dap/test_bata24_stress.py
```

The cross-architecture suite compiles a real dynamic fixture against every
pinned default-lane glibc sysroot, runs it under the matching QEMU-user, and
drives the exact bata24 source through `gdb-multiarch`.  It verifies all 20
supported default-glibc targets, exact guest-side libc identity,
architecture/endianness,
typed DAP access, core GEF commands, and a nested host callback.  Provisioned
sysroots share the payload test cache.  A comma-separated target selector is
available for focused diagnosis:

```sh
PWNC_GEF_QEMU_TESTS=1 \
  uv run --with pytest --with pwntools python -m pytest -q \
  tests/dap/test_bata24_multiarch.py

PWNC_GEF_QEMU_TESTS=1 \
PWNC_GEF_QEMU_TARGETS=x86_64-le-amd64-sysv,powerpc64-be-powerpc64-elfv1 \
  uv run --with pytest --with pwntools python -m pytest -q \
  tests/dap/test_bata24_multiarch.py
```

Set `PWNC_TEST_GEF` if the pinned source is installed elsewhere,
`PWNC_TEST_MULTIARCH_GDB` for a non-default all-target GDB, and
`PWNC_GLIBC_SYSROOT_CACHE` to relocate the shared sysroot cache.  These paths
must be whitespace-free because the relevant GDB `source`/`set` commands
preserve quote characters instead of parsing them as shell quoting.

The source fixture is never changed.  The QEMU lane injects narrow runtime
guards for bata24's `/proc` PID race, recursive Qiling detection, and live
CET/PAC/MTE probes that otherwise depend on `/proc/<qemu-pid>/mem`; file-level
mitigation detection remains active.  Dynamic heap-arena discovery is an
upstream bata24 limitation on MIPS32, MIPS64, and SPARC32, so those cases must
return the plugin's explicit unsupported diagnostic while every other target
must traverse real chunks.  The pinned plugin also declares AArch64 class
metadata as little-endian even for AArch64-BE; that lane requires the known
metadata mismatch while independently proving big-endian runtime packing and
memory access.

## Layout

```
pwnc/gdb/dap/
├── __init__.py    # public API: Gdb, debug(), attach() + sym/reg accessors
├── transport.py   # routed DAP reader/writer/event/completion lanes
├── client.py      # DapBytesProvider: readMemory/writeMemory -> pwnc.types
├── _ext.py        # in-gdb extension: custom requests (type layout, regs, skip, …)
├── _runtime_ext.py # structured maps/modules, threads/DWARF, and bata24 facts
├── runtime.py     # ergonomic modules, maps, memory, targets, and layout
├── facts.py       # batched per-thread registers, frames, variables, libc facts
├── marks.py       # address/range, typed-memory, heap, and payload annotations
├── heap.py        # direct bata24 heap objects and allocation generations
├── history.py     # selective snapshots, bounded events, semantic A/B diffs
├── verify.py      # caller-supplied exploit/debugger truth checks
├── inspector.py   # event-driven JSON publisher for the native ImGui process
├── callbacks.py   # host operation state, admission, recursive callback stacks
├── _callback_ext.py # in-gdb operation/reply/cancel protocol and registration
├── _lowering.py   # private async-looking source -> synchronous generators
├── console.py     # none/borrowed/owned console configuration and PTY broker
├── viewer.py      # durable reconnectable bridge router and atomic retargeting
├── pool.py        # configured targetless GDB reserve and process-death failover
├── discovery.py   # deterministic project/socket discovery and manager lease
├── viewer_client.py # independently managed terminal viewer supervisor
├── _process.py    # event-driven bounded child exit/reap waits
├── _tty_resize_bridge.py # event-driven target-TTY SIGWINCH relay
└── _console_bridge.py # standalone viewer, byte I/O, and resize relay
```

Type reconstruction lives in `pwnc.types.serial` (`from_descriptor`), shared and
gdb-independent.

## Custom requests (added by `_ext.py`)

`pwncResolveSymbol`, `pwncTypeOf` (gdb.Type → descriptor), `pwncReadRegister(s)`,
`pwncWriteRegister`, `pwncSkip`, `pwncEval`, `pwncBreakpoint`, `pwncWatch`,
`pwncDeleteBreakpoint`, `pwncArch`, `pwncNewUI`/`pwncSetWinsize` (console).
`_runtime_ext.py` adds `pwncRuntimeInfo`, `pwncRuntimeThreads`,
`pwncRuntimeThread`, `pwncLookupType`, `pwncBataHeapChunk`, and
`pwncBataHeapArenas`; these return JSON-native facts and call bata24 Python
objects directly rather than parsing command output.
`_callback_ext.py` additionally provides `pwncOperationStart`,
`pwncOperationReply`, `pwncOperationCancel`, and `pwncOperationSnapshot`.
Everything else (memory, stepping,
continue, stacks, disassembly) uses native DAP requests.
