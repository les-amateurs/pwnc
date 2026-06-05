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

## Interactive console

Open a real gdb CLI console in a terminal window — independent of the session,
headless or not:

```python
g = launch("./bin", headless=False)   # open the console at startup, or:
g.console()                           # ...open it any time (kitty by default)
g.console_close()                     # ...and close it any time
```

The console and the script **share one gdb/inferior**: type gdb commands in the
window (`run`/`continue`/`break`/`stepi`/`print`/…) and the script's breakpoint
callbacks still fire — driving from the console produces stops the script
receives via `g.wait()`. To hand control to the console and let callbacks fire as
you drive:

```python
g.bp("target", callback=my_cb)
while g.wait().get("reason") not in ("exited", "terminated"):
    pass                              # callbacks fire on each console-driven stop
```

- **Terminal:** kitty by default; override with `console=<argv>` or
  `$PWNC_DAP_TERMINAL`. The library uses the ambient `$DISPLAY` (no Xvfb — that's
  only the test harness).
- **Resize:** an in-window agent forwards `SIGWINCH`/size to gdb, so width-aware
  plugins (pwndbg/GEF/bata24) render at the real window width.
- **Lifecycle:** the window auto-closes when gdb exits; pass
  `console_keep_open=True` (to `debug`/`attach`/`launch`) to keep it up.

## Layout

```
pwnc/gdb/dap/
├── __init__.py    # public API: Gdb, debug(), attach() + sym/reg accessors
├── transport.py   # DAP JSON-RPC over gdb stdio (framing, seq futures, events)
├── client.py      # DapBytesProvider: readMemory/writeMemory -> pwnc.types
├── _ext.py        # in-gdb extension: custom requests (type layout, regs, skip, …)
├── console.py     # interactive console: terminal + new-ui + resize side channel
└── _console_agent.py  # runs in the terminal window; relays tty + size to gdb
```

Type reconstruction lives in `pwnc.types.serial` (`from_descriptor`), shared and
gdb-independent.

## Custom requests (added by `_ext.py`)

`pwncResolveSymbol`, `pwncTypeOf` (gdb.Type → descriptor), `pwncReadRegister(s)`,
`pwncWriteRegister`, `pwncSkip`, `pwncEval`, `pwncBreakpoint`, `pwncWatch`,
`pwncDeleteBreakpoint`, `pwncArch`, `pwncNewUI`/`pwncSetWinsize` (console).
Everything else (memory, stepping,
continue, stacks, disassembly) uses native DAP requests.
