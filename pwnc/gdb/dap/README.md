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
g.run(); g.wait()

g.sym.counter                  # typed pwnc.types Value over live memory
g.sym.origin.x                 # struct fields, bitfields, pointers, arrays
g.reg.rip; g.reg.rip = 0x401000
g.read(addr, 64); g.write(addr, b"\x90")
g.stepi(); g.nexti(); g.skip(); g.cont()

bp = g.bp("update_origin", callback=lambda g: print(int(g.sym.counter)))
g.cont(); g.wait()             # callback runs each hit; return False to stop

g.close()
```

`attach(pid_or_name)` attaches to a running process. Both are **headless** by
default; pass `headless=False` (optionally `console=<terminal argv>` or set
`$PWNC_DAP_TERMINAL`) for an interactive gdb console window — no hard-coded
terminal dependency.

## Layout

```
pwnc/gdb/dap/
├── __init__.py    # public API: Gdb, debug(), attach() + sym/reg accessors
├── transport.py   # DAP JSON-RPC over gdb stdio (framing, seq futures, events)
├── client.py      # DapBytesProvider: readMemory/writeMemory -> pwnc.types
├── _ext.py        # in-gdb extension: custom requests (type layout, regs, skip, …)
└── console.py     # optional pluggable interactive console
```

Type reconstruction lives in `pwnc.types.serial` (`from_descriptor`), shared and
gdb-independent.

## Custom requests (added by `_ext.py`)

`pwncResolveSymbol`, `pwncTypeOf` (gdb.Type → descriptor), `pwncReadRegister(s)`,
`pwncWriteRegister`, `pwncSkip`, `pwncEval`, `pwncBreakpoint`, `pwncWatch`,
`pwncDeleteBreakpoint`, `pwncArch`. Everything else (memory, stepping,
continue, stacks, disassembly) uses native DAP requests.
