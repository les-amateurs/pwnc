# pwnc.gdb.mi — GDB MI3 Library

Self-contained GDB MI3 library for scripting GDB from Python.

## Architecture

```
pwnc/gdb/mi/
├── __init__.py    # Public API: Gdb, debug(), attach()
├── parser.py      # Full MI3 output record parser
├── process.py     # GDB subprocess management (MI3 mode)
├── protocol.py    # Pickle-based Unix socket RPC
├── bridge.py      # GDB-side bridge script (runs inside GDB)
├── proxy.py       # Client-side proxy descriptors + proxy classes
└── README.md
```

## Usage

```python
from pwnc.gdb.mi import debug

gdb = debug("./binary")

# set breakpoints
bp = gdb.bp("main")

# run and wait for stop
gdb.run()
gdb.wait()

# access typed symbols
val = gdb.sym.global_var  # → Value with pwnc.types type

# registers
rax = gdb.reg.rax
gdb.reg.rip = 0x401000

# memory
data = gdb.read(0x7fff0000, 64)
gdb.write(0x7fff0000, b"\x90" * 4)

# execution control
gdb.stepi()
gdb.nexti()
gdb.skip()    # advance PC past current instruction
gdb.cont()

# proxy objects
inf = gdb.inferior()
threads = inf.threads()
frame = gdb.frame()
pc = frame.pc()

gdb.close()
```

## Components

### MI3 Parser (`parser.py`)

Full recursive-descent parser for GDB Machine Interface v3 output. Handles all record types:

- **Result records** (`^done`, `^error`, `^exit`) — command responses
- **Exec async** (`*stopped`, `*running`) — execution state changes
- **Status async** (`+download`) — progress notifications
- **Notify async** (`=thread-created`, `=library-loaded`) — informational
- **Stream records** (`~` console, `@` target, `&` log) — text output

Values are parsed recursively: c-strings, tuples `{}`, and lists `[]` with proper escape handling.

### Process Management (`process.py`)

`GdbProcess` spawns GDB with `--interpreter=mi3` and manages communication:

- Token-based command/response matching via `Future`s
- Background reader thread for async event dispatch
- Callback registration for async events (`*stopped`, `=thread-created`, etc.)
- Console command execution via `-interpreter-exec`

### Protocol (`protocol.py`)

Pickle-based bidirectional RPC over Unix sockets:

- **Wire format**: 4-byte big-endian length prefix + pickle payload
- **Message types**: `Call`, `Return`, `Error`, `Release`
- **Proxy serialization**: `persistent_id`/`persistent_load` for transparent GDB object proxying
- **Nested callbacks**: Client can handle incoming `Call` while waiting for `Return`

### Proxy Objects (`proxy.py`)

Descriptor-based proxy classes for GDB Python API objects:

- `ThreadProxy` — `gdb.InferiorThread`
- `InferiorProxy` — `gdb.Inferior`
- `ProgspaceProxy` — `gdb.Progspace`
- `FrameProxy` — `gdb.Frame`
- `SymbolProxy` — `gdb.Symbol`
- `BlockProxy` — `gdb.Block`
- `BreakpointProxy` — `gdb.Breakpoint`

Uses three descriptor types:
- `RemoteProperty` — read-only attribute access
- `RemoteRWProperty` — read-write attribute access
- `RemoteMethod` — method call

### Bridge (`bridge.py`)

Runs inside GDB's Python interpreter. Provides:

- Generic proxy handlers (`proxy.call`, `proxy.get`, `proxy.set`, `proxy.release`)
- Symbol resolution with GDB type → pwnc.types conversion
- Memory read/write
- Register get/set
- Instruction skip
- Thread-safe execution via `gdb.post_event()`

### Type Integration

`gdb.sym.X` resolves symbols using GDB's Python type API:

1. `gdb.lookup_symbol(name)` → get symbol + type
2. Convert `gdb.Type` → serializable descriptor → `pwnc.types.Type`
3. Create `GdbRemoteBytesProvider` for remote memory access
4. Return `type.use(provider)` → `Value`

Type mapping: `TYPE_CODE_INT` → `Int`, `TYPE_CODE_FLT` → `Float`/`Double`, `TYPE_CODE_PTR` → `Ptr`, `TYPE_CODE_ARRAY` → `Array`, `TYPE_CODE_STRUCT` → `Struct`, `TYPE_CODE_UNION` → `Union`, `TYPE_CODE_ENUM` → `Enum`.

Falls back to `Ptr(Int(8), bits=64)` (u8*) when type resolution fails.
