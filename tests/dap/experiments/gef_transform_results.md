# Active-frame GEF callback feasibility

## Fixture and matrix

All probes use `/home/ctf/bata24-gef/gef.py` with SHA-256
`f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01`.
The suite checks the hash, size, and modification time before and after it runs.
Runtime injection is allowed; the file is never edited.

The complete suite passes on the locally built GDB matrix:

| GDB | Python | Result |
| --- | --- | --- |
| 14.2 | 3.12 | PASS |
| 15.1 | 3.12 | PASS |
| 16.3 | 3.12 | PASS |
| 17.2 | 3.12 | PASS |

Run one version with:

```sh
python3 tests/dap/experiments/gef_transform_test.py \
  --gdb /tmp/pwnc-gdb-version-matrix/install/17.2/bin/gdb
```

## What was tested

### Dynamic `gdb.execute` interception

The injection pauses in the untouched
`GenericCommand.invoke -> parse_args.wrapper -> HistoryCommand.do_invoke ->
HistoryCommand.get_history -> gdb.execute("show commands 0")` stack.

An external host immediately submits `evaluate("show pagination")` through
DAP. The DAP reader accepts and frames the request, but its GDB-main portion
does not run during a 750 ms fuse. It runs only after `HistoryCommand` and the
outer `gdb.execute("history -n")` return. Replacing the `gdb.execute` module
attribute therefore observes the call but does not make the caller suspendable.

Calling the original `gdb.execute` directly from the interceptor does work
recursively before GEF returns. This is useful as a control: recursive GDB
execution itself is possible when it remains inline on GDB's main thread. It
is not an external host callback and provides no place for the host to block
and later re-enter.

### `gdb.post_event`

Posting an event from the active GEF frame and waiting for it does not run the
event. The event executes on the same GDB thread immediately after GEF returns
to the event loop. This matches GDB's contract: `post_event` enqueues work for
later event processing; it does not recursively dispatch it.

The official GDB threading documentation also states that GDB is not
thread-safe, that GDB-specific functions must run on the GDB thread, and that
`gdb.post_event` is one of the explicitly thread-safe exceptions:
<https://sourceware.org/gdb/current/onlinedocs/gdb.html/Threading-in-GDB.html>.

### Calling GDB from another Python thread

Both `threading.Thread` and `gdb.Thread` happen to complete the trivial
read-only command `show pagination` while the GDB main thread is blocked in
GEF. `gdb.Thread` only arranges signal masking; it does not transfer GDB-main
thread ownership.

That apparent escape is not usable. Running the state-changing command
`file <native-debug-ELF>` from either worker produces an internal GDB failure
on 14.2, 15.1, and 16.3. GDB 17.2 aborts at `ext_lang_guard`'s
`is_main_thread()` assertion (`gdb/extension.c:738`). The backtrace enters
through `execute_gdb_command` on the worker. This is deterministic in the
matrix and directly confirms the documented thread-safety restriction.

### Python tracing and code-object replacement

`sys.settrace` can inject a callback at `HistoryCommand.get_history`'s call
event. A direct inline `gdb.execute` from that trace callback succeeds on the
same GDB thread.

Tracing does not expose a continuation:

- Raising a synthetic suspension exception unwinds the real GEF stack. A
  retained traceback names `invoke`, `parse_args.wrapper`, `do_invoke`, and
  `get_history`, but the retained `frame` has no `send` or `throw` operation.
- Assigning `frame.f_lineno` after unwinding fails because line jumps are only
  accepted from a currently executing trace function. Even a trace-time line
  jump changes control flow; it does not preserve and later restore the frame.
- Replacing `HistoryCommand.get_history.__code__` during its call event leaves
  the active frame on the old code. The original nested `show commands` calls
  complete; only the next method invocation uses the replacement code.

Opcode tracing, `sys.monitoring`, and bytecode rewriting have the same active
frame limitation: their callbacks execute inline, while changing a function's
code affects subsequently created frames. Raising or injecting an exception
unwinds rather than suspends the stack.

### Import hooks and source-time AST/CPS injection

Normal `source gef.py` does not call a replaced `builtins.compile` and does not
ask a `sys.meta_path` finder to load the top-level script. A CPython audit hook
observes one `compile` event for the GEF path, but audit hooks cannot replace
the source or resulting code object. Transparent import/compile monkeypatching
therefore cannot transform a normally sourced GEF file.

A custom loader can read the exact file, transform its AST in memory, compile
it under the original filename, and execute it without changing the file. The
targeted experiment transforms the concrete HistoryCommand chain:

1. `HistoryCommand.get_history` yields its `gdb.execute` operation.
2. `HistoryCommand.do_invoke` uses `yield from`.
3. `GenericCommand.invoke` drives the returned generator.

This proves two different behaviors:

- **Inline driver:** the generator handles every effect before returning to
  GDB. The command remains synchronous, but no external callback can suspend
  and re-enter it.
- **Deferred driver:** the generator is retained and GDB regains its event
  loop. Intervening GDB work and later resumption succeed, but the outer
  `gdb.execute("history -n")` has already returned while the GEF command is
  incomplete. The required synchronous contract has changed.

Transforming more GEF source does not remove the final boundary. Supporting an
arbitrary command would require transforming every transitive Python caller,
decorator, callback, dynamically imported dependency, and relevant library
call. Python cannot yield through an untransformed C frame. Ultimately GDB's C
command dispatcher invokes `gdb.Command.invoke` synchronously; it must either:

- remain blocked and service nested work with a recursive event/message pump;
- retain its native/Python stack using a stackful-continuation mechanism;
- return and make the command observably asynchronous; or
- execute GDB APIs from another OS thread, which is unsupported and crashes in
  the probe above.

A whole-world interpreter or native stack-copying extension could emulate a
continuation, but that is the same class of facility as the rejected greenlet
approach, not ordinary AST injection. It also cannot leave arbitrary native
extension frames untouched.

There is a protocol-shaped spelling of the same forbidden pump: let the GDB
main thread wait for a callback response, wake it with a nested-command
request, execute that command inline, return its result to the host, then wait
again for the original callback. Calling this a condition-variable bridge or
restricted reverse-RPC loop does not change its control flow; the active GEF
stack is recursively servicing messages while its callback is incomplete.

## Supported boundary

The implementable no-pump design is:

```text
pwnc-lowered operation on GDB main
  -> yields a host effect and returns GDB main to its event loop
  -> ordinary synchronous host callback runs on its own OS thread
  -> callback invokes arbitrary untouched GEF/plugin commands through DAP
  -> each plugin and its nested gdb.execute calls finish synchronously on GDB main
  -> callback response resumes the lowered pwnc generator
```

It can recurse by retaining one host stack/thread per active callback level.
The stronger reverse direction—an already-active arbitrary untouched plugin
initiates the host callback and requires same-GDB work before its own return—
is not supportable through public GDB/CPython mechanisms under the constraints
of no recursive pump, no stackful continuation, and synchronous plugin
semantics.
