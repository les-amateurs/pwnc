# Primary CLI plus side-DAP compatibility result

## Outcome

Starting ordinary GDB on the primary PTY and manually bootstrapping its stock
`gdb.dap` server on a socketpair is **not compatible enough** to replace GDB's
native DAP interpreter. The design passes ordinary structured requests and
simple execution control, but untouched Bata24 GEF fails while executing
`next-ret -n` inside a real host callback.

The production direction therefore remains GDB's native
`--interpreter=dap`. The primary-CLI/side-DAP prototype is retained only as a
negative compatibility probe; it is not production console transport code.

## Decisive test

The test loads the exact unmodified Bata24 GEF file at
`/home/ctf/bata24-gef/gef.py`, whose SHA-256 is:

```text
f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01
```

At `pwnc_marker_one`, a real pwnc operation invokes a host callback. The
callback synchronously runs:

```python
gdb.execute("next-ret -n")
```

Success requires the command to reach the function's return instruction,
render Bata24's registers/stack/code context, return through the callback, and
allow the next public `cont()` to reach `pwnc_marker_two` with a coherent
frame.

The exact native-DAP callback probe passed on every supported GDB in the local
matrix. The side-DAP architecture failed on every version at the same point:

| GDB | Native DAP callback | Primary CLI + side DAP | Native internal stops classified |
| --- | --- | --- | ---: |
| 14.2 | PASS | FAIL | 5 |
| 15.1 | PASS | FAIL | 5 |
| 16.3 | PASS | FAIL | 5 |
| 17.2 | PASS | FAIL | 5 |

The side-DAP failure occurs during Bata24's instruction loop at
`pwnc_marker_one+0xf`:

```text
[!] 'NoneType' object has no attribute 'mnemonic'
```

Ordinary primary-CLI execution of `next-ret -n` also passed on the host GDB
15.1, so the failure is specifically the hybrid's execution context, not the
fixture or the command.

## What the hybrid did prove

The rejected design still established that a manually started side server can
use the same GDB Python thread machinery as native DAP:

- both DAP loops are `gdb.Thread` instances;
- both dispatch GDB API work on GDB's main thread;
- both use the same DAP-thread signal mask;
- nested host callbacks and ordinary structured requests work;
- `continue` followed by `pause` works;
- automatic GEF context reaches the primary PTY;
- PTY geometry, resize, partial readline redraw, and viewer reconnect work;
- no `new-ui` is involved.

That parity is not sufficient. The top-level native DAP interpreter supplies
execution/UI semantics that an otherwise identical manually bootstrapped DAP
thread does not reproduce for arbitrary execution-driving plugin commands.
Suppressing DAP stop notifications and routing the command through
`interpreter-exec console` did not change the failure.

## Production stop ownership fix

Native DAP emits one `stopped` event for each of Bata24's five internal `ni`
commands. Those events are command history once `next-ret -n` returns; leaving
them in pwnc's public stop queue makes the following `cont()` return a stale
`step` stop while the inferior is actually running.

Production now sends a `pwncEventBarrier` request before each public execution
request. Its response is paired with a marker in the transport's ordered
passive-event FIFO. Once that marker is observed, already queued nonterminal
stops are known to precede the new execution request and are discarded.
Terminal exit/termination records are retained. This uses DAP ordering,
conditions, and events only: it adds no polling loop or sleep.

On the host GDB 15.1, 200 stopped-inferior barrier round trips measured a
0.287 ms median, 0.358 ms p95, and 0.549 ms maximum. The barrier runs only when
the caller asks to resume, step, or interrupt; it adds no idle-session work.

After this fix, the exact native callback probe discards five internal stops
and the following `cont()` reaches `pwnc_marker_two` on all four GDB versions.
The comprehensive live feature runner also passes 29/29 tests.

## Reproduction

Run the accepted native architecture:

```sh
python3 tests/dap/experiments/native_callback_next_ret_probe.py \
  --gdb GDB_PATH --json
```

Run the rejected hybrid gate (failure is the expected result with the tested
GDB versions):

```sh
python3 tests/dap/experiments/primary_cli_side_dap_probe.py \
  --gdb GDB_PATH --json
```

The matrix paths are:

```text
/tmp/pwnc-gdb-version-matrix/install/14.2/bin/gdb
/usr/bin/gdb
/tmp/pwnc-gdb-version-matrix/install/16.3/bin/gdb
/tmp/pwnc-gdb-version-matrix/install/17.2/bin/gdb
```
