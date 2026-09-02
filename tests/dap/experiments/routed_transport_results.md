# Reader-isolated synchronous DAP transport experiment

## Result

`routed_transport_probe.py` demonstrates a synchronous DAP transport in which
the stdout byte-reader thread does only two things:

1. parse `Content-Length` framing and read exactly that many raw bytes;
2. put an envelope containing those bytes (or EOF/read failure) on a queue.

The reader does not decode JSON, look up a request, complete a response object,
set a `Future`/`Event`, invoke an event handler, invoke user code, write a DAP
response, or wait for a callback.  Even reader diagnostics are carried in the
queue envelope and recorded by the router rather than by the reader.

A dedicated router thread decodes JSON, correlates responses, selects timeout
and close outcomes, and fans out events.  It never calls user code: each event
handler and completion callback runs on a newly created ordinary OS thread.
The request API itself is plain synchronous Python backed by a condition-based
response slot.  There is no asyncio, greenlet, worker pool, or recursive
message pump.

Outbound I/O has a separate dedicated writer thread. Concurrent synchronous
senders assign a sequence number, register the pending slot, and enqueue the
framed bytes in one critical section; the FIFO writer therefore puts messages
on the wire in exact DAP sequence order. It loops until the full frame is
written, and reports writer failures through the router so all pending callers
receive a terminal error. Reverse requests are also enqueued, so the router
never writes to a potentially blocked pipe.

## Executable evidence

Run the live probe with:

```sh
timeout --signal=KILL 90s python3 \
  tests/dap/experiments/routed_transport_probe.py \
  --gdb GDB_PATH \
  --gef /home/ctf/bata24-gef/gef.py \
  --require-gef \
  --depth 8
```

It was run on 2026-08-02 against the four real GDB binaries already built for
the callback version matrix:

| GDB | Result | Recursive operations | Sync callback workers | Late responses | Pending close |
| --- | --- | ---: | ---: | ---: | --- |
| 14.2 | PASS | 9 | 9 | 1 classified | failed by router |
| 15.1 | PASS | 9 | 9 | 1 classified | failed by router |
| 16.3 | PASS | 9 | 9 | 1 classified | failed by router |
| 17.2 | PASS | 9 | 9 | 1 classified | failed by router |

An additional GDB 15.1 stress run at depth 32 also passed with 33 nested
operations, 33 simultaneously retained synchronous callback stacks, 68 total
short-lived transport workers, and no pending response slots after cleanup.

The exact binaries were:

```text
/tmp/pwnc-gdb-version-matrix/install/14.2/bin/gdb
/usr/bin/gdb
/tmp/pwnc-gdb-version-matrix/install/16.3/bin/gdb
/tmp/pwnc-gdb-version-matrix/install/17.2/bin/gdb
```

The implementation and executable affinity assertions cover these properties:

- Reader and router have distinct thread IDs.
- Reader, router, and writer have three distinct thread IDs.
- Every outbound message is written only by the writer, with contiguous DAP
  sequence numbers in wire order. A deterministic two-sender test holds the
  first enqueue inside its ordering lock and proves the second cannot overtake
  it.
- A short-writing fake stream requires multiple writes and still receives one
  byte-exact, correctly framed DAP message.
- An injected writer failure is routed back through the router, terminates
  acceptance, and fails and clears every pending response slot.
- Every response completion, timeout decision, and late-response
  classification is recorded on the one router thread.
- No event handler or completion callback runs on the reader, router, writer,
  or public caller thread.
- A response completion callback synchronously issues another real GDB DAP
  request.  It finishes, proving that it cannot have captured the router.
- A callback registered after its response is already complete is still
  scheduled on a worker rather than invoked inline in the registering thread.
- Nine callback workers remain synchronously blocked at recursive depth eight,
  and the ninth nested operation completes without fixed-pool starvation.
- Every callback invokes `history -n` from unmodified bata24 GEF.  Runtime-only
  injection observes GEF synchronously nesting `gdb.execute("show commands
  ...")`; the outer and nested calls all remain on GDB's one main thread.
- GEF is rejected before sourcing unless its SHA-256 is exactly
  `f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01`.
  The same exact digest is enforced again after every run.
- A real GDB `evaluate` request that sleeps for 300 ms times out after 30 ms.
  Its eventual response is classified against a bounded timeout tombstone,
  and a subsequent synchronous request succeeds.
- Closing a second transport while a real GDB request is pending completes the
  response slot with an error on the router, clears the registry, and reaps
  GDB, the reader/router/writer/stderr threads, and the pending slot's
  completion worker under one shared five-second cleanup deadline.
- A separate close test deliberately keeps that completion worker blocked
  outside the transport. Close still reaps GDB and every infrastructure thread
  under its deadline and explicitly reports the surviving callback thread.
- All dynamically created workers are joined in the success path, and no
  response slots remain pending.
- Valid JSON with a non-object top level terminates the channel, fails and
  clears every pending slot, and stops accepting requests. An outer router
  failure guard applies the same cleanup to unexpected implementation errors.
- An injected `Thread.start()` failure is recorded, removes its reserved worker
  entry, and does not terminate or capture the router; a subsequent real GDB
  request succeeds.

The local style/test commands also pass:

```sh
uv run --isolated --python 3.12 --with ruff --no-project \
  ruff check tests/dap/experiments/routed_transport_probe.py

uv run --isolated --python 3.12 --with pytest --no-project \
  pytest -q -s tests/dap/experiments/routed_transport_probe.py
```

The real-GDB matrix can also be rerun through pytest rather than relying on the
default `gdb` in `PATH`:

```sh
PWNC_ROUTED_GDB_MATRIX_JSON='{"14.2":"/tmp/pwnc-gdb-version-matrix/install/14.2/bin/gdb","15.1":"/usr/bin/gdb","16.3":"/tmp/pwnc-gdb-version-matrix/install/16.3/bin/gdb","17.2":"/tmp/pwnc-gdb-version-matrix/install/17.2/bin/gdb"}' \
uv run --isolated --python 3.12 --with pytest --no-project \
  pytest -q -s tests/dap/experiments/routed_transport_probe.py \
  -k live_gdb_matrix_from_environment
```

## Why not complete a `concurrent.futures.Future` on the router?

`Future.set_result()` invokes registered `add_done_callback` functions inline
in the setter thread.  Registering a callback on an already-finished Future
also invokes it inline in the registering thread.  The probe has a direct
assertion for both standard-library behaviors.

Consequently, merely moving `Future.set_result()` from the byte reader to the
router is insufficient: an arbitrary done callback could synchronously call
back into DAP, occupy the router, and deadlock waiting for a response that only
that router can correlate.  The experiment's response slot wakes synchronous
condition waiters on the router, but schedules every optional completion
callback onto a user worker.  A production implementation can omit completion
callbacks entirely if the public contract only needs `send`/`result`/`request`.

## Tradeoffs and production constraints

- **Thread cost:** arbitrary synchronous nesting needs one live stack per
  active callback level.  New threads avoid fixed-pool starvation, but
  production needs explicit maximum depth, maximum active callbacks, and a
  fail-fast admission error.  A fixed pool can silently deadlock when every
  worker waits for a child that has no worker available.
- **Event ordering:** this proof schedules every user event handler
  independently, which permits unrelated handlers to run out of order.  The
  production router should distinguish protocol-completion events (handled as
  router-owned state transitions), re-entrant callback events (fresh worker
  per invocation), and passive notification subscriptions (a serial lane per
  subscription when ordering is part of their contract).
- **Router discipline:** JSON decoding and routing are serialized. The router
  mutates only small protocol registries and condition slots, schedules user
  workers, and enqueues reverse responses; it never performs pipe I/O, executes
  plugin/user code, or waits for GDB/callback work.
- **Backpressure:** the experiment uses unbounded inbound and outbound queues.
  Production needs byte/message budgets and a defined overload policy that
  does not turn the reader, router, or writer into a user-code execution path.
- **Shutdown:** ordinary Python threads cannot be forcibly cancelled. Closing
  the transport uses one global deadline and records any user-worker survivors;
  a callback blocked outside the transport still needs cooperative cancellation.
  Callback-owned operation cells must be failed as part of higher-level
  dispatcher shutdown.
- **Late responses:** timeout tombstones are deliberately bounded (64 here).
  Responses older than the retained horizon can only be classified as unknown,
  not associated with their original timed-out command.
- **Extra hop:** routing through a queue adds one scheduling hop to every DAP
  message.  This is the cost of making the reader mechanically incapable of
  running completion/user logic; it is negligible beside interactive GDB
  command latency but should still be benchmarked under high-volume output.

This model supports the intended interleaving boundary: a pwnc-owned lowered
operation suspends, its synchronous host callback invokes unmodified plugin
commands (including nested `gdb.execute`), and the operation resumes.  It does
not turn an already-active, unmodified plugin stack into a suspendable
continuation.
