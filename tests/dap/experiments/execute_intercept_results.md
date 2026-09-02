# `gdb.execute` interception experiment

Run on 2026-08-02 with Ubuntu GDB 15.1 through both the batch interpreter and
the actual DAP interpreter:

```console
$ python3 tests/dap/experiments/execute_intercept_driver.py
PASS: GDB 15.1 execute interception semantics matched expectations via batch, dap
```

Use `--json` to print every recorded call, nesting depth, exception, and thread
identifier. The driver separately launches `gdb -q -nx -batch` and
`gdb -q -nx --interpreter=dap`. In the latter case it uses raw framed DAP to
initialize GDB and sources the probe with an `evaluate` request. The probe
itself executes inside GDB's embedded Python and registers real `gdb.Command`
subclasses.

## Observations

1. The `gdb` module permits `gdb.execute = replacement`.  Calls which perform a
   fresh module-attribute lookup reach the replacement.
2. A reference to the original built-in function captured before replacement
   continues to invoke it directly.  Replacing the module attribute cannot
   intercept such a reference.
3. Python `gdb.Command.invoke` calls are synchronous and re-entrant.  In the
   dynamic nesting probe, wrapper depths were `0`, `1`, and `2` for the outer
   command, inner command, and inner `set` command respectively.  Every event
   ran on the same OS thread.
4. Dispatch through a captured original `gdb.execute` bypasses interception for
   that dispatch only.  A nested command that later looks up `gdb.execute`
   dynamically reaches the replacement.  Conversely, a plugin that retained
   the original function can hide its own nested command dispatch from the
   replacement.
5. GDB accepts generator and coroutine functions as `invoke` methods without a
   registration or execution error, but it does not drive the returned object.
   Neither function body starts.  The coroutine additionally produces
   `RuntimeWarning: coroutine ... was never awaited`.
6. Raising a custom exception from the replacement can be caught by the plugin
   at that immediate Python call site.  If it escapes a Python
   `gdb.Command.invoke`, GDB converts it into `gdb.error`.  Each additional
   Python-command boundary adds another `Error occurred in Python:` layer.
7. Invoking the failed outer command again does not resume its Python frame.
   The experiment observes both outer and inner prefixes twice and both
   suffixes zero times.  Thus exception plus replay cannot transparently pause
   arbitrary synchronous plugin commands: it unwinds them, loses their locals,
   and repeats already-performed effects on replay.

## Consequence for the callback design

Monkeypatching is useful as an opt-in interception point for plugins that do
dynamic `gdb.execute` lookups.  It is not a complete compatibility boundary,
because captured references bypass it.  More importantly, throwing a
"suspend" exception and replaying commands cannot preserve an arbitrary plugin
stack.  A resumable design has to retain the live Python frame (for example by
transforming cooperating code into a generator/state machine), or execute the
callback without unwinding that frame by some other mechanism.

## Real GEF smoke

The separate optional smoke sources an unmodified real GEF fixture, then
intercepts a harmless synchronous command with a known nested call:

```console
$ python3 tests/dap/experiments/execute_intercept_gef_driver.py --require
PASS: GDB 15.1 sourced GEF f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01; intercepted ['history -n', 'show commands 0', 'show commands 0'] on one thread
```

The fixture was `/home/ctf/bata24-gef/gef.py`. `history -n` returned normally
with an empty `str`. The outer dispatch was observed at wrapper depth zero and
both GEF-internal `gdb.execute("show commands 0", to_string=True)` calls at
depth one, all on the same OS thread. The driver skips when the optional
fixture is missing unless `--require` is supplied.
