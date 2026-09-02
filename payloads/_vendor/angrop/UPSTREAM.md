# Vendored angrop provenance

- Upstream repository: <https://github.com/angr/angrop>
- Baseline commit: `e7c3c1edfc4c25887f5017544f7dd46505795cce`
- Upstream package version: `9.2.13.dev0`
- Upstream `angrop/` Git tree: `205e6c012e018765ae9881c7c4232e0abe6da84c`
- Patched Python-source SHA-256: `4f196ded3957cfb8949862af2df0f65ac232b26fc3f3fbf36abb5f881e34927a`
- Vendored on: 2026-08-05
- License: BSD 2-Clause; the unmodified upstream text is retained in
  [`LICENSE`](LICENSE).

The Python sources in this directory were initially copied byte-for-byte from
the upstream Git tree identified above. Upstream build metadata, tests, and
repository automation are not part of the runtime copy. Project-specific
patches applied after vendoring are changes relative to this recorded baseline
and remain reviewable in pwnc's version history.

The patched-source digest hashes every `*.py` file in sorted relative-path
order as `path + NUL + contents + NUL`, starting from an empty SHA-256 state.
It excludes this ledger and the license, so either document can be updated
without creating a circular digest.

Pwnc embeds the sources as `payloads._vendor.angrop` so direct-checkout and
installed-wheel imports cannot accidentally resolve an unrelated external
`angrop` distribution. Its runtime dependencies are installed through pwnc's
optional `rop` extra.

## Local patches

### Namespace isolation

`angrop_cli.py`'s absolute `import angrop` was replaced by a relative import of
`.rop`, and its analysis construction now indexes angr's factory with that exact
embedded class. The upstream process-global
`register_analysis(ROP, "ROP")` call was removed: pwnc resolves the embedded
`ROP` class directly and asks angr's analysis factory to instantiate that exact
class. Importing pwnc therefore cannot overwrite another package's named `ROP`
analysis registration, nor can a foreign registration redirect pwnc's backend.

### Function-call correctness

`chain_builder/func_caller.py` retains the return-address slot and stack
arguments for a terminal (`needs_return=False`) function call. The upstream
baseline returned immediately after the function address and therefore lost
all cdecl arguments; real i386 execution exposed this as `exit(42)` receiving
zero. Register-argument terminal calls are unchanged.

The same function caller canonicalizes register-return-address aliases through
archinfo before passing them to angrop's register setter. In particular,
angr's AArch64 calling convention names the return register `lr`, while
archinfo and angrop's gadget model expose the same register as `x30`. Returning
AArch64 calls no longer fail solely because `lr` is unknown to the register
setter; synthesis still requires a gadget set which can preserve and later set
`x30` independently. Architectures whose convention names are already
canonical are unchanged.

### Callback-driven multiprocessing waits

`gadget_finder/__init__.py` replaces both the blocking first-phase
`imap_unordered()` iterator and the upstream second-phase 100 ms polling sleep
with batched asynchronous callbacks and `threading.Condition` deadlines.
Successful callbacks notify the waiter immediately; the same overall deadline,
late-stage stall deadline, and worker-death stall behavior remain, using
monotonic time.

### Import and logger isolation

Importing the embedded package no longer disables Python's integer-string
conversion limit process-wide. Gadget-finder construction also no longer
changes the process-global angr and pyvex logger levels. Worker-only formatter
cleanup remains local to multiprocessing children. The four upstream logger
names hard-coded under the top-level `angrop` namespace now derive from
`__name__`, preventing collisions with an independently installed package's
logging configuration.

### SimState plugin isolation

`rop_utils.make_initial_state` serializes its temporary replacement of angr's
process-global default symbolic-memory plugin and restores the exact previous
plugin in a `finally` block, including when state construction fails.

All other baseline Python sources are unchanged.
