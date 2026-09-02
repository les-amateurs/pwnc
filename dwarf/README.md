# Teemo: Binary Ninja analysis in GDB

Teemo converts Binary Ninja analysis into a GDB-loadable ELF/DWARF companion
without modifying the analyzed binary:

```text
Binary Ninja HLIL/MLIL/LLIL
          -> versioned typed JSON IR
          -> Rust ELF/DWARF emitter
          -> add-symbol-file in GDB
```

The generated debug information includes decompiler-derived source text,
machine-address-to-HLIL line records, functions, lexical blocks, arguments,
locals, globals, labels, types, declarations, and PC-ranged variable
locations. The initial target is Linux ELF on x86-64, i386, ARM/AArch32, and
AArch64, for both PIE and non-PIE executables.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the address model, component
boundaries, and variable-location truthfulness rules.

## Requirements

- Binary Ninja 5.2 or newer. The pinned compatibility harness uses 5.2.8722.
- Python 3.11 or newer for tests and the standalone GDB loader helpers.
- Rust/Cargo to build `teemo-dwarf`.
- GDB 13 or newer; GDB 15.1 and `gdb-multiarch` are used in development.
- `clang`, LLD, `readelf`, `llvm-objdump`, `llvm-dwarfdump`, and QEMU user-mode
  emulators for the full cross-architecture test matrix.

The Binary Ninja plugin has no RPyC server and no MCP dependency. GDB and
Binary Ninja communicate through immutable artifact generations and one
atomically replaced manifest pointer.

## Build and test

From the repository root:

```sh
make -C dwarf emitter
make -C dwarf test
```

The full test target runs ordinary extraction/IR tests, Rust emitter tests,
native GDB tests, and compiled PIE/non-PIE fixtures for all four required
architectures. Cross-architecture runtime tests start each binary under QEMU,
let GDB derive its load bias, stop on generated source lines, and inspect
available and unavailable variable ranges.

Real Binary Ninja validation uses only the approved container harness at
`/home/ctf/binja-mcp-workspace/binja-mcp-full/test-auto`:

```sh
python3 dwarf/tests/run_binja_harness.py --build
```

The probe checks the exact core version, user-plugin registration, public type
mutation APIs, and real extraction on all four target architectures. It also
verifies idempotent orphan recovery, x86 TLS and ARM global canary annotations,
format-signature bootstrap, writable/unknown format classifications, inferred
wrappers, and Teemo-owned auto tags without persistent user annotations. It
requires useful HLIL lines, nested scopes, arguments, locals, globals, seeded
type kinds, and available variable locations before validating the IR and
running DWARF emission, `llvm-dwarfdump --verify`, and `readelf`. It exits with
status 77 when its command-line fallback can identify an absent or invalid
license; GUI startup failures are reported as test failures. Replace
`test-auto/inject/license.dat` (or `license.txt`) with a valid license and
rerun; license contents are never printed. The pinned image is Personal
edition, so the runner opens the fixtures in the Xvfb-backed GUI and submits
the probe through a test-only auto-loaded GUI helper plugin instead of
attempting unsupported headless analysis. The runner does not depend on window
placement, keyboard focus, synthetic mouse clicks, or the Python console.

The same licensed GUI harness can analyze a real challenge binary without the
fixture-only type seeding or assertions:

```sh
python3 dwarf/tests/run_binja_harness.py \
  --binary /absolute/path/to/challenge \
  --timeout 600
```

This generic mode still runs orphan recovery, canary and format analysis, tag
synchronization, IR extraction/validation, DWARF emission, and the available
external DWARF validators. Its JSON result reports recovered/rejected orphan
addresses, canary matches, printf-family calls/findings/wrappers, tag changes,
diagnostic counts plus a bounded detail sample, and document
function/line/type counts. The complete diagnostics remain in the validated IR.
`--binary` is repeatable; omitting it retains the original four-architecture
fixture matrix unchanged.

## Install

The defaults install the Binary Ninja plugin into
`~/.binaryninja/plugins/teemo`, including its release emitter, and the GDB
scripts into `~/.local/share/pwnc-teemo/gdb`:

```sh
make -C dwarf install
```

Override `BINJA_PLUGIN_DIR` or `PREFIX` when needed:

```sh
make -C dwarf install BINJA_PLUGIN_DIR=/custom/binaryninja/plugins/teemo PREFIX=/opt/teemo
```

Restart Binary Ninja after installing or updating the plugin.

## Explicit refresh workflow

1. Open an ELF in Binary Ninja and let analysis settle.
2. Run **Teemo → Export or refresh GDB debug info**. Teemo first performs its
   bounded orphan → format-signature → canary → format-analysis/tag prepass.
   Binary Ninja shows the resulting automatic names and tags, logs
   recovery/annotation counts, and logs the absolute `current.json` path.
3. In GDB, load the commands and refresh the matching executable:

```gdb
file ./program
source ~/.local/share/pwnc-teemo/gdb/teemo_gdb.py
teemo-refresh /absolute/path/to/current.json
teemo-status
```

If neither a manifest nor `--target` is given, `teemo-refresh` identifies GDB's
current executable and searches `$TEEMO_STATE_DIR` (default
`~/.cache/pwnc-teemo`) for an exact binary-path or build-ID match. `--bias
ADDRESS` overrides automatic rebasing, and `--force` reloads the same epoch.
`teemo-unload` removes the generated symbols.

To select a Binary Ninja view independently of GDB's current executable, name
the analyzed ELF instead of its manifest:

```gdb
teemo-refresh --target /absolute/path/to/program
```

`--target` searches the same state directory by exact path and then by the
ELF's GNU build ID, so a renamed copy still finds the right view. A positional
`current.json` is also an authoritative manual selection. These two forms
bypass only the GDB-main identity check; architecture and artifact validation
still apply. They are mutually exclusive on one command line.

For a readable, manually selected non-PIE, the omitted bias is zero. If a
positional manifest's original ELF is unavailable, pass `--bias` explicitly.
If the selected PIE is also GDB's current executable, normal runtime rebasing
remains available. Otherwise its runtime placement is unknowable from the
current inferior, so pass it explicitly:

```gdb
teemo-refresh --target /absolute/path/to/program-pie --bias 0x555555554000
```

Published generations are ordinary immutable files. Refresh and manual
selection continue to work when Binary Ninja and its plugin are not running;
only live publication notifications require an active exporter.

For a local running PIE, Teemo derives the bias by matching `/proc/PID/maps`
against the ELF `PT_LOAD` segments. For remote targets such as QEMU's GDB stub,
it falls back to GDB's relocated entry point. A stopped/running inferior is
therefore required for automatic PIE rebasing.

## Live synchronization

Live mode remains explicit on both sides:

1. Run **Teemo → Enable live export** in Binary Ninja.
2. Run either `teemo-live on /absolute/path/to/current.json` or
   `teemo-live on --target /absolute/path/to/program` in GDB.

Binary Ninja coalesces analysis notifications and publishes only a complete,
settled generation. Each live GDB program space binds a private Unix datagram
socket and registers it under the view state. After atomically replacing
`current.json`, Binary Ninja sends a nonblocking epoch wakeup to every
subscriber before retention cleanup. A wakeup may be dropped when a receiver
already has a full queue because queued epochs are only hints. GDB blocks in
`select()` rather than polling; the socket thread posts work onto GDB's event
thread, which rereads the authoritative manifest and
transactionally swaps symbol files. If loading a new debug object fails, the
previous generation is restored. Lease files prevent a generation in use by
GDB from being removed by retention cleanup.

The initial live export runs orphan recovery. Later live exports rerun it when
bytes, sections, segments, the view base, or import symbols change, or when a
function is removed. Function additions/updates and type/data-variable
notifications still produce settled generations without repeatedly rescanning
unchanged executable bytes. Canary and format enrichment run for every
generation; only the more expensive orphan scan is gated by that dirty state.

A target-based live subscription stays pinned to that view even when GDB's
main executable is different. The same manual PIE `--bias` rule applies to
`teemo-live on`.

Use `teemo-live off` before changing to an unrelated BinaryView. Closing GDB
also removes its leases, subscriber descriptor, and socket.

## Artifact and IR layout

By default each BinaryView is keyed under `~/.cache/pwnc-teemo/<view-id>/`:

```text
current.json
generations/<epoch>/
    manifest.json
    teemo-ir.json
    teemo.debug
    teemo.sources/...
leases/...
subscribers/...
```

`current.json` is replaced atomically only after extraction, strict IR
validation, source materialization, and DWARF emission all succeed. Generation
directories are built completely under a hidden staging name, synchronized
once, and renamed into place before publication. The emitter records the final
committed source path in DWARF even while materializing files in staging.
Generation directories are immutable after publication. The compatibility boundary is
documented by `schema/teemo-ir-v1.schema.json`; the Rust emitter independently
deserializes and validates the same contract.

Set `TEEMO_STATE_DIR` to move the artifact root and `TEEMO_DWARF` to select a
specific emitter executable. Live sockets use `$XDG_RUNTIME_DIR/pwnc-teemo`
when available and otherwise `/tmp/pwnc-teemo-<uid>`; `TEEMO_RUNTIME_DIR`
overrides that private runtime directory.

## Analysis behavior and limits

The combined pre-export pipeline has a fixed order: establish a settled
function baseline (with orphan recovery when requested), bootstrap missing auto
signatures for recognized format imports/PLT stubs and reanalyze affected
callers, annotate canaries on the rebuilt IL, analyze format calls and wrappers,
reconcile auto tags, and only then extract IR. There is one owner for the
baseline wait; signature and canary changes are separately batched and each settle at most
once. Orphan recovery and rollback are fail-closed and abort publication.
Canary, signature, format, diagnostic, and tag failures are fail-soft and are
included in the exported IR diagnostics so an optional security pass cannot
hide otherwise valid debug information.

### Orphan recovery

Before an explicit export, Teemo scans executable code-section gaps that no
existing Binary Ninja function owns. It skips writable code and GOT/PLT sections
themselves. A decoded island is considered only when it both:

- directly calls or tail-branches to a PLT/IPLT or imported/library-function
  target, or exposes a GOT/IGOT or import-slot address as an LLIL
  constant-pointer/external-pointer node; and
- ends in a recognized return or an import tail-call within 64 KiB.

Candidates are added in one batch with
`BinaryView.add_function(..., auto_discovered=False)` and analyzed before any IR
is extracted. Here `auto_discovered=False` makes an otherwise unreferenced seed
an analysis root; it does not mean Teemo created a persistent user function.
Teemo does not call `create_user_function` and the recovered function has no
user annotation. A candidate is removed again if analysis is skipped, becomes
too large, has no ranges/basic blocks/LLIL, escapes its original unclaimed gap,
or its analyzed CFG does not contain the import evidence. If analysis or
validation raises, newly introduced roots are rolled back and no generation is
published. Existing functions are never removed.

One pass scans at most 16 MiB, considers at most 64 KiB for one candidate, and
creates at most 256 candidates. The log reports scanned bytes, candidates,
accepted and rejected roots, cascaded Binary Ninja discoveries, and whether a
cap truncated the scan. Accepted functions are excluded from future gaps, so
repeating the pass is idempotent.

These requirements intentionally miss some real code. Orphans without direct
GOT/PLT/import evidence, syscall-only and internal-only helpers, unresolved
indirect imports, functions without a recognized return/import tail-call,
writable or ambiguously classified code, oversized candidates, and candidates
beyond the global scan/count caps are not recovered automatically. This
conservative bias avoids turning embedded executable data into GDB functions;
define a function manually in Binary Ninja when stronger analyst evidence is
available.

### Stack-canary annotations

For Linux x86-64, Teemo matches pointer-sized MLIL accesses to
`fsbase + 0x28`; for i386 it matches `gsbase + 0x14`. It requires the TLS guard
load plus either an exact nonzero `__stack_chk_fail` or
`__stack_chk_fail_local` reference, or a structural reload-and-check. A match
gets an analysis-owned local named `CANARY`; the x86 TLS base becomes `tcb`
and receives a stable auto-defined glibc `tcbhead_t` type.

Linux ARM/AArch32 and AArch64 instead match exact symbol-backed
`__stack_chk_guard` global loads, including `MLIL_IMPORT`, and add only the
`CANARY` local. They never receive a fabricated x86-style TCB. Teemo uses auto
type/variable APIs throughout. It will not replace a user variable, a user
`tcbhead_t`, or a conflicting type ID, and uncertain ownership causes the
annotation to be skipped. `CANARY` and `tcb` are visible in Binary Ninja's
decompiler/IL variable views and `tcbhead_t` in the Types view.

The match is deliberately ABI specific. Alternative libc offsets, custom
guards, stripped ARM globals, unrecognized compiler IL, and functions lacking
failure-call or structural-check evidence can be missed. Canary annotations
are batched into one analysis wait only when something changes and are
idempotent on later exports.

### Format-string analysis and automatic tags

Teemo's exact-name registry covers common narrow, wide, fortified, alias, and
syslog printf families. It can resolve direct/import symbols, bounded PLT
stubs, and complete finite indirect target sets. Freestanding imports may not
have enough parameters in Binary Ninja to expose the format argument, so Teemo
first uses `Function.set_auto_type` to install a minimal analysis-only
prototype on exact recognized import/PLT functions. It does not type ordinary
local implementations, never overwrites a user type, marks/reanalyzes callers,
and settles once only if an auto signature changed.

Wrapper inference follows an unambiguous parameter forwarded into the same
format position and character width, iterating to a fixed point so nested
printf-like wrappers are covered. Conflicting forwarding paths are rejected.
The result is visible immediately in Binary Ninja through reversible,
Teemo-owned auto tags:

- **Teemo format writable** (`⚠`) appears at a call whose format is stack
  storage or has any possible address in a writable segment.
- **Teemo format unproven** (`?`) appears at a call whose format is not
  completely proven read-only. Unknown means insufficient proof, not proven
  writability or exploitability.
- **Teemo printf-like** (`%`) appears on an inferred wrapper function and
  identifies its forwarded parameter and ultimate family.

The two risk tags are address tags on call instructions in disassembly/IL; the
wrapper tag is a function tag. All are also available in Binary Ninja's normal
tag list/filter UI. Synchronization removes stale Teemo auto tags but never
removes a user tag (even one using a Teemo tag type) or an unrelated auto tag.
The same writable and unproven findings are added to `teemo-ir.json` as
diagnostics.

Read-only is a positive proof: every address in a complete finite set must be
readable, non-writable, aligned for its character width, and NUL-terminated
within the read bound. One writable alternative makes the result writable.
Incomplete or over-cap value flow, missing mapping/read evidence, null or
negative pointers, wide misalignment, or a missing bounded terminator remains
unknown. The analyzer proves storage provenance only; it does not parse format
directives, prove attacker control, or decide whether a call is exploitable.

Default format caps are 16 indirect targets, 4 KiB read per format, eight
wrapper fixed-point rounds, and 256 bytes per PLT scan (32 bytes when no
containing function bounds the stub). Over-cap evidence is unknown or produces
a localized diagnostic. The orphan caps remain 16 MiB total gap bytes, 64 KiB
per candidate, and 256 candidates.

### Extraction truthfulness

- HLIL addresses are not trusted as instruction ranges. Teemo maps exact
  decoded instruction spans through LLIL-to-HLIL relations and assigns
  statement owners in the normalized HLIL AST. Disjoint mappings receive
  discriminators.
- HLIL constructs form lexical blocks, including disjoint scope ranges and
  shadowed names. A variable's lexical visibility and storage lifetime are
  represented separately.
- Stack storage is normalized to DWARF CFA offsets. Register and spilled
  argument locations are emitted only while Binary Ninja's register/stack
  dataflow still proves they contain the entry value. MLIL SSA def/use data is
  used for proven constant values. Ambiguous or unknown intervals are explicit
  unavailable gaps.
- Composite/piecewise locations and arbitrary computed expressions are not yet
  exported. Optimized values without a proven complete location remain
  unavailable.
- Live changes are coalesced for 350 ms, but a settled change still produces a
  complete IR/debug generation and a whole GDB symbol-file swap. Teemo logs
  analysis, extraction, serialization, emitter, durability, notification, and
  cleanup timings for each Binary Ninja publication. Parameter register flow
  is queried at basic-block entries and register-write transitions; scope
  ownership and location partitions use indexed/sweep-line processing rather
  than repeated full scans.
- The extractor currently supports Linux ELF only. Mach-O, PE, core files, and
  non-GDB consumers are outside the v1 contract.
- GNU build IDs are accepted only from a complete `NT_GNU_BUILD_ID` note with
  owner `GNU`. Extraction checks bounded mapped note sections first, then a
  bounded `PT_NOTE` table from the original ELF, and finally bounded mapped ELF
  program headers. This does not shell out or scan an unbounded file/view range.
