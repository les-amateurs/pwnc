# Teemo architecture

Teemo turns Binary Ninja analysis into a separate ELF debug object that GDB can
load without modifying the analyzed binary.

```text
Binary Ninja BinaryView
        |
        | Python API
        v
versioned Teemo IR (JSON) ----> generated pseudocode source files
        |
        | validated input
        v
Rust DWARF emitter (gimli + object)
        |
        v
relocatable ELF debug object
        |
        | add-symbol-file, using the inferior's section addresses
        v
GDB
```

## Ownership boundaries

- The Binary Ninja plugin owns analysis. It resolves Binary Ninja types,
  associates machine instructions with rendered HLIL lines, derives lexical
  scopes, and describes variable locations only where the analysis supports
  them.
- The IR is the compatibility boundary. It contains no Binary Ninja Python
  objects, temporary paths, or GDB runtime addresses. The schema is versioned
  independently of the plugin and emitter.
- The Rust emitter owns DWARF and ELF correctness. It validates the complete IR
  before writing output, translates canonical register names for the selected
  architecture, and emits relocations, ranges, line tables, and location lists.
- The GDB client owns the runtime load bias, section-address discovery, atomic
  symbol-file replacement, and synchronization lifecycle.

## Address model

Every IR address is a link-time virtual address from the BinaryView. An address
may name its containing section. When it does, the emitter converts it to a
relocation against that ELF section plus `value - section.address`. Address
ranges are half-open (`start <= pc < end`).

The extractor must reject a section-relative address outside its section. It
may retain an absolute address only for targets that genuinely do not belong to
an ELF section. Absolute addresses are unsuitable for rebased PIE code and are
reported as a diagnostic.

The GDB client computes runtime addresses independently and supplies them to
`add-symbol-file`. The IR and generated debug object therefore remain stable
across ASLR runs.

Automatic routing identifies GDB's main executable by canonical path and then
GNU build ID. Explicit `--target` routing instead identifies the requested ELF
by those keys and deliberately ignores the GDB-main identity; a positional
manifest is authoritative as well. This selection mode is retained by live
subscriptions. A manually selected ET_EXEC has zero bias, while a PIE that is
not the current inferior requires an explicit runtime bias.

## Pre-export analysis pipeline

The plugin runs one combined pass before it snapshots the BinaryView. Its
ordering is part of the analysis contract:

1. establish a settled function baseline, optionally including orphan
   recovery;
2. bootstrap missing analysis-owned signatures on exact recognized
   printf-family imports/PLT functions and reanalyze their callers;
3. recognize and annotate stack-canary storage after that caller IL rebuild;
4. analyze format call sites and infer forwarding wrappers on the refreshed
   IL;
5. create IR diagnostics and reconcile Teemo-owned auto tags;
6. extract and validate the IR.

When orphan recovery is disabled for a settled live generation, the pipeline
does not repeat the initial wait. Canary and signature mutation stages each
batch their changes and own at most one subsequent wait. The coordinator never
adds a redundant settle between stages.

### Orphan recovery

Teemo performs orphan recovery before it snapshots the BinaryView into IR. The
pass is conservative and bounded rather than a second general-purpose linear
sweep:

1. Explicit export first waits for pending Binary Ninja analysis. A settled
   live event may reuse the already complete analysis state.
2. Teemo indexes physical `.got*`/`.igot*` ranges, `.plt*`/`.iplt*` ranges,
   import-address symbols, and imported/library-function destinations. It then
   subtracts all existing function ranges from non-writable executable ELF code
   sections.
3. It decodes each remaining gap using the associated Binary Ninja
   architecture. Leading padding is skipped and undecodable bytes break
   islands. A candidate needs a direct call or tail branch to a PLT/import
   destination, or an LLIL constant-pointer/external-pointer node into a
   GOT/import slot, and must terminate in a return or import tail-call. A plain
   integer is not address evidence, and a non-import unconditional transfer
   ends the byte-linear island.
4. Candidate starts are batched through
   `BinaryView.add_function(..., auto_discovered=False)`, followed by one
   analysis wait. Despite the flag name, `auto_discovered=False` makes a seed
   with no incoming analysis edge an analysis root. It is not the persistent
   user-function operation: Teemo never calls `create_user_function`, and these
   roots do not carry user annotations.
5. Binary Ninja's CFG is authoritative. Teemo rejects a root if analysis was
   skipped, the function is too large, it has no ranges/basic blocks/LLIL, any
   analyzed range escapes the original gap, the decoded terminal is absent, or
   no analyzed basic block contains still-valid, re-decoded import evidence.
   Rejected roots are removed with reference updates and analysis settles once
   more before extraction.

The prepass snapshots the original function identities and never removes an
existing or concurrent user function. If adding or validating speculative
roots raises, it removes only the roots Teemo created, settles analysis, and
aborts publication; an incomplete rollback is surfaced as an error. A
successful pass may also expose ordinary cascaded auto-discoveries from Binary
Ninja; those are reported separately.
Accepted roots claim their ranges, so subsequent passes find no duplicate
candidate and are idempotent.

Default limits are 16 MiB scanned across all gaps, 64 KiB for one candidate, and
256 candidates. An overlong island is ineligible; exhausting the global byte or
candidate-count budget stops the remaining scan and marks the report as
truncated. The design intentionally misses import-free, syscall-only, and
internal-only functions; indirect imports without a recoverable GOT constant;
functions without a recognized return/import tail-call; writable or
ambiguously classified code; and work beyond the caps. On variable-length
architectures especially, requiring import evidence and post-analysis gap
containment is the guard against decoding embedded data as functions.

Explicit exports always run recovery. Enabling live export does the same for
its initial generation. Later live operation tracks a separate discovery-dirty
bit: byte, segment, section, rebase, and symbol notifications request another
pass, as does function removal. Function additions/updates and type or
data-variable notifications only request a settled export. Recovery-triggered
analysis can therefore cause at most one converging follow-up pass rather than
an unbounded rescan loop.

### Canary enrichment

Canary matching is structural and operates on non-SSA MLIL without retaining
Binary Ninja objects in its reports. Linux x86-64 requires a pointer-sized load
from `fsbase + 0x28`; Linux i386 requires `gsbase + 0x14`. The containing
function must also reference the exact nonzero `__stack_chk_fail` or
`__stack_chk_fail_local` symbol, or contain a structural compare/XOR/subtract
between the saved value and a fresh guard load. The first qualified saved value
is given the auto name `CANARY`.

On x86, the register-backed TLS base is also given the auto name `tcb` and the
stable auto-defined type `tcbhead_t *`. Separate stable type IDs describe the
glibc x86-64 and i386 layouts, whose `stack_guard` fields are at `0x28` and
`0x14`. `define_type`, `create_auto_var`, `is_type_auto_defined`, and
`is_var_user_defined` form the ownership boundary: an existing user type,
claimed name/ID, user variable, or unavailable ownership API makes the pass
skip that mutation rather than overwrite persistent analyst intent.

Linux ARM/AArch32 and AArch64 use exact nonzero `__stack_chk_guard` symbol
addresses and accept constant, external-pointer, and `MLIL_IMPORT` load forms.
They receive `CANARY` only; no TCB type or TLS-base variable is invented.
One batch analysis wait occurs only when the pass creates an auto type or
variable, and repeating the pass is idempotent.

The pass does not attempt generic canary discovery. Non-glibc layouts, custom
offsets, stripped global guards without symbol evidence, unfamiliar compiler
lowerings, and functions without failure-call or structural-check evidence are
expected conservative misses.

### Format signatures, analysis, and tags

Format resolution uses an immutable exact-name registry for narrow, wide,
fortified, syslog, and common glibc alias families. Only ELF version/PLT
decorations are normalized. A callee may be proven by a direct symbol, an
import, a bounded PLT-to-import-slot relation, or a complete finite indirect
set whose members agree on format position, character width, and ultimate
callee. An unresolved member or disagreement makes the call ineligible.

Before call analysis, the bootstrap stage examines only exact recognized
external/import/PLT functions. If Binary Ninja exposes too few parameters, it
uses `Function.set_auto_type` to install a minimal `__teemo_printf_like`
prototype sufficient to expose the format argument (and a `va_list` placeholder
where required). Ordinary local implementations and every function with
`has_user_type` are skipped. Changed imports mark their callers for update,
code-reference callers are queued for reanalysis, and the view settles once if
and only if an auto signature changed.

Wrapper inference iterates parameter-forwarding evidence to a fixed point. A
function is considered printf-like only when recognized edges agree on one
forwarded parameter and character width; nested wrappers retain their ultimate
callee names. Conflicting evidence is not guessed. The default cap is eight
rounds, after which wrapper inference returns no wrappers and records a
localized truncation issue.

Format-origin classification is a three-state proof lattice:

- `read_only` requires a complete finite address set and, for every member, a
  readable non-writable segment, character-width alignment, readable bytes,
  and a NUL code unit within the bounded read;
- `writable` includes stack-backed formats and any finite set with at least one
  writable-segment member;
- `unknown` covers incomplete/over-cap value flow and every failure to prove
  the read-only conditions. It is not equivalent to writable and is not a
  claim of exploitability.

The default proof caps are 16 indirect alternatives, 4 KiB read from one
format address, 256 bytes for a containing PLT function, and a 32-byte PLT
fallback when no containing function exists. Over-cap evidence fails closed to
unknown or a diagnostic. The analyzer establishes storage provenance only; it
does not parse conversion directives or prove attacker control.

Tag synchronization is a projection of the current report into three visible
auto tag types: **Teemo format writable** (`⚠`) and **Teemo format unproven**
(`?`) are address tags on call instructions, while **Teemo printf-like** (`%`)
is a function tag on inferred wrappers. They appear in Binary Ninja's normal
disassembly/IL and tag-list UI. Synchronization adds current and removes stale
Teemo-owned auto tags. It enumerates no user tags for removal, even if a user
tag shares a Teemo tag type, and never touches unrelated auto tag types.

### Failure boundary

Orphan recovery is the baseline integrity boundary: an exception or incomplete
rollback aborts publication. Canary, signature, format, diagnostic-conversion,
and tag stages are optional enrichments. Their exceptions and localized issues
become stable Teemo IR diagnostics, and independent later stages continue when
their inputs remain available. A failed format analysis deliberately skips tag
reconciliation instead of treating failure as an empty report and deleting
previously valid auto tags.

## Live notification model

`current.json` is the authoritative, atomically replaced generation pointer.
Live GDB clients bind private `AF_UNIX/SOCK_DGRAM` endpoints and publish
subscriber descriptors under the matching per-view state directory. Binary
Ninja sends a small view/epoch wakeup only after the new pointer and immutable
generation are durable. The GDB watcher blocks in `select()` on the datagram
socket and a shutdown socketpair, then uses `gdb.post_event()` so all symbol
operations remain on GDB's event thread.

The datagram never supplies artifact paths or debug data; GDB always rereads
and validates `current.json`. Registering the socket before an immediate
catch-up refresh closes the startup race, while queued datagrams coalesce
bursts. Sends are nonblocking, so a full receiver queue drops a redundant hint
rather than delaying publication. Notifications happen before best-effort
retention cleanup. Multiple GDB processes receive independent notifications.
PID start times, private directories, socket ownership checks, and
stale-descriptor cleanup prevent PID reuse or abandoned endpoints from
affecting publication.

## Publication and performance model

A generation is extracted and emitted under a hidden staging directory. The
emitter materializes source files there while recording their eventual
committed directory in DWARF. Teemo synchronizes the completed tree once,
renames it into `generations/<epoch>`, synchronizes the parent, and atomically
replaces `current.json`. No incomplete generation is visible under its epoch
name, and no second whole-tree synchronization is required.

Live export is event-driven and uses Binary Ninja's notification barrier as a
350 ms quiet-period debounce; it contains no sleeping or periodic polling.
Each settled publication is still a complete snapshot. Extraction caches AST
ancestry, assigns instruction ranges to containing scopes in one inverted
pass, refreshes parameter-register dataflow only at basic-block entries and
register writes, and partitions competing locations with a sweep line. Phase
timings are logged so large-binary bottlenecks can be measured independently
of analysis wait time.

## Variable truthfulness

A lexical scope and a storage lifetime are different things:

- A scope says where a name is visible and is represented by a subprogram or
  `DW_TAG_lexical_block` and its ranges.
- A location says where the value can be recovered for a particular PC and is
  represented by an expression or location list.

Teemo never extends a register value merely to make a variable printable. Gaps
or ambiguous value flow are emitted as unavailable ranges. Stack variables may
have long-lived storage while still being attached to a narrower lexical
scope. Shadowed variables receive distinct stable IDs and DIEs.

## Initial compatibility contract

- Binary Ninja: 5.2.8722 container harness at
  `/home/ctf/binja-mcp-workspace/binja-mcp-full/test-auto`.
- GDB: 13 or newer; development validation uses GDB 15.1 and
  `gdb-multiarch`.
- Object format: little- or big-endian Linux ELF where supported by the target.
- Required architectures: x86-64, i386, ARM/AArch32, and AArch64.
- DWARF: version 5, 32-bit section offsets, target-sized addresses.

No MCP implementation is part of the plugin or its validation path.
