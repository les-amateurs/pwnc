# Teemo Binary Ninja plugin

This directory is an installable Binary Ninja Python plugin. It registers
three BinaryView commands:

- **Export or refresh GDB debug info** performs one analysis-complete export,
  including the conservative pre-export passes described below.
- **Enable live export** coalesces analysis notifications and publishes new
  immutable generations.
- **Disable live export** unregisters the notification object for the view.

The Python plugin performs Binary Ninja-specific extraction only. It serializes
the versioned IR, invokes the bundled or configured `teemo-dwarf` executable,
and atomically publishes `current.json`. It never opens a listener or accepts
commands from GDB; after publication it only sends wakeup datagrams to live
GDB subscribers registered in the per-view state directory. Wakeups are
nonblocking hints, and every successful export logs phase timings for analysis,
extraction, emission, durability, notification, and cleanup.

## Automatic pre-export pipeline

Every export runs one ordered prepass before the BinaryView is copied into the
Teemo IR:

1. settle pending analysis and, when requested, recover bounded
   high-confidence orphan functions;
2. seed missing printf-family import/PLT prototypes with auto types and settle
   their callers only if a signature changed;
3. recognize stack-canary storage and add analysis-owned names/types after any
   caller IL rebuild;
4. analyze format-string call sites and inferred forwarding wrappers;
5. convert findings to IR diagnostics and reconcile Teemo-owned auto tags.

The prepass has one owner for the initial analysis wait. Format signature
bootstrap and canary annotations each batch their own changes and wait at most once;
there is no unconditional wait between stages. Orphan recovery is fail-closed:
if its analysis or rollback fails, Teemo does not publish. Canary, format, and
tag enrichment are optional and fail-soft; a localized failure is recorded as
an IR diagnostic while the remaining independent stages and export continue.

## Automatic orphan-function recovery

Before extraction, Teemo searches unclaimed bytes in non-writable executable
ELF code sections for high-confidence functions that Binary Ninja's ordinary
analysis left behind. A candidate must form a decodable instruction island,
contain direct import evidence, and end in either a return or a tail branch to
an import. Import evidence is one of:

- a direct call or unconditional tail branch into a PLT/IPLT section or a
  Binary Ninja imported/library-function symbol; or
- an LLIL constant-pointer or external-pointer node into a GOT/IGOT
  section or an `ImportAddressSymbol` slot.

Teemo batches candidate roots with
`BinaryView.add_function(..., auto_discovered=False)`, waits for Binary Ninja
analysis, and then retains only roots with address ranges, basic blocks, LLIL,
and the original import evidence inside the original unclaimed gap. The
apparently counterintuitive `auto_discovered=False` is required because an
unreferenced function has no incoming analysis edge and must be an analysis
root. This low-level `add_function` use is reversible and does not create a
persistent user function or user annotation; Teemo never calls
`create_user_function`. Rejected roots are removed with reference updates, and
an exception rolls back newly introduced roots before publication.

The default bounds are 16 MiB of scanned executable gaps, 64 KiB per candidate,
and 256 candidates per pass. An overlong island is discarded; exhausting the
global byte or candidate-count budget stops the remaining scan and is reported
in the Binary Ninja log. Accepted functions claim their ranges, so a second
pass is idempotent and does not add them again.

Every explicit export asks the prepass to settle analysis and run recovery. Enabling live
export performs that same initial export. Later live generations rerun recovery
after byte, segment, section, rebase, or import-symbol changes and after a
function is removed. Function additions/updates and ordinary type/data-variable
notifications reuse the already settled function set.

This is intentionally not an exhaustive linear sweep. Teemo can miss functions
without direct GOT/PLT/import evidence, syscall-only or internal-only helpers,
indirect imports whose LLIL does not expose a GOT address, functions without a
recognized return/import tail-call boundary, code in writable or non-code
sections, candidates beyond the caps, and ambiguous instruction streams. These
misses are preferred to manufacturing functions from executable data.

## Automatic stack-canary annotations

On Linux x86-64, Teemo recognizes pointer-sized MLIL loads from
`fsbase + 0x28`; on Linux i386 it recognizes `gsbase + 0x14`. A function is
annotated only when that structural TLS access is accompanied by a reference to
the exact `__stack_chk_fail`/`__stack_chk_fail_local` symbol or by a structural
reload-and-compare/XOR/subtract guard check. Qualified functions receive an
auto local named `CANARY`. Teemo also defines the glibc `tcbhead_t` layout under
a stable auto-type ID and names the TLS base auto variable `tcb`.

ARM/AArch32 and AArch64 use the global `__stack_chk_guard` model instead. Teemo
recognizes exact nonzero symbol-backed loads, including Binary Ninja
`MLIL_IMPORT` expressions, and names the saved local `CANARY`. It deliberately
does not invent a TLS base or `tcbhead_t` layout on those architectures.

All of these annotations use `define_type` and `create_auto_var`, never their
user-owned counterparts. An existing user type named `tcbhead_t`, a claimed
stable type ID, or a user-defined variable is left untouched; ambiguous
ownership fails closed. The resulting `CANARY`/`tcb` names are visible in
Binary Ninja's IL and decompiler variable views, and `tcbhead_t` is visible in
the Types view. Changes are batched into at most one canary analysis wait and a
second pass is idempotent.

This pass is intentionally glibc-ABI and structure specific. It may miss
non-glibc TLS layouts, custom guards, stripped ARM binaries without a
recoverable `__stack_chk_guard`, compiler lowering that does not retain the
recognized MLIL shape, and functions without either failure-call or guard-check
evidence.

## Format-string analysis and visible tags

Teemo recognizes exact narrow, wide, fortified, and common glibc alias names
for the printf/syslog families. It resolves direct symbols, imports, bounded
PLT/import-slot stubs, and complete finite indirect target sets. Before this
analysis it may give an otherwise untyped recognized import/PLT function a
minimal auto prototype so Binary Ninja exposes the format argument. Bootstrap
uses `Function.set_auto_type`, skips ordinary local implementations, and always
skips a function with a user type. It marks and reanalyzes callers, then waits
once only when at least one auto signature changed.

The analyzer follows unambiguous forwarding of one function parameter into a
recognized format position to a fixed point, including nested wrappers. A
conflicting parameter/character-width path is not inferred. Findings are
displayed through three automatically maintained Binary Ninja tag types:

- **Teemo format writable** (`⚠`) is an address tag on a call whose format is
  stack-backed or may point into a writable segment.
- **Teemo format unproven** (`?`) is an address tag on a call whose format
  storage cannot be completely proven read-only. This is uncertainty, not a
  claim that the call is exploitable.
- **Teemo printf-like** (`%`) is a function tag on an inferred forwarding
  wrapper and names the forwarded parameter and ultimate family.

Address tags appear on the call instruction in Binary Ninja's disassembly/IL
views; wrapper tags appear on the function and all three are available through
Binary Ninja's normal tag list/filter UI. They are auto tags, not persistent
user annotations. Each pass adds current findings and removes stale tags only
from these Teemo-owned auto tag types. User tags, including user tags using the
same tag type, and unrelated auto tags are never removed.

`read_only` is awarded only for a complete finite address set whose every
target is readable, non-writable, correctly aligned for wide characters, and
NUL-terminated within the bounded read. Any writable alternative makes the
result `writable`. Incomplete value flow, an oversized target set, missing
mapping/read evidence, a null or negative address, wide-character
misalignment, or failure to prove a bounded terminator produces `unknown` and
the **Teemo format unproven** tag. The pass classifies storage provenance; it
does not prove attacker control, interpret conversion directives, or decide
exploitability.

Default format-analysis caps are 16 indirect targets, 4 KiB read for one
format string, eight wrapper-inference rounds, and 256 bytes for one PLT scan
(the no-function fallback is 32 bytes). Exceeding a proof cap yields unknown or
a localized diagnostic rather than optimistic classification.

Build, installation, GDB commands, and operational limitations are documented
in the parent [README](../README.md).
