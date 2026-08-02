# Payload construction

`payloads` is an architecture-aware foundation for constructing Linux exploit
payload bytes. Its target catalog is broader than its payload builders. A
target being recognized means that its word width, byte order, ABI, register
convention, and assembler triple are known; it does **not** mean that every
payload operation is implemented for that target.

The authoritative coverage data is in `payloads.support`. It deliberately
separates three levels:

- `recognized`: target resolution and packing exist, but this capability has
  no builder for the target;
- `implemented`: a builder exists, but no end-to-end QEMU execution test
  covers the pair;
- `qemu-verified`: a builder exists and an opt-in QEMU execution test covers
  the raw result.

Each cell also exposes explicit `recognized`, `implemented`,
`qemu_verified`, and `native_verified` booleans. Native execution is
orthogonal to the three QEMU-oriented levels: a target/capability pair can
carry both QEMU and direct-host evidence. The whole matrix can be serialized
without custom encoders:

```python
import json

from payloads.support import capability_support, support_matrix_data

print(capability_support("mipseb", "command").as_dict())
print(json.dumps(support_matrix_data(), indent=2))
```

The schema is versioned by `SUPPORT_SCHEMA_VERSION`. Consumers should use the
matrix instead of inferring payload support from `SUPPORTED_TARGETS`.
In the matrix, `stager` means the target-native mmap/read/mprotect shellcode;
the callback-driven `PayloadStager` belongs to `arb-executor`.

## Current coverage

The current command, ORW, exit, and RW-to-RX mmap-stager shellcode builders are
implemented for every exact Linux target in the catalog. Raw execution is
QEMU-verified for every variant except little-endian PPC32, whose lowering is
assembly-tested because the supported qemu-user suite has no matching
little-endian 32-bit PowerPC emulator:

| Architecture | Bits | Endian | ABI | Shellcode evidence |
| --- | ---: | --- | --- | --- |
| x86 | 32 | little | i386 SysV | QEMU-verified; native-verified |
| x86-64 | 64 | little | AMD64 SysV | QEMU-verified; native-verified |
| ARM and Thumb | 32 | little and big | ARM EABI | QEMU-verified |
| ARM64 | 64 | little and big | AAPCS64 | QEMU-verified |
| MIPS32 | 32 | little and big | o32 | QEMU-verified |
| MIPS64 | 64 | little and big | n64 | QEMU-verified |
| RISC-V 32 | 32 | little | ILP32 | QEMU-verified |
| RISC-V 64 | 64 | little | LP64 | QEMU-verified |
| PowerPC32 | 32 | big | PowerPC SysV | QEMU-verified |
| PowerPC32 | 32 | little | PowerPC SysV | implemented; assembly-tested |
| PowerPC64 | 64 | big | ELFv1 | QEMU-verified |
| PowerPC64 | 64 | little | ELFv2 | QEMU-verified |
| SPARC32 | 32 | big | SPARC SysV | QEMU-verified |
| SPARC64 | 64 | big | SPARC64 SysV | QEMU-verified |
| s390x | 64 | big | s390x SysV | QEMU-verified |

Symbolic static syscall ROP is implemented for every catalog target, and
symbolic static function calls are implemented except on PPC64 ELFv1 and
SPARC. The opt-in QEMU suite executes the static syscall chains on all 20
runnable target variants and the direct-call chains on all 17 runnable variants
that model direct calls. Because no matching qemu-user emulator is available,
PPC32 little-endian shellcode remains assembly-tested and its ROP builders
remain unit-tested; neither has QEMU execution evidence. Ret2libc
`system(command)` has the same direct-call exclusions; exact-artifact,
live-base chains execute under QEMU on i386 and AMD64, while every other
implemented variant is covered by the exact-identity unit matrix.
Target-generic arbitrary-memory adapters, explicit payload
staging/triggering, and exact-libc call workflows are implemented for every
catalog target and are unit-tested, not QEMU-tested.

On an x86-64 Linux host, a separate opt-in suite executes the command, ORW,
RW-to-RX stager, static syscall ROP, static direct-call ROP, and exact-loaded-
libc ret2libc paths directly in both 64-bit AMD64 and kernel i386 compatibility
mode. These runs do not start QEMU. The native ret2libc fixture also validates
the loaded libc device/inode mappings, independently derives its live base,
and, when host ASLR is enabled, observes address variation across fresh
processes.

## Resolving an exact target

Builders accept a fully resolved `Target`, not a loose architecture string:

```python
from payloads import ABI, Endian, resolve_target

mips_be = resolve_target("mips32", bits=32, endian=Endian.BIG, abi=ABI.MIPS_O32)
amd64 = resolve_target("amd64")
```

Aliases with an endian suffix imply byte order (`mipsel`, `mipseb`, `armeb`,
`ppc64le`). Supplying a contradictory `endian=` raises
`UnsupportedTargetError`; it is never silently overridden. Unsuffixed ARM and
MIPS default to little endian. Unsuffixed PowerPC, SPARC, and s390 default to
big endian. RISC-V is currently little-endian only.

`Target.pack`, `unpack`, and `pack_words` always use the resolved word width
and endian. Packing rejects overflow unless `truncate=True` is requested
explicitly. The target also owns the function-call and syscall register
conventions and stack alignment. Thumb entries set bit zero through
`Payload.entry()`/`Target.function_pointer()`. A big-endian PPC64 ELFv1 symbol
is a function descriptor rather than a raw program counter, so
`Target.function_pointer()` rejects it without a descriptor- and TOC-aware
primitive.

## Read-only ELF and mitigation inspection

`inspect_elf(path)` parses an untrusted artifact without loading or executing
it. The immutable `ELFProfile` binds its findings to the file SHA-256 and GNU
build ID, resolves the exact target, and records PIE/non-PIE, static/dynamic
linkage, static PIE versus shared-object role, GNU-stack NX evidence, RELRO,
LOAD permissions, symbols, and unambiguous GOT/PLT offsets:

```python
from payloads import ExecutionPolicy, inspect_elf

profile = inspect_elf("./challenge")
mitigations = profile.to_mitigations(ExecutionPolicy.QEMU_ELF_PERMISSIONS)

# Supply the page size observed in the actual process/emulator. This proves
# writability for the image-relative slot after RELRO; missing runtime evidence
# or conflicting layouts return False.
puts_got_is_writable = profile.got_slot_writable(
    "puts",
    runtime_page_size=observed_runtime_page_size,
)
```

Profile addresses are ELF virtual values: add the runtime load bias for PIE,
static PIE, and shared objects; use a zero bias for an ordinary `ET_EXEC`.
Missing `PT_GNU_STACK` leaves `profile.nx` unknown, and an `ET_DYN` with no
reliable executable/shared-object discriminator leaves linkage unknown.
`to_mitigations()` rejects either ambiguity unless the caller supplies facts
from the actual runtime/toolchain. The `ExecutionPolicy` is always explicit:
an ELF file cannot establish whether a particular QEMU version ignores guest
execute permissions. Likewise, `PT_LOAD.p_align` is not proof of the runtime
page size, so writability helpers require an observed `runtime_page_size` for
any affirmative answer.

## Command shellcode

`command_shellcode` emits position-independent raw code which performs
`execve("/bin/sh", ["/bin/sh", "-c", command], NULL)`. It does not rely on
pwntools shellcraft or a target libc.

```python
from payloads import command_shellcode, resolve_target

target = resolve_target("mipseb")
payload = command_shellcode("id; uname -a", target)

# Write payload.data into memory satisfying payload.memory, then transfer
# control to the ISA-correct entry (important for Thumb).
load_address = 0x410000
entry = payload.entry(load_address)
```

The command must be non-empty and contain no NUL byte. The generated temporary
stack image is capped at 1792 bytes and aligned for the target ABI. Inspect
`payload.memory` rather than assuming its requirements: the code bytes need an
executable mapping, and the generated command uses writable stack space.
`payload.metadata["requires_instruction_cache_sync_after_runtime_write"]` is
true for ARM/Thumb, ARM64, MIPS, RISC-V, PowerPC, and SPARC. A runtime
arbitrary-write path must perform the platform-appropriate instruction-cache
synchronization before jumping when the environment requires it. It is false
for x86/x86-64 and s390x; s390x has coherent instruction/data caches and does
not require an external cache-flush hook.

### QEMU user-mode semihosting host escape

`qemu_semihosting_command_shellcode` deliberately escapes the guest and asks
QEMU's user-mode semihosting handler to run `SYS_SYSTEM` (`0x12`) on the host.
This is a CTF pwn primitive: it is not guest `execve` shellcode, and the
command is interpreted by the host shell with the privileges and environment
of the QEMU process.

```python
from payloads import qemu_semihosting_command_shellcode, resolve_target

target = resolve_target("riscv64")
escape = qemu_semihosting_command_shellcode("id > /tmp/qemu-host-id", target)
```

QEMU user mode automatically recognizes this architecture-specific trap; the
payload runner must not add `-semihosting` or `-semihosting-config`. The exact
implemented and QEMU-executed matrix is:

| ISA | Bits | Endian variants | Semihosting trap |
| --- | ---: | --- | --- |
| ARM A32 | 32 | little, big | `svc #0x123456` |
| Thumb T32 | 32 | little, big | `svc #0xab` |
| AArch64 | 64 | little, big | `hlt #0xf000` |
| RISC-V | 32, 64 | little | 16-byte-aligned `slli` / `ebreak` / `srai` sequence |

The RISC-V code mapping must satisfy the payload's 16-byte alignment
requirement so the three-instruction signature remains correctly aligned.
Other catalog architectures are reported as recognized but unsupported for
this capability: system-emulation semihosting support does not imply automatic
qemu-user interception.

The verified route is the trap being consumed by QEMU user mode. It is not
native-hardware execution, a guest Linux syscall, or GDB remote file I/O. A
debugger configured to catch or reroute the semihosting breakpoint changes
that route; a GDB stop at the trap is therefore not evidence that this QEMU
host escape executed. The opt-in test uses a host marker file to prove that
QEMU itself handled the command without a semihosting command-line flag.

`orw_shellcode(path, target, max_bytes=0x400, output_fd=1)` emits one
position-independent open/read/write pass. It opens the NUL-free path
read-only, reads at most `max_bytes` once, writes the returned byte count once
to `output_fd`, and exits. It preserves embedded NULs in file data. It is not a
looping file copier: short reads and short writes are not retried. Its stack
image, including the read buffer, shares the 1792-byte cap.

`sendfile_orw_shellcode(path, target, max_bytes=0x400, output_fd=1)` is the
buffer-free alternative. It opens the path and calls
`sendfile(output_fd, opened_fd, NULL, max_bytes)` before exiting. It therefore
needs no writable read buffer, but it still performs a single transfer and
does not retry a short send.

### RW-to-RX stager

`mmap_stager(size, target, input_fd=0, page_size=0x1000)` allocates an anonymous
RW mapping, loops until it has read exactly `size` bytes, changes the complete
mapping to RX with `mprotect`, finalizes the target instruction cache, and
transfers control to the second stage. It never requests a simultaneous RWX
mapping.

```python
from payloads import command_shellcode, mmap_stager, resolve_target

target = resolve_target("arm64")
second_stage = command_shellcode("id", target)
first_stage = mmap_stager(len(second_stage.data), target, input_fd=0)

# Deliver/enter first_stage.data through the original executable-code
# primitive, then send exactly second_stage.data on input_fd.
```

`page_size` is explicit because the runtime page size is not an ISA constant.
EOF or a read error before the exact byte count takes the failure exit. ARM,
AArch64, MIPS, RISC-V, PowerPC, and SPARC stagers perform their
architecture-specific cache maintenance. x86 relies on its coherent
instruction cache; s390x likewise needs no cache flush and emits a serializing
`bcr` before branching. This solves the second-stage W^X transition only: the
first-stage bytes still need an initial executable region or another valid
control-flow path.

### Zig assembler backend

Raw bytes are assembled by `ZigAssembler` by default. It invokes `zig cc` for
the exact target triple, then uses `pyelftools` to extract `.text`; unresolved
relocations are rejected rather than copied into a payload. The backend never
uses pwntools' assembler or shellcraft. Pass
`ZigAssembler("/absolute/path/to/zig")` when `zig` is not on `PATH`.

`LLVMAssembler` remains an explicit backend and the fallback for big-endian
PPC64 ELFv1, which current Zig/LLD cannot emit. On every other catalog target,
the test suite requires Zig's bytes to match the LLVM reference bytes exactly.
Toolchain target support still varies by installation, so recognizing a target
does not itself prove a local compiler can assemble it.

`ld.lld` is not required for normal payload construction. The QEMU tests use
it where it can faithfully wrap the exact raw bytes in a minimal static ELF,
and construct a minimal test envelope directly where it cannot. In particular,
a big-endian PPC64 ELFv1 process enters through a function descriptor rather
than a raw code address. Its test envelope sets the ELFv1 ABI flag, points
`e_entry` at a descriptor, and makes that descriptor name the raw payload code.
Some LLD versions reject ELFv1 or emit an ELFv2 executable instead; such an
executable would not validate the catalog's PPC64 ELFv1 target.

## Libc identity and runtime addresses

Never select offsets from the string `glibc 2.39` alone. Distribution patches,
toolchain choices, and package rebuilds can change symbols and gadgets without
changing the upstream version. `LibcImage.from_file` uses the same single-read,
non-executing ELF inspection path for the exact symbol offsets, target,
SHA-256, and GNU build ID:

```python
from payloads import LibcImage, RuntimeLayout

libc = LibcImage.from_file(
    "./libc.so.6",
    symbols=("puts", "system"),
    glibc_version="2.39",
    distro="ubuntu",
    package_release="0ubuntu8.4",
)
base = libc.base_from_leak("puts", leaked_puts)
system = libc.address("system", RuntimeLayout(libc_base=base))
```

The distro, package release, version, and source path are provenance metadata;
they do not replace the artifact digest. Preserve the challenge's actual libc
file and verify `LibcIdentity.matches()` if bytes may have changed. A
`LibcImage` supplies exact symbol offsets and base arithmetic; the separate ROP
and arbitrary-call builders consume it. `bind_libc_address(libc, offset)` ties
libc-relative strings and gadgets to the same digest so a stock-glibc offset
cannot be mixed accidentally with a distro-patched image. The package does not
discover the remote libc, find gadgets, or leak a base.

`Address` represents an absolute value or an offset in `MAIN`, `LIBC`,
`LOADER`, `STACK`, or a named extra image. PIE/ASLR-relative values require a
matching `RuntimeLayout` base; missing bases raise instead of being guessed.

## Symbolic ret2libc and static ROP

ROP addresses stay symbolic until `ROPChain.materialize(layout)`. This keeps
PIE/main-image and libc-relative addresses separate and applies target word
width, endian, Thumb state bits, and function-pointer rules only after runtime
bases are known.

There is intentionally no universal gadget catalog. A `SemanticGadget`
describes the exact stack words consumed by a gadget from the challenge binary:
which slots populate registers, which slot supplies the next PC/LR/RA, fixed
slots, and clobbers. The chain selector can compose the supplied records, but
it does not disassemble a binary or assert that a gadget exists.

```python
from payloads import RuntimeLayout, bind_libc_address, resolve_target
from payloads.rop import SemanticGadget, build_ret2libc_system

target = resolve_target("x86_64")
# `libc` is a LibcImage loaded from the exact challenge artifact.
pop_rdi = SemanticGadget(
    target=target,
    address=bind_libc_address(libc, pop_rdi_offset, "pop rdi; ret"),
    frame_words=2,
    register_slots={"rdi": 0},
    next_pc_slot=1,
)
chain = build_ret2libc_system(
    libc,
    bind_libc_address(libc, bin_sh_offset, '"/bin/sh"'),
    gadgets=(pop_rdi,),
)
raw_chain = chain.materialize(
    RuntimeLayout(libc_base=leaked_libc_base),
    chain_base=known_overflow_chain_address,
)
```

`build_ret2libc_system` derives `system` only from the supplied exact
`LibcImage`; register ABIs still require suitable caller-supplied semantic
gadgets. i386 uses its real cdecl stack shape. Direct function calls reject
PPC64 ELFv1 (function descriptors/TOC are not modeled) and SPARC32/64 (register
windows and `o7 + 8` return frames are not modeled).

`LibcROPBuilder.from_file()` provides composable libc ORW stages. The path is
required; writable storage is optional because `open` can use path bytes
appended to an x86 chain and `sendfile` needs no transfer buffer. `read` and
`write` require a caller-supplied writable area. File descriptors stay
explicit, so an exploit can lower `open` independently and hardcode the
observed descriptor in a later exfiltration stage:

```python
from payloads import LibcROPBuilder, RuntimeLayout

builder = LibcROPBuilder.from_file("./libc.so.6", b"/flag")
program = builder.compose(
    builder.open(),
    builder.sendfile(1, 3, 0x400),
    builder.exit(),
)
payload = program.lower_pwntools(
    RuntimeLayout(libc_base=leaked_libc_base),
    chain_base=known_chain_address,
).as_payload()
```

Automatic linked lowering deliberately uses pwntools' `ELF`, mitigation, and
`ROP` support only on the live-tested i386 and AMD64 ABIs. Every other direct-
call ABI exposes independently composable `LibcROPStage` objects which lower
through caller-supplied `SemanticGadget` records; no unsupported stack
transition is guessed. `ExactELFAdapter` rechecks the artifact digest before
creating a fresh pwntools object and never accesses process-backed helpers such
as `ELF.libs`, `ELF.maps`, or `ELF.libc`.

Every function-call chain carries a `CallFrame` describing the function-entry
SP offset, required ABI alignment/bias, and emitted mandatory caller area.
`materialize(..., chain_base=...)`, `validate_call_frame()`, and
`validate_entry_sp()` reject a concrete misaligned placement. MIPS o32,
PPC32, PPC64 ELFv2, and s390x caller areas are emitted explicitly; PPC64 ELFv2
also loads `r12` with the global-entry address. A call with `return_to=None`
does not invent a safe return path.

`build_static_call` and `build_static_syscall` use `MAIN`-relative offsets, so
the same descriptions cover non-PIE (`main_base=0` when offsets are virtual
addresses) and PIE once the main base is known. Generic static syscall chains
are modeled for every catalog target, including PPC64 ELFv1, but require exact
caller-supplied register-loading and syscall gadgets plus the correct Linux
syscall number. Static direct calls retain the PPC64 ELFv1/SPARC exclusions.

The opt-in QEMU fixtures materialize builder-produced chains and transfer
control through synthetic gadgets with the documented semantics. Primary x86,
ARM, and AArch64 fixtures place the chain in writable non-executable `.data`;
the remaining minimal raw envelopes embed it as non-writable bytes in their
executable load segment. The static syscall fixtures execute on all 20 runnable
catalog variants. Direct-call fixtures execute on all 17 runnable variants
where calls are modeled; they check function-entry stack alignment and the
MIPS o32, PPC32, PPC64 ELFv2, and s390x mandatory caller areas against an
independent test-owned ABI table at runtime. PPC64 ELFv1 and SPARC therefore
have syscall-only ROP execution evidence, and PPC32 little-endian is
unit-tested only.

Separate i386 and AMD64 fixtures load the host's exact target libc through
QEMU, disclose the actual `system` address and owning mapping base, parse that
same artifact as a `LibcImage`, and execute a late-materialized
`build_ret2libc_system` chain. The test verifies the libc SONAME, the
independently disclosed base, placement in writable non-executable memory,
command output, and the return path. This is live-base and exact-artifact
evidence, not ASLR-variance evidence: the tested QEMU version may choose a
repeatable guest libc base.

## FILE-stream payloads (FSOP)

`FSOP` constructs exact-libc FILE layouts across four explicit axes: the
`stdout`, `stderr`, `stdin`, or owned `heap` stream; `legacy` or `wide`
dispatch; the activation; and the intended jump slot. It serializes the
FILE/wide-data/vtable state needed by the selected route. It does not model a
controlled allocation, controlled free, heap corruption, or the primitive
which installs or activates that state.

The named routes are:

- **Legacy fake primary vtable:** `EXIT` and `FFLUSH_ALL` (`fflush(NULL)`)
  traverse `_IO_list_all` and dispatch `OVERFLOW`; direct `FFLUSH` dispatches
  `SYNC`; `SEEK` dispatches `SEEKOFF` or `SEEKPOS`. A heap/list-triggered
  legacy payload is labelled **House of Orange**, referring only to its FILE
  list-dispatch stage—not to Orange's allocator-corruption setup. `EXPLICIT`
  accepts any intended primary jump slot only with `dispatch_attested=True`.
- **House of Apple 2:** a validated (possibly biased) `_IO_wfile_jumps`
  primary dispatch enters `_IO_wfile_overflow`, which reaches the fake wide
  table's `DOALLOCATE` entry through `_IO_wdoallocbuf`. `EXIT`, `FFLUSH_ALL`,
  direct `FFLUSH`, and `SEEK` select and validate their different primary
  dispatch offsets. A negative bias (the direct-`FFLUSH` and `SEEK` forms)
  must be covered by caller-supplied exact `IOVtableBounds`; the builder does
  not guess the artifact's hidden `__io_vtables` boundaries. Bind debugger or
  debug-symbol offsets with `IOVtableBounds.from_libc_offsets()`.
- **House of Cat:** a validated `_IO_wfile_jumps` primary dispatch enters
  `_IO_wfile_seekoff`; its wide-get-mode switch dispatches the fake wide
  table's `OVERFLOW` (`WOVERFLOW`) slot. The `SEEK` route is
  source-proven for glibc `fseek`'s nonzero mode and supports `SEEKOFF` only;
  automatic wide `SEEKPOS` is rejected. `EXIT`, `FFLUSH_ALL`, and direct
  `FFLUSH` have an ABI-sensitive prototype mismatch and therefore need a
  `DispatchAttestation` naming the call-site evidence and a nonzero
  `seekoff_mode`. Direct `FFLUSH` also has a negative primary-vtable bias and
  therefore needs exact `IOVtableBounds`.
- **Wide explicit slot:** `EXPLICIT` places the callback in any requested wide
  jump slot, but requires `dispatch_attested=True`; the caller owns proof that
  its control-flow path executes that exact `WJUMP` entry.

For example, this builds an exit-triggered House of Apple 2 payload for a heap
FILE and then safely replaces the callback's argument-zero bytes:

```python
from payloads import FSOP, FSOPActivation, FSOPFamily, IOJumpSlot, LibcImage, RuntimeLayout

libc = LibcImage.from_file("./libc.so.6", glibc_version="2.39")
apple = FSOP(
    libc,
    stream="heap",
    family=FSOPFamily.WIDE,
    address=known_fake_file_address,
    storage=known_auxiliary_storage,
).build(
    FSOPActivation.EXIT,
    "system",
    slot=IOJumpSlot.DOALLOCATE,
)
arg0 = b" sh\0" if libc.target.endian.value == "little" else b"sh\0\0"
apple = apple.overlay_arg0(arg0)
writes = apple.writes(RuntimeLayout(libc_base=leaked_libc_base))
```

The FILE pointer is callback argument zero. `overlay_arg0()` and the general
`overlay()` re-run every byte-level execution predicate and reject changes
that break flags, pointer relations, bounds, or protected relocations with
`FSOPOverlayError`; they are composition operations, not unchecked byte
patches. On a sparse standard stream, overlays are restricted to fields the
builder already owns, so a longer arg0 cannot silently overwrite a live lock
or other preserved state. Heap FILEs and auxiliary objects are complete owned placements.
`stdout`, `stderr`, and `stdin` are exact-symbol sparse patches so live locks,
chain pointers, and unrelated state are not accidentally zeroed: use
`writes()` for minimal spans, or give `materialize()` the original FILE bytes
when a complete image is required.

Wide layouts require an exact glibc version because `_IO_wide_data` changed at
glibc 2.30 and `_flags2` became three bytes at 2.41. Legacy fake primary
vtables are accepted directly only before glibc 2.24; newer artifacts require
`allow_vtable_bypass=True`, which is an explicit caller claim that a real
vtable-validation bypass exists. Symbol callbacks and FILE/vtable addresses
stay bound to the supplied `LibcImage` digest until runtime bases are applied.
On PPC64 ELFv1, the callback must be explicitly attested as an `.opd` function
descriptor with `callback_is_descriptor=True`; raw Thumb callback addresses
must already carry the ISA-state bit (exact symbols preserve their recorded
`st_value`).

FILE, wide-data, and jump-table bytes are layout-tested for every repository
architecture and endian variant. This is structural serialization coverage,
not a blanket live-exploit claim. The pinned-sysroot QEMU suite's default
contract runs heap-stream payloads against the full glibc 2.39 lane: House of
Apple 2 through direct `fflush(fp)` and House of Cat through `fseek(fp, ...)`
for all 20 qemu-user-runnable catalog targets. It also covers a glibc 2.23
AMD64 legacy fake-vtable `fflush` route and representative glibc 2.24 and 2.41
wide routes. The distinct native suite runs the two modern routes against the
loaded host glibc in i386 and AMD64 modes.

Those fixtures provide a test-owned heap FILE pointer and invoke `fflush` or
`fseek` directly. They do not prove an allocator corruption, `_IO_list_all`
insertion, exit/flush-all traversal, a standard-stream overwrite, or every
custom dispatch slot. Upstream glibc does not provide PPC32 little-endian, so
that target describes supplied downstream/custom artifacts only and has no
pinned-sysroot QEMU claim. The builder likewise does not claim that a selected
glibc build, call site, lock state, or list insertion is reachable without the
runtime preconditions reported by `FSOPPayload`.

## Arbitrary-read/write adapters and execution

`payloads.arbio` turns challenge-specific memory callbacks into strict,
target-aware operations. Callback addresses are absolute target addresses:

```python
from payloads.arbio import ArbitraryMemory, IOPrimitiveTraits

memory = ArbitraryMemory(
    target,
    read_at=arbread,  # arbread(address, size) -> exactly size bytes
    write_at=arbwrite,  # arbwrite(address, data) -> None or len(data)
    traits=IOPrimitiveTraits(
        read_chunk=0x100,
        write_chunk=8,
        read_alignment=1,
        write_alignment=8,
        write_width=8,
        verify_writes=True,
    ),
)
pointer = memory.read_ptr(pointer_address)
memory.write_ptr(pointer_address, replacement)
```

Transfers are chunked without implicit overreads, padding, or
read/modify/write. Declared address alignment and transfer width are enforced;
short callbacks raise structured errors. `read_ptr`/`write_ptr` use the exact
target word width and endian. Read-back verification requires a read callback,
and `probe()` is disabled unless `invalid_read_safe=True` explicitly says a
bad probe cannot kill or corrupt the target. `ArbitraryMemory.from_bytes_provider`
and `as_bytes_provider()` provide structural adapters for existing
`BytesProvider`-shaped objects. The outward adapter is also a nominal
`pwnc.types.BytesProvider`, so it can be passed directly to `Type.use()`.

Arbitrary read/write is not itself control flow. `PayloadStager` writes a
`Payload` at a caller-selected address and preflights NX/QEMU policy before the
first write. Executing it additionally requires an explicit target-matched
`ControlFlowTrigger`:

```python
from payloads.arbio import CallbackControlFlowTrigger, PayloadStager

stager = PayloadStager(
    memory,
    mitigations,
    make_executable=make_executable,  # optional (address, size) hook
    synchronize_instruction_cache=cache_sync,  # required when metadata says so
)
trigger = CallbackControlFlowTrigger(target, jump_to)
stager.stage_and_execute(
    command_shellcode("id", target),
    shellcode_address,
    trigger,
    verify=True,
)
```

The `make_executable` and cache-sync hooks are exploit primitives supplied by
the caller; the adapter does not synthesize them from arbitrary write. An
already executable region can instead be asserted with
`executable_region=True`. Legacy-all-executable QEMU policy permits the modeled
legacy path. Thumb entry-state adjustment is applied automatically. Staging
alone never invokes code.

For a useful data-only path, `build_shell_command_execve_data` builds a
target-width/endian `execve` argv image at a known writable address, and
`ExecveCallWorkflow` stages it then uses an explicit `FunctionCallPrimitive` to
call `execve` from the exact `LibcImage`:

```python
from payloads.arbio import (
    CallbackFunctionCall,
    ExecveCallWorkflow,
    PayloadStager,
    build_shell_command_execve_data,
)

data = build_shell_command_execve_data("id", target, writable_address)
workflow = ExecveCallWorkflow.from_libc(
    data,
    libc,
    RuntimeLayout(libc_base=leaked_libc_base),
)
workflow.execute(
    PayloadStager(memory, mitigations),
    CallbackFunctionCall(target, call_function),
    verify=True,
)
```

The function-call callback owns the ABI-level call primitive; it is not
derived from the memory callbacks. PPC64 ELFv1 calls require a callback marked
function-descriptor-aware. `GotSystemWorkflow` is an alternative for dynamic
binaries with no/partial RELRO: it writes the command, temporarily replaces a
specified GOT slot with exact-artifact `system`, calls the specified PLT entry,
and restores the original slot in `finally`. It is unavailable on PPC64 ELFv1,
where a GOT function pointer needs descriptor/TOC material rather than a raw
`system` address; use a descriptor-aware explicit call workflow instead.
`from_libc()` requires an explicit `got_slot_writable=` assertion for that
exact slot; use
`profile.got_slot_writable(symbol, runtime_page_size=...)` with a page size
observed from that runtime when an `ELFProfile` is available. It
rejects the strategy before memory I/O for full RELRO, static linkage, or an
unproven slot. Restoration is attempted even after a short/failed overwrite,
but cannot be promised if restoration itself fails, the process exits, the
transport disconnects, or control never returns. None of these callback
workflows has QEMU end-to-end coverage.

## Mitigations and QEMU execute policy

`Mitigations` records PIE, NX, RELRO, dynamic/static linkage, and an explicit
`ExecutionPolicy`. `ELFProfile.to_mitigations()` derives file-backed facts, but
the package does not inspect a live process or infer a QEMU execution policy.

- `ELF_PERMISSIONS` and `QEMU_ELF_PERMISSIONS` mean mapping execute bits are
  respected. Writable storage is not assumed executable. In particular, an
  executable stack (`nx=False`) does not prove that an arbitrary heap, BSS, or
  anonymous staging address is executable.
- `QEMU_LEGACY_ALL_EXECUTABLE` models older/configured user-mode QEMU behavior
  where writable guest memory can be executed despite ELF permissions.
- `UNKNOWN` is conservative: `require_shellcode_path()` requires a known
  executable region or an
  `mprotect`/`mmap`-style permission-changing primitive.

`require_got_overwrite()` permits a dynamic GOT overwrite only with no or
partial RELRO. Full RELRO and static linkage reject it. These checks validate a
chosen strategy; they do not bypass PIE, NX, RELRO, or ASLR by themselves.

Treat legacy-QEMU executability as an observed property of the exact challenge
runtime, not as an architecture property. Newer QEMU configurations commonly
respect guest execute permissions. Even when memory is executable, a payload
whose metadata requests instruction-cache synchronization still needs the
target-specific finalization step after self-modifying or runtime-written code.

### Pinned QEMU execute-permission boundary

The separate version suite fixes one observed boundary to AArch64 linux-user.
Its manifest pins the official [QEMU 7.1.0 source
archive](https://download.qemu.org/qemu-7.1.0.tar.xz), [QEMU 7.2.0 source
archive](https://download.qemu.org/qemu-7.2.0.tar.xz), their SHA-256 digests,
and upstream commit
[`cdf713085131`](https://qemu.googlesource.com/qemu/+/cdf7130851318004e6512dbfdb73156fe59c7a59).
That commit changed user-mode instruction fetch from returning an address
without a permission check to probing `MMU_INST_FETCH` access. It is absent
from 7.1.0 and present in 7.2.0.

The live probe copies an AArch64 `exit(42)` sequence to a fresh anonymous
mapping. With the mapping left RW, QEMU 7.1.0 exits 42 while QEMU 7.2.0 raises
guest `SIGSEGV`; after changing the same mapping to RX, both releases exit 42.
This establishes that exact AArch64 boundary. It does not turn a QEMU version
number into evidence for every target, vendor patch set, or configuration.

There are two deliberately different provenance levels. Binaries selected
through `PWNC_QEMU_VERSION_ROOT` must have a valid adjacent build-provenance
sidecar, so the suite can bind their observed behavior to the pinned source and
recorded build identity. An explicit `PWNC_QEMU_7_1_AARCH64` or
`PWNC_QEMU_7_2_AARCH64` override instead records the external binary's version
banner and SHA-256 and tests its behavior, but does not claim that it came from
the pinned upstream archive or recorded build. The test reports that weaker
origin as `external:behavior-attested`.

## Tests

Run the normal foundation, lowering, assembly, and matrix tests with:

```sh
python3 -m unittest discover -s payloads/tests -v
```

Assembly tests skip when `llvm-mc` is unavailable. General end-to-end QEMU
execution is opt-in because it needs LLVM, LLD, Zig, and the complete set of
qemu-user emulators claimed by that matrix:

```sh
PWNC_QEMU_TESTS=1 python3 -m unittest discover -s payloads/tests -v
```

On an x86-64 Linux host, run the direct AMD64 and i386 compatibility-mode
suite with:

```sh
PWNC_NATIVE_TESTS=1 python3 -m unittest discover -s payloads/tests -v
```

This native opt-in requires both 64-bit and 32-bit compiler, loader, and libc
support in addition to LLVM and LLD. Once enabled, a missing prerequisite or a
kernel that cannot execute i386 ELF files fails the run rather than skipping
one half of the matrix.

### Pinned glibc sysroots

`payloads/tests/runtime_support/glibc_sysroots.json` contains 33
content-pinned runtime specifications. Every input has an exact HTTPS URL and
SHA-256; provisioning validates the libc and loader ELF class, endian,
machine, PPC64 ABI flags where applicable, and a glibc version marker.

| Lane | Sysroot specs | Catalog targets | Purpose |
| --- | ---: | ---: | --- |
| glibc 2.23 | 1 | 1 | Exact Ubuntu Xenial AMD64 legacy fake-vtable lane |
| glibc 2.24 | 6 | 7 | Representative validation-boundary lane spanning 32/64-bit and both endians |
| glibc 2.39 | 18 | 20 | Full baseline for every qemu-user-runnable catalog target |
| glibc 2.41 | 8 | 9 | Representative `_flags2` layout lane spanning 32/64-bit and both endians |

ARM and Thumb share one libc root per endian but are compiled and executed as
distinct target-state runs. The 2.24 and 2.41 matrices are representative,
not architecture-by-version cross products; their AArch64 representative is
big-endian, while the full 2.39 lane includes both AArch64 endians. PPC32
little-endian is explicitly unsupported because there is no standardized
upstream Linux/glibc ABI for it. The SPARC32 baseline uses the real Ubuntu
SPARC V8+ multilib root and requires an external `sparc64-linux-gnu-gcc -m32`
compiler; a missing compiler is an error in an enabled run. Its headers,
glibc linker inputs, loader, and runtime libraries are pinned by the sysroot,
while GCC's multilib CRT objects and `libgcc` come from that external compiler.
Ubuntu stores the SPARC32 loader below its cross-package prefix even though
guest binaries request the canonical `/lib/ld-linux.so.2` ABI path; the
manifest records and validates those two paths separately.

Provision one root through the checked API (there is deliberately no implicit
download in the normal test suite):

```python
from payloads.tests.runtime_support import provision_sysroot

root = provision_sysroot(
    "aarch64",
    "/tmp/pwnc-runtime-sysroot-cache",
    lane="glibc-2.39",
)
print(root.libc)
print(root.compiler_argv)
print(root.qemu_argv("/tmp/dynamic-fixture"))
```

Run every pinned spec and every target mapped by it with:

```sh
PWNC_GLIBC_QEMU_TESTS=1 \
PWNC_GLIBC_SYSROOT_CACHE=/tmp/pwnc-runtime-sysroot-cache \
python3 -m unittest payloads.tests.test_glibc_qemu -v
```

For a focused development run, select exact manifest IDs:

```sh
PWNC_GLIBC_QEMU_TESTS=1 \
PWNC_GLIBC_SYSROOT_CACHE=/tmp/pwnc-runtime-sysroot-cache \
PWNC_GLIBC_QEMU_SPECS=aarch64-glibc-2.39,amd64-xenial-glibc-2.23 \
python3 -m unittest payloads.tests.test_glibc_qemu -v
```

With no selector, all 33 specs are mandatory. A selected run is useful
evidence only for those IDs. Live validation has completed every mapped target
in the 2.23, 2.24, 2.39, and 2.41 lanes across focused selector batches,
including distinct ARM/Thumb runs, both PPC64 ABIs, and SPARC32's
external-GCC/pinned-glibc combination; this was not one no-selector invocation.
The FSOP support cells are QEMU-verified because both the checked-in
no-selector contract and those completed live batches cover all 20 mapped 2.39
target variants, not because every FSOP activation or exploitation
precondition is covered.

The dynamic fixture is invoked with the provisioned loader directly,
`--inhibit-cache`, and an exact `--library-path`; it does not use raw `qemu -L`.
It then requires the path reported by `dladdr` to be the provisioned libc via
`samefile`, binds SHA-256/build ID/version to `LibcImage`, and checks the leaked
base-plus-symbol equation. This attests the libc used by the payload. It is not
a chroot and does not prove that every possible transitive DSO came from the
sysroot. The qemu-user binary for this glibc suite is the named host executable,
not a version-pinned emulator; use the separate version suite for QEMU-policy
evidence.

### Pinned QEMU releases

Provision and execute the exact 7.1.0/7.2.0 boundary pair with:

```sh
python3 -m payloads.tests.provision_qemu_versions --root /tmp/pwnc-qemu
PWNC_QEMU_VERSION_ROOT=/tmp/pwnc-qemu \
PWNC_QEMU_VERSION_TESTS=1 \
python3 -m unittest payloads.tests.test_qemu_versions -v
```

The provisioner downloads and verifies the official source archives and builds
only `aarch64-linux-user`. Each installed binary gets an adjacent
`qemu-aarch64.provenance.json`; the root also gets an aggregate
`attestation.json`. The sidecar binds the binary hash, banner, and version to
the archive URL/SHA-256/name, extracted-source tree hash, exact target/configure
arguments, expected execute policy/fix, and build-mode identity. A container
build additionally binds the pinned base image, builder Dockerfile hash, and
resolved image ID. A native build instead binds the selected tool paths and
version banners.

`PWNC_QEMU_VERSION_ROOT` requires those sidecars to validate before execution;
an older pre-sidecar cache must be reprovisioned. Per-release `PWNC_QEMU_*`
overrides intentionally accept external binaries without a sidecar, but then
provide only banner/hash/behavior evidence as described above. The default
container still resolves unversioned packages from mutable `apt` repositories,
so even provisioned-root evidence is source/build-identity-bound and
output-hashed, not a promise of bit-identical future rebuilds. `--native-build`
is an explicit, less isolated compatibility path.

### What the execution evidence means

| Suite | Real runtime evidence | Test-owned or not established |
| --- | --- | --- |
| Native i386/AMD64 | Direct host-kernel execution and the exact loaded host libc; FSOP callback dispatch and live-base ret2libc | Compiled fixtures, supplied control transfer, and challenge preconditions |
| General qemu-user | Exact builder shellcode bytes, automatic semihosting escape, and materialized ROP control flow | Minimal static ELF envelopes and semantic ROP gadgets are test-owned; shellcode cases use no foreign libc |
| Pinned glibc qemu-user | Real dynamic programs, exact pinned loader/libc identity, target-endian FSOP ingestion, live Apple 2/Cat dispatch, glibc 2.23 legacy dispatch, and x86 libc ORW/sendfile chains | Heap FILE placement, activation call, callbacks, challenge ELF, and its pivot/gadgets are test fixtures; the host QEMU version is not pinned |
| QEMU 7.1/7.2 boundary | Provisioned roots bind observed banners, output hashes, source trees, configure arguments, and build identity; both origins test RW-versus-RX AArch64 fetch | Explicit binary overrides attest only banner/hash/behavior; the static probe makes no libc, payload-exploit, non-AArch64, or native-hardware claim |

The x86 pinned-libc ROP fixture supplies the file path in writable main-image
storage, composes `open` with either `read`/`write` or `sendfile`, deliberately
hardcodes the observed next descriptor as fd 3, and lowers through pwntools
using the exact challenge ELF as the extra gadget image. It verifies binary
file output and the intended exit code. That is a real chain against the pinned
libc and real fixture gadgets, but the fixture is not an arbitrary challenge.

PPC32 little-endian remains covered by source and relocation-free assembly
tests but is intentionally absent from QEMU/glibc execution evidence. With an
opt-in variable unset, its execution classes skip. Once a suite is enabled,
missing mandatory emulators, compilers, linkers, or runtime artifacts fail
instead of silently becoming evidence-free success.

## Limitations

- Linux syscall numbers and ABIs are fixed to the exact catalog entries; other
  OSes, ARM OABI, MIPS n32, RISC-V big endian, and x32 are not represented.
- ROP builders need exact caller-supplied gadget semantics and offsets. They do
  not find gadgets, solve bad bytes, or select a stack pivot. The opt-in QEMU
  fixtures validate chains against their supplied synthetic gadgets, not
  arbitrary challenge gadgets or binaries.
- There is no automatic leak discovery, remote-libc identification service,
  live-process/QEMU policy detection, or exploit-specific allocator/control-flow
  primitive.
- Arbitrary-memory workflows do not turn read/write callbacks into a function
  call, instruction-cache flush, or jump. Those capabilities must be supplied
  explicitly, and GOT restoration is only best-effort while control returns.
- QEMU payload tests do not establish native-hardware behavior. The pinned
  old/new execute-permission result is limited to the exact upstream AArch64
  QEMU 7.1.0/7.2.0 builds and the anonymous-mapping probe described above; it
  is not a blanket policy assertion for every architecture or QEMU build.
- Raw command/ORW payloads and the generic arbitrary-memory stager do not make
  memory executable by themselves. The mmap stager performs its own second
  stage RW-to-RX transition, but its first stage still needs an executable
  entry path. Callers must satisfy every `MemoryRequirement` and provide all
  required address leaks, permission/control primitives, and cache maintenance.
