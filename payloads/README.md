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
and observes address randomization across fresh processes.

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

### LLVM requirement

Raw bytes are assembled by `LLVMAssembler`, which requires `llvm-mc` from
LLVM. Pass `LLVMAssembler("/absolute/path/to/llvm-mc")` when it is not on
`PATH`. `pyelftools` is used to extract `.text`; unresolved relocations are
rejected rather than copied into the payload. LLVM/LLD target support varies by
installation, so matrix recognition alone does not prove that a particular
local LLVM build can assemble a target.

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

## Tests

Run the normal foundation, lowering, assembly, and matrix tests with:

```sh
python3 -m unittest discover -s payloads/tests -v
```

Assembly tests skip when `llvm-mc` is unavailable. End-to-end execution is
opt-in because it needs LLVM, LLD, and the complete set of QEMU user emulators
for the QEMU-verified matrix:

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

The shellcode QEMU tests place exactly the bytes returned by the command, ORW,
and RW-to-RX stager builders in a minimal static ELF, then check command output,
binary file bytes, and execution of an exact second-stage exit payload. They use
no foreign libc or sysroot. The semihosting test runs every one of the eight
automatic qemu-user variants with no semihosting flag and checks a file written
by the host command. The static ROP tests patch the exact materialized chain
into a fixture and pivot to its first word; syscall and direct-call exits are
deliberately distinct. The ret2libc tests use `-L /` with sanitized loader
environment variables so that the libc path parsed by the framework is the
artifact actually loaded by the guest. They require suitable native compiler
and multilib support in addition to the i386 and AMD64 emulators.

PPC32 little-endian remains covered by source and relocation-free assembly
tests but is intentionally absent from QEMU evidence. With the opt-in variable
unset, execution classes are skipped. Once `PWNC_QEMU_TESTS=1` is set, a
missing compiler, linker, multilib runtime, or claimed emulator fails the run
instead of silently turning it into evidence-free success. The ret2libc test
establishes correct use of the disclosed live base; it does not claim that
repeated QEMU runs produce different ASLR layouts.

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
- QEMU payload tests do not establish native-hardware behavior and do not test
  old-versus-new QEMU execute-permission policy.
- Raw command/ORW payloads and the generic arbitrary-memory stager do not make
  memory executable by themselves. The mmap stager performs its own second
  stage RW-to-RX transition, but its first stage still needs an executable
  entry path. Callers must satisfy every `MemoryRequirement` and provide all
  required address leaks, permission/control primitives, and cache maintenance.
