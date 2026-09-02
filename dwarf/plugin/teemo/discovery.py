"""Conservative recovery of unreferenced ELF functions before Teemo export.

Binary Ninja's recursive analysis and linear sweep intentionally reject some
ambiguous executable bytes.  That is usually desirable, but it can hide a CTF
``win`` function which has no incoming reference even though it calls an
import through the PLT or accesses an import slot in the GOT.

This module adds only analysis functions, never persistent user functions.
Candidate starts must be unclaimed
code-section boundaries (or follow a decoded terminal), their instruction
stream must contain import evidence, and it must end in a return or an import
tail-call.  Binary Ninja then performs the authoritative CFG analysis; any
candidate whose analyzed ranges escape the original gap is removed again.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AddressSpan:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError(f"invalid address span {self.start:#x}-{self.end:#x}")

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def contains_span(self, span: AddressSpan) -> bool:
        return self.start <= span.start and span.end <= self.end


@dataclass(frozen=True)
class CandidateEvidence:
    address: int
    kind: str
    target: int


@dataclass(frozen=True)
class OrphanCandidate:
    start: int
    end: int
    gap: AddressSpan
    evidence: tuple[CandidateEvidence, ...]


@dataclass(frozen=True)
class ImportTargetIndex:
    got: tuple[AddressSpan, ...]
    plt: tuple[AddressSpan, ...]
    imported_functions: tuple[AddressSpan, ...]

    def is_got(self, address: int) -> bool:
        return _contains(self.got, address)

    def is_import_target(self, address: int) -> bool:
        return _contains(self.plt, address) or _contains(self.imported_functions, address)

    @property
    def empty(self) -> bool:
        return not self.got and not self.plt and not self.imported_functions


@dataclass(frozen=True)
class RecoveryLimits:
    max_scan_bytes: int = 16 * 1024 * 1024
    max_candidate_bytes: int = 64 * 1024
    max_candidates: int = 256

    def __post_init__(self) -> None:
        if self.max_scan_bytes <= 0 or self.max_candidate_bytes <= 0 or self.max_candidates <= 0:
            raise ValueError("orphan recovery limits must be positive")


DEFAULT_RECOVERY_LIMITS = RecoveryLimits()


@dataclass(frozen=True)
class DiscoveryReport:
    scanned_bytes: int = 0
    candidates: int = 0
    added: tuple[int, ...] = ()
    rejected: tuple[int, ...] = ()
    rejection_reasons: tuple[tuple[int, str], ...] = ()
    cascaded: tuple[int, ...] = ()
    truncated: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.added or self.rejected or self.cascaded)


@dataclass(frozen=True)
class _DecodedInstruction:
    address: int
    length: int
    mnemonic: str
    evidence: tuple[CandidateEvidence, ...]
    returns: bool
    import_tail_call: bool
    stops_linear_path: bool

    @property
    def end(self) -> int:
        return self.address + self.length

    @property
    def is_padding(self) -> bool:
        mnemonic = self.mnemonic.lower().split(".", 1)[0]
        return mnemonic in {"nop", "int3"}


def build_import_target_index(view: Any) -> ImportTargetIndex:
    """Index physical GOT regions and callable import/PLT destinations."""

    got: list[AddressSpan] = []
    plt: list[AddressSpan] = []
    imported_functions: list[AddressSpan] = []
    pointer_size = max(
        1, int(getattr(view, "address_size", 0) or getattr(getattr(view, "arch", None), "address_size", 0) or 1)
    )

    for name, section in _section_items(view):
        span = _object_span(section)
        if span is None:
            continue
        normalized = name.lower()
        if _is_got_section(normalized):
            got.append(span)
        if _is_plt_section(normalized):
            plt.append(span)

    getter = getattr(view, "get_symbols", None)
    if callable(getter):
        try:
            symbols = tuple(getter())
        except Exception:  # noqa: BLE001 - Binary Ninja plugin exceptions are not stable API types.
            symbols = ()
        for symbol in symbols:
            try:
                address = int(symbol.address)
            except (AttributeError, TypeError, ValueError, OverflowError):
                continue
            symbol_type = _enum_name(getattr(symbol, "type", ""))
            raw_name = str(getattr(symbol, "raw_name", getattr(symbol, "name", ""))).lower()
            if symbol_type == "ImportAddressSymbol":
                got.append(AddressSpan(address, address + pointer_size))
            elif symbol_type in {"ImportedFunctionSymbol", "LibraryFunctionSymbol"} or raw_name.endswith(
                ("@plt", ".plt")
            ):
                imported_functions.append(AddressSpan(address, address + 1))

    return ImportTargetIndex(
        tuple(_merge_spans(got)),
        tuple(_merge_spans(plt)),
        tuple(_merge_spans(imported_functions)),
    )


def build_unclaimed_code_ranges(view: Any) -> tuple[AddressSpan, ...]:
    """Return executable code-section bytes not owned by existing functions."""

    code: list[AddressSpan] = []
    for name, section in _section_items(view):
        if _is_got_section(name.lower()) or _is_plt_section(name.lower()):
            continue
        span = _object_span(section)
        if span is None or not _is_safe_code_section(view, section, span):
            continue
        code.append(span)

    if not code:
        return ()

    claimed: list[AddressSpan] = []
    for function in tuple(getattr(view, "functions", ()) or ()):
        claimed.extend(_function_spans(function))

    # Do not subtract auto data variables from executable code sections.  The
    # exact failure this pass repairs often begins with Binary Ninja having
    # classified the orphan's prologue as data; treating that classification
    # as authoritative can move a candidate start into the middle of a real
    # function.  Structural CFG validation remains the fail-closed boundary.

    gaps: list[AddressSpan] = []
    # Preserve ELF section boundaries even when two executable sections are
    # adjacent.  Linkers may leave literal pools at the end of one section;
    # merging it with the next code section can make those bytes look like a
    # prologue for a function that actually starts at the next section.
    for span in sorted(code, key=lambda value: (value.start, value.end)):
        gaps.extend(_subtract_span(span, claimed))
    return tuple(gaps)


def collect_candidate_seeds(
    view: Any,
    gaps: Iterable[AddressSpan],
    imports: ImportTargetIndex,
    *,
    limits: RecoveryLimits = DEFAULT_RECOVERY_LIMITS,
) -> tuple[tuple[OrphanCandidate, ...], int, bool]:
    """Decode unclaimed instruction islands and retain import-bearing ones."""

    candidates: list[OrphanCandidate] = []
    scanned = 0
    truncated = False
    for gap in gaps:
        if scanned >= limits.max_scan_bytes or len(candidates) >= limits.max_candidates:
            truncated = True
            break
        budget = min(gap.end - gap.start, limits.max_scan_bytes - scanned)
        if budget < gap.end - gap.start:
            truncated = True
        scan_end = gap.start + budget
        scanned += budget

        cursor = gap.start
        candidate_start: int | None = None
        evidence: list[CandidateEvidence] = []
        discard_until_boundary = False
        while cursor < scan_end:
            decoded = _decode_instruction(view, cursor, imports)
            if decoded is None or decoded.end > scan_end:
                cursor = _next_instruction_address(view, cursor)
                candidate_start = None
                evidence.clear()
                discard_until_boundary = False
                continue
            terminal = decoded.returns or decoded.import_tail_call
            if discard_until_boundary:
                if terminal or decoded.stops_linear_path:
                    discard_until_boundary = False
                cursor = decoded.end
                continue
            if candidate_start is None:
                if decoded.is_padding:
                    cursor = decoded.end
                    continue
                candidate_start = cursor
            evidence.extend(decoded.evidence)

            if decoded.end - candidate_start > limits.max_candidate_bytes:
                candidate_start = None
                evidence.clear()
                discard_until_boundary = not terminal and not decoded.stops_linear_path
            elif terminal:
                if evidence:
                    candidates.append(
                        OrphanCandidate(
                            candidate_start,
                            decoded.end,
                            gap,
                            tuple(_deduplicate_evidence(evidence)),
                        )
                    )
                    if len(candidates) >= limits.max_candidates:
                        truncated = cursor < scan_end or gap.end > scan_end
                        break
                candidate_start = None
                evidence.clear()
            elif decoded.stops_linear_path:
                # A byte-linear scan cannot safely continue across an
                # unconditional or unresolved transfer and pretend the bytes
                # after it belong to the same function.
                candidate_start = None
                evidence.clear()
            cursor = decoded.end

    by_start: dict[int, OrphanCandidate] = {}
    for candidate in candidates:
        existing = by_start.get(candidate.start)
        if existing is None or len(candidate.evidence) > len(existing.evidence):
            by_start[candidate.start] = candidate
    return tuple(by_start[address] for address in sorted(by_start)), scanned, truncated


def prepare_view_for_export(
    view: Any,
    *,
    initially_settled: bool,
    limits: RecoveryLimits = DEFAULT_RECOVERY_LIMITS,
) -> DiscoveryReport:
    """Recover high-confidence orphan functions and settle Binary Ninja analysis.

    Every speculative function is created with ``add_function`` rather than
    ``create_user_function``.  Binary Ninja requires a seed with no incoming
    analysis edge to be an analysis root (``auto_discovered=False``); setting
    that flag to true makes the core garbage-collect the unreferenced seed.
    This does not create persistent user intent.  Existing functions are never removed.  If
    validation or analysis raises, all newly introduced auto functions are
    rolled back before the exception escapes and Teemo publishes nothing.
    """

    if not initially_settled:
        view.update_analysis_and_wait()
    if str(getattr(view, "view_type", "")).lower() != "elf":
        return DiscoveryReport()

    baseline = _function_map(view)
    imports = build_import_target_index(view)
    if imports.empty:
        return DiscoveryReport()
    gaps = build_unclaimed_code_ranges(view)
    candidates, scanned, truncated = collect_candidate_seeds(view, gaps, imports, limits=limits)
    if not candidates:
        return DiscoveryReport(scanned_bytes=scanned, truncated=truncated)

    candidate_by_start = {candidate.start: candidate for candidate in candidates}
    attempted: set[int] = set()
    created_roots: list[Any] = []
    try:
        for candidate in candidates:
            identity = _identity_for_start(view, candidate.start)
            if identity in baseline or _get_function_at(view, candidate.start) is not None:
                continue
            function = view.add_function(candidate.start, auto_discovered=False)
            if function is not None:
                attempted.add(candidate.start)
                created_roots.append(function)
        if attempted:
            view.update_analysis_and_wait()

        rejected: list[int] = []
        rejection_reasons: list[tuple[int, str]] = []
        accepted: list[int] = []
        validation_imports = build_import_target_index(view)
        for start in sorted(attempted):
            function = _get_function_at(view, start)
            candidate = candidate_by_start[start]
            reason = (
                "function disappeared during analysis"
                if function is None
                else _candidate_rejection_reason(
                    view,
                    function,
                    candidate,
                    validation_imports,
                )
            )
            if reason is not None:
                rejected.append(start)
                rejection_reasons.append((start, reason))
                if function is not None:
                    view.remove_function(function, update_refs=True)
            else:
                accepted.append(start)
        if rejected:
            view.update_analysis_and_wait()

        after = _function_map(view)
        cascaded = sorted(
            identity[1]
            for identity, function in after.items()
            if identity not in baseline and identity[1] not in attempted and _is_auto_function(function)
        )
        return DiscoveryReport(
            scanned_bytes=scanned,
            candidates=len(candidates),
            added=tuple(accepted),
            rejected=tuple(rejected),
            rejection_reasons=tuple(rejection_reasons),
            cascaded=tuple(cascaded),
            truncated=truncated,
        )
    except BaseException as error:
        rollback_failures = _rollback_trial_roots(view, created_roots)
        if rollback_failures:
            detail = "; ".join(rollback_failures)
            raise RuntimeError(f"orphan recovery failed and rollback was incomplete: {detail}") from error
        raise


def _decode_instruction(view: Any, address: int, imports: ImportTargetIndex) -> _DecodedInstruction | None:
    arch, decode_address = _associated_architecture(view, address)
    if arch is None or decode_address != address:
        return None
    try:
        data = bytes(view.read(address, int(arch.max_instr_length)))
        info = arch.get_instruction_info(data, address)
    except Exception:  # noqa: BLE001 - raw architecture decoders may raise plugin-defined exceptions.
        return None
    if info is None:
        return None
    length = int(getattr(info, "length", 0))
    if length <= 0 or length > len(data):
        return None

    mnemonic = ""
    try:
        rendered = arch.get_instruction_text(data, address)
        if rendered is not None:
            tokens, rendered_length = rendered
            if int(rendered_length) == length:
                for token in tokens:
                    if _enum_name(getattr(token, "type", "")) == "InstructionToken":
                        mnemonic = str(getattr(token, "text", "")).strip()
                        break
    except Exception:  # noqa: BLE001 - mnemonic text is optional evidence.
        mnemonic = ""

    evidence = [
        CandidateEvidence(address, "got-reference", target)
        for target in _instruction_constants(arch, view, address)
        if imports.is_got(target)
    ]
    returns = False
    import_tail_call = False
    stops_linear_path = False
    for branch in tuple(getattr(info, "branches", ()) or ()):
        branch_type = _enum_name(getattr(branch, "type", ""))
        target = int(getattr(branch, "target", 0))
        if branch_type == "FunctionReturn":
            returns = True
        if branch_type in {"CallDestination", "UnconditionalBranch"} and imports.is_import_target(target):
            kind = "plt-call" if branch_type == "CallDestination" else "plt-tail-call"
            evidence.append(CandidateEvidence(address, kind, target))
            import_tail_call = branch_type == "UnconditionalBranch"
        if branch_type == "IndirectBranch" and evidence:
            import_tail_call = True
        if branch_type in {
            "UnconditionalBranch",
            "IndirectBranch",
            "ExceptionBranch",
            "UnresolvedBranch",
            "UserDefinedBranch",
        }:
            stops_linear_path = True

    return _DecodedInstruction(
        address,
        length,
        mnemonic,
        tuple(_deduplicate_evidence(evidence)),
        returns,
        import_tail_call,
        stops_linear_path,
    )


def _instruction_constants(arch: Any, view: Any, address: int) -> Iterator[int]:
    try:
        instruction = arch.get_instruction_low_level_il_instruction(view, address)
    except Exception:  # noqa: BLE001 - architecture lifters may raise plugin-defined exceptions.
        return

    def constant(node: Any) -> int | None:
        operation = _enum_name(getattr(node, "operation", ""))
        # A plain integer that happens to equal a GOT address is not an address
        # reference.  Architecture lifters use pointer/external-pointer nodes
        # for resolved memory operands such as RIP-relative GOT accesses.
        if operation not in {"LLIL_CONST_PTR", "LLIL_EXTERN_PTR"}:
            return None
        try:
            value = int(node.constant)
            if operation == "LLIL_EXTERN_PTR":
                value += int(getattr(node, "offset", 0))
            return value
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None

    try:
        yield from (value for value in instruction.traverse(constant) if value is not None)
    except Exception:  # noqa: BLE001 - malformed raw IL fails closed.
        return


def _candidate_rejection_reason(
    view: Any,
    function: Any,
    candidate: OrphanCandidate,
    imports: ImportTargetIndex,
) -> str | None:
    if bool(getattr(function, "analysis_skipped", False)):
        return "Binary Ninja skipped function analysis"
    if bool(getattr(function, "too_large", False)):
        return "Binary Ninja classified the function as too large"
    spans = _function_spans(function)
    if not spans:
        return "the analyzed function has no address ranges"
    if any(not candidate.gap.contains_span(span) for span in spans):
        return "the analyzed function escaped its unclaimed executable gap"
    if not any(span.contains(candidate.end - 1) for span in spans):
        return "the analyzed function does not contain the decoded terminal"
    try:
        blocks = tuple(getattr(function, "basic_blocks", ()) or ())
        if not blocks:
            return "the analyzed function has no basic blocks"
    except Exception:  # noqa: BLE001 - core-backed block enumeration can fail.
        return "Binary Ninja could not enumerate the function's basic blocks"
    block_spans = tuple(span for block in blocks if (span := _object_span(block)) is not None)
    if not block_spans:
        return "the analyzed function's basic blocks have no address ranges"
    evidence_is_current = False
    for expected in candidate.evidence:
        if not any(span.contains(expected.address) for span in block_spans):
            continue
        decoded = _decode_instruction(view, expected.address, imports)
        if decoded is not None and expected in decoded.evidence:
            evidence_is_current = True
            break
    if not evidence_is_current:
        return "the analyzed CFG does not contain current import evidence"
    try:
        llil = getattr(function, "llil", None)
        if llil is None or len(llil) == 0:
            return "the analyzed function has no LLIL"
    except Exception:  # noqa: BLE001 - core-backed IL enumeration can fail.
        return "Binary Ninja could not enumerate the function's LLIL"
    return None


def _rollback_trial_roots(view: Any, created_roots: Iterable[Any]) -> tuple[str, ...]:
    roots = tuple(created_roots)
    removed = False
    removal_errors: dict[int, Exception] = {}
    for function in roots:
        start = int(getattr(function, "start", -1))
        current = _get_function_at(view, start)
        if current is None or bool(getattr(current, "has_user_annotations", False)):
            continue
        try:
            view.remove_function(current, update_refs=True)
            removed = True
        except Exception as error:  # noqa: BLE001 - report arbitrary core rollback failures.
            removal_errors[start] = error

    failures: list[str] = []
    if removed or removal_errors:
        try:
            view.update_analysis_and_wait()
        except Exception as error:  # noqa: BLE001 - report arbitrary core rollback failures.
            failures.append(f"analysis did not settle after rollback ({error})")
    for function in roots:
        start = int(getattr(function, "start", -1))
        current = _get_function_at(view, start)
        if current is None or bool(getattr(current, "has_user_annotations", False)):
            continue
        detail = removal_errors.get(start)
        suffix = f" ({detail})" if detail is not None else ""
        failures.append(f"analysis root {start:#x} remains{suffix}")
    return tuple(failures)


def _function_map(view: Any) -> dict[tuple[str, int], Any]:
    result: dict[tuple[str, int], Any] = {}
    for function in tuple(getattr(view, "functions", ()) or ()):
        result[_function_identity(function)] = function
    return result


def _function_identity(function: Any) -> tuple[str, int]:
    platform = getattr(function, "platform", None)
    return str(getattr(platform, "name", platform) or ""), int(function.start)


def _identity_for_start(view: Any, start: int) -> tuple[str, int]:
    platform = getattr(view, "platform", None)
    return str(getattr(platform, "name", platform) or ""), start


def _get_function_at(view: Any, start: int) -> Any | None:
    getter = getattr(view, "get_function_at", None)
    if callable(getter):
        try:
            return getter(start)
        except Exception:  # noqa: BLE001 - fall back to the function list.
            return next(
                (
                    function
                    for function in tuple(getattr(view, "functions", ()) or ())
                    if int(getattr(function, "start", -1)) == start
                ),
                None,
            )
    for function in tuple(getattr(view, "functions", ()) or ()):
        if int(getattr(function, "start", -1)) == start:
            return function
    return None


def _is_auto_function(function: Any) -> bool:
    return bool(getattr(function, "auto", True))


def _associated_architecture(view: Any, address: int) -> tuple[Any | None, int]:
    arch = getattr(view, "arch", None)
    if arch is None:
        return None, address
    associate = getattr(arch, "get_associated_arch_by_address", None)
    if callable(associate):
        try:
            associated = associate(address)
            if isinstance(associated, tuple) and len(associated) == 2:
                return associated[0], int(associated[1])
        except Exception:  # noqa: BLE001 - associated architectures are plugin-defined.
            return None, address
    return arch, address


def _instruction_alignment(view: Any, address: int) -> int:
    arch, _address = _associated_architecture(view, address)
    try:
        return max(1, int(arch.instr_alignment))
    except (AttributeError, TypeError, ValueError, OverflowError):
        return 1


def _next_instruction_address(view: Any, address: int) -> int:
    alignment = _instruction_alignment(view, address)
    return ((address // alignment) + 1) * alignment


def _is_safe_code_section(view: Any, section: Any, span: AddressSpan) -> bool:
    try:
        if not bool(view.is_offset_executable(span.start)):
            return False
        if not bool(view.is_offset_code_semantics(span.start)):
            return False
        if bool(view.is_offset_writable(span.start)):
            return False
    except Exception:  # noqa: BLE001 - support minimal/fake BinaryViews conservatively.
        semantics = _enum_name(getattr(section, "semantics", ""))
        if "CodeSectionSemantics" not in semantics:
            return False
    return True


def _section_items(view: Any) -> Iterator[tuple[str, Any]]:
    sections = getattr(view, "sections", {})
    if hasattr(sections, "items"):
        for name, section in sections.items():
            yield str(name), section
    else:
        for section in sections or ():
            yield str(getattr(section, "name", "")), section


def _object_span(value: Any) -> AddressSpan | None:
    try:
        start = int(value.start)
        end = int(value.end)
        return AddressSpan(start, end) if end > start else None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def _function_spans(function: Any) -> list[AddressSpan]:
    result = []
    for value in tuple(getattr(function, "address_ranges", ()) or ()):
        span = _object_span(value)
        if span is not None:
            result.append(span)
    return result


def _subtract_span(span: AddressSpan, excluded: Iterable[AddressSpan]) -> list[AddressSpan]:
    result = [span]
    for blocked in _merge_spans(excluded):
        next_result = []
        for current in result:
            if blocked.end <= current.start or current.end <= blocked.start:
                next_result.append(current)
                continue
            if current.start < blocked.start:
                next_result.append(AddressSpan(current.start, blocked.start))
            if blocked.end < current.end:
                next_result.append(AddressSpan(blocked.end, current.end))
        result = next_result
        if not result:
            break
    return result


def _merge_spans(spans: Iterable[AddressSpan]) -> list[AddressSpan]:
    result: list[AddressSpan] = []
    for span in sorted(spans, key=lambda value: (value.start, value.end)):
        if result and span.start <= result[-1].end:
            previous = result[-1]
            result[-1] = AddressSpan(previous.start, max(previous.end, span.end))
        else:
            result.append(span)
    return result


def _contains(spans: Iterable[AddressSpan], address: int) -> bool:
    return any(span.contains(address) for span in spans)


def _is_got_section(name: str) -> bool:
    return name in {".got", ".igot"} or name.startswith((".got.", ".igot."))


def _is_plt_section(name: str) -> bool:
    return name in {".plt", ".iplt"} or name.startswith((".plt.", ".iplt."))


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value))


def _deduplicate_evidence(values: Iterable[CandidateEvidence]) -> list[CandidateEvidence]:
    return list(dict.fromkeys(values))
