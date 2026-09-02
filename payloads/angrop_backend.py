"""Exact-artifact, multi-image adapter for the vendored angrop engine.

The public records in this module contain no angr or angrop objects.  The
backend is imported only when :func:`prepare_angrop` is called, every ELF is
digest checked before it is copied into a private analysis directory, and CLE
is always configured with ``auto_load_libs=False``.  Runtime addresses are
concrete and explicit: ``load_bias`` is the relocation delta added to the
virtual addresses in the ELF, including an explicit zero for ET_EXEC files.

Upstream angrop discovers and rebases gadgets relative to ``main_object``.
For a multi-image process we therefore discover each requested image while it
is the main object, load all exact images together at their declared runtime
addresses, and attach the discovered gadget semantics to a fresh combined
builder.  This keeps the multi-image adaptation in pwnc's wrapper while using
one embedded upstream source tree.
"""

from __future__ import annotations

import importlib
import math
import signal
import threading
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType, ModuleType
from typing import Any, Self

from .elf import ELFImageKind
from .errors import PayloadError, UnsupportedTargetError
from .libc import LibcIdentity
from .model import Payload, PayloadKind, Permission
from .pwntools_compat import ExactELFAdapter
from .rop import ChainWord, ROPChain
from .target import ABI, Architecture, Endian, FunctionPointerModel, Target

ANGROP_BASELINE_REVISION = "e7c3c1edfc4c25887f5017544f7dd46505795cce"
"""Upstream commit copied into :mod:`payloads._vendor.angrop`."""

ANGROP_VENDOR_REVISION = f"{ANGROP_BASELINE_REVISION}+pwnc.5"
"""Embedded source revision, including the five documented local patch groups."""

ANGROP_PATCHED_SOURCE_SHA256 = "4f196ded3957cfb8949862af2df0f65ac232b26fc3f3fbf36abb5f881e34927a"
"""Digest of the sorted path-and-content stream for every embedded Python source."""

_RUNTIME_PAGE_SIZE = 0x1000
_ANGROP_GLOBAL_STATE_LOCK = threading.RLock()


def _is_positive_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return value > 0 and math.isfinite(value)
    except OverflowError:
        return False


class AngropBackendError(PayloadError):
    """Base class for exact angrop preparation and synthesis failures."""


class AngropUnavailableError(AngropBackendError, ImportError):
    """The optional angr runtime or the vendored angrop package is unavailable."""


class AngropCompatibilityError(AngropBackendError, RuntimeError):
    """The vendored angrop/angr API or loaded CLE image set is incompatible."""


class AngropImageError(AngropBackendError, ValueError):
    """An exact image set or declared runtime mapping is invalid."""


class AngropSynthesisError(AngropBackendError, ValueError):
    """Angrop could not synthesize the requested ordered calls."""


class AngropTimeoutError(AngropSynthesisError, TimeoutError):
    """A caller-requested end-to-end synthesis deadline expired."""


class AngropBadByteError(AngropSynthesisError):
    """The final serialized chain contains forbidden bytes."""

    def __init__(self, violations: Sequence[tuple[int, int]]) -> None:
        self.violations = tuple(violations)
        preview = ", ".join(f"offset {offset:#x}=0x{value:02x}" for offset, value in self.violations[:8])
        if len(self.violations) > 8:
            preview += f", and {len(self.violations) - 8} more"
        super().__init__(f"serialized angrop chain contains forbidden bytes: {preview}")


def _target_key(target: Target) -> tuple[object, ...]:
    return (
        target.arch,
        target.bits,
        target.endian,
        target.abi,
        target.function_pointer_model,
    )


def _align_down(value: int, alignment: int) -> int:
    return value & -alignment


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


@dataclass(frozen=True, slots=True)
class AngropRuntimeRange:
    """One target mapping after adding an image's explicit load bias."""

    start: int
    end: int
    permissions: Permission
    elf_start: int
    file_offset: int
    file_size: int

    def __post_init__(self) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (self.start, self.end)):
            raise TypeError("runtime range bounds must be integers")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("runtime ranges must be nonempty and non-negative")
        if not isinstance(self.permissions, Permission):
            object.__setattr__(self, "permissions", Permission(self.permissions))

    @property
    def executable(self) -> bool:
        return bool(self.permissions & Permission.EXECUTE)

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass(frozen=True, slots=True)
class AngropImageSpec:
    """One authenticated ELF and its concrete runtime relocation delta.

    Construct this with :meth:`from_adapter` to reuse an already authenticated
    pwntools/checksec adapter, or :meth:`from_file` when no adapter exists yet.
    ``load_bias`` deliberately has no default, even for ET_EXEC images.
    """

    adapter: ExactELFAdapter
    load_bias: int
    name: str | None = None
    scan_gadgets: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.adapter, ExactELFAdapter):
            raise TypeError("adapter must be an ExactELFAdapter created by ExactELFAdapter.from_file()")
        if isinstance(self.load_bias, bool) or not isinstance(self.load_bias, int):
            raise TypeError("load_bias must be an explicit integer")
        if self.name is not None and (not isinstance(self.name, str) or not self.name.strip()):
            raise ValueError("image name must be a nonempty string or None")
        if not isinstance(self.scan_gadgets, bool):
            raise TypeError("scan_gadgets must be bool")
        if not self.adapter.profile.load_ranges:
            raise AngropImageError("angrop images require at least one nonempty PT_LOAD range")

        if self.mapped_base < 0:
            raise AngropImageError(f"image {self.display_name!r} maps below address zero")
        try:
            runtime_ranges = self.runtime_load_ranges
        except ValueError as exc:
            raise AngropImageError(f"image {self.display_name!r} maps below address zero") from exc
        for runtime_range in runtime_ranges:
            if runtime_range.end > self.target.mask + 1:
                raise AngropImageError(
                    f"image {self.display_name!r} range ending at {runtime_range.end:#x} "
                    f"does not fit {self.target.bits}-bit addresses"
                )

    @classmethod
    def from_adapter(
        cls,
        adapter: ExactELFAdapter,
        *,
        load_bias: int,
        name: str | None = None,
        scan_gadgets: bool = True,
    ) -> AngropImageSpec:
        """Reuse an exact adapter without reparsing its source artifact."""

        return cls(adapter, load_bias, name, scan_gadgets)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        load_bias: int,
        name: str | None = None,
        scan_gadgets: bool = True,
        expected_identity: LibcIdentity | None = None,
        expected_target: Target | None = None,
    ) -> AngropImageSpec:
        adapter = ExactELFAdapter.from_file(
            path,
            expected_identity=expected_identity,
            expected_target=expected_target,
        )
        return cls.from_adapter(
            adapter,
            load_bias=load_bias,
            name=name,
            scan_gadgets=scan_gadgets,
        )

    @property
    def target(self) -> Target:
        return self.adapter.target

    @property
    def identity(self) -> LibcIdentity:
        return self.adapter.identity

    @property
    def display_name(self) -> str:
        return self.name or Path(self.adapter.path).name

    @property
    def runtime_load_ranges(self) -> tuple[AngropRuntimeRange, ...]:
        return tuple(
            AngropRuntimeRange(
                self.load_bias + item.start,
                self.load_bias + item.end,
                item.permissions,
                item.start,
                item.file_offset,
                item.file_size,
            )
            for item in self.adapter.profile.load_ranges
            if item.size
        )

    @property
    def load_ranges(self) -> tuple[AngropRuntimeRange, ...]:
        """Alias emphasizing that ranges are normalized runtime PT_LOADs."""

        return self.runtime_load_ranges

    @property
    def linked_base(self) -> int:
        """CLE-compatible linked image base derived from PT_LOAD addresses."""

        return min(_align_down(item.start, _RUNTIME_PAGE_SIZE) for item in self.adapter.profile.load_ranges)

    @property
    def mapped_base(self) -> int:
        return self.linked_base + self.load_bias

    @property
    def mapped_envelope(self) -> tuple[int, int]:
        """Conservative page envelope CLE must reserve for this ELF object."""

        end = max(_align_up(item.end, _RUNTIME_PAGE_SIZE) for item in self.adapter.profile.load_ranges)
        return self.mapped_base, self.load_bias + end

    def runtime_address(self, elf_virtual_address: int) -> int:
        if isinstance(elf_virtual_address, bool) or not isinstance(elf_virtual_address, int):
            raise TypeError("ELF virtual address must be an int")
        if not 0 <= elf_virtual_address <= self.target.mask:
            raise ValueError("ELF virtual address does not fit the target")
        result = self.load_bias + elf_virtual_address
        if result < 0:
            raise AngropImageError("runtime address underflows the target pointer width")
        if result > self.target.mask:
            raise AngropImageError("runtime address overflows the target pointer width")
        return result

    def runtime_symbol(self, name: str) -> int:
        """Resolve one exact symbol without asking angrop to search main_object."""

        return self.runtime_address(self.adapter.symbol(name))


@dataclass(frozen=True, slots=True)
class AngropDiscoveryOptions:
    """Gadget discovery plus current ROPBlock/graph optimizer controls."""

    processes: int = 4
    show_progress: bool = False
    timeout: float | None = None
    optimize: bool = True
    fast_mode: bool | None = None
    only_check_near_rets: bool = True
    cond_br: bool = False
    max_bb_cnt: int = 2

    def __post_init__(self) -> None:
        if isinstance(self.processes, bool) or not isinstance(self.processes, int) or self.processes <= 0:
            raise ValueError("processes must be a positive integer")
        if not isinstance(self.show_progress, bool) or not isinstance(self.optimize, bool):
            raise TypeError("show_progress and optimize must be bool")
        if self.timeout is not None and not _is_positive_finite_number(self.timeout):
            raise ValueError("timeout must be a positive finite number or None")
        if self.fast_mode is not None and not isinstance(self.fast_mode, bool):
            raise TypeError("fast_mode must be bool or None")
        if not isinstance(self.only_check_near_rets, bool) or not isinstance(self.cond_br, bool):
            raise TypeError("only_check_near_rets and cond_br must be bool")
        if isinstance(self.max_bb_cnt, bool) or not isinstance(self.max_bb_cnt, int) or self.max_bb_cnt <= 0:
            raise ValueError("max_bb_cnt must be a positive integer")


@dataclass(frozen=True, slots=True)
class AngropDirectCall:
    """One concrete direct call in an ordered synthesized program."""

    function: int
    arguments: tuple[int, ...] = ()
    name: str | None = None
    needs_return: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.function, bool) or not isinstance(self.function, int) or self.function < 0:
            raise ValueError("function must be a non-negative integer address")
        arguments = tuple(self.arguments)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in arguments):
            raise ValueError("direct-call arguments must be integer words")
        object.__setattr__(self, "arguments", arguments)
        if self.name is not None and (not isinstance(self.name, str) or not self.name):
            raise ValueError("call name must be a nonempty string or None")
        if not isinstance(self.needs_return, bool):
            raise TypeError("needs_return must be bool")


@dataclass(frozen=True, slots=True)
class AngropImageProvenance:
    index: int
    name: str
    source_path: str
    sha256: str
    build_id: str | None
    load_bias: int
    mapped_base: int
    runtime_load_ranges: tuple[AngropRuntimeRange, ...]
    scan_gadgets: bool
    cle_main: bool


@dataclass(frozen=True, slots=True)
class AngropCallProvenance:
    index: int
    name: str | None
    function: int
    arguments: tuple[int, ...]
    needs_return: bool
    image_index: int
    image_name: str
    image_sha256: str
    image_offset: int
    entry_sp: int
    entry_sp_offset: int
    stack_alignment: int
    stack_alignment_bias: int
    alignment_padding: int


@dataclass(frozen=True, slots=True)
class AngropGadgetProvenance:
    index: int
    address: int
    description: str
    image_index: int
    image_name: str
    image_sha256: str
    image_offset: int
    call_target: bool


@dataclass(frozen=True, slots=True)
class AngropSynthesisResult:
    """Backend-neutral bytes and exact provenance for one angrop chain."""

    target: Target
    chain_base: int
    data: bytes
    words: tuple[int, ...]
    images: tuple[AngropImageProvenance, ...]
    calls: tuple[AngropCallProvenance, ...]
    gadgets: tuple[AngropGadgetProvenance, ...]
    bad_bytes: frozenset[int]
    backend_revision: str
    discovery_options: AngropDiscoveryOptions

    def as_rop_chain(self, *, description: str = "angrop direct-call chain") -> ROPChain:
        """Return concrete words in the backend-neutral :class:`ROPChain` model."""

        roles = {item.address: item.description for item in self.gadgets}
        words = tuple(
            ChainWord(value, roles.get(value, f"angrop word[{index}]")) for index, value in enumerate(self.words)
        )
        steps = tuple(item.name or f"call {item.function:#x}" for item in self.calls)
        return ROPChain(
            self.target,
            words,
            description,
            PayloadKind.ROP,
            steps,
            required_chain_base=self.chain_base,
        )

    def as_payload(self, *, description: str = "angrop direct-call chain") -> Payload:
        metadata = {
            "backend": "angrop",
            "backend_revision": self.backend_revision,
            "chain_base": self.chain_base,
            "words": self.words,
            "bad_bytes": tuple(sorted(self.bad_bytes)),
            "discovery": {
                "processes": self.discovery_options.processes,
                "optimize": self.discovery_options.optimize,
                "fast_mode": self.discovery_options.fast_mode,
                "cond_br": self.discovery_options.cond_br,
                "max_bb_cnt": self.discovery_options.max_bb_cnt,
            },
            "images": tuple(
                {
                    "index": item.index,
                    "name": item.name,
                    "sha256": item.sha256,
                    "build_id": item.build_id,
                    "load_bias": item.load_bias,
                    "mapped_base": item.mapped_base,
                    "scan_gadgets": item.scan_gadgets,
                    "cle_main": item.cle_main,
                }
                for item in self.images
            ),
            "calls": tuple(
                {
                    "index": item.index,
                    "name": item.name,
                    "function": item.function,
                    "arguments": item.arguments,
                    "needs_return": item.needs_return,
                    "image_index": item.image_index,
                    "image_sha256": item.image_sha256,
                    "image_offset": item.image_offset,
                    "entry_sp": item.entry_sp,
                    "entry_sp_offset": item.entry_sp_offset,
                    "stack_alignment": item.stack_alignment,
                    "stack_alignment_bias": item.stack_alignment_bias,
                    "alignment_padding": item.alignment_padding,
                }
                for item in self.calls
            ),
            "gadgets": tuple(
                {
                    "index": item.index,
                    "address": item.address,
                    "description": item.description,
                    "image_index": item.image_index,
                    "image_sha256": item.image_sha256,
                    "image_offset": item.image_offset,
                    "call_target": item.call_target,
                }
                for item in self.gadgets
            ),
        }
        return Payload(
            self.data,
            self.target,
            PayloadKind.ROP,
            description,
            metadata=metadata,
            required_load_address=self.chain_base,
        )


def _load_angrop_modules() -> tuple[ModuleType, ModuleType]:
    """Load the optional solver and collision-proof vendored frontend lazily."""

    try:
        angr = importlib.import_module("angr")
    except ImportError as exc:
        raise AngropUnavailableError("angr is required; install pwnc with the 'rop' extra") from exc
    try:
        angrop = importlib.import_module("payloads._vendor.angrop")
    except ImportError as exc:
        raise AngropUnavailableError("the vendored payloads._vendor.angrop package is unavailable") from exc
    return angr, angrop


_SUPPORTED_TARGETS: MappingProxyType[Architecture, frozenset[ABI]] = MappingProxyType(
    {
        Architecture.X86: frozenset({ABI.I386_SYSV}),
        Architecture.X86_64: frozenset({ABI.AMD64_SYSV}),
        Architecture.ARM: frozenset({ABI.ARM_EABI}),
        Architecture.ARM64: frozenset({ABI.AARCH64_AAPCS}),
    }
)


def _validate_backend_target(target: Target) -> None:
    supported_abis = _SUPPORTED_TARGETS.get(target.arch)
    if supported_abis is None or target.abi not in supported_abis:
        raise UnsupportedTargetError(
            f"the pwnc angrop adapter does not safely implement {target.name}; supported architecture families are "
            "x86/i386, AMD64, ARM EABI, and AArch64"
        )
    if target.endian is not Endian.LITTLE:
        raise UnsupportedTargetError(
            f"the pwnc angrop adapter does not safely implement big-endian target {target.name}; "
            "ARM BE8 is known to be misdecoded by the pinned angr runtimes and no other big-endian backend is attested"
        )
    if target.function_pointer_model is FunctionPointerModel.PPC64_ELFV1_DESCRIPTOR:
        raise UnsupportedTargetError("vendored angrop cannot call PPC64 ELFv1 descriptors")


def _canonical_code_address(target: Target, address: int) -> int:
    if target.function_pointer_model is FunctionPointerModel.THUMB_STATE_BIT:
        return address & ~1
    return address


def _validate_image_set(
    images: Sequence[AngropImageSpec],
    target: Target | None,
) -> tuple[tuple[AngropImageSpec, ...], Target, int]:
    normalized = tuple(images)
    if not normalized:
        raise AngropImageError("at least one exact image is required")
    if any(not isinstance(image, AngropImageSpec) for image in normalized):
        raise TypeError("images must contain only AngropImageSpec records")

    selected_target = normalized[0].target if target is None else target
    if not isinstance(selected_target, Target):
        raise TypeError("target must be a Target or None")
    _validate_backend_target(selected_target)
    expected = _target_key(selected_target)
    seen_identities: dict[str, int] = {}
    for index, image in enumerate(normalized):
        if _target_key(image.target) != expected:
            raise AngropImageError(
                f"image {image.display_name!r} targets {image.target.name}, expected {selected_target.name}"
            )
        previous = seen_identities.get(image.identity.sha256)
        if previous is not None:
            raise AngropImageError(
                f"duplicate exact ELF SHA-256 {image.identity.sha256[:12]} at image indices {previous} and {index}; "
                "CLE may deduplicate equal SONAMEs, so each prepared image must be a distinct artifact"
            )
        seen_identities[image.identity.sha256] = index

    for left_index, left in enumerate(normalized):
        left_start, left_end = left.mapped_envelope
        for right_index in range(left_index + 1, len(normalized)):
            right = normalized[right_index]
            right_start, right_end = right.mapped_envelope
            if left_start < right_end and right_start < left_end:
                raise AngropImageError(
                    f"runtime image envelopes overlap: {left.display_name!r} [{left_start:#x}, {left_end:#x}) "
                    f"and {right.display_name!r} [{right_start:#x}, {right_end:#x})"
                )

    executable_indices = tuple(
        index
        for index, image in enumerate(normalized)
        if image.adapter.profile.image_kind
        in {ELFImageKind.EXECUTABLE, ELFImageKind.PIE_EXECUTABLE, ELFImageKind.STATIC_PIE}
    )
    cle_main_index = executable_indices[0] if len(executable_indices) == 1 else 0
    return normalized, selected_target, cle_main_index


def _cle_image_options(image: AngropImageSpec) -> dict[str, object]:
    options: dict[str, object] = {
        "base_addr": image.mapped_base,
        "discard_section_headers": True,
    }
    if image.adapter.profile.elf_type != "ET_DYN" and image.load_bias:
        options["force_rebase"] = True
    return options


def _project_load_options(
    primary: tuple[AngropImageSpec, Path],
    supplemental: Sequence[tuple[AngropImageSpec, Path]],
) -> dict[str, object]:
    lib_opts: dict[str, dict[str, object]] = {}
    force_load_libs: list[str] = []
    for image, path in supplemental:
        force_load_libs.append(str(path))
        options = _cle_image_options(image)
        # Snapshot basenames are unique.  CLE checks both the full path and
        # basename identifiers when it selects lib_opts.
        lib_opts[str(path)] = options
        lib_opts[path.name] = options
    return {
        "auto_load_libs": False,
        "main_opts": _cle_image_options(primary[0]),
        "force_load_libs": tuple(force_load_libs),
        "lib_opts": lib_opts,
    }


def _new_project(angr: ModuleType, main_path: Path, load_options: dict[str, object]) -> Any:
    try:
        return angr.Project(
            str(main_path),
            use_sim_procedures=False,
            load_options=load_options,
        )
    except Exception as exc:
        raise AngropCompatibilityError(f"angr/CLE could not load exact image {main_path.name!r}") from exc


def _expected_angr_arch(target: Target, observed: str) -> bool:
    if target.arch is Architecture.X86:
        return observed == "X86"
    if target.arch is Architecture.X86_64:
        return observed == "AMD64"
    if target.arch in {Architecture.ARM, Architecture.THUMB}:
        return observed.startswith("ARM")
    if target.arch is Architecture.ARM64:
        return observed == "AARCH64"
    if target.arch in {Architecture.MIPS32, Architecture.MIPS64}:
        return observed.startswith("MIPS")
    if target.arch is Architecture.RISCV64:
        return observed == "RISCV64"
    return False


def _verify_project_target(project: Any, target: Target) -> None:
    arch = getattr(project, "arch", None)
    name = getattr(arch, "name", "")
    if not _expected_angr_arch(target, name):
        raise AngropCompatibilityError(f"angr reports architecture {name!r}, expected {target.name}")
    if getattr(arch, "bits", None) != target.bits:
        raise AngropCompatibilityError(f"angr reports {getattr(arch, 'bits', None)!r} bits, expected {target.bits}")
    expected_endness = "Iend_LE" if target.endian is Endian.LITTLE else "Iend_BE"
    if getattr(arch, "memory_endness", None) != expected_endness:
        raise AngropCompatibilityError(
            f"angr reports memory endness {getattr(arch, 'memory_endness', None)!r}, expected {expected_endness}"
        )


def _object_path(obj: Any) -> Path | None:
    binary = getattr(obj, "binary", None)
    if not isinstance(binary, (str, Path)):
        return None
    try:
        return Path(binary).resolve(strict=True)
    except OSError:
        return None


def _verify_exact_loader(
    project: Any,
    ordered: Sequence[tuple[AngropImageSpec, Path]],
    target: Target,
) -> None:
    _verify_project_target(project, target)
    loader = getattr(project, "loader", None)
    if loader is None:
        raise AngropCompatibilityError("angr project has no CLE loader")
    if bool(getattr(loader, "auto_load_libs", False)):
        raise AngropCompatibilityError("CLE enabled automatic dependency loading")

    expected_by_path = {path.resolve(): image for image, path in ordered}
    observed_by_path: dict[Path, Any] = {}
    for obj in getattr(loader, "all_elf_objects", ()):
        path = _object_path(obj)
        if path is not None:
            observed_by_path[path] = obj
    if set(observed_by_path) != set(expected_by_path):
        missing = sorted(path.name for path in set(expected_by_path) - set(observed_by_path))
        unexpected = sorted(path.name for path in set(observed_by_path) - set(expected_by_path))
        raise AngropCompatibilityError(
            f"CLE exact image set differs from the request (missing={missing}, unexpected={unexpected})"
        )
    for path, image in expected_by_path.items():
        observed_base = getattr(observed_by_path[path], "mapped_base", None)
        if observed_base != image.mapped_base:
            raise AngropCompatibilityError(
                f"CLE mapped {image.display_name!r} at {observed_base!r}, expected {image.mapped_base:#x}"
            )


def _analysis_constructor_options(target: Target, options: AngropDiscoveryOptions) -> dict[str, object]:
    return {
        "only_check_near_rets": options.only_check_near_rets,
        "fast_mode": options.fast_mode,
        "is_thumb": target.arch is Architecture.THUMB,
        "cond_br": options.cond_br,
        "max_bb_cnt": options.max_bb_cnt,
    }


def _vendored_rop_analysis_class(angrop: ModuleType) -> type[Any]:
    rop_module = getattr(angrop, "rop", None)
    analysis_class = getattr(rop_module, "ROP", None)
    if not isinstance(analysis_class, type):
        raise AngropCompatibilityError("vendored angrop does not expose its exact ROP analysis class")
    return analysis_class


def _new_rop_analysis(
    project: Any,
    target: Target,
    options: AngropDiscoveryOptions,
    analysis_class: type[Any],
) -> Any:
    try:
        factory = project.analyses[analysis_class]
        analysis = factory(**_analysis_constructor_options(target, options))
    except Exception as exc:
        raise AngropCompatibilityError("vendored angrop ROP analysis could not be constructed") from exc
    if type(analysis) is not analysis_class:
        raise AngropCompatibilityError("angr constructed a foreign ROP analysis instead of the vendored class")
    for attribute in ("_all_gadgets", "_duplicates", "_screen_gadgets"):
        if not hasattr(analysis, attribute):
            raise AngropCompatibilityError(f"vendored angrop no longer exposes required adapter hook {attribute!r}")
    return analysis


def _discover_project_gadgets(
    project: Any,
    target: Target,
    options: AngropDiscoveryOptions,
    analysis_class: type[Any],
) -> tuple[list[Any], dict[object, list[int]]]:
    analysis = _new_rop_analysis(project, target, options, analysis_class)
    kwargs: dict[str, object] = {
        "processes": options.processes,
        "show_progress": options.show_progress,
    }
    if options.timeout is not None:
        kwargs["timeout"] = options.timeout
    try:
        # Optimize only after all images have been merged so graph/ROPBlock
        # construction can combine semantics from different exact objects.
        analysis.find_gadgets(optimize=False, **kwargs)
    except Exception as exc:
        raise AngropCompatibilityError("vendored angrop gadget discovery failed") from exc
    gadgets = list(analysis._all_gadgets)
    duplicates = {key: list(addresses) for key, addresses in (analysis._duplicates or {}).items()}
    return gadgets, duplicates


def _merge_duplicates(
    destination: dict[object, list[int]],
    source: dict[object, list[int]],
) -> None:
    for key, addresses in source.items():
        existing = destination.setdefault(key, [])
        for address in addresses:
            if address not in existing:
                existing.append(address)


def _normalize_bad_bytes(values: Iterable[int | bytes]) -> frozenset[int]:
    result: set[int] = set()
    for value in values:
        if isinstance(value, bytes):
            if len(value) != 1:
                raise ValueError("bad-byte byte strings must have length one")
            value = value[0]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
            raise ValueError("bad bytes must be integers from 0 through 255 or one-byte values")
        result.add(value)
    return frozenset(result)


class _DeadlineExpired(BaseException):
    """Internal signal exception kept outside broad third-party catches."""


@contextmanager
def _operation_deadline(timeout: float | None):
    """Apply one non-polling wall-clock deadline to the complete operation."""

    if timeout is None:
        yield
        return
    if threading.current_thread() is not threading.main_thread():
        raise AngropCompatibilityError("a hard angrop timeout requires the Python main thread")
    if not all(hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")):
        raise AngropCompatibilityError("this host cannot provide a hard non-polling angrop timeout")
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining or interval:
        raise AngropCompatibilityError("a hard angrop timeout cannot replace an active ITIMER_REAL timer")
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expire(_signum: int, _frame: object) -> None:
        raise _DeadlineExpired

    signal.signal(signal.SIGALRM, expire)
    try:
        try:
            signal.setitimer(signal.ITIMER_REAL, timeout)
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, previous_handler)


def _entry_sp_alignment_bias(target: Target) -> int:
    if target.abi in {ABI.I386_SYSV, ABI.AMD64_SYSV}:
        return target.word_size
    return 0


def _direct_call_gadget(stage: Any, target: Target, function: int) -> Any:
    canonical = _canonical_code_address(target, function)
    matches = tuple(
        gadget
        for gadget in getattr(stage, "_gadgets", ())
        if isinstance(getattr(gadget, "addr", None), int) and _canonical_code_address(target, gadget.addr) == canonical
    )
    if not matches:
        raise AngropCompatibilityError(
            f"angrop used an indirect terminal for {function:#x}; exact function-entry alignment is unattested"
        )
    return matches[-1]


def _gadget_entry_sp_offset(chain: Any, target_gadget: Any, target: Target) -> int:
    """Compute entry SP from angrop semantics, not serialized word indices."""

    offset = target.word_size
    for gadget in getattr(chain, "_gadgets", ()):
        if gadget is target_gadget:
            return offset
        stack_change = getattr(gadget, "stack_change", None)
        if (
            isinstance(stack_change, bool)
            or not isinstance(stack_change, int)
            or stack_change < 0
            or stack_change % target.word_size
        ):
            raise AngropCompatibilityError("angrop emitted a gadget with an invalid stack_change")
        offset += stack_change
    raise AngropCompatibilityError("angrop lost a direct-call gadget while composing the chain")


def _entry_is_aligned(chain_base: int, entry_offset: int, target: Target) -> bool:
    return (chain_base + entry_offset + _entry_sp_alignment_bias(target)) % target.convention.stack_alignment == 0


def _alignment_prefixes(analysis: Any, target: Target) -> Iterable[Any]:
    """Yield bounded angrop-native stack shifts, shortest requests first."""

    alignment = target.convention.stack_alignment
    word = target.word_size
    shift = getattr(analysis, "shift", None)
    retsled = getattr(analysis, "retsled", None)
    for size in range(word, alignment * 2 + word, word):
        if callable(shift):
            try:
                yield shift(size)
            except Exception:  # noqa: BLE001,S110 - an unavailable shift is an expected candidate miss
                pass
        if callable(retsled):
            try:
                yield retsled(size)
            except Exception:  # noqa: BLE001,S110 - an unavailable shift is an expected candidate miss
                pass
        if callable(shift) and size > word:
            try:
                # Upstream refuses to synthesize a requested shift from more
                # than one gadget.  Its RopBlock API can still compose exact
                # word shifts, giving i386 (and sparse gadget sets generally)
                # every ABI-alignment residue without fabricating a chain.
                repeated = shift(word)
                for _ in range(1, size // word):
                    repeated = repeated + shift(word)
                yield repeated
            except Exception:  # noqa: BLE001,S110 - repeated shifts are an optional fallback
                pass


def _prepend_alignment_to_first_stage(prefix: Any, stage: Any) -> Any:
    """Compose an angrop shift block without inheriting RopBlock.__add__."""

    try:
        return prefix + stage
    except Exception as direct_error:
        # Shifter.shift() returns RopBlock.  Its specialized __add__ only
        # accepts another exact RopBlock, while a function call is a
        # RopChain.  Convert through an empty base chain so the pinned base
        # implementation performs both joins and owns the resulting type.
        module = importlib.import_module("payloads._vendor.angrop.rop_chain")
        chain_type = module.RopChain
        if type(prefix) is chain_type or not isinstance(prefix, chain_type):
            raise TypeError("alignment prefix is not a composable vendored RopBlock") from direct_error
        project = prefix._p
        builder = prefix._builder
        empty = chain_type(project, builder, badbytes=getattr(prefix, "badbytes", None))
        return (empty + prefix) + stage


def _align_call_stage(
    analysis: Any,
    prior_chain: Any | None,
    stage: Any,
    target_gadget: Any,
    target: Target,
    chain_base: int,
    call: AngropDirectCall,
) -> tuple[Any, int, int]:
    candidate = stage if prior_chain is None else prior_chain + stage
    entry_offset = _gadget_entry_sp_offset(candidate, target_gadget, target)
    if _entry_is_aligned(chain_base, entry_offset, target):
        return candidate, entry_offset, 0
    baseline_payload_len = int(getattr(candidate, "payload_len", 0))

    for prefix in _alignment_prefixes(analysis, target):
        try:
            if prior_chain is None:
                candidate = _prepend_alignment_to_first_stage(prefix, stage)
            else:
                candidate = (prior_chain + prefix) + stage
        except Exception:  # noqa: BLE001,S112 - not every angrop shift chain is composable
            continue
        entry_offset = _gadget_entry_sp_offset(candidate, target_gadget, target)
        if _entry_is_aligned(chain_base, entry_offset, target):
            padding = int(getattr(candidate, "payload_len", 0)) - baseline_payload_len
            if padding <= 0 or padding % target.word_size:
                raise AngropCompatibilityError("angrop alignment prefix has an invalid serialized size")
            return candidate, entry_offset, padding

    bias = _entry_sp_alignment_bias(target)
    raise AngropSynthesisError(
        f"angrop cannot align call {call.name or hex(call.function)!r}: entry SP "
        f"{chain_base + entry_offset:#x} plus ABI bias {bias:#x} must be a multiple of "
        f"{target.convention.stack_alignment}"
    )


def _builder_state_owner(builder: Any) -> type[Any] | None:
    """Find vendored Builder's class-owned writable-pointer scratch list."""

    candidates = (builder, *vars(builder).values())
    for candidate in candidates:
        for cls in type(candidate).__mro__:
            if "used_writable_ptrs" in vars(cls):
                return cls
    return None


@contextmanager
def _isolated_angrop_builder_state(builder: Any):
    """Serialize and isolate angrop's process-global writable-pointer scratch.

    Upstream ``Builder.used_writable_ptrs`` is a mutable class attribute.  Its
    graph optimizer calls the memory writer even for a direct-call-only
    session, so a per-session lock is insufficient when several prepared
    sessions coexist in one exploit process.
    """

    with _ANGROP_GLOBAL_STATE_LOCK:
        owner = _builder_state_owner(builder)
        if owner is None:
            raise AngropCompatibilityError("vendored angrop Builder.used_writable_ptrs hook is unavailable")
        previous = owner.used_writable_ptrs
        if not isinstance(previous, list):
            raise AngropCompatibilityError("vendored angrop Builder.used_writable_ptrs is not a list")
        owner.used_writable_ptrs = []
        try:
            yield
        finally:
            owner.used_writable_ptrs = previous


class PreparedAngropSession:
    """Digest-checked multi-image gadget inventory reusable across call chains."""

    def __init__(
        self,
        *,
        target: Target,
        images: tuple[AngropImageSpec, ...],
        cle_main_index: int,
        options: AngropDiscoveryOptions,
        project: Any,
        analysis_class: type[Any],
        all_gadgets: list[Any],
        duplicates: dict[object, list[int]],
        temporary: TemporaryDirectory[str],
        snapshot_paths: tuple[Path, ...],
        backend_revision: str,
    ) -> None:
        self.target = target
        self.images = images
        self.cle_main_index = cle_main_index
        self.options = options
        self._project = project
        self._analysis_class = analysis_class
        self._all_gadgets = all_gadgets
        self._duplicates = duplicates
        self._temporary = temporary
        self._snapshot_paths = snapshot_paths
        self.backend_revision = backend_revision
        self._analysis_cache: dict[frozenset[int], Any] = {}
        self._lock = threading.RLock()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def image_provenance(self) -> tuple[AngropImageProvenance, ...]:
        return tuple(
            AngropImageProvenance(
                index,
                image.display_name,
                image.adapter.path,
                image.identity.sha256,
                image.identity.build_id,
                image.load_bias,
                image.mapped_base,
                image.runtime_load_ranges,
                image.scan_gadgets,
                index == self.cle_main_index,
            )
            for index, image in enumerate(self.images)
        )

    def __enter__(self) -> Self:
        if self._closed:
            raise AngropCompatibilityError("prepared angrop session is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._analysis_cache.clear()
            self._all_gadgets.clear()
            self._duplicates.clear()
            self._project = None
            root = Path(self._temporary.name)
            try:
                root.chmod(0o700)
                for path in self._snapshot_paths:
                    if path.exists():
                        path.chmod(0o600)
            except OSError:
                pass
            self._temporary.cleanup()
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise AngropCompatibilityError("prepared angrop session is closed")

    def _owner_for_code(self, address: int) -> tuple[int, AngropImageSpec]:
        canonical = _canonical_code_address(self.target, address)
        matches: list[tuple[int, AngropImageSpec]] = []
        for index, image in enumerate(self.images):
            if any(item.executable and item.contains(canonical) for item in image.runtime_load_ranges):
                matches.append((index, image))
        if len(matches) != 1:
            if not matches:
                raise AngropSynthesisError(f"code address {address:#x} is outside every exact executable PT_LOAD")
            raise AngropCompatibilityError(f"code address {address:#x} belongs to overlapping exact images")
        return matches[0]

    def _validate_calls(self, calls: Sequence[AngropDirectCall]) -> tuple[AngropDirectCall, ...]:
        requested = tuple(calls)
        if not requested:
            raise AngropSynthesisError("at least one direct call is required")
        if any(not isinstance(call, AngropDirectCall) for call in requested):
            raise TypeError("calls must contain only AngropDirectCall records")
        normalized: list[AngropDirectCall] = []
        signed_minimum = -(1 << (self.target.bits - 1))
        for index, call in enumerate(requested):
            if index + 1 < len(requested) and not call.needs_return:
                raise AngropSynthesisError(f"non-final call {index} must return before the next ordered call")
            self.target.pack(call.function)
            self._owner_for_code(call.function)
            arguments: list[int] = []
            for argument in call.arguments:
                if argument < signed_minimum:
                    raise AngropSynthesisError(
                        f"call {index} argument {argument} is below the target's signed word range"
                    )
                word = argument & self.target.mask if argument < 0 else argument
                self.target.pack(word)
                arguments.append(word)
            normalized.append(
                AngropDirectCall(
                    call.function,
                    tuple(arguments),
                    call.name,
                    call.needs_return,
                )
            )
        if normalized[-1].needs_return:
            raise AngropSynthesisError(
                "the final call must use needs_return=False; no unmodeled continuation word is emitted"
            )
        return tuple(normalized)

    def _analysis_for(self, bad_bytes: frozenset[int]) -> Any:
        cached = self._analysis_cache.get(bad_bytes)
        if cached is not None:
            return cached
        analysis = _new_rop_analysis(
            self._project,
            self.target,
            self.options,
            self._analysis_class,
        )
        analysis._all_gadgets = list(self._all_gadgets)
        analysis._duplicates = {key: list(value) for key, value in self._duplicates.items()}
        analysis.badbytes = sorted(bad_bytes)
        try:
            analysis._screen_gadgets()
            builder = analysis.chain_builder
            with _isolated_angrop_builder_state(builder):
                if self.options.optimize:
                    builder.optimize(processes=self.options.processes)
        except Exception as exc:
            raise AngropCompatibilityError("vendored angrop could not prepare the merged multi-image builder") from exc
        for method in ("func_call",):
            if not callable(getattr(analysis, method, None)):
                raise AngropCompatibilityError(f"vendored angrop analysis lacks required method {method!r}")
        self._analysis_cache[bad_bytes] = analysis
        return analysis

    def _call_provenance(
        self,
        calls: Sequence[AngropDirectCall],
        entry_offsets: Sequence[int],
        alignment_paddings: Sequence[int],
        chain_base: int,
    ) -> tuple[AngropCallProvenance, ...]:
        records: list[AngropCallProvenance] = []
        alignment = self.target.convention.stack_alignment
        bias = _entry_sp_alignment_bias(self.target)
        for index, (call, entry_offset, alignment_padding) in enumerate(
            zip(calls, entry_offsets, alignment_paddings, strict=True)
        ):
            image_index, image = self._owner_for_code(call.function)
            canonical = _canonical_code_address(self.target, call.function)
            entry_sp = chain_base + entry_offset
            if (entry_sp + bias) % alignment:
                raise AngropCompatibilityError("an angrop call lost its validated ABI stack alignment")
            records.append(
                AngropCallProvenance(
                    index,
                    call.name,
                    call.function,
                    call.arguments,
                    call.needs_return,
                    image_index,
                    image.display_name,
                    image.identity.sha256,
                    canonical - image.load_bias,
                    entry_sp,
                    entry_offset,
                    alignment,
                    bias,
                    alignment_padding,
                )
            )
        return tuple(records)

    def _gadget_provenance(
        self,
        chain: Any,
        calls: Sequence[AngropDirectCall],
    ) -> tuple[AngropGadgetProvenance, ...]:
        call_targets = {call.function for call in calls}
        records: list[AngropGadgetProvenance] = []
        for index, gadget in enumerate(getattr(chain, "_gadgets", ())):
            address = getattr(gadget, "addr", None)
            if isinstance(address, bool) or not isinstance(address, int):
                raise AngropCompatibilityError("angrop emitted a gadget without a concrete integer address")
            image_index, image = self._owner_for_code(address)
            dstr = getattr(gadget, "dstr", None)
            try:
                description = str(dstr()) if callable(dstr) else type(gadget).__name__
            except Exception:  # noqa: BLE001 - provenance rendering must not break a valid chain
                description = type(gadget).__name__
            canonical = _canonical_code_address(self.target, address)
            records.append(
                AngropGadgetProvenance(
                    index,
                    address,
                    description,
                    image_index,
                    image.display_name,
                    image.identity.sha256,
                    canonical - image.load_bias,
                    address in call_targets,
                )
            )
        return tuple(records)

    def synthesize_calls(
        self,
        calls: Sequence[AngropDirectCall],
        *,
        chain_base: int,
        bad_bytes: Iterable[int | bytes] = (),
        timeout: float | None = None,
    ) -> AngropSynthesisResult:
        """Synthesize aligned calls at one exact chain address before a deadline."""

        with self._lock:
            self._require_open()
            normalized_calls = self._validate_calls(calls)
            normalized_bad_bytes = _normalize_bad_bytes(bad_bytes)
            if isinstance(chain_base, bool) or not isinstance(chain_base, int):
                raise TypeError("chain_base must be an int")
            if not 0 <= chain_base <= self.target.mask:
                raise ValueError("chain_base does not fit the target address width")
            if timeout is not None and not _is_positive_finite_number(timeout):
                raise ValueError("timeout must be a positive finite number or None")
            try:
                with _operation_deadline(timeout):
                    analysis = self._analysis_for(normalized_bad_bytes)
                    chain = None
                    entry_offsets: list[int] = []
                    alignment_paddings: list[int] = []
                    try:
                        with _isolated_angrop_builder_state(analysis.chain_builder):
                            for call in normalized_calls:
                                stage = analysis.func_call(
                                    call.function,
                                    list(call.arguments),
                                    needs_return=call.needs_return,
                                )
                                target_gadget = _direct_call_gadget(stage, self.target, call.function)
                                chain, entry_offset, alignment_padding = _align_call_stage(
                                    analysis,
                                    chain,
                                    stage,
                                    target_gadget,
                                    self.target,
                                    chain_base,
                                    call,
                                )
                                entry_offsets.append(entry_offset)
                                alignment_paddings.append(alignment_padding)
                            if chain is None:  # pragma: no cover - guarded by _validate_calls
                                raise AngropSynthesisError("angrop returned no chain")
                            raw = chain.payload_str(timeout=None)
                    except AngropBackendError:
                        raise
                    except Exception as exc:
                        raise AngropSynthesisError(
                            "vendored angrop failed to synthesize the ordered direct calls"
                        ) from exc

                    if not isinstance(raw, (bytes, bytearray)):
                        raise AngropCompatibilityError("angrop payload_str() did not return bytes")
                    data = bytes(raw)
                    if len(data) % self.target.word_size:
                        raise AngropCompatibilityError("angrop emitted a payload not aligned to the target word size")
                    if chain_base + len(data) > self.target.mask + 1:
                        raise AngropSynthesisError("serialized angrop chain exceeds the target address space")
                    violations = tuple(
                        (offset, value) for offset, value in enumerate(data) if value in normalized_bad_bytes
                    )
                    if violations:
                        raise AngropBadByteError(violations)
                    words = tuple(
                        self.target.unpack(data[offset : offset + self.target.word_size])
                        for offset in range(0, len(data), self.target.word_size)
                    )
                    return AngropSynthesisResult(
                        self.target,
                        chain_base,
                        data,
                        words,
                        self.image_provenance,
                        self._call_provenance(
                            normalized_calls,
                            entry_offsets,
                            alignment_paddings,
                            chain_base,
                        ),
                        self._gadget_provenance(chain, normalized_calls),
                        normalized_bad_bytes,
                        self.backend_revision,
                        self.options,
                    )
            except _DeadlineExpired as exc:
                raise AngropTimeoutError(f"angrop synthesis exceeded its {timeout:g}-second deadline") from exc


def _snapshot_exact_images(
    images: Sequence[AngropImageSpec],
) -> tuple[TemporaryDirectory[str], tuple[Path, ...], tuple[bytes, ...]]:
    temporary: TemporaryDirectory[str] = TemporaryDirectory(prefix="pwnc-angrop-")
    root = Path(temporary.name)
    paths: list[Path] = []
    raw_images: list[bytes] = []
    try:
        for index, image in enumerate(images):
            raw = image.adapter.verified_artifact_bytes()
            path = root / f"image-{index:03d}-{image.identity.sha256[:16]}.elf"
            path.write_bytes(raw)
            path.chmod(0o400)
            paths.append(path)
            raw_images.append(raw)
        root.chmod(0o500)
    except Exception:
        try:
            root.chmod(0o700)
            for path in paths:
                path.chmod(0o600)
        except OSError:
            pass
        temporary.cleanup()
        raise
    return temporary, tuple(paths), tuple(raw_images)


def _verify_snapshots(
    images: Sequence[AngropImageSpec],
    paths: Sequence[Path],
    expected_raw: Sequence[bytes],
) -> None:
    from hashlib import sha256

    for image, path, raw in zip(images, paths, expected_raw, strict=True):
        try:
            observed = path.read_bytes()
        except OSError as exc:
            raise AngropCompatibilityError("an exact angrop analysis snapshot disappeared") from exc
        if observed != raw or sha256(observed).hexdigest() != image.identity.sha256:
            raise AngropCompatibilityError(f"exact angrop snapshot for {image.display_name!r} changed during analysis")


def prepare_angrop(
    images: Sequence[AngropImageSpec],
    *,
    target: Target | None = None,
    options: AngropDiscoveryOptions | None = None,
) -> PreparedAngropSession:
    """Authenticate, map, and discover a reusable exact multi-image session."""

    normalized, selected_target, cle_main_index = _validate_image_set(images, target)
    selected_options = AngropDiscoveryOptions() if options is None else options
    if not isinstance(selected_options, AngropDiscoveryOptions):
        raise TypeError("options must be AngropDiscoveryOptions or None")

    # Import only after all inexpensive structural and overlap validation has
    # passed.  The embedded ROP class is instantiated by exact class identity;
    # no named global analysis registration or external top-level angrop
    # package is ever considered.
    angr, angrop = _load_angrop_modules()
    analysis_class = _vendored_rop_analysis_class(angrop)
    backend_version = str(getattr(angrop, "__version__", "unknown"))
    backend_revision = f"{backend_version}+{ANGROP_VENDOR_REVISION}"

    temporary, snapshot_paths, expected_raw = _snapshot_exact_images(normalized)
    try:
        indexed = tuple(zip(normalized, snapshot_paths, strict=True))
        primary = indexed[cle_main_index]
        supplemental = tuple(item for index, item in enumerate(indexed) if index != cle_main_index)
        combined_order = (primary, *supplemental)
        combined = _new_project(
            angr,
            primary[1],
            _project_load_options(primary, supplemental),
        )
        _verify_exact_loader(combined, combined_order, selected_target)

        all_gadgets: list[Any] = []
        duplicates: dict[object, list[int]] = {}
        for image, path in indexed:
            if not image.scan_gadgets:
                continue
            project = _new_project(
                angr,
                path,
                _project_load_options((image, path), ()),
            )
            _verify_exact_loader(project, ((image, path),), selected_target)
            gadgets, image_duplicates = _discover_project_gadgets(
                project,
                selected_target,
                selected_options,
                analysis_class,
            )
            for gadget in gadgets:
                # Upstream gadget semantics are address based.  The combined
                # project maps the same exact bytes at the same address.
                if hasattr(gadget, "project"):
                    gadget.project = combined
            all_gadgets.extend(gadgets)
            _merge_duplicates(duplicates, image_duplicates)

        _verify_snapshots(normalized, snapshot_paths, expected_raw)
        return PreparedAngropSession(
            target=selected_target,
            images=normalized,
            cle_main_index=cle_main_index,
            options=selected_options,
            project=combined,
            analysis_class=analysis_class,
            all_gadgets=all_gadgets,
            duplicates=duplicates,
            temporary=temporary,
            snapshot_paths=snapshot_paths,
            backend_revision=backend_revision,
        )
    except Exception:
        root = Path(temporary.name)
        try:
            root.chmod(0o700)
            for path in snapshot_paths:
                if path.exists():
                    path.chmod(0o600)
        except OSError:
            pass
        temporary.cleanup()
        raise


__all__ = [
    "ANGROP_BASELINE_REVISION",
    "ANGROP_PATCHED_SOURCE_SHA256",
    "ANGROP_VENDOR_REVISION",
    "AngropBackendError",
    "AngropBadByteError",
    "AngropCallProvenance",
    "AngropCompatibilityError",
    "AngropDirectCall",
    "AngropDiscoveryOptions",
    "AngropGadgetProvenance",
    "AngropImageError",
    "AngropImageProvenance",
    "AngropImageSpec",
    "AngropRuntimeRange",
    "AngropSynthesisError",
    "AngropSynthesisResult",
    "AngropTimeoutError",
    "AngropUnavailableError",
    "PreparedAngropSession",
    "prepare_angrop",
]
