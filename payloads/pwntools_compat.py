"""Read-only, exact-artifact adapters for selected pwntools features.

Pwntools is excellent at ELF symbol access, mitigation discovery, packing, and
ROP gadget discovery.  Some of its convenience properties also start the
inspected program to discover its runtime environment.  Payload construction
must never do that implicitly, so this module exposes only byte-backed facts
and creates a fresh :class:`pwnlib.elf.elf.ELF` after rechecking the artifact
digest whenever a caller explicitly requests a pwntools ROP object.
"""

from __future__ import annotations

import logging
import warnings
import weakref
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import InitVar, dataclass, replace
from hashlib import sha256
from pathlib import Path
from tempfile import mkdtemp
from types import MappingProxyType

from pwnlib.context import context
from pwnlib.elf.elf import ELF
from pwnlib.rop.rop import ROP
from pwnlib.util.packing import pack

from .elf import ELFProfile, inspect_elf
from .libc import LibcIdentity
from .model import Relro
from .target import ABI, Architecture, Target


class PwntoolsCompatibilityError(ValueError):
    """An exact artifact and pwntools' interpretation do not agree."""


class PwntoolsROPUnsupported(PwntoolsCompatibilityError):
    """Automatic pwntools ROP lowering is not claimed for this target."""


_EXACT_ELF_FACTORY_TOKEN = object()


class _MissingGOTFilter(logging.Filter):
    """Drop one noisy pwntools diagnostic for intentionally tiny ELFs."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not (record.name == "pwnlib.elf.elf" and record.getMessage() == "Did not find any GOT entries")


@contextmanager
def _suppress_missing_got_warning():
    """Suppress only pwntools' expected no-GOT warning, never exceptions."""

    logger = logging.getLogger("pwnlib.elf.elf")
    warning_filter = _MissingGOTFilter()
    logger.addFilter(warning_filter)
    try:
        yield
    finally:
        logger.removeFilter(warning_filter)


@contextmanager
def _suppress_rop_cache_resource_warning():
    """Work around pwntools' known unclosed ROP-cache file expression."""

    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r"unclosed file <_io\.TextIOWrapper name='.*[/\\]rop-cache[/\\].*'",
            category=ResourceWarning,
            module=r"pwnlib\.rop\.rop",
        )
        yield


@dataclass(frozen=True, slots=True)
class PwntoolsMitigations:
    """Mitigation facts obtained without executing the inspected ELF."""

    pie: bool
    nx: bool
    relro: Relro
    canary: bool
    fortify: bool


def _target_key(target: Target) -> tuple[object, ...]:
    return (
        target.arch,
        target.bits,
        target.endian,
        target.abi,
        target.function_pointer_model,
    )


def _pwntools_relro(value: str | None) -> Relro:
    if value is None:
        return Relro.NONE
    normalized = value.strip().lower()
    if normalized == "partial":
        return Relro.PARTIAL
    if normalized == "full":
        return Relro.FULL
    raise PwntoolsCompatibilityError(f"pwntools returned an unknown RELRO value: {value!r}")


def _expected_pwntools_arch(target: Target) -> str:
    # The backend spelling is already part of Target, but keeping this table
    # explicit catches an accidentally constructed Target with a misleading
    # backend alias before pwntools is asked to discover gadgets.
    return {
        Architecture.X86: "i386",
        Architecture.X86_64: "amd64",
        Architecture.ARM: "arm",
        Architecture.THUMB: "thumb",
        Architecture.ARM64: "aarch64",
        Architecture.MIPS32: "mips",
        Architecture.MIPS64: "mips64",
        Architecture.RISCV32: "riscv32",
        Architecture.RISCV64: "riscv64",
        Architecture.POWERPC32: "powerpc",
        Architecture.POWERPC64: "powerpc64",
        Architecture.SPARC32: "sparc",
        Architecture.SPARC64: "sparc64",
        Architecture.S390X: "s390",
    }[target.arch]


def _accepted_pwntools_elf_arches(target: Target) -> tuple[str, ...]:
    """Return parser spellings accepted for an exact target.

    Pwntools' public context spelling for s390x is ``s390``, while its ELF
    parser can expose pyelftools' machine name ``em_s390`` for a real s390x
    artifact.  Keep the context/backend spelling strict and admit the parser
    alias only at the byte-backed ELF cross-check boundary.
    """

    expected = _expected_pwntools_arch(target)
    if target.arch is Architecture.S390X:
        return (expected, "em_s390")
    return (expected,)


def _crosscheck_pwntools_elf(elf: ELF, profile: ELFProfile) -> PwntoolsMitigations:
    target = profile.target
    expected_arch = _expected_pwntools_arch(target)
    if target.pwntools_arch != expected_arch:
        raise PwntoolsCompatibilityError(
            f"target backend alias {target.pwntools_arch!r} does not match {expected_arch!r} for {target.name}"
        )
    accepted_arches = _accepted_pwntools_elf_arches(target)
    if elf.arch not in accepted_arches:
        expected_description = (
            repr(expected_arch)
            if len(accepted_arches) == 1
            else "one of " + ", ".join(repr(item) for item in accepted_arches)
        )
        raise PwntoolsCompatibilityError(
            f"pwntools reports arch={elf.arch!r}, expected {expected_description} for {target.name}"
        )
    if elf.bits != target.bits:
        raise PwntoolsCompatibilityError(f"pwntools reports {elf.bits} bits, expected {target.bits}")
    if elf.endian != target.endian.value:
        raise PwntoolsCompatibilityError(f"pwntools reports endian={elf.endian!r}, expected {target.endian.value!r}")
    if elf.os != target.os:
        raise PwntoolsCompatibilityError(f"pwntools reports OS {elf.os!r}, expected {target.os!r}")

    mitigations = PwntoolsMitigations(
        pie=bool(elf.pie),
        nx=bool(elf.nx),
        relro=_pwntools_relro(elf.relro),
        canary=bool(elf.canary),
        fortify=bool(elf.fortify),
    )
    if mitigations.pie != profile.pie:
        raise PwntoolsCompatibilityError("pwntools and ELFProfile disagree about PIE")
    if profile.nx is not None and mitigations.nx != profile.nx:
        raise PwntoolsCompatibilityError("pwntools and ELFProfile disagree about NX")
    if mitigations.relro is not profile.relro:
        raise PwntoolsCompatibilityError("pwntools and ELFProfile disagree about RELRO")

    # Pwntools keeps ordinary symbols when it adds its synthetic plt./got.
    # aliases.  Cross-check all symbols independently parsed by ELFProfile.
    for name, expected in profile.symbol_offsets.items():
        observed = elf.symbols.get(name)
        if observed is not None and int(observed) != expected:
            raise PwntoolsCompatibilityError(
                f"pwntools and ELFProfile disagree about symbol {name!r}: {observed:#x} != {expected:#x}"
            )
    return mitigations


def _same_profile_facts(left: ELFProfile, right: ELFProfile) -> bool:
    """Compare byte-derived profile facts while ignoring path spelling."""

    return replace(left, path="") == replace(right, path="")


def _cleanup_snapshot(mapping: object | None, file: object | None, path: Path) -> None:
    for resource in (mapping, file):
        close = getattr(resource, "close", None)
        if close is not None:
            try:
                close()
            except (BufferError, OSError, ValueError):
                pass
    directory = path.parent
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        directory.rmdir()
    except OSError:
        pass


class _SnapshotELF(ELF):
    """Pwntools ELF backed by a private read-only artifact snapshot."""

    def __init__(self, raw: bytes, *, checksec: bool = False) -> None:
        snapshot_directory = Path(mkdtemp(prefix="pwnc-exact-elf-"))
        snapshot_path = snapshot_directory / "artifact.elf"
        self._pwnc_snapshot_path = snapshot_path
        try:
            snapshot_path.write_bytes(raw)
            snapshot_path.chmod(0o400)
            snapshot_directory.chmod(0o500)
            # Preserve the inspector's stable domain errors and bind pwntools
            # to the same private snapshot used for independent profiling.
            self._pwnc_profile = inspect_elf(snapshot_path)
            super().__init__(str(snapshot_path), checksec=checksec)
            self._pwnc_finalizer = weakref.finalize(
                self,
                _cleanup_snapshot,
                self.mmap,
                self.file,
                snapshot_path,
            )
        except Exception:
            _cleanup_snapshot(getattr(self, "mmap", None), getattr(self, "file", None), snapshot_path)
            raise

    def close(self) -> None:
        finalizer = getattr(self, "_pwnc_finalizer", None)
        if finalizer is not None:
            finalizer()

    def verify_snapshot(self, expected_sha256: str) -> None:
        try:
            raw = self._pwnc_snapshot_path.read_bytes()
        except OSError as exc:
            raise PwntoolsCompatibilityError("the private ELF snapshot disappeared") from exc
        if sha256(raw).hexdigest() != expected_sha256:
            raise PwntoolsCompatibilityError("the private ELF snapshot changed during pwntools processing")


@dataclass(frozen=True, slots=True)
class ExactELFAdapter:
    """Immutable facts for one ELF plus safe factories for fresh pwntools objects."""

    path: str
    identity: LibcIdentity
    profile: ELFProfile
    symbols: Mapping[str, int]
    mitigations: PwntoolsMitigations
    _factory_token: InitVar[object | None] = None

    def __post_init__(self, _factory_token: object | None) -> None:
        if _factory_token is not _EXACT_ELF_FACTORY_TOKEN:
            raise PwntoolsCompatibilityError("ExactELFAdapter must be constructed with ExactELFAdapter.from_file()")
        object.__setattr__(self, "symbols", MappingProxyType(dict(self.symbols)))

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        profile: ELFProfile | None = None,
        expected_identity: LibcIdentity | None = None,
        expected_target: Target | None = None,
    ) -> ExactELFAdapter:
        artifact = Path(path).resolve(strict=True)
        raw = artifact.read_bytes()
        digest = sha256(raw).hexdigest()
        with _suppress_missing_got_warning(), context.local(log_level="error"):
            elf = _SnapshotELF(raw, checksec=False)
            try:
                independently_inspected = replace(elf._pwnc_profile, path=str(artifact))
                if profile is not None and not _same_profile_facts(profile, independently_inspected):
                    raise PwntoolsCompatibilityError(
                        "caller-supplied ELFProfile differs from an independent inspection of the artifact"
                    )
                inspected = independently_inspected
                if inspected.sha256 != digest:
                    raise PwntoolsCompatibilityError("ELFProfile does not describe the current artifact bytes")
                if expected_identity is not None:
                    if expected_identity.sha256 != digest:
                        raise PwntoolsCompatibilityError("the artifact does not match the required exact identity")
                    if expected_identity.build_id is not None and expected_identity.build_id != inspected.build_id:
                        raise PwntoolsCompatibilityError("the artifact build ID does not match the required identity")
                if expected_target is not None and _target_key(expected_target) != _target_key(inspected.target):
                    raise PwntoolsCompatibilityError(
                        f"artifact target {inspected.target.name} does not match required target {expected_target.name}"
                    )
                mitigations = _crosscheck_pwntools_elf(elf, inspected)
                symbols = dict(elf.symbols)
            finally:
                elf.close()
        identity = expected_identity or LibcIdentity(
            digest,
            build_id=inspected.build_id,
            source=str(artifact),
        )
        return cls(
            str(artifact),
            identity,
            inspected,
            symbols,
            mitigations,
            _factory_token=_EXACT_ELF_FACTORY_TOKEN,
        )

    @property
    def target(self) -> Target:
        return self.profile.target

    def symbol(self, name: str) -> int:
        """Return one exact ELF virtual symbol value."""

        try:
            return self.symbols[name]
        except KeyError as exc:
            raise KeyError(f"symbol {name!r} is absent from {self.identity.sha256[:12]}") from exc

    def crosscheck_profile(self, profile: ELFProfile) -> None:
        """Verify that another independently obtained profile is identical."""

        if profile.sha256 != self.identity.sha256:
            raise PwntoolsCompatibilityError("ELFProfile SHA-256 differs from the adapter identity")
        if profile.build_id != self.profile.build_id:
            raise PwntoolsCompatibilityError("ELFProfile build ID differs from the adapter profile")
        if _target_key(profile.target) != _target_key(self.target):
            raise PwntoolsCompatibilityError("ELFProfile target differs from the adapter target")
        if profile.pie != self.profile.pie or profile.nx != self.profile.nx or profile.relro is not self.profile.relro:
            raise PwntoolsCompatibilityError("ELFProfile mitigation facts differ from the adapter profile")
        if not _same_profile_facts(profile, self.profile):
            raise PwntoolsCompatibilityError("ELFProfile byte-derived facts differ from the adapter profile")

    def verified_artifact_bytes(self) -> bytes:
        """Return one digest-checked snapshot of the exact local artifact."""

        raw = Path(self.path).read_bytes()
        observed = sha256(raw).hexdigest()
        if observed != self.identity.sha256:
            raise PwntoolsCompatibilityError("the ELF artifact changed after the adapter was created")
        return raw

    def fresh_elf(self, *, runtime_base: int | None = None) -> ELF:
        """Return a newly loaded pwntools ELF after revalidating its digest.

        This method never accesses ``ELF.libs``, ``ELF.maps``, ``ELF.libc``, or
        any other process-backed property.  Setting ``runtime_base`` only
        rebases the new in-memory pwntools object.
        """

        if runtime_base is not None:
            if isinstance(runtime_base, bool) or not isinstance(runtime_base, int):
                raise TypeError("runtime_base must be an int or None")
            if not 0 <= runtime_base <= self.target.mask:
                raise ValueError("runtime_base does not fit the target address width")

        raw = self.verified_artifact_bytes()
        with _suppress_missing_got_warning(), context.local(log_level="error"):
            elf = _SnapshotELF(raw, checksec=False)
            try:
                _crosscheck_pwntools_elf(elf, self.profile)
                elf.verify_snapshot(self.identity.sha256)
            except Exception:
                elf.close()
                raise
        if runtime_base is not None:
            elf.address = runtime_base
        return elf

    def fresh_rop(self, *, runtime_base: int | None = None) -> tuple[ELF, ROP]:
        """Create a pwntools ROP object for the targets we verify automatically."""

        images, rop = self.fresh_rop_group(runtime_base=runtime_base)
        return images[0], rop

    def fresh_rop_group(
        self,
        *,
        runtime_base: int | None = None,
        extra_images: Sequence[tuple[ExactELFAdapter, int | None]] = (),
    ) -> tuple[tuple[ELF, ...], ROP]:
        """Create one ROP search space from exact, target-compatible ELFs.

        ``self`` remains the primary image (normally libc).  Extra images are
        useful for the challenge binary's register-loading and stack-cleanup
        gadgets when the selected libc does not happen to contain a complete
        sequence.  A ``None`` base preserves an ELF's linked virtual
        addresses; PIE images need their disclosed runtime base explicitly.
        Every adapter rechecks its artifact digest before pwntools sees it.
        """

        if self.target.abi not in {ABI.I386_SYSV, ABI.AMD64_SYSV}:
            raise PwntoolsROPUnsupported(
                f"automatic pwntools ROP lowering is only claimed for i386/AMD64, not {self.target.name}"
            )
        normalized = tuple(extra_images)
        seen = {self.identity.sha256}
        for index, item in enumerate(normalized):
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError(f"extra image {index} must be an (ExactELFAdapter, runtime_base) tuple")
            adapter, base = item
            if not isinstance(adapter, ExactELFAdapter):
                raise TypeError(f"extra image {index} must contain an ExactELFAdapter")
            if _target_key(adapter.target) != _target_key(self.target):
                raise PwntoolsCompatibilityError(
                    f"extra image target {adapter.target.name} does not match primary target {self.target.name}"
                )
            if adapter.identity.sha256 in seen:
                raise PwntoolsCompatibilityError("a ROP search space cannot contain the same exact ELF twice")
            seen.add(adapter.identity.sha256)
            if base is not None and (isinstance(base, bool) or not isinstance(base, int)):
                raise TypeError(f"extra image {index} runtime base must be an int or None")

        images: list[ELF] = []
        try:
            images.append(self.fresh_elf(runtime_base=runtime_base))
            for adapter, base in normalized:
                images.append(adapter.fresh_elf(runtime_base=base))
            with (
                _suppress_rop_cache_resource_warning(),
                context.local(
                    arch=self.target.pwntools_arch,
                    bits=self.target.bits,
                    endian=self.target.endian.value,
                    os=self.target.os,
                    log_level="error",
                ),
            ):
                rop = ROP(images)
            for adapter, image in zip((self, *(item[0] for item in normalized)), images, strict=True):
                if not isinstance(image, _SnapshotELF):  # pragma: no cover - fresh_elf is fixed above
                    raise PwntoolsCompatibilityError("pwntools ROP image is not backed by a private snapshot")
                image.verify_snapshot(adapter.identity.sha256)
        except Exception:
            for image in images:
                image.close()
            raise
        return tuple(images), rop


def pack_target_word(target: Target, value: int) -> bytes:
    """Strict target packing implemented through pwntools and cross-checked."""

    expected = target.pack(value)
    with context.local(bits=target.bits, endian=target.endian.value, os=target.os):
        observed = pack(value, word_size=target.bits, endianness=target.endian.value, sign=False)
    if observed != expected:  # pragma: no cover - guards a backend regression
        raise PwntoolsCompatibilityError("pwntools packing disagrees with Target.pack")
    return observed


__all__ = [
    "ExactELFAdapter",
    "PwntoolsCompatibilityError",
    "PwntoolsMitigations",
    "PwntoolsROPUnsupported",
    "pack_target_word",
]
