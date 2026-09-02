from __future__ import annotations

import concurrent.futures
import importlib.util
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, Self
from unittest import mock

from payloads.angrop_backend import (
    ANGROP_BASELINE_REVISION,
    ANGROP_VENDOR_REVISION,
    AngropBadByteError,
    AngropCompatibilityError,
    AngropDirectCall,
    AngropDiscoveryOptions,
    AngropImageError,
    AngropImageSpec,
    AngropSynthesisError,
    AngropTimeoutError,
    _load_angrop_modules,
    _operation_deadline,
    prepare_angrop,
)
from payloads.elf import inspect_elf
from payloads.errors import UnsupportedTargetError
from payloads.model import Permission
from payloads.pwntools_compat import ExactELFAdapter
from payloads.rop import ROPBuildError
from payloads.target import resolve_target

_ASSEMBLY = r"""
.text
.globl first, second, gadget
.type first,@function
first: ret
.type second,@function
second: ret
.type gadget,@function
gadget: pop %rdi; ret
"""

_AARCH64_ASSEMBLY = r"""
.text
.globl first, second
.type first,%function
first: ret
.type second,%function
second: ret
.globl shift_x30, load_x0_x16, load_x30_x16
.type shift_x30,%function
shift_x30: ldr x30, [sp], #8; ret
.type load_x0_x16,%function
load_x0_x16: ldp x0, x16, [sp], #16; br x16
.type load_x30_x16,%function
load_x30_x16: ldp x30, x16, [sp], #16; br x16
"""

_ARM_EABI_QEMU_MARKER = b"PWNC_ARM_ANGROP\n"
_ARM_EABI_QEMU_ASSEMBLY = r"""
.syntax unified
.arch armv7-a
.arm
.section .text
.global _start
.type _start,%function
_start:
  ldr sp, =chain
  pop {pc}
.global pwnc_pop_args
.type pwnc_pop_args,%function
pwnc_pop_args:
  pop {r0, r1, r2, r3, pc}
.global pwnc_pop_lr
.type pwnc_pop_lr,%function
pwnc_pop_lr:
  pop {lr}
  pop {pc}
.global pwnc_write_checked
.type pwnc_write_checked,%function
pwnc_write_checked:
  tst sp, #7
  bne pwnc_alignment_failure
  mov r7, #4
  svc #0
  bx lr
.global pwnc_exit
.type pwnc_exit,%function
pwnc_exit:
  tst sp, #7
  bne pwnc_alignment_failure
  mov r7, #1
  svc #0
  udf #0
pwnc_alignment_failure:
  mov r0, #99
  mov r7, #1
  svc #0
  udf #0
.section .rodata
.global pwnc_marker
pwnc_marker:
  .ascii "PWNC_ARM_ANGROP\n"
.global pwnc_marker_end
pwnc_marker_end:
.section .data
.balign 16
.global chain
chain:
  .space 4096
.section .note.GNU-stack,"",%progbits
"""

_AARCH64_QEMU_MARKER = b"PWNC_AARCH64_ANGROP\n"
_AARCH64_QEMU_ASSEMBLY = r"""
.arch armv8-a
.section .text
.global _start
.type _start,%function
_start:
  adrp x9, chain
  add x9, x9, :lo12:chain
  mov sp, x9
  ldr x30, [sp], #8
  ret
.global pwnc_load_x0_x16
.type pwnc_load_x0_x16,%function
pwnc_load_x0_x16:
  ldp x0, x16, [sp], #16
  br x16
.global pwnc_load_x1_x16
.type pwnc_load_x1_x16,%function
pwnc_load_x1_x16:
  ldp x1, x16, [sp], #16
  br x16
.global pwnc_load_x2_x16
.type pwnc_load_x2_x16,%function
pwnc_load_x2_x16:
  ldp x2, x16, [sp], #16
  br x16
.global pwnc_load_x30_x16
.type pwnc_load_x30_x16,%function
pwnc_load_x30_x16:
  ldp x30, x16, [sp], #16
  br x16
.global pwnc_write_checked
.type pwnc_write_checked,%function
pwnc_write_checked:
  mov x9, sp
  and x9, x9, #15
  cbnz x9, pwnc_alignment_failure
  mov x8, #64
  svc #0
  ret
.global pwnc_exit
.type pwnc_exit,%function
pwnc_exit:
  mov x9, sp
  and x9, x9, #15
  cbnz x9, pwnc_alignment_failure
  mov x8, #93
  svc #0
  brk #0
pwnc_alignment_failure:
  mov x0, #99
  mov x8, #93
  svc #0
  brk #0
.section .rodata
.global pwnc_marker
pwnc_marker:
  .ascii "PWNC_AARCH64_ANGROP\n"
.global pwnc_marker_end
pwnc_marker_end:
.section .data
.balign 16
.global chain
chain:
  .space 4096
.section .note.GNU-stack,"",%progbits
"""

_CHAIN_BASE = 0x7FFFFFFFD000
_QEMU_OPT_IN = os.environ.get("PWNC_QEMU_TESTS") == "1"
_ARM_EABI_QEMU_REQUIRED_TOOLS = ("zig", "qemu-arm")
_AARCH64_QEMU_REQUIRED_TOOLS = ("zig", "qemu-aarch64")


class _BoundedPipeBlock:
    """A blocking syscall with a condition-based test watchdog, never a poll."""

    def __init__(self, watchdog_seconds: float = 1.0) -> None:
        self.read_fd, self.write_fd = os.pipe()
        self.watchdog = threading.Timer(
            watchdog_seconds,
            os.write,
            args=(self.write_fd, b"\x01"),
        )

    def __enter__(self) -> Self:
        self.watchdog.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.watchdog.cancel()
        self.watchdog.join()
        os.close(self.read_fd)
        os.close(self.write_fd)

    def block(self, *_args: object, **_kwargs: object) -> bytes:
        return os.read(self.read_fd, 1)


def _compile_fixture(root: Path, name: str, *, executable: bool) -> Path:
    output = root / name
    command = [
        "cc",
        "-nostdlib",
        "-Wl,--build-id",
        "-Wl,-z,noexecstack",
        "-x",
        "assembler",
        "-",
        "-o",
        str(output),
    ]
    if executable:
        command[1:1] = ["-no-pie", "-Wl,-e,first"]
    else:
        command[1:1] = ["-shared", f"-Wl,-soname,{name}"]
    result = subprocess.run(command, input=_ASSEMBLY, text=True, capture_output=True, check=False)
    if result.returncode:
        raise unittest.SkipTest(f"exact angrop fixture is unavailable: {result.stderr.strip()}")
    return output


def _compile_aarch64_fixture(root: Path) -> Path:
    output = root / "aarch64-calls.so"
    result = subprocess.run(
        [
            "zig",
            "cc",
            "-target",
            "aarch64-linux-gnu",
            "-nostdlib",
            "-shared",
            "-Wl,-soname,aarch64-calls.so",
            "-Wl,--build-id",
            "-Wl,-z,noexecstack",
            "-x",
            "assembler",
            "-",
            "-o",
            str(output),
        ],
        input=_AARCH64_ASSEMBLY,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise unittest.SkipTest(f"Zig AArch64 angrop fixture is unavailable: {result.stderr.strip()}")
    return output


def _compile_arm_eabi_qemu_fixture(root: Path) -> Path:
    """Build one static ARM EABI executable with Zig, without a host libc."""

    target = resolve_target("arm", endian="little")
    output = root / "arm-eabi-angrop"
    result = subprocess.run(
        [
            "zig",
            "cc",
            "-target",
            target.zig_target,
            "-nostdlib",
            "-static",
            "-fno-pic",
            "-fno-pie",
            "-no-pie",
            "-Wl,-e,_start",
            "-Wl,--build-id=none",
            "-Wl,-z,noexecstack",
            "-x",
            "assembler",
            "-",
            "-o",
            str(output),
        ],
        input=_ARM_EABI_QEMU_ASSEMBLY,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        diagnostics = result.stderr.strip() or result.stdout.strip() or "no diagnostics"
        raise AssertionError(f"Zig could not build the ARM EABI angrop fixture: {diagnostics}")
    return output


def _compile_aarch64_qemu_fixture(root: Path) -> Path:
    """Build one static AArch64 executable with Zig, without a host libc."""

    target = resolve_target("aarch64", endian="little")
    output = root / "aarch64-angrop"
    result = subprocess.run(
        [
            "zig",
            "cc",
            "-target",
            target.zig_target,
            "-nostdlib",
            "-static",
            "-fno-pic",
            "-fno-pie",
            "-no-pie",
            "-Wl,-e,_start",
            "-Wl,--build-id=none",
            "-Wl,-z,noexecstack",
            "-x",
            "assembler",
            "-",
            "-o",
            str(output),
        ],
        input=_AARCH64_QEMU_ASSEMBLY,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        diagnostics = result.stderr.strip() or result.stdout.strip() or "no diagnostics"
        raise AssertionError(f"Zig could not build the AArch64 angrop fixture: {diagnostics}")
    return output


def _patch_qemu_chain(template: Path, output: Path, adapter: ExactELFAdapter, address: int, data: bytes) -> None:
    """Patch a chain into one exact file-backed writable PT_LOAD range."""

    matches = tuple(
        item
        for item in adapter.profile.load_ranges
        if item.writable and item.start <= address and address + len(data) <= item.start + item.file_size
    )
    if len(matches) != 1:
        raise AssertionError(f"chain [{address:#x}, {address + len(data):#x}) is not in one writable file-backed load")
    mapping = matches[0]
    file_offset = mapping.file_offset + address - mapping.start
    image = bytearray(template.read_bytes())
    if file_offset + len(data) > len(image):
        raise AssertionError("chain patch exceeds the exact fixture bytes")
    image[file_offset : file_offset + len(data)] = data
    output.write_bytes(image)
    output.chmod(0o755)


class _FakeObject:
    def __init__(self, binary: str, mapped_base: int) -> None:
        self.binary = str(Path(binary).resolve())
        self.binary_basename = Path(binary).name
        self.profile = inspect_elf(binary)
        self.mapped_base = mapped_base
        self.load_bias = mapped_base - min(item.start & -0x1000 for item in self.profile.load_ranges)
        self.min_addr = min(item.start for item in self.profile.load_ranges) + self.load_bias
        self.max_addr = max(item.end for item in self.profile.load_ranges) + self.load_bias - 1
        self.pic = self.profile.elf_type == "ET_DYN" or bool(self.load_bias)

    @property
    def executable_address(self) -> int:
        executable = next(item for item in self.profile.load_ranges if item.permissions & Permission.EXECUTE)
        return executable.start + self.load_bias


class _FakeLoader:
    def __init__(self, objects: list[_FakeObject], auto_load_libs: bool) -> None:
        self.main_object = objects[0]
        self.all_elf_objects = objects
        self.auto_load_libs = auto_load_libs


class _FakeGadget:
    def __init__(self, address: int, description: str, project: object, *, stack_change: int) -> None:
        self.addr = address
        self.description = description
        self.project = project
        self.stack_change = stack_change

    def dstr(self) -> str:
        return self.description


class _FakeChain:
    def __init__(self, project: object, words: list[int], gadgets: list[_FakeGadget]) -> None:
        self.project = project
        self.words = words
        self._gadgets = gadgets
        self.payload_len = len(words) * (self.project.arch.bits // 8)
        self.timeout = None

    def __add__(self, other: _FakeChain) -> _FakeChain:
        return _FakeChain(self.project, [*self.words, *other.words], [*self._gadgets, *other._gadgets])

    def set_timeout(self, timeout: float) -> None:
        self.timeout = timeout

    def payload_str(self, timeout: float | None = None) -> bytes:
        if timeout is not None:
            self.timeout = timeout
        width = self.project.arch.bits // 8
        byteorder = "little" if self.project.arch.memory_endness == "Iend_LE" else "big"
        return b"".join(value.to_bytes(width, byteorder) for value in self.words)


class _FakeBuilder:
    used_writable_ptrs: ClassVar[list[tuple[int, int]]] = []

    def __init__(self, analysis: _FakeROP) -> None:
        self.analysis = analysis
        self.optimize_calls: list[int] = []
        self.observed_global_state: list[tuple[tuple[int, int], ...]] = []

    def optimize(self, processes: int = 1) -> None:
        self.observed_global_state.append(tuple(type(self).used_writable_ptrs))
        type(self).used_writable_ptrs.append((0x41410000, 8))
        self.optimize_calls.append(processes)


class _FakeROP:
    def __init__(self, project: _FakeProject, **kwargs: object) -> None:
        self.project = project
        self.constructor_options = kwargs
        self._all_gadgets: list[_FakeGadget] = []
        self._duplicates: dict[bytes, list[int]] = {}
        self.rop_gadgets: list[_FakeGadget] = []
        self.badbytes: list[int] = []
        self.chain_builder = _FakeBuilder(self)
        self.calls: list[tuple[int, tuple[int, ...], bool]] = []
        self.retsled_calls: list[int] = []
        self.shift_calls: list[int] = []

    def find_gadgets(self, *, optimize: bool, processes: int, show_progress: bool, **kwargs: object) -> None:
        if optimize:
            raise AssertionError("per-image discovery must defer merged graph optimization")
        address = self.project.loader.main_object.executable_address + 2
        word_size = self.project.arch.bits // 8
        return_gadget = _FakeGadget(
            self.project.loader.main_object.executable_address,
            "ret",
            self.project,
            stack_change=word_size,
        )
        gadget = _FakeGadget(address, "pop rdi; ret", self.project, stack_change=2 * word_size)
        self._all_gadgets = [return_gadget, gadget]
        self._duplicates = {
            b"ret": [return_gadget.addr],
            b"pop-rdi-ret": [address],
        }
        self.project.discovery_arguments.append((processes, show_progress, kwargs))

    def _screen_gadgets(self) -> None:
        self.rop_gadgets = list(self._all_gadgets)

    def func_call(self, function: int, arguments: list[int], *, needs_return: bool) -> _FakeChain:
        self.chain_builder.observed_global_state.append(tuple(type(self.chain_builder).used_writable_ptrs))
        type(self.chain_builder).used_writable_ptrs.append((function, 8))
        self.calls.append((function, tuple(arguments), needs_return))
        if not self.rop_gadgets:
            raise RuntimeError("no gadgets")
        word_size = self.project.arch.bits // 8
        setup_template = next(gadget for gadget in self.rop_gadgets if gadget.description == "pop rdi; ret")
        setup = _FakeGadget(
            setup_template.addr,
            setup_template.description,
            self.project,
            stack_change=(len(arguments) + 1) * word_size,
        )
        target = _FakeGadget(function, f"call {function:#x}", self.project, stack_change=word_size)
        return _FakeChain(self.project, [setup.addr, *arguments, function], [setup, target])

    def retsled(self, size: int) -> _FakeChain:
        self.retsled_calls.append(size)
        word_size = self.project.arch.bits // 8
        return_gadget = next(gadget for gadget in self.rop_gadgets if gadget.description == "ret")
        count = size // word_size
        return _FakeChain(
            self.project,
            [return_gadget.addr] * count,
            [return_gadget] * count,
        )

    def shift(self, size: int) -> _FakeChain:
        self.shift_calls.append(size)
        return self.retsled(size)


class _FakeAnalyses:
    def __init__(self, project: _FakeProject) -> None:
        self.project = project

    def ROP(self, **_kwargs: object) -> _FakeROP:
        raise AssertionError("the mutable named analysis registry must not be used")

    def __getitem__(self, analysis_class: type[object]):
        if analysis_class is not _FakeROP:
            raise AssertionError("only the exact vendored fake ROP class is allowed")

        def construct(**kwargs: object) -> _FakeROP:
            analysis = _FakeROP(self.project, **kwargs)
            self.project.rop_analyses.append(analysis)
            return analysis

        return construct


class _FakeProject:
    def __init__(self, binary: str, *, use_sim_procedures: bool, load_options: dict[str, object]) -> None:
        self.binary = str(Path(binary).resolve())
        self.use_sim_procedures = use_sim_procedures
        self.load_options = load_options
        paths = [self.binary, *load_options["force_load_libs"]]
        objects: list[_FakeObject] = []
        for index, path in enumerate(paths):
            if index == 0:
                options = load_options["main_opts"]
            else:
                options = load_options["lib_opts"][Path(path).name]
            objects.append(_FakeObject(path, options["base_addr"]))
        self.loader = _FakeLoader(objects, bool(load_options["auto_load_libs"]))
        self.arch = SimpleNamespace(name="AMD64", bits=64, memory_endness="Iend_LE")
        self.discovery_arguments: list[tuple[int, bool, dict[str, object]]] = []
        self.rop_analyses: list[_FakeROP] = []
        self.analyses = _FakeAnalyses(self)


class _FakeAngr:
    def __init__(self) -> None:
        self.projects: list[_FakeProject] = []

    def Project(self, binary: str, *, use_sim_procedures: bool, load_options: dict[str, object]) -> _FakeProject:
        project = _FakeProject(binary, use_sim_procedures=use_sim_procedures, load_options=load_options)
        self.projects.append(project)
        return project


def _fake_angrop(version: str) -> SimpleNamespace:
    return SimpleNamespace(
        __version__=version,
        rop=SimpleNamespace(ROP=_FakeROP),
    )


@unittest.skipUnless(shutil.which("cc"), "a compiler/linker is required for exact ELF fixtures")
class AngropImageSpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="pwnc-angrop-tests-")
        self.root = Path(self.temporary.name)
        self.shared_path = _compile_fixture(self.root, "libfixture.so", executable=False)
        self.other_shared_path = _compile_fixture(self.root, "libother.so", executable=False)
        self.main_path = _compile_fixture(self.root, "challenge", executable=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_from_adapter_reuses_authenticated_profile_and_exposes_runtime_ranges(self) -> None:
        adapter = ExactELFAdapter.from_file(self.shared_path)
        with mock.patch.object(ExactELFAdapter, "from_file", side_effect=AssertionError("must not reparse")):
            image = AngropImageSpec.from_adapter(
                adapter,
                load_bias=0x700000000000,
                name="libc",
                scan_gadgets=False,
            )

        self.assertIs(image.adapter, adapter)
        self.assertEqual(image.target, resolve_target("x86_64"))
        self.assertEqual(image.runtime_symbol("first"), 0x700000000000 + adapter.symbol("first"))
        self.assertEqual(image.load_ranges, image.runtime_load_ranges)
        self.assertTrue(any(item.executable for item in image.runtime_load_ranges))
        self.assertFalse(image.scan_gadgets)

    def test_load_bias_is_mandatory_and_runtime_overflow_is_rejected(self) -> None:
        adapter = ExactELFAdapter.from_file(self.shared_path)
        with self.assertRaises(TypeError):
            AngropImageSpec.from_adapter(adapter)  # type: ignore[call-arg]
        with self.assertRaisesRegex(AngropImageError, "does not fit"):
            AngropImageSpec.from_adapter(adapter, load_bias=(1 << 64) - 1)

        executable = ExactELFAdapter.from_file(self.main_path)
        desired_base = 0x10000
        linked_base = min(item.start & -0x1000 for item in executable.profile.load_ranges)
        relocated = AngropImageSpec.from_adapter(executable, load_bias=desired_base - linked_base)
        self.assertLess(relocated.load_bias, 0)
        self.assertEqual(relocated.mapped_base, desired_base)
        self.assertEqual(relocated.runtime_symbol("first"), executable.symbol("first") + relocated.load_bias)
        with self.assertRaisesRegex(AngropImageError, "below address zero"):
            AngropImageSpec.from_adapter(executable, load_bias=-executable.profile.load_ranges[0].start - 1)

    def test_duplicate_identity_overlap_and_unsupported_target_fail_before_backend_import(self) -> None:
        adapter = ExactELFAdapter.from_file(self.shared_path)
        left = AngropImageSpec.from_adapter(adapter, load_bias=0x700000000000)
        duplicate = AngropImageSpec.from_adapter(adapter, load_bias=0x710000000000, name="duplicate artifact")
        with (
            mock.patch("payloads.angrop_backend._load_angrop_modules") as load,
            self.assertRaisesRegex(AngropImageError, "duplicate exact ELF SHA-256"),
        ):
            prepare_angrop((left, duplicate))
        load.assert_not_called()

        other = AngropImageSpec.from_file(self.other_shared_path, load_bias=0x700000000000)
        with (
            mock.patch("payloads.angrop_backend._load_angrop_modules") as load,
            self.assertRaisesRegex(AngropImageError, "overlap"),
        ):
            prepare_angrop((left, other))
        load.assert_not_called()

        with (
            mock.patch("payloads.angrop_backend._load_angrop_modules") as load,
            self.assertRaises(UnsupportedTargetError),
        ):
            prepare_angrop((left,), target=resolve_target("riscv32"))
        load.assert_not_called()

        for unsafe_target in ("thumb", "mips32", "mips64", "riscv64"):
            with (
                self.subTest(target=unsafe_target),
                mock.patch("payloads.angrop_backend._load_angrop_modules") as load,
                self.assertRaisesRegex(UnsupportedTargetError, "does not safely implement"),
            ):
                prepare_angrop((left,), target=resolve_target(unsafe_target))
            load.assert_not_called()

        for unsafe_target in ("arm", "arm64"):
            with (
                self.subTest(target=unsafe_target, endian="big"),
                mock.patch("payloads.angrop_backend._load_angrop_modules") as load,
                self.assertRaises(UnsupportedTargetError),
            ):
                prepare_angrop((left,), target=resolve_target(unsafe_target, endian="big"))
            load.assert_not_called()

    def test_only_collision_proof_vendored_module_is_imported(self) -> None:
        loaded: list[str] = []

        def import_module(name: str) -> object:
            loaded.append(name)
            return SimpleNamespace(__name__=name)

        with mock.patch("payloads.angrop_backend.importlib.import_module", side_effect=import_module):
            angr, angrop = _load_angrop_modules()
        self.assertEqual(loaded, ["angr", "payloads._vendor.angrop"])
        self.assertEqual(angr.__name__, "angr")
        self.assertEqual(angrop.__name__, "payloads._vendor.angrop")

    def test_exact_analysis_class_bypasses_a_foreign_named_registry_entry(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
        ):
            result = session.synthesize_calls(
                (AngropDirectCall(main.runtime_symbol("first"), needs_return=False),),
                chain_base=_CHAIN_BASE,
            )

        self.assertTrue(result.data)
        analyses = [analysis for project in fake_angr.projects for analysis in project.rop_analyses]
        self.assertTrue(analyses)
        self.assertTrue(all(type(analysis) is _FakeROP for analysis in analyses))

    def test_multi_image_calls_use_deterministic_executable_main_and_exact_provenance(self) -> None:
        shared = AngropImageSpec.from_file(
            self.shared_path,
            load_bias=0x700000000000,
            name="libc",
            scan_gadgets=False,
        )
        main = AngropImageSpec.from_file(
            self.main_path,
            load_bias=0,
            name="challenge",
            scan_gadgets=True,
        )
        fake_angr = _FakeAngr()
        fake_angrop = _fake_angrop("9.2.13.dev0")
        options = AngropDiscoveryOptions(processes=3, optimize=True, fast_mode=True, timeout=2.5)

        with mock.patch("payloads.angrop_backend._load_angrop_modules", return_value=(fake_angr, fake_angrop)):
            with prepare_angrop((shared, main), options=options) as session:
                first = AngropDirectCall(shared.runtime_symbol("first"), (1, 2), name="open", needs_return=True)
                second = AngropDirectCall(main.runtime_symbol("second"), (3,), name="write", needs_return=False)
                result = session.synthesize_calls(
                    (first, second),
                    chain_base=_CHAIN_BASE,
                    timeout=1.25,
                )

                self.assertEqual([item.name for item in result.images], ["libc", "challenge"])
                self.assertEqual([item.cle_main for item in result.images], [False, True])
                self.assertEqual([item.name for item in result.calls], ["open", "write"])
                self.assertEqual([item.image_name for item in result.calls], ["libc", "challenge"])
                self.assertEqual(ANGROP_VENDOR_REVISION, f"{ANGROP_BASELINE_REVISION}+pwnc.5")
                self.assertEqual(result.backend_revision, f"9.2.13.dev0+{ANGROP_VENDOR_REVISION}")
                self.assertIs(result.discovery_options, options)
                generic_chain = result.as_rop_chain()
                self.assertEqual(generic_chain.required_chain_base, _CHAIN_BASE)
                self.assertEqual(generic_chain.materialize(chain_base=_CHAIN_BASE), result.data)
                with self.assertRaisesRegex(ROPBuildError, "requires base|must be placed"):
                    generic_chain.materialize(chain_base=_CHAIN_BASE + 8)
                generic_payload = result.as_payload()
                self.assertEqual(generic_payload.data, result.data)
                self.assertEqual(generic_payload.required_load_address, _CHAIN_BASE)
                self.assertTrue(any(item.image_name == "libc" and item.call_target for item in result.gadgets))
                self.assertTrue(any(item.image_name == "challenge" and not item.call_target for item in result.gadgets))

                # The combined project is built first.  Even though the caller
                # listed libc first, the sole ET_EXEC is its deterministic main.
                combined = fake_angr.projects[0]
                self.assertIn("image-001-", Path(combined.binary).name)
                self.assertFalse(combined.use_sim_procedures)
                self.assertFalse(combined.load_options["auto_load_libs"])
                self.assertTrue(combined.load_options["main_opts"]["discard_section_headers"])
                self.assertEqual(len(combined.load_options["force_load_libs"]), 1)
                self.assertIn("image-000-", Path(combined.load_options["force_load_libs"][0]).name)
                self.assertTrue(
                    all(options["discard_section_headers"] for options in combined.load_options["lib_opts"].values())
                )

                # scan_gadgets=False prevents a separate libc discovery project.
                self.assertEqual(len(fake_angr.projects), 2)
                discovery_project = fake_angr.projects[1]
                self.assertIn("image-001-", Path(discovery_project.binary).name)
                self.assertEqual(discovery_project.discovery_arguments, [(3, False, {"timeout": 2.5})])
                merged_analysis = combined.rop_analyses[-1]
                self.assertEqual(merged_analysis.chain_builder.optimize_calls, [3])
                observed = merged_analysis.chain_builder.observed_global_state
                self.assertEqual(observed[:2], [(), ()])
            self.assertTrue(session.closed)

    def test_signed_arguments_are_normalized_to_target_words(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
        ):
            result = session.synthesize_calls(
                (AngropDirectCall(main.runtime_symbol("first"), (-1,), needs_return=False),),
                chain_base=_CHAIN_BASE,
            )
            with self.assertRaisesRegex(AngropSynthesisError, "signed word range"):
                session.synthesize_calls(
                    (AngropDirectCall(main.runtime_symbol("first"), (-(1 << 64) - 1,), needs_return=False),),
                    chain_base=_CHAIN_BASE,
                )

        self.assertEqual(result.calls[0].arguments, (result.target.mask,))

    def test_chain_base_is_required_and_every_amd64_call_entry_is_independently_aligned(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0, name="challenge")
        fake_angr = _FakeAngr()
        calls = (
            AngropDirectCall(main.runtime_symbol("first"), (0x1111,), name="first", needs_return=True),
            AngropDirectCall(main.runtime_symbol("second"), (0x2222,), name="second", needs_return=False),
        )

        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
        ):
            with self.assertRaises(TypeError):
                session.synthesize_calls(calls)  # type: ignore[call-arg]

            result = session.synthesize_calls(calls, chain_base=_CHAIN_BASE)
            shifted_result = session.synthesize_calls(calls, chain_base=_CHAIN_BASE + 8)

        self.assertEqual(result.chain_base, _CHAIN_BASE)
        self.assertEqual([item.entry_sp_offset for item in result.calls], [0x18, 0x38])
        self.assertEqual([item.alignment_padding for item in result.calls], [0, 8])
        for call in result.calls:
            with self.subTest(call=call.name):
                self.assertEqual(call.entry_sp, result.chain_base + call.entry_sp_offset)
                self.assertEqual(call.stack_alignment, 16)
                self.assertEqual(call.stack_alignment_bias, 8)
                self.assertEqual((call.entry_sp + call.stack_alignment_bias) % call.stack_alignment, 0)

        self.assertEqual([item.entry_sp_offset for item in shifted_result.calls], [0x20, 0x40])
        self.assertEqual([item.alignment_padding for item in shifted_result.calls], [8, 8])
        for call in shifted_result.calls:
            with self.subTest(call=call.name, shifted_base=True):
                self.assertEqual(call.entry_sp, shifted_result.chain_base + call.entry_sp_offset)
                self.assertEqual((call.entry_sp + call.stack_alignment_bias) % call.stack_alignment, 0)

        metadata = result.as_payload().metadata
        self.assertEqual(metadata["chain_base"], _CHAIN_BASE)
        metadata_calls = metadata["calls"]
        self.assertEqual(
            [
                (
                    item["entry_sp"],
                    item["entry_sp_offset"],
                    item["stack_alignment"],
                    item["stack_alignment_bias"],
                    item["alignment_padding"],
                )
                for item in metadata_calls
            ],
            [
                (
                    item.entry_sp,
                    item.entry_sp_offset,
                    item.stack_alignment,
                    item.stack_alignment_bias,
                    item.alignment_padding,
                )
                for item in result.calls
            ],
        )

    @unittest.skipUnless(importlib.util.find_spec("angr"), "locked angr runtime is not installed")
    def test_locked_angr_multi_call_entries_match_runtime_amd64_abi(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0, name="challenge")
        calls = (
            AngropDirectCall(main.runtime_symbol("first"), (0x4141,), name="first", needs_return=True),
            AngropDirectCall(main.runtime_symbol("second"), (0x4242,), name="second", needs_return=False),
        )

        with (
            mock.patch(
                "payloads._vendor.angrop.gadget_finder.time.sleep",
                side_effect=AssertionError("gadget discovery must not poll or sleep"),
            ),
            prepare_angrop(
                (main,),
                options=AngropDiscoveryOptions(processes=1, optimize=False),
            ) as session,
        ):
            result = session.synthesize_calls(calls, chain_base=_CHAIN_BASE)
            shifted_result = session.synthesize_calls(calls, chain_base=_CHAIN_BASE + 8)

        for synthesized in (result, shifted_result):
            self.assertEqual(len(synthesized.calls), 2)
            self.assertTrue(any(item.alignment_padding for item in synthesized.calls))
            for call in synthesized.calls:
                with self.subTest(call=call.name, chain_base=synthesized.chain_base):
                    self.assertEqual(call.entry_sp, synthesized.chain_base + call.entry_sp_offset)
                    self.assertEqual(call.stack_alignment, 16)
                    self.assertEqual(call.stack_alignment_bias, 8)
                    self.assertEqual((call.entry_sp + call.stack_alignment_bias) % 16, 0)

        self.assertEqual(result.chain_base, _CHAIN_BASE)
        self.assertEqual(shifted_result.chain_base, _CHAIN_BASE + 8)
        self.assertGreater(shifted_result.calls[0].alignment_padding, 0)

    @unittest.skipUnless(importlib.util.find_spec("angr"), "locked angr runtime is not installed")
    @unittest.skipUnless(shutil.which("zig"), "Zig is required for the AArch64 exact fixture")
    def test_locked_angr_aarch64_returning_call_canonicalizes_lr_to_x30(self) -> None:
        path = _compile_aarch64_fixture(self.root)
        image = AngropImageSpec.from_file(
            path,
            load_bias=0x7000000000,
            name="aarch64-calls",
        )
        calls = (
            AngropDirectCall(
                image.runtime_symbol("first"),
                (0x4141,),
                name="returning",
                needs_return=True,
            ),
            AngropDirectCall(
                image.runtime_symbol("second"),
                (0x4242,),
                name="terminal",
                needs_return=False,
            ),
        )
        chain_base = 0x7FFF00000000

        with prepare_angrop(
            (image,),
            options=AngropDiscoveryOptions(
                processes=1,
                optimize=False,
                only_check_near_rets=False,
            ),
        ) as session:
            result = session.synthesize_calls(calls, chain_base=chain_base)

        self.assertEqual([item.needs_return for item in result.calls], [True, False])
        self.assertIn(image.runtime_symbol("first"), result.words)
        self.assertIn(image.runtime_symbol("second"), result.words)
        for call in result.calls:
            with self.subTest(call=call.name):
                self.assertEqual(call.entry_sp, chain_base + call.entry_sp_offset)
                self.assertEqual(call.stack_alignment, 16)
                self.assertEqual(call.stack_alignment_bias, 0)
                self.assertEqual(call.entry_sp % call.stack_alignment, 0)

    @unittest.skipUnless(hasattr(signal, "setitimer"), "ITIMER_REAL hard deadlines are unavailable")
    def test_operation_timeout_interrupts_analysis_preparation(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        call = AngropDirectCall(main.runtime_symbol("first"), needs_return=False)

        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
            _BoundedPipeBlock() as blocker,
            mock.patch.object(session, "_analysis_for", side_effect=blocker.block),
            self.assertRaisesRegex(AngropTimeoutError, "deadline|timed out|timeout"),
        ):
            session.synthesize_calls(
                (call,),
                chain_base=_CHAIN_BASE,
                timeout=0.05,
            )

    @unittest.skipUnless(hasattr(signal, "setitimer"), "ITIMER_REAL hard deadlines are unavailable")
    def test_operation_timeout_interrupts_func_call_building(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        call = AngropDirectCall(main.runtime_symbol("first"), needs_return=False)

        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
        ):
            analysis = session._analysis_for(frozenset())
            with (
                _BoundedPipeBlock() as blocker,
                mock.patch.object(analysis, "func_call", side_effect=blocker.block),
                self.assertRaisesRegex(AngropTimeoutError, "deadline|timed out|timeout"),
            ):
                session.synthesize_calls(
                    (call,),
                    chain_base=_CHAIN_BASE,
                    timeout=0.05,
                )

    def test_hard_timeout_rejects_non_main_thread_instead_of_degrading_to_polling(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        call = AngropDirectCall(main.runtime_symbol("first"), needs_return=False)

        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
            concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor,
        ):
            future = executor.submit(
                session.synthesize_calls,
                (call,),
                chain_base=_CHAIN_BASE,
                timeout=1.0,
            )
            with self.assertRaisesRegex(AngropCompatibilityError, "main thread"):
                future.result(timeout=2.0)

    def test_nonfinite_timeouts_are_rejected_before_installing_a_signal_handler(self) -> None:
        invalid = (float("nan"), float("inf"), float("-inf"), 10**1000)
        for timeout in invalid:
            with self.subTest(scope="discovery", timeout=timeout), self.assertRaisesRegex(ValueError, "finite"):
                AngropDiscoveryOptions(timeout=timeout)

        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        call = AngropDirectCall(main.runtime_symbol("first"), needs_return=False)
        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
            mock.patch("payloads.angrop_backend.signal.signal") as install_handler,
        ):
            for timeout in invalid:
                with self.subTest(scope="synthesis", timeout=timeout), self.assertRaisesRegex(ValueError, "finite"):
                    session.synthesize_calls(
                        (call,),
                        chain_base=_CHAIN_BASE,
                        timeout=timeout,
                    )
        install_handler.assert_not_called()

    @unittest.skipUnless(hasattr(signal, "setitimer"), "ITIMER_REAL hard deadlines are unavailable")
    def test_deadline_arming_failure_restores_the_previous_signal_handler(self) -> None:
        previous_handler = signal.getsignal(signal.SIGALRM)
        timer_calls: list[tuple[int, float]] = []

        def fail_while_arming(which: int, seconds: float) -> None:
            timer_calls.append((which, seconds))
            if len(timer_calls) == 1:
                raise OSError("fixture timer arming failure")

        with (
            mock.patch("payloads.angrop_backend.signal.getitimer", return_value=(0.0, 0.0)),
            mock.patch("payloads.angrop_backend.signal.setitimer", side_effect=fail_while_arming),
            self.assertRaisesRegex(OSError, "arming failure"),
            _operation_deadline(1.0),
        ):
            self.fail("an unarmed deadline must not enter its body")

        self.assertEqual(timer_calls, [(signal.ITIMER_REAL, 1.0), (signal.ITIMER_REAL, 0)])
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous_handler)

    def test_upstream_builder_global_scratch_is_saved_reset_and_restored(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        sentinel = [(0xDEAD0000, 0x20)]
        previous = _FakeBuilder.used_writable_ptrs
        _FakeBuilder.used_writable_ptrs = list(sentinel)
        try:
            with (
                mock.patch(
                    "payloads.angrop_backend._load_angrop_modules",
                    return_value=(fake_angr, _fake_angrop("test")),
                ),
                prepare_angrop((main,)) as session,
            ):
                session.synthesize_calls(
                    (AngropDirectCall(main.runtime_symbol("first")),),
                    chain_base=_CHAIN_BASE,
                )
            self.assertEqual(_FakeBuilder.used_writable_ptrs, sentinel)
            combined = fake_angr.projects[0]
            states = combined.rop_analyses[-1].chain_builder.observed_global_state
            self.assertTrue(states)
            self.assertTrue(all(not state for state in states))
        finally:
            _FakeBuilder.used_writable_ptrs = previous

    def test_snapshot_mutation_is_rejected_and_private_directory_is_cleaned(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        original_project = fake_angr.Project
        snapshot_root: Path | None = None

        def mutate_project(binary: str, *, use_sim_procedures: bool, load_options: dict[str, object]) -> _FakeProject:
            nonlocal snapshot_root
            project = original_project(
                binary,
                use_sim_procedures=use_sim_procedures,
                load_options=load_options,
            )
            if snapshot_root is None:
                path = Path(binary)
                snapshot_root = path.parent
                path.parent.chmod(0o700)
                path.chmod(0o600)
                path.write_bytes(path.read_bytes() + b"mutated")
                path.chmod(0o400)
                path.parent.chmod(0o500)
            return project

        fake_angr.Project = mutate_project  # type: ignore[method-assign]
        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            self.assertRaisesRegex(Exception, "snapshot.*changed"),
        ):
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False))
        self.assertIsNotNone(snapshot_root)
        assert snapshot_root is not None
        self.assertFalse(snapshot_root.exists())

    def test_whole_payload_bad_bytes_and_ordered_noreturn_constraints_are_enforced(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        with (
            mock.patch(
                "payloads.angrop_backend._load_angrop_modules",
                return_value=(fake_angr, _fake_angrop("test")),
            ),
            prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False)) as session,
        ):
            target = main.runtime_symbol("first")
            with self.assertRaisesRegex(AngropSynthesisError, "non-final call"):
                session.synthesize_calls(
                    (
                        AngropDirectCall(target, needs_return=False),
                        AngropDirectCall(target),
                    ),
                    chain_base=_CHAIN_BASE,
                )
            with self.assertRaises(AngropBadByteError) as caught:
                session.synthesize_calls(
                    (AngropDirectCall(target),),
                    chain_base=_CHAIN_BASE,
                    bad_bytes=(b"\x00",),
                )
            self.assertTrue(caught.exception.violations)

            terminal = AngropDirectCall(target, tuple(range(7)), needs_return=False)
            result = session.synthesize_calls((terminal,), chain_base=_CHAIN_BASE)
            self.assertFalse(result.calls[0].needs_return)
            combined = fake_angr.projects[0]
            self.assertFalse(combined.rop_analyses[-1].calls[-1][2])

    def test_session_close_is_idempotent_and_prevents_reuse(self) -> None:
        main = AngropImageSpec.from_file(self.main_path, load_bias=0)
        fake_angr = _FakeAngr()
        with mock.patch(
            "payloads.angrop_backend._load_angrop_modules",
            return_value=(fake_angr, _fake_angrop("test")),
        ):
            session = prepare_angrop((main,), options=AngropDiscoveryOptions(optimize=False))
        snapshot_root = Path(session._temporary.name)
        self.assertTrue(snapshot_root.exists())
        session.close()
        session.close()
        self.assertFalse(snapshot_root.exists())
        with self.assertRaisesRegex(Exception, "closed"):
            session.synthesize_calls(
                (AngropDirectCall(main.runtime_symbol("first")),),
                chain_base=_CHAIN_BASE,
            )


@unittest.skipUnless(
    _QEMU_OPT_IN,
    "set PWNC_QEMU_TESTS=1 to run the embedded-angrop ARM EABI QEMU test",
)
class AngropArmEABIQemuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not sys.platform.startswith("linux"):
            raise AssertionError("PWNC_QEMU_TESTS=1 ARM EABI execution requires a Linux host")
        missing = [tool for tool in _ARM_EABI_QEMU_REQUIRED_TOOLS if shutil.which(tool) is None]
        if importlib.util.find_spec("angr") is None:
            missing.append("Python module angr")
        if importlib.util.find_spec("payloads._vendor.angrop") is None:
            missing.append("vendored payloads._vendor.angrop")
        if missing:
            raise AssertionError(
                "PWNC_QEMU_TESTS=1 requires the ARM EABI embedded-angrop runtime prerequisites; missing: "
                + ", ".join(missing)
            )

    def test_returning_write_then_terminal_exit_executes_with_aligned_entry_sp(self) -> None:
        target = resolve_target("arm", endian="little")
        with tempfile.TemporaryDirectory(prefix="pwnc-angrop-arm-qemu-") as directory:
            root = Path(directory)
            template = _compile_arm_eabi_qemu_fixture(root)
            adapter = ExactELFAdapter.from_file(template, expected_target=target)
            image = AngropImageSpec.from_adapter(adapter, load_bias=0, name="Zig ARM EABI fixture")

            self.assertEqual(adapter.target, target)
            self.assertEqual(adapter.profile.elf_type, "ET_EXEC")
            self.assertFalse(adapter.profile.pie)
            self.assertTrue(adapter.profile.nx, adapter.profile.nx_evidence)
            self.assertIsNone(adapter.profile.interpreter)

            chain_base = image.runtime_symbol("chain")
            marker = image.runtime_symbol("pwnc_marker")
            marker_size = image.runtime_symbol("pwnc_marker_end") - marker
            self.assertEqual(marker_size, len(_ARM_EABI_QEMU_MARKER))
            chain_mapping = next(
                item
                for item in image.runtime_load_ranges
                if item.start <= chain_base
                and chain_base + 4096 <= item.end
                and item.file_size >= chain_base + 4096 - item.start
            )
            self.assertTrue(chain_mapping.permissions & Permission.WRITE)
            self.assertFalse(chain_mapping.executable)

            _angr, vendored_angrop = _load_angrop_modules()
            self.assertIsNotNone(vendored_angrop.__file__)
            vendor_root = (Path(__file__).resolve().parents[1] / "_vendor" / "angrop").resolve()
            self.assertEqual(Path(vendored_angrop.__file__).resolve().parent, vendor_root)

            calls = (
                AngropDirectCall(
                    image.runtime_symbol("pwnc_write_checked"),
                    (1, marker, marker_size),
                    name="returning write",
                    needs_return=True,
                ),
                AngropDirectCall(
                    image.runtime_symbol("pwnc_exit"),
                    (47,),
                    name="terminal exit",
                    needs_return=False,
                ),
            )
            with prepare_angrop(
                (image,),
                options=AngropDiscoveryOptions(
                    processes=1,
                    optimize=False,
                    only_check_near_rets=False,
                    timeout=120,
                ),
            ) as session:
                synthesis = session.synthesize_calls(calls, chain_base=chain_base, timeout=30)

            self.assertEqual(
                [(call.name, call.needs_return) for call in synthesis.calls],
                [("returning write", True), ("terminal exit", False)],
            )
            self.assertEqual(
                [call.function for call in synthesis.calls],
                [image.runtime_symbol("pwnc_write_checked"), image.runtime_symbol("pwnc_exit")],
            )
            self.assertEqual(
                [call.arguments for call in synthesis.calls],
                [(1, marker, marker_size), (47,)],
            )
            self.assertLess(synthesis.calls[0].entry_sp, synthesis.calls[1].entry_sp)
            for call in synthesis.calls:
                with self.subTest(call=call.name):
                    self.assertEqual(call.entry_sp, chain_base + call.entry_sp_offset)
                    self.assertEqual(call.stack_alignment, 8)
                    self.assertEqual(call.stack_alignment_bias, 0)
                    self.assertEqual(call.entry_sp % 8, 0)
                    self.assertEqual(call.image_sha256, adapter.identity.sha256)
            self.assertTrue(synthesis.gadgets)
            self.assertEqual({gadget.image_sha256 for gadget in synthesis.gadgets}, {adapter.identity.sha256})
            self.assertLessEqual(len(synthesis.data), 4096)

            executable = root / "arm-eabi-angrop-patched"
            _patch_qemu_chain(template, executable, adapter, chain_base, synthesis.data)
            executed = subprocess.run(
                ["qemu-arm", str(executable)],
                capture_output=True,
                timeout=10,
                check=False,
            )
            # Both called functions exit with 99 on an unaligned public-interface
            # SP, so the marker plus status 47 proves return flow and both checks.
            self.assertEqual(executed.stdout, _ARM_EABI_QEMU_MARKER)
            self.assertEqual(executed.returncode, 47, executed.stderr.decode(errors="replace"))
            self.assertEqual(executed.stderr, b"")


@unittest.skipUnless(
    _QEMU_OPT_IN,
    "set PWNC_QEMU_TESTS=1 to run the embedded-angrop AArch64 QEMU test",
)
class AngropAArch64QemuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if not sys.platform.startswith("linux"):
            raise AssertionError("PWNC_QEMU_TESTS=1 AArch64 execution requires a Linux host")
        missing = [tool for tool in _AARCH64_QEMU_REQUIRED_TOOLS if shutil.which(tool) is None]
        if importlib.util.find_spec("angr") is None:
            missing.append("Python module angr")
        if importlib.util.find_spec("payloads._vendor.angrop") is None:
            missing.append("vendored payloads._vendor.angrop")
        if missing:
            raise AssertionError(
                "PWNC_QEMU_TESTS=1 requires the AArch64 embedded-angrop runtime prerequisites; missing: "
                + ", ".join(missing)
            )

    def test_returning_write_then_terminal_exit_executes_with_aligned_entry_sp(self) -> None:
        target = resolve_target("aarch64", endian="little")
        with tempfile.TemporaryDirectory(prefix="pwnc-angrop-aarch64-qemu-") as directory:
            root = Path(directory)
            template = _compile_aarch64_qemu_fixture(root)
            adapter = ExactELFAdapter.from_file(template, expected_target=target)
            image = AngropImageSpec.from_adapter(adapter, load_bias=0, name="Zig AArch64 fixture")

            self.assertEqual(adapter.target, target)
            self.assertEqual(adapter.profile.elf_type, "ET_EXEC")
            self.assertFalse(adapter.profile.pie)
            self.assertTrue(adapter.profile.nx, adapter.profile.nx_evidence)
            self.assertIsNone(adapter.profile.interpreter)

            chain_base = image.runtime_symbol("chain")
            marker = image.runtime_symbol("pwnc_marker")
            marker_size = image.runtime_symbol("pwnc_marker_end") - marker
            self.assertEqual(marker_size, len(_AARCH64_QEMU_MARKER))
            chain_mapping = next(
                item
                for item in image.runtime_load_ranges
                if item.start <= chain_base
                and chain_base + 4096 <= item.end
                and item.file_size >= chain_base + 4096 - item.start
            )
            self.assertTrue(chain_mapping.permissions & Permission.WRITE)
            self.assertFalse(chain_mapping.executable)

            _angr, vendored_angrop = _load_angrop_modules()
            self.assertIsNotNone(vendored_angrop.__file__)
            vendor_root = (Path(__file__).resolve().parents[1] / "_vendor" / "angrop").resolve()
            self.assertEqual(Path(vendored_angrop.__file__).resolve().parent, vendor_root)

            calls = (
                AngropDirectCall(
                    image.runtime_symbol("pwnc_write_checked"),
                    (1, marker, marker_size),
                    name="returning write",
                    needs_return=True,
                ),
                AngropDirectCall(
                    image.runtime_symbol("pwnc_exit"),
                    (53,),
                    name="terminal exit",
                    needs_return=False,
                ),
            )
            with prepare_angrop(
                (image,),
                options=AngropDiscoveryOptions(
                    processes=1,
                    optimize=False,
                    only_check_near_rets=False,
                    timeout=120,
                ),
            ) as session:
                synthesis = session.synthesize_calls(calls, chain_base=chain_base, timeout=30)

            self.assertEqual(
                [(call.name, call.needs_return) for call in synthesis.calls],
                [("returning write", True), ("terminal exit", False)],
            )
            self.assertEqual(
                [call.function for call in synthesis.calls],
                [image.runtime_symbol("pwnc_write_checked"), image.runtime_symbol("pwnc_exit")],
            )
            self.assertEqual(
                [call.arguments for call in synthesis.calls],
                [(1, marker, marker_size), (53,)],
            )
            self.assertLess(synthesis.calls[0].entry_sp, synthesis.calls[1].entry_sp)
            for call in synthesis.calls:
                with self.subTest(call=call.name):
                    self.assertEqual(call.entry_sp, chain_base + call.entry_sp_offset)
                    self.assertEqual(call.stack_alignment, 16)
                    self.assertEqual(call.stack_alignment_bias, 0)
                    self.assertEqual(call.entry_sp % 16, 0)
                    self.assertEqual(call.image_sha256, adapter.identity.sha256)
            self.assertTrue(synthesis.gadgets)
            self.assertEqual({gadget.image_sha256 for gadget in synthesis.gadgets}, {adapter.identity.sha256})
            self.assertLessEqual(len(synthesis.data), 4096)

            executable = root / "aarch64-angrop-patched"
            _patch_qemu_chain(template, executable, adapter, chain_base, synthesis.data)
            executed = subprocess.run(
                ["qemu-aarch64", str(executable)],
                capture_output=True,
                timeout=10,
                check=False,
            )
            # Both called functions exit with 99 on an unaligned public-interface
            # SP, so the marker plus status 53 proves return flow and both checks.
            self.assertEqual(executed.stdout, _AARCH64_QEMU_MARKER)
            self.assertEqual(executed.returncode, 53, executed.stderr.decode(errors="replace"))
            self.assertEqual(executed.stderr, b"")


if __name__ == "__main__":
    unittest.main()
