"""Opt-in host-escape tests for automatic QEMU user-mode semihosting.

Run with ``PWNC_QEMU_TESTS=1 python3 -m unittest discover -s payloads/tests``.
Each payload executes ``SYS_SYSTEM`` in the QEMU host process and then exits
through the guest Linux ABI.  No ``-semihosting`` option is passed.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from payloads import SUPPORTED_TARGETS, LLVMAssembler, qemu_semihosting_command_shellcode, resolve_target
from payloads.tests.test_shellcode_qemu import _link_raw_payload

AUTOMATIC_QEMU_USER_SEMIHOSTING_TARGETS = (
    ("arm", "little", "qemu-arm"),
    ("arm", "big", "qemu-armeb"),
    ("thumb", "little", "qemu-arm"),
    ("thumb", "big", "qemu-armeb"),
    ("arm64", "little", "qemu-aarch64"),
    ("arm64", "big", "qemu-aarch64_be"),
    ("riscv32", None, "qemu-riscv32"),
    ("riscv64", None, "qemu-riscv64"),
)

_QEMU_OPT_IN = os.environ.get("PWNC_QEMU_TESTS") == "1"
_REQUIRED_TOOLS = (
    "llvm-mc",
    "ld.lld",
    *sorted({qemu for _, _, qemu in AUTOMATIC_QEMU_USER_SEMIHOSTING_TARGETS}),
)
_MISSING_TOOLS = tuple(tool for tool in _REQUIRED_TOOLS if shutil.which(tool) is None)


def _clean_qemu_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "QEMU_GDB",
        "QEMU_LD_PREFIX",
        "QEMU_SET_ENV",
        "QEMU_STRACE",
        "QEMU_UNSET_ENV",
    ):
        environment.pop(name, None)
    return environment


class QemuSemihostingMatrixTests(unittest.TestCase):
    def test_matrix_is_exactly_the_supported_catalog_variants(self) -> None:
        runtime_targets = {
            resolve_target(architecture, endian=endian).name
            for architecture, endian, _ in AUTOMATIC_QEMU_USER_SEMIHOSTING_TARGETS
        }
        self.assertEqual(
            runtime_targets,
            {
                target.name
                for target in SUPPORTED_TARGETS
                if target.arch.value in {"arm", "thumb", "arm64", "riscv32", "riscv64"}
            },
        )
        self.assertEqual(
            {qemu for _, _, qemu in AUTOMATIC_QEMU_USER_SEMIHOSTING_TARGETS},
            {
                "qemu-arm",
                "qemu-armeb",
                "qemu-aarch64",
                "qemu-aarch64_be",
                "qemu-riscv32",
                "qemu-riscv64",
            },
        )


@unittest.skipUnless(
    _QEMU_OPT_IN,
    "set PWNC_QEMU_TESTS=1 to run automatic QEMU user-mode semihosting escapes",
)
class QemuSemihostingExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if _MISSING_TOOLS:
            raise AssertionError(
                "PWNC_QEMU_TESTS=1 requires the complete semihosting matrix; missing: " + ", ".join(_MISSING_TOOLS)
            )

    def test_host_command_escape_executes_on_every_automatic_qemu_user_target(self) -> None:
        assembler = LLVMAssembler()
        expected = b"PWNC_QEMU_SEMIHOST_ESCAPE"
        for architecture, endian, qemu in AUTOMATIC_QEMU_USER_SEMIHOSTING_TARGETS:
            target = resolve_target(architecture, endian=endian)
            with (
                self.subTest(target=target.name),
                tempfile.TemporaryDirectory(prefix="pwnc-qemu-semihost-") as directory,
            ):
                root = Path(directory)
                marker = root / "host-marker"
                command = f"printf PWNC_QEMU_SEMIHOST_ESCAPE > {shlex.quote(str(marker))}"
                payload = qemu_semihosting_command_shellcode(command, target, assembler=assembler)
                executable = root / "payload.elf"
                _link_raw_payload(payload.data, target, executable)

                result = subprocess.run(
                    [qemu, str(executable)],
                    capture_output=True,
                    env=_clean_qemu_environment(),
                    timeout=10,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, b"")
                self.assertEqual(marker.read_bytes(), expected)
                self.assertTrue(payload.metadata["command_executes_on_host"])


if __name__ == "__main__":
    unittest.main()
