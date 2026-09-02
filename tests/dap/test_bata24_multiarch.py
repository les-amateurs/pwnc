"""Real glibc/QEMU-user coverage for the exact unmodified bata24 GEF.

This suite is intentionally opt-in because provisioning every pinned cross
sysroot is large.  The cache is shared with the payload runtime tests, so a
fully provisioned checkout does not download or rebuild toolchains.

Enable the full default-glibc matrix with::

    PWNC_GEF_QEMU_TESTS=1 \
      uv run --with pytest --with pwntools python -m pytest -q \
      tests/dap/test_bata24_multiarch.py

``PWNC_GEF_QEMU_TARGETS`` accepts comma-separated canonical payload target
names for focused runs.  GEF is always read from its pinned, byte-identical
source.  A test-only runtime compatibility loader guards narrowly identified
QEMU-user incompatibilities in that source; it never rewrites the file.
"""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from payloads import Architecture, Endian, SUPPORTED_TARGETS
from payloads.tests.runtime_support import (
    DEFAULT_GLIBC_LANE,
    ProvisionedSysroot,
    SysrootSpec,
    load_manifest,
    provision_sysroot,
)
from pwnc.gdb.dap import Gdb
from pwnc.gdb.dap.transport import DapTransport


TIMEOUT = 90.0
GEF_PATH = Path(os.environ.get("PWNC_TEST_GEF", "/home/ctf/bata24-gef/gef.py"))
GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
EXPERIMENTS = Path(__file__).with_name("experiments")
CALLBACK_OPERATIONS = Path(__file__).with_name("fixtures") / "callback_operations.py"
GDB_MULTIARCH = os.environ.get("PWNC_TEST_MULTIARCH_GDB", "gdb-multiarch")
NATIVE_VIEWER = Path(__file__).parents[2] / "native" / "runtime_viewer" / "build" / "pwnc-runtime-viewer"
_OPT_IN = os.environ.get("PWNC_GEF_QEMU_TESTS") == "1"
_CACHE = Path(
    os.environ.get("PWNC_GLIBC_SYSROOT_CACHE", "/tmp/pwnc-runtime-sysroot-cache")
).expanduser()
_TARGETS_BY_NAME = {target.name: target for target in SUPPORTED_TARGETS}
_PYTHON_ERROR_MARKERS = (
    "Traceback (most recent call last)",
    "Error occurred in Python",
    "Python Exception",
    "RecursionError",
    "PermissionError",
    "FileNotFoundError",
    "Exception raised",
    "Detailed stacktrace",
    "During handling of the above exception",
)
_BATA24_DYNAMIC_HEAP_ARENA_UNSUPPORTED = frozenset(
    {
        Architecture.MIPS32,
        Architecture.MIPS64,
        Architecture.SPARC32,
    }
)
_BATA24_DECLARED_ENDIAN_MISMATCH = {
    # bata24 selects the right AARCH64 class and its runtime Endian helper is
    # correct, but the class metadata itself is still hard-coded little-endian.
    "arm64-be-aarch64-aapcs64": "little",
}
_GEF_ARCH_NAMES = {
    Architecture.X86: "X86",
    Architecture.X86_64: "X86",
    Architecture.ARM: "ARM",
    Architecture.THUMB: "ARM",
    Architecture.ARM64: "ARM64",
    Architecture.MIPS32: "MIPS",
    Architecture.MIPS64: "MIPS",
    Architecture.RISCV32: "RISCV",
    Architecture.RISCV64: "RISCV",
    Architecture.POWERPC32: "PPC",
    Architecture.POWERPC64: "PPC",
    Architecture.SPARC32: "SPARC",
    Architecture.SPARC64: "SPARC",
    Architecture.S390X: "S390X",
}

pytestmark = pytest.mark.skipif(
    not _OPT_IN,
    reason="set PWNC_GEF_QEMU_TESTS=1 to run the real glibc/QEMU GEF matrix",
)


_INFERIOR_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile void *pwnc_gef_allocation;
volatile uintptr_t pwnc_gef_word = (uintptr_t)0x10203040U;
char pwnc_gef_libc_path[4096];

__attribute__((noinline, used)) void pwnc_gef_marker(uintptr_t phase) {
    volatile uintptr_t scoped = phase + pwnc_gef_word;
    __asm__ volatile("" : "+r"(scoped) :: "memory");
}

int main(void) {
    Dl_info libc_info;
    void *libc_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    void *libc_malloc;

    if (libc_handle == NULL)
        return 71;
    libc_malloc = dlsym(libc_handle, "malloc");
    if (libc_malloc == NULL || dladdr(libc_malloc, &libc_info) == 0 ||
        libc_info.dli_fname == NULL)
        return 72;
    strncpy(pwnc_gef_libc_path, libc_info.dli_fname,
            sizeof(pwnc_gef_libc_path) - 1);
    pwnc_gef_libc_path[sizeof(pwnc_gef_libc_path) - 1] = '\0';
    pwnc_gef_allocation = malloc(0x90);
    if (pwnc_gef_allocation == NULL)
        return 70;
    memset((void *)pwnc_gef_allocation, 0x41, 0x90);
    puts("pwnc multiarch GEF fixture");
    pwnc_gef_marker((uintptr_t)7U);
    free((void *)pwnc_gef_allocation);
    return 0;
}
"""


def _stable_stat(path: Path) -> tuple[int, ...]:
    stat = path.stat()
    return (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )


@pytest.fixture(scope="module")
def exact_gef() -> Path:
    assert GEF_PATH.is_file(), f"exact bata24 GEF fixture is unavailable: {GEF_PATH}"
    before_hash = hashlib.sha256(GEF_PATH.read_bytes()).hexdigest()
    assert before_hash == GEF_SHA256
    before_stat = _stable_stat(GEF_PATH)
    try:
        yield GEF_PATH
    finally:
        assert hashlib.sha256(GEF_PATH.read_bytes()).hexdigest() == before_hash
        assert _stable_stat(GEF_PATH) == before_stat


def _selected_cases():
    manifest = load_manifest()
    cases = [
        (spec, _TARGETS_BY_NAME[target_name])
        for spec in manifest.sysroots
        if spec.lane == DEFAULT_GLIBC_LANE
        for target_name in spec.targets
    ]
    selector = os.environ.get("PWNC_GEF_QEMU_TARGETS", "").strip()
    if not selector:
        names = [target.name for _spec, target in cases]
        if len(names) != 20 or len(set(names)) != 20:
            raise AssertionError(
                "the default bata24 matrix must contain exactly 20 unique "
                f"targets, got {len(names)} entries/{len(set(names))} unique"
            )
        expected = set(_TARGETS_BY_NAME).difference(manifest.unsupported)
        if set(names) != expected:
            raise AssertionError(
                "the default bata24 matrix does not cover the complete "
                "supported default-glibc catalog"
            )
        return tuple(cases)
    requested = {item.strip() for item in selector.split(",") if item.strip()}
    if not requested:
        raise AssertionError(
            "PWNC_GEF_QEMU_TARGETS must name at least one target"
        )
    known = {target.name for _spec, target in cases}
    unknown = sorted(requested.difference(known))
    if unknown:
        raise AssertionError(
            "PWNC_GEF_QEMU_TARGETS contains unknown default-lane targets: "
            + ", ".join(unknown)
        )
    return tuple(case for case in cases if case[1].name in requested)


_CASES = _selected_cases()


def _isolated_environment(tmp_path: Path, gef_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    environment = os.environ.copy()
    for name in (
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "QEMU_LD_PREFIX",
        "QEMU_SET_ENV",
        "QEMU_UNSET_ENV",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "HOME": os.fspath(home),
            "TMPDIR": os.fspath(tmp_path),
            "TERM": "xterm",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PWNC_BATA24_GEF_PATH": os.fspath(gef_path),
            "PWNC_BATA24_GEF_QEMU": "1",
        }
    )
    return environment


def _compile_inferior(
    provisioned: ProvisionedSysroot,
    target,
    output: Path,
) -> None:
    target_flags = ("-mthumb",) if target.arch is Architecture.THUMB else ()
    command = (
        *provisioned.compiler_argv,
        *target_flags,
        "-x",
        "c",
        "-",
        "-std=gnu11",
        "-g3",
        "-O0",
        "-Wall",
        "-Wextra",
        "-fno-omit-frame-pointer",
        "-fno-stack-protector",
        "-fno-pie",
        "-no-pie",
        "-Wl,-z,relro",
        "-Wl,-z,noexecstack",
        "-o",
        os.fspath(output),
        "-ldl",
    )
    compiled = subprocess.run(
        command,
        input=_INFERIOR_SOURCE,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert compiled.returncode == 0, (
        f"{provisioned.spec.id}/{target.name} compilation failed:\n"
        f"{compiled.stdout}\n{compiled.stderr}"
    )


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _gdb_path_argument(value: str | os.PathLike[str]) -> str:
    """Return a controlled path that GDB will not store with literal quotes.

    Several ``set`` commands do not apply the filename parser: quoting a path
    there makes the quote characters part of ``sysroot`` or
    ``solib-search-path``.  Test-generated paths are deliberately
    whitespace-free, so passing them verbatim is both unambiguous and works
    consistently across the GDB versions covered by this repository.
    """

    text = os.fspath(value)
    assert text
    assert not any(character.isspace() for character in text)
    return text


def _source(gdb: Gdb, path: Path) -> str:
    resolved = os.fspath(path.resolve())
    assert "\n" not in resolved and "\r" not in resolved
    # GDB's `source` command treats quotes as literal filename characters.
    # Every test path is controlled and whitespace-free.
    assert not any(character.isspace() for character in resolved)
    return gdb.execute("source " + resolved, timeout=TIMEOUT)


def _reap_qemu(process: subprocess.Popen[bytes]) -> bytes:
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3.0)
    _stdout, stderr = process.communicate(timeout=3.0)
    return stderr


@contextmanager
def _qemu_gdb_session(
    provisioned: ProvisionedSysroot,
    binary: Path,
    environment: dict[str, str],
):
    qemu = shutil.which(provisioned.qemu)
    assert qemu is not None, f"required QEMU binary is unavailable: {provisioned.qemu}"
    gdb_path = shutil.which(GDB_MULTIARCH)
    assert gdb_path is not None, f"multiarch GDB is unavailable: {GDB_MULTIARCH}"

    port = _unused_tcp_port()
    # Use the exact loader/library-path invocation shared with the real-libc
    # payload tests.  Some historical x86-64 sysroots crash inside ld.so when
    # launched through QEMU's ``-L`` prefix handling.  Explicit-loader mode is
    # stable, and re-selecting the executable after attach below compensates
    # for QEMU reporting the loader as the top-level image in qOffsets.
    runtime_argv = provisioned.qemu_argv(binary)
    assert runtime_argv[0] == qemu
    qemu_argv = (runtime_argv[0], "-g", str(port), *runtime_argv[1:])
    process = subprocess.Popen(
        qemu_argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    transport = None
    gdb = None
    try:
        transport = DapTransport(gdb_path=gdb_path, env=environment, init=False)
        gdb = Gdb(transport)
        gdb._initialize()
        gdb.execute("set pagination off", timeout=TIMEOUT)
        gdb.execute("set confirm off", timeout=TIMEOUT)
        gdb.execute("set debuginfod enabled off", timeout=TIMEOUT)
        gdb.execute("set breakpoint pending on", timeout=TIMEOUT)
        gdb.execute("file " + _gdb_path_argument(binary.resolve()), timeout=TIMEOUT)
        gdb.execute(
            "set sysroot " + _gdb_path_argument(provisioned.sysroot),
            timeout=TIMEOUT,
        )
        gdb.execute(
            "set solib-search-path "
            + _gdb_path_argument(provisioned.libc.parent),
            timeout=TIMEOUT,
        )
        # Load the exact plugin before the remote target exists.  On raw
        # qemu-x86_64, sourcing GEF while already attached can immediately
        # recurse through is_qiling -> maps -> auxv -> is_qiling before a later
        # request has any chance to install a runtime guard.  The explicit
        # QEMU-intent environment flag lets the atomic loader install that
        # narrow guard now; the post-attach snapshots still prove the actual
        # transport is qemu-user.
        _source(gdb, EXPERIMENTS / "gef_injection_ext.py")
        _source(gdb, EXPERIMENTS / "gef_qemu_compat_ext.py")
        _source(gdb, EXPERIMENTS / "gef_arch_snapshot_ext.py")
        _source(gdb, CALLBACK_OPERATIONS)
        gdb.execute("gef config gef.disable_color True", timeout=TIMEOUT)
        gdb.execute('gef config context.layout ""', timeout=TIMEOUT)
        # Configuring GDB and sourcing GEF gives QEMU time to bind.  A
        # one-shot liveness check catches loader/bind failures without a
        # sleep/poll loop; the attach request itself is the readiness event.
        if process.poll() is not None:
            stderr = _reap_qemu(process).decode("utf-8", "replace")
            raise AssertionError("QEMU exited before the GDB attach:\n" + stderr)
        pending = transport.send("attach", {"target": f"127.0.0.1:{port}"})
        gdb._post_connect(pending, consume_initial_stop=False)
        initial_stop = gdb.wait(timeout=TIMEOUT)
        assert initial_stop.get("reason") not in {"exited", "terminated"}
        # Explicit-loader mode makes qOffsets describe ld.so.  Re-selecting
        # the fixture restores its link-time symbols without changing the
        # already-connected remote target.
        gdb.execute("file " + _gdb_path_argument(binary.resolve()), timeout=TIMEOUT)
        # GDB's DAP attach path may replace solib settings while creating the
        # remote target.  Reapply the exact cross sysroot after that transition
        # and load the already-present dynamic linker/libc symbols.
        gdb.execute(
            "set sysroot " + _gdb_path_argument(provisioned.sysroot),
            timeout=TIMEOUT,
        )
        gdb.execute(
            "set solib-search-path "
            + _gdb_path_argument(provisioned.libc.parent),
            timeout=TIMEOUT,
        )
        gdb.execute("sharedlibrary", timeout=TIMEOUT)
        yield gdb, process
    finally:
        try:
            if gdb is not None:
                gdb.close()
            elif transport is not None:
                transport.close()
        finally:
            _reap_qemu(process)


def _assert_clean_output(
    label: str,
    output: str,
    *,
    allowed_gef_warnings: tuple[str, ...] = (),
) -> None:
    assert output.strip(), f"GEF returned no output for {label!r}"
    for marker in _PYTHON_ERROR_MARKERS:
        assert marker not in output, f"{label!r} leaked {marker!r}:\n{output}"
    for line in output.splitlines():
        if not line.lstrip().startswith("[!]"):
            continue
        assert any(
            allowed in line for allowed in allowed_gef_warnings
        ), f"{label!r} leaked a GEF error diagnostic:\n{output}"


def _assert_breakpoint_stop(gdb: Gdb, stop: dict) -> None:
    if stop.get("reason") == "breakpoint":
        return
    diagnostics = [f"stop event: {stop!r}"]
    for command in ("x/i $pc", "info registers", "bt 8"):
        try:
            output = gdb.execute(command, timeout=TIMEOUT)
        except Exception as error:  # noqa: BLE001 - diagnostic best effort
            output = f"<{type(error).__name__}: {error}>"
        diagnostics.append(f"{command}:\n{output}")
    stderr = gdb.transport.stderr_tail.decode("utf-8", "replace")
    if stderr:
        diagnostics.append("GDB stderr:\n" + stderr)
    raise AssertionError("inferior did not reach the marker\n" + "\n".join(diagnostics))


def _assert_native_runtime_snapshots(gdb: Gdb, target, tmp_path: Path) -> None:
    """Exercise the compiled retained model when the optional viewer is built."""

    if not os.access(NATIVE_VIEWER, os.X_OK):
        return
    socket_path = tmp_path / ("viewer-" + target.name + ".sock")
    model_path = tmp_path / ("viewer-" + target.name + ".json")
    ready_read, ready_write = os.pipe()
    process = subprocess.Popen(
        [
            NATIVE_VIEWER,
            "--headless",
            "--socket",
            socket_path,
            "--ready-fd",
            str(ready_write),
            "--exit-after-snapshots",
            "2",
            "--model-out",
            model_path,
        ],
        pass_fds=(ready_write,),
    )
    os.close(ready_write)
    try:
        assert select.select([ready_read], [], [], TIMEOUT)[0]
        assert os.read(ready_read, 1) == b"R"
        gdb.viewer.connect(socket_path, capture=False)
        assert process.wait(TIMEOUT) == 0
        model = json.loads(model_path.read_text(encoding="utf-8"))
        assert len(model["sessions"]) == 1
        session = model["sessions"][0]
        assert session["info"]["architecture"] == gdb.runtime.architecture
        assert [item["name"] for item in session["snapshots"]] == [
            "multiarch-before",
            "multiarch-after",
        ]
        assert session["snapshots"][1]["marks"][0]["label"] == "multiarch-word"
        assert session["diffs"][1]["changed"] is True
        assert session["diffs"][1]["marks"]["changed"]
    finally:
        os.close(ready_read)
        gdb.viewer.disconnect()
        if process.poll() is None:
            process.terminate()
            process.wait(TIMEOUT)


@pytest.mark.parametrize(
    ("spec", "target"),
    _CASES,
    ids=[target.name for _spec, target in _CASES],
)
def test_unmodified_bata24_across_real_glibc_qemu_targets(
    exact_gef: Path,
    tmp_path: Path,
    spec: SysrootSpec,
    target,
) -> None:
    provisioned = provision_sysroot(spec, _CACHE)
    binary = tmp_path / ("bata24-" + target.name)
    _compile_inferior(provisioned, target, binary)
    environment = _isolated_environment(tmp_path, exact_gef)

    with _qemu_gdb_session(provisioned, binary, environment) as (gdb, _qemu):
        version = gdb.execute("gef version --compact", timeout=TIMEOUT)
        _assert_clean_output("gef version --compact", version)
        assert "gdb:" in version
        assert "python:" in version

        compat = gdb.transport.request("pwncGefQemuCompatSnapshot", timeout=TIMEOUT)
        assert compat["source"]["verified"] is True
        assert compat["source"]["sha256"] == GEF_SHA256
        assert compat["source"]["loaded_by_compat"] is True
        _assert_clean_output(
            "bata24 source",
            compat["source"]["output"] or "GEF loaded cleanly",
        )
        assert not compat["missing_commands"]
        assert compat["pid_guard"]["installed"] is True
        assert compat["qemu_user_confirmed"] is True
        assert compat["qiling_guard"] == {
            "installed": True,
            "original_preserved": True,
        }
        assert all(compat["checksec_guard"]["installed"].values())
        assert compat["checksec_guard"]["originals_preserved"] is True
        assert not compat["initialization_errors"]
        probe = gdb.transport.request("pwncGefQemuCompatProbe", timeout=TIMEOUT)
        assert probe["pid_guard_installed"] is True
        assert probe["sessions"] == []
        assert probe["suppressed_delta"] == 1

        architecture = gdb.transport.request("pwncArch", timeout=TIMEOUT)
        assert architecture == {
            "ptrbits": target.bits,
            "byteorder": target.endian.value,
        }
        gdb.bp("pwnc_gef_marker")
        stop = gdb.cont(timeout=TIMEOUT)
        _assert_breakpoint_stop(gdb, stop)

        # Thumb state is meaningful only after leaving the ARM-mode dynamic
        # loader and reaching the Thumb-compiled fixture.
        gef_arch = gdb.transport.request(
            "pwncGefArchitectureSnapshot",
            timeout=TIMEOUT,
        )
        assert gef_arch["current_arch"]["arch"] == _GEF_ARCH_NAMES[target.arch]
        assert gef_arch["current_arch"]["bit_length"] == target.bits
        declared_endians = {
            item.strip()
            for item in gef_arch["current_arch"]["endianness"].split("/")
        }
        if target.name in _BATA24_DECLARED_ENDIAN_MISMATCH:
            assert declared_endians == {
                _BATA24_DECLARED_ENDIAN_MISMATCH[target.name]
            }
        else:
            assert target.endian.value in declared_endians
        assert gef_arch["runtime_endian"]["name"] == target.endian.value
        assert gef_arch["p32_01020304"] == (
            "04030201" if target.endian is Endian.LITTLE else "01020304"
        )
        assert gef_arch["is_remote_debug"] is True
        assert gef_arch["is_qemu"] is True
        assert gef_arch["is_qemu_user"] is True
        assert not gef_arch["errors"]
        assert gef_arch["registers"]["pc"].startswith("$")
        assert gef_arch["registers"]["sp"].startswith("$")
        if target.arch is Architecture.THUMB:
            assert gef_arch["current_arch"]["mode"] == "THUMB"
        elif target.arch is Architecture.ARM:
            assert gef_arch["current_arch"]["mode"] == "ARM"

        libc_path_symbol = gdb.sym.pwnc_gef_libc_path
        libc_path_data = gdb.read(libc_path_symbol.address, 4096, timeout=TIMEOUT)
        libc_path = Path(libc_path_data.split(b"\0", 1)[0].decode())
        assert libc_path.samefile(provisioned.libc)

        word = gdb.sym.pwnc_gef_word
        assert word.nbits == target.bits
        assert int(word) == 0x10203040
        assert word.bytes == target.pack(0x10203040)
        assert gdb.read(word.address, target.word_size, timeout=TIMEOUT) == target.pack(
            0x10203040
        )
        assert gdb.eval("$pc", timeout=TIMEOUT) > 0
        assert gdb.eval("$sp", timeout=TIMEOUT) > 0
        assert gdb.frame(timeout=TIMEOUT).pc() > 0

        # The user-facing runtime API must remain ordinary Python while its
        # explicit JSON boundary carries the same facts to the native viewer.
        runtime_json = gdb.runtime.to_json()
        assert gdb.arch == target
        assert runtime_json["architecture"]
        assert runtime_json["map_provider"].startswith("bata24")
        assert runtime_json["bata24"]["adapter"] == "bata24-direct-v1"
        assert runtime_json["bata24"]["maps"] is True
        assert gdb.main is not None and Path(gdb.main.path).samefile(binary)
        assert gdb.libc is not None and Path(gdb.libc.path).samefile(provisioned.libc), runtime_json["modules"]
        assert gdb.maps.require(gdb.reg.pc).executable
        assert gdb.modules.at(gdb.reg.pc) == gdb.main
        assert gdb.heap.available
        if target.arch not in _BATA24_DYNAMIC_HEAP_ARENA_UNSUPPORTED:
            allocation = int(gdb.sym.pwnc_gef_allocation)
            chunk = gdb.heap.chunk(allocation)
            assert chunk.address == allocation
            assert chunk.allocated
            assert chunk.usable_size >= 0x90

        facts = gdb.thread_facts(frames=4, libc=True)
        assert facts.top is not None and facts.top.name == "pwnc_gef_marker"
        assert facts.reg.pc == gdb.reg.pc
        assert facts.top.variable("phase") is not None
        assert facts.top.variable("scoped") is not None

        typed_word = gdb.memory.capture(word.address, "uintptr_t")
        assert typed_word.data == target.pack(0x10203040)
        assert int(typed_word.value) == 0x10203040
        word_mark = gdb.mark(typed_word.value, label="multiarch-word")
        before = gdb.snapshot("multiarch-before", frames=2, libc=True)
        changed_word = 0x50607080
        gdb.write(word.address, target.pack(changed_word))
        after = gdb.snapshot("multiarch-after", frames=2, libc=True)
        difference = before.diff(after)
        assert difference.changed
        assert difference.marks_changed
        assert difference.marks_changed[0].id == word_mark.id
        assert gdb.verify.memory(word.address, target.pack(changed_word)).require().ok
        assert after.to_json()["threads"][0]["frames"][0]["arguments"][0]["name"] == "phase"
        _assert_native_runtime_snapshots(gdb, target, tmp_path)

        commands = {
            "checksec -f " + _gdb_path_argument(binary): (
                "Canary",
                "NX",
                "PIE",
                "RELRO",
            ),
            # bata24's qemu-user map reconstruction does not consistently
            # label anonymous brk storage as ``[heap]`` (and x86 may render
            # some loader-owned ranges as ``<explored>``).  The fixture and
            # stack are stable semantic anchors; ``heap chunks`` below proves
            # allocator traversal independently.
            "vmmap": (binary.name, "[stack]"),
            "xinfo $pc": ("pwnc_gef_marker",),
            "got -n": ("malloc", "free"),
            "context regs stack code": ("register", "stack", "code"),
        }
        outputs = {}
        for command, fragments in commands.items():
            output = gdb.execute(command, timeout=TIMEOUT)
            _assert_clean_output(command, output)
            outputs[command] = output
            lowered = output.lower()
            for fragment in fragments:
                assert fragment.lower() in lowered, (command, fragment, output)

        heap_output = gdb.execute("heap chunks -n", timeout=TIMEOUT)
        if target.arch in _BATA24_DYNAMIC_HEAP_ARENA_UNSUPPORTED:
            _assert_clean_output(
                "heap chunks -n",
                heap_output,
                allowed_gef_warnings=(
                    "Failed to get the arena",
                    "No valid arena",
                ),
            )
            # The pinned plugin cannot find a dynamic arena on these targets.
            # Keep executing the command so the known limitation cannot turn
            # into a traceback, hang, or different silent failure.
            assert "Failed to get the arena" in heap_output
            assert "No valid arena" in heap_output
        else:
            _assert_clean_output("heap chunks -n", heap_output)
            assert "Chunk(" in heap_output
            assert "top" in heap_output

        callback_threads = []

        def host_callback(
            depth,
            sync_callback,
            _recursive_callback,
            *,
            max_depth,
            binary,
        ):
            assert (depth, max_depth) == (0, 0)
            assert binary == (b"pwnc", b"callback")
            callback_threads.append(threading.get_ident())
            xinfo = gdb.execute("xinfo $pc", timeout=TIMEOUT)
            context = gdb.execute("context regs stack code", timeout=TIMEOUT)
            _assert_clean_output("callback xinfo", xinfo)
            _assert_clean_output("callback context", context)
            return {
                "sync": sync_callback(40, increment=2),
                "marker": "pwnc_gef_marker" in xinfo,
            }

        result = gdb.use(timeout=TIMEOUT).call(
            "pwnc.test.capabilities",
            host_callback,
            0,
            max_depth=0,
        )
        assert result == {"sync": 42, "marker": True}
        assert len(callback_threads) == 1
        assert callback_threads[0] not in {
            gdb.transport.reader_thread_id,
            gdb.transport.router_thread_id,
            gdb.transport.writer_thread_id,
            gdb.transport.event_thread_id,
        }

        operation = gdb.transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert operation["activeCount"] == 0
        assert not gdb.operations.errors
        assert gdb.operations.active_operations == 0
        assert gdb.operations.active_callbacks == 0
        assert gdb.transport.pending_count == 0

        injection = gdb.transport.request("pwncGefInjectionSnapshot", timeout=TIMEOUT)
        assert injection["installed"] is True
        assert any(
            event["kind"] == "execute-enter"
            and event["depth"] > 0
            for event in injection["events"]
        )
        final_compat = gdb.transport.request(
            "pwncGefQemuCompatSnapshot",
            timeout=TIMEOUT,
        )
        expected_skips = {
            name: 0
            for name in final_compat["checksec_guard"]["skipped"]
        }
        if target.arch is Architecture.ARM64:
            expected_skips["get_pac_status"] = 1
            expected_skips["get_mte_status"] = 1
        elif target.arch in {Architecture.X86, Architecture.X86_64}:
            expected_skips["get_cet_status_new_interface"] = 1
            expected_skips["get_cet_status_via_procfs"] = 1
        assert final_compat["checksec_guard"]["skipped"] == expected_skips
        pid_snapshot = final_compat["pid_guard"]
        assert pid_snapshot["installed"] is True
        # The compatibility wrapper keeps a raw GEF /proc race from aborting
        # the session, but a real race must remain a visible test failure.  In
        # a clean run the synthetic impossible-PID probe is the sole event.
        assert pid_snapshot["suppressed_count"] == 1
        assert pid_snapshot["by_type"] == {"FileNotFoundError": 1}
        assert pid_snapshot["by_errno"] == {"2": 1}
        assert pid_snapshot["by_pid"] == {str(probe["pid"]): 1}
        assert not gdb.transport.worker_errors
        _assert_clean_output(
            "GDB stderr",
            gdb.transport.stderr_tail.decode("utf-8", "replace") or "clean",
        )
