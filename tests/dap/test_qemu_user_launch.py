"""Automatic qemu-user launch/debug coverage for the public DAP API."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import contextlib
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwn import ELF, process
from pwnc.gdb import dap


TIMEOUT = 20.0


def _live_qemu_x86_64_available():
    emulator = shutil.which("qemu-x86_64")
    debugger = shutil.which("gdb-multiarch")
    if emulator is None or debugger is None:
        pytest.skip("qemu-x86_64 and gdb-multiarch are required")
    return emulator, debugger


def _elf64_le_program_headers(data):
    if data[4:6] != b"\x02\x01":
        pytest.skip("ELF mutation probe expects a little-endian ELF64 host")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    return tuple(phoff + index * phentsize for index in range(phnum))


@contextlib.contextmanager
def _qemu_x86_64_remote(target, program):
    emulator, debugger = _live_qemu_x86_64_available()
    endpoint = dap._QemuSocketPath()
    inferior = process([emulator, "-g", endpoint.path, os.fspath(target)])
    session = None
    try:
        dap._wait_for_qemu_socket(target=inferior, path=endpoint.path)
        session = dap.start(gdb_path=debugger, init=False)
        session.connect(
            endpoint.path,
            os.fspath(program),
            sysroot="/",
            qemu_user=True,
        )
        yield session
    finally:
        if session is not None:
            session.close()
        inferior.close()
        endpoint.close()


class _RemoteTransport:
    def __init__(self):
        self.sent = []

    def send(self, command, arguments):
        pending = (command, arguments)
        self.sent.append(pending)
        return pending


class _RemoteSession:
    _configure_remote_files = dap.Gdb._configure_remote_files
    _connect_remote = dap.Gdb._connect_remote

    def __init__(self):
        self.transport = _RemoteTransport()
        self.requests = []
        self.post_connect = []
        self._sym_type_cache = {}
        self._qemu_user_relocation = None

    def _request(self, command, arguments=None):
        self.requests.append((command, arguments))
        if command == "pwncRemoteFileSettings":
            return dict(arguments)
        return {}

    def _post_connect(self, pending, consume_initial_stop):
        self.post_connect.append((pending, consume_initial_stop))


def test_remote_attach_configures_program_once_and_reapplies_remote_paths():
    session = _RemoteSession()
    session._connect_remote(
        '/tmp/program with "quotes"',
        "/tmp/private.sock",
        sysroot="/opt/cross root",
        solib_search_path="/opt/cross root/lib:/opt/cross root/usr/lib",
    )

    assert session.transport.sent == [("attach", {"target": "/tmp/private.sock"})]
    assert session.post_connect == [(("attach", {"target": "/tmp/private.sock"}), True)]
    assert session.requests == [
        (
            "evaluate",
            {
                "expression": 'file "/tmp/program with \\"quotes\\""',
                "context": "repl",
            },
        ),
        (
            "pwncRemoteFileSettings",
            {
                "sysroot": "/opt/cross root",
                "solibSearchPath": "/opt/cross root/lib:/opt/cross root/usr/lib",
            },
        ),
        (
            "pwncRemoteFileSettings",
            {
                "sysroot": "/opt/cross root",
                "solibSearchPath": "/opt/cross root/lib:/opt/cross root/usr/lib",
            },
        ),
    ]


def test_qemu_remote_requires_verified_rsp_symbol_rebase_after_path_reapply():
    session = _RemoteSession()
    session._connect_remote(
        "/guest/program",
        "/tmp/private.sock",
        sysroot="/guest/root",
        qemu_user=True,
    )

    assert session.requests == [
        (
            "evaluate",
            {"expression": 'file "/guest/program"', "context": "repl"},
        ),
        (
            "pwncRemoteFileSettings",
            {"sysroot": "/guest/root"},
        ),
        (
            "pwncRemoteFileSettings",
            {"sysroot": "/guest/root"},
        ),
        ("pwncQemuUserRebase", {"program": "/guest/program"}),
    ]
    assert dict(session._qemu_user_relocation) == {}


def test_qemu_remote_rebase_failure_is_not_silently_downgraded():
    class FailingSession(_RemoteSession):
        def _request(self, command, arguments=None):
            if command == "pwncQemuUserRebase":
                raise dap.DapError("QEMU did not report guest executable relocation via qOffsets")
            return super()._request(command, arguments)

    with pytest.raises(dap.DapError, match="did not report.*qOffsets"):
        FailingSession()._connect_remote(
            "/guest/program",
            "/tmp/private.sock",
            qemu_user=True,
        )


def test_remote_path_configuration_rejects_quote_contaminated_sysroot():
    class BrokenSession(_RemoteSession):
        def _request(self, command, arguments=None):
            if command == "pwncRemoteFileSettings":
                return {"sysroot": '"' + arguments["sysroot"] + '"'}
            return super()._request(command, arguments)

    with pytest.raises(dap.DapError, match="did not preserve.*sysroot"):
        BrokenSession()._configure_remote_files(None, "/guest root", None)


def test_prepared_launch_and_debug_forward_qemu_controls(monkeypatch, tmp_path):
    program = tmp_path / "foreign"
    program.write_bytes(b"not inspected because detection is stubbed")
    calls = []

    monkeypatch.setattr(dap, "_needs_qemu", lambda _program, _qemu: True)
    monkeypatch.setattr(
        dap,
        "_qemu_prepared",
        lambda session, executable, args, env, **options: calls.append((session, executable, args, env, options)),
    )

    for method in (dap.Gdb.launch, dap.Gdb.debug):
        session = object.__new__(dap.Gdb)

        def bind(operation, bound=session):
            operation()
            return bound

        session._bind_once = bind
        result = method(
            session,
            program,
            "one",
            b"two",
            env={b"RAW": b"\xff"},
            qemu="/custom/qemu-aarch64",
            sysroot="/cross root",
            host_aslr=True,
            qemu_aslr=False,
        )
        assert result is session

    assert len(calls) == 2
    for session, executable, arguments, environment, options in calls:
        assert executable == os.fspath(program.resolve())
        assert arguments == ("one", b"two")
        assert environment == {b"RAW": b"\xff"}
        assert options == {
            "qemu": "/custom/qemu-aarch64",
            "sysroot": "/cross root",
            "host_aslr": True,
            "qemu_aslr": False,
        }


def test_native_launch_maps_host_aslr_to_gdb_randomization_setting():
    class Session:
        def __init__(self):
            self.requests = []
            self.transport = _RemoteTransport()

        def _request(self, command, arguments=None):
            self.requests.append((command, arguments))

        def _post_connect(self, pending, consume_initial_stop):
            self.pending = pending

    for enabled, expected in ((True, "off"), (False, "on")):
        session = Session()
        dap.Gdb._launch(
            session,
            "/native",
            stop_at_main=False,
            host_aslr=enabled,
        )
        assert session.requests[0] == (
            "evaluate",
            {
                "expression": f"set disable-randomization {expected}",
                "context": "repl",
            },
        )


def test_native_debug_maps_host_aslr_to_gdbserver_flag(monkeypatch):
    import pwn

    commands = []
    discarded = []

    class Target:
        def close(self):
            raise AssertionError("adopted target must not be closed")

    target = Target()
    monkeypatch.setattr(
        dap,
        "prepare_launch",
        lambda *_args: ("/launcher", {b"CONTROL": b"1"}, "/config"),
    )
    monkeypatch.setattr(dap, "discard_config", discarded.append)
    monkeypatch.setattr(
        pwn,
        "process",
        lambda command, **options: commands.append((command, options)) or target,
    )
    monkeypatch.setattr(dap, "_gdbserver_port", lambda _target: 31337)
    monkeypatch.setattr(dap, "_finish_inferior_launch", lambda *_args: None)
    monkeypatch.setattr(dap, "_adopt_target", lambda *_args: None)
    monkeypatch.setattr(
        dap,
        "_elf_identity",
        lambda _program: SimpleNamespace(bits=64),
    )

    class Session:
        def _connect_remote(self, program, endpoint, **options):
            assert program == "/program"
            assert endpoint == "127.0.0.1:31337"
            assert options == {"reapply": True}

        def _configure_remote_files(self, program, sysroot, solib_search_path):
            assert (program, sysroot, solib_search_path) == ("/program", "/", None)

    for enabled, expected in (
        (True, "--no-disable-randomization"),
        (False, "--disable-randomization"),
    ):
        dap._debug_prepared(
            Session(),
            "/program",
            (),
            None,
            host_aslr=enabled,
        )
        assert expected in commands[-1][0]
        assert commands[-1][1]["aslr"] is enabled
        if enabled:
            assert commands[-1][1]["preexec_fn"] is dap._enable_host_aslr_preexec
        else:
            assert "preexec_fn" not in commands[-1][1]

    assert discarded == ["/config", "/config"]


def test_default_gdb_changes_to_multiarch_only_for_qemu(monkeypatch):
    monkeypatch.setattr(dap, "_needs_qemu", lambda _program, _qemu: True)
    monkeypatch.setattr(
        dap.shutil,
        "which",
        lambda name: "/usr/bin/gdb-multiarch" if name == "gdb-multiarch" else None,
    )
    assert dap._select_gdb_for_program("foreign", "gdb", None) == "/usr/bin/gdb-multiarch"
    assert dap._select_gdb_for_program("foreign", "/custom/gdb", None) == "/custom/gdb"


def test_qemu_remote_rejects_same_header_different_real_executable():
    false = Path("/usr/bin/false")
    true = Path("/usr/bin/true")
    if not false.is_file() or not true.is_file():
        pytest.skip("the real /usr/bin/false and /usr/bin/true probes are unavailable")
    if false.read_bytes() == true.read_bytes():
        pytest.skip("/usr/bin/false and /usr/bin/true are the same image")

    with (
        pytest.raises(dap.DapError, match="mapped GNU build-ID note differs"),
        _qemu_x86_64_remote(false, true),
    ):
        pass


def test_qemu_remote_accepts_same_real_executable():
    true = Path("/usr/bin/true")
    if not true.is_file():
        pytest.skip("the real /usr/bin/true probe is unavailable")

    with _qemu_x86_64_remote(true, true) as session:
        assert dict(session.qemu_user_relocation)["identity"] == "gnu-build-id+immutable-load-segments"


def test_qemu_remote_validates_exact_program_header_layout(tmp_path):
    true = Path("/usr/bin/true")
    if not true.is_file():
        pytest.skip("the real /usr/bin/true probe is unavailable")
    configured = tmp_path / "true with different load layout"
    shutil.copy2(true, configured)
    data = bytearray(configured.read_bytes())
    if data[4:6] != b"\x02\x01":
        pytest.skip("program-header mutation probe expects a little-endian ELF64 host")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from("<I", data, offset)[0] != 0x6474E551:  # PT_GNU_STACK
            continue
        alignment = struct.unpack_from("<Q", data, offset + 48)[0]
        struct.pack_into("<Q", data, offset + 48, alignment * 2)
        break
    else:
        pytest.skip("/usr/bin/true has no PT_GNU_STACK layout entry")
    configured.write_bytes(data)

    with (
        pytest.raises(dap.DapError, match="ELF/program-header layout differs"),
        _qemu_x86_64_remote(true, configured),
    ):
        pass


def test_qemu_remote_build_id_does_not_hide_immutable_code_difference(tmp_path):
    true = Path("/usr/bin/true")
    if not true.is_file():
        pytest.skip("the real /usr/bin/true probe is unavailable")
    configured = tmp_path / "true with copied build id but different code"
    shutil.copy2(true, configured)
    elf = ELF(configured, checksec=False)
    if not elf.buildid:
        pytest.skip("/usr/bin/true has no GNU build-ID")
    executable = next(
        segment
        for segment in elf.segments
        if segment.header.p_type == "PT_LOAD"
        and segment.header.p_filesz > 16
        and segment.header.p_flags & 1
        and not segment.header.p_flags & 2
    )
    data = bytearray(configured.read_bytes())
    data[executable.header.p_offset + 16] ^= 1
    configured.write_bytes(data)

    with (
        pytest.raises(dap.DapError, match="immutable PT_LOAD segment differs"),
        _qemu_x86_64_remote(true, configured),
    ):
        pass


@pytest.fixture(scope="module")
def build_id_less_binaries(tmp_path_factory):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("GCC is required for the build-ID-less ELF probes")
    directory = tmp_path_factory.mktemp("dap-qemu-identity")
    source = directory / "guest.c"
    target = directory / "guest without build id"
    writable_different = directory / "guest writable data differs"
    immutable_different = directory / "guest immutable code differs"
    malformed_note = directory / "guest malformed note"
    source.write_text(
        "volatile int pwnc_identity_marker = 0x11223344;\nint main(void) { return pwnc_identity_marker == 7; }\n",
        encoding="utf-8",
    )
    compiled = subprocess.run(
        [
            compiler,
            "-g3",
            "-O0",
            "-fPIE",
            "-pie",
            "-Wl,--build-id=none",
            "-o",
            os.fspath(target),
            os.fspath(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if compiled.returncode != 0:
        pytest.skip("GCC cannot build the identity fixture: " + compiled.stderr)

    shutil.copy2(target, writable_different)
    elf = ELF(writable_different, checksec=False)
    marker_address = elf.symbols["pwnc_identity_marker"]
    marker_offset = elf.vaddr_to_offset(marker_address)
    marker_segment = next(
        segment
        for segment in elf.segments
        if segment.header.p_type == "PT_LOAD"
        and segment.header.p_vaddr <= marker_address < segment.header.p_vaddr + segment.header.p_memsz
    )
    assert marker_segment.header.p_flags & 2  # PF_W
    writable_bytes = bytearray(writable_different.read_bytes())
    writable_bytes[marker_offset : marker_offset + 4] = b"\x88\x77\x66\x55"
    writable_different.write_bytes(writable_bytes)

    shutil.copy2(target, immutable_different)
    immutable_elf = ELF(immutable_different, checksec=False)
    main_address = immutable_elf.symbols["main"]
    main_offset = immutable_elf.vaddr_to_offset(main_address)
    main_segment = next(
        segment
        for segment in immutable_elf.segments
        if segment.header.p_type == "PT_LOAD"
        and segment.header.p_vaddr <= main_address < segment.header.p_vaddr + segment.header.p_memsz
    )
    assert main_segment.header.p_flags & 1  # PF_X
    assert not main_segment.header.p_flags & 2  # PF_W
    immutable_bytes = bytearray(immutable_different.read_bytes())
    immutable_bytes[main_offset] ^= 1
    immutable_different.write_bytes(immutable_bytes)

    shutil.copy2(target, malformed_note)
    malformed_bytes = bytearray(malformed_note.read_bytes())
    if malformed_bytes[4] != 2 or malformed_bytes[5] != 1:
        pytest.skip("malformed-note fixture expects a little-endian ELF64 host")
    phoff = struct.unpack_from("<Q", malformed_bytes, 32)[0]
    phentsize = struct.unpack_from("<H", malformed_bytes, 54)[0]
    phnum = struct.unpack_from("<H", malformed_bytes, 56)[0]
    for index in range(phnum):
        header_offset = phoff + index * phentsize
        if struct.unpack_from("<I", malformed_bytes, header_offset)[0] != 4:
            continue
        note_offset = struct.unpack_from("<Q", malformed_bytes, header_offset + 8)[0]
        struct.pack_into("<I", malformed_bytes, note_offset, 0xFFFFFFFF)
        break
    else:
        pytest.skip("compiler fixture has no PT_NOTE to corrupt")
    malformed_note.write_bytes(malformed_bytes)

    return target, writable_different, immutable_different, malformed_note


def test_qemu_remote_missing_build_id_uses_full_immutable_load_fallback(
    build_id_less_binaries,
):
    target, _writable_different, _immutable_different, _malformed_note = build_id_less_binaries
    with _qemu_x86_64_remote(target, target) as session:
        assert dict(session.qemu_user_relocation)["identity"] == "immutable-load-segments"


def test_qemu_remote_immutable_fallback_excludes_writable_only_difference(
    build_id_less_binaries,
):
    target, writable_different, _immutable_different, _malformed_note = build_id_less_binaries
    with _qemu_x86_64_remote(target, writable_different) as session:
        # This method is intentionally an exact identity of immutable mapped
        # load segments, not a full-file identity.  Writable/relocated state is
        # outside the evidence used for safe symbol rebasing.
        assert dict(session.qemu_user_relocation)["identity"] == "immutable-load-segments"


def test_qemu_remote_immutable_fallback_rejects_code_difference(
    build_id_less_binaries,
):
    target, _writable_different, immutable_different, _malformed_note = build_id_less_binaries
    with (
        pytest.raises(dap.DapError, match="immutable PT_LOAD segment differs"),
        _qemu_x86_64_remote(target, immutable_different),
    ):
        pass


def test_qemu_remote_immutable_fallback_rejects_writable_executable_load(
    build_id_less_binaries,
    tmp_path,
):
    target = build_id_less_binaries[0]
    writable_executable = tmp_path / "guest with writable executable load"
    shutil.copy2(target, writable_executable)
    data = bytearray(writable_executable.read_bytes())
    for offset in _elf64_le_program_headers(data):
        if struct.unpack_from("<I", data, offset)[0] != 1:  # PT_LOAD
            continue
        flags = struct.unpack_from("<I", data, offset + 4)[0]
        if flags & 1:  # PF_X
            struct.pack_into("<I", data, offset + 4, flags | 2)  # PF_W
            break
    else:
        pytest.skip("identity fixture has no executable PT_LOAD")
    writable_executable.write_bytes(data)

    with (
        pytest.raises(dap.DapError, match="writable-executable PT_LOAD"),
        _qemu_x86_64_remote(writable_executable, writable_executable),
    ):
        pass


def test_qemu_remote_immutable_fallback_rejects_text_relocation(
    build_id_less_binaries,
    tmp_path,
):
    target = build_id_less_binaries[0]
    textrel = tmp_path / "guest with text relocation"
    shutil.copy2(target, textrel)
    data = bytearray(textrel.read_bytes())
    for offset in _elf64_le_program_headers(data):
        if struct.unpack_from("<I", data, offset)[0] != 2:  # PT_DYNAMIC
            continue
        dynamic_offset = struct.unpack_from("<Q", data, offset + 8)[0]
        dynamic_size = struct.unpack_from("<Q", data, offset + 32)[0]
        for cursor in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
            if struct.unpack_from("<q", data, cursor)[0] != 0:
                struct.pack_into("<q", data, cursor, 22)  # DT_TEXTREL
                break
        else:
            pytest.skip("identity fixture has no mutable dynamic tag")
        break
    else:
        pytest.skip("identity fixture has no PT_DYNAMIC")
    textrel.write_bytes(data)

    with (
        pytest.raises(dap.DapError, match="permits text relocations"),
        _qemu_x86_64_remote(textrel, textrel),
    ):
        pass


def test_qemu_remote_immutable_fallback_rejects_duplicate_dynamic_headers(
    build_id_less_binaries,
    tmp_path,
):
    target = build_id_less_binaries[0]
    duplicate = tmp_path / "guest with duplicate dynamic headers"
    shutil.copy2(target, duplicate)
    data = bytearray(duplicate.read_bytes())
    dynamic_seen = False
    replacement = None
    for offset in _elf64_le_program_headers(data):
        header_type = struct.unpack_from("<I", data, offset)[0]
        dynamic_seen |= header_type == 2
        if header_type == 4:  # PT_NOTE is safe to reinterpret for this stopped probe.
            replacement = offset
    if not dynamic_seen or replacement is None:
        pytest.skip("identity fixture cannot form a duplicate PT_DYNAMIC probe")
    struct.pack_into("<I", data, replacement, 2)
    duplicate.write_bytes(data)

    with (
        pytest.raises(dap.DapError, match="malformed or ambiguous dynamic metadata"),
        _qemu_x86_64_remote(duplicate, duplicate),
    ):
        pass


def test_qemu_remote_malformed_note_without_build_id_fails_closed(
    build_id_less_binaries,
):
    target, _writable_different, _immutable_different, malformed_note = build_id_less_binaries
    with (
        pytest.raises(dap.DapError, match="malformed PT_NOTE"),
        _qemu_x86_64_remote(target, malformed_note),
    ):
        pass


@pytest.fixture(scope="module")
def aarch64_binary(tmp_path_factory) -> Path:
    zig = shutil.which("zig")
    if zig is None or shutil.which("qemu-aarch64") is None:
        pytest.skip("Zig and qemu-aarch64 are required")
    if shutil.which("gdb-multiarch") is None:
        pytest.skip("gdb-multiarch is required")

    directory = tmp_path_factory.mktemp("dap-qemu-aarch64")
    source = directory / "guest.c"
    binary = directory / "guest"
    source.write_text(
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "int main(int argc, char **argv) {\n"
        '  printf("ARG=%s ENV=%s\\n", argc > 1 ? argv[1] : "", '
        'getenv("PWNC_GUEST"));\n'
        "  return 42;\n"
        "}\n"
    )
    compiled = subprocess.run(
        [
            zig,
            "cc",
            "-target",
            "aarch64-linux-musl",
            "-static",
            "-g3",
            "-O0",
            "-fno-pie",
            "-no-pie",
            "-o",
            os.fspath(binary),
            os.fspath(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if compiled.returncode != 0:
        pytest.skip("Zig cannot build the aarch64 fixture: " + compiled.stderr)
    return binary


@pytest.fixture(scope="module")
def s390x_binary(tmp_path_factory) -> Path:
    zig = shutil.which("zig")
    if zig is None or shutil.which("qemu-s390x") is None:
        pytest.skip("Zig and qemu-s390x are required")
    if shutil.which("gdb-multiarch") is None:
        pytest.skip("gdb-multiarch is required")

    directory = tmp_path_factory.mktemp("dap-qemu-s390x")
    source = directory / "guest.c"
    binary = directory / "guest"
    source.write_text(
        "volatile int reached_main;\nint main(void) { reached_main = 0x2468ace; return 0; }\n",
        encoding="utf-8",
    )
    compiled = subprocess.run(
        [
            zig,
            "cc",
            "-target",
            "s390x-linux-musl",
            "-static",
            "-g3",
            "-O0",
            "-fno-pie",
            "-no-pie",
            "-o",
            os.fspath(binary),
            os.fspath(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if compiled.returncode != 0:
        pytest.skip("Zig cannot build the s390x fixture: " + compiled.stderr)
    return binary


@pytest.fixture(scope="module")
def i386_pie_binary(tmp_path_factory) -> Path:
    compiler = shutil.which("gcc")
    emulator = shutil.which("qemu-i386")
    if compiler is None or emulator is None:
        pytest.skip("GCC and qemu-i386 are required")
    if shutil.which("gdb-multiarch") is None:
        pytest.skip("gdb-multiarch is required")

    directory = tmp_path_factory.mktemp("dap-qemu-i386-pie")
    source = directory / "guest.c"
    binary = directory / "guest"
    source.write_text(
        "volatile int reached_main;\nint main(void) { reached_main = 0x13579bdf; return 0; }\n",
        encoding="utf-8",
    )
    compiled = subprocess.run(
        [
            compiler,
            "-m32",
            "-g3",
            "-O0",
            "-fPIE",
            "-pie",
            "-o",
            os.fspath(binary),
            os.fspath(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if compiled.returncode != 0:
        pytest.skip("32-bit glibc development files are unavailable: " + compiled.stderr)
    return binary


def test_qemu_s390x_big_endian_et_exec_identity(s390x_binary):
    session = dap.debug(
        s390x_binary,
        qemu=shutil.which("qemu-s390x"),
        init=False,
        host_aslr=True,
        qemu_aslr=False,
    )
    try:
        assert dict(session.qemu_user_relocation) == {
            "pie": False,
            "loadBias": 0,
            "source": "elf",
            "symbolsReloaded": True,
            "identity": "immutable-load-segments",
        }
        assert session.reg.pc == ELF(s390x_binary, checksec=False).entry
    finally:
        session.close()


def test_qemu_i386_pie_symbols_use_verified_guest_runtime_bias(i386_pie_binary):
    emulator = shutil.which("qemu-i386")
    session = dap.debug(
        i386_pie_binary,
        qemu=emulator,
        init=False,
        host_aslr=True,
        qemu_aslr=False,
    )
    try:
        assert session.remote_file_settings["sysroot"] == "/"
        relocation = dict(session.qemu_user_relocation)
        assert relocation == {
            "pie": True,
            "loadBias": relocation["loadBias"],
            "source": "qOffsets",
            "symbolsReloaded": True,
            "identity": "gnu-build-id+immutable-load-segments",
        }
        assert relocation["loadBias"] > 0
        elf = ELF(i386_pie_binary, checksec=False)
        expected_main = relocation["loadBias"] + elf.symbols["main"]
        assert int(session.sym.main) == expected_main

        session.bp("main")
        stop = session.run(timeout=TIMEOUT)
        assert stop["reason"] == "breakpoint"
        # A source-level ``break main`` may advance past the function prologue,
        # but it must remain in the rebased main image rather than link-time VA.
        assert expected_main <= session.reg.pc < expected_main + 64
    finally:
        session.close()


def test_qemu_i386_livectf_challenge_uses_mapped_build_id():
    root = os.environ.get("PWNC_LIVECTF_PRINTF_PLUS_PLUS_ROOT")
    if not root:
        pytest.skip("set PWNC_LIVECTF_PRINTF_PLUS_PLUS_ROOT to the extracted handout")
    challenge = Path(root) / "challenge"
    emulator = shutil.which("qemu-i386")
    if emulator is None or not challenge.is_file():
        pytest.skip("qemu-i386 and the extracted LiveCTF challenge are required")

    session = dap.debug(
        challenge,
        qemu=emulator,
        init=False,
        host_aslr=True,
        qemu_aslr=False,
    )
    try:
        relocation = dict(session.qemu_user_relocation)
        assert relocation["identity"] == "gnu-build-id+immutable-load-segments"
        assert relocation["loadBias"] > 0
        assert (
            int(session.sym.main)
            == relocation["loadBias"]
            + ELF(
                challenge,
                checksec=False,
            ).symbols["main"]
        )
    finally:
        session.close()


@pytest.mark.parametrize("constructor", [dap.debug, dap.launch], ids=["debug", "launch"])
def test_foreign_aarch64_starts_at_first_instruction_with_clean_io(
    constructor,
    aarch64_binary,
):
    session = constructor(
        aarch64_binary,
        "round trip",
        env={"PWNC_GUEST": "exact"},
        init=False,
        host_aslr=True,
        qemu_aslr=False,
    )
    qemu_argv = tuple(map(os.fsdecode, session.target.argv))
    socket_path = qemu_argv[qemu_argv.index("-g") + 1]
    try:
        assert "-R" in qemu_argv
        assert dict(session.qemu_user_relocation) == {
            "pie": False,
            "loadBias": 0,
            "source": "elf",
            "symbolsReloaded": True,
            "identity": "immutable-load-segments",
        }
        assert session.reg.pc == ELF(aarch64_binary, checksec=False).entry
        assert session.target.poll(block=False) is None
        stop = session.run(timeout=TIMEOUT)
        assert stop["reason"] in {"exited", "terminated"}
        assert session.target.recvall(timeout=2.0) == b"ARG=round trip ENV=exact\n"
    finally:
        session.close()

    assert not os.path.exists(socket_path)
    assert not os.path.exists(os.path.dirname(socket_path))
