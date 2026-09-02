"""Real-GDB coverage for clean DAP shutdown and shared CLI history."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import ConsoleConfig, launch
from pwnc.gdb.dap import console as console_module


TIMEOUT = 10.0


@pytest.fixture
def shutdown_binary(tmp_path):
    if not shutil.which("gdb") or not shutil.which("gcc"):
        pytest.skip("live GDB and GCC are required")
    source = tmp_path / "shutdown.c"
    binary = tmp_path / "shutdown"
    source.write_text(
        "#include <unistd.h>\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc > 1) for (;;) usleep(10000);\n"
        "    return 0;\n"
        "}\n"
    )
    subprocess.run(
        ["gcc", "-g", "-O0", "-no-pie", "-o", str(binary), str(source)],
        check=True,
    )
    return binary


def _connect_console(gdb):
    console = gdb._console
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(TIMEOUT)
    client.connect(console._broker.socket_path)
    hello = json.dumps(
        {
            "version": console_module._PROTOCOL_VERSION,
            "token": console._broker.token,
            "session": console.session_id,
        }
    ).encode()
    client.sendall(console_module._pack_frame(console_module._FRAME_HELLO, hello))
    return client


def _type_and_confirm(gdb, client, command, marker):
    client.sendall(console_module._pack_frame(console_module._FRAME_INPUT, (command + "\n").encode()))
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if marker.lower() in gdb.execute("show commands").lower():
            return
        time.sleep(0.02)
    pytest.fail("secondary GDB UI did not record the typed command")


def test_close_preserves_real_gdb_history_across_sequential_sessions(shutdown_binary, tmp_path):
    history = tmp_path / "gdb-history"
    gdb_path = os.environ.get("PWNC_TEST_GDB", "gdb")
    environment = dict(os.environ)
    environment["GDBHISTFILE"] = str(history)

    first = launch(
        str(shutdown_binary),
        gdb_path=gdb_path,
        env=environment,
        init=False,
        console=ConsoleConfig.owned(),
    )
    first_client = _connect_console(first)
    try:
        _type_and_confirm(first, first_client, "print 0xa11ce001", "a11ce001")
        first.console_close()
        assert first._console.endpoint_alive
        assert not first._console.viewer_connected
        assert int(first.sym.main) > 0
        started = time.monotonic()
        first.close()
        assert time.monotonic() - started < 5.0
    finally:
        first.close()
        first_client.close()

    first_history = history.read_text().lower()
    assert "print 0xa11ce001" in first_history

    second = launch(
        str(shutdown_binary),
        "spin",
        gdb_path=gdb_path,
        env=environment,
        init=False,
        console=ConsoleConfig.owned(),
    )
    second_client = _connect_console(second)
    try:
        # GDB itself loaded the prior session through GDBHISTFILE.
        assert "print 0xa11ce001" in second.execute("show commands").lower()
        _type_and_confirm(second, second_client, "print 0xb22ce002", "b22ce002")
        second.cont_nowait()
        started = time.monotonic()
        second.close()
        assert time.monotonic() - started < 5.0
    finally:
        second.close()
        second_client.close()

    final_history = history.read_text().lower()
    assert "print 0xa11ce001" in final_history
    assert "print 0xb22ce002" in final_history
