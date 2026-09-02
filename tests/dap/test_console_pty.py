"""Real-GDB coverage for the public borrowed-console modes.

These tests intentionally go through ``Gdb.console``.  They do not recreate
``pwncNewUI`` or terminal resize forwarding in test-side scaffolding: the only
test helper is the terminal itself (a PTY master/slave pair).
"""

from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import termios
import time
from contextlib import contextmanager

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import ConsoleConfig, ConsoleMode, launch, start


TIMEOUT = 15.0
GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")


def _has_command(command: str) -> bool:
    if os.sep in command:
        return os.path.isfile(command) and os.access(command, os.X_OK)
    return shutil.which(command) is not None


pytestmark = pytest.mark.skipif(
    not _has_command(GDB_PATH) or shutil.which("gcc") is None,
    reason="gdb and gcc are required",
)


def _eventually(get_value, predicate, timeout: float = TIMEOUT):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = get_value()
        if predicate(last):
            return last
        time.sleep(0.05)
    assert predicate(last), last


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _reported_width(terminal) -> int | None:
    terminal.write(b"show width\n")
    output = terminal.expect(b"(gdb)")
    match = re.search(rb"(?:line is|width is)\s+(\d+)", output)
    return int(match.group(1)) if match else None


@contextmanager
def _stdin_from(fd: int):
    """Temporarily make a PTY the actual current stdin for ``current()``."""
    saved = os.dup(0)
    try:
        os.dup2(fd, 0)
        yield
    finally:
        os.dup2(saved, 0)
        os.close(saved)


class _TestTerminal:
    def __init__(self, rows: int = 40, cols: int = 123):
        self.master, self.slave = pty.openpty()
        self.tty = os.ttyname(self.slave)
        self._buffer = bytearray()
        _set_winsize(self.master, rows, cols)

    def write(self, data: bytes) -> None:
        os.write(self.master, data)

    def expect(self, marker: bytes, timeout: float = TIMEOUT) -> bytes:
        deadline = time.monotonic() + timeout
        while marker not in self._buffer and time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if self.master not in ready:
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError:
                break
            if not data:
                break
            self._buffer.extend(data)
        assert marker in self._buffer, bytes(self._buffer)
        end = self._buffer.index(marker) + len(marker)
        result = bytes(self._buffer[:end])
        del self._buffer[:end]
        return result

    def resize(self, rows: int, cols: int) -> None:
        _set_winsize(self.master, rows, cols)

    def close(self) -> None:
        for fd in (self.master, self.slave):
            if fd < 0:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
        self.master = self.slave = -1


@pytest.fixture
def inferior(tmp_path):
    source = tmp_path / "borrowed-console.c"
    binary = tmp_path / "borrowed-console"
    source.write_text(
        "volatile int counter = 41;\n"
        "__attribute__((noinline)) void ping(void) { counter++; }\n"
        "int main(void) {\n"
        "  for (int i = 0; i < 100000; i++) {\n"
        "    ping();\n"
        "    for (volatile int j = 0; j < 3000; j++) {}\n"
        "  }\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["gcc", "-g", "-O0", "-no-pie", "-o", os.fspath(binary), os.fspath(source)],
        check=True,
    )
    return binary


def _open_borrowed(gdb, terminal: _TestTerminal, mode: ConsoleMode):
    if mode is ConsoleMode.CURRENT:
        # Exercise the default fd=0 contract, rather than passing the slave as
        # an explicit stand-in for the current terminal.
        with _stdin_from(terminal.slave):
            return gdb.console(ConsoleConfig.current(save_history=False))
    return gdb.console(ConsoleConfig.target(terminal.tty, save_history=False))


def test_startup_output_is_replayed_before_prompt_without_allocation_notice(inferior):
    gdb = launch(os.fspath(inferior), gdb_path=GDB_PATH, init=False)
    terminal = _TestTerminal()
    try:
        # Exercise both paths native DAP uses before a CLI UI exists: captured
        # repl results and raw fd-1 output events.
        gdb.execute("echo PWNC_REPL_STARTUP\\n")
        gdb.execute(
            'python import os; os.write(1, b"PWNC_RAW_STARTUP\\n")'
        )
        gdb.console(
            ConsoleConfig.target(terminal.tty, save_history=False)
        )
        output = terminal.expect(b"(gdb)").replace(b"\r", b"")

        assert output.index(b"PWNC_REPL_STARTUP") < output.index(b"(gdb)")
        assert output.index(b"PWNC_RAW_STARTUP") < output.index(b"(gdb)")
        assert b"New UI allocated" not in output

        terminal.write(b"echo PWNC_AFTER_ATTACH\n")
        later = terminal.expect(b"(gdb)").replace(b"\r", b"")
        assert b"PWNC_AFTER_ATTACH" in later
        assert b"PWNC_REPL_STARTUP" not in later
        assert b"PWNC_RAW_STARTUP" not in later
        assert b"New UI allocated" not in later
    finally:
        gdb.close()
        terminal.close()


def test_gdbinit_logs_and_errors_are_replayed_before_first_prompt(tmp_path):
    home = tmp_path / "gdb-home"
    home.mkdir()
    (home / ".gdbinit").write_text(
        "echo PWNC_GDBINIT_LOG\\n\n"
        "python print('PWNC_GDBINIT_PYTHON')\n"
        "python raise RuntimeError('PWNC_GDBINIT_ERROR')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["HOME"] = os.fspath(home)
    gdb = start(gdb_path=GDB_PATH, env=environment, init=True)
    terminal = _TestTerminal()
    try:
        gdb.console(ConsoleConfig.target(terminal.tty, save_history=False))
        output = terminal.expect(b"(gdb)").replace(b"\r", b"")
        prompt = output.index(b"(gdb)")
        assert output.index(b"PWNC_GDBINIT_LOG") < prompt
        assert output.index(b"PWNC_GDBINIT_PYTHON") < prompt
        assert output.index(b"PWNC_GDBINIT_ERROR") < prompt
        assert b"New UI allocated" not in output
    finally:
        gdb.close()
        terminal.close()


@pytest.mark.parametrize("mode", [ConsoleMode.CURRENT, ConsoleMode.TARGET])
def test_public_borrowed_console_interleaves_with_dap_and_tracks_size(inferior, mode):
    gdb = launch(os.fspath(inferior), gdb_path=GDB_PATH, init=False)
    terminal = _TestTerminal(rows=40, cols=123)
    handle = None
    try:
        handle = _open_borrowed(gdb, terminal, mode)
        assert handle.mode is mode
        assert os.path.samefile(handle.tty, terminal.tty)
        assert not handle.detachable
        terminal.expect(b"(gdb)")
        assert (
            _eventually(lambda: _reported_width(terminal), lambda width: width == 123)
            == 123
        )

        # A command entered through the borrowed console is immediately
        # observable through the DAP controller.
        terminal.write(b"set variable counter = 77\n")
        terminal.expect(b"(gdb)")
        assert gdb.eval("counter") == 77

        # A DAP-installed callback fires when the user resumes from the CLI.
        hits = []

        def on_ping(session):
            hits.append(int(session.reg.rip))
            return False

        gdb.bp("ping", callback=on_ping)
        terminal.write(b"continue\n")
        stop = gdb.wait(timeout=TIMEOUT)
        assert stop.get("reason") == "breakpoint", stop
        assert hits
        terminal.expect(b"(gdb)")

        # Control can alternate in either direction after the same stop.
        before = int(gdb.reg.rip)
        terminal.write(b"stepi\n")
        gdb.wait(timeout=TIMEOUT)
        assert int(gdb.reg.rip) != before
        terminal.expect(b"(gdb)")
        before = int(gdb.reg.rip)
        gdb.stepi(timeout=TIMEOUT)
        assert int(gdb.reg.rip) != before

        # Resizes are observed by the production borrowed-TTY watcher and are
        # synchronously visible to subsequent script-side commands.
        terminal.resize(52, 171)
        assert (
            _eventually(lambda: _reported_width(terminal), lambda width: width == 171)
            == 171
        )

        # GDB cannot remove a borrowed new-ui.  The public lifecycle reports
        # that fact without losing control of the still-live debugger.
        with pytest.raises(RuntimeError, match="borrowed"):
            gdb.console_close()
        assert gdb.eval("counter") >= 77
    finally:
        gdb.close()
        terminal.close()
