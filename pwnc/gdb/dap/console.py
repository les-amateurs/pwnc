"""Optional, pluggable interactive gdb console for a DAP session.

Spawns a terminal window (default kitty, or `$PWNC_DAP_TERMINAL` / a `console=`
argv) running `_console_agent.py`, which reports its tty over a unix socket; the
driver then attaches a gdb CLI UI to it (`new-ui console <tty>`). The agent also
relays the window size (initial + on SIGWINCH) so gdb's width-aware plugins
render correctly, since gdb — attached by tty path — never sees the resize.

The terminal uses the ambient `$DISPLAY`; this module never references Xvfb
(that's only the headless test harness). The handshake is timeout-bounded so it
can never hang the caller.
"""

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading


_FALLBACK_TERMINALS = [
    ["kitty", "-e"],
    ["gnome-terminal", "--"],
    ["konsole", "-e"],
    ["xterm", "-e"],
    ["x-terminal-emulator", "-e"],
]


def _terminal_argv(terminal):
    if terminal:
        return shlex.split(terminal) if isinstance(terminal, str) else list(terminal)
    env = os.environ.get("PWNC_DAP_TERMINAL")
    if env:
        return shlex.split(env)
    for cand in _FALLBACK_TERMINALS:
        if shutil.which(cand[0]):
            return cand
    raise RuntimeError(
        "no terminal found; pass console=[...], set $PWNC_DAP_TERMINAL, "
        "or keep headless=True")


def _recv_line(conn, buf):
    """Read one newline-terminated line; returns (line_bytes_or_None, leftover)."""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, buf            # EOF
        buf += chunk
    line, _, rest = buf.partition(b"\n")
    return line, rest


class Console:
    """Handle for a running console window + its agent side channel."""

    def __init__(self, proc, server, conn, tty, keep_open, sock_path, tmpdir):
        self.proc = proc
        self.tty = tty
        self.keep_open = keep_open
        self._server = server
        self._conn = conn
        self._sock_path = sock_path
        self._tmpdir = tmpdir
        self._closed = False

    def alive(self):
        return self.proc.poll() is None

    def close(self):
        """Drop the side channel. The agent sees EOF and exits (closing the
        window) — or, if ``keep_open``, leaves the window up."""
        if self._closed:
            return
        self._closed = True
        for s in (self._conn, self._server):
            # shutdown() forces the FIN (so the agent sees EOF and exits) even
            # though the resize thread is blocked in recv() on this socket; a
            # plain close() would not, leaving the agent — and the window — up.
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        try:
            os.unlink(self._sock_path)
        except OSError:
            pass
        try:
            os.rmdir(self._tmpdir)
        except OSError:
            pass

    def kill(self):
        """Force the window closed now, regardless of ``keep_open``."""
        try:
            self.proc.kill()
            self.proc.wait(timeout=3)
        except Exception:
            pass
        self.close()


def start_console(gdb, terminal=None, timeout=10, keep_open=False):
    """Open a terminal, attach a gdb console UI to it, return a `Console`."""
    argv = _terminal_argv(terminal)
    tmpdir = tempfile.mkdtemp(prefix="pwnc-console-")
    sock_path = os.path.join(tmpdir, "agent.sock")

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    server.settimeout(timeout)

    agent = os.path.join(os.path.dirname(__file__), "_console_agent.py")
    cmd = list(argv) + [sys.executable, agent, sock_path]
    if keep_open:
        cmd.append("--keep-open")
    proc = subprocess.Popen(cmd)

    def _fail(msg):
        try:
            proc.kill()
        except Exception:
            pass
        try:
            server.close()
        except OSError:
            pass
        for p in (sock_path,):
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass
        raise RuntimeError(msg)

    try:
        conn, _ = server.accept()
    except (socket.timeout, OSError):
        _fail("console terminal did not connect within %ds" % timeout)

    conn.settimeout(timeout)
    try:
        line, buf = _recv_line(conn, b"")
        init = json.loads(line) if line else None
    except (OSError, ValueError):
        init = None
    if not init or "tty" not in init:
        try:
            conn.close()
        except OSError:
            pass
        _fail("console agent did not report a tty within %ds" % timeout)
    conn.settimeout(None)

    gdb.transport.request("pwncNewUI", {"tty": init["tty"]})
    rows, cols = init.get("rows", 0), init.get("cols", 0)
    if rows and cols:
        gdb.transport.request("pwncSetWinsize", {"rows": rows, "cols": cols})

    # forward window resizes (SIGWINCH in the agent) to gdb's width/height
    def _resize_loop(leftover):
        b = leftover
        while True:
            try:
                line2, b = _recv_line(conn, b)
            except OSError:
                return
            if line2 is None:
                return                  # agent gone
            try:
                msg = json.loads(line2)
            except ValueError:
                continue
            if msg.get("type") == "winsize" and msg.get("rows") and msg.get("cols"):
                try:
                    gdb.transport.request(
                        "pwncSetWinsize", {"rows": msg["rows"], "cols": msg["cols"]})
                except Exception:
                    return

    threading.Thread(target=_resize_loop, args=(buf,), daemon=True).start()
    return Console(proc, server, conn, init["tty"], keep_open, sock_path, tmpdir)
