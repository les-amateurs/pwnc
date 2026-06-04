"""Optional, pluggable interactive gdb console for a DAP session.

mi hard-coded the ``kitty`` terminal and blocked forever if it never produced a
tty (review finding H9). Here the terminal is configurable — a ``console`` argv
passed to ``debug()``/``attach()``, ``$PWNC_DAP_TERMINAL``, or an autodetected
fallback — entirely optional (headless by default), and the tty handshake has a
timeout so it can never hang the caller.
"""

import os
import select
import shlex
import shutil
import subprocess
import tempfile
import time


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


def _read_tty(fifo, timeout):
    """Read the tty path the spawned terminal writes into *fifo* (with timeout)."""
    fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    try:
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            ready, _, _ = select.select([fd], [], [], max(0.0, remaining))
            if fd not in ready:
                continue
            chunk = os.read(fd, 256)
            if not chunk:
                if buf:
                    break
                time.sleep(0.05)        # writer not open yet
                continue
            buf += chunk
            if b"\n" in buf:
                break
        line = buf.split(b"\n", 1)[0].decode("utf-8", "replace").strip()
        return line or None
    finally:
        os.close(fd)


def start_console(gdb, terminal=None, timeout=10):
    """Spawn a terminal and attach a gdb console UI to it via ``new-ui``.

    Returns the terminal subprocess (so the caller can kill it on close).
    """
    argv = _terminal_argv(terminal)
    tmpdir = tempfile.mkdtemp()
    fifo = os.path.join(tmpdir, "tty")
    os.mkfifo(fifo)

    sh = "tty > %s; exec sleep infinity < /dev/null > /dev/null 2>&1" % fifo
    proc = subprocess.Popen(argv + ["sh", "-c", sh])
    try:
        tty_path = _read_tty(fifo, timeout)
    finally:
        try:
            os.unlink(fifo)
            os.rmdir(tmpdir)
        except OSError:
            pass

    if not tty_path:
        proc.kill()
        raise RuntimeError(
            "console terminal did not report a tty within %ds" % timeout)

    gdb.transport.request(
        "evaluate", {"expression": "new-ui console %s" % tty_path, "context": "repl"})
    return proc
