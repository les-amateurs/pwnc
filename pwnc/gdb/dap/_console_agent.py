"""In-window agent for the interactive gdb console (runs inside the terminal).

`console.py` launches the terminal as ``<terminal> -e python3 _console_agent.py
<unix-socket> [--keep-open]``. The agent runs as the terminal pty's *foreground*
process, which is the only thing that receives the window's ``SIGWINCH`` — gdb
attaches to the pty by path and would never see resizes. The agent therefore:

  * reports its tty path + initial size to the driving script (over the socket),
    so the script can ``new-ui console <tty>`` and set gdb's width/height;
  * on ``SIGWINCH`` re-reports the new size (→ gdb width/height, for plugins);
  * detaches its own stdio from the pty so it never competes with gdb for the
    terminal's input/output;
  * stays alive (keeping the window open) until the socket closes — i.e. gdb /
    the session exited — then exits so the window auto-closes, unless
    ``--keep-open`` was given, in which case it waits for a keypress first.

Pure stdlib; imports nothing from pwnc.
"""

import fcntl
import json
import os
import signal
import socket
import struct
import sys
import termios


def _winsize(fd):
    try:
        data = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\x00" * 8)
        rows, cols, _xp, _yp = struct.unpack("HHHH", data)
        return rows, cols
    except OSError:
        return 0, 0


def main(argv):
    keep_open = "--keep-open" in argv
    positional = [a for a in argv if not a.startswith("-")]
    if not positional:
        return 2
    sock_path = positional[0]

    # Keep a private fd to the terminal pty (a dup of stdout) for size ioctls and
    # the keep-open message, then point our own stdio at /dev/null so we never
    # read/write the pty that gdb owns.
    try:
        pty_fd = os.dup(1)
        tty_path = os.ttyname(pty_fd)
    except OSError:
        return 2

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
    except OSError:
        return 1

    def send(obj):
        try:
            sock.sendall((json.dumps(obj) + "\n").encode())
        except OSError:
            pass

    rows, cols = _winsize(pty_fd)
    send({"type": "init", "tty": tty_path, "rows": rows, "cols": cols})

    def on_winch(_signum, _frame):
        r, c = _winsize(pty_fd)
        send({"type": "winsize", "rows": r, "cols": c})

    signal.signal(signal.SIGWINCH, on_winch)

    # detach stdio from the pty (gdb owns input/output)
    try:
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        os.close(devnull)
    except OSError:
        pass

    # Block until the driver closes the socket (gdb/session gone). SIGWINCH
    # interrupts recv() to run on_winch, then recv() auto-resumes (PEP 475).
    try:
        while True:
            if not sock.recv(4096):
                break
    except OSError:
        pass

    if keep_open:
        try:
            os.write(pty_fd, b"\r\n[gdb exited \xe2\x80\x94 press Enter to close]\r\n")
            os.read(pty_fd, 1)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
