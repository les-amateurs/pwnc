"""Event-driven SIGWINCH relay for a borrowed target TTY.

This helper is intentionally standalone.  It receives a validated TTY fd and
a notification-pipe fd from the parent, then either joins a foreground process
group in its inherited session or claims an otherwise unowned PTY as its
controlling terminal.  Kernel SIGWINCH delivery is reduced to one nonblocking
pipe byte; there is no timer or geometry scan.
"""

from __future__ import annotations

import fcntl
import os
import select
import signal
import sys
import termios


def _notify(fd: int, value: bytes) -> None:
    try:
        os.write(fd, value)
    except (BlockingIOError, OSError):
        pass


def _join_or_claim_foreground(tty_fd: int) -> bool:
    """Arrange for this process to receive the target TTY's SIGWINCH."""

    try:
        foreground = os.tcgetpgrp(tty_fd)
    except OSError:
        foreground = 0

    if foreground > 0:
        try:
            if os.getsid(foreground) != os.getsid(0):
                return False
            if os.getpgrp() != foreground:
                os.setpgid(0, foreground)
            return True
        except (OSError, ProcessLookupError):
            return False

    # An unowned PTY can safely become this helper's controlling terminal.
    # Ignore job-control output stops only around the foreground transition.
    previous_ttou = signal.getsignal(signal.SIGTTOU)
    try:
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        os.setsid()
        fcntl.ioctl(tty_fd, termios.TIOCSCTTY, 0)
        os.tcsetpgrp(tty_fd, os.getpgrp())
        return True
    except OSError:
        return False
    finally:
        signal.signal(signal.SIGTTOU, previous_ttou)


def main(argv=None) -> int:
    values = sys.argv[1:] if argv is None else list(argv)
    if len(values) != 2:
        return 2
    try:
        tty_fd, notify_fd = map(int, values)
        if not os.isatty(tty_fd):
            return 2
        os.set_blocking(notify_fd, False)
    except (OSError, TypeError, ValueError):
        return 2

    stop_r, stop_w = os.pipe()
    os.set_blocking(stop_r, False)
    os.set_blocking(stop_w, False)

    def resized(_signum, _frame):
        _notify(notify_fd, b"W")

    def stop(_signum, _frame):
        _notify(stop_w, b"Q")

    signal.signal(signal.SIGWINCH, resized)
    signal.signal(signal.SIGTERM, stop)
    # Joining an interactive foreground group must not make terminal keystrokes
    # kill or suspend this notification-only helper.
    for signum in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP, signal.SIGTTIN):
        signal.signal(signum, signal.SIG_IGN)

    if not _join_or_claim_foreground(tty_fd):
        _notify(notify_fd, b"U")
        return 3

    _notify(notify_fd, b"R")
    try:
        # A self-pipe closes the check-then-signal race inherent in
        # ``while not stopping: signal.pause()``. A TERM received before this
        # blocking call leaves a byte ready; one received during it wakes the
        # kernel poll immediately.
        poller = select.poll()
        poller.register(stop_r, select.POLLIN | select.POLLHUP | select.POLLERR)
        poller.poll()
        return 0
    finally:
        os.close(stop_r)
        os.close(stop_w)


if __name__ == "__main__":
    raise SystemExit(main())
