"""Standalone terminal bridge for :mod:`pwnc.gdb.dap.console`.

This file intentionally imports no pwnc modules.  A terminal launcher runs it
with ordinary terminal stdio; it proxies bytes to a stable PTY broker and
forwards terminal resizes.  Disconnecting the bridge never closes the GDB PTY.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import json
import os
import selectors
import signal
import socket
import struct
import sys
import termios
import tty

_PROTOCOL_VERSION = 2
_FRAME_HEADER = struct.Struct("!BI")
_FRAME_HELLO = 1
_FRAME_OUTPUT = 2
_FRAME_INPUT = 3
_FRAME_RESIZE = 4
_FRAME_DETACH = 5
_FRAME_CLOSE = 6
_FRAME_HELLO_ACK = 7
_FRAME_SWITCH_PAUSE = 8
_FRAME_SWITCH_PAUSED = 9
_FRAME_EPOCH_INPUT = 10
_FRAME_EPOCH_RESIZE = 11
_FRAME_SWITCH_RESUME = 12
_FRAME_SWITCH_RESUMED = 13
_EPOCH = struct.Struct("!Q")
_SWITCH = struct.Struct("!QQ")
_MAX_FRAME_BYTES = 4 * 1024 * 1024
_MAX_PENDING_BYTES = 4 * 1024 * 1024
_PR_SET_PDEATHSIG = 1


def _error_reason(error):
    reasons = {
        errno.EMFILE: "this process has too many open files",
        errno.ENFILE: "the system has too many open files",
        errno.ENOMEM: "the system does not have enough memory",
        errno.ENOSPC: "the filesystem has no space available",
    }
    reason = reasons.get(error.errno)
    if reason is not None:
        return reason
    if error.strerror:
        return str(error.strerror).rstrip(".")
    if error.args:
        return str(error.args[-1]).rstrip(".")
    return type(error).__name__


def _connect_error(sock_path, error):
    """Explain a failed Unix-socket connection without leaking bare errno text."""
    endpoint = repr(os.fsdecode(sock_path))
    reasons = {
        errno.ENOENT: (
            "the socket does not exist; start the pool manager or verify the "
            "discovered/explicit socket path"
        ),
        errno.ECONNREFUSED: (
            "the socket refused the connection; its discovery entry may be "
            "stale or the pool manager may have exited"
        ),
        errno.EACCES: "permission was denied; check the socket and parent-directory permissions",
        errno.EPERM: "the operation was not permitted; check the socket permissions",
        errno.ENOTSOCK: "the endpoint exists but is not a Unix socket",
        errno.ENAMETOOLONG: "the endpoint path is too long for a Unix socket",
        errno.ETIMEDOUT: "the connection timed out while waiting for the pool manager",
        errno.EAGAIN: "the endpoint cannot accept another connection yet",
    }
    reason = reasons.get(error.errno)
    if reason is None:
        reason = _error_reason(error)
    return ConnectionError(f"cannot connect to GDB console endpoint {endpoint}: {reason}")


def _admission_error(sock_path):
    endpoint = repr(os.fsdecode(sock_path))
    return ConnectionError(
        f"GDB console endpoint {endpoint} closed before protocol admission; "
        "another viewer may already be connected, or the pool manager may be shutting down"
    )


def _frame(frame_type, payload=b""):
    return _FRAME_HEADER.pack(frame_type, len(payload)) + payload


def _frames(buffer):
    while len(buffer) >= _FRAME_HEADER.size:
        frame_type, length = _FRAME_HEADER.unpack(buffer[: _FRAME_HEADER.size])
        if length > _MAX_FRAME_BYTES:
            raise ValueError("bridge frame is too large")
        end = _FRAME_HEADER.size + length
        if len(buffer) < end:
            return
        payload = bytes(buffer[_FRAME_HEADER.size : end])
        del buffer[:end]
        yield frame_type, payload


def _winsize(fd):
    try:
        raw = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, _xp, _yp = struct.unpack("HHHH", raw)
        return int(rows), int(cols)
    except OSError:
        return 0, 0


def _join_or_claim_foreground(fd):
    """Best-effort foreground membership for event-driven target SIGWINCH."""
    try:
        foreground = os.tcgetpgrp(fd)
    except OSError:
        foreground = 0
    if foreground > 0:
        try:
            if os.getsid(foreground) != os.getsid(0):
                return False
            if os.getpgrp() != foreground:
                os.setpgid(0, foreground)
            return True
        except OSError:
            return False

    previous_ttou = signal.getsignal(signal.SIGTTOU)
    try:
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        os.setsid()
        fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
        os.tcsetpgrp(fd, os.getpgrp())
        return True
    except OSError:
        return False
    finally:
        signal.signal(signal.SIGTTOU, previous_ttou)


def _resize_frame(fd):
    rows, cols = _winsize(fd)
    if not rows or not cols:
        return b""
    payload = json.dumps({"rows": rows, "cols": cols}, separators=(",", ":")).encode("ascii")
    return _frame(_FRAME_RESIZE, payload)


def _discard_pending_input(fd):
    """Drop bytes accumulated while a router switch had terminal input paused."""
    try:
        if os.isatty(fd):
            termios.tcflush(fd, termios.TCIFLUSH)
            return
    except OSError:
        # A disappearing terminal is handled by the ordinary read path.  If it
        # is still a usable nonblocking descriptor, the fallback below is safe.
        pass

    # Pipes and other non-TTY fixtures have no tcflush equivalent.  Never risk
    # blocking here: bridge setup makes stdin nonblocking, but verify that fact
    # before draining in case the descriptor rejected the mode change.
    try:
        if os.get_blocking(fd):
            return
    except OSError:
        return
    while True:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            return
        except OSError:
            return
        if not data:
            return


def _set_events(selector, fileobj, data, events):
    try:
        selector.modify(fileobj, events, data)
    except KeyError:
        selector.register(fileobj, events, data)


def _queue(buffer, data, lane):
    if len(buffer) + len(data) > _MAX_PENDING_BYTES:
        raise BufferError("console bridge %s queue exceeded %d bytes" % (lane, _MAX_PENDING_BYTES))
    buffer.extend(data)


def _ansi_sequence_end(data, start):
    """Return the exclusive end of the ESC sequence at *start*, or ``None``."""
    size = len(data)
    index = start + 1
    if index >= size:
        return None
    introducer = data[index]

    if introducer == ord("["):
        # CSI: parameters/intermediates followed by one final byte.
        index += 1
        while index < size:
            value = data[index]
            if 0x40 <= value <= 0x7E:
                return index + 1
            if value == 0x1B:
                # This ESC aborts the malformed CSI and starts a new sequence.
                return index
            if value in (0x18, 0x1A):  # CAN/SUB cancel the sequence.
                return index + 1
            if not 0x20 <= value <= 0x3F:
                # Invalid bytes terminate parser uncertainty; forwarding them
                # preserves the source stream without stalling it.
                return index + 1
            index += 1
        return None

    if introducer in (ord("]"), ord("P"), ord("X"), ord("^"), ord("_")):
        # OSC accepts BEL as well as ST. DCS/SOS/PM/APC use ST. CAN/SUB
        # cancels every control string. Embedded ESC is data unless it is the
        # first half of ST (ESC backslash).
        osc = introducer == ord("]")
        index += 1
        while index < size:
            value = data[index]
            if value in (0x18, 0x1A) or (osc and value == 0x07):
                return index + 1
            if value == 0x1B:
                if index + 1 >= size:
                    return None
                if data[index + 1] == ord("\\"):
                    return index + 2
            index += 1
        return None

    if 0x20 <= introducer <= 0x2F:
        # General ESC sequence: zero or more intermediate bytes and one final
        # byte. Charset selectors such as ESC ( B use this form.
        index += 1
        while index < size and 0x20 <= data[index] <= 0x2F:
            index += 1
        return None if index >= size else index + 1

    # Two-byte Fe/Fp/Fs escapes are already complete. A control or invalid
    # follower also ends uncertainty instead of retaining arbitrary data.
    return index + 1


def _ansi_safe_suffix(data, limit):
    """Return at most *limit* trailing bytes without a partial ANSI prefix."""
    if limit < 0:
        raise ValueError("ANSI suffix limit cannot be negative")
    size = len(data)
    if size <= limit:
        return bytes(data)
    if limit == 0:
        return b""

    cut = size - limit
    cursor = 0
    while cursor < cut:
        start = data.find(b"\x1b", cursor)
        if start < 0 or start >= cut:
            break
        end = _ansi_sequence_end(data, start)
        if end is None:
            # The retained tail would begin inside an unfinished sequence.
            # Drop it instead of exposing its parameters as printable text.
            return b""
        if cut < end:
            cut = end
            break
        cursor = end
    return bytes(data[cut:])


def _arm_supervisor_death(supervisor_pid, wake):
    """Arrange a restoration-capable exit if a Linux supervisor disappears."""
    if supervisor_pid is None or not sys.platform.startswith("linux"):
        return
    if isinstance(supervisor_pid, bool) or supervisor_pid <= 0:
        raise ValueError("supervisor PID must be a positive integer")

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_PDEATHSIG, int(signal.SIGHUP), 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    # PR_SET_PDEATHSIG cannot retroactively report a death between fork/exec and
    # prctl.  The expected PID closes that race without a liveness polling loop.
    if os.getppid() != supervisor_pid:
        wake(signal.SIGHUP, None)


def bridge(
    sock_path,
    keep_open=False,
    target_tty=False,
    reconnect=False,
    *,
    token=None,
    session=None,
    supervisor_pid=None,
):
    if (token is None) != (session is None):
        raise ValueError("token and session must be supplied together")
    routed_viewer = token is None
    stdin_fd, stdout_fd = 0, 1
    saved_termios = None
    saved_blocking = {}
    wake_r, wake_w = os.pipe()
    os.set_blocking(wake_r, False)
    os.set_blocking(wake_w, False)
    stopping = False
    remote_closed = False
    failure = None
    input_epoch = None
    admitted = not routed_viewer
    # The router's HELLO_ACK publishes the current input epoch.  Keep stdin
    # disabled until it arrives so a newly attached bridge can reconnect to an
    # already-selected endpoint without emitting untagged or stale input.
    input_paused = routed_viewer
    paused_switch = None
    last_resumed = None

    def wake(_signum, _frame):
        try:
            os.write(wake_w, bytes((_signum & 0xFF,)))
        except OSError:
            pass

    old_handlers = {}
    for signum in (signal.SIGWINCH, signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, wake)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _arm_supervisor_death(supervisor_pid, wake)
        sock.settimeout(10.0)
        try:
            sock.connect(sock_path)
        except OSError as error:
            raise _connect_error(sock_path, error) from error
        terminal_fd = stdout_fd if os.isatty(stdout_fd) else stdin_fd
        if target_tty and os.isatty(terminal_fd):
            # Dedicated/unowned PTYs can be claimed, while a foreground group
            # in our inherited session can be joined without stealing terminal
            # ownership.  An unrelated controlling session is intentionally
            # left alone; it can still relay SIGWINCH explicitly.
            _join_or_claim_foreground(terminal_fd)
        rows, cols = _winsize(terminal_fd)
        hello_fields = {"version": _PROTOCOL_VERSION}
        if not routed_viewer:
            # Direct per-GDB broker connections retain their private
            # capability.  ViewerRouter downstream connections deliberately do
            # not send or accept these fields.
            hello_fields.update({"token": token, "session": session})
        elif reconnect:
            # Pool failover is a viewer policy.  Omission deliberately means
            # close this viewer when its selected GDB exits.
            hello_fields["reconnect"] = True
        if rows and cols:
            # Protocol negotiation and initial terminal geometry travel in one
            # frame so the router can size the selected PTY before publishing
            # the viewer connection.
            hello_fields.update({"rows": rows, "cols": cols})
        hello = json.dumps(hello_fields, separators=(",", ":")).encode("utf-8")
        if os.isatty(stdin_fd):
            saved_termios = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)
        # Capture every status before changing any of them: stdin/stdout commonly
        # share one underlying terminal open-file description, so toggling fd 0
        # can otherwise make fd 1 appear to have started nonblocking and leave
        # keep-open's final read spuriously returning EAGAIN.
        for fd in (stdin_fd, stdout_fd):
            try:
                saved_blocking[fd] = os.get_blocking(fd)
            except OSError:
                pass
        for fd in saved_blocking:
            try:
                os.set_blocking(fd, False)
            except OSError:
                pass

        # HELLO is the parent's startup barrier.  Send it only after terminal
        # mutation is complete, so a later parent-side recovery cannot race a
        # bridge which has not yet applied raw/nonblocking state.
        sock.sendall(_frame(_FRAME_HELLO, hello))
        sock.setblocking(False)

        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ, "socket")
        selector.register(wake_r, selectors.EVENT_READ, "signal")
        socket_in = bytearray()
        socket_out = bytearray()
        terminal_out = bytearray()

        while not stopping:
            if remote_closed:
                if not terminal_out:
                    break
                for fileobj in (sock, stdin_fd):
                    try:
                        selector.unregister(fileobj)
                    except (KeyError, ValueError):
                        pass
            else:
                socket_events = selectors.EVENT_READ
                if socket_out:
                    socket_events |= selectors.EVENT_WRITE
                _set_events(selector, sock, "socket", socket_events)

            if input_paused or remote_closed:
                try:
                    selector.unregister(stdin_fd)
                except (KeyError, ValueError):
                    pass
            else:
                _set_events(selector, stdin_fd, "stdin", selectors.EVENT_READ)
            if terminal_out:
                _set_events(selector, stdout_fd, "stdout", selectors.EVENT_WRITE)
            else:
                try:
                    selector.unregister(stdout_fd)
                except (KeyError, ValueError):
                    pass

            for key, mask in selector.select():
                if key.data == "signal":
                    signals = b""
                    try:
                        while True:
                            chunk = os.read(wake_r, 4096)
                            if not chunk:
                                break
                            signals += chunk
                    except (BlockingIOError, OSError):
                        pass
                    if any(value != (signal.SIGWINCH & 0xFF) for value in signals):
                        # Process-directed termination overrides the optional
                        # post-disconnect "press Enter" hold.  Otherwise a
                        # supervised `view(..., keep_open=True)` could receive
                        # SIGTERM successfully and then wait forever for input.
                        keep_open = False
                        stopping = True
                        break
                    # Repeated SIGWINCH notifications are harmlessly coalesced.
                    resize = _resize_frame(stdout_fd if os.isatty(stdout_fd) else stdin_fd)
                    if resize:
                        if input_epoch is None:
                            framed_resize = resize
                        else:
                            _kind, length = _FRAME_HEADER.unpack(resize[: _FRAME_HEADER.size])
                            payload = resize[_FRAME_HEADER.size : _FRAME_HEADER.size + length]
                            framed_resize = _frame(
                                _FRAME_EPOCH_RESIZE,
                                _EPOCH.pack(input_epoch) + payload,
                            )
                        _queue(socket_out, framed_resize, "socket")
                elif key.data == "stdin":
                    # The socket and stdin can both have appeared in one
                    # selector result.  A PAUSE processed earlier in this same
                    # batch must win without consuming another terminal byte.
                    if input_paused:
                        continue
                    try:
                        data = os.read(stdin_fd, 65536)
                    except BlockingIOError:
                        continue
                    except OSError:
                        data = b""
                    if not data:
                        _queue(socket_out, _frame(_FRAME_DETACH), "socket")
                        stopping = True
                        break
                    if input_epoch is None:
                        input_frame = _frame(_FRAME_INPUT, data)
                    else:
                        input_frame = _frame(
                            _FRAME_EPOCH_INPUT,
                            _EPOCH.pack(input_epoch) + data,
                        )
                    _queue(socket_out, input_frame, "socket")
                elif key.data == "stdout":
                    try:
                        count = os.write(stdout_fd, terminal_out)
                    except BlockingIOError:
                        continue
                    except OSError:
                        stopping = True
                        break
                    del terminal_out[:count]
                elif key.data == "socket":
                    if mask & selectors.EVENT_READ:
                        try:
                            data = sock.recv(65536)
                        except BlockingIOError:
                            data = None
                        except OSError:
                            data = b""
                        if data == b"":
                            if not admitted:
                                failure = _admission_error(sock_path)
                            remote_closed = True
                            break
                        if data:
                            socket_in.extend(data)
                            try:
                                incoming = list(_frames(socket_in))
                            except ValueError:
                                failure = ValueError("viewer router sent an invalid protocol frame")
                                stopping = True
                                break
                            for frame_type, payload in incoming:
                                if frame_type == _FRAME_HELLO_ACK:
                                    if not routed_viewer or len(payload) != _EPOCH.size or input_epoch is not None:
                                        failure = ValueError("viewer router sent an invalid protocol admission")
                                        stopping = True
                                        break
                                    _discard_pending_input(stdin_fd)
                                    input_epoch = _EPOCH.unpack(payload)[0]
                                    input_paused = False
                                    admitted = True
                                elif not admitted:
                                    failure = ConnectionError(
                                        "viewer router rejected the connection before protocol admission"
                                    )
                                    stopping = True
                                    break
                                elif frame_type == _FRAME_OUTPUT:
                                    _queue(terminal_out, payload, "terminal")
                                elif frame_type == _FRAME_SWITCH_PAUSE:
                                    if len(payload) != _SWITCH.size:
                                        stopping = True
                                        break
                                    switch_id, _new_epoch = _SWITCH.unpack(payload)
                                    if paused_switch not in (None, switch_id):
                                        stopping = True
                                        break
                                    input_paused = True
                                    paused_switch = switch_id
                                    # PAUSED follows every old-epoch input frame
                                    # already queued in this direction.  stdin
                                    # remains disabled until a matching RESUME.
                                    _queue(
                                        socket_out,
                                        _frame(_FRAME_SWITCH_PAUSED, payload),
                                        "socket",
                                    )
                                elif frame_type == _FRAME_SWITCH_RESUME:
                                    if len(payload) != _SWITCH.size:
                                        stopping = True
                                        break
                                    switch_id, epoch = _SWITCH.unpack(payload)
                                    if paused_switch == switch_id:
                                        # Bytes already framed before PAUSED
                                        # retain the old epoch.  Bytes typed
                                        # after that barrier accumulated in the
                                        # terminal while stdin was unregistered;
                                        # discard them before installing the new
                                        # epoch so they can never spill into the
                                        # replacement GDB.
                                        _discard_pending_input(stdin_fd)
                                        input_epoch = epoch
                                        input_paused = False
                                        paused_switch = None
                                        last_resumed = (switch_id, epoch)
                                    elif last_resumed is not None and last_resumed[0] == switch_id:
                                        # A timeout/candidate failure can race a
                                        # just-sent commit RESUME.  A corrective
                                        # RESUME for the same transaction safely
                                        # restores the old epoch; any intervening
                                        # new-epoch input is rejected by the
                                        # router until commit is acknowledged.
                                        _discard_pending_input(stdin_fd)
                                        input_epoch = epoch
                                        input_paused = False
                                        last_resumed = (switch_id, epoch)
                                    else:
                                        stopping = True
                                        break
                                    # Queue the acknowledgement before stdin is
                                    # re-enabled in the next selector turn.  New
                                    # epoch input is therefore ordered after it.
                                    _queue(
                                        socket_out,
                                        _frame(_FRAME_SWITCH_RESUMED, payload),
                                        "socket",
                                    )
                                elif frame_type == _FRAME_CLOSE:
                                    remote_closed = True
                                    break
                                else:
                                    failure = ValueError("viewer router sent an unexpected protocol frame")
                                    stopping = True
                                    break
                    if mask & selectors.EVENT_WRITE and socket_out:
                        try:
                            count = sock.send(socket_out)
                        except BlockingIOError:
                            continue
                        except OSError:
                            if not admitted:
                                failure = _admission_error(sock_path)
                            stopping = True
                            break
                        del socket_out[:count]
                if stopping or remote_closed:
                    break
        selector.close()
    finally:
        try:
            sock.close()
        except OSError:
            pass
        if saved_termios is not None:
            try:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved_termios)
            except OSError:
                pass
        for fd, value in saved_blocking.items():
            try:
                os.set_blocking(fd, value)
            except OSError:
                pass
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        for fd in (wake_r, wake_w):
            try:
                os.close(fd)
            except OSError:
                pass

    if failure is not None:
        raise failure
    if keep_open and os.isatty(stdout_fd):
        try:
            os.write(stdout_fd, b"\r\n[gdb console closed - press Enter to exit]\r\n")
            os.read(stdin_fd, 1)
        except OSError:
            pass
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="bridge a terminal to a pwnc GDB PTY")
    parser.add_argument("socket")
    # These options are only for the private per-GDB PTY broker.  A durable
    # ViewerRouter never puts either value on its child argv or wire HELLO.
    parser.add_argument("--token")
    parser.add_argument("--session")
    parser.add_argument("--keep-open", action="store_true")
    parser.add_argument(
        "--reconnect",
        action="store_true",
        help="keep this viewer open and select a warm GDB after the current GDB exits",
    )
    parser.add_argument("--target-tty", action="store_true")
    parser.add_argument("--supervisor-pid", type=int)
    args = parser.parse_args(argv)
    try:
        return bridge(
            args.socket,
            args.keep_open,
            args.target_tty,
            args.reconnect,
            token=args.token,
            session=args.session,
            supervisor_pid=args.supervisor_pid,
        )
    except OSError as error:
        try:
            sys.stderr.write(f"pwnc console bridge: {_error_reason(error)}\n")
        except OSError:
            pass
        return 1
    except (BufferError, ValueError) as error:
        try:
            sys.stderr.write("pwnc console bridge: %s\n" % error)
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
