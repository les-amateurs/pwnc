"""Deterministic tests for the production DAP console endpoint and bridge."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pty
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import console as console_module
from pwnc.gdb.dap import _console_bridge as bridge_module
from pwnc.gdb.dap.console import (
    ArgvTerminalLauncher,
    ConsoleConfig,
    ConsoleMode,
    ViewerConfig,
    open_console,
)


TIMEOUT = 10.0
GEF_PATH = Path(os.environ.get("PWNC_TEST_GEF", "/home/ctf/bata24-gef/gef.py"))
GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")


def _eventually(predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate()


def _read_fd(fd, marker, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    output = bytearray()
    while marker not in output and time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if fd not in ready:
            continue
        try:
            output.extend(os.read(fd, 65536))
        except OSError:
            break
    assert marker in output, bytes(output)
    return bytes(output)


def _read_fd_markers(fd, markers, timeout=TIMEOUT):
    markers = tuple(markers)
    deadline = time.monotonic() + timeout
    output = bytearray()
    while not all(marker in output for marker in markers) and time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if fd not in ready:
            continue
        try:
            output.extend(os.read(fd, 65536))
        except OSError:
            break
    assert all(marker in output for marker in markers), bytes(output)
    return bytes(output)


class _FakeTransport:
    """Act like pwncNewUI by really opening the reported PTY slave."""

    def __init__(self):
        self.requests = []
        self.ui_fd = None
        self._lock = threading.Lock()

    def request(self, command, arguments):
        with self._lock:
            self.requests.append((command, dict(arguments)))
        if command == "pwncNewUI":
            self.ui_fd = os.open(arguments["tty"], os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            tty.setraw(self.ui_fd)
        return {}

    def sizes(self):
        with self._lock:
            return [(args["rows"], args["cols"]) for command, args in self.requests if command == "pwncSetWinsize"]

    def close(self):
        if self.ui_fd is not None:
            os.close(self.ui_fd)
            self.ui_fd = None


class _FakeGdb:
    def __init__(self):
        self.transport = _FakeTransport()


class _StartupTranscriptTransport(_FakeTransport):
    def __init__(self, output, *, fail_attach=False):
        super().__init__()
        self.output = output
        self.fail_attach = fail_attach
        self.claims = 0
        self.restored = []

    def claim_startup_output(self, timeout):
        assert timeout > 0
        self.claims += 1
        output, self.output = self.output, ""
        return output

    def restore_startup_output(self, output):
        self.restored.append(output)
        self.output = output + self.output

    def request(self, command, arguments):
        if command == "pwncNewUI" and self.fail_attach:
            raise RuntimeError("synthetic new-ui failure")
        return super().request(command, arguments)


class _BridgeClient:
    def __init__(self, handle, token=None, size=None):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(TIMEOUT)
        self.socket.connect(handle._broker.socket_path)
        hello_fields = {
            "version": console_module._PROTOCOL_VERSION,
            "token": handle._broker.token if token is None else token,
            "session": handle.session_id,
        }
        if size is not None:
            hello_fields.update({"rows": size[0], "cols": size[1]})
        hello = json.dumps(hello_fields).encode()
        self.socket.sendall(console_module._pack_frame(console_module._FRAME_HELLO, hello))
        self.buffer = bytearray()

    def send_input(self, data):
        self.socket.sendall(console_module._pack_frame(console_module._FRAME_INPUT, data))

    def output(self, marker, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        output = bytearray()
        while marker not in output and time.monotonic() < deadline:
            data = self.socket.recv(65536)
            assert data
            self.buffer.extend(data)
            for frame_type, payload in console_module._extract_frames(self.buffer):
                if frame_type == console_module._FRAME_OUTPUT:
                    output.extend(payload)
                elif frame_type == console_module._FRAME_CLOSE:
                    pytest.fail("broker closed before expected output")
        assert marker in output, bytes(output)
        return bytes(output)

    def close(self):
        self.socket.close()


class _PtyLauncher:
    def __init__(self):
        self.master, self.slave = pty.openpty()
        self.proc = None

    def spawn(self, argv):
        self.proc = subprocess.Popen(
            list(argv),
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            close_fds=True,
        )
        return self.proc

    def close(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=3)
        for fd in (self.master, self.slave):
            try:
                os.close(fd)
            except OSError:
                pass


def test_config_and_shell_free_launcher_contract(monkeypatch):
    assert ConsoleConfig.none().mode is ConsoleMode.NONE
    assert ConsoleConfig.current().tty == 0
    assert ConsoleConfig.target("/dev/tty").mode is ConsoleMode.TARGET
    assert ConsoleConfig.owned().viewer is None
    with pytest.raises(ValueError, match="backlog_bytes"):
        ConsoleConfig.owned(backlog_bytes=console_module._MAX_FRAME_BYTES + 1)
    with pytest.raises(TypeError, match="initial_rows"):
        ConsoleConfig.owned(initial_size=(1.5, 80))
    with pytest.raises(TypeError, match="initial_cols"):
        ConsoleConfig.owned(initial_size=(24, True))

    pending = bytearray(bridge_module._MAX_PENDING_BYTES)
    with pytest.raises(BufferError, match="terminal queue"):
        bridge_module._queue(pending, b"x", "terminal")

    launcher = ArgvTerminalLauncher(["terminal", "--", "{command}"])
    assert launcher.command(["python", "bridge.py"]) == [
        "terminal",
        "--",
        "python",
        "bridge.py",
    ]
    assert ArgvTerminalLauncher(["terminal", "-e"]).command(["bridge"]) == [
        "terminal",
        "-e",
        "bridge",
    ]

    gdb = _FakeGdb()
    monkeypatch.setattr(
        console_module.pty,
        "openpty",
        lambda: pytest.fail("none mode allocated a PTY"),
    )
    assert open_console(gdb, ConsoleConfig.none()) is None
    assert not gdb.transport.requests


def test_owned_broker_constructor_unwinds_partial_resources(monkeypatch):
    opened = []
    real_openpty = console_module.pty.openpty

    def record_openpty():
        descriptors = real_openpty()
        opened.extend(descriptors)
        return descriptors

    def fail_winsize(*_args):
        raise OSError("injected winsize failure")

    monkeypatch.setattr(console_module.pty, "openpty", record_openpty)
    monkeypatch.setattr(console_module, "_set_winsize", fail_winsize)
    with pytest.raises(OSError, match="injected winsize failure"):
        open_console(_FakeGdb(), ConsoleConfig.owned())
    assert len(opened) == 2
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_owned_broker_start_failure_preserves_error_and_cleans_up(monkeypatch):
    gdb = _FakeGdb()
    resize_worker = console_module._LatestResizeWorker(gdb)
    broker = console_module._OwnedPtyBroker(
        resize_worker.submit,
        initial_size=(24, 80),
        backlog_bytes=16,
    )
    socket_path = broker.socket_path
    master_fd = broker.master_fd
    slave_fd = broker._slave_fd

    def fail_start(_thread):
        raise RuntimeError("injected broker thread start failure")

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    try:
        with pytest.raises(RuntimeError, match="injected broker thread start failure"):
            broker.start()
        assert broker._thread is None
        assert not broker.alive
        assert not os.path.exists(socket_path)
        for fd in (master_fd, slave_fd):
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        resize_worker.close()


def test_borrowed_target_is_validated_and_never_closed():
    master, slave = pty.openpty()
    import fcntl

    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 37, 143, 0, 0))
    gdb = _FakeGdb()
    handle = open_console(gdb, ConsoleConfig.target(slave))
    try:
        assert handle.mode is ConsoleMode.TARGET
        assert isinstance(handle._watcher, console_module._BorrowedResizeWatcher)
        assert not handle.detachable
        assert os.path.samefile(handle.tty, os.ttyname(slave))
        assert gdb.transport.requests[:2] == [
            ("pwncSetWinsize", {"rows": 37, "cols": 143}),
            (
                "pwncNewUI",
                {"tty": os.ttyname(slave), "save_history": True},
            ),
        ]
        os.fstat(slave)
        with pytest.raises(RuntimeError, match="borrowed"):
            handle.dispose_endpoint()
    finally:
        handle.close()
        # GDB cannot detach a borrowed UI, so close() deliberately retains its
        # watcher until session cleanup.
        os.fstat(slave)
        handle._dispose_resources(force_viewer=False)
        gdb.transport.close()

    current_gdb = _FakeGdb()
    current = open_console(current_gdb, ConsoleConfig.current(slave))
    try:
        assert current.mode is ConsoleMode.CURRENT
        assert os.path.samefile(current.tty, os.ttyname(slave))
    finally:
        current.close()
        os.fstat(slave)
        current._dispose_resources(force_viewer=False)
        current_gdb.transport.close()
        os.close(master)
        os.close(slave)

    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(ValueError, match="not a tty"):
            open_console(_FakeGdb(), ConsoleConfig.target(read_fd))
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_console_passes_claimed_startup_output_to_new_ui_once():
    master, slave = pty.openpty()
    gdb = _FakeGdb()
    gdb.transport = _StartupTranscriptTransport(
        "bata24 initialized\nbata24 warning\n"
    )
    handle = None
    try:
        handle = open_console(gdb, ConsoleConfig.target(slave))
        assert gdb.transport.claims == 1
        assert gdb.transport.restored == []
        assert gdb.transport.requests[-1] == (
            "pwncNewUI",
            {
                "tty": os.ttyname(slave),
                "save_history": True,
                "startup_output": "bata24 initialized\nbata24 warning\n",
            },
        )
    finally:
        if handle is not None:
            handle.close()
            handle._dispose_resources(force_viewer=False)
        gdb.transport.close()
        os.close(master)
        os.close(slave)


def test_failed_new_ui_restores_claimed_startup_output_for_retry():
    master, slave = pty.openpty()
    gdb = _FakeGdb()
    gdb.transport = _StartupTranscriptTransport(
        "startup failure details\n",
        fail_attach=True,
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic new-ui failure"):
            open_console(gdb, ConsoleConfig.target(slave))
        assert gdb.transport.claims == 1
        assert gdb.transport.restored == ["startup failure details\n"]
        assert gdb.transport.output == "startup failure details\n"
    finally:
        gdb.transport.close()
        os.close(master)
        os.close(slave)


@pytest.mark.parametrize("inside", [1, 2, 3, 4])
def test_retained_terminal_suffix_never_starts_inside_csi(inside):
    prefix = b"already rendered: "
    sequence = b"\x1b[36m"
    tail = b"-----\x1b[0m\n"
    stream = prefix + sequence + tail
    cut = len(prefix) + inside
    retained = bridge_module._ansi_safe_suffix(stream, len(stream) - cut)

    assert len(retained) <= len(stream) - cut
    assert retained == tail
    assert not retained.startswith(b"36m")


def test_owned_broker_streams_split_ansi_without_a_carry_buffer():
    broker = console_module._OwnedPtyBroker(
        lambda _rows, _cols: None,
        initial_size=(24, 80),
        backlog_bytes=4096,
    )
    tty.setraw(broker._slave_fd)
    broker.start()
    try:
        os.write(broker._slave_fd, b"gef> \x1b[")
        _eventually(lambda: bytes(broker._backlog) == b"gef> \x1b[")

        os.write(broker._slave_fd, b"36m-----\x1b[0m\n")
        expected = b"gef> \x1b[36m-----\x1b[0m\n"
        _eventually(lambda: bytes(broker._backlog) == expected)
    finally:
        broker.close()


def test_owned_broker_backlog_trimming_drops_whole_csi_and_resets_replay():
    broker = console_module._OwnedPtyBroker(
        lambda _rows, _cols: None,
        initial_size=(24, 80),
        backlog_bytes=12,
    )
    try:
        stream = b"old\x1b[36m-----\x1b[0m\n"
        broker._remember(stream)
        retained = bytes(broker._backlog)

        assert len(retained) <= 12
        assert broker._backlog_truncated
        assert not retained.startswith(b"36m")
        assert retained == b"-----\x1b[0m\n"
    finally:
        broker.close()


def test_standalone_bridge_drains_split_ansi_output_before_remote_close(tmp_path):
    socket_path = tmp_path / "split-ansi.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(socket_path))
    listener.listen(1)
    launcher = _PtyLauncher()
    expected = b"before \x1b[38;5;196mred\x1b[0m after\r\n"
    errors = []

    def serve():
        conn = None
        try:
            conn, _address = listener.accept()
            incoming = bytearray()
            while True:
                data = conn.recv(65536)
                assert data
                incoming.extend(data)
                if list(bridge_module._frames(incoming)):
                    break
            wire = b"".join(
                [
                    bridge_module._frame(bridge_module._FRAME_OUTPUT, b"before \x1b[38;5;"),
                    bridge_module._frame(bridge_module._FRAME_OUTPUT, b"196mred\x1b["),
                    bridge_module._frame(bridge_module._FRAME_OUTPUT, b"0m after\r\n"),
                    bridge_module._frame(bridge_module._FRAME_CLOSE),
                ]
            )
            conn.sendall(wire)
        except BaseException as error:  # noqa: BLE001 - relay server-thread failure
            errors.append(error)
        finally:
            if conn is not None:
                conn.close()
            listener.close()

    server = threading.Thread(target=serve, name="split-ansi-server")
    server.start()
    try:
        launcher.spawn(
            [
                sys.executable,
                os.fspath(Path(bridge_module.__file__)),
                os.fspath(socket_path),
                "--token=test-token",
                "--session=test-session",
            ]
        )
        assert launcher.proc.wait(timeout=TIMEOUT) == 0
        server.join(TIMEOUT)
        assert not server.is_alive()
        assert errors == []

        output = bytearray()
        while select.select([launcher.master], [], [], 0)[0]:
            try:
                output.extend(os.read(launcher.master, 65536))
            except OSError:
                break
        assert expected in output
    finally:
        launcher.close()
        server.join(TIMEOUT)
        listener.close()


def test_standalone_bridge_reports_stale_socket_actionably(tmp_path):
    socket_path = tmp_path / "stale.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(os.fspath(socket_path))
    stale.close()
    launcher = _PtyLauncher()
    try:
        launcher.spawn(
            [
                sys.executable,
                os.fspath(Path(bridge_module.__file__)),
                os.fspath(socket_path),
            ]
        )
        assert launcher.proc.wait(timeout=TIMEOUT) == 1
        output = _read_fd(launcher.master, b"discovery entry may be stale")
        assert os.fsencode(socket_path) in output
        assert b"socket refused the connection" in output
        assert b"pool manager may have exited" in output
        assert b"[Errno" not in output
    finally:
        launcher.close()


def test_current_resize_watchers_share_sigwinch_and_restore_handler(monkeypatch):
    # Isolate the process-global relay so this test can assert exact chaining
    # and restoration without depending on another console test's lifetime.
    relay = console_module._SigwinchRelay()
    monkeypatch.setattr(console_module, "_SIGWINCH_RELAY", relay)
    original_handler = signal.getsignal(signal.SIGWINCH)
    chained = []

    def previous_handler(signum, _frame):
        chained.append(signum)

    signal.signal(signal.SIGWINCH, previous_handler)
    first_master, first_slave = pty.openpty()
    second_master, second_slave = pty.openpty()
    first_sizes = []
    second_sizes = []
    first = second = None
    try:
        console_module._set_winsize(first_master, 24, 80)
        console_module._set_winsize(second_master, 31, 100)
        first = console_module._CurrentResizeWatcher(
            os.dup(first_slave),
            lambda rows, cols: first_sizes.append((rows, cols)),
            lambda: pytest.fail("first tty unexpectedly hung up"),
        )
        second = console_module._CurrentResizeWatcher(
            os.dup(second_slave),
            lambda rows, cols: second_sizes.append((rows, cols)),
            lambda: pytest.fail("second tty unexpectedly hung up"),
        )

        console_module._set_winsize(first_master, 47, 151)
        console_module._set_winsize(second_master, 53, 173)
        os.kill(os.getpid(), signal.SIGWINCH)
        _eventually(lambda: first_sizes == [(47, 151)])
        _eventually(lambda: second_sizes == [(53, 173)])
        assert chained

        first.close()
        first = None
        assert signal.getsignal(signal.SIGWINCH) is relay._handler
        console_module._set_winsize(second_master, 61, 181)
        os.kill(os.getpid(), signal.SIGWINCH)
        _eventually(lambda: second_sizes[-1:] == [(61, 181)])

        second.close()
        second = None
        assert signal.getsignal(signal.SIGWINCH) is previous_handler
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()
        signal.signal(signal.SIGWINCH, original_handler)
        for fd in (first_master, first_slave, second_master, second_slave):
            os.close(fd)


def test_foreground_current_console_selects_event_driven_resize(monkeypatch):
    relay = console_module._SigwinchRelay()
    monkeypatch.setattr(console_module, "_SIGWINCH_RELAY", relay)
    monkeypatch.setattr(console_module, "_is_foreground_process_tty", lambda _fd: True)
    master, slave = pty.openpty()
    gdb = _FakeGdb()
    handle = None
    try:
        console_module._set_winsize(master, 37, 143)
        handle = open_console(gdb, ConsoleConfig.current(slave))
        assert isinstance(handle._watcher, console_module._CurrentResizeWatcher)

        console_module._set_winsize(master, 49, 157)
        os.kill(os.getpid(), signal.SIGWINCH)
        _eventually(lambda: gdb.transport.sizes()[-1:] == [(49, 157)])
    finally:
        if handle is not None:
            handle._dispose_resources(force_viewer=False)
        gdb.transport.close()
        os.close(master)
        os.close(slave)


def test_owned_broker_only_times_selector_for_authentication_deadline(monkeypatch):
    broker = console_module._OwnedPtyBroker(
        lambda _rows, _cols: None,
        initial_size=(24, 80),
        backlog_bytes=16,
    )
    peer = None
    try:
        assert broker._authentication_timeout() is None

        client, peer = socket.socketpair()
        broker._client = client
        broker._client_deadline = 105.0
        monkeypatch.setattr(console_module.time, "monotonic", lambda: 100.25)
        assert broker._authentication_timeout() == pytest.approx(4.75)

        broker._client_authenticated = True
        assert broker._authentication_timeout() is None
        broker._client_authenticated = False
        broker._client_deadline = 99.0
        assert broker._authentication_timeout() == 0.0
    finally:
        broker.close()
        if peer is not None:
            peer.close()


def test_owned_broker_is_binary_safe_and_reconnectable():
    gdb = _FakeGdb()
    handle = open_console(
        gdb,
        ConsoleConfig.owned(initial_size=(31, 119), backlog_bytes=4096),
    )
    first = None
    second = None
    try:
        assert gdb.transport.requests[:2] == [
            ("pwncSetWinsize", {"rows": 31, "cols": 119}),
            (
                "pwncNewUI",
                {"tty": handle.tty, "save_history": True},
            ),
        ]

        malformed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        malformed.connect(handle._broker.socket_path)
        malformed.sendall(console_module._pack_frame(console_module._FRAME_HELLO, b"[]"))
        malformed.shutdown(socket.SHUT_WR)
        malformed.settimeout(TIMEOUT)
        assert malformed.recv(1) == b""
        malformed.close()
        _eventually(lambda: handle.endpoint_alive and not handle.viewer_connected)

        first = _BridgeClient(handle)
        _eventually(lambda: handle.viewer_connected)

        payload = b"prompt:\x00\xff\n"
        os.write(gdb.transport.ui_fd, payload)
        assert payload in first.output(payload)

        first.send_input(b"show width\n")
        assert b"show width\n" in _read_fd(gdb.transport.ui_fd, b"show width\n")
        first.close()
        first = None
        _eventually(lambda: not handle.viewer_connected)

        # GDB's endpoint remains live with no viewer, and the broker drains it
        # into bounded backlog rather than allowing the PTY to block.
        os.write(gdb.transport.ui_fd, b"while-disconnected\n")
        second = _BridgeClient(handle)
        assert b"while-disconnected" in second.output(b"while-disconnected")
        _eventually(lambda: handle.viewer_connected)
        assert handle.endpoint_alive
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()
        handle.dispose_endpoint()
        assert not handle.endpoint_alive
        assert not os.path.exists(handle._broker.socket_path)
        gdb.transport.close()


def test_tiny_history_backlog_does_not_throttle_live_io():
    gdb = _FakeGdb()
    handle = open_console(gdb, ConsoleConfig.owned(backlog_bytes=1))
    client = _BridgeClient(handle)
    try:
        _eventually(lambda: handle.viewer_connected)
        inbound = b"input-is-much-larger-than-history\n"
        client.send_input(inbound)
        assert inbound in _read_fd(gdb.transport.ui_fd, inbound)

        outbound = b"output-is-also-much-larger-than-history\n"
        os.write(gdb.transport.ui_fd, outbound)
        assert outbound in client.output(outbound)
        assert handle.viewer_connected
        assert handle._broker._live_queue_limit >= console_module._MAX_FRAME_BYTES
    finally:
        client.close()
        handle.dispose_endpoint()
        gdb.transport.close()


def test_owned_initial_and_reconnect_sizes_are_synchronous_and_precede_new_ui():
    import fcntl

    gdb = _FakeGdb()
    first = _PtyLauncher()
    fcntl.ioctl(
        first.master,
        termios.TIOCSWINSZ,
        struct.pack("HHHH", 41, 137, 0, 0),
    )
    second = None
    handle = open_console(
        gdb,
        ConsoleConfig.owned(
            viewer=ViewerConfig.external(first),
            initial_size=(24, 80),
        ),
        timeout=TIMEOUT,
    )
    try:
        commands = [command for command, _arguments in gdb.transport.requests]
        new_ui_index = commands.index("pwncNewUI")
        assert (
            "pwncSetWinsize",
            {"rows": 41, "cols": 137},
        ) in gdb.transport.requests[:new_ui_index]
        assert handle._broker.current_size == (41, 137)

        first.proc.terminate()
        first.proc.wait(timeout=3)
        _eventually(lambda: not handle.viewer_connected)

        second = _PtyLauncher()
        fcntl.ioctl(
            second.master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", 53, 173, 0, 0),
        )
        handle.attach_viewer(ViewerConfig.external(second), timeout=TIMEOUT)
        # No polling: attach_viewer must not return before DAP observes the
        # reconnecting viewer's HELLO geometry.
        assert gdb.transport.sizes()[-1] == (53, 173)
        assert handle._broker.current_size == (53, 173)
    finally:
        handle.dispose_endpoint()
        first.close()
        if second is not None:
            second.close()
        gdb.transport.close()


def test_standalone_bridge_forwards_io_resize_and_reconnects(monkeypatch):
    # URL-safe credentials can legitimately start with '-'.  The launcher must
    # pass them as --token=value so argparse does not consume them as options.
    monkeypatch.setattr(console_module.secrets, "token_urlsafe", lambda _size: "-token")
    gdb = _FakeGdb()
    first = _PtyLauncher()
    second = None
    handle = open_console(
        gdb,
        ConsoleConfig.owned(viewer=ViewerConfig.external(first)),
        timeout=TIMEOUT,
    )
    try:
        assert handle.proc is first.proc
        assert handle.viewer_connected
        os.write(gdb.transport.ui_fd, b"first-viewer")
        assert b"first-viewer" in _read_fd(first.master, b"first-viewer")
        os.write(first.master, b"continue\n")
        assert b"continue\n" in _read_fd(gdb.transport.ui_fd, b"continue\n")

        import fcntl

        fcntl.ioctl(first.master, termios.TIOCSWINSZ, struct.pack("HHHH", 47, 151, 0, 0))
        os.kill(first.proc.pid, signal.SIGWINCH)
        _eventually(lambda: (47, 151) in gdb.transport.sizes())

        first.proc.terminate()
        first.proc.wait(timeout=3)
        _eventually(lambda: not handle.viewer_connected)
        assert handle.endpoint_alive

        second = _PtyLauncher()
        handle.attach_viewer(ViewerConfig.external(second), timeout=TIMEOUT)
        assert handle.proc is second.proc
        os.write(gdb.transport.ui_fd, b"second-viewer")
        assert b"second-viewer" in _read_fd(second.master, b"second-viewer")
    finally:
        handle.dispose_endpoint()
        if second is not None and second.proc is not None:
            second.proc.wait(timeout=3)
        first.close()
        if second is not None:
            second.close()
        gdb.transport.close()


def test_graceful_force_close_restores_bridge_terminal_mode():
    gdb = _FakeGdb()
    launcher = _PtyLauncher()
    before = termios.tcgetattr(launcher.slave)
    handle = open_console(
        gdb,
        ConsoleConfig.owned(viewer=ViewerConfig.external(launcher)),
        timeout=TIMEOUT,
    )
    try:
        _eventually(lambda: termios.tcgetattr(launcher.slave) != before)
        handle.kill()
        assert launcher.proc.wait(timeout=3) is not None
        assert termios.tcgetattr(launcher.slave) == before
    finally:
        handle.dispose_endpoint()
        launcher.close()
        gdb.transport.close()


def test_endpoint_disposal_reaps_stopped_viewer_unless_keep_open():
    gdb = _FakeGdb()
    stopped = _PtyLauncher()
    handle = open_console(
        gdb,
        ConsoleConfig.owned(viewer=ViewerConfig.external(stopped)),
        timeout=TIMEOUT,
    )
    os.kill(stopped.proc.pid, signal.SIGSTOP)
    started = time.monotonic()
    handle.dispose_endpoint()
    assert time.monotonic() - started < 5.0
    assert stopped.proc.poll() is not None
    stopped.close()
    gdb.transport.close()

    keep_gdb = _FakeGdb()
    kept = _PtyLauncher()
    keep_handle = open_console(
        keep_gdb,
        ConsoleConfig.owned(
            viewer=ViewerConfig.external(kept, keep_open=True),
        ),
        timeout=TIMEOUT,
    )
    try:
        keep_handle.dispose_endpoint()
        time.sleep(0.1)
        assert kept.proc.poll() is None
        keep_handle.kill()
        assert kept.proc.poll() is not None
    finally:
        kept.close()
        keep_gdb.transport.close()


def test_current_viewer_parent_restores_terminal_after_sigkill():
    # Exercise the actual ViewerConfig.current() parent/child relationship in a
    # subprocess whose fd 0/1 are a real PTY.  SIGKILL prevents the standalone
    # bridge from running its finally block; Console.close() must still restore
    # the termios copy captured by the parent.
    script = r"""
import os, signal, sys, termios, time, tty
from pwnc.gdb.dap.console import ConsoleConfig, ViewerConfig, open_console

class Transport:
    def __init__(self):
        self.ui_fd = None
    def request(self, command, arguments):
        if command == "pwncNewUI":
            self.ui_fd = os.open(arguments["tty"], os.O_RDWR | os.O_NOCTTY)
            tty.setraw(self.ui_fd)
        return {}

class Gdb:
    def __init__(self):
        self.transport = Transport()

gdb = Gdb()
before = termios.tcgetattr(0)
before_blocking = (os.get_blocking(0), os.get_blocking(1))
handle = open_console(
    gdb,
    ConsoleConfig.owned(viewer=ViewerConfig.current()),
    timeout=5.0,
)
deadline = time.monotonic() + 5.0
while termios.tcgetattr(0) == before and time.monotonic() < deadline:
    time.sleep(0.01)
assert termios.tcgetattr(0) != before
handle.proc.kill()
handle.proc.wait(timeout=2.0)
handle.close()
assert termios.tcgetattr(0) == before
assert (os.get_blocking(0), os.get_blocking(1)) == before_blocking
handle.dispose_endpoint()
os.close(gdb.transport.ui_fd)
gdb.transport.ui_fd = None

keep = open_console(
    gdb,
    ConsoleConfig.owned(viewer=ViewerConfig.current(keep_open=True)),
    timeout=5.0,
)
deadline = time.monotonic() + 5.0
while termios.tcgetattr(0) == before and time.monotonic() < deadline:
    time.sleep(0.01)
assert termios.tcgetattr(0) != before
os.kill(keep.proc.pid, signal.SIGSTOP)
keep.dispose_endpoint()
assert termios.tcgetattr(0) == before
assert (os.get_blocking(0), os.get_blocking(1)) == before_blocking
keep.kill()
assert keep.proc.poll() is not None
os.close(gdb.transport.ui_fd)
"""
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=Path(__file__).parents[2],
        close_fds=True,
    )
    os.close(slave)
    try:
        code = proc.wait(timeout=15.0)
        output = bytearray()
        while True:
            ready, _, _ = select.select([master], [], [], 0)
            if master not in ready:
                break
            try:
                output.extend(os.read(master, 65536))
            except OSError:
                break
        assert code == 0, bytes(output)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2.0)
        os.close(master)


def test_terminal_restore_is_complete_before_a_racing_close_returns():
    console = console_module.Console(
        mode=ConsoleMode.OWNED,
        tty="/dev/null",
        gdb=object(),
        config=ConsoleConfig.owned(),
        resize_worker=None,
    )
    proc = object()
    restore_entered = threading.Event()
    allow_restore = threading.Event()
    restore_complete = threading.Event()

    class BlockingSnapshot:
        def restore(self):
            restore_entered.set()
            assert allow_restore.wait(TIMEOUT)
            restore_complete.set()

    console._viewer_terminal_state = (proc, BlockingSnapshot())
    monitor = threading.Thread(target=console._restore_viewer_terminal, args=(proc,))
    monitor.start()
    assert restore_entered.wait(TIMEOUT)

    close_returned = threading.Event()

    def racing_close():
        console._restore_viewer_terminal(proc)
        close_returned.set()

    closer = threading.Thread(target=racing_close)
    closer.start()
    assert not close_returned.wait(0.1)
    allow_restore.set()
    monitor.join(TIMEOUT)
    closer.join(TIMEOUT)

    assert not monitor.is_alive()
    assert not closer.is_alive()
    assert restore_complete.is_set()
    assert close_returned.is_set()


def test_public_console_reconnects_owned_viewer_and_rejects_replacement():
    from pwnc.gdb.dap import Gdb

    controller = object.__new__(Gdb)
    controller.transport = _FakeTransport()
    controller._closed = False
    controller._console = None
    controller._console_lock = threading.RLock()
    first = _PtyLauncher()
    second = None
    third = None
    handle = Gdb.console(
        controller,
        ConsoleConfig.owned(viewer=ViewerConfig.external(first)),
        timeout=TIMEOUT,
    )
    try:
        first.proc.terminate()
        first.proc.wait(timeout=3.0)
        _eventually(lambda: not handle.viewer_connected)

        second = _PtyLauncher()
        reconnected = Gdb.console(
            controller,
            ConsoleConfig.owned(viewer=ViewerConfig.external(second)),
            timeout=TIMEOUT,
        )
        assert reconnected is handle
        assert handle.proc is second.proc
        assert handle.viewer_connected

        third = _PtyLauncher()
        with pytest.raises(ValueError, match="different console viewer"):
            Gdb.console(
                controller,
                ConsoleConfig.owned(viewer=ViewerConfig.external(third)),
                timeout=TIMEOUT,
            )
        with pytest.raises(ValueError, match="none mode"):
            Gdb.console(controller, ConsoleConfig.none(), timeout=TIMEOUT)
    finally:
        handle.dispose_endpoint()
        first.close()
        if second is not None:
            second.close()
        if third is not None:
            third.close()
        controller.transport.close()


def test_public_borrowed_console_cleanup_never_duplicates_gdb_ui():
    from pwnc.gdb.dap import Gdb

    controller = object.__new__(Gdb)
    controller.transport = _FakeTransport()
    controller._closed = False
    controller._console = None
    controller._console_lock = threading.RLock()
    master, slave = pty.openpty()
    config = ConsoleConfig.target(slave)
    handle = Gdb.console(controller, config)
    try:
        handle.close()
        assert handle.endpoint_alive
        assert Gdb.console(controller, config) is handle
        assert sum(command == "pwncNewUI" for command, _arguments in controller.transport.requests) == 1
        with pytest.raises(ValueError, match="already uses target mode"):
            Gdb.console(controller, ConsoleConfig.owned())
    finally:
        controller._closed = True
        handle._dispose_resources(force_viewer=False)
        controller.transport.close()
        os.close(master)
        os.close(slave)


def test_borrowed_tty_hangup_marks_endpoint_lost_and_allows_replacement():
    from pwnc.gdb.dap import Gdb

    controller = object.__new__(Gdb)
    controller.transport = _FakeTransport()
    controller._closed = False
    controller._console = None
    controller._console_lock = threading.RLock()
    first_master, first_slave = pty.openpty()
    second_master = second_slave = -1
    first = Gdb.console(controller, ConsoleConfig.target(first_slave))
    try:
        first.close()
        assert first.endpoint_alive
        os.close(first_master)
        first_master = -1
        os.close(first_slave)
        first_slave = -1
        _eventually(lambda: not first.endpoint_alive)

        # Mirror GDB's secondary-ui HUP cleanup before asking pwnc to create a
        # replacement on a different borrowed terminal.
        os.close(controller.transport.ui_fd)
        controller.transport.ui_fd = None
        second_master, second_slave = pty.openpty()
        replacement = Gdb.console(
            controller,
            ConsoleConfig.target(second_slave),
        )
        assert replacement is not first
        assert replacement.endpoint_alive
        assert sum(command == "pwncNewUI" for command, _arguments in controller.transport.requests) == 2
    finally:
        controller._closed = True
        if controller._console is not None:
            controller._console._dispose_resources(force_viewer=False)
        controller.transport.close()
        for fd in (first_master, first_slave, second_master, second_slave):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


@pytest.mark.skipif(not shutil.which("gdb") or not shutil.which("gcc"), reason="gdb and gcc required")
def test_live_gdb_uses_production_owned_console(tmp_path):
    source = tmp_path / "console.c"
    binary = tmp_path / "console"
    source.write_text(
        "void ping(void){} int main(void){ for(int i=0;i<100000;i++){"
        "ping(); for(volatile int j=0;j<3000;j++); } return 0; }\n"
    )
    subprocess.run(["gcc", "-g", "-O0", "-no-pie", "-o", str(binary), str(source)], check=True)

    from pwnc.gdb.dap import launch

    gdb = launch(str(binary), gdb_path=GDB_PATH, init=False)
    launcher = _PtyLauncher()
    handle = None
    try:
        # This travels through Gdb.console -> start_console -> open_console.
        handle = gdb.console(
            ConsoleConfig.owned(viewer=ViewerConfig.external(launcher), initial_size=(35, 127)),
            timeout=TIMEOUT,
        )
        _read_fd(launcher.master, b"(gdb)")
        os.write(launcher.master, b"show width\n")
        shown = _read_fd(launcher.master, b"(gdb)")
        assert b"127" in shown

        hits = []

        def callback(session):
            hits.append(int(session.reg.rip))
            return False

        gdb.bp("ping", callback=callback)
        os.write(launcher.master, b"continue\n")
        stop = gdb.wait(timeout=TIMEOUT)
        assert stop.get("reason") == "breakpoint"
        assert hits
    finally:
        gdb.close()
        if handle is not None and handle.proc is not None:
            handle.proc.wait(timeout=3)
        launcher.close()


@pytest.mark.skipif(not shutil.which("gdb") or not shutil.which("gcc"), reason="gdb and gcc required")
def test_owned_console_drains_large_plugin_prompt_during_new_ui(tmp_path):
    source = tmp_path / "large-prompt.c"
    binary = tmp_path / "large-prompt"
    source.write_text("int main(void){ return 0; }\n")
    subprocess.run(["gcc", "-g", "-o", str(binary), str(source)], check=True)

    from pwnc.gdb.dap import launch

    gdb = launch(str(binary), gdb_path=GDB_PATH, init=False)
    handle = None
    try:
        # A plugin prompt hook runs synchronously while GDB creates the new UI.
        # One MiB is much larger than a typical PTY kernel buffer, so opening
        # the drain lane after pwncNewUI would deadlock before its DAP response.
        gdb.execute("python import gdb; gdb.prompt_hook = lambda current: 'P' * (1024 * 1024)")
        started = time.monotonic()
        handle = gdb.console(ConsoleConfig.owned())
        assert time.monotonic() - started < 5.0
        assert handle.endpoint_alive
    finally:
        gdb.close()


@pytest.mark.skipif(not shutil.which("gdb"), reason="gdb required")
def test_live_owned_bridge_streams_csi_split_across_gdb_writes():
    from pwnc.gdb.dap import start

    gdb = start(gdb_path=GDB_PATH, init=False)
    launcher = _PtyLauncher()
    handle = None
    try:
        handle = gdb.console(
            ConsoleConfig.owned(viewer=ViewerConfig.external(launcher)),
            timeout=TIMEOUT,
        )
        _read_fd(launcher.master, b"(gdb)")

        gdb.execute(
            'python import os; os.write(1, b"gef> " + bytes((27, 91)))'
        )
        first = _read_fd(launcher.master, b"gef> \x1b[")
        gdb.execute(
            'python import os; os.write(1, b"36m-----" + '
            'bytes((27, 91)) + b"0m" + bytes((10,)))'
        )
        output = first + _read_fd(launcher.master, b"\x1b[0m\r\n")

        assert b"gef> \x1b[36m-----\x1b[0m\r\n" in output
        assert b"gef> 36m-----" not in output
    finally:
        gdb.close()
        if handle is not None and handle.proc is not None:
            handle.proc.wait(timeout=3)
        launcher.close()


@pytest.mark.skipif(not shutil.which("gdb"), reason="gdb required")
def test_owned_console_redirects_gef_loaded_as_an_imported_module():
    """Match wrappers which import GEF instead of sourcing it into __main__."""
    from pwnc.gdb.dap import start

    gdb = start(gdb_path=GDB_PATH, init=False)
    launcher = _PtyLauncher()
    handle = None
    module_source = (
        "settings = {'context.redirect': ''}\n"
        "class Config:\n"
        "    @staticmethod\n"
        "    def set_gef_setting(name, value): settings[name] = value\n"
        "    @staticmethod\n"
        "    def get_gef_setting(name): return settings.get(name)\n"
        "class ContextCommand: pass\n"
    )
    try:
        gdb.execute(
            "python import sys, types; "
            "module = types.ModuleType('bata24'); "
            f"exec({module_source!r}, module.__dict__); "
            "sys.modules['bata24'] = module"
        )
        handle = gdb.console(
            ConsoleConfig.owned(viewer=ViewerConfig.external(launcher)),
            timeout=TIMEOUT,
        )
        _read_fd(launcher.master, b"(gdb)")

        redirect = gdb.execute(
            "python import sys; gdb.write("
            "sys.modules['bata24'].Config.get_gef_setting('context.redirect') "
            "+ '\\n')"
        ).strip()
        assert os.path.samefile(redirect, handle.tty)
    finally:
        gdb.close()
        if handle is not None and handle.proc is not None:
            handle.proc.wait(timeout=3)
        launcher.close()


@pytest.mark.skipif(
    not os.path.isfile(GEF_PATH) or not shutil.which("gdb") or not shutil.which("gcc"),
    reason="exact bata24 GEF, gdb, and gcc required",
)
def test_live_owned_console_runs_unmodified_bata24_gef_through_bridge(tmp_path):
    before = os.stat(GEF_PATH)
    before_bytes = GEF_PATH.read_bytes()
    assert hashlib.sha256(before_bytes).hexdigest() == GEF_SHA256

    source = tmp_path / "gef-console.c"
    binary = tmp_path / "gef-console"
    source.write_text(
        "#include <stdint.h>\n"
        "volatile uint64_t pwnc_console_value = 0x1122334455667788ULL;\n"
        "__attribute__((noinline)) void pwnc_console_marker(void) {\n"
        "    pwnc_console_value ^= 0x10ULL;\n"
        "    __asm__ volatile(\"\" ::: \"memory\");\n"
        "}\n"
        "__attribute__((noinline)) void pwnc_console_after(void) {\n"
        "    pwnc_console_value ^= 0x20ULL;\n"
        "    __asm__ volatile(\"\" ::: \"memory\");\n"
        "}\n"
        "int main(void) {\n"
        "    pwnc_console_marker();\n"
        "    pwnc_console_after();\n"
        "    return (int)(pwnc_console_value & 0);\n"
        "}\n"
    )
    subprocess.run(
        [
            "gcc",
            "-g",
            "-O0",
            "-fno-omit-frame-pointer",
            "-fno-pie",
            "-no-pie",
            "-o",
            str(binary),
            str(source),
        ],
        check=True,
    )

    from pwnc.gdb.dap import launch

    gdb = launch(str(binary), gdb_path=GDB_PATH, init=False)
    launcher = _PtyLauncher()
    rows, cols = 44, 143
    fcntl.ioctl(
        launcher.master,
        termios.TIOCSWINSZ,
        struct.pack("HHHH", rows, cols, 0, 0),
    )
    handle = None
    try:
        handle = gdb.console(
            ConsoleConfig.owned(viewer=ViewerConfig.external(launcher)),
            timeout=TIMEOUT,
        )
        _read_fd(launcher.master, b"(gdb)")
        gdb.execute("source " + str(GEF_PATH))
        gdb.execute("set pagination off")
        gdb.execute("set confirm off")
        gdb.execute("gef config gef.disable_color True")
        gdb.execute("gef config context.clear_screen False")
        gdb.execute('gef config context.layout "regs code"')

        os.write(launcher.master, b"gef version --compact\n")
        output = _read_fd(launcher.master, b"gef>", timeout=20.0)
        assert b"gdb:" in output
        assert b"python:" in output

        # Native DAP owns the original process stdio, but pwnc binds fd 0/1 to
        # the selected console after DAP has saved its protocol descriptors.
        # The exact unmodified GEF therefore observes the viewer geometry rather
        # than its pipe fallback of (600, 100).
        os.write(
            launcher.master,
            b'python print("PWNC_GEF_SIZE", GefUtil.get_terminal_size())\n',
        )
        sized = _read_fd(launcher.master, b"gef>")
        assert ("PWNC_GEF_SIZE (%d, %d)" % (rows, cols)).encode() in sized

        # GEF was intentionally sourced after console creation.  pwnc's
        # event-driven adapter must configure its built-in redirect before
        # GEF's own stop hook, even when execution was driven through DAP.
        gdb.execute("break pwnc_console_marker")
        stopped = gdb.cont(timeout=20.0)
        assert stopped["reason"] == "breakpoint"
        context = _read_fd_markers(
            launcher.master,
            (b"registers", b"code:", b"pwnc_console_marker", b"-" * cols),
            timeout=20.0,
        )
        assert any(line == b"-" * cols for line in context.replace(b"\r", b"").splitlines())
        redirect = gdb.execute(
            "python print(Config.get_gef_setting('context.redirect'))"
        ).strip()
        assert os.path.samefile(redirect, handle.tty)

        # Bata24's execution helpers manipulate raw fd 0/1 themselves.  The
        # compatibility binding must survive that cycle while retaining native
        # DAP's synchronous execution semantics.
        next_ret_result = gdb.execute("next-ret -n", timeout=20.0)
        assert "NoneType" not in next_ret_result
        next_ret_context = _read_fd_markers(
            launcher.master,
            (b"registers", b"code:", b"-" * cols),
            timeout=20.0,
        )
        assert b"\r|" in next_ret_context
        assert "ret" in gdb.execute("x/i $pc").lower()

        os.write(
            launcher.master,
            b'python print("PWNC_GEF_SIZE_AFTER", GefUtil.get_terminal_size())\n',
        )
        sized_after = _read_fd(launcher.master, b"gef>")
        assert ("PWNC_GEF_SIZE_AFTER (%d, %d)" % (rows, cols)).encode() in sized_after

        # Internal stops from next-ret must not poison the next public DAP
        # operation, and structured requests remain usable after stdio binding.
        stepped = gdb.nexti(timeout=20.0)
        assert stepped["reason"] == "step"
        assert isinstance(gdb.eval("pwnc_console_value"), int)
    finally:
        gdb.close()
        if handle is not None and handle.proc is not None:
            handle.proc.wait(timeout=3)
        launcher.close()

    after = os.stat(GEF_PATH)
    after_bytes = GEF_PATH.read_bytes()
    assert hashlib.sha256(after_bytes).hexdigest() == GEF_SHA256
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
