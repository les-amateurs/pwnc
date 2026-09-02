"""Focused tests for the persistent console viewer router."""

from __future__ import annotations

import fcntl
import json
import os
import pty
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty

import pytest

from pwnc.gdb.dap import console as console_module
from pwnc.gdb.dap.console import (
    _FRAME_CLOSE,
    _FRAME_EPOCH_INPUT,
    _FRAME_HELLO,
    _FRAME_HELLO_ACK,
    _FRAME_OUTPUT,
    _FRAME_SWITCH_PAUSE,
    _FRAME_SWITCH_PAUSED,
    _FRAME_SWITCH_RESUME,
    _FRAME_SWITCH_RESUMED,
    _PROTOCOL_VERSION,
    ConsoleConfig,
    ViewerConfig,
    ViewerMode,
    _extract_frames,
    _pack_frame,
    open_console,
)
from pwnc.gdb.dap.viewer import ViewerRouter

TIMEOUT = 10.0
_EPOCH = struct.Struct("!Q")
_SWITCH = struct.Struct("!QQ")


def _read(fd, marker, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    output = bytearray()
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError((marker, bytes(output)))
        ready, _, _ = select.select([fd], [], [], remaining)
        if fd not in ready:
            continue
        try:
            output.extend(os.read(fd, 65536))
        except OSError:
            break
    assert marker in output, bytes(output)
    return bytes(output)


class _Transport:
    def __init__(self):
        self.ui_fd = None
        self.requests = []
        self._condition = threading.Condition()

    def request(self, command, arguments, timeout=None):
        with self._condition:
            self.requests.append((command, dict(arguments)))
            self._condition.notify_all()
        if command == "pwncNewUI":
            self.ui_fd = os.open(arguments["tty"], os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            tty.setraw(self.ui_fd)
        return {}

    def wait_size(self, size, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        with self._condition:
            while ("pwncSetWinsize", {"rows": size[0], "cols": size[1]}) not in self.requests:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError((size, self.requests))
                self._condition.wait(remaining)

    def close(self):
        if self.ui_fd is not None:
            os.close(self.ui_fd)
            self.ui_fd = None


class _Gdb:
    def __init__(self):
        self.transport = _Transport()


class _PtyLauncher:
    def __init__(self, size=(41, 137)):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(
            self.master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", size[0], size[1], 0, 0),
        )
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

    def resize(self, rows, cols):
        fcntl.ioctl(
            self.master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, cols, 0, 0),
        )
        os.kill(self.proc.pid, signal.SIGWINCH)

    def close(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=3.0)
        for fd in (self.master, self.slave):
            try:
                os.close(fd)
            except OSError:
                pass


class _ControlledProcess:
    """Small Popen facade for the deterministic protocol peer below."""

    def __init__(self, launcher):
        self._launcher = launcher
        self.pid = -1

    def poll(self):
        return 0 if self._launcher._exited.is_set() else None

    def wait(self, timeout=None):
        if not self._launcher._exited.wait(timeout):
            raise subprocess.TimeoutExpired("controlled-console-bridge", timeout)
        return 0

    def terminate(self):
        self._launcher._shutdown()

    def kill(self):
        self._launcher._shutdown()


class _ControlledLauncher:
    """Protocol-level bridge whose switch acknowledgements are controllable.

    The production bridge is covered by the PTY tests.  This peer makes the
    otherwise tiny timeout and disconnect race windows deterministic without
    adding sleeps or polling to either production code or the tests.
    """

    def __init__(self, size=(41, 137), *, malformed_hello_first=False):
        self.size = size
        self.malformed_hello_first = malformed_hello_first
        self.proc = _ControlledProcess(self)
        self.sock = None
        self._reader_thread = None
        self._send_lock = threading.Lock()
        self._condition = threading.Condition()
        self._exited = threading.Event()
        self._pause_count = 0
        self._resume_count = 0
        self._pause_payloads = {}
        self._held_pauses = {}
        self._hold_pauses = set()
        self._drop_pauses = set()
        self._inject_before_pause = {}
        self.epoch = None
        self.output = bytearray()
        self.argv = None
        self.hello_fields = None

    def spawn(self, argv):
        argv = list(argv)
        self.argv = argv
        if self.malformed_hello_first:
            recursive_json = b"[" * 10_000 + b"0" + b"]" * 10_000
            with pytest.raises(RecursionError):
                json.loads(recursive_json)
            self._reader_thread = threading.Thread(
                target=self._malformed_then_read,
                args=(argv[2], recursive_json),
                name="controlled-console-bridge",
                daemon=True,
            )
            self._reader_thread.start()
            return self.proc

        self.connect(argv[2], reconnect="--reconnect" in argv)
        return self.proc

    def connect(self, socket_path, *, version=_PROTOCOL_VERSION, reconnect=False):
        self._connect_valid(
            socket_path,
            version=version,
            reconnect=reconnect,
        )
        self._reader_thread = threading.Thread(
            target=self._read_loop,
            name="controlled-console-bridge",
            daemon=True,
        )
        self._reader_thread.start()
        return self

    def _malformed_then_read(self, socket_path, recursive_json):
        try:
            malformed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            malformed.settimeout(TIMEOUT)
            malformed.connect(socket_path)
            malformed.sendall(_pack_frame(_FRAME_HELLO, recursive_json))
            assert malformed.recv(1) == b""
            malformed.close()
            self._connect_valid(socket_path)
            self._read_loop()
        except BaseException:
            self._shutdown()

    def _connect_valid(
        self,
        socket_path,
        *,
        version=_PROTOCOL_VERSION,
        reconnect=False,
    ):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(socket_path)
        self.sock = sock
        self.hello_fields = {
            "version": version,
            "rows": self.size[0],
            "cols": self.size[1],
        }
        if reconnect:
            self.hello_fields["reconnect"] = True
        hello = json.dumps(self.hello_fields, separators=(",", ":")).encode("ascii")
        sock.sendall(_pack_frame(_FRAME_HELLO, hello))

    def hold_pause(self, number):
        with self._condition:
            self._hold_pauses.add(number)

    def drop_on_pause(self, number):
        with self._condition:
            self._drop_pauses.add(number)

    def inject_before_pause(self, number, data):
        with self._condition:
            self._inject_before_pause[number] = bytes(data)

    def wait_for_pause(self, number, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._pause_count < number:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError((number, self._pause_count))
                self._condition.wait(remaining)
            return self._pause_payloads[number]

    def wait_epoch(self, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        with self._condition:
            while self.epoch is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError("controlled bridge did not receive its epoch")
                self._condition.wait(remaining)
            return self.epoch

    def send_input(self, data, *, epoch=None):
        selected_epoch = self.epoch if epoch is None else epoch
        assert selected_epoch is not None
        self.send_frame(
            _FRAME_EPOCH_INPUT,
            _EPOCH.pack(selected_epoch) + bytes(data),
        )

    def send_frame(self, frame_type, payload=b""):
        self._send(_pack_frame(frame_type, payload))

    def _send(self, data):
        with self._send_lock:
            sock = self.sock
            if sock is None:
                raise RuntimeError("controlled bridge is disconnected")
            sock.sendall(data)

    def _handle_pause(self, payload):
        switch_id, _new_epoch = _SWITCH.unpack(payload)
        with self._condition:
            self._pause_count += 1
            number = self._pause_count
            self._pause_payloads[number] = payload
            injected = self._inject_before_pause.pop(number, None)
            held = number in self._hold_pauses
            dropped = number in self._drop_pauses
            if held:
                self._held_pauses[switch_id] = payload
            self._condition.notify_all()
        if dropped:
            self._shutdown()
            return False
        frames = bytearray()
        if injected is not None:
            assert self.epoch is not None
            frames.extend(
                _pack_frame(
                    _FRAME_EPOCH_INPUT,
                    _EPOCH.pack(self.epoch) + injected,
                )
            )
        if not held:
            frames.extend(_pack_frame(_FRAME_SWITCH_PAUSED, payload))
        if frames:
            self._send(bytes(frames))
        return True

    def _handle_resume(self, payload):
        switch_id, epoch = _SWITCH.unpack(payload)
        with self._condition:
            self._resume_count += 1
            held = self._held_pauses.pop(switch_id, None)
            self.epoch = epoch
            self._condition.notify_all()
        frames = bytearray()
        if held is not None:
            # Model a PAUSED acknowledgement already ordered ahead of this
            # RESUME but delayed in transit.
            frames.extend(_pack_frame(_FRAME_SWITCH_PAUSED, held))
        frames.extend(_pack_frame(_FRAME_SWITCH_RESUMED, payload))
        self._send(bytes(frames))

    def _read_loop(self):
        incoming = bytearray()
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    return
                incoming.extend(data)
                for frame_type, payload in list(_extract_frames(incoming)):
                    if frame_type == _FRAME_HELLO_ACK:
                        if len(payload) != _EPOCH.size or self.epoch is not None:
                            return
                        with self._condition:
                            self.epoch = _EPOCH.unpack(payload)[0]
                            self._condition.notify_all()
                    elif frame_type == _FRAME_OUTPUT:
                        with self._condition:
                            self.output.extend(payload)
                            self._condition.notify_all()
                    elif frame_type == _FRAME_SWITCH_PAUSE:
                        if len(payload) != _SWITCH.size or not self._handle_pause(payload):
                            return
                    elif frame_type == _FRAME_SWITCH_RESUME:
                        if len(payload) != _SWITCH.size:
                            return
                        self._handle_resume(payload)
                    elif frame_type == _FRAME_CLOSE:
                        return
                    else:
                        raise AssertionError((frame_type, payload))
        except (OSError, RuntimeError):
            pass
        finally:
            self._shutdown()

    def _shutdown(self):
        with self._send_lock:
            sock, self.sock = self.sock, None
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
        self._exited.set()

    def close(self):
        self._shutdown()
        thread = self._reader_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3.0)


class _ConnectionLog:
    def __init__(self):
        self._condition = threading.Condition()
        self.events = []
        self.threads = []

    def __call__(self, connected, reason):
        with self._condition:
            self.events.append((connected, reason))
            self.threads.append(threading.current_thread())
            self._condition.notify_all()

    def wait(self, count, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self.events) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError((count, self.events))
                self._condition.wait(remaining)
            return list(self.events)


def _endpoint(size=(24, 80), backlog=4096):
    gdb = _Gdb()
    endpoint = open_console(
        gdb,
        ConsoleConfig.owned(initial_size=size, backlog_bytes=backlog),
    )
    return gdb, endpoint


def _dispose(gdb, endpoint):
    if endpoint is not None and endpoint.endpoint_alive:
        endpoint.dispose_endpoint()
    gdb.transport.close()


def test_target_viewer_config_normalizes_and_rejects_ambiguous_fields():
    class TtyPath:
        def __fspath__(self):
            return "/dev/pts/example"

    by_fd = ViewerConfig.target(17, keep_open=True, reconnect=True)
    assert by_fd.mode is ViewerMode.TARGET
    assert by_fd.tty == 17
    assert by_fd.launcher is None
    assert by_fd.keep_open
    assert by_fd.reconnect

    by_path = ViewerConfig.target(TtyPath())
    assert by_path.mode is ViewerMode.TARGET
    assert by_path.tty == "/dev/pts/example"
    assert not by_path.reconnect

    with pytest.raises(ValueError, match="requires a tty"):
        ViewerConfig(ViewerMode.TARGET)
    with pytest.raises(ValueError, match="cannot have a launcher"):
        ViewerConfig(ViewerMode.TARGET, launcher=["terminal"], tty=17)
    with pytest.raises(ValueError, match="cannot have a target tty"):
        ViewerConfig(ViewerMode.EXTERNAL, tty=17)
    with pytest.raises(ValueError, match="cannot have a launcher or target tty"):
        ViewerConfig(ViewerMode.CURRENT, tty=17)
    with pytest.raises(TypeError, match="path or file descriptor"):
        ViewerConfig.target(True)
    with pytest.raises(TypeError, match="path or file descriptor"):
        ViewerConfig.target(object())
    with pytest.raises(ValueError, match="cannot be empty"):
        ViewerConfig.target("")


@pytest.mark.parametrize("target_kind", ["fd", "path"])
def test_target_viewer_routes_real_pty_and_parent_restores_after_sigkill(target_kind):
    gdb, endpoint = _endpoint()
    terminal = _PtyLauncher(size=(46, 151))
    before_termios = termios.tcgetattr(terminal.slave)
    before_blocking = os.get_blocking(terminal.slave)
    target = terminal.slave if target_kind == "fd" else os.ttyname(terminal.slave)
    viewer = ViewerRouter(ViewerConfig.target(target)).start()
    closed = False
    try:
        assert viewer.viewer_connected
        assert termios.tcgetattr(terminal.slave) != before_termios

        viewer.switch(endpoint)
        assert endpoint._broker.current_size == (46, 151)
        os.write(gdb.transport.ui_fd, b"target-viewer-output\n")
        _read(terminal.master, b"target-viewer-output")
        os.write(terminal.master, b"target-viewer-input\n")
        _read(gdb.transport.ui_fd, b"target-viewer-input")

        fcntl.ioctl(
            terminal.master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", 58, 183, 0, 0),
        )
        # Target mode makes the bridge an eligible foreground SIGWINCH
        # recipient on this otherwise unowned PTY; no explicit signal relay or
        # periodic size scan is needed.
        gdb.transport.wait_size((58, 183))

        # Prevent the bridge's own finally block from restoring the target.
        # ViewerRouter's parent-side snapshot must cover this failure mode.
        viewer.viewer_process.kill()
        viewer.viewer_process.wait(timeout=3.0)
        viewer.close()
        closed = True
        assert termios.tcgetattr(terminal.slave) == before_termios
        assert os.get_blocking(terminal.slave) == before_blocking
    finally:
        if not closed:
            viewer.close()
        terminal.close()
        _dispose(gdb, endpoint)


def test_owned_console_can_attach_bridge_directly_to_target_tty():
    gdb = _Gdb()
    terminal = _PtyLauncher(size=(44, 147))
    before_termios = termios.tcgetattr(terminal.slave)
    endpoint = open_console(
        gdb,
        ConsoleConfig.owned(
            viewer=ViewerConfig.target(os.ttyname(terminal.slave)),
            initial_size=(24, 80),
        ),
        timeout=TIMEOUT,
    )
    try:
        assert endpoint.viewer_connected
        assert endpoint._broker.current_size == (44, 147)
        os.write(gdb.transport.ui_fd, b"direct-target-output\n")
        _read(terminal.master, b"direct-target-output")
        os.write(terminal.master, b"direct-target-input\n")
        _read(gdb.transport.ui_fd, b"direct-target-input")

        endpoint.detach_viewer(timeout=TIMEOUT)
        assert not endpoint.viewer_connected
        assert termios.tcgetattr(terminal.slave) == before_termios
    finally:
        terminal.close()
        _dispose(gdb, endpoint)


def test_target_viewer_rejects_non_tty_and_unwinds_partial_router():
    viewer = ViewerRouter(ViewerConfig.target(os.devnull))
    with pytest.raises(ValueError, match="not a tty"):
        viewer.start(timeout=1.0)

    assert not viewer.alive
    assert viewer._router_done.is_set()
    assert not viewer._thread.is_alive()
    assert not viewer._loss_thread.is_alive()
    assert not os.path.exists(viewer.socket_path)


def test_borrowed_target_resize_watcher_uses_only_blocking_event_poll(monkeypatch):
    real_poll = console_module.select.poll
    poll_arguments = []

    class RecordingPoll:
        def __init__(self):
            self._poll = real_poll()

        def register(self, *args):
            return self._poll.register(*args)

        def unregister(self, *args):
            return self._poll.unregister(*args)

        def poll(self, *args):
            poll_arguments.append(args)
            return self._poll.poll(*args)

    monkeypatch.setattr(console_module.select, "poll", RecordingPoll)
    master, slave = pty.openpty()
    resized = threading.Event()
    sizes = []
    watcher = console_module._BorrowedResizeWatcher(
        os.dup(slave),
        lambda rows, cols: (sizes.append((rows, cols)), resized.set()),
        lambda: pytest.fail("target TTY unexpectedly hung up"),
    )
    try:
        assert watcher._helper_ready.is_set()
        fcntl.ioctl(
            master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", 54, 177, 0, 0),
        )
        assert resized.wait(TIMEOUT)
        assert sizes[-1] == (54, 177)
    finally:
        watcher.close()
        os.close(master)
        os.close(slave)

    assert poll_arguments
    assert all(arguments == () for arguments in poll_arguments)


def test_borrowed_target_helper_readiness_failure_unwinds_started_thread(
    monkeypatch,
):
    helpers = []

    class SilentHelper:
        def __init__(self, *, pass_fds):
            self._notify = os.dup(pass_fds[1])
            self._status = None
            self.terminated = False

        def poll(self):
            return self._status

        def terminate(self):
            self.terminated = True
            self._status = 0
            os.close(self._notify)
            self._notify = -1

        def kill(self):
            self.terminate()

        def wait(self, timeout=None):
            del timeout
            return self._status

    def silent_popen(_argv, **kwargs):
        helper = SilentHelper(pass_fds=kwargs["pass_fds"])
        helpers.append(helper)
        return helper

    monkeypatch.setattr(console_module.subprocess, "Popen", silent_popen)
    master, slave = pty.openpty()
    watcher_fd = os.dup(slave)
    threads_before = set(threading.enumerate())
    try:
        with pytest.raises(RuntimeError, match="did not become ready"):
            console_module._BorrowedResizeWatcher(
                watcher_fd,
                lambda _rows, _cols: None,
                lambda: None,
            )
    finally:
        os.close(watcher_fd)
        os.close(master)
        os.close(slave)

    assert len(helpers) == 1
    assert helpers[0].terminated
    assert not [thread for thread in threading.enumerate() if thread not in threads_before]


def test_borrowed_target_helper_eof_without_status_is_not_published(monkeypatch):
    class CrashedHelper:
        def __init__(self, *, pass_fds):
            inherited_notify = os.dup(pass_fds[1])
            os.close(inherited_notify)

        def poll(self):
            return 1

        def wait(self, timeout=None):
            del timeout
            return 1

    monkeypatch.setattr(
        console_module.subprocess,
        "Popen",
        lambda _argv, **kwargs: CrashedHelper(pass_fds=kwargs["pass_fds"]),
    )
    master, slave = pty.openpty()
    watcher_fd = os.dup(slave)
    threads_before = set(threading.enumerate())
    try:
        with pytest.raises(RuntimeError, match="exited before reporting readiness"):
            console_module._BorrowedResizeWatcher(
                watcher_fd,
                lambda _rows, _cols: None,
                lambda: None,
            )
    finally:
        os.close(watcher_fd)
        os.close(master)
        os.close(slave)

    assert not [thread for thread in threading.enumerate() if thread not in threads_before]


def test_managed_router_bridge_argv_and_hello_have_no_downstream_auth_fields():
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        assert not any(item.startswith("--token") for item in launcher.argv)
        assert not any(item.startswith("--session") for item in launcher.argv)
        assert launcher.hello_fields == {
            "version": _PROTOCOL_VERSION,
            "rows": 41,
            "cols": 137,
        }
        assert not hasattr(viewer, "token")
        assert not hasattr(viewer, "session_id")
        assert launcher.wait_epoch() == 0
    finally:
        viewer.close()
        launcher.close()


def test_managed_router_negotiates_reconnect_only_when_explicitly_enabled():
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(
        ViewerConfig.external(launcher, reconnect=True)
    ).start()
    try:
        assert "--reconnect" in launcher.argv
        assert launcher.hello_fields == {
            "version": _PROTOCOL_VERSION,
            "rows": 41,
            "cols": 137,
            "reconnect": True,
        }
        assert viewer.viewer_reconnect
    finally:
        viewer.close()
        launcher.close()


def test_close_viewer_exits_bridge_but_retains_listener_for_fresh_attachment():
    first = _ControlledLauncher()
    second = _ControlledLauncher(size=(57, 181))
    viewer = ViewerRouter(ViewerConfig.external(first)).start()
    try:
        assert not viewer.viewer_reconnect
        assert viewer.close_viewer("selected GDB exited normally")
        assert viewer.wait_viewer_disconnected(TIMEOUT)
        assert first.proc.wait(TIMEOUT) == 0
        assert viewer.alive
        assert viewer.current is None

        second.connect(viewer.socket_path, reconnect=True)
        assert viewer.wait_viewer_connected(TIMEOUT)
        assert second.wait_epoch() == 0
        assert viewer.viewer_reconnect
        assert viewer.viewer_alive
    finally:
        viewer.close()
        first.close()
        second.close()


def test_detached_router_starts_without_process_and_preserves_supplied_path(tmp_path):
    socket_path = tmp_path / "viewer.sock"
    viewer = ViewerRouter(viewer=None, socket_path=socket_path).start()
    try:
        assert viewer.socket_path == os.fspath(socket_path)
        assert viewer.proc is None
        assert viewer.viewer_process is None
        assert viewer.alive
        assert not viewer.viewer_connected
        assert not viewer.viewer_alive
        assert socket_path.exists()
    finally:
        viewer.close()

    # A supplied rendezvous path belongs to its discovery lease/caller.  The
    # router closes its listener but does not unlink that shared publication.
    assert socket_path.exists()
    socket_path.unlink()
    assert tmp_path.exists()


def test_detached_router_connection_waits_are_event_driven(tmp_path):
    socket_path = tmp_path / "viewer.sock"
    viewer = ViewerRouter(viewer=None, socket_path=socket_path).start()
    peer = _ControlledLauncher()
    try:
        with pytest.raises(TimeoutError, match="waiting for the console viewer"):
            viewer.wait_viewer_connected(0)

        peer.connect(os.fspath(socket_path))
        assert viewer.wait_viewer_connected(TIMEOUT)
        assert peer.wait_epoch() == 0

        peer.close()
        assert viewer.wait_viewer_disconnected(TIMEOUT)
    finally:
        peer.close()
        viewer.close()
        socket_path.unlink(missing_ok=True)


def test_detached_router_accepts_prebound_duplicate_without_owning_path(tmp_path):
    socket_path = tmp_path / "claimed.sock"
    owner = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    owner.bind(os.fspath(socket_path))
    owner.listen(4)
    duplicate = owner.dup()
    viewer = ViewerRouter(
        viewer=None,
        socket_path=socket_path,
        listener=duplicate,
    ).start()
    try:
        assert viewer.alive
        assert owner.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
    finally:
        viewer.close()

    assert duplicate.fileno() == -1
    assert owner.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
    assert socket_path.exists()
    owner.close()
    socket_path.unlink()


def test_router_bind_failure_reports_operation_path_and_reason(tmp_path):
    socket_path = tmp_path / "occupied.sock"
    owner = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    owner.bind(os.fspath(socket_path))
    viewer = ViewerRouter(viewer=None, socket_path=socket_path)
    try:
        with pytest.raises(
            RuntimeError,
            match=r"bind the viewer Unix listener.*address is already in use",
        ) as caught:
            viewer.start()
        assert isinstance(caught.value.__cause__, OSError)
        assert os.fspath(socket_path) in str(caught.value)
        assert "[Errno" not in str(caught.value)
    finally:
        viewer.close()
        owner.close()
        socket_path.unlink(missing_ok=True)


def test_router_endpoint_connect_failure_is_contextual(tmp_path):
    gdb, endpoint = _endpoint()
    viewer = ViewerRouter().start()
    original_path = endpoint._broker.socket_path
    missing_path = tmp_path / "missing-endpoint.sock"
    endpoint._broker.socket_path = os.fspath(missing_path)
    try:
        with pytest.raises(
            RuntimeError,
            match=r"connect the viewer router to GDB console endpoint.*path does not exist",
        ) as caught:
            viewer.switch(endpoint, timeout=TIMEOUT)
        assert isinstance(caught.value.__cause__, OSError)
        assert os.fspath(missing_path) in str(caught.value)
        assert "[Errno" not in str(caught.value)
    finally:
        endpoint._broker.socket_path = original_path
        viewer.close()
        _dispose(gdb, endpoint)


def test_detached_router_rejects_malformed_and_wrong_version_then_connects(tmp_path):
    socket_path = tmp_path / "viewer.sock"
    viewer = ViewerRouter(socket_path=socket_path).start()
    changes = _ConnectionLog()
    unsubscribe = viewer.add_connection_listener(changes)
    valid = _ControlledLauncher(size=(47, 153))
    try:
        for payload in (
            b"not-json",
            json.dumps({"version": True}).encode("ascii"),
            json.dumps({"version": _PROTOCOL_VERSION + 1}).encode("ascii"),
            json.dumps({"version": _PROTOCOL_VERSION, "rows": 24}).encode("ascii"),
            json.dumps({"version": _PROTOCOL_VERSION, "reconnect": 1}).encode("ascii"),
        ):
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            peer.settimeout(TIMEOUT)
            peer.connect(os.fspath(socket_path))
            peer.sendall(_pack_frame(_FRAME_HELLO, payload))
            assert peer.recv(1) == b""
            peer.close()
            assert viewer.alive
            assert not viewer.viewer_connected
            assert changes.events == []

        valid.connect(os.fspath(socket_path))
        assert changes.wait(1) == [(True, None)]
        assert viewer.viewer_connected
        assert viewer.viewer_alive
        assert valid.wait_epoch() == 0
        assert all(thread is viewer._loss_thread for thread in changes.threads)
    finally:
        unsubscribe()
        valid.close()
        viewer.close()
        if socket_path.exists():
            socket_path.unlink()


def test_detached_independent_bridge_reconnects_to_active_endpoint(tmp_path):
    gdb, endpoint = _endpoint()
    socket_path = tmp_path / "viewer.sock"
    viewer = ViewerRouter(socket_path=socket_path).start()
    changes = _ConnectionLog()
    unsubscribe = viewer.add_connection_listener(changes)
    bridge_script = os.path.join(
        os.path.dirname(console_module.__file__),
        "_console_bridge.py",
    )
    first = _PtyLauncher(size=(43, 149))
    second = _PtyLauncher(size=(57, 181))
    first_before = termios.tcgetattr(first.slave)
    second_before = termios.tcgetattr(second.slave)
    first_before_blocking = os.get_blocking(first.slave)
    second_before_blocking = os.get_blocking(second.slave)
    try:
        first.spawn([sys.executable, bridge_script, os.fspath(socket_path)])
        assert changes.wait(1) == [(True, None)]
        assert viewer.proc is None
        assert viewer.viewer_alive
        viewer.switch(endpoint)

        os.write(gdb.transport.ui_fd, b"first-independent-output\n")
        _read(first.master, b"first-independent-output")
        os.write(first.master, b"first-independent-input\n")
        _read(gdb.transport.ui_fd, b"first-independent-input")

        first.proc.terminate()
        first.proc.wait(timeout=3.0)
        disconnected = changes.wait(2)
        assert disconnected[0] == (True, None)
        assert disconnected[1][0] is False
        assert disconnected[1][1]
        assert not viewer.viewer_alive
        assert not viewer.viewer_connected
        assert viewer.current is endpoint
        assert endpoint.viewer_connected
        assert termios.tcgetattr(first.slave) == first_before
        assert os.get_blocking(first.slave) == first_before_blocking

        # Output produced while no viewer exists is replayed after reconnect.
        os.write(gdb.transport.ui_fd, b"disconnected-backlog\n")
        second.spawn([sys.executable, bridge_script, os.fspath(socket_path)])
        assert changes.wait(3)[-1] == (True, None)
        assert viewer.viewer_alive
        _read(second.master, b"disconnected-backlog")
        gdb.transport.wait_size((57, 181))

        # HELLO_ACK resynchronizes the active epoch, so input reaches the
        # existing endpoint without forcing another router.switch().
        os.write(second.master, b"reconnected-input\n")
        _read(gdb.transport.ui_fd, b"reconnected-input")

        viewer.close()
        second.proc.wait(timeout=3.0)
        assert changes.wait(4)[-1][0] is False
        assert termios.tcgetattr(second.slave) == second_before
        assert os.get_blocking(second.slave) == second_before_blocking
        assert viewer.current is None
    finally:
        unsubscribe()
        viewer.close()
        first.close()
        second.close()
        if socket_path.exists():
            socket_path.unlink()
        _dispose(gdb, endpoint)


def test_detached_idle_router_blocks_in_selector_without_polling(monkeypatch):
    import pwnc.gdb.dap.viewer as viewer_module

    real_selector = viewer_module.selectors.DefaultSelector
    entered = threading.Event()
    timeouts = []

    class RecordingSelector:
        def __init__(self):
            self._selector = real_selector()

        def __getattr__(self, name):
            return getattr(self._selector, name)

        def select(self, timeout=None):
            timeouts.append(timeout)
            entered.set()
            return self._selector.select(timeout)

    monkeypatch.setattr(viewer_module.selectors, "DefaultSelector", RecordingSelector)
    viewer = ViewerRouter().start()
    try:
        assert entered.wait(TIMEOUT)
        assert timeouts == [None]
    finally:
        viewer.close()


def test_switch_reuses_one_bridge_and_routes_only_to_current_endpoint():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _PtyLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        bridge_pid = viewer.viewer_process.pid
        assert viewer.viewer_connected
        assert viewer.current is None

        viewer.switch(first)
        assert viewer.current is first
        os.write(first_gdb.transport.ui_fd, b"from-first\n")
        _read(launcher.master, b"from-first")
        os.write(launcher.master, b"first-command\n")
        _read(first_gdb.transport.ui_fd, b"first-command")

        # Output produced before selection is replayed from the endpoint's
        # bounded reconnect backlog after the atomic switch.
        os.write(second_gdb.transport.ui_fd, b"second-backlog\n")
        viewer.switch(second)
        assert viewer.viewer_process.pid == bridge_pid
        assert viewer.current is second
        _read(launcher.master, b"second-backlog")

        os.write(launcher.master, b"second-command\n")
        _read(second_gdb.transport.ui_fd, b"second-command")
        ready, _, _ = select.select([first_gdb.transport.ui_fd], [], [], 0)
        assert first_gdb.transport.ui_fd not in ready
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_endpoint_eof_notifies_once_and_never_closes_the_viewer():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _PtyLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    losses = []
    lost = threading.Event()

    def on_lost(endpoint, reason, generation):
        losses.append((endpoint, reason, generation))
        lost.set()

    unsubscribe = viewer.add_loss_listener(on_lost)
    first_disposed = False
    try:
        viewer.switch(first)
        bridge_pid = viewer.viewer_process.pid
        first.dispose_endpoint()
        first_disposed = True

        assert lost.wait(TIMEOUT)
        assert losses == [(first, "endpoint closed", 1)]
        assert viewer.current is None
        assert viewer.viewer_connected
        assert viewer.viewer_alive

        viewer.switch(second)
        assert viewer.viewer_process.pid == bridge_pid
        os.write(second_gdb.transport.ui_fd, b"replacement\n")
        _read(launcher.master, b"replacement")
        assert len(losses) == 1
    finally:
        unsubscribe()
        viewer.close()
        launcher.close()
        if not first_disposed:
            first.dispose_endpoint()
        first_gdb.transport.close()
        _dispose(second_gdb, second)


def test_latest_viewer_geometry_is_applied_synchronously_on_every_switch():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _PtyLauncher(size=(43, 149))
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        viewer.switch(first)
        first_gdb.transport.wait_size((43, 149))
        assert first._broker.current_size == (43, 149)

        launcher.resize(57, 181)
        first_gdb.transport.wait_size((57, 181))
        viewer.switch(second)
        # switch() itself is the barrier; no eventual-state polling is needed.
        assert (
            "pwncSetWinsize",
            {"rows": 57, "cols": 181},
        ) in second_gdb.transport.requests
        assert second._broker.current_size == (57, 181)
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_failed_candidate_does_not_disturb_current_endpoint():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _PtyLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        viewer.switch(first)
        second.dispose_endpoint()
        with pytest.raises(RuntimeError, match="closed"):
            viewer.switch(second)
        assert viewer.current is first
        assert first.viewer_connected
        os.write(first_gdb.transport.ui_fd, b"still-first\n")
        _read(launcher.master, b"still-first")
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        second_gdb.transport.close()


def test_router_close_restores_external_viewer_terminal_state():
    launcher = _PtyLauncher()
    before = termios.tcgetattr(launcher.slave)
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    assert termios.tcgetattr(launcher.slave) != before
    viewer.close()
    assert launcher.proc.wait(timeout=3.0) is not None
    assert termios.tcgetattr(launcher.slave) == before
    launcher.close()


def test_router_terminal_restore_completes_before_racing_close_returns():
    viewer = ViewerRouter(ViewerConfig.current())
    proc = object()
    restore_entered = threading.Event()
    allow_restore = threading.Event()
    restore_complete = threading.Event()

    class BlockingSnapshot:
        def restore(self):
            restore_entered.set()
            assert allow_restore.wait(TIMEOUT)
            restore_complete.set()

    viewer._terminal_state = (proc, BlockingSnapshot())
    monitor = threading.Thread(target=viewer._restore_terminal, args=(proc,))
    monitor.start()
    assert restore_entered.wait(TIMEOUT)

    close_returned = threading.Event()

    def racing_close():
        viewer._restore_terminal(proc)
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


def test_startup_failure_stops_partial_router_and_notification_threads():
    class BrokenLauncher:
        def spawn(self, _argv):
            raise RuntimeError("launcher failed")

    viewer = ViewerRouter(ViewerConfig.external(BrokenLauncher()))
    with pytest.raises(RuntimeError, match="launcher failed"):
        viewer.start()

    assert not viewer.alive
    assert viewer._router_done.is_set()
    assert not viewer._thread.is_alive()
    assert not viewer._loss_thread.is_alive()
    assert not os.path.exists(viewer.socket_path)


def test_silent_endpoint_accepts_input_without_waiting_for_output():
    gdb, endpoint = _endpoint()
    launcher = _PtyLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        viewer.switch(endpoint)
        os.write(launcher.master, b"input-to-silent-endpoint\n")
        _read(gdb.transport.ui_fd, b"input-to-silent-endpoint")
    finally:
        viewer.close()
        launcher.close()
        _dispose(gdb, endpoint)


def test_recursive_malformed_hello_is_rejected_without_killing_router():
    launcher = _ControlledLauncher(malformed_hello_first=True)
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        assert viewer.alive
        assert viewer.viewer_connected
        assert viewer._error is None
    finally:
        viewer.close()
        launcher.close()


def test_broker_rejects_unicode_auth_edge_cases_without_dying():
    gdb, endpoint = _endpoint()

    def hello(**updates):
        fields = {
            "version": _PROTOCOL_VERSION,
            "token": endpoint._broker.token,
            "session": endpoint._broker.session_id,
        }
        fields.update(updates)
        return json.dumps(fields, separators=(",", ":")).encode("ascii")

    try:
        for payload in (
            hello(nonce="\ud800"),
            hello(token="non-ascii-\u00e9"),
        ):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(endpoint._broker.socket_path)
            client.sendall(_pack_frame(_FRAME_HELLO, payload))
            assert client.recv(1) == b""
            client.close()
            assert endpoint.endpoint_alive
            assert not endpoint.viewer_connected

        # A well-formed client can still authenticate after both rejections;
        # neither malformed string escaped the per-client failure boundary.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(endpoint._broker.socket_path)
        client.sendall(_pack_frame(_FRAME_HELLO, hello()))
        endpoint._broker.wait_connected(TIMEOUT)
        assert endpoint.endpoint_alive
        client.close()
        endpoint._broker.wait_disconnected(TIMEOUT)
    finally:
        try:
            client.close()
        except (NameError, OSError):
            pass
        _dispose(gdb, endpoint)


def test_pause_barrier_routes_queued_old_input_before_switch_only_to_old_endpoint():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        viewer.switch(first)
        old_epoch = launcher.epoch
        launcher.inject_before_pause(2, b"queued-old-input\n")

        viewer.switch(second)
        _read(first_gdb.transport.ui_fd, b"queued-old-input")

        # Even a delayed frame explicitly tagged with the old epoch is stale
        # after the transaction commits.  The following current-epoch frame is
        # an event-driven processing barrier for both frames.
        launcher.send_input(b"stale-old-input\n", epoch=old_epoch)
        launcher.send_input(b"current-input\n")
        received = _read(second_gdb.transport.ui_fd, b"current-input")
        assert b"queued-old-input" not in received
        assert b"stale-old-input" not in received
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_real_bridge_discards_terminal_bytes_typed_while_switch_is_paused():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _PtyLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    pause_seen = threading.Event()
    release_resume = threading.Event()
    completed = threading.Event()
    outcome = []
    original_switch_paused = viewer._switch_paused

    def hold_before_resume(selector, command):
        pause_seen.set()
        if not release_resume.wait(TIMEOUT):
            raise TimeoutError("test did not release the switch RESUME")
        original_switch_paused(selector, command)

    def switch_candidate():
        try:
            outcome.append(viewer.switch(second, timeout=TIMEOUT))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)
        finally:
            completed.set()

    thread = threading.Thread(target=switch_candidate)
    try:
        viewer.switch(first)
        viewer._switch_paused = hold_before_resume
        thread.start()
        assert pause_seen.wait(TIMEOUT)

        # The production bridge has processed PAUSE and unregistered stdin.
        # These bytes therefore sit unread in its terminal input queue until
        # RESUME performs the boundary flush.
        os.write(launcher.master, b"typed-during-pause\n")
        release_resume.set()
        assert completed.wait(TIMEOUT)
        thread.join(TIMEOUT)
        assert outcome == [second]

        os.write(launcher.master, b"typed-after-resume\n")
        received = _read(second_gdb.transport.ui_fd, b"typed-after-resume")
        assert b"typed-during-pause" not in received
    finally:
        release_resume.set()
        thread.join(TIMEOUT)
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_switch_timeout_restores_old_epoch_and_ignores_late_acknowledgements():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        viewer.switch(first)
        old_epoch = launcher.epoch
        launcher.hold_pause(2)

        with pytest.raises(TimeoutError, match="timed out"):
            viewer.switch(second, timeout=0.1)

        timed_out_payload = launcher.wait_for_pause(2)
        switch_id, proposed_epoch = _SWITCH.unpack(timed_out_payload)
        assert launcher.epoch == old_epoch
        assert viewer.current is first
        assert viewer.viewer_connected
        second._broker.wait_disconnected(TIMEOUT)

        # Duplicated acknowledgements from the completed transaction are
        # protocol noise, not a reason to kill the stable viewer.
        launcher.send_frame(_FRAME_SWITCH_PAUSED, timed_out_payload)
        launcher.send_frame(
            _FRAME_SWITCH_RESUMED,
            _SWITCH.pack(switch_id, proposed_epoch),
        )
        launcher.send_input(b"after-rollback\n")
        _read(first_gdb.transport.ui_fd, b"after-rollback")
        assert viewer.current is first
        assert viewer.viewer_connected
        ready, _, _ = select.select([second_gdb.transport.ui_fd], [], [], 0)
        assert second_gdb.transport.ui_fd not in ready

        # The rolled-back transaction releases every lane and does not poison
        # the bridge's next transaction.
        viewer.switch(second)
        launcher.send_input(b"successful-retry\n")
        _read(second_gdb.transport.ui_fd, b"successful-retry")
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_viewer_loss_during_switch_fails_promptly_and_preserves_old_endpoint():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        viewer.switch(first)
        launcher.drop_on_pause(2)
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="viewer disconnected"):
            viewer.switch(second, timeout=2.0)
        elapsed = time.monotonic() - started

        assert elapsed < 1.0
        assert viewer.current is first
        assert not viewer.viewer_connected
        assert not viewer.viewer_alive
        second._broker.wait_disconnected(TIMEOUT)
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_viewer_loss_before_candidate_auth_wakes_switch_and_releases_lease():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    original_queue_client = second._broker._queue_client
    outcome = []
    completed = threading.Event()

    def withhold_authentication_ack(frame_type, payload=b""):
        if frame_type != _FRAME_HELLO_ACK:
            original_queue_client(frame_type, payload)

    def switch_candidate():
        try:
            viewer.switch(second, timeout=2.0)
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)
        finally:
            completed.set()

    thread = threading.Thread(target=switch_candidate)
    try:
        viewer.switch(first)
        second._broker._queue_client = withhold_authentication_ack
        thread.start()
        second._broker.wait_connected(TIMEOUT)

        started = time.monotonic()
        launcher._shutdown()
        assert completed.wait(0.75)
        elapsed = time.monotonic() - started
        thread.join(TIMEOUT)

        assert elapsed < 0.75
        assert len(outcome) == 1
        assert isinstance(outcome[0], RuntimeError)
        assert "viewer disconnected" in str(outcome[0])
        assert viewer.current is first
        second._broker.wait_disconnected(TIMEOUT)
    finally:
        launcher._shutdown()
        thread.join(TIMEOUT)
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_viewer_loss_during_sync_geometry_releases_candidate_before_request_returns():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    original_apply_sync = second._resize_worker.apply_sync
    geometry_entered = threading.Event()
    release_geometry = threading.Event()
    completed = threading.Event()
    outcome = []

    def hold_synchronous_resize(rows, cols, *, timeout=None):
        geometry_entered.set()
        if not release_geometry.wait(TIMEOUT):
            raise TimeoutError("test did not release synchronous geometry")
        return original_apply_sync(rows, cols, timeout=timeout)

    def switch_candidate():
        try:
            viewer.switch(second, timeout=TIMEOUT)
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)
        finally:
            completed.set()

    thread = threading.Thread(target=switch_candidate)
    try:
        viewer.switch(first)
        second._resize_worker.apply_sync = hold_synchronous_resize
        thread.start()
        assert geometry_entered.wait(TIMEOUT)

        launcher._shutdown()
        # The Python caller cannot be preempted while an arbitrary synchronous
        # transport request is on its stack, but viewer EOF still closes the
        # candidate socket and releases its broker lease immediately.
        second._broker.wait_disconnected(0.75)
        assert not completed.is_set()

        release_geometry.set()
        assert completed.wait(TIMEOUT)
        thread.join(TIMEOUT)
        assert len(outcome) == 1
        assert isinstance(outcome[0], RuntimeError)
        assert "viewer disconnected" in str(outcome[0])
        assert viewer.current is first
    finally:
        release_geometry.set()
        launcher._shutdown()
        thread.join(TIMEOUT)
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_geometry_application_uses_switch_deadline_and_cleans_failed_candidate():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _ControlledLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    observed_timeouts = []
    original_request = second_gdb.transport.request

    def fail_resize(command, arguments, timeout=None):
        if command == "pwncSetWinsize":
            observed_timeouts.append(timeout)
            raise TimeoutError("injected resize timeout")
        return original_request(command, arguments, timeout=timeout)

    try:
        viewer.switch(first)
        second_gdb.transport.request = fail_resize
        with pytest.raises(TimeoutError, match="injected resize timeout"):
            viewer.switch(second, timeout=0.2)

        assert any(timeout is not None and 0 < timeout <= 0.2 for timeout in observed_timeouts)
        assert viewer.current is first
        second._broker.wait_disconnected(TIMEOUT)
        launcher.send_input(b"after-resize-failure\n")
        _read(first_gdb.transport.ui_fd, b"after-resize-failure")
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)


def test_repeated_immediate_switch_back_waits_for_old_broker_lease_release():
    first_gdb, first = _endpoint()
    second_gdb, second = _endpoint()
    launcher = _PtyLauncher()
    viewer = ViewerRouter(ViewerConfig.external(launcher)).start()
    try:
        viewer.switch(first)
        bridge_pid = viewer.viewer_process.pid
        for _iteration in range(25):
            viewer.switch(second)
            viewer.switch(first)

        assert viewer.viewer_process.pid == bridge_pid
        os.write(launcher.master, b"back-on-first\n")
        _read(first_gdb.transport.ui_fd, b"back-on-first")
        ready, _, _ = select.select([second_gdb.transport.ui_fd], [], [], 0)
        assert second_gdb.transport.ui_fd not in ready
    finally:
        viewer.close()
        launcher.close()
        _dispose(first_gdb, first)
        _dispose(second_gdb, second)
