"""Black-box tests for the independently managed pool viewer client."""

from __future__ import annotations

import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
from pathlib import Path

import pytest

import pwnc.gdb.dap as dap
from pwnc.gdb.dap.console import (
    _DEFAULT_BACKLOG_BYTES,
    ConsoleConfig,
    open_console,
)
from pwnc.gdb.dap.discovery import acquire_pool_socket, discover_manager
from pwnc.gdb.dap.viewer import ViewerRouter
from pwnc.gdb.dap.viewer_client import PoolConnectionError, view
from pwnc.pwncli import get_main_parser, main

TIMEOUT = 10.0
_CLI = "from pwnc.pwncli import main; raise SystemExit(main())"
_REPOSITORY = Path(__file__).resolve().parents[2]


def _read_until(fd: int, marker: bytes, timeout: float = TIMEOUT) -> bytes:
    """Read an fd until *marker* arrives, using readiness rather than sleeps."""
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
            data = os.read(fd, 65536)
        except BlockingIOError:
            continue
        if not data:
            break
        output.extend(data)
    assert marker in output, bytes(output)
    return bytes(output)


class _ConnectionLog:
    """Event-driven recorder for detached-router viewer transitions."""

    def __init__(self):
        self._condition = threading.Condition()
        self.events: list[tuple[bool, str | None]] = []

    def __call__(self, connected: bool, reason: str | None) -> None:
        with self._condition:
            self.events.append((connected, reason))
            self._condition.notify_all()

    def wait(self, count: int, timeout: float = TIMEOUT) -> list[tuple[bool, str | None]]:
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self.events) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError((count, self.events))
                self._condition.wait(remaining)
            return list(self.events)


class _Process:
    """Popen with an eventful, blocking-waitpid completion monitor."""

    def __init__(self, argv, **kwargs):
        self.proc = subprocess.Popen(argv, **kwargs)
        self.exited = threading.Event()
        self.status: int | None = None
        self._thread = threading.Thread(
            target=self._wait,
            name=f"viewer-client-waitpid-{self.proc.pid}",
            daemon=True,
        )
        self._thread.start()

    @property
    def pid(self) -> int:
        return self.proc.pid

    def _wait(self) -> None:
        self.status = self.proc.wait()
        self.exited.set()

    def wait(self, timeout: float = TIMEOUT) -> int:
        if not self.exited.wait(timeout):
            raise AssertionError(f"viewer process {self.pid} did not exit")
        self._thread.join()
        assert self.status is not None
        return self.status

    def terminate(self) -> int:
        if not self.exited.is_set():
            self.proc.terminate()
        return self.wait()

    def close(self) -> None:
        if self.exited.is_set():
            self._thread.join()
            return
        self.proc.terminate()
        if self.exited.wait(3.0):
            self._thread.join()
            return
        self.proc.kill()
        assert self.exited.wait(3.0)
        self._thread.join()


class _ViewerPty:
    """PTY and independently launched ``pwnc gdb view`` process."""

    def __init__(self, size=(43, 149)):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(
            self.master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", size[0], size[1], 0, 0),
        )
        self.initial_termios = termios.tcgetattr(self.slave)
        self.initial_blocking = os.get_blocking(self.slave)
        self.process: _Process | None = None

    @property
    def path(self) -> str:
        return os.ttyname(self.slave)

    def start(self, arguments, *, cwd: Path, env: dict[str, str], target=False) -> _Process:
        argv = [sys.executable, "-c", _CLI, "gdb", "view", *map(os.fspath, arguments)]
        if target:
            argv.extend(("--tty", self.path))
            kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        else:
            kwargs = {"stdin": self.slave, "stdout": self.slave, "stderr": self.slave}
        self.process = _Process(argv, cwd=cwd, env=env, close_fds=True, **kwargs)
        return self.process

    def assert_restored(self) -> None:
        assert termios.tcgetattr(self.slave) == self.initial_termios
        assert os.get_blocking(self.slave) == self.initial_blocking

    def close(self) -> None:
        if self.process is not None:
            self.process.close()
        for fd in (self.master, self.slave):
            try:
                os.close(fd)
            except OSError:
                pass


class _Transport:
    """The small DAP surface needed by a real owned console endpoint."""

    def __init__(self):
        self.ui_fd: int | None = None
        self.requests: list[tuple[str, dict]] = []

    def request(self, command, arguments, timeout=None):
        del timeout
        self.requests.append((command, dict(arguments)))
        if command == "pwncNewUI":
            self.ui_fd = os.open(arguments["tty"], os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            tty.setraw(self.ui_fd)
        return {}

    def close(self) -> None:
        if self.ui_fd is not None:
            os.close(self.ui_fd)
            self.ui_fd = None


class _Gdb:
    def __init__(self):
        self.transport = _Transport()


def _owned_endpoint():
    gdb = _Gdb()
    endpoint = open_console(
        gdb,
        ConsoleConfig.owned(initial_size=(24, 80), backlog_bytes=4096),
    )
    return gdb, endpoint


def _dispose_endpoint(gdb, endpoint) -> None:
    if endpoint is not None and endpoint.endpoint_alive:
        endpoint.dispose_endpoint()
    gdb.transport.close()


def _subprocess_environment(**updates: str) -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join([os.fspath(_REPOSITORY), *([existing] if existing else [])])
    env.setdefault("TERM", "xterm")
    env.update(updates)
    return env


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _bridge_child_pid(supervisor_pid: int) -> int:
    """Return the supervised bridge child after its connection barrier.

    This is intentionally Linux-only test instrumentation.  Reading the
    kernel's child list once after ViewerRouter's connected callback avoids a
    process-table polling loop and does not leak implementation details into
    the public API.
    """
    children = Path(f"/proc/{supervisor_pid}/task/{supervisor_pid}/children")
    if not children.is_file():
        pytest.skip("bridge-child SIGKILL recovery requires Linux procfs")
    pids = [int(value) for value in children.read_text().split()]
    assert len(pids) == 1, pids
    return pids[0]


def test_gdb_view_parser_is_lazy_and_preserves_public_options(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert dap.view is view
    assert dap.PoolConnectionError is PoolConnectionError
    assert dap.discover_manager is discover_manager
    assert dap.acquire_pool_socket is acquire_pool_socket

    args = get_main_parser().parse_args(
        [
            "gdb",
            "view",
            "--socket",
            "manual.sock",
            "--config",
            "elsewhere/pwnc.toml",
            "--name",
            "reserve",
            "--keep-open",
            "--reconnect",
            "--tty",
            "/dev/pts/7",
        ]
    )

    assert args.subcommand == "gdb"
    assert getattr(args, "subcommand.gdb") == "view"
    assert args.socket_path == Path("manual.sock")
    assert args.config_path == Path("elsewhere/pwnc.toml")
    assert args.name == "reserve"
    assert args.keep_open
    assert args.reconnect
    assert args.tty == Path("/dev/pts/7")
    assert not (tmp_path / "pwnc.toml").exists()


def test_router_backlog_never_retains_only_csi_parameter_suffix():
    router = ViewerRouter()
    payload = b"\x1b[36m" + b"-" * (_DEFAULT_BACKLOG_BYTES - 3)
    assert len(payload) == _DEFAULT_BACKLOG_BYTES + 2

    router._remember_viewer(payload)

    retained = bytes(router._viewer_backlog)
    assert router._viewer_backlog_truncated
    assert len(retained) <= _DEFAULT_BACKLOG_BYTES
    assert retained == b"-" * (_DEFAULT_BACKLOG_BYTES - 3)
    assert not retained.startswith(b"36m")


def test_gdb_view_cli_reports_expected_validation_errors_without_traceback(
    tmp_path,
    monkeypatch,
    capsys,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["pwnc", "gdb", "view", "--socket", "manual.sock", "--name", ""],
    )

    assert main() == 1
    captured = capsys.readouterr()
    assert "pool name cannot be empty" in captured.out
    assert "Traceback" not in captured.out + captured.err
    assert not (tmp_path / "pwnc.toml").exists()


@pytest.mark.parametrize("kind", ["missing", "regular-file"])
def test_view_rejects_unusable_socket_with_pool_source_and_remediation(tmp_path, kind):
    socket_path = tmp_path / "manual.sock"
    if kind == "regular-file":
        socket_path.write_text("not a socket")

    with pytest.raises(PoolConnectionError) as caught:
        view(socket_path=socket_path)

    message = str(caught.value)
    assert "GDB pool 'default'" in message
    assert os.fspath(socket_path) in message
    assert "explicit socket path" in message
    assert "[Errno" not in message
    if kind == "missing":
        assert "Start the pool manager" in message
    else:
        assert "not a Unix socket" in message


def test_gdb_view_cli_reports_missing_socket_without_opaque_errno(
    tmp_path,
    monkeypatch,
    capsys,
):
    socket_path = tmp_path / "missing.sock"
    monkeypatch.setattr(
        sys,
        "argv",
        ["pwnc", "gdb", "view", "--socket", os.fspath(socket_path)],
    )

    assert main() == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "gdb view: cannot connect to GDB pool 'default'" in output
    assert os.fspath(socket_path) in output
    assert "Start the pool manager" in output
    assert "[Errno" not in output
    assert "Traceback" not in output


def test_explicit_socket_cli_bypasses_config_and_reconnects_active_endpoint(tmp_path):
    """Two independent viewer programs can replace each other in one router."""
    socket_path = tmp_path / "manual.sock"
    malformed_config = tmp_path / "pwnc.toml"
    malformed_config.write_bytes(b"[deliberately malformed\n")
    before_config = malformed_config.read_bytes()
    viewer = ViewerRouter(socket_path=socket_path).start()
    connections = _ConnectionLog()
    unsubscribe = viewer.add_connection_listener(connections)
    gdb, endpoint = _owned_endpoint()
    first = _ViewerPty(size=(43, 149))
    second = _ViewerPty(size=(57, 181))
    rejected = _ViewerPty(size=(59, 185))
    third = _ViewerPty(size=(61, 191))
    env = _subprocess_environment()
    try:
        first_process = first.start(("--socket", socket_path), cwd=tmp_path, env=env)
        assert connections.wait(1) == [(True, None)]
        assert viewer.viewer_connected
        assert not viewer.viewer_reconnect
        viewer.switch(endpoint, timeout=TIMEOUT)

        assert gdb.transport.ui_fd is not None
        os.write(gdb.transport.ui_fd, b"first-cli-output\n")
        _read_until(first.master, b"first-cli-output")
        os.write(first.master, b"first-cli-input\n")
        _read_until(gdb.transport.ui_fd, b"first-cli-input")

        # The public viewer is a supervisor.  Killing only its bridge child
        # must still let the parent restore the borrowed terminal, including
        # O_NONBLOCK on the inherited PTY open-file description.
        os.kill(_bridge_child_pid(first_process.pid), signal.SIGKILL)
        assert first_process.wait() == 128 + signal.SIGKILL
        disconnected = connections.wait(2)
        assert disconnected[0] == (True, None)
        assert disconnected[1][0] is False
        assert disconnected[1][1]
        assert viewer.alive
        assert viewer.current is endpoint
        first.assert_restored()

        # Output generated without a viewer is retained by the persistent
        # router and appears in the replacement program's terminal.
        os.write(gdb.transport.ui_fd, b"between-cli-backlog\n")
        second_process = second.start(
            ("--socket", socket_path, "--keep-open", "--reconnect"),
            cwd=tmp_path,
            env=env,
        )
        assert connections.wait(3)[-1] == (True, None)
        assert viewer.viewer_reconnect
        _read_until(second.master, b"between-cli-backlog")
        os.write(second.master, b"second-cli-input\n")
        _read_until(gdb.transport.ui_fd, b"second-cli-input")
        assert viewer.current is endpoint

        # A second process can connect at the kernel level while the router's
        # one viewer slot is occupied, but lack of HELLO_ACK is a rejected
        # admission and must not look like a successful zero-length session.
        rejected_process = rejected.start(("--socket", socket_path), cwd=tmp_path, env=env)
        assert rejected_process.wait() == 1
        rejected_output = _read_until(rejected.master, b"before protocol admission")
        assert b"pwnc console bridge:" in rejected_output
        rejected.assert_restored()
        assert connections.wait(3) == [*disconnected, (True, None)]

        # A signal sent to the public supervisor is forwarded to the bridge;
        # its conventional shell status is retained while cleanup still runs.
        assert second_process.terminate() == 128 + signal.SIGTERM
        assert connections.wait(4)[-1][0] is False
        second.assert_restored()

        # If the supervisor itself receives SIGKILL, its Linux bridge gets a
        # parent-death SIGHUP and restores the terminal from its own snapshot.
        third_process = third.start(("--socket", socket_path), cwd=tmp_path, env=env)
        assert connections.wait(5)[-1] == (True, None)
        bridge_pid = _bridge_child_pid(third_process.pid)
        if not hasattr(os, "pidfd_open"):
            pytest.skip("supervisor SIGKILL recovery requires pidfd_open")
        bridge_pidfd = os.pidfd_open(bridge_pid)
        try:
            os.kill(third_process.pid, signal.SIGKILL)
            assert third_process.wait() == -signal.SIGKILL
            ready, _, _ = select.select([bridge_pidfd], [], [], TIMEOUT)
            assert bridge_pidfd in ready
        finally:
            os.close(bridge_pidfd)
        assert connections.wait(6)[-1][0] is False
        third.assert_restored()
        assert malformed_config.read_bytes() == before_config
    finally:
        unsubscribe()
        viewer.close()
        first.close()
        second.close()
        rejected.close()
        third.close()
        _dispose_endpoint(gdb, endpoint)
        _unlink(socket_path)


def test_seed_autodiscovery_matches_nested_cwd_and_explicit_config(tmp_path, monkeypatch):
    """Manager and separately launched viewers converge on path + seed + name."""
    project = tmp_path / "project"
    nested = project / "one" / "two"
    outside = tmp_path / "outside"
    xdg = tmp_path / "xdg"
    nested.mkdir(parents=True)
    outside.mkdir()
    xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", os.fspath(xdg))

    address = discover_manager("reserve", start=project)
    lease = acquire_pool_socket(address)
    viewer = ViewerRouter(
        socket_path=address.path,
        listener=lease.duplicate_socket(),
    ).start()
    connections = _ConnectionLog()
    unsubscribe = viewer.add_connection_listener(connections)
    first = _ViewerPty()
    second = _ViewerPty()
    config_path = project / "pwnc.toml"
    config_after_manager = config_path.read_bytes()
    manager_style_env = _subprocess_environment(XDG_RUNTIME_DIR=os.fspath(xdg))
    terminal_style_env = _subprocess_environment()
    terminal_style_env.pop("XDG_RUNTIME_DIR", None)
    try:
        first_process = first.start(
            ("--name", "reserve"),
            cwd=nested,
            env=manager_style_env,
        )
        assert connections.wait(1) == [(True, None)]
        assert first_process.terminate() == 128 + signal.SIGTERM
        assert connections.wait(2)[-1][0] is False
        first.assert_restored()

        second_process = second.start(
            ("--name", "reserve", "--config", config_path),
            cwd=outside,
            env=terminal_style_env,
        )
        assert connections.wait(3)[-1] == (True, None)
        viewer.close()
        assert second_process.wait() == 0
        second.assert_restored()

        # Viewer-side lookup is strictly read-only in both discovery modes.
        assert config_path.read_bytes() == config_after_manager
        assert address.path.parent == Path("/tmp") / f"pwnc-{os.getuid()}"
    finally:
        unsubscribe()
        viewer.close()
        lease.close()
        first.close()
        second.close()


def test_target_tty_cli_relays_io_and_restores_terminal_on_exit(tmp_path):
    socket_path = tmp_path / "target.sock"
    viewer = ViewerRouter(socket_path=socket_path).start()
    connections = _ConnectionLog()
    unsubscribe = viewer.add_connection_listener(connections)
    gdb, endpoint = _owned_endpoint()
    terminal = _ViewerPty(size=(51, 173))
    env = _subprocess_environment()
    try:
        process = terminal.start(
            ("--socket", socket_path),
            cwd=tmp_path,
            env=env,
            target=True,
        )
        assert connections.wait(1) == [(True, None)]
        viewer.switch(endpoint, timeout=TIMEOUT)

        assert gdb.transport.ui_fd is not None
        os.write(gdb.transport.ui_fd, b"target-cli-output\n")
        _read_until(terminal.master, b"target-cli-output")
        os.write(terminal.master, b"target-cli-input\n")
        _read_until(gdb.transport.ui_fd, b"target-cli-input")

        assert process.terminate() == 128 + signal.SIGTERM
        assert connections.wait(2)[-1][0] is False
        terminal.assert_restored()
        assert viewer.alive
        assert viewer.current is endpoint
    finally:
        unsubscribe()
        viewer.close()
        terminal.close()
        _dispose_endpoint(gdb, endpoint)
        _unlink(socket_path)
