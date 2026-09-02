"""Real-GDB coverage for targetless pool setup and stable-viewer failover."""

from __future__ import annotations

import fcntl
import hashlib
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
from pathlib import Path

import pytest

from pwnc.gdb.dap import ConsoleConfig, GdbPool, GdbPoolError, GdbState, ViewerConfig

TIMEOUT = 30.0
GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")
GEF_PATH = Path(os.environ.get("PWNC_TEST_GEF", "/home/ctf/bata24-gef/gef.py"))
GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
VIEW_CLI = "from pwnc.pwncli import main; raise SystemExit(main())"


class _PtyLauncher:
    def __init__(self, size=(39, 143)):
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

    def close(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=3.0)
        for descriptor in (self.master, self.slave):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_until(descriptor, marker, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    output = bytearray()
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError((marker, bytes(output)))
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if descriptor not in ready:
            continue
        try:
            data = os.read(descriptor, 65536)
        except OSError as error:
            raise AssertionError((marker, bytes(output))) from error
        if not data:
            raise AssertionError((marker, bytes(output)))
        output.extend(data)
    return bytes(output)


def _require_gdb():
    if not shutil.which(GDB_PATH) and not os.path.isfile(GDB_PATH):
        pytest.skip("GDB with DAP support is required")


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_stat(path):
    """Metadata that read-only use of the pinned source must preserve."""
    stat = path.stat()
    return (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )


@pytest.fixture
def exact_gef():
    _require_gdb()
    if not GEF_PATH.is_file():
        pytest.skip("exact bata24 GEF fixture is not installed")

    digest = _sha256(GEF_PATH)
    assert digest == GEF_SHA256, (
        f"the installed GEF fixture is not the agreed unmodified bata24 source: expected {GEF_SHA256}, got {digest}"
    )
    metadata = _stable_stat(GEF_PATH)
    try:
        yield GEF_PATH.resolve()
    finally:
        assert _sha256(GEF_PATH) == digest
        assert _stable_stat(GEF_PATH) == metadata


def _isolated_environment(root):
    home = root / "home"
    temporary = root / "tmp"
    home.mkdir()
    temporary.mkdir()
    environment = os.environ.copy()
    environment["HOME"] = os.fspath(home)
    environment["TMPDIR"] = os.fspath(temporary)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.setdefault("TERM", "xterm")
    return environment, home, temporary


def _targetless_setup_recorder(prompt_prefix):
    records = []
    condition = threading.Condition()

    def setup(gdb):
        assert gdb.state is GdbState.PREPARED
        assert gdb.target is None
        assert gdb._console is not None
        assert gdb._console.endpoint_alive
        assert not gdb._console.viewer_connected
        pid = gdb.transport.proc.pid
        prompt = f"({prompt_prefix}-{pid})"
        gdb.execute("set confirm off")
        gdb.execute(f"set prompt {prompt} ")
        with condition:
            records.append((pid, gdb, prompt.encode()))
            condition.notify_all()

    return setup, records, condition


def test_live_pool_only_retargets_on_real_gdb_death_and_keeps_the_same_bridge():
    _require_gdb()
    setup_records = []
    setup_condition = threading.Condition()

    def setup(gdb):
        # This callback is deliberately observant: every fact asserted here
        # must hold before this GDB can enter either the reserve or the viewer.
        assert gdb.state is GdbState.PREPARED
        assert gdb.target is None
        assert gdb._console is not None
        assert gdb._console.endpoint_alive
        assert not gdb._console.viewer_connected
        pid = gdb.transport.proc.pid
        gdb.execute("set confirm off")
        gdb.execute(f"set prompt (pool-{pid}) ")
        with setup_condition:
            setup_records.append((pid, gdb))
            setup_condition.notify_all()

    launcher = _PtyLauncher()
    pool = GdbPool(
        size=1,
        setup=setup,
        gdb_path=GDB_PATH,
        init=False,
        console=ConsoleConfig.owned(
            save_history=False,
            initial_size=(39, 143),
        ),
    )
    view = None
    try:
        pool.start(timeout=TIMEOUT)
        assert pool.current is None
        assert pool.ready == 1
        assert len(setup_records) == 1

        view = pool.console(
            ViewerConfig.external(launcher, reconnect=True),
            timeout=TIMEOUT,
        )
        assert pool.ready == 1
        assert len(setup_records) == 2

        first = view.current
        first_generation = view.generation
        first_pid = first.transport.proc.pid
        bridge_pid = view.viewer_process.pid
        assert first.state is GdbState.PREPARED
        assert first.target is None
        assert setup_records[0] == (first_pid, first)

        os.write(launcher.master, b"echo first-pool-ready\n")
        first_output = _read_until(
            launcher.master,
            f"(pool-{first_pid})".encode(),
        )
        assert b"first-pool-ready" in first_output

        # A literal terminal ^C is just input for the selected GDB.  A complete
        # round-trip afterwards proves the pool did not treat that byte as a
        # viewer lifecycle signal or select another process.
        os.write(launcher.master, b"\x03\nshow pagination\n")
        control_c_output = _read_until(launcher.master, b"State of pagination is")
        assert b"show pagination" in control_c_output
        assert view.current is first
        assert view.generation == first_generation
        assert first.transport.proc.poll() is None

        # An out-of-band process kill becomes transport EOF and does retarget.
        os.kill(first_pid, signal.SIGKILL)
        assert first.wait_closed(TIMEOUT)
        assert first.transport.closed
        assert first.transport.terminal_reason

        replacement = view.wait_changed(first_generation, timeout=TIMEOUT)
        second = replacement.gdb
        second_pid = second.transport.proc.pid
        assert replacement.generation == first_generation + 1
        assert second is setup_records[1][1]
        assert second_pid != first_pid
        assert second.state is GdbState.PREPARED
        assert second.target is None
        assert view.viewer_process.pid == bridge_pid
        assert view.viewer_process.poll() is None

        os.write(launcher.master, b"echo replacement-pool-ready\n")
        replacement_output = _read_until(
            launcher.master,
            f"(pool-{second_pid})".encode(),
        )
        assert b"replacement-pool-ready" in replacement_output

        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        with setup_condition:
            assert setup_condition.wait_for(lambda: len(setup_records) >= 3, TIMEOUT)
        assert len(setup_records) == 3
        assert view.current is second
        assert pool.current is second

        # `q` takes the ordinary GDB command path.  The installed GDB-side
        # hook makes it a real process exit, and the pool again reacts only to
        # the resulting DAP EOF.
        os.write(launcher.master, b"q\n")
        assert second.wait_closed(TIMEOUT)
        assert second.transport.closed
        assert second.transport.terminal_reason

        third_selection = view.wait_changed(replacement.generation, timeout=TIMEOUT)
        third = third_selection.gdb
        third_pid = third.transport.proc.pid
        assert third_selection.generation == replacement.generation + 1
        assert third is setup_records[2][1]
        assert third_pid not in {first_pid, second_pid}
        assert third.state is GdbState.PREPARED
        assert third.target is None
        assert view.viewer_process.pid == bridge_pid

        os.write(launcher.master, b"show pagination\n")
        third_output = _read_until(
            launcher.master,
            f"(pool-{third_pid})".encode(),
        )
        assert b"State of pagination is" in third_output

        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        with setup_condition:
            assert setup_condition.wait_for(lambda: len(setup_records) >= 4, TIMEOUT)
        assert len(setup_records) == 4
        assert setup_records[-1][1].state is GdbState.PREPARED
        assert setup_records[-1][1].target is None
        assert view.current is third
        assert pool.current is third
    finally:
        if view is not None:
            view.close()
        pool.close()
        launcher.close()

    assert pool.closed
    assert launcher.proc is None or launcher.proc.poll() is not None


def test_live_endpoint_loss_waits_for_actual_gdb_eof_before_consuming_spare():
    _require_gdb()
    setup, setup_records, setup_condition = _targetless_setup_recorder("endpoint-loss")
    launcher = _PtyLauncher()
    pool = GdbPool(
        size=1,
        setup=setup,
        gdb_path=GDB_PATH,
        init=False,
        console=ConsoleConfig.owned(save_history=False),
    )
    view = None
    try:
        pool.start(timeout=TIMEOUT)
        view = pool.console(
            ViewerConfig.external(launcher, reconnect=True),
            timeout=TIMEOUT,
        )
        assert pool.ready == 1
        assert len(setup_records) == 2

        first = view.current
        generation = view.generation
        bridge_pid = view.viewer_process.pid
        spare = setup_records[1][1]
        assert first is setup_records[0][1]

        os.write(launcher.master, b"echo endpoint-before-loss\n")
        before = _read_until(launcher.master, setup_records[0][2])
        assert b"endpoint-before-loss" in before

        # Detaching the owned endpoint proves only that its routing socket was
        # lost.  The DAP process remains live and stays owned by this view.
        first.console_close()
        with pytest.raises(GdbPoolError, match="could not select") as caught:
            view.wait_changed(generation, timeout=TIMEOUT)
        endpoint_error = view.error
        assert caught.value.__cause__ is endpoint_error
        assert isinstance(endpoint_error, GdbPoolError)
        assert "endpoint was lost" in str(endpoint_error)
        assert view.current is None
        assert view.generation == generation
        assert pool.current is first
        assert pool.ready == 1
        assert len(setup_records) == 2
        assert spare is setup_records[1][1]
        assert not spare.closed
        assert not first.closed
        assert first.transport.proc.poll() is None
        assert first._console.endpoint_alive
        assert not first._console.viewer_connected
        assert view.viewer_process.pid == bridge_pid
        assert view.viewer_alive
        assert view._router.viewer_connected
        assert "gdb" in first.execute("show version").lower()

        # Only independent DAP terminal state authorizes consuming the spare.
        first.close()
        assert first.wait_closed(TIMEOUT)
        replacement = view.wait_changed(generation, timeout=TIMEOUT)
        assert replacement.gdb is spare
        assert replacement.generation == generation + 1
        assert pool.current is spare
        assert view.error is None
        assert view.viewer_process.pid == bridge_pid

        os.write(launcher.master, b"echo endpoint-after-eof\n")
        after = _read_until(launcher.master, setup_records[1][2])
        assert b"endpoint-after-eof" in after

        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        with setup_condition:
            assert setup_condition.wait_for(lambda: len(setup_records) >= 3, TIMEOUT)
        assert len(setup_records) == 3
        assert not setup_records[2][1].closed
    finally:
        if view is not None:
            view.close()
        pool.close()
        launcher.close()


def test_live_dead_bridge_preserves_spare_for_a_fresh_viewer_after_gdb_eof():
    _require_gdb()
    setup, setup_records, setup_condition = _targetless_setup_recorder("viewer-loss")
    first_launcher = _PtyLauncher()
    second_launcher = _PtyLauncher()
    pool = GdbPool(
        size=1,
        setup=setup,
        gdb_path=GDB_PATH,
        init=False,
        console=ConsoleConfig.owned(save_history=False),
    )
    view = None
    fresh = None
    try:
        pool.start(timeout=TIMEOUT)
        view = pool.console(
            ViewerConfig.external(first_launcher),
            timeout=TIMEOUT,
        )
        active = view.current
        generation = view.generation
        preserved_spare = setup_records[1][1]
        dead_bridge = view.viewer_process
        assert pool.ready == 1
        assert len(setup_records) == 2

        dead_bridge.kill()
        dead_bridge.wait(timeout=TIMEOUT)
        assert view.wait_viewer_disconnected(TIMEOUT)
        assert not view.viewer_alive
        assert view.current is active
        assert pool.current is active
        assert pool.ready == 1
        assert len(setup_records) == 2
        assert not preserved_spare.closed

        os.kill(active.transport.proc.pid, signal.SIGKILL)
        assert active.wait_closed(TIMEOUT)
        with pytest.raises(GdbPoolError, match="could not select") as caught:
            view.wait_changed(generation, timeout=TIMEOUT)
        assert isinstance(caught.value.__cause__, GdbPoolError)
        assert "no longer connected" in str(caught.value.__cause__)
        with pool._condition:
            assert pool._condition.wait_for(lambda: pool._active is None, TIMEOUT)
        assert view.current is None
        assert pool.current is None
        assert pool.ready == 1
        assert pool.last_error is None
        assert len(setup_records) == 2
        assert preserved_spare is setup_records[1][1]
        assert not preserved_spare.closed
        assert preserved_spare.state is GdbState.PREPARED

        view.close()
        assert view.closed
        assert pool.ready == 1
        assert len(setup_records) == 2
        first_launcher.close()

        fresh = pool.console(
            ViewerConfig.external(second_launcher),
            timeout=TIMEOUT,
        )
        assert fresh.current is preserved_spare
        assert fresh.generation == 1
        assert fresh.viewer_process.pid != dead_bridge.pid
        assert fresh.viewer_alive
        assert pool.current is preserved_spare
        assert pool.ready == 1

        with setup_condition:
            assert setup_condition.wait_for(lambda: len(setup_records) >= 3, TIMEOUT)
        assert len(setup_records) == 3
        assert setup_records[2][1] is not preserved_spare
        assert setup_records[2][1].state is GdbState.PREPARED

        os.write(second_launcher.master, b"echo fresh-viewer-kept-spare\n")
        output = _read_until(second_launcher.master, setup_records[1][2])
        assert b"fresh-viewer-kept-spare" in output
    finally:
        if fresh is not None:
            fresh.close()
        if view is not None:
            view.close()
        pool.close()
        first_launcher.close()
        second_launcher.close()


def test_live_detached_serve_selects_only_on_connection_and_reuses_its_socket(
    tmp_path,
):
    _require_gdb()
    setup, setup_records, setup_condition = _targetless_setup_recorder(
        "detached"
    )
    first_launcher = _PtyLauncher()
    second_launcher = _PtyLauncher()
    socket_path = tmp_path / "detached-pool.sock"
    pool = GdbPool(
        size=1,
        setup=setup,
        gdb_path=GDB_PATH,
        init=False,
        console=ConsoleConfig.owned(save_history=False),
    )
    view = None
    try:
        pool.start(timeout=TIMEOUT)
        view = pool.serve(socket_path=socket_path, timeout=TIMEOUT)
        assert view.selection is None
        assert view.viewer_process is None
        assert not view.viewer_connected
        assert pool.current is None
        assert pool.ready == 1
        assert len(setup_records) == 1
        assert view.socket_path == os.fspath(socket_path)
        assert view.address.source == "explicit"
        assert socket_path.is_socket()
        assert not (tmp_path / "pwnc.toml").exists()

        first_launcher.spawn(
            [
                sys.executable,
                "-c",
                VIEW_CLI,
                "gdb",
                "view",
                "--socket",
                os.fspath(view.socket_path),
            ]
        )
        first_selection = view.wait_selected(timeout=TIMEOUT)
        active = first_selection.gdb
        generation = first_selection.generation
        assert active is setup_records[0][1]
        assert view.viewer_connected
        assert view.viewer_alive
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(setup_records) == 2
        preserved_spare = setup_records[1][1]

        os.write(first_launcher.master, b"echo detached-first-viewer\n")
        first_output = _read_until(first_launcher.master, setup_records[0][2])
        assert b"detached-first-viewer" in first_output

        # The default viewer does not consume the spare when its selected GDB
        # dies. The pool sends a normal close frame, so the CLI exits cleanly
        # and restores its terminal while the durable listener stays up.
        os.write(first_launcher.master, b"q\n")
        assert active.wait_closed(TIMEOUT)
        assert first_launcher.proc.wait(timeout=TIMEOUT) == 0
        assert view.wait_viewer_disconnected(TIMEOUT)
        with pool._condition:
            assert pool._condition.wait_for(lambda: pool._active is None, TIMEOUT)
        assert view.current is None
        assert pool.current is None
        assert pool.ready == 1
        assert len(setup_records) == 2
        assert not preserved_spare.closed

        second_launcher.spawn(
            [
                sys.executable,
                "-c",
                VIEW_CLI,
                "gdb",
                "view",
                "--socket",
                os.fspath(view.socket_path),
            ]
        )
        assert view.wait_viewer_connected(TIMEOUT)
        replacement = view.wait_changed(generation, timeout=TIMEOUT)
        assert replacement.gdb is preserved_spare
        assert replacement.generation == generation + 1
        assert pool.current is preserved_spare
        assert view.viewer_connected
        assert view.viewer_process is None
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        with setup_condition:
            assert setup_condition.wait_for(lambda: len(setup_records) >= 3, TIMEOUT)
        assert len(setup_records) == 3

        os.write(second_launcher.master, b"echo detached-second-viewer\n")
        second_output = _read_until(second_launcher.master, setup_records[1][2])
        assert b"detached-second-viewer" in second_output
    finally:
        if view is not None:
            view.close()
        pool.close()
        first_launcher.close()
        second_launcher.close()

    assert not socket_path.exists()
    assert not (tmp_path / "pwnc.toml").exists()


def test_live_pool_configures_unmodified_bata24_gef_before_q_failover(
    exact_gef,
    tmp_path,
):
    environment, isolated_home, isolated_tmp = _isolated_environment(tmp_path)
    setup_records = []
    setup_condition = threading.Condition()

    def setup(gdb):
        assert gdb.state is GdbState.PREPARED
        assert gdb.target is None
        assert gdb._console is not None
        assert gdb._console.endpoint_alive
        assert not gdb._console.viewer_connected

        pid = gdb.transport.proc.pid
        assert os.fspath(isolated_home) in gdb.execute("show environment HOME")
        assert os.fspath(isolated_tmp) in gdb.execute("show environment TMPDIR")
        source_output = gdb.execute("source " + os.fspath(exact_gef))
        assert "GEF is ready" in source_output
        assert "Loaded " in source_output
        assert " commands (" in source_output
        for marker in (
            "Traceback (most recent call last)",
            "Error occurred in Python",
            "Python Exception",
            "Exception raised",
        ):
            assert marker not in source_output

        gdb.execute("set pagination off")
        gdb.execute("set confirm off")
        gdb.execute("gef config gef.disable_color True")
        gdb.execute(f"set $pwnc_pool_setup_pid = {pid}")
        probe_output = gdb.execute("gef missing")
        assert "No missing command" in probe_output

        with setup_condition:
            setup_records.append(
                {
                    "gdb": gdb,
                    "pid": pid,
                    "state": gdb.state,
                    "target": gdb.target,
                    "source_output": source_output,
                    "probe_output": probe_output,
                }
            )
            setup_condition.notify_all()

    def run_cli_gef(launcher):
        os.write(launcher.master, b"gef version --compact\n")
        output = _read_until(launcher.master, b"kernel:", timeout=TIMEOUT)
        assert b"gdb:" in output
        assert b"python:" in output
        assert b"OS:" in output
        assert b"Traceback (most recent call last)" not in output
        assert b"Python Exception" not in output
        return output

    launcher = _PtyLauncher()
    socket_path = tmp_path / "gef-detached-pool.sock"
    pool = GdbPool(
        size=1,
        setup=setup,
        gdb_path=GDB_PATH,
        env=environment,
        init=False,
        console=ConsoleConfig.owned(
            save_history=False,
            initial_size=(39, 143),
        ),
    )
    view = None
    try:
        pool.start(timeout=TIMEOUT)
        assert pool.current is None
        assert pool.ready == 1
        assert len(setup_records) == 1

        view = pool.serve(socket_path=socket_path, timeout=TIMEOUT)
        assert view.selection is None
        assert view.viewer_process is None
        launcher.spawn(
            [
                sys.executable,
                "-c",
                VIEW_CLI,
                "gdb",
                "view",
                "--socket",
                os.fspath(socket_path),
                "--reconnect",
            ]
        )
        first_selection = view.wait_selected(timeout=TIMEOUT)
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        with setup_condition:
            assert setup_condition.wait_for(lambda: len(setup_records) >= 2, TIMEOUT)
        assert len(setup_records) == 2

        first = first_selection.gdb
        first_generation = first_selection.generation
        first_pid = first.transport.proc.pid
        viewer_pid = launcher.proc.pid
        assert first is setup_records[0]["gdb"]
        assert first_pid == setup_records[0]["pid"]
        assert first.state is GdbState.PREPARED
        assert first.target is None
        assert view.viewer_process is None
        assert launcher.proc.poll() is None
        run_cli_gef(launcher)

        os.write(launcher.master, b"q\n")
        assert first.wait_closed(TIMEOUT)
        assert first.transport.closed
        assert first.transport.terminal_reason

        replacement = view.wait_changed(first_generation, timeout=TIMEOUT)
        second = replacement.gdb
        second_pid = second.transport.proc.pid
        assert replacement.generation == first_generation + 1
        assert second is setup_records[1]["gdb"]
        assert second_pid == setup_records[1]["pid"]
        assert second_pid != first_pid
        assert second.state is GdbState.PREPARED
        assert second.target is None
        assert view.viewer_process is None
        assert launcher.proc.pid == viewer_pid
        assert launcher.proc.poll() is None
        run_cli_gef(launcher)

        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        with setup_condition:
            assert setup_condition.wait_for(lambda: len(setup_records) >= 3, TIMEOUT)
        assert len(setup_records) == 3
        assert all(record["state"] is GdbState.PREPARED for record in setup_records)
        assert all(record["target"] is None for record in setup_records)
        assert all("GEF is ready" in record["source_output"] for record in setup_records)
        assert all("No missing command" in record["probe_output"] for record in setup_records)
        assert setup_records[2]["gdb"].state is GdbState.PREPARED
        assert setup_records[2]["gdb"].target is None
        assert view.current is second
        assert pool.current is second
    finally:
        if view is not None:
            view.close()
        pool.close()
        launcher.close()

    assert pool.closed
    assert not socket_path.exists()
    assert launcher.proc is None or launcher.proc.poll() is not None
    assert all(record["gdb"].closed for record in setup_records)
    assert all(record["gdb"].wait_closed(0) for record in setup_records)
