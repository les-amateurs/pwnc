"""Blocking client for an independently managed GDB pool viewer."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import threading
from contextlib import contextmanager

from ._process import wait_process
from .console import ViewerConfig, _spawn_terminal_bridge
from .discovery import PoolAddress, _os_error_reason, discover_viewer


class PoolConnectionError(RuntimeError):
    """A discovered GDB pool endpoint could not accept a viewer."""


def _address_source(address: PoolAddress) -> str:
    if address.source == "explicit":
        return "the explicit socket path"
    if address.source == "config" and address.config_path is not None:
        return f"[gdb.pool].socket in {address.config_path}"
    if address.config_path is not None:
        return f"pool discovery in {address.config_path}"
    return f"{address.source} discovery"


def _validate_connection_target(address: PoolAddress) -> None:
    """Reject a missing or non-socket rendezvous before mutating a terminal."""
    path = address.path
    source = _address_source(address)
    try:
        # Match Unix-domain connect semantics by following a caller-supplied
        # symlink. The actual connect still owns the unavoidable race after
        # this early, terminal-preserving diagnostic check.
        info = path.stat()
    except FileNotFoundError as error:
        raise PoolConnectionError(
            f"cannot connect to GDB pool {address.name!r}: no Unix socket exists "
            f"at {path} (resolved from {source}). Start the pool manager, verify "
            "the pool name, or pass the intended socket explicitly."
        ) from error
    except OSError as error:
        raise PoolConnectionError(
            f"cannot inspect the Unix socket for GDB pool {address.name!r} at "
            f"{path} (resolved from {source}): {_os_error_reason(error)}"
        ) from error
    if not stat.S_ISSOCK(info.st_mode):
        raise PoolConnectionError(
            f"cannot connect to GDB pool {address.name!r}: {path} exists but is "
            f"not a Unix socket (resolved from {source}). Remove the stale path "
            "or pass the intended socket explicitly."
        )


def _bridge_argv(socket_path, *, keep_open: bool, reconnect: bool) -> list[str]:
    bridge = os.path.join(os.path.dirname(__file__), "_console_bridge.py")
    argv = [sys.executable, bridge, os.fspath(socket_path)]
    if keep_open:
        argv.append("--keep-open")
    if reconnect:
        argv.append("--reconnect")
    return argv


def _stop_bridge(proc: subprocess.Popen) -> None:
    """Bounded cleanup for a bridge whose normal wait was interrupted."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        wait_process(proc, 2.0)
        return
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            return
    try:
        wait_process(proc, 2.0)
    except subprocess.TimeoutExpired:
        # There is nothing stronger than SIGKILL.  Keep terminal restoration
        # independent of a pathological wait implementation or unreaped child.
        pass


@contextmanager
def _forward_termination_signals(proc: subprocess.Popen):
    """Forward process-directed termination while the supervisor waits."""
    received: list[int] = []
    handlers = {}

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[signum] = signal.getsignal(signum)

            def forward(value, _frame, *, _proc=proc):
                received.append(value)
                try:
                    _proc.send_signal(value)
                except OSError:
                    pass

            signal.signal(signum, forward)
    try:
        yield received
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


def _exit_status(returncode: int, received: list[int]) -> int:
    if received:
        return 128 + received[0]
    if returncode < 0:
        return 128 - returncode
    return returncode


def view(
    socket_path=None,
    *,
    config_path=None,
    name: str = "default",
    keep_open: bool = False,
    reconnect: bool = False,
    tty=None,
) -> int:
    """Display a discovered pool and block until this viewer closes.

    Discovery is read-only.  With no explicit socket, the nearest existing
    ``pwnc.toml`` must contain either ``[pwnc].seed`` or
    ``[gdb.pool].socket``.  The bridge runs as a supervised child in the current
    terminal or *tty*.  Keeping the parent-side terminal snapshot alive lets us
    restore raw mode and descriptor flags even if that child is killed.
    """
    address = discover_viewer(
        name=name,
        socket_path=socket_path,
        config_path=config_path,
    )
    _validate_connection_target(address)
    viewer = (
        ViewerConfig.current(keep_open=keep_open, reconnect=reconnect)
        if tty is None
        else ViewerConfig.target(tty, keep_open=keep_open, reconnect=reconnect)
    )
    proc, snapshot = _spawn_terminal_bridge(
        _bridge_argv(
            address.path,
            keep_open=keep_open,
            reconnect=reconnect,
        ),
        viewer,
    )
    try:
        with _forward_termination_signals(proc) as received:
            return _exit_status(proc.wait(), received)
    finally:
        try:
            _stop_bridge(proc)
        finally:
            snapshot.restore()


__all__ = ["PoolConnectionError", "view"]
