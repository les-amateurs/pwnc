from __future__ import annotations

import os
import subprocess
import sys
import threading

import pytest

from pwnc.gdb.dap import _process
from pwnc.gdb.dap._process import wait_process


class _EventProcess:
    """Popen facade whose only wait primitive is an unbounded event wait."""

    args = ("event-process",)
    pid = -1

    def __init__(self, *, result: int = 23, error: BaseException | None = None):
        self.release = threading.Event()
        self.result = result
        self.error = error
        self.wait_calls = 0

    def poll(self):
        return self.result if self.release.is_set() and self.error is None else None

    def wait(self):
        self.wait_calls += 1
        self.release.wait()
        if self.error is not None:
            raise self.error
        return self.result


def test_portable_waiter_uses_one_blocking_wait_thread(monkeypatch):
    monkeypatch.setattr(_process, "_wait_pidfd", lambda _proc, _timeout: _process._PIDFD_UNAVAILABLE)
    proc = _EventProcess()

    with pytest.raises(subprocess.TimeoutExpired) as first:
        wait_process(proc, 0.01)
    with pytest.raises(subprocess.TimeoutExpired):
        wait_process(proc, 0.01)

    assert first.value.cmd == proc.args
    assert proc.wait_calls == 1

    proc.release.set()
    assert wait_process(proc, 1.0) == 23
    assert proc.wait_calls == 1


def test_portable_waiter_replays_wait_failure(monkeypatch):
    monkeypatch.setattr(_process, "_wait_pidfd", lambda _proc, _timeout: _process._PIDFD_UNAVAILABLE)
    failure = RuntimeError("wait failed")
    proc = _EventProcess(error=failure)
    proc.release.set()

    with pytest.raises(RuntimeError, match="wait failed") as raised:
        wait_process(proc, 1.0)
    assert raised.value is failure


@pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="Linux pidfd support is unavailable")
def test_pidfd_wait_is_bounded_without_popen_timeout(monkeypatch):
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
        stdin=subprocess.PIPE,
    )
    assert proc.stdin is not None
    real_wait = proc.wait
    calls = []

    def wait_without_timeout():
        calls.append(True)
        return real_wait()

    monkeypatch.setattr(proc, "wait", wait_without_timeout)
    monkeypatch.setattr(
        _process,
        "_thread_wait_state",
        lambda _proc: pytest.fail("pidfd wait unexpectedly used the thread fallback"),
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            wait_process(proc, 0.01)
        assert calls == []

        proc.stdin.close()
        assert wait_process(proc, 2.0) == 0
        assert calls == [True]
    finally:
        if proc.poll() is None:
            proc.kill()
        real_wait()


def test_zero_timeout_observes_an_already_completed_facade(monkeypatch):
    monkeypatch.setattr(_process, "_wait_pidfd", lambda _proc, _timeout: _process._PIDFD_UNAVAILABLE)
    proc = _EventProcess(result=7)
    proc.release.set()

    assert wait_process(proc, 0) == 7
    assert proc.wait_calls == 1
