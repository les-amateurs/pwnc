"""Event-driven waiting for subprocess completion.

``subprocess.Popen.wait(timeout=...)`` uses a busy loop on POSIX.  DAP
lifecycles need the same synchronous, timeout-bounded interface without
periodic process-status probes, so this module waits for a kernel exit event
instead.  Linux uses a pidfd directly.  Other platforms use one daemon thread
per process to perform the ordinary blocking ``wait()`` and publish completion
through :class:`threading.Event`.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any

_PIDFD_UNAVAILABLE = object()


def _timeout_error(proc: Any, timeout: float | None) -> subprocess.TimeoutExpired:
    command = getattr(proc, "args", None)
    if command is None:
        command = getattr(proc, "pid", "child process")
    return subprocess.TimeoutExpired(command, timeout)


def _wait_pidfd(proc: Any, timeout: float | None):
    """Return a status, raise TimeoutExpired, or report unavailable."""
    pidfd_open = getattr(os, "pidfd_open", None)
    if pidfd_open is None:
        return _PIDFD_UNAVAILABLE
    try:
        pid = int(proc.pid)
        if pid <= 0:
            return _PIDFD_UNAVAILABLE
        pidfd = pidfd_open(pid, 0)
    except (AttributeError, OSError, TypeError, ValueError):
        return _PIDFD_UNAVAILABLE

    selector = selectors.DefaultSelector()
    try:
        selector.register(pidfd, selectors.EVENT_READ)
        ready = selector.select(timeout)
    except (OSError, ValueError):
        return _PIDFD_UNAVAILABLE
    finally:
        selector.close()
        os.close(pidfd)

    if not ready:
        # Resolve the exit-vs-deadline edge exactly once.  This is a one-shot
        # status observation, not a polling loop.
        status = proc.poll()
        if status is None:
            raise _timeout_error(proc, timeout)
        return status

    # Pidfd readability is level-triggered only once the process has exited,
    # so an unbounded wait here cannot stall.  It also performs the necessary
    # child reap and updates Popen.returncode.
    return proc.wait()


@dataclass(slots=True)
class _ThreadWait:
    done: threading.Event = field(default_factory=threading.Event)
    result: int | None = None
    error: BaseException | None = None


_thread_waits: weakref.WeakKeyDictionary[Any, _ThreadWait] = weakref.WeakKeyDictionary()
_thread_waits_lock = threading.Lock()


def _thread_wait_state(proc: Any) -> _ThreadWait:
    """Return the single fallback blocking waiter associated with *proc*."""
    def make_waiter() -> tuple[_ThreadWait, threading.Thread]:
        state = _ThreadWait()

        def reap() -> None:
            try:
                state.result = proc.wait()
            except BaseException as error:  # noqa: BLE001 - replay in caller
                state.error = error
            finally:
                state.done.set()

        thread = threading.Thread(
            target=reap,
            name=f"pwnc-child-wait-{getattr(proc, 'pid', 'unknown')}",
            daemon=True,
        )
        return state, thread

    try:
        weakref.ref(proc)
        hash(proc)
    except TypeError:
        # An unusual unhashable or non-weakrefable Popen facade cannot be
        # cached.  It still gets an event-driven bounded wait for this call.
        state, thread = make_waiter()
        thread.start()
        return state

    with _thread_waits_lock:
        state = _thread_waits.get(proc)
        if state is not None:
            return state
        state, thread = make_waiter()
        _thread_waits[proc] = state
        try:
            # Publish and start under the same lock so another caller can
            # never observe a cached state whose reaper failed to start.
            thread.start()
        except BaseException:
            del _thread_waits[proc]
            raise
        return state


def wait_process(proc: Any, timeout: float | None = None) -> int:
    """Synchronously wait for *proc* without a timeout polling loop.

    The result and :class:`subprocess.TimeoutExpired` behavior match
    ``Popen.wait`` closely.  ``proc`` may also be a Popen-compatible facade;
    such objects automatically use the portable blocking-thread path when
    their PID cannot be opened as a pidfd.
    """
    if timeout is not None:
        timeout = max(0.0, float(timeout))

    status = _wait_pidfd(proc, timeout)
    if status is not _PIDFD_UNAVAILABLE:
        return status

    state = _thread_wait_state(proc)
    if not state.done.wait(timeout):
        raise _timeout_error(proc, timeout)
    if state.error is not None:
        raise state.error
    assert state.result is not None
    return state.result


__all__ = ["wait_process"]
