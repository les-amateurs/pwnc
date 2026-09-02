"""Session-level serialization for public console creation."""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import types

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import DapError, Gdb
from pwnc.gdb.dap import console as console_module


class _Handle:
    def __init__(self):
        self.closed = False

    def alive(self):
        return not self.closed

    @property
    def endpoint_alive(self):
        return not self.closed

    def reuse(self, *_args, **_kwargs):
        return self

    def close(self):
        self.closed = True

    def _abort(self):
        self.close()


def _controller() -> Gdb:
    controller = object.__new__(Gdb)
    controller._closed = False
    controller._console = None
    controller._console_lock = threading.RLock()
    return controller


def test_concurrent_console_calls_create_exactly_one_endpoint(monkeypatch) -> None:
    controller = _controller()
    entered = threading.Event()
    release = threading.Event()
    handle = _Handle()
    calls = []
    results = []
    errors = []

    def start_console(*_args, **_kwargs):
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(5.0)
        return handle

    monkeypatch.setattr(console_module, "start_console", start_console)

    def open_console():
        try:
            results.append(Gdb.console(controller))
        except BaseException as error:  # noqa: BLE001 - thread observation
            errors.append(error)

    first = threading.Thread(target=open_console)
    second = threading.Thread(target=open_console)
    first.start()
    assert entered.wait(5.0)
    second.start()
    time.sleep(0.1)
    assert len(calls) == 1
    release.set()
    first.join(5.0)
    second.join(5.0)

    assert not first.is_alive() and not second.is_alive()
    assert not errors
    assert calls and len(calls) == 1
    assert results == [handle, handle]


def test_console_created_during_close_is_disposed_not_published(monkeypatch) -> None:
    controller = _controller()
    entered = threading.Event()
    release = threading.Event()
    handle = _Handle()
    errors = []

    def start_console(*_args, **_kwargs):
        entered.set()
        assert release.wait(5.0)
        return handle

    monkeypatch.setattr(console_module, "start_console", start_console)

    def open_console():
        try:
            Gdb.console(controller)
        except BaseException as error:  # noqa: BLE001 - thread observation
            errors.append(error)

    worker = threading.Thread(target=open_console)
    worker.start()
    assert entered.wait(5.0)
    controller._closed = True
    release.set()
    worker.join(5.0)

    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], DapError)
    assert handle.closed
    assert controller._console is None


def test_console_reuse_during_close_never_returns_a_stale_handle() -> None:
    controller = _controller()
    entered = threading.Event()
    release = threading.Event()
    handle = _Handle()
    controller._console = handle
    errors = []

    def reuse(*_args, **_kwargs):
        entered.set()
        assert release.wait(5.0)
        return handle

    handle.reuse = reuse

    def reconnect():
        try:
            Gdb.console(controller)
        except BaseException as error:  # noqa: BLE001 - thread observation
            errors.append(error)

    worker = threading.Thread(target=reconnect)
    worker.start()
    assert entered.wait(5.0)
    controller._closed = True
    release.set()
    worker.join(5.0)

    assert not worker.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], DapError)


def test_concurrent_close_waits_for_the_owning_close_to_finish() -> None:
    controller = object.__new__(Gdb)
    controller._closed = False
    controller._close_lock = threading.Lock()
    controller._close_done = threading.Event()
    controller._close_owner = None
    controller._close_error = None
    controller._event_state_lock = threading.Lock()
    controller._wait_terminal_queued = False
    controller._wait_terminal_reason = None
    controller._stops = queue.Queue()
    entered = threading.Event()
    release = threading.Event()
    returned = []

    def close_impl(_self):
        entered.set()
        assert release.wait(5.0)

    controller._close_impl = types.MethodType(close_impl, controller)

    first = threading.Thread(target=lambda: (Gdb.close(controller), returned.append(1)))
    second = threading.Thread(target=lambda: (Gdb.close(controller), returned.append(2)))
    first.start()
    assert entered.wait(5.0)
    second.start()
    time.sleep(0.1)
    assert returned == []
    release.set()
    first.join(5.0)
    second.join(5.0)

    assert not first.is_alive() and not second.is_alive()
    assert sorted(returned) == [1, 2]
