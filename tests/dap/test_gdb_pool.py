"""Deterministic public-API and concurrency tests for prepared GDB pools."""

from __future__ import annotations

import itertools
import queue
import threading
from types import SimpleNamespace

import pytest

import pwnc.gdb.dap as dap
from pwnc.gdb.dap import (
    ConsoleConfig,
    GdbPool,
    GdbPoolError,
    GdbState,
    PoolConsole,
    PoolSelection,
    ViewerConfig,
)
from pwnc.gdb.dap import viewer as viewer_module
from pwnc.gdb.dap import pool as pool_module
from pwnc.gdb.dap import discovery as discovery_module


TIMEOUT = 10.0


class _FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.status = None

    def poll(self):
        return self.status

    def wait(self, timeout=None):
        del timeout
        return self.status


class _FakeTransport:
    def __init__(self, owner, pid):
        self.owner = owner
        self.proc = _FakeProcess(pid)
        self._lock = threading.Lock()
        self._listeners = []
        self.terminal_reason = None

    @property
    def closed(self):
        return self.owner.closed

    def add_terminal_listener(self, callback):
        with self._lock:
            if self.owner.closed:
                reason = self.terminal_reason or "transport already closed"
            else:
                self._listeners.append(callback)
                reason = None
        if reason is not None:
            callback(reason)

        def unsubscribe():
            with self._lock:
                try:
                    self._listeners.remove(callback)
                except ValueError:
                    return False
                return True

        return unsubscribe

    def terminate(self, reason="synthetic DAP EOF"):
        with self._lock:
            if self.owner.closed:
                return
            self.owner.closed = True
            self.owner.state = GdbState.CLOSED
            self.proc.status = 0
            self.terminal_reason = reason
            listeners = list(self._listeners)
            self._listeners.clear()
        self.owner._closed.set()
        for listener in listeners:
            listener(reason)


class _FakeEndpoint:
    def __init__(self, owner):
        self.owner = owner
        self.endpoint_alive = True
        self.viewer_connected = False


class _FakeGdb:
    def __init__(self, number):
        self.number = number
        self.state = GdbState.PREPARED
        self.target = None
        self.closed = False
        self._closed = threading.Event()
        self.transport = _FakeTransport(self, 10_000 + number)
        self.endpoint = _FakeEndpoint(self)
        self.console_calls = []
        self.execute_calls = []
        self.configured = False

    def console(self, config):
        self.console_calls.append(config)
        return self.endpoint

    def execute(self, command):
        self.execute_calls.append(command)
        return ""

    def wait_closed(self, timeout=None):
        return self._closed.wait(timeout)

    def close(self):
        self.transport.terminate("synthetic close")


class _GdbFactory:
    def __init__(self):
        self._condition = threading.Condition()
        self.created = []
        self.calls = []
        self.fail_calls = set()
        self.failure_entered = threading.Event()

    def __call__(self, **kwargs):
        on_created = kwargs.pop("_on_created", None)
        with self._condition:
            number = len(self.calls) + 1
            self.calls.append(dict(kwargs))
            self._condition.notify_all()
        if number in self.fail_calls:
            self.failure_entered.set()
            raise RuntimeError(f"synthetic spawn failure {number}")
        gdb = _FakeGdb(number)
        with self._condition:
            self.created.append(gdb)
            self._condition.notify_all()
        if on_created is not None:
            on_created(gdb)
        return gdb

    def wait_calls(self, count, timeout=TIMEOUT):
        with self._condition:
            return self._condition.wait_for(lambda: len(self.calls) >= count, timeout)


class _RouterFactory:
    def __init__(self):
        self.instances = []
        self._pids = itertools.count(20_000)
        self.start_entered = threading.Event()
        self.start_release = threading.Event()
        self.start_release.set()
        self.switched = threading.Event()
        self.detached_connect_on_start = False
        self.close_order = []

    def __call__(self, viewer, *, socket_path=None, listener=None):
        router = _FakeRouter(
            self,
            viewer,
            next(self._pids),
            socket_path=socket_path,
            listener=listener,
        )
        self.instances.append(router)
        return router


class _FakeRouter:
    def __init__(self, factory, viewer, pid, *, socket_path=None, listener=None):
        self.factory = factory
        self.viewer = viewer
        self.proc = None if viewer is None else _FakeProcess(pid)
        self.socket_path = socket_path
        self.listener = listener
        self.current = None
        self.generation = 0
        self.switches = []
        self.switch_timeouts = []
        self._listeners = []
        self._connection_listeners = []
        self._started = False
        self._closed = False
        self._viewer_connected = False
        self._viewer_reconnect = False
        self._viewer_condition = threading.Condition()
        self.close_viewer_reasons = []
        self.disconnect_on_switch = False
        self.fail_switch = False

    @property
    def viewer_process(self):
        return self.proc

    @property
    def viewer_alive(self):
        if self._viewer_connected:
            return True
        if self.proc is None:
            return False
        return self.proc.poll() is None

    @property
    def viewer_connected(self):
        with self._viewer_condition:
            return self._viewer_connected

    @property
    def viewer_reconnect(self):
        with self._viewer_condition:
            return self._viewer_connected and self._viewer_reconnect

    def wait_viewer_connected(self, timeout=None):
        with self._viewer_condition:
            if not self._viewer_condition.wait_for(lambda: self._viewer_connected, timeout):
                raise TimeoutError("synthetic viewer did not connect")
            return True

    def wait_viewer_disconnected(self, timeout=None):
        with self._viewer_condition:
            if not self._viewer_condition.wait_for(lambda: not self._viewer_connected, timeout):
                raise TimeoutError("synthetic viewer did not disconnect")
            return True

    @property
    def alive(self):
        return self._started and not self._closed

    def start(self, timeout=TIMEOUT):
        self.factory.start_entered.set()
        if not self.factory.start_release.wait(timeout):
            raise TimeoutError("synthetic viewer startup timeout")
        if self._closed:
            raise RuntimeError("synthetic viewer was closed during startup")
        self._started = True
        if self.viewer is not None:
            self.connect_viewer(reconnect=self.viewer.reconnect)
        elif self.factory.detached_connect_on_start:
            self.connect_viewer()
        return self

    def switch(self, endpoint, timeout=TIMEOUT):
        if not self.alive:
            raise RuntimeError("synthetic viewer is closed")
        if endpoint.owner.closed:
            raise RuntimeError("synthetic endpoint is closed")
        if self.disconnect_on_switch:
            self.disconnect_viewer()
            raise RuntimeError("synthetic viewer disconnected during switch")
        if self.fail_switch:
            raise RuntimeError("synthetic healthy endpoint switch failure")
        self.current = endpoint
        self.generation += 1
        self.switches.append(endpoint)
        self.switch_timeouts.append(timeout)
        self.factory.switched.set()

    def add_loss_listener(self, callback):
        self._listeners.append(callback)

        def unsubscribe():
            try:
                self._listeners.remove(callback)
            except ValueError:
                return False
            return True

        return unsubscribe

    def emit_loss(self, endpoint, reason="synthetic router EOF"):
        for listener in list(self._listeners):
            listener(endpoint, reason, self.generation)

    def add_connection_listener(self, callback):
        self._connection_listeners.append(callback)

        def unsubscribe():
            try:
                self._connection_listeners.remove(callback)
            except ValueError:
                return False
            return True

        return unsubscribe

    def connect_viewer(self, *, reconnect=False):
        with self._viewer_condition:
            self._viewer_connected = True
            self._viewer_reconnect = bool(reconnect)
            self._viewer_condition.notify_all()
        for listener in list(self._connection_listeners):
            listener(True, None)

    def disconnect_viewer(self, reason="synthetic viewer disconnected"):
        if self.proc is not None:
            self.proc.status = 0
        with self._viewer_condition:
            self._viewer_connected = False
            self._viewer_reconnect = False
            self._viewer_condition.notify_all()
        for listener in list(self._connection_listeners):
            listener(False, reason)

    def close_viewer(self, reason="selected GDB exited"):
        if not self.viewer_connected:
            return False
        self.close_viewer_reasons.append(str(reason))
        self.disconnect_viewer(reason)
        return True

    def close(self):
        if self._closed:
            return
        self._closed = True
        with self._viewer_condition:
            self._viewer_connected = False
            self._viewer_condition.notify_all()
        if self.proc is not None:
            self.proc.status = 0
        listener = self.listener
        if listener is not None:
            listener.close()
            self.listener = None
        self.factory.close_order.append("router")
        self.factory.start_release.set()


class _FakeListener:
    def __init__(self, order):
        self.order = order
        self.closed = False

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.order.append("listener")


class _FakeLease:
    def __init__(self, address, order):
        self.address = address
        self.path = address.path
        self.order = order
        self.closed = False
        self.duplicates = []

    def duplicate_socket(self):
        listener = _FakeListener(self.order)
        self.duplicates.append(listener)
        return listener

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.order.append("lease")


class _FakeDiscovery:
    def __init__(self, order):
        self.order = order
        self.discover_calls = []
        self.acquire_calls = []
        self.leases = []

    def discover_manager(self, name="default", *, socket_path=None, config_path=None):
        self.discover_calls.append(
            {
                "name": name,
                "socket_path": socket_path,
                "config_path": config_path,
            }
        )
        path = socket_path or f"/tmp/pwnc-{name}.sock"
        return SimpleNamespace(name=name, path=path, source="synthetic")

    def acquire_pool_socket(self, address):
        self.acquire_calls.append(address)
        lease = _FakeLease(address, self.order)
        self.leases.append(lease)
        return lease


@pytest.fixture
def fake_runtime(monkeypatch):
    gdbs = _GdbFactory()
    routers = _RouterFactory()
    monkeypatch.setattr(dap, "start", gdbs)
    monkeypatch.setattr(viewer_module, "ViewerRouter", routers)
    return gdbs, routers


@pytest.fixture
def fake_discovery(fake_runtime, monkeypatch):
    gdbs, routers = fake_runtime
    discovery = _FakeDiscovery(routers.close_order)
    monkeypatch.setattr(discovery_module, "discover_manager", discovery.discover_manager)
    monkeypatch.setattr(
        discovery_module,
        "acquire_pool_socket",
        discovery.acquire_pool_socket,
    )
    return gdbs, routers, discovery


def _open_fake_console(pool, *, reconnect=True):
    # Most legacy pool tests exercise the explicit seamless-failover mode.
    return pool.console(
        ViewerConfig.external(
            ["unused-by-fake-router"],
            reconnect=reconnect,
        ),
        timeout=TIMEOUT,
    )


def test_constructor_is_inert_validates_pool_specific_constraints_and_exports(fake_runtime):
    gdbs, _routers = fake_runtime

    assert dap.GdbPool is GdbPool
    assert dap.GdbPoolError is GdbPoolError
    assert dap.PoolConsole is PoolConsole
    assert dap.PoolSelection is PoolSelection
    with pytest.raises(TypeError, match="positive integer"):
        GdbPool(True)
    with pytest.raises(ValueError, match="positive"):
        GdbPool(0)
    with pytest.raises(TypeError, match="setup"):
        GdbPool(setup=object())
    with pytest.raises(TypeError, match="init"):
        GdbPool(init=1)
    with pytest.raises(ValueError, match="owned console"):
        GdbPool(console=ConsoleConfig.none())
    with pytest.raises(ValueError, match="must not embed a viewer"):
        GdbPool(
            console=ConsoleConfig.owned(
                viewer=ViewerConfig.external(["unused"]),
            )
        )

    pool = GdbPool(size=1)
    try:
        assert pool.init is True
        assert gdbs.calls == []
        assert pool.ready == 0
        assert pool.current is None
        with pytest.raises(GdbPoolError, match="start"):
            _open_fake_console(pool)
    finally:
        pool.close()


def test_serve_waits_for_connection_then_preserves_state_across_reconnect(
    fake_discovery,
):
    gdbs, routers, discovery = fake_discovery
    pool = GdbPool(size=1, switch_timeout=7.25).start(timeout=TIMEOUT)
    view = pool.serve(
        "arena",
        socket_path="/tmp/explicit-arena.sock",
        config_path="/ignored/by/explicit/socket/pwnc.toml",
        timeout=TIMEOUT,
    )
    router = routers.instances[0]
    lease = discovery.leases[0]
    try:
        assert discovery.discover_calls == [
            {
                "name": "arena",
                "socket_path": "/tmp/explicit-arena.sock",
                "config_path": "/ignored/by/explicit/socket/pwnc.toml",
            }
        ]
        assert discovery.acquire_calls == [view.address]
        assert view.address is lease.address
        assert view.socket_path == "/tmp/explicit-arena.sock"
        assert view.selection is None
        assert view.current is None
        assert view.viewer_process is None
        assert not view.viewer_connected
        assert not view.viewer_alive
        assert pool.current is None
        assert pool.ready == 1
        assert len(gdbs.calls) == 1
        assert gdbs.calls[0]["init"] is True
        assert router.viewer is None
        assert router.listener is lease.duplicates[0]

        # Connection callbacks are notification-only: even while the pool lock
        # is held, delivery returns after queueing and does not mutate state.
        callback_done = threading.Event()

        def connect():
            router.connect_viewer()
            callback_done.set()

        thread = threading.Thread(target=connect)
        with pool._condition:
            thread.start()
            assert callback_done.wait(TIMEOUT)
            assert view.selection is None
            assert pool.current is None
        thread.join(TIMEOUT)
        assert not thread.is_alive()

        first = view.wait_selected(timeout=TIMEOUT)
        assert first == PoolSelection(1, gdbs.created[0])
        assert view.wait_selected(timeout=0) == first
        assert view.viewer_connected
        assert view.viewer_alive
        assert router.switch_timeouts == [7.25]
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 2
        active = first.gdb
        spare = gdbs.created[1]

        router.disconnect_viewer("detached bridge went away")
        assert view.wait_viewer_disconnected(TIMEOUT)
        with view._condition:
            disconnected = view._condition.wait_for(
                lambda: isinstance(view._error, pool_module._ViewerDisconnectedError),
                TIMEOUT,
            )
        assert disconnected
        generation = view.generation
        assert view.current is active
        assert pool.current is active
        assert pool.ready == 1
        assert not spare.closed
        assert len(gdbs.calls) == 2

        router.connect_viewer()
        assert view.wait_viewer_connected(TIMEOUT)
        with view._condition:
            reconnected = view._condition.wait_for(
                lambda: view._error is None,
                TIMEOUT,
            )
        assert reconnected
        assert view.current is active
        assert view.generation == generation
        assert router.switches == [active.endpoint]
        assert pool.ready == 1

        # If the active GDB dies during another disconnected interval, the
        # exact spare remains ready until a later authenticated reconnect.
        router.disconnect_viewer("viewer offline during GDB death")
        with view._condition:
            assert view._condition.wait_for(lambda: view._error is not None, TIMEOUT)
        active.transport.terminate("active GDB exited while detached")
        with pool._condition:
            assert pool._condition.wait_for(lambda: pool._active is None, TIMEOUT)
        assert view.current is None
        assert pool.current is None
        assert pool.ready == 1
        assert len(gdbs.calls) == 2
        assert not spare.closed

        with view._condition:
            assert view._condition.wait_for(
                lambda: isinstance(view._error, pool_module._ViewerDisconnectedError),
                TIMEOUT,
            )

        # Both detached wait APIs treat viewer loss as a transient.  Enter
        # them while disconnected and prove they are sleeping on the
        # condition (rather than returning the sticky diagnostic) before the
        # viewer reconnects.
        waiter_started = {
            "changed": threading.Event(),
            "selected": threading.Event(),
        }
        waiter_outcomes = {}

        def wait_for_replacement(kind):
            try:
                # Holding the re-entrant condition while entering the public
                # API gives the test a deterministic handoff: the main thread
                # can reacquire it only after wait() releases it or the call
                # returns.
                with view._condition:
                    waiter_started[kind].set()
                    if kind == "changed":
                        outcome = view.wait_changed(generation, timeout=TIMEOUT)
                    else:
                        outcome = view.wait_selected(timeout=TIMEOUT)
                waiter_outcomes[kind] = outcome
            except BaseException as error:  # noqa: BLE001 - relay thread result
                waiter_outcomes[kind] = error

        waiters = [
            threading.Thread(target=wait_for_replacement, args=(kind,))
            for kind in waiter_started
        ]
        for waiter in waiters:
            waiter.start()
        for started in waiter_started.values():
            assert started.wait(TIMEOUT)
        with view._condition:
            assert len(view._condition._waiters) == len(waiters)

        router.connect_viewer()
        for waiter in waiters:
            waiter.join(TIMEOUT)
            assert not waiter.is_alive()

        replacement = PoolSelection(generation + 1, spare)
        assert waiter_outcomes == {
            "changed": replacement,
            "selected": replacement,
        }
        assert pool.current is spare
        assert view.error is None
        assert router.switch_timeouts == [7.25, 7.25]
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 3
    finally:
        view.close()
        pool.close()

    assert lease.closed
    assert routers.close_order[-2:] == ["router", "lease"]


def test_serve_handles_connection_before_attach_and_uses_default_discovery_name(
    fake_discovery,
):
    gdbs, routers, discovery = fake_discovery
    routers.detached_connect_on_start = True
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = pool.serve(timeout=TIMEOUT)
    lease = discovery.leases[0]
    try:
        selection = view.wait_selected(timeout=TIMEOUT)
        assert selection.gdb is gdbs.created[0]
        assert selection.generation == 1
        assert view.viewer_process is None
        assert view.viewer_connected
        assert view.socket_path == "/tmp/pwnc-default.sock"
        assert discovery.discover_calls == [
            {
                "name": "default",
                "socket_path": None,
                "config_path": None,
            }
        ]
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 2
    finally:
        view.close()
        pool.close()

    assert lease.closed


def test_close_interrupts_detached_listener_start_and_releases_discovery_lease(
    fake_discovery,
):
    _gdbs, routers, discovery = fake_discovery
    routers.start_release.clear()
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    outcome = []

    def serve():
        try:
            outcome.append(pool.serve(socket_path="/tmp/blocked.sock", timeout=TIMEOUT))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        assert routers.start_entered.wait(TIMEOUT)
        assert len(discovery.leases) == 1
        lease = discovery.leases[0]
        assert not lease.closed

        pool.close()
        thread.join(TIMEOUT)
        assert not thread.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], RuntimeError)
        assert "closed during startup" in str(outcome[0])
        assert pool.closed
        assert lease.closed
        assert routers.close_order[-2:] == ["router", "lease"]
    finally:
        routers.start_release.set()
        thread.join(TIMEOUT)
        pool.close()


def test_setup_is_serial_and_finishes_before_a_targetless_gdb_is_published(fake_runtime):
    gdbs, _routers = fake_runtime
    setup_entered = threading.Event()
    setup_release = threading.Event()
    completed = threading.Event()
    outcome = []

    def setup(gdb):
        assert gdb.state is GdbState.PREPARED
        assert gdb.target is None
        assert len(gdb.console_calls) == 1
        assert "define hook-quit" in gdb.execute_calls[0]
        setup_entered.set()
        assert setup_release.wait(TIMEOUT)
        gdb.configured = True

    pool = GdbPool(
        size=1,
        setup=setup,
        console=ConsoleConfig.owned(initial_size=(37, 131)),
        gdb_path="synthetic-gdb",
        gdb_args=("-q",),
        env={"POOL_TEST": "1"},
        init=False,
    )

    def start_pool():
        try:
            outcome.append(pool.start(timeout=TIMEOUT))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)
        finally:
            completed.set()

    thread = threading.Thread(target=start_pool)
    thread.start()
    try:
        assert setup_entered.wait(TIMEOUT)
        assert not completed.is_set()
        assert pool.ready == 0
        assert pool.current is None

        setup_release.set()
        assert completed.wait(TIMEOUT)
        thread.join(TIMEOUT)
        assert outcome == [pool]
        assert pool.ready == 1
        assert pool.start(timeout=TIMEOUT) is pool
        assert gdbs.created[0].configured
        assert gdbs.created[0].state is GdbState.PREPARED
        assert gdbs.created[0].target is None
        assert gdbs.calls == [
            {
                "gdb_path": "synthetic-gdb",
                "gdb_args": ("-q",),
                "env": {"POOL_TEST": "1"},
                "init": False,
                "console": pool.console_config,
            }
        ]
    finally:
        setup_release.set()
        thread.join(TIMEOUT)
        pool.close()

    assert gdbs.created[0].closed


def test_console_handoff_keeps_ready_reserve_and_transport_eof_selects_replacement(
    fake_runtime,
):
    gdbs, routers = fake_runtime

    def setup(gdb):
        gdb.configured = True

    pool = GdbPool(size=1, setup=setup).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    try:
        assert len(routers.instances) == 1
        router = routers.instances[0]
        bridge_pid = view.viewer_process.pid
        first = view.current
        first_generation = view.generation

        assert isinstance(view, PoolConsole)
        assert view.proc is view.viewer_process
        assert view.viewer_alive
        assert view.error is None
        assert first is gdbs.created[0]
        assert first.configured
        assert first.state is GdbState.PREPARED
        assert view.selection == PoolSelection(first_generation, first)
        assert tuple(view.selection) == (first_generation, first)
        assert pool.current is first
        assert pool.ready == 1
        assert len(gdbs.created) == 2

        # Both signals describe endpoint/process loss.  They must deduplicate to
        # one generation change; no terminal input byte is inspected here.
        first.transport.terminate("real transport EOF")
        router.emit_loss(first.endpoint, "same endpoint EOF")

        selection = view.wait_changed(first_generation, timeout=TIMEOUT)
        assert selection.generation == first_generation + 1
        assert selection.gdb is gdbs.created[1]
        assert selection.gdb.state is GdbState.PREPARED
        assert view.viewer_process.pid == bridge_pid
        assert router.switches[:2] == [first.endpoint, selection.gdb.endpoint]

        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.created) == 3
        assert view.generation == first_generation + 1
        assert pool.current is selection.gdb

        with pytest.raises(TypeError, match="generation"):
            view.wait_changed(True, timeout=0)
    finally:
        view.close()
        pool.close()

    assert view.closed
    assert all(gdb.closed for gdb in gdbs.created)


def test_default_viewer_closes_on_selected_gdb_death_and_fresh_viewer_gets_spare(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = _open_fake_console(pool, reconnect=False)
    try:
        router = routers.instances[0]
        active = view.current
        generation = view.generation
        preserved_spare = gdbs.created[1]

        assert not view.viewer_reconnect
        active.transport.terminate("normal selected GDB exit")
        assert view.wait_viewer_disconnected(TIMEOUT)
        with pool._condition:
            assert pool._condition.wait_for(lambda: pool._active is None, TIMEOUT)

        assert router.close_viewer_reasons == [
            "selected GDB exited: normal selected GDB exit"
        ]
        assert view.current is None
        assert pool.current is None
        assert pool.ready == 1
        assert not preserved_spare.closed
        assert router.switches == [active.endpoint]
        assert len(gdbs.calls) == 2

        # The durable listener remains available, but this is a new viewer
        # attachment rather than an automatic handoff in the old viewer.
        router.connect_viewer()
        with view._condition:
            assert view._condition.wait_for(
                lambda: view.current is preserved_spare,
                TIMEOUT,
            )
        replacement = view.selection
        assert replacement is not None
        assert replacement.generation == generation + 1
        assert replacement.gdb is preserved_spare
        assert router.switches == [active.endpoint, preserved_spare.endpoint]
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 3
    finally:
        view.close()
        pool.close()


def test_spawn_failure_degrades_once_then_explicit_replenish_recovers(fake_runtime):
    gdbs, _routers = fake_runtime
    gdbs.fail_calls.add(3)

    pool = GdbPool(size=1, setup=lambda gdb: setattr(gdb, "configured", True)).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    try:
        first_generation = view.generation
        view.current.transport.terminate("active process exited")
        replacement = view.wait_changed(first_generation, timeout=TIMEOUT)
        assert replacement.gdb is gdbs.created[1]
        assert gdbs.failure_entered.wait(TIMEOUT)

        with pytest.raises(GdbPoolError, match="degraded") as caught:
            pool.wait_ready(1, timeout=TIMEOUT)
        assert isinstance(caught.value.__cause__, RuntimeError)
        assert pool.last_error is caught.value.__cause__
        assert len(gdbs.calls) == 3

        pool.replenish()
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 4
        assert pool.last_error is None
        assert pool.current is replacement.gdb
    finally:
        view.close()
        pool.close()


def test_replenish_restores_a_viewer_that_lost_active_and_ready_gdbs(fake_runtime):
    gdbs, _routers = fake_runtime
    gdbs.fail_calls.add(3)

    pool = GdbPool(size=1, setup=lambda gdb: setattr(gdb, "configured", True)).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    try:
        generation = view.generation
        active = view.current
        ready = gdbs.created[1]

        ready.transport.terminate("ready process exited")
        assert gdbs.failure_entered.wait(TIMEOUT)
        with pytest.raises(GdbPoolError, match="degraded"):
            pool.wait_ready(1, timeout=TIMEOUT)

        active.transport.terminate("active process exited with no spare")
        with pytest.raises(GdbPoolError, match="could not select") as caught:
            view.wait_changed(generation, timeout=TIMEOUT)
        assert view.current is None
        assert view.error is not None
        assert isinstance(caught.value.__cause__, GdbPoolError)

        pool.replenish()
        replacement = view.wait_changed(generation, timeout=TIMEOUT)
        assert replacement.gdb is gdbs.created[2]
        assert replacement.gdb.configured
        assert view.error is None
        assert pool.current is replacement.gdb
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 5
    finally:
        view.close()
        pool.close()


def test_setup_failure_closes_partial_gdb_and_does_not_hot_loop(fake_runtime):
    gdbs, _routers = fake_runtime

    def fail_setup(_gdb):
        raise RuntimeError("setup rejected this GDB")

    pool = GdbPool(size=1, setup=fail_setup)
    with pytest.raises(GdbPoolError, match="fill") as caught:
        pool.start(timeout=TIMEOUT)

    assert isinstance(caught.value.__cause__, RuntimeError)
    assert "setup rejected" in str(caught.value.__cause__)
    assert len(gdbs.calls) == 1
    assert len(gdbs.created) == 1
    assert gdbs.created[0].closed
    assert pool.closed


def test_setup_returning_an_awaitable_is_rejected_and_closed(fake_runtime):
    gdbs, _routers = fake_runtime

    async def invalid_async_setup(_gdb):
        return None

    pool = GdbPool(size=1, setup=invalid_async_setup)
    with pytest.raises(GdbPoolError, match="fill") as caught:
        pool.start(timeout=TIMEOUT)

    assert isinstance(caught.value.__cause__, TypeError)
    assert "must be synchronous" in str(caught.value.__cause__)
    assert len(gdbs.calls) == 1
    assert gdbs.created[0].closed
    assert pool.closed


def test_setup_cannot_publish_an_owned_endpoint_leased_to_another_viewer(
    fake_runtime,
):
    gdbs, _routers = fake_runtime

    def invalid_setup(gdb):
        gdb.endpoint.viewer_connected = True

    pool = GdbPool(size=1, setup=invalid_setup)
    with pytest.raises(GdbPoolError, match="fill") as caught:
        pool.start(timeout=TIMEOUT)

    assert isinstance(caught.value.__cause__, GdbPoolError)
    assert "attached a viewer" in str(caught.value.__cause__)
    assert len(gdbs.calls) == 1
    assert gdbs.created[0].closed
    assert pool.closed


def test_router_endpoint_loss_waits_for_real_transport_death_before_failover(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    try:
        router = routers.instances[0]
        first = view.current
        generation = view.generation
        spare = gdbs.created[1]

        router.emit_loss(first.endpoint, "routing socket EOF")

        assert view.current is None
        assert view.generation == generation
        assert isinstance(view.error, GdbPoolError)
        assert pool.current is first
        assert not first.closed
        assert pool.ready == 1
        assert len(gdbs.calls) == 2
        assert router.switches == [first.endpoint]
        endpoint_error = view.error
        pool.replenish()
        assert view.error is endpoint_error
        assert len(gdbs.calls) == 2
        with pytest.raises(GdbPoolError, match="could not select") as caught:
            view.wait_changed(generation, timeout=TIMEOUT)
        assert caught.value.__cause__ is view.error

        # The independent DAP terminal notification is the point at which the
        # pool is allowed to consume the spare and retarget the viewer.
        first.transport.terminate("real GDB process EOF")
        replacement = view.wait_changed(generation, timeout=TIMEOUT)
        assert replacement.gdb is spare
        assert pool.current is spare
        assert view.error is None
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 3
    finally:
        view.close()
        pool.close()


def test_late_coordinator_status_cannot_clear_a_closed_view_error(fake_runtime):
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    view.close()
    try:
        closed_error = view.error
        assert isinstance(closed_error, GdbPoolError)

        view._resume()
        view._fail(RuntimeError("late coordinator failure"))

        assert view.closed
        assert view.error is closed_error
        with pytest.raises(GdbPoolError, match="closed"):
            view.wait_changed(timeout=TIMEOUT)
    finally:
        pool.close()


def test_dead_bridge_does_not_spawn_or_discard_replacements_after_gdb_death(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    fresh = None
    try:
        router = routers.instances[0]
        first = view.current
        generation = view.generation
        preserved_spare = gdbs.created[1]

        router.disconnect_viewer()
        first.transport.terminate("active GDB exited after viewer disappeared")

        with pytest.raises(GdbPoolError, match="could not select") as caught:
            view.wait_changed(generation, timeout=TIMEOUT)
        assert isinstance(caught.value.__cause__, GdbPoolError)
        assert "no longer connected" in str(caught.value.__cause__)
        assert view.current is None
        assert pool.current is None
        assert pool.ready == 1
        assert len(gdbs.calls) == 2
        assert not preserved_spare.closed

        # Closing only the degraded viewer leaves its unconsumed reserve
        # available to a new durable bridge.
        view.close()
        fresh = _open_fake_console(pool)
        assert fresh.current is preserved_spare
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 3
    finally:
        if fresh is not None:
            fresh.close()
        view.close()
        pool.close()


def test_viewer_loss_racing_switch_restores_candidate_without_refill_churn(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    fresh = None
    try:
        router = routers.instances[0]
        generation = view.generation
        candidate = gdbs.created[1]
        router.disconnect_on_switch = True

        view.current.transport.terminate("active GDB exited at viewer-loss race")
        with pytest.raises(GdbPoolError, match="could not select"):
            view.wait_changed(generation, timeout=TIMEOUT)

        assert pool.ready == 1
        assert len(gdbs.calls) == 2
        assert not candidate.closed

        view.close()
        fresh = _open_fake_console(pool)
        assert fresh.current is candidate
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 3
    finally:
        if fresh is not None:
            fresh.close()
        view.close()
        pool.close()


def test_healthy_endpoint_switch_failure_degrades_once_until_replenished(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    try:
        router = routers.instances[0]
        generation = view.generation
        failed_candidate = gdbs.created[1]
        router.fail_switch = True

        view.current.transport.terminate("active GDB exited before routing fault")
        with pytest.raises(GdbPoolError, match="could not select") as caught:
            view.wait_changed(generation, timeout=TIMEOUT)

        assert "could not route" in str(caught.value.__cause__)
        assert isinstance(pool.last_error, RuntimeError)
        assert failed_candidate.closed
        assert pool.ready == 0
        assert len(gdbs.calls) == 2

        router.fail_switch = False
        pool.replenish()
        replacement = view.wait_changed(generation, timeout=TIMEOUT)
        assert replacement.gdb is gdbs.created[2]
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.calls) == 4
    finally:
        view.close()
        pool.close()


def test_ready_death_during_viewer_startup_is_replaced_without_coordinator_failure(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    pool = GdbPool(size=1, setup=lambda gdb: setattr(gdb, "configured", True)).start(timeout=TIMEOUT)
    routers.start_release.clear()
    outcome = []

    def open_console():
        try:
            outcome.append(_open_fake_console(pool))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)

    thread = threading.Thread(target=open_console)
    thread.start()
    try:
        assert routers.start_entered.wait(TIMEOUT)
        gdbs.created[0].transport.terminate("ready GDB died during viewer startup")
        assert gdbs.wait_calls(2, timeout=TIMEOUT)

        routers.start_release.set()
        thread.join(TIMEOUT)
        assert not thread.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], PoolConsole), outcome
        view = outcome[0]
        assert view.current is gdbs.created[1]
        assert view.current.configured
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.created) == 3
    finally:
        routers.start_release.set()
        thread.join(TIMEOUT)
        if outcome and isinstance(outcome[0], PoolConsole):
            outcome[0].close()
        pool.close()


def test_view_publication_and_attach_queueing_are_atomic_with_ready_death(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    attach_put_entered = threading.Event()
    attach_put_release = threading.Event()

    class BlockingAttachQueue(queue.Queue):
        def put(self, item, block=True, timeout=None):
            if isinstance(item, pool_module._Attach):
                attach_put_entered.set()
                assert attach_put_release.wait(TIMEOUT)
            return super().put(item, block, timeout)

    pool = GdbPool(size=1, setup=lambda gdb: setattr(gdb, "configured", True))
    pool._events = BlockingAttachQueue()
    pool.start(timeout=TIMEOUT)
    outcome = []

    def open_console():
        try:
            outcome.append(_open_fake_console(pool))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)

    thread = threading.Thread(target=open_console)
    thread.start()
    try:
        assert attach_put_entered.wait(TIMEOUT)

        # console() holds the pool lock while publishing its PoolConsole and
        # queueing _Attach.  Even though terminal delivery itself is lock-free,
        # the coordinator cannot publish a replacement into a half-attached
        # view while this queue insertion is paused.
        gdbs.created[0].transport.terminate("ready process exited in attach window")
        assert not routers.switched.is_set()

        attach_put_release.set()
        thread.join(TIMEOUT)
        assert not thread.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], PoolConsole), outcome
        view = outcome[0]
        assert view.current is gdbs.created[1]
        assert view.generation == 1
        assert pool.wait_ready(1, timeout=TIMEOUT) == 1
        assert len(gdbs.created) == 3
    finally:
        attach_put_release.set()
        thread.join(TIMEOUT)
        if outcome and isinstance(outcome[0], PoolConsole):
            outcome[0].close()
        pool.close()


def test_close_during_blocked_setup_closes_constructing_gdb_and_wakes_start(
    fake_runtime,
):
    gdbs, _routers = fake_runtime
    setup_entered = threading.Event()
    setup_release = threading.Event()
    start_outcome = []

    def setup(_gdb):
        setup_entered.set()
        assert setup_release.wait(TIMEOUT)

    pool = GdbPool(size=1, setup=setup)

    def start_pool():
        try:
            start_outcome.append(pool.start(timeout=TIMEOUT))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            start_outcome.append(error)

    start_thread = threading.Thread(target=start_pool)
    close_thread = threading.Thread(target=pool.close)
    start_thread.start()
    try:
        assert setup_entered.wait(TIMEOUT)
        assert len(gdbs.created) == 1
        close_thread.start()

        # close() actively terminates a GDB whose synchronous setup hook has
        # not returned; it does not wait for setup before initiating teardown.
        assert gdbs.created[0].wait_closed(TIMEOUT)
        setup_release.set()
        start_thread.join(TIMEOUT)
        close_thread.join(TIMEOUT)
        assert not start_thread.is_alive()
        assert not close_thread.is_alive()
        assert len(start_outcome) == 1
        assert isinstance(start_outcome[0], GdbPoolError)
        assert pool.closed
        assert pool.current is None
        assert pool.ready == 0
    finally:
        setup_release.set()
        start_thread.join(TIMEOUT)
        if close_thread.ident is not None:
            close_thread.join(TIMEOUT)
        pool.close()


def test_close_during_blocked_viewer_start_wakes_console_and_closes_partial_router(
    fake_runtime,
):
    gdbs, routers = fake_runtime
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    routers.start_release.clear()
    outcome = []

    def open_console():
        try:
            outcome.append(_open_fake_console(pool))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            outcome.append(error)

    thread = threading.Thread(target=open_console)
    thread.start()
    try:
        assert routers.start_entered.wait(TIMEOUT)
        pool.close()
        assert pool.closed
        assert gdbs.created[0].closed

        thread.join(TIMEOUT)
        assert not thread.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], RuntimeError)
        assert "closed during startup" in str(outcome[0])
        assert len(routers.instances) == 1
        assert not routers.instances[0].alive
        assert routers.instances[0].proc.poll() is not None
    finally:
        routers.start_release.set()
        thread.join(TIMEOUT)
        pool.close()


def test_worker_start_failure_transactionally_stops_the_started_peer(
    fake_runtime,
    monkeypatch,
):
    del fake_runtime
    real_thread = threading.Thread
    constructed = []

    class BrokenThread:
        ident = None

        def start(self):
            raise RuntimeError("synthetic thread-start failure")

        def is_alive(self):
            return False

        def join(self, timeout=None):
            del timeout

    def thread_factory(*args, **kwargs):
        if constructed:
            thread = BrokenThread()
        else:
            thread = real_thread(*args, **kwargs)
        constructed.append(thread)
        return thread

    monkeypatch.setattr(pool_module.threading, "Thread", thread_factory)
    pool = GdbPool(size=1)
    with pytest.raises(GdbPoolError, match="workers") as caught:
        pool.start(timeout=TIMEOUT)

    assert isinstance(caught.value.__cause__, RuntimeError)
    assert pool.closed
    assert len(constructed) == 2
    assert not constructed[0].is_alive()


def test_pool_and_view_selection_publish_as_one_snapshot(fake_runtime, monkeypatch):
    _gdbs, _routers = fake_runtime
    publish_entered = threading.Event()
    publish_release = threading.Event()
    original_publish = PoolConsole._publish

    def blocked_publish(view, gdb):
        publish_entered.set()
        assert publish_release.wait(TIMEOUT)
        return original_publish(view, gdb)

    monkeypatch.setattr(PoolConsole, "_publish", blocked_publish)
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    console_outcome = []

    def open_console():
        try:
            console_outcome.append(_open_fake_console(pool))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            console_outcome.append(error)

    console_thread = threading.Thread(target=open_console)
    console_thread.start()
    reader_started = threading.Event()
    reader_done = threading.Event()
    observed = []

    def read_pool_current():
        reader_started.set()
        observed.append(pool.current)
        reader_done.set()

    reader_thread = threading.Thread(target=read_pool_current)
    try:
        assert publish_entered.wait(TIMEOUT)
        reader_thread.start()
        assert reader_started.wait(TIMEOUT)
        # _publish is deliberately blocked while holding the pool condition;
        # pool.current cannot expose the new GDB ahead of view.selection.
        assert not reader_done.wait(0.05)

        publish_release.set()
        console_thread.join(TIMEOUT)
        reader_thread.join(TIMEOUT)
        assert not console_thread.is_alive()
        assert not reader_thread.is_alive()
        assert len(console_outcome) == 1
        assert isinstance(console_outcome[0], PoolConsole), console_outcome
        view = console_outcome[0]
        assert observed == [view.current]
        assert pool.current is view.current
        assert view.selection == PoolSelection(view.generation, pool.current)
    finally:
        publish_release.set()
        console_thread.join(TIMEOUT)
        if reader_thread.ident is not None:
            reader_thread.join(TIMEOUT)
        if console_outcome and isinstance(console_outcome[0], PoolConsole):
            console_outcome[0].close()
        pool.close()


def test_detach_admission_cannot_be_stranded_behind_pool_stop(fake_runtime):
    del fake_runtime
    detach_put_entered = threading.Event()
    detach_put_release = threading.Event()

    class BlockingDetachQueue(queue.Queue):
        def put(self, item, block=True, timeout=None):
            if isinstance(item, pool_module._Detach):
                detach_put_entered.set()
                assert detach_put_release.wait(TIMEOUT)
            return super().put(item, block, timeout)

    pool = GdbPool(size=1)
    pool._events = BlockingDetachQueue()
    pool.start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    detach_thread = threading.Thread(target=view.close)
    close_done = threading.Event()

    def close_pool():
        pool.close()
        close_done.set()

    close_thread = threading.Thread(target=close_pool)
    detach_thread.start()
    try:
        assert detach_put_entered.wait(TIMEOUT)
        close_thread.start()
        # detach queueing owns the pool condition, so STOP cannot overtake it.
        assert not close_done.wait(0.05)

        detach_put_release.set()
        detach_thread.join(TIMEOUT)
        close_thread.join(TIMEOUT)
        assert not detach_thread.is_alive()
        assert not close_thread.is_alive()
        assert pool.closed
        assert view.closed
        assert not pool._coordinator.is_alive()
    finally:
        detach_put_release.set()
        detach_thread.join(TIMEOUT)
        if close_thread.ident is not None:
            close_thread.join(TIMEOUT)
        pool.close()


def test_start_timeout_closes_gdb_owned_before_initialization_returns(monkeypatch):
    created = []

    def blocking_start(**kwargs):
        on_created = kwargs.pop("_on_created")
        gdb = _FakeGdb(1)
        created.append(gdb)
        on_created(gdb)
        # Model a real initialization request: closing the nascent controller
        # interrupts its transport and lets this lane return.
        assert gdb.wait_closed(TIMEOUT)
        raise RuntimeError("synthetic initialization interrupted")

    monkeypatch.setattr(dap, "start", blocking_start)
    pool = GdbPool(size=1)
    with pytest.raises(GdbPoolError, match="fill"):
        pool.start(timeout=0.05)

    assert len(created) == 1
    assert created[0].closed
    assert pool.closed
    assert not pool._spawner.is_alive()
    assert not pool._coordinator.is_alive()


def test_console_close_wakes_generation_waiter_and_pool_rejects_second_live_viewer(
    fake_runtime,
):
    _gdbs, _routers = fake_runtime
    pool = GdbPool(size=1).start(timeout=TIMEOUT)
    view = _open_fake_console(pool)
    result = []
    waiter_started = threading.Event()

    def wait_for_change():
        waiter_started.set()
        try:
            result.append(view.wait_changed(view.generation, timeout=TIMEOUT))
        except BaseException as error:  # noqa: BLE001 - relay thread result
            result.append(error)

    thread = threading.Thread(target=wait_for_change)
    thread.start()
    try:
        assert waiter_started.wait(TIMEOUT)
        with pytest.raises(GdbPoolError, match="already has"):
            _open_fake_console(pool)
        view.close()
        thread.join(TIMEOUT)
        assert not thread.is_alive()
        assert len(result) == 1
        assert isinstance(result[0], GdbPoolError)
        assert "closed while waiting" in str(result[0])
    finally:
        view.close()
        thread.join(TIMEOUT)
        pool.close()
