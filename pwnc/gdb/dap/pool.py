"""Event-driven pool of prepared GDBs with one persistent console viewer.

``GdbPool`` keeps a configured reserve of initialized GDB processes which have
not selected a target yet.  A displayed GDB is additional to that reserve.  If
the displayed GDB's DAP transport becomes terminal, its viewer closes by
default.  A viewer which explicitly enables reconnect is switched to a ready
process before the dead process is cleaned up.  The reserve is replenished in
the background either way.

There is no steady-state polling.  Transport terminal listeners only enqueue a
small event; the coordinator and spawner block on queues, and public waiters
block on conditions.
"""

from __future__ import annotations

import inspect
import math
import operator
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from .console import ConsoleConfig, ConsoleMode, ViewerConfig


_STOP = object()
_FILL = object()
_SPAWN = object()


class GdbPoolError(RuntimeError):
    """A prepared-GDB pool could not satisfy an operation."""


@dataclass(frozen=True, slots=True)
class PoolSelection:
    """Race-free snapshot of the GDB currently displayed by a pool console."""

    generation: int
    gdb: object

    def __iter__(self):
        yield self.generation
        yield self.gdb


@dataclass(eq=False, slots=True)
class _Slot:
    gdb: object
    endpoint: object
    unsubscribe: Callable[[], object] | None = None
    state: str = "spawning"
    dead: threading.Event = field(default_factory=threading.Event)
    dead_reason: str | None = None


class _EndpointLostError(GdbPoolError):
    """A routing-only loss whose selected GDB may subsequently terminate."""

    def __init__(self, slot: _Slot, reason: str):
        super().__init__("selected GDB console endpoint was lost while its DAP transport remains alive")
        self.slot = slot
        self.__cause__ = RuntimeError(str(reason))


class _ViewerDisconnectedError(GdbPoolError):
    """A viewer left while the pool and prepared GDBs stay live."""

    def __init__(self, reason: str | None = None, cause: BaseException | None = None):
        super().__init__("pool console viewer is no longer connected")
        if cause is not None:
            self.__cause__ = cause
        elif reason:
            self.__cause__ = RuntimeError(str(reason))


@dataclass(slots=True)
class _Spawned:
    slot: _Slot | None = None
    error: BaseException | None = None


@dataclass(slots=True)
class _Dead:
    slot: _Slot
    reason: str


@dataclass(slots=True)
class _ViewerConnection:
    view: "PoolConsole"
    connected: bool
    reason: str | None


@dataclass(slots=True)
class _Attach:
    view: "PoolConsole"
    deadline: float | None
    done: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None


@dataclass(slots=True)
class _Detach:
    view: "PoolConsole"
    done: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None


def _deadline(timeout) -> float | None:
    if timeout is None:
        return None
    if isinstance(timeout, bool):
        raise TypeError("timeout must be a nonnegative real number or None")
    try:
        value = float(timeout)
    except (TypeError, ValueError) as error:
        raise TypeError("timeout must be a nonnegative real number or None") from error
    if value < 0:
        raise ValueError("timeout cannot be negative")
    if not math.isfinite(value):
        raise ValueError("timeout must be finite; use None for no deadline")
    return time.monotonic() + value


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("GDB pool operation timed out")
    return value


def _switch_timeout(deadline: float | None, fallback: float) -> float:
    remaining = _remaining(deadline)
    return fallback if remaining is None else remaining


def _duration(value, name: str) -> float:
    if value is None or isinstance(value, bool):
        raise TypeError(f"{name} must be a nonnegative finite real number")
    try:
        value = float(value)
    except (TypeError, ValueError) as error:
        raise TypeError(f"{name} must be a nonnegative finite real number") from error
    if value < 0:
        raise ValueError(f"{name} cannot be negative")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


class PoolConsole:
    """Stable terminal viewer whose selected GDB changes by generation."""

    def __init__(self, pool: "GdbPool", router, *, detached=False, lease=None):
        self._pool = pool
        self._router = router
        self._detached = bool(detached)
        self._lease = lease
        self._condition = threading.Condition()
        self._current = None
        self._generation = 0
        self._error: BaseException | None = None
        self._closed = False
        self._loss_unsubscribe = router.add_loss_listener(self._on_router_loss)
        self._connection_unsubscribe = router.add_connection_listener(
            self._on_viewer_connection
        )

    def _on_router_loss(self, endpoint, reason, _router_generation) -> None:
        self._pool._router_lost(self, endpoint, reason)

    def _on_viewer_connection(self, connected, reason) -> None:
        # Router notification lanes never mutate pool/view state.  The sole
        # coordinator serializes this transition with spawn, death, and detach.
        self._pool._viewer_connection(self, bool(connected), reason)

    @property
    def current(self):
        with self._condition:
            return self._current

    @property
    def generation(self) -> int:
        with self._condition:
            return self._generation

    @property
    def selection(self) -> PoolSelection | None:
        with self._condition:
            if self._current is None:
                return None
            return PoolSelection(self._generation, self._current)

    @property
    def viewer_process(self):
        return self._router.viewer_process

    @property
    def proc(self):
        return self._router.proc

    @property
    def viewer_alive(self) -> bool:
        return self._router.viewer_alive

    @property
    def viewer_connected(self) -> bool:
        return self._router.viewer_connected

    @property
    def viewer_reconnect(self) -> bool:
        """Whether the connected viewer opted into automatic pool failover."""
        return self._router.viewer_reconnect

    def wait_viewer_connected(self, timeout=None) -> bool:
        """Wait eventfully for a compatible standalone viewer to connect."""
        return self._router.wait_viewer_connected(timeout)

    def wait_viewer_disconnected(self, timeout=None) -> bool:
        """Wait eventfully for the current standalone viewer to disconnect."""
        return self._router.wait_viewer_disconnected(timeout)

    @property
    def socket_path(self):
        return self._router.socket_path

    @property
    def address(self):
        lease = self._lease
        return None if lease is None else lease.address

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    @property
    def error(self):
        """The error preventing selection, or ``None`` while healthy."""
        with self._condition:
            return self._error

    def _publish(self, gdb) -> PoolSelection:
        with self._condition:
            if self._closed:
                raise GdbPoolError("pool console is closed")
            self._current = gdb
            self._error = None
            self._generation += 1
            result = PoolSelection(self._generation, gdb)
            self._condition.notify_all()
            return result

    def _clear(self) -> None:
        with self._condition:
            self._current = None
            self._condition.notify_all()

    def _fail(self, error: BaseException) -> None:
        with self._condition:
            if self._closed:
                return
            self._error = error
            self._condition.notify_all()

    def _resume(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._error = None
            self._condition.notify_all()

    def _mark_closed(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._current = None
            self._error = GdbPoolError("pool console is closed")
            self._condition.notify_all()
        try:
            self._loss_unsubscribe()
        except Exception:
            pass
        unsubscribe = self._connection_unsubscribe
        self._connection_unsubscribe = None
        if unsubscribe is not None:
            try:
                unsubscribe()
            except Exception:
                pass
        lease, self._lease = self._lease, None
        if lease is not None:
            try:
                lease.close()
            except Exception:
                pass

    def wait_changed(self, previous_generation: int | None = None, timeout=None) -> PoolSelection:
        """Wait for and return the next selected ``(generation, gdb)`` snapshot.

        With no explicit generation, the generation current when this method is
        called is used.  Closure wakes the waiter with :class:`GdbPoolError`.
        """
        deadline = _deadline(timeout)
        with self._condition:
            if previous_generation is None:
                previous_generation = self._generation
            else:
                if isinstance(previous_generation, bool):
                    raise TypeError("generation must be an integer")
                previous_generation = operator.index(previous_generation)
            while self._generation <= previous_generation or self._current is None:
                if self._closed:
                    raise GdbPoolError("pool console closed while waiting")
                if self._error is not None:
                    if isinstance(self._error, _EndpointLostError) and (
                        self._error.slot.dead.is_set() or self._error.slot.gdb.closed
                    ):
                        # Endpoint EOF can precede the transport-terminal
                        # listener by a few instructions.  Once process death
                        # is independently known, wait eventfully for the
                        # already-queued DAP-authorized handoff rather than
                        # exposing the stale routing-only error.
                        self._condition.wait(_remaining(deadline))
                        continue
                    if isinstance(self._error, _ViewerDisconnectedError) and self._detached:
                        # A detached router remains available while its viewer
                        # is offline.  Keep its wait APIs pending until a
                        # reconnect selects a GDB, the console closes, or the
                        # caller's deadline expires.  ``error`` remains
                        # inspectable for callers that need connection state.
                        self._condition.wait(_remaining(deadline))
                        continue
                    raise GdbPoolError("pool console could not select a replacement GDB") from self._error
                self._condition.wait(_remaining(deadline))
            return PoolSelection(self._generation, self._current)

    def wait_selected(self, timeout=None) -> PoolSelection:
        """Return the current selection, waiting eventfully for the first one."""
        deadline = _deadline(timeout)
        with self._condition:
            while self._current is None:
                if self._closed:
                    raise GdbPoolError("pool console closed while waiting")
                if self._error is not None:
                    if isinstance(self._error, _EndpointLostError) and (
                        self._error.slot.dead.is_set() or self._error.slot.gdb.closed
                    ):
                        self._condition.wait(_remaining(deadline))
                        continue
                    if isinstance(self._error, _ViewerDisconnectedError) and self._detached:
                        self._condition.wait(_remaining(deadline))
                        continue
                    raise GdbPoolError("pool console could not select a GDB") from self._error
                self._condition.wait(_remaining(deadline))
            return PoolSelection(self._generation, self._current)

    def close(self) -> None:
        self._pool._detach_view(self)

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()


class GdbPool:
    """Maintain configured, targetless GDBs and optional console failover.

    ``size`` is the number of *ready spares*.  A GDB selected by the viewer is
    additional, so ``size=1`` still maintains one warm failover process after
    the initial handoff has replenished.

    ``setup(gdb)`` is synchronous and runs exactly once in the spawn lane after
    GDB initialization and owned-console creation, but before publication.
    ``init=True`` gives every process normal GDB initialization; ``False``
    passes ``-nx`` before the setup hook runs.
    """

    def __init__(
        self,
        size=1,
        *,
        setup=None,
        console=None,
        gdb_path="gdb",
        gdb_args=None,
        env=None,
        init=True,
        switch_timeout=10.0,
    ):
        if isinstance(size, bool):
            raise TypeError("pool size must be a positive integer")
        try:
            size = operator.index(size)
        except TypeError as error:
            raise TypeError("pool size must be a positive integer") from error
        if size <= 0:
            raise ValueError("pool size must be positive")
        if setup is not None and not callable(setup):
            raise TypeError("setup must be callable or None")
        if type(init) is not bool:
            raise TypeError("init must be True or False")
        if console is None:
            console = ConsoleConfig.owned()
        if not isinstance(console, ConsoleConfig):
            raise TypeError("console must be a ConsoleConfig")
        if console.mode is not ConsoleMode.OWNED:
            raise ValueError("a GDB pool requires an owned console configuration")
        if console.viewer is not None:
            raise ValueError("pooled GDB consoles must not embed a viewer")
        switch_timeout = _duration(switch_timeout, "switch_timeout")

        self.size = size
        self.setup = setup
        self.console_config = console
        self.gdb_path = gdb_path
        self.gdb_args = None if gdb_args is None else tuple(gdb_args)
        self.env = None if env is None else dict(env)
        self.init = init
        self.switch_timeout = switch_timeout

        self._condition = threading.Condition(threading.RLock())
        self._close_lock = threading.Lock()
        self._events: queue.Queue = queue.Queue()
        self._spawn_requests: queue.Queue = queue.Queue()
        self._ready = deque()
        self._slots: set[_Slot] = set()
        self._endpoint_slots: dict[int, _Slot] = {}
        self._active: _Slot | None = None
        self._view: PoolConsole | None = None
        self._view_starting = False
        self._starting_router = None
        self._waiting_attach: _Attach | None = None
        self._pending_spawns = 0
        self._constructing = None
        self._spawn_error: BaseException | None = None
        self._coordinator_error: BaseException | None = None
        self._started = False
        self._closing = False
        self._closed = False
        self._coordinator = None
        self._spawner = None

    @property
    def ready(self) -> int:
        with self._condition:
            return len(self._ready)

    @property
    def current(self):
        with self._condition:
            return None if self._active is None else self._active.gdb

    @property
    def last_error(self):
        with self._condition:
            return self._coordinator_error or self._spawn_error

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    def _ensure_reserve_locked(self) -> None:
        if self._closing or self._spawn_error is not None:
            return
        if len(self._ready) + self._pending_spawns >= self.size:
            return
        # One serial spawn lane is intentional: setup hooks may mutate shared
        # plugin/configuration state.  The active failover path never waits for
        # this lane while a ready spare exists.
        self._pending_spawns += 1
        self._spawn_requests.put(_SPAWN)

    def _install_console_quit(self, gdb) -> None:
        # GDB 15's DAP-owned secondary new-ui otherwise loses its prompt and
        # wedges when `quit` is entered.  This is a GDB command hook, not input
        # inspection: it turns quit/q into a real process exit, which is then
        # observed through the ordinary transport-terminal listener.  User
        # setup runs afterwards and may intentionally replace hook-quit.
        gdb.execute("define hook-quit\npython import os; os._exit(0)\nend")

    def _spawn_one(self) -> _Slot:
        # Lazy import avoids a package-initialization cycle when pool classes are
        # re-exported from pwnc.gdb.dap.
        from . import GdbState, start

        gdb = None
        slot = None
        try:

            def own_construction(created):
                nonlocal gdb
                gdb = created
                with self._condition:
                    self._constructing = created
                    closing = self._closing
                if closing:
                    raise GdbPoolError("GDB pool closed while spawning")

            gdb = start(
                gdb_path=self.gdb_path,
                gdb_args=self.gdb_args,
                env=self.env,
                init=self.init,
                console=self.console_config,
                _on_created=own_construction,
            )
            with self._condition:
                # Compatibility with an injected test/factory start callable
                # which accepts but does not implement the private early hook.
                self._constructing = gdb
                closing = self._closing
            if closing:
                raise GdbPoolError("GDB pool closed while spawning")
            endpoint = gdb.console(self.console_config)
            self._install_console_quit(gdb)
            if self.setup is not None:
                result = self.setup(gdb)
                if inspect.isawaitable(result):
                    close_awaitable = getattr(result, "close", None)
                    if close_awaitable is not None:
                        close_awaitable()
                    raise TypeError("pool setup must be synchronous; it returned an awaitable")
            if gdb.state is not GdbState.PREPARED or gdb.closed:
                raise GdbPoolError("pool setup did not leave GDB targetless and ready")
            if not endpoint.endpoint_alive:
                raise GdbPoolError("pool setup closed the owned console endpoint")
            if endpoint.viewer_connected:
                raise GdbPoolError("pool setup attached a viewer to the owned console endpoint")
            slot = _Slot(gdb, endpoint)

            def terminal(reason):
                slot.dead_reason = str(reason)
                slot.dead.set()
                self._events.put(_Dead(slot, str(reason)))

            slot.unsubscribe = gdb.transport.add_terminal_listener(terminal)
            with self._condition:
                self._constructing = None
                if self._closing:
                    raise GdbPoolError("GDB pool closed while spawning")
                self._slots.add(slot)
                self._endpoint_slots[id(endpoint)] = slot
            return slot
        except BaseException:
            with self._condition:
                if self._constructing is gdb:
                    self._constructing = None
            if slot is not None and slot.unsubscribe is not None:
                try:
                    slot.unsubscribe()
                except Exception:
                    pass
            if gdb is not None:
                try:
                    gdb.close()
                except Exception:
                    pass
            raise

    def _spawner_loop(self) -> None:
        while True:
            request = self._spawn_requests.get()
            if request is _STOP:
                return
            try:
                slot = self._spawn_one()
            except BaseException as error:
                with self._condition:
                    closing = self._closing
                if not closing:
                    self._events.put(_Spawned(error=error))
            else:
                with self._condition:
                    closing = self._closing
                if closing:
                    self._safe_close_slot(slot)
                else:
                    self._events.put(_Spawned(slot=slot))

    def _safe_close_slot(self, slot: _Slot) -> None:
        if slot.unsubscribe is not None:
            try:
                slot.unsubscribe()
            except Exception:
                pass
            slot.unsubscribe = None
        slot.state = "disposed"
        try:
            slot.gdb.close()
        except Exception:
            pass

    def _discard_slot_locked(self, slot: _Slot) -> None:
        try:
            self._ready.remove(slot)
        except ValueError:
            pass
        if self._active is slot:
            self._active = None
        self._slots.discard(slot)
        self._endpoint_slots.pop(id(slot.endpoint), None)
        slot.state = "disposed"

    def _publish_slot(self, view: PoolConsole, slot: _Slot, deadline) -> None:
        if slot.dead.is_set() or slot.gdb.closed:
            raise GdbPoolError(slot.dead_reason or "prepared GDB died before selection")
        if not view._router.alive:
            raise GdbPoolError("pool console viewer is not running")
        view._router.switch(
            slot.endpoint,
            timeout=_switch_timeout(deadline, self.switch_timeout),
        )
        if slot.dead.is_set() or slot.gdb.closed:
            raise GdbPoolError(slot.dead_reason or "prepared GDB died while selecting")
        with self._condition:
            if self._closing or slot not in self._slots:
                raise GdbPoolError("GDB pool closed while selecting a prepared GDB")
            if slot.dead.is_set() or slot.gdb.closed:
                raise GdbPoolError(slot.dead_reason or "prepared GDB died while selecting")
            slot.state = "active"
            self._active = slot
            # PoolConsole._publish takes only the view condition.  Keeping the
            # pool condition across it makes pool.current and the public
            # (generation, gdb) snapshot one atomic publication.
            view._publish(slot.gdb)

    @staticmethod
    def _viewer_usable(view: PoolConsole) -> bool:
        """Whether the durable bridge can commit a console switch right now."""
        router = view._router
        return router.alive and router.viewer_connected

    def _fail_viewer_selection(
        self,
        view: PoolConsole,
        command: _Attach | None,
        cause: BaseException | None = None,
    ) -> None:
        error = _ViewerDisconnectedError(cause=cause)
        view._fail(error)
        if command is not None:
            command.error = error
            if self._waiting_attach is command:
                self._waiting_attach = None
            command.done.set()

    def _try_assign_view(self) -> None:
        while True:
            with self._condition:
                view = self._view
                command = self._waiting_attach
                if self._closing or view is None or self._view_starting:
                    return
                # A freshly spawned slot can be published in the small window
                # between console() installing its PoolConsole and the queued
                # _Attach command reaching this coordinator.  In that case the
                # attach is already satisfied; acknowledge it instead of
                # leaving its caller asleep forever.
                if view.current is not None:
                    if command is not None:
                        self._waiting_attach = None
                        command.done.set()
                    return
                # Endpoint loss while the GDB process remains alive is a
                # sticky view error, not permission to consume another spare.
                # A later transport-terminal event clears it immediately
                # before process-death failover.
                if view.error is not None:
                    return
                if not self._viewer_usable(view):
                    self._fail_viewer_selection(view, command)
                    return
                if not self._ready:
                    if self._spawn_error is not None:
                        error = GdbPoolError("could not prepare a GDB for the pool console")
                        error.__cause__ = self._spawn_error
                        if command is not None:
                            command.error = error
                            self._waiting_attach = None
                            command.done.set()
                        else:
                            view._fail(error)
                    return
                slot = self._ready.popleft()
                slot.state = "selecting"
                deadline = None if command is None else command.deadline

            try:
                self._publish_slot(view, slot, deadline)
            except BaseException as error:
                selection_failed = False
                with self._condition:
                    slot_healthy = not slot.dead.is_set() and not slot.gdb.closed
                    if slot_healthy and not self._viewer_usable(view):
                        # The candidate itself is healthy. Preserve it for a
                        # fresh viewer instead of discarding/refilling forever
                        # after the durable bridge has disappeared.
                        slot.state = "ready"
                        self._ready.appendleft(slot)
                        self._fail_viewer_selection(view, command, error)
                        self._condition.notify_all()
                        return
                    self._discard_slot_locked(slot)
                    if slot_healthy:
                        # A healthy, configured GDB failed the routing
                        # transaction while the bridge still reports usable.
                        # Automatically trying newly spawned copies can turn a
                        # systemic endpoint/protocol failure into unbounded
                        # process churn. Degrade once; replenish() is the
                        # explicit retry after the cause has been fixed.
                        self._spawn_error = error
                        selection_error = GdbPoolError("could not route a prepared GDB to the pool console")
                        selection_error.__cause__ = error
                        view._fail(selection_error)
                        if command is not None:
                            command.error = selection_error
                            if self._waiting_attach is command:
                                self._waiting_attach = None
                            command.done.set()
                        self._condition.notify_all()
                        selection_failed = True
                    else:
                        self._ensure_reserve_locked()
                self._safe_close_slot(slot)
                if selection_failed:
                    return
                if command is not None and deadline is not None and time.monotonic() >= deadline:
                    command.error = error
                    with self._condition:
                        if self._waiting_attach is command:
                            self._waiting_attach = None
                    command.done.set()
                    return
                continue

            with self._condition:
                # Refill only after the viewer transaction commits. Starting
                # it when a candidate is merely popped can create needless
                # GDBs if the bridge disappears during the switch.
                self._ensure_reserve_locked()
                if command is not None:
                    if self._waiting_attach is command:
                        self._waiting_attach = None
                    command.done.set()
            return

    def _handle_spawned(self, event: _Spawned) -> None:
        close_slot = None
        with self._condition:
            self._pending_spawns = max(0, self._pending_spawns - 1)
            if event.error is not None:
                self._spawn_error = event.error
                self._condition.notify_all()
            elif event.slot is not None:
                slot = event.slot
                if self._closing or slot.dead.is_set() or slot.gdb.closed:
                    self._discard_slot_locked(slot)
                    close_slot = slot
                else:
                    slot.state = "ready"
                    self._ready.append(slot)
                    close_slot = None
                self._condition.notify_all()
            else:
                close_slot = None
            self._ensure_reserve_locked()
        if close_slot is not None:
            self._safe_close_slot(close_slot)
        self._try_assign_view()

    def _handle_dead(self, event: _Dead) -> None:
        slot = event.slot
        reconnect = False
        with self._condition:
            if slot.state == "disposed" or slot not in self._slots:
                return
            was_active = self._active is slot
            view = self._view if was_active else None
            self._discard_slot_locked(slot)
            if view is not None:
                reconnect = view.viewer_reconnect
                view._clear()
                # The router endpoint can report EOF slightly before DAP
                # reports the actual GDB exit. Only this independent transport
                # terminal event authorizes either viewer closure or failover.
                view._resume()
                if not reconnect:
                    view._fail(
                        _ViewerDisconnectedError(
                            "selected GDB exited: " + str(event.reason)
                        )
                    )
            self._ensure_reserve_locked()
            self._condition.notify_all()

        if view is not None:
            if reconnect:
                # The replacement path comes first. Cleanup of an already-dead
                # GDB must never add latency to an opted-in visible failover.
                self._try_assign_view()
            else:
                # This closes only the current bridge. The router listener and
                # warm reserve remain available to a later, fresh viewer.
                view._router.close_viewer(
                    "selected GDB exited: " + str(event.reason)
                )
        self._safe_close_slot(slot)

    def _handle_attach(self, command: _Attach) -> None:
        detached = False
        should_assign = True
        with self._condition:
            if self._closing or self._view is not command.view:
                command.error = GdbPoolError("GDB pool is closing")
                command.done.set()
                return
            if self._waiting_attach is not None:
                command.error = GdbPoolError("another pool console is waiting")
                command.done.set()
                return
            self._view_starting = False
            detached = command.view._detached
            if detached:
                # Detached admission is complete when the listener-backed view
                # is installed.  Viewer arrival can happen arbitrarily later
                # and therefore has no relationship to serve()'s deadline.
                command.done.set()
                should_assign = self._viewer_usable(command.view)
            else:
                self._waiting_attach = command
        if should_assign:
            self._try_assign_view()

    def _handle_viewer_connection(self, event: _ViewerConnection) -> None:
        with self._condition:
            view = event.view
            if (
                self._closing
                or self._view is not view
                or view.closed
            ):
                return
            if event.connected:
                if isinstance(view.error, _ViewerDisconnectedError):
                    view._resume()
            else:
                view._fail(_ViewerDisconnectedError(event.reason))
                self._condition.notify_all()
                return
        self._try_assign_view()

    def _handle_detach(self, command: _Detach) -> None:
        with self._condition:
            if self._view is not command.view:
                command.done.set()
                return
            self._view = None
            self._view_starting = False
            if self._waiting_attach is not None:
                self._waiting_attach.error = GdbPoolError("pool console closed")
                self._waiting_attach.done.set()
                self._waiting_attach = None
            slot, self._active = self._active, None
            if slot is not None:
                self._discard_slot_locked(slot)
            self._condition.notify_all()
        try:
            command.view._router.close()
        except BaseException as error:
            command.error = error
        command.view._mark_closed()
        if slot is not None:
            self._safe_close_slot(slot)
        command.done.set()

    def _record_coordinator_error(self, event, error: BaseException) -> None:
        wrapped = GdbPoolError("GDB pool coordinator failed")
        wrapped.__cause__ = error
        with self._condition:
            if self._coordinator_error is None:
                self._coordinator_error = error
            view = self._view
            if isinstance(event, (_Attach, _Detach)):
                event.error = wrapped
                event.done.set()
            if self._waiting_attach is not None:
                self._waiting_attach.error = wrapped
                self._waiting_attach.done.set()
                self._waiting_attach = None
            self._condition.notify_all()
        if isinstance(view, PoolConsole):
            view._fail(wrapped)

    def _coordinator_loop(self) -> None:
        while True:
            event = self._events.get()
            if event is _STOP:
                return
            try:
                if event is _FILL:
                    with self._condition:
                        self._ensure_reserve_locked()
                elif isinstance(event, _Spawned):
                    self._handle_spawned(event)
                elif isinstance(event, _Dead):
                    self._handle_dead(event)
                elif isinstance(event, _Attach):
                    self._handle_attach(event)
                elif isinstance(event, _Detach):
                    self._handle_detach(event)
                elif isinstance(event, _ViewerConnection):
                    self._handle_viewer_connection(event)
            except BaseException as error:
                # A malformed external endpoint or setup callback must wake
                # every synchronous waiter instead of silently killing this
                # sole coordinator lane.  Keep draining events so close/detach
                # remain usable, while public work observes the degraded state.
                self._record_coordinator_error(event, error)

    def start(self, timeout=None) -> "GdbPool":
        """Start the coordinator and return after the ready reserve is full."""
        deadline = _deadline(timeout)
        start_workers = False
        with self._condition:
            if self._closed or self._closing:
                raise GdbPoolError("GDB pool is closed")
            if not self._started:
                self._started = True
                start_workers = True
                self._coordinator = threading.Thread(
                    target=self._coordinator_loop,
                    name="pwnc-gdb-pool",
                    daemon=True,
                )
                self._spawner = threading.Thread(
                    target=self._spawner_loop,
                    name="pwnc-gdb-pool-spawner",
                    daemon=True,
                )

        if start_workers:
            try:
                self._coordinator.start()
                self._spawner.start()
            except BaseException as error:
                # Thread.start itself is allowed to fail (resource exhaustion,
                # test injection).  Treat the pair transactionally so a lone
                # coordinator/spawner cannot survive a failed pool startup.
                self.close()
                raise GdbPoolError("could not start the GDB pool workers") from error
            with self._condition:
                if self._closing or self._closed:
                    startup_interrupted = True
                else:
                    startup_interrupted = False
                    self._events.put(_FILL)
            if startup_interrupted:
                self.close()
                raise GdbPoolError("GDB pool closed while starting")

        with self._condition:
            while len(self._ready) < self.size:
                if self._coordinator_error is not None:
                    error = self._coordinator_error
                    break
                if self._spawn_error is not None:
                    error = self._spawn_error
                    break
                if self._closing or self._closed:
                    raise GdbPoolError("GDB pool closed while starting")
                try:
                    self._condition.wait(_remaining(deadline))
                except TimeoutError:
                    error = TimeoutError("timed out filling the prepared GDB pool")
                    break
            else:
                return self
        self.close()
        raise GdbPoolError("could not fill the prepared GDB pool") from error

    def wait_ready(self, count=None, timeout=None) -> int:
        """Wait eventfully until *count* ready spares exist and return the count."""
        if count is None:
            count = self.size
        if isinstance(count, bool):
            raise TypeError("ready count must be a nonnegative integer")
        count = operator.index(count)
        if count < 0 or count > self.size:
            raise ValueError("ready count must be between zero and pool size")
        deadline = _deadline(timeout)
        with self._condition:
            while len(self._ready) < count:
                if self._coordinator_error is not None:
                    raise GdbPoolError("the GDB pool coordinator failed") from self._coordinator_error
                if self._spawn_error is not None:
                    raise GdbPoolError("the GDB pool reserve is degraded") from self._spawn_error
                if self._closing or self._closed:
                    raise GdbPoolError("GDB pool closed while waiting for a spare")
                self._condition.wait(_remaining(deadline))
            return len(self._ready)

    def replenish(self) -> "GdbPool":
        """Retry one failed reserve fill without entering an automatic hot loop."""
        with self._condition:
            if not self._started or self._closing or self._closed:
                raise GdbPoolError("GDB pool is not running")
            if self._coordinator_error is not None:
                raise GdbPoolError("the GDB pool coordinator failed") from self._coordinator_error
            self._spawn_error = None
            view = self._view
            active = self._active
        if isinstance(view, PoolConsole) and view.current is None and active is None:
            view._resume()
        self._events.put(_FILL)
        return self

    def console(self, viewer=None, timeout=30.0) -> PoolConsole:
        """Open the pool's one stable viewer and select a configured GDB."""
        if viewer is None:
            viewer = ViewerConfig.current()
        if not isinstance(viewer, ViewerConfig):
            raise TypeError("viewer must be a ViewerConfig")
        deadline = _deadline(timeout)
        with self._condition:
            if not self._started or self._closing or self._closed:
                raise GdbPoolError("start the GDB pool before opening its console")
            if self._coordinator_error is not None:
                raise GdbPoolError("the GDB pool coordinator failed") from self._coordinator_error
            if self._view is not None or self._view_starting:
                raise GdbPoolError("this GDB pool already has a console viewer")
            # Reserve the one-viewer slot before launching an external process.
            self._view_starting = True

        from .viewer import ViewerRouter

        router = None
        view = None
        try:
            router = ViewerRouter(viewer)
            with self._condition:
                if self._closing:
                    raise GdbPoolError("GDB pool closed while opening its console")
                self._starting_router = router
            router.start(timeout=_switch_timeout(deadline, self.switch_timeout))
            view = PoolConsole(self, router)
            command = _Attach(view, deadline)
            with self._condition:
                if self._starting_router is router:
                    self._starting_router = None
                if self._closing:
                    raise GdbPoolError("GDB pool closed while opening its console")
                self._view = view
                # Publish the view and its attach command as one coordinator
                # handoff.  close() takes the same lock before queuing STOP, so
                # it cannot strand this synchronous command behind shutdown.
                self._events.put(command)
            if not command.done.wait(_remaining(deadline)):
                raise TimeoutError("timed out selecting a prepared GDB")
            if command.error is not None:
                raise command.error
            # `size` is a ready reserve, so do not return a nominally healthy
            # console until the initial handoff's replacement is warm as well.
            self.wait_ready(self.size, timeout=_remaining(deadline))
            return view
        except BaseException:
            if view is not None:
                try:
                    self._detach_view(view)
                except Exception:
                    pass
            elif router is not None:
                router.close()
            with self._condition:
                if self._starting_router is router:
                    self._starting_router = None
                self._view_starting = False
            raise

    def serve(
        self,
        name="default",
        *,
        socket_path=None,
        config_path=None,
        timeout=30.0,
    ) -> PoolConsole:
        """Serve a detached viewer socket without waiting for a viewer.

        The returned console initially has no selection.  A configured spare
        is selected only after a protocol-compatible viewer connects.  ``timeout``
        bounds discovery, listener startup, and coordinator admission; it is
        never retained as a deadline for a later viewer connection.
        """
        deadline = _deadline(timeout)
        with self._condition:
            if not self._started or self._closing or self._closed:
                raise GdbPoolError("start the GDB pool before serving its console")
            if self._coordinator_error is not None:
                raise GdbPoolError("the GDB pool coordinator failed") from self._coordinator_error
            if self._view is not None or self._view_starting:
                raise GdbPoolError("this GDB pool already has a console viewer")
            self._view_starting = True

        # Lazy imports keep package initialization acyclic and make the pool's
        # managed-viewer path independent of discovery configuration.
        from .discovery import acquire_pool_socket, discover_manager
        from .viewer import ViewerRouter

        lease = None
        listener = None
        router = None
        view = None
        try:
            address = discover_manager(
                name,
                socket_path=socket_path,
                config_path=config_path,
            )
            lease = acquire_pool_socket(address)
            _remaining(deadline)
            listener = lease.duplicate_socket()
            try:
                router = ViewerRouter(
                    None,
                    socket_path=lease.path,
                    listener=listener,
                )
            except BaseException:
                listener.close()
                listener = None
                raise
            listener = None  # ViewerRouter owns and closes the duplicate.
            view = PoolConsole(self, router, detached=True, lease=lease)
            lease = None  # PoolConsole now owns the discovery lease.
            with self._condition:
                if self._closing:
                    raise GdbPoolError("GDB pool closed while serving its console")
                self._starting_router = router
            router.start(timeout=_switch_timeout(deadline, self.switch_timeout))

            # A detached attach deliberately carries no deadline: selection is
            # triggered by a future connection and uses switch_timeout then.
            command = _Attach(view, None)
            with self._condition:
                if self._starting_router is router:
                    self._starting_router = None
                if self._closing:
                    raise GdbPoolError("GDB pool closed while serving its console")
                self._view = view
                self._events.put(command)
            if not command.done.wait(_remaining(deadline)):
                raise TimeoutError("timed out admitting the detached pool console")
            if command.error is not None:
                raise command.error
            return view
        except BaseException:
            with self._condition:
                published = view is not None and self._view is view
            if published:
                try:
                    self._detach_view(view)
                except Exception:
                    pass
            elif view is not None:
                try:
                    router.close()
                finally:
                    view._mark_closed()
            elif router is not None:
                router.close()
            if listener is not None:
                try:
                    listener.close()
                except Exception:
                    pass
            if lease is not None:
                try:
                    lease.close()
                except Exception:
                    pass
            with self._condition:
                if self._starting_router is router:
                    self._starting_router = None
                self._view_starting = False
            raise

    def _router_lost(self, view: PoolConsole, endpoint, reason: str) -> None:
        with self._condition:
            if self._closing or view.closed or self._view is not view:
                return
            slot = self._endpoint_slots.get(id(endpoint))
            if slot is None or self._active is not slot:
                return
            if slot.dead.is_set() or slot.gdb.closed:
                # The independent transport listener has already established
                # real process death and queued the ordinary failover event.
                return
            # Losing the routing socket does not prove that GDB exited. Keep
            # the live controller owned by this view, expose the fault, and
            # wait for its DAP transport-terminal notification. This prevents
            # endpoint faults (including console_close()) from silently
            # killing a live debugging session or consuming a spare.
            error = _EndpointLostError(slot, str(reason))
            view._clear()
            view._fail(error)
            self._condition.notify_all()

    def _viewer_connection(
        self,
        view: PoolConsole,
        connected: bool,
        reason: str | None,
    ) -> None:
        # Called on the router's notification lane.  Keep it non-blocking and
        # side-effect free apart from handing immutable state to the sole pool
        # coordinator.
        self._events.put(_ViewerConnection(view, bool(connected), reason))

    def _detach_view(self, view: PoolConsole) -> None:
        direct = False
        command = None
        with self._condition:
            if view.closed:
                return
            if self._closing or self._closed:
                direct = True
            else:
                command = _Detach(view)
                # Admission and queueing share close()'s lock.  Either this
                # command is ahead of STOP, or shutdown owns cleanup directly;
                # a detach can never be stranded behind the coordinator stop.
                self._events.put(command)
        if direct:
            view._router.close()
            view._mark_closed()
            return
        command.done.wait()
        if command.error is not None:
            raise command.error

    def close(self) -> None:
        with self._close_lock:
            with self._condition:
                if self._closed:
                    return
                self._closing = True
                view = self._view if isinstance(self._view, PoolConsole) else None
                starting_router = self._starting_router
                constructing = self._constructing
                self._condition.notify_all()

            # Closing the router first interrupts a coordinator switch without
            # waiting for its normal per-switch deadline.
            if view is not None:
                try:
                    view._router.close()
                except Exception:
                    pass
                view._mark_closed()
            if starting_router is not None:
                try:
                    starting_router.close()
                except Exception:
                    pass
            if constructing is not None:
                try:
                    constructing.close()
                except Exception:
                    pass

            self._events.put(_STOP)
            self._spawn_requests.put(_STOP)
            current = threading.current_thread()
            for thread in (self._coordinator, self._spawner):
                if thread is not None and thread is not current and thread.ident is not None:
                    thread.join(timeout=6.0)

            with self._condition:
                slots = list(self._slots)
                self._slots.clear()
                self._ready.clear()
                self._endpoint_slots.clear()
                self._active = None
                self._view = None
                self._view_starting = False
                self._starting_router = None
                if self._waiting_attach is not None:
                    self._waiting_attach.error = GdbPoolError("GDB pool closed")
                    self._waiting_attach.done.set()
                    self._waiting_attach = None
            for slot in slots:
                self._safe_close_slot(slot)

            with self._condition:
                self._closed = True
                self._condition.notify_all()

    def __enter__(self):
        return self.start()

    def __exit__(self, _type, _value, _traceback):
        self.close()


__all__ = [
    "GdbPool",
    "GdbPoolError",
    "PoolConsole",
    "PoolSelection",
]
