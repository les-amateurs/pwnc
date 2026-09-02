"""pwnc.gdb.dap — drive gdb from an external python process over DAP.

A reimplementation of ``pwnc.gdb.mi`` on top of gdb's native Debug Adapter
Protocol interpreter (``gdb --interpreter=dap``). Native DAP handles the control
plane (run/step/break, memory, registers, stacks); a small in-gdb extension
(``_ext.py``) adds the things DAP omits — most importantly structural
``gdb.Type`` layout, reconstructed client-side into ``pwnc.types`` Values.

Public API mirrors ``pwnc.gdb.mi``::

    from pwnc.gdb.dap import debug
    g = debug("./binary")
    g.bp("main"); stop = g.run()
    x = g.sym.counter            # typed pwnc.types Value over live memory
    g.reg.rip = 0x401000         # registers
    data = g.read(addr, 64)      # raw memory
    g.stepi(); g.cont(); g.close()
"""

import atexit
import base64
import ctypes
import math
import os
import queue
import re
import select
import shutil
import stat
import tempfile
import threading
import time
from enum import Enum as _PyEnum
from numbers import Real
from types import MappingProxyType

from pwnc.types.provider import ByteOrder, BufferProvider
from pwnc.types.primitives import Ptr, Int, Float, Double
from pwnc.types.containers import Array, Enum
from pwnc.types.value import Value, ArrayValue, _typed_value
from pwnc.types.serial import from_descriptor

from .transport import DapTransport, DapError, DapTimeout
from .client import DapBytesProvider
from .facts import LibcThreadFacts, RegisterSet, RuntimeFrame, ScopedVariable, ThreadFacts, ThreadView
from .heap import Heap, HeapArena, HeapChunk, HeapUnavailableError
from .history import HeapArenaChange, HeapChunkChange, RuntimeEvent, RuntimeHistory, RuntimeSnapshot, SnapshotDiff
from .inspector import RuntimeViewer, ViewerConnectionError, ViewerStats
from .marks import CapturedMark, MarkKind, Marks, MemoryMark, PayloadAnnotation, SemanticSpan, TypedField
from .runtime import (
    AmbiguousModuleError,
    Memory,
    MemoryMap,
    MemoryMaps,
    Module,
    ModuleAddressTable,
    Modules,
    Runtime,
    RuntimeUnavailableError,
    TypedMemoryCapture,
)
from .verify import VerificationError, VerificationResult, Verifier
from ._inferior_launcher import discard_config, prepare_launch
from .callbacks import (
    CallbackAdmissionError,
    OperationCancelled,
    OperationDispatcher,
    OperationError,
    OperationFailed,
)
from .console import (
    ArgvTerminalLauncher,
    ConsoleConfig,
    ConsoleMode,
    ViewerConfig,
    ViewerMode,
)

__all__ = [
    "Gdb",
    "GdbState",
    "start",
    "debug",
    "attach",
    "launch",
    "DapError",
    "DapTimeout",
    "OperationError",
    "OperationFailed",
    "OperationCancelled",
    "CallbackAdmissionError",
    "ArgvTerminalLauncher",
    "ConsoleConfig",
    "ConsoleMode",
    "ViewerConfig",
    "ViewerMode",
    "AmbiguousModuleError",
    "CapturedMark",
    "Heap",
    "HeapArena",
    "HeapArenaChange",
    "HeapChunk",
    "HeapChunkChange",
    "HeapUnavailableError",
    "LibcThreadFacts",
    "MarkKind",
    "Marks",
    "Memory",
    "MemoryMap",
    "MemoryMaps",
    "MemoryMark",
    "Module",
    "ModuleAddressTable",
    "Modules",
    "PayloadAnnotation",
    "RegisterSet",
    "Runtime",
    "RuntimeEvent",
    "RuntimeFrame",
    "RuntimeHistory",
    "RuntimeSnapshot",
    "RuntimeUnavailableError",
    "RuntimeViewer",
    "ScopedVariable",
    "SemanticSpan",
    "SnapshotDiff",
    "ThreadFacts",
    "ThreadView",
    "TypedMemoryCapture",
    "TypedField",
    "VerificationError",
    "VerificationResult",
    "Verifier",
    "ViewerConnectionError",
    "ViewerStats",
]


class _DefaultSetting:
    def __repr__(self):
        return "<configured default>"


_DEFAULT = _DefaultSetting()
_SUPPORTED_SETTINGS = frozenset({"timeout"})


class GdbState(str, _PyEnum):
    """One-shot lifecycle state of a DAP-controlled GDB process."""

    NEW = "new"
    INITIALIZING = "initializing"
    PREPARED = "prepared"
    BINDING = "binding"
    BOUND = "bound"
    CLOSED = "closed"


class _WaitTerminal:
    """A persistent terminal notification carried through the stop queue."""

    __slots__ = ("reason",)

    def __init__(self, reason):
        self.reason = reason


# ── attribute-style accessors ──────────────────────────────────────────────


class SymbolAccessor:
    """``g.sym.main`` -> typed pwnc.types Value at the symbol's address."""

    def __init__(self, gdb):
        object.__setattr__(self, "_gdb", gdb)

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return self._gdb._resolve_symbol(name)

    def __getitem__(self, name):
        return self._gdb._resolve_symbol(name)


class Registers:
    """``g.reg.rax`` -> int; ``g.reg.rax = v`` -> set; ``g.reg()`` -> all."""

    def __init__(self, gdb):
        object.__setattr__(self, "_gdb", gdb)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._gdb._request("pwncReadRegister", {"name": name})["value"]

    def __setattr__(self, name, value):
        self._gdb._request("pwncWriteRegister", {"name": name, "value": int(value)})

    def __call__(self, *, timeout=_DEFAULT):
        return self._gdb._request("pwncReadRegisters", timeout=timeout)["registers"]


# ── lightweight handles (no gdb-object proxies / no server object store) ────


class DapBreakpoint:
    def __init__(self, gdb, number):
        self._gdb = gdb
        self.number = number

    def delete(self, *, timeout=_DEFAULT):
        self._gdb._request(
            "pwncDeleteBreakpoint",
            {"number": self.number},
            timeout=timeout,
        )
        self._gdb._bp_callbacks.pop(self.number, None)

    def __repr__(self):
        return "<DapBreakpoint #%d>" % self.number


class DapFrame:
    """A slim frame view backed by a DAP stackTrace entry."""

    def __init__(self, gdb, raw, level):
        self._gdb = gdb
        self._raw = raw
        self.level = level

    def pc(self):
        ref = self._raw.get("instructionPointerReference")
        return int(ref, 16) if ref else None

    def name(self):
        return self._raw.get("name")

    def older(self, *, timeout=_DEFAULT):
        return self._gdb.frame(self.level + 1, timeout=timeout)

    def __repr__(self):
        return "<DapFrame #%d %s @ %#x>" % (self.level, self.name(), self.pc() or 0)


# ── main controller ─────────────────────────────────────────────────────────


class Gdb:
    """gdb controller over DAP with typed memory/symbol access."""

    def __init__(self, transport):
        self.transport = transport
        self.target = None              # pwntools tube (set by debug())
        self._target_cleanup = None     # owned non-tube launch resources
        self._closed = False
        self._lifecycle_lock = threading.RLock()
        self._state = GdbState.NEW
        self._close_lock = threading.Lock()
        self._close_done = threading.Event()
        self._close_owner = None
        self._close_error = None
        self._console_lock = threading.RLock()
        self._wait_lock = threading.Lock()
        self._event_state_lock = threading.Lock()
        self._terminal_stop_queued = False
        self._wait_terminal_queued = False
        self._wait_terminal_reason = None
        self._bp_callbacks = {}         # gdb bp number -> callback(gdb)
        self._stops = queue.Queue()
        self._discarded_internal_stops = 0
        self._cur_thread = None
        self._byteorder = ByteOrder.Little
        self._ptrbits = 64
        self._qemu_user_relocation = None
        self._remote_file_settings = MappingProxyType({})
        self._sym_type_cache = {}       # symbol name -> reconstructed Type
        self._console = None            # Console handle (interactive UI)
        self.operations = OperationDispatcher(transport)
        self.sym = SymbolAccessor(self)
        self.reg = Registers(self)
        self.runtime = Runtime(self)
        self.modules = self.runtime.modules
        self.maps = self.runtime.maps
        self.memory = self.runtime.memory
        self.thread_views = self.runtime.threads
        self.marks = self.runtime.marks
        self.heap = self.runtime.heap
        self.history = self.runtime.history
        self.verify = self.runtime.verify
        self.viewer = self.runtime.viewer
        transport.on("stopped", self._on_stopped)
        transport.on("exited", self._on_exited)
        transport.on("terminated", self._on_terminated)
        self._transport_terminal_unsubscribe = transport.add_terminal_listener(
            self._on_transport_terminal
        )
        self._atexit_callback = self.close
        atexit.register(self._atexit_callback)

    @property
    def state(self):
        """Current one-shot session state.

        Transport death is terminal even when the caller has not yet invoked
        :meth:`close` to dispose the remaining host-side resources.
        """
        if self.closed:
            return GdbState.CLOSED
        with self._lifecycle_lock:
            return self._state

    @property
    def closed(self):
        """Whether close began or the GDB DAP process became terminal."""
        if self._closed or self.transport.closed:
            self._mark_lifecycle_closed()
            return True
        with self._lifecycle_lock:
            return self._state is GdbState.CLOSED

    def wait_closed(self, timeout=None):
        """Wait eventfully for the GDB DAP process to become terminal."""
        return self.transport.wait_closed(timeout)

    @property
    def main(self):
        """The exact main executable currently loaded by this inferior."""
        return self.runtime.main

    @property
    def libc(self):
        """The uniquely identified loaded libc, when one is present."""
        return self.runtime.libc

    @property
    def loader(self):
        """The uniquely identified dynamic loader, when one is present."""
        return self.runtime.loader

    @property
    def layout(self):
        """An immutable payloads RuntimeLayout derived from debugger truth."""
        return self.runtime.layout

    @property
    def qemu_user_relocation(self):
        """Verified guest executable relocation facts for QEMU-user targets."""
        return self._qemu_user_relocation

    @property
    def remote_file_settings(self):
        """Exact GDB remote path settings confirmed by GDB after assignment."""
        return self._remote_file_settings

    @property
    def arch(self):
        """The exact payloads Target for the selected inferior architecture."""
        return self.runtime.target

    def _mark_lifecycle_closed(self):
        # A few legacy white-box tests construct partial Gdb instances with
        # object.__new__.  Keep close() tolerant of those fixtures while all
        # normally constructed controllers take this lock.
        lock = getattr(self, "_lifecycle_lock", None)
        if lock is None:
            return
        with lock:
            self._state = GdbState.CLOSED

    def use(self, **settings):
        """Return an immutable configured view of this GDB session.

        The view shares the transport, operation dispatcher, inferior, and all
        lifecycle state with this controller.  Settings are defaults: an
        explicit timeout accepted by a method still takes precedence.
        """
        unknown = sorted(set(settings).difference(_SUPPORTED_SETTINGS))
        if unknown:
            names = ", ".join(repr(name) for name in unknown)
            raise TypeError(f"unsupported GDB setting(s): {names}")
        if "timeout" in settings:
            timeout = settings["timeout"]
            if timeout is not None:
                if isinstance(timeout, bool) or not isinstance(timeout, Real):
                    raise TypeError("timeout must be a nonnegative real number or None")
                if timeout < 0:
                    raise ValueError("timeout cannot be negative")
                try:
                    finite = math.isfinite(timeout)
                except OverflowError:
                    finite = False
                if not finite:
                    raise ValueError("timeout must be finite; use None for no deadline")

        if isinstance(self, _ConfiguredGdb):
            root = self._configured_root
            merged = dict(self._use_settings)
        else:
            root = self
            merged = {}
        merged.update(settings)
        return _ConfiguredGdb(root, merged)

    def _setting(self, name, supplied=_DEFAULT, *, fallback=_DEFAULT):
        if supplied is not _DEFAULT:
            return supplied
        settings = getattr(self, "_use_settings", None)
        if settings is not None and name in settings:
            return settings[name]
        return fallback

    def _request(self, command, arguments=None, *, timeout=_DEFAULT):
        timeout = self._setting("timeout", timeout)
        if timeout is _DEFAULT:
            return self.transport.request(command, arguments)
        return self.transport.request(command, arguments, timeout=timeout)

    def _result(self, future, *, timeout=_DEFAULT):
        timeout = self._setting("timeout", timeout)
        if timeout is _DEFAULT:
            return self.transport.result(future)
        return self.transport.result(future, timeout=timeout)

    # --- async events (reader thread) ---

    def _on_stopped(self, body):
        tid = body.get("threadId")
        if tid is not None:
            self._cur_thread = tid
        runtime = getattr(self, "runtime", None)
        if runtime is not None:
            runtime.invalidate()
            runtime._record_event("stop", body)
        self._stops.put(body)

    def _on_exited(self, body):
        runtime = getattr(self, "runtime", None)
        if runtime is not None:
            runtime.invalidate()
            runtime._record_event("exit", body)
        self._queue_terminal_stop(
            {"reason": "exited", "exitCode": body.get("exitCode")}
        )

    def _on_terminated(self, body):
        runtime = getattr(self, "runtime", None)
        if runtime is not None:
            runtime.invalidate()
            runtime._record_event("terminated", body)
        self._queue_terminal_stop({"reason": "terminated"})

    def _queue_terminal_stop(self, stop):
        # GDB normally emits both exited and terminated for one inferior.  One
        # terminal record is enough; retaining both makes a later wait() return
        # a stale second exit.
        with self._event_state_lock:
            if self._terminal_stop_queued:
                return
            self._terminal_stop_queued = True
        self._stops.put(stop)

    def _on_transport_terminal(self, reason):
        self._mark_lifecycle_closed()
        self._queue_wait_terminal(
            reason or "GDB DAP channel closed while waiting for a stop"
        )

    def _queue_wait_terminal(self, reason):
        # Closure travels through the same primitive as inferior stops.  This
        # closes the check-then-block race without periodically waking wait().
        with self._event_state_lock:
            if self._wait_terminal_queued:
                return
            self._wait_terminal_queued = True
            self._wait_terminal_reason = str(reason)
        self._stops.put(_WaitTerminal(self._wait_terminal_reason))

    # --- bootstrap / connect ---

    def _initialize(self):
        with self._lifecycle_lock:
            if self._state is not GdbState.NEW:
                raise DapError(
                    "GDB session cannot be initialized from state %s"
                    % self._state.value
                )
            if self._closed or self.transport.closed:
                self._state = GdbState.CLOSED
                raise DapError("GDB session is closed")
            self._state = GdbState.INITIALIZING
        try:
            self.transport.request("initialize", {
                "clientID": "pwnc", "adapterID": "gdb", "locale": "en",
                "linesStartAt1": True, "columnsStartAt1": True, "pathFormat": "path",
                "supportsVariableType": True, "supportsMemoryReferences": True,
                "supportsRunInTerminalRequest": False,
            })
            self.transport.wait_initialized()
            ext = os.path.join(os.path.dirname(__file__), "_ext.py")
            self.transport.request(
                "evaluate",
                {"expression": "source " + ext, "context": "repl"},
            )
            callback_ext = os.path.join(os.path.dirname(__file__), "_callback_ext.py")
            self.transport.request(
                "evaluate",
                {"expression": "source " + callback_ext, "context": "repl"},
            )
            runtime_ext = os.path.join(os.path.dirname(__file__), "_runtime_ext.py")
            self.transport.request(
                "evaluate",
                {"expression": "source " + runtime_ext, "context": "repl"},
            )
            # configurationDone is deliberately NOT sent here: gdb 14+/17+
            # require it to come after launch/attach. See _post_connect.
            with self._lifecycle_lock:
                if (
                    self._state is not GdbState.INITIALIZING
                    or self._closed
                    or self.transport.closed
                ):
                    self._state = GdbState.CLOSED
                    raise DapError("GDB session closed while initializing")
                self._state = GdbState.PREPARED
        except BaseException:
            self._mark_lifecycle_closed()
            raise

    def _begin_bind(self):
        with self._lifecycle_lock:
            if self._closed or self.transport.closed:
                self._state = GdbState.CLOSED
            if self._state is GdbState.PREPARED:
                self._state = GdbState.BINDING
                return
            if self._state is GdbState.BINDING:
                raise DapError("GDB session is already binding a target")
            if self._state is GdbState.BOUND:
                raise DapError("GDB session already has a target")
            if self._state is GdbState.CLOSED:
                raise DapError("GDB session is closed")
            raise DapError(
                "GDB session is not prepared (state %s)" % self._state.value
            )

    def _finish_bind(self):
        with self._lifecycle_lock:
            if (
                self._state is GdbState.BINDING
                and not self._closed
                and not self.transport.closed
            ):
                self._state = GdbState.BOUND
                return
            self._state = GdbState.CLOSED
        raise DapError("GDB session closed while binding its target")

    def _bind_once(self, operation):
        self._begin_bind()
        try:
            operation()
            self._finish_bind()
        except BaseException as error:
            self._mark_lifecycle_closed()
            try:
                self.close()
            except BaseException as cleanup_error:
                try:
                    error.add_note(
                        "GDB bind cleanup also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                except Exception:
                    pass
            raise
        return self

    def _post_connect(self, pending=None, consume_initial_stop=True):
        # DAP/gdb ordering (verified against gdb 17.2 dap/launch.py): launch &
        # attach return a deferred "promise" whose response gdb withholds until
        # configurationDone reschedules it. So the caller sends launch/attach via
        # transport.send() (non-blocking) and hands us the Future; we send
        # configurationDone (which fulfils the promise), then collect the
        # launch/attach result. Blocking on launch/attach *before*
        # configurationDone deadlocks; sending configurationDone first errors with
        # "launch or attach not specified". (gdb 15.x answered launch/attach
        # eagerly and made configurationDone a no-op, so either order worked there.)
        self._request("configurationDone")
        if pending is not None:
            self._result(pending)
        arch = self._request("pwncArch")
        self._byteorder = (ByteOrder.Little if arch.get("byteorder") == "little"
                           else ByteOrder.Big)
        self._ptrbits = arch.get("ptrbits", 64)
        try:
            ths = self._request("threads").get("threads", [])
            if ths:
                self._cur_thread = ths[0]["id"]
        except DapError:
            pass
        # Consume the initial attach/stop-at-main stop so the user's first
        # wait() returns their next stop.  A launch explicitly configured not
        # to stop has no such event and must not pay a blind ten-second delay.
        if consume_initial_stop:
            stop_timeout = self._setting("timeout", fallback=10.0)
            deadline = (
                None
                if stop_timeout is None
                else time.monotonic() + stop_timeout
            )
            try:
                initial = self._next_stop(deadline)
            except DapTimeout:
                pass
            else:
                if initial.get("reason") in {"exited", "terminated"}:
                    raise DapError("inferior exited while connecting", body=initial)

    def _configure_remote_files(self, program, sysroot, solib_search_path):
        if program:
            quoted_program = _gdb_path_argument(program)
            self._request(
                "evaluate", {"expression": "file " + quoted_program, "context": "repl"})
        settings = {}
        if sysroot is not None:
            settings["sysroot"] = sysroot
        if solib_search_path is not None:
            settings["solibSearchPath"] = solib_search_path
        if settings:
            configured = self._request("pwncRemoteFileSettings", settings)
            for name, expected in settings.items():
                actual = configured.get(name)
                if actual != expected:
                    raise DapError(
                        "GDB did not preserve the exact remote %s setting "
                        "(%r != %r)" % (name, actual, expected)
                    )
            current = dict(getattr(self, "_remote_file_settings", {}))
            current.update(configured)
            self._remote_file_settings = MappingProxyType(current)

    def _connect_remote(
        self,
        program,
        target,
        *,
        sysroot="/",
        solib_search_path=None,
        reapply=True,
        qemu_user=False,
    ):
        # Configure both sides of target creation.  GDB's remote attach can
        # replace shared-library settings while selecting the remote target.
        # Do not repeat ``file`` after attach: GDB has already applied the
        # target's qOffsets relocation by then and another ``file`` silently
        # resets PIE symbols to their link-time addresses.
        self._configure_remote_files(program, sysroot, solib_search_path)
        pending = self.transport.send("attach", {"target": target})
        self._post_connect(pending, consume_initial_stop=True)
        if reapply:
            self._configure_remote_files(None, sysroot, solib_search_path)
        if qemu_user:
            if not program:
                raise DapError("QEMU-user symbol rebasing requires the guest program")
            relocation = self._request(
                "pwncQemuUserRebase",
                {"program": program},
            )
            self._qemu_user_relocation = MappingProxyType(dict(relocation))
            self._sym_type_cache.clear()

    def _connect_pid(self, pid, program=None):
        args = {"pid": pid}
        if program:
            args["program"] = program
        pending = self.transport.send("attach", args)
        self._post_connect(pending, consume_initial_stop=True)

    def _launch(
        self,
        program,
        args=(),
        env=None,
        stop_at_main=True,
        host_aslr=None,
    ):
        if host_aslr is not None:
            self._request(
                "evaluate",
                {
                    "expression": (
                        "set disable-randomization "
                        + ("off" if host_aslr else "on")
                    ),
                    "context": "repl",
                },
            )
        launch_args = {
            "program": program,
            "args": [str(a) for a in args],
            "stopAtBeginningOfMainSubprogram": bool(stop_at_main),
        }
        if env is not None:
            launch_args["env"] = dict(env)
        # send (not request): the launch response is deferred until
        # configurationDone (see _post_connect), so don't block here.
        pending = self.transport.send("launch", launch_args)
        self._post_connect(
            pending,
            consume_initial_stop=bool(stop_at_main),
        )                                               # configurationDone + optional stop

    # Public one-shot target binding.  A prepared DAP session may select one
    # target.  GDB's configurationDone handshake cannot be reset reliably, so
    # any failure after binding starts closes the session.

    def attach(self, pid_or_name, program=None):
        """Attach this prepared GDB to one process by PID or exact name."""
        pid = _resolve_pid(pid_or_name)
        if program is not None:
            program = os.fsdecode(program)
        return self._bind_once(lambda: self._connect_pid(pid, program))

    def connect(
        self,
        target,
        program=None,
        *,
        sysroot="/",
        solib_search_path=None,
        qemu_user=False,
    ):
        """Connect this prepared GDB to one remote GDB target.

        Set ``qemu_user=True`` for a QEMU linux-user stub.  PIE symbols are
        then verified and loaded at the exact guest bias reported by RSP;
        connection fails explicitly if that bias cannot be established.
        """
        target = os.fsdecode(target)
        if not target:
            raise ValueError("remote GDB target cannot be empty")
        if program is not None:
            program = os.fsdecode(program)
        if sysroot is not None:
            sysroot = os.fsdecode(sysroot)
        if solib_search_path is not None:
            solib_search_path = os.fsdecode(solib_search_path)
        if not isinstance(qemu_user, bool):
            raise TypeError("qemu_user must be bool")
        if qemu_user and program is None:
            raise ValueError("qemu_user=True requires program")
        if sysroot == "/" and solib_search_path is None:
            if qemu_user:
                operation = lambda: self._connect_remote(
                    program,
                    target,
                    qemu_user=True,
                )
            else:
                operation = lambda: self._connect_remote(program, target)
        else:
            options = {
                "sysroot": sysroot,
                "solib_search_path": solib_search_path,
            }
            if qemu_user:
                options["qemu_user"] = True
            operation = lambda: self._connect_remote(program, target, **options)
        return self._bind_once(operation)

    def launch(
        self,
        program,
        *args,
        env=None,
        stop_at_main=True,
        qemu=None,
        sysroot=None,
        host_aslr=None,
        qemu_aslr=None,
    ):
        """Launch one inferior, automatically using qemu-user when foreign."""
        program = os.path.abspath(os.fsdecode(program))
        arguments = tuple(args)
        environment = None if env is None else dict(env)
        stop_at_main = bool(stop_at_main)
        host_aslr = _validate_aslr_setting(host_aslr, "host_aslr")
        qemu_aslr = _validate_aslr_setting(qemu_aslr, "qemu_aslr")
        if _needs_qemu(program, qemu):
            return self._bind_once(
                lambda: _qemu_prepared(
                    self,
                    program,
                    arguments,
                    environment,
                    qemu=qemu,
                    sysroot=sysroot,
                    host_aslr=host_aslr,
                    qemu_aslr=qemu_aslr,
                )
            )
        if qemu_aslr is not None:
            raise ValueError("qemu_aslr requires a qemu-user launch")
        return self._bind_once(
            lambda: self._launch(
                program,
                arguments,
                environment,
                stop_at_main,
                host_aslr,
            )
        )

    def debug(
        self,
        program,
        *args,
        env=None,
        qemu=None,
        sysroot=None,
        host_aslr=None,
        qemu_aslr=None,
    ):
        """Debug one inferior with clean I/O, using qemu-user when foreign."""
        program = os.path.abspath(os.fsdecode(program))
        arguments = tuple(args)
        environment = None if env is None else dict(env)
        host_aslr = _validate_aslr_setting(host_aslr, "host_aslr")
        qemu_aslr = _validate_aslr_setting(qemu_aslr, "qemu_aslr")
        if _needs_qemu(program, qemu):
            return self._bind_once(
                lambda: _qemu_prepared(
                    self,
                    program,
                    arguments,
                    environment,
                    qemu=qemu,
                    sysroot=sysroot,
                    host_aslr=host_aslr,
                    qemu_aslr=qemu_aslr,
                )
            )
        if qemu_aslr is not None:
            raise ValueError("qemu_aslr requires a qemu-user launch")
        if host_aslr is None:
            operation = lambda: _debug_prepared(
                self, program, arguments, environment
            )
        else:
            operation = lambda: _debug_prepared(
                self,
                program,
                arguments,
                environment,
                host_aslr=host_aslr,
            )
        return self._bind_once(operation)

    # --- execution control ---

    def _tid(self):
        return self._cur_thread if self._cur_thread is not None else 1

    def _prepare_execution_request(self, timeout):
        """Discard stops fully consumed by an earlier synchronous command.

        Plugin commands such as Bata24 ``next-ret -n`` run several inferior
        steps before their ``evaluate`` response returns.  Stock DAP emits a
        stopped event for every one of those steps.  Once the plugin command
        has returned, those events describe history rather than the next stop
        requested by ``cont``/``step``.  Drain the ordered event lane before
        resuming, then remove only non-terminal stops already in the queue.
        """
        drain_events = getattr(self.transport, "drain_events", None)
        if drain_events is None:
            # Small white-box/fake transports used by embedders may implement
            # only request().  Real DapTransport always provides the barrier.
            return 0
        if timeout is _DEFAULT:
            drain_events()
        else:
            drain_events(timeout=timeout)

        retained = []
        discarded = 0
        while True:
            try:
                item = self._stops.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, _WaitTerminal) or (
                isinstance(item, dict)
                and item.get("reason") in {"exited", "terminated"}
            ):
                retained.append(item)
            else:
                discarded += 1
        for item in retained:
            self._stops.put(item)
        self._discarded_internal_stops += discarded
        return discarded

    # Resume/step methods block until the next stop and return its dict (running
    # breakpoint callbacks). Use cont_nowait()/interrupt()/wait() for async control.

    def run(self, *args, timeout=_DEFAULT):
        # After attach (gdbserver/pid) the inferior is stopped; "run" == go.
        return self.cont(timeout=timeout)

    def cont(self, timeout=_DEFAULT):
        """Continue, then block until the next stop; returns the stop dict."""
        timeout = self._setting("timeout", timeout)
        self.cont_nowait(timeout=timeout)
        return self.wait(timeout=timeout)

    def cont_nowait(self, *, timeout=_DEFAULT):
        """Continue without waiting (async). Collect the stop later via wait()."""
        timeout = self._setting("timeout", timeout)
        self._prepare_execution_request(timeout)
        self._request("continue", {"threadId": self._tid()}, timeout=timeout)

    def interrupt(self, *, timeout=_DEFAULT):
        """Stop a running inferior (async). Collect the stop via wait()."""
        timeout = self._setting("timeout", timeout)
        self._prepare_execution_request(timeout)
        self._request("pause", {"threadId": self._tid()}, timeout=timeout)

    def stepi(self, timeout=_DEFAULT):
        timeout = self._setting("timeout", timeout)
        self._prepare_execution_request(timeout)
        self._request(
            "stepIn",
            {"threadId": self._tid(), "granularity": "instruction"},
            timeout=timeout,
        )
        return self.wait(timeout=timeout)

    def nexti(self, timeout=_DEFAULT):
        timeout = self._setting("timeout", timeout)
        self._prepare_execution_request(timeout)
        self._request(
            "next",
            {"threadId": self._tid(), "granularity": "instruction"},
            timeout=timeout,
        )
        return self.wait(timeout=timeout)

    def step(self, timeout=_DEFAULT):
        timeout = self._setting("timeout", timeout)
        self._prepare_execution_request(timeout)
        self._request("stepIn", {"threadId": self._tid()}, timeout=timeout)
        return self.wait(timeout=timeout)

    def next(self, timeout=_DEFAULT):
        timeout = self._setting("timeout", timeout)
        self._prepare_execution_request(timeout)
        self._request("next", {"threadId": self._tid()}, timeout=timeout)
        return self.wait(timeout=timeout)

    def stepout(self, timeout=_DEFAULT):
        timeout = self._setting("timeout", timeout)
        self._prepare_execution_request(timeout)
        self._request("stepOut", {"threadId": self._tid()}, timeout=timeout)
        return self.wait(timeout=timeout)

    def skip(self, *, timeout=_DEFAULT):
        return self._request("pwncSkip", timeout=timeout)["pc"]

    def eval(self, expression, *, timeout=_DEFAULT):
        return self._request(
            "pwncEval",
            {"expression": expression},
            timeout=timeout,
        )["value"]

    def wait(self, timeout=_DEFAULT):
        """Block until the inferior stops; run breakpoint callbacks.

        cont()/stepi()/... already call this for you; use it directly only after
        the async cont_nowait()/interrupt(). A breakpoint callback gets this
        ``Gdb`` and may read/write freely. If it returns ``False`` the stop is
        delivered to the caller; otherwise execution auto-continues and ``wait``
        keeps waiting. Event-driven over a stop queue, so stops are never lost or
        coalesced.
        """
        request_timeout = self._setting("timeout", timeout)
        timeout = None if request_timeout is _DEFAULT else request_timeout
        if not self._wait_lock.acquire(blocking=False):
            raise DapError("another thread is already waiting for an inferior stop")
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            while True:
                stop = self._next_stop(deadline)
                ran = stop_requested = False
                for num in (stop.get("hitBreakpointIds") or []):
                    cb = self._bp_callbacks.get(int(num))
                    if cb is None:
                        continue
                    ran = True
                    if cb(self) is False:
                        stop_requested = True
                if ran and not stop_requested:
                    self.cont_nowait(
                        timeout=request_timeout
                    )  # resume without recursing into cont()/wait()
                    continue
                return stop
        finally:
            self._wait_lock.release()

    def _next_stop(self, deadline):
        try:
            item = self._stops.get_nowait()
        except queue.Empty:
            if self._closed:
                raise DapError("GDB session closed while waiting for a stop")
            with self._event_state_lock:
                terminal_reason = self._wait_terminal_reason
            if terminal_reason is not None:
                raise DapError(terminal_reason)

            if deadline is None:
                wait_for = None
            else:
                wait_for = deadline - time.monotonic()
                if wait_for <= 0:
                    raise DapTimeout("timed out waiting for inferior to stop")
            try:
                item = self._stops.get(timeout=wait_for)
            except queue.Empty as error:
                raise DapTimeout("timed out waiting for inferior to stop") from error

        if isinstance(item, _WaitTerminal):
            raise DapError(item.reason)
        return item

    # --- breakpoints / watchpoints ---

    def bp(
        self,
        location,
        callback=None,
        condition=None,
        temporary=False,
        *,
        timeout=_DEFAULT,
    ):
        spec = location if isinstance(location, str) else ("*" + hex(location))
        args = {"spec": spec, "temporary": temporary}
        if condition is not None:                  # omit None: gdb type-checks args
            args["condition"] = condition
        num = self._request("pwncBreakpoint", args, timeout=timeout)["number"]
        if callback is not None:
            self._bp_callbacks[num] = callback
        return DapBreakpoint(self, num)

    def watch(self, expression, kind="w", condition=None, *, timeout=_DEFAULT):
        args = {"expression": expression, "kind": kind}
        if condition is not None:
            args["condition"] = condition
        return DapBreakpoint(
            self,
            self._request("pwncWatch", args, timeout=timeout)["number"],
        )

    # --- memory ---

    def read(self, addr, size, *, timeout=_DEFAULT):
        body = self._request(
            "readMemory",
            {"memoryReference": hex(addr), "count": size},
            timeout=timeout,
        )
        data = base64.b64decode(body.get("data", "")) if body else b""
        if len(data) < size:
            raise IOError(
                "short read at %#x: got %d/%d bytes (unreadable memory)"
                % (addr, len(data), size)
            )
        return data[:size]

    def write(self, addr, data, *, timeout=_DEFAULT):
        marks = getattr(self, "marks", None)
        prepared = None if marks is None else marks._prepare_payload(addr, data)
        annotation = None
        if prepared is None:
            raw = bytes(data)
        else:
            raw, annotation = prepared
        body = self._request(
            "writeMemory",
            {
                "memoryReference": hex(addr),
                "data": base64.b64encode(raw).decode("ascii"),
            },
            timeout=timeout,
        )
        written = body.get("bytesWritten") if body else None
        if written is not None and written != len(raw):
            raise IOError(
                "short write at %#x: wrote %d/%d bytes"
                % (addr, written, len(raw))
            )
        mark = None
        if annotation is not None:
            mark = marks._commit_payload(addr, raw, annotation)
        self._record_runtime_event(
            "memory-write",
            {"address": int(addr), "size": len(raw), "payload_mark": None if mark is None else mark.id},
        )
        return mark

    def _on_typed_memory_write(self, address, raw):
        self._record_runtime_event(
            "memory-write",
            {"address": int(address), "size": len(raw), "payload_mark": None},
        )

    def _record_runtime_event(self, kind, details):
        runtime = getattr(self, "runtime", None)
        if runtime is not None:
            runtime._record_event(kind, details)

    def mark(self, address, size=None, label=None, **options):
        """Mark a live address/range for captures, history, and the viewer."""
        return self.marks.add(address, size, label, **options)

    def snapshot(self, name=None, **options):
        """Capture selected live facts into bounded semantic history."""
        return self.history.snapshot(name, **options)

    # --- console / frames / threads ---

    def execute(self, cmd, *, timeout=_DEFAULT):
        body = self._request(
            "evaluate",
            {"expression": cmd, "context": "repl"},
            timeout=timeout,
        )
        return body.get("result", "") if body else ""

    def call(self, operation, /, *args, **kwargs):
        """Synchronously call a registered GDB-side operation.

        Every keyword argument is passed to the operation.  Configure the host
        deadline separately with ``gdb.use(timeout=...).call(...)``.
        """
        timeout = self._setting("timeout", fallback=None)
        return self.operations._call(
            operation,
            args,
            kwargs,
            timeout=timeout,
        )

    def run_operation(
        self,
        name,
        arguments=None,
        *,
        callbacks=None,
        cleanup_callbacks=(),
        timeout=_DEFAULT,
        cancel_timeout=5.0,
    ):
        """Run a registered stackless GDB operation synchronously.

        Callback handlers are ordinary functions.  They may call ``execute``
        (including unmodified plugin commands) or recursively call
        ``run_operation``; no public coroutine or recursive DAP pump is used.
        """
        timeout = self._setting("timeout", timeout, fallback=None)
        return self.operations.run(
            name,
            arguments,
            callbacks=callbacks,
            cleanup_callbacks=cleanup_callbacks,
            timeout=timeout,
            cancel_timeout=cancel_timeout,
        )

    def cancel_operation(self, operation_id, timeout=_DEFAULT):
        """Request cooperative cancellation of an active operation."""
        timeout = self._setting("timeout", timeout, fallback=5.0)
        return self.operations.cancel(operation_id, timeout=timeout)

    def frame(self, level=0, *, timeout=_DEFAULT):
        body = self._request(
            "stackTrace",
            {"threadId": self._tid(), "startFrame": level, "levels": 1},
            timeout=timeout,
        )
        frames = body.get("stackFrames", [])
        if not frames:
            return None
        return DapFrame(self, frames[0], level)

    def thread(self):
        return self._tid()

    def threads(self, *, timeout=_DEFAULT):
        return self._request("threads", timeout=timeout).get("threads", [])

    def thread_facts(
        self,
        thread_id=None,
        *,
        frames=64,
        registers=True,
        variables=True,
        libc=True,
    ):
        """Capture registers, frames, scoped variables, and libc facts once."""
        return self.thread_views.capture(
            thread_id,
            frames=frames,
            registers=registers,
            variables=variables,
            libc=libc,
        )

    # --- typed symbols ---

    def _resolve_symbol(self, name, *, timeout=_DEFAULT):
        body = self._request(
            "pwncResolveSymbol",
            {"name": name},
            timeout=timeout,
        )
        if not body.get("found"):
            raise AttributeError("symbol %r not found" % name)
        addr = body["address"]

        if body.get("kind") == "function":
            # the address IS the value -> return it as a pointer
            ptype = Ptr(None, bits=self._ptrbits)
            order = "little" if self._byteorder == ByteOrder.Little else "big"
            buf = addr.to_bytes(self._ptrbits // 8, order)
            return ptype.use(BufferProvider(buf, self._byteorder, self._ptrbits))

        ptype = self._sym_type_cache.get(name)
        if ptype is None:
            doc = body.get("type")
            ptype = from_descriptor(doc) if doc else None
            if ptype is None:
                ptype = Ptr(Int(8), bits=self._ptrbits)
            self._sym_type_cache[name] = ptype
        timeout = self._setting("timeout")
        on_write = self._on_typed_memory_write if getattr(self, "runtime", None) is not None else None
        if timeout is _DEFAULT:
            provider = DapBytesProvider(
                self.transport,
                addr,
                self._byteorder,
                self._ptrbits,
                on_write=on_write,
            )
        else:
            provider = DapBytesProvider(
                self.transport,
                addr,
                self._byteorder,
                self._ptrbits,
                timeout=timeout,
                on_write=on_write,
            )
        # Return a typed value (IntValue/RefValue/...) for primitives so g.sym.X
        # supports arithmetic/deref like struct-field access does; ArrayValue for
        # arrays; a plain Value for structs/unions.
        if isinstance(ptype, (Int, Float, Double, Ptr, Enum)):
            return _typed_value(ptype, provider, 0)
        if isinstance(ptype, Array):
            return ArrayValue(ptype, provider, 0)
        return Value(ptype, provider, 0)

    # --- interactive console (independent start/stop) ---

    def console(self, terminal=None, timeout=_DEFAULT, keep_open=False):
        """Attach a configured GDB CLI console endpoint.

        ``terminal`` may be a :class:`ConsoleConfig` selecting a borrowed
        current/target TTY or an owned reconnectable PTY.  Historical terminal
        argv remains a compatibility shorthand for an owned PTY displayed in
        that external terminal.  Script and console share one GDB/inferior, and
        console-driven stops are delivered to ``wait()``.  Idempotent while the
        existing endpoint remains alive.
        """
        timeout = self._setting("timeout", timeout, fallback=10)
        console_timeout = float("inf") if timeout is None else timeout
        with self._console_lock:
            if self._closed:
                raise DapError("GDB session is closed")
            if self._console is not None and self._console.endpoint_alive:
                reused = self._console.reuse(
                    terminal,
                    timeout=console_timeout,
                    keep_open=keep_open,
                )
                if self._closed:
                    raise DapError("GDB session closed while reconnecting its console")
                return reused
            if self._console is not None:
                stale, self._console = self._console, None
                try:
                    stale._dispose_resources(force_viewer=True)
                except Exception:
                    pass
            from .console import start_console

            created = start_console(
                self,
                terminal,
                timeout=console_timeout,
                keep_open=keep_open,
            )
            # close() may have selected the session for shutdown while this
            # thread was inside the synchronous new-ui handshake.  Never
            # publish a fresh endpoint into an already-closing controller.
            if self._closed:
                if created is not None:
                    try:
                        created._abort()
                    except Exception:
                        pass
                raise DapError("GDB session closed while opening its console")
            self._console = created
            return created

    def console_close(self):
        """Close an owned viewer without removing GDB's history-bearing UI.

        Borrowed current/target TTY UIs cannot be detached with GDB's API and
        therefore raise instead of pretending the UI was removed.  The owned
        broker continues draining its PTY and can accept a later viewer; it is
        disposed only after GDB's real quit-time history flush.
        """
        with self._console_lock:
            con = self._console
            if con is None:
                return
            if not getattr(con, "detachable", True):
                raise RuntimeError(
                    "a borrowed GDB console UI cannot be detached; close the GDB session"
                )
            con.detach_viewer(timeout=3.0)

    # --- lifecycle ---

    def close(self):
        owner = threading.get_ident()
        with self._close_lock:
            if self._closed:
                if self._close_owner == owner:
                    return
                wait_for_close = True
            else:
                self._closed = True
                self._close_owner = owner
                wait_for_close = False
        if not wait_for_close:
            self._mark_lifecycle_closed()
            self._queue_wait_terminal("GDB session closed while waiting for a stop")
        if wait_for_close:
            self._close_done.wait()
            if self._close_error is not None:
                raise self._close_error
            return
        try:
            self._close_impl()
        except BaseException as error:
            with self._close_lock:
                self._close_error = error
            raise
        finally:
            with self._close_lock:
                self._close_owner = None
            self._close_done.set()

    def _quiesce_for_console_history(self):
        """Unwind an active native-DAP execution before GDB saves history.

        Native DAP captures the output of its execution command for as long as
        the inferior is running.  GDB implements that capture with its global
        batch-output flag, and ``quit_force`` intentionally skips CLI history
        while that flag is set.  A secondary interactive UI therefore needs
        one real stop before disconnect if history saving is enabled.

        The pause response alone is not the boundary: the corresponding stop
        event proves that GDB has unwound the suspended execution command.  Use
        an event for that boundary and keep the entire best-effort shutdown
        step bounded; stopped/targetless inferiors reject pause immediately.
        """
        console = getattr(self, "_console", None)
        config = getattr(console, "_config", None)
        if console is None or not getattr(config, "save_history", False):
            return
        transport = self.transport
        if not all(hasattr(transport, name) for name in ("on", "off", "request")):
            return

        quiesced = threading.Event()

        def mark_quiesced(_body):
            quiesced.set()

        events = ("stopped", "exited", "terminated")
        registered = []
        try:
            for event in events:
                transport.on(event, mark_quiesced)
                registered.append(event)
            try:
                transport.request(
                    "pause",
                    {"threadId": self._tid()},
                    timeout=1.0,
                )
            except Exception:
                # A stopped or targetless inferior has no active captured
                # execution frame and needs no quiescence step.
                return
            quiesced.wait(1.0)
        finally:
            for event in registered:
                try:
                    transport.off(event, mark_quiesced)
                except Exception:
                    pass

    def _close_impl(self):
        try:
            viewer = getattr(self, "viewer", None)
            if viewer is not None:
                viewer.close()
        except Exception:
            pass
        try:
            atexit.unregister(self._atexit_callback)
        except Exception:
            pass
        try:
            self.operations.close(timeout=5.0)
        except Exception:
            pass
        self._quiesce_for_console_history()
        disconnected = False
        try:
            self.transport.request("disconnect", {"terminateDebuggee": False},
                                   timeout=5)
            disconnected = True
        except Exception:
            pass
        if disconnected:
            # A successful DAP disconnect only confirms that its response was
            # queued.  GDB still has to drain that response and run its normal
            # process-wide `quit_force` cleanup (including shared CLI history).
            # Keep all UIs alive for a short bounded grace period; transport
            # teardown retains TERM/KILL as the fallback for a wedged GDB.
            self.transport.wait_closed(timeout=1.0)
        transport_error = None
        try:
            self.transport.close()
        except Exception as error:
            transport_error = error
        finally:
            try:
                self._transport_terminal_unsubscribe()
            except Exception:
                pass
            if self.target is not None:
                try:
                    self.target.close()
                except Exception:
                    pass
            target_cleanup = getattr(self, "_target_cleanup", None)
            self._target_cleanup = None
            if target_cleanup is not None:
                try:
                    target_cleanup()
                except Exception:
                    pass
            with self._console_lock:
                console, self._console = self._console, None
                if console is not None:
                    # Drop the side channel; the bridge closes its viewer once
                    # GDB is gone (or leaves it up if keep_open was selected).
                    try:
                        console._dispose_resources(force_viewer=False)
                    except Exception:
                        pass
        if transport_error is not None:
            raise transport_error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class _ConfiguredGdb(Gdb):
    """A cheap immutable settings facade over one live :class:`Gdb`."""

    _LOCAL_ATTRIBUTES = frozenset({"_configured_root", "_use_settings", "sym", "reg"})

    def __init__(self, root, settings):
        # Deliberately do not call Gdb.__init__: this is another view of the
        # same controller, not another transport, dispatcher, or atexit owner.
        object.__setattr__(self, "_configured_root", root)
        object.__setattr__(
            self,
            "_use_settings",
            MappingProxyType(dict(settings)),
        )
        object.__setattr__(self, "sym", SymbolAccessor(self))
        object.__setattr__(self, "reg", Registers(self))

    def __getattr__(self, name):
        return getattr(self._configured_root, name)

    def __setattr__(self, name, value):
        if name in self._LOCAL_ATTRIBUTES:
            raise AttributeError("configured GDB views are immutable")
        setattr(self._configured_root, name, value)

    def __delattr__(self, name):
        if name in self._LOCAL_ATTRIBUTES:
            raise AttributeError("configured GDB views are immutable")
        delattr(self._configured_root, name)


# ── convenience constructors ────────────────────────────────────────────────

_GDBSERVER_START_TIMEOUT = 15.0
_GDBSERVER_DIAGNOSTIC_BYTES = 64 * 1024


def _gdb_path_argument(path):
    """Quote one local filename for a GDB CLI command."""
    path = os.fsdecode(path)
    if "\n" in path or "\r" in path:
        raise ValueError("GDB paths cannot contain newlines")
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _validate_aslr_setting(value, name):
    if value is not None and type(value) is not bool:
        raise TypeError(f"{name} must be True, False, or None")
    return value


def _enable_host_aslr_preexec():
    """Clear an inherited ADDR_NO_RANDOMIZE personality in a new child."""
    personality = ctypes.CDLL(None, use_errno=True).personality
    personality.argtypes = [ctypes.c_ulong]
    personality.restype = ctypes.c_int
    current = personality(ctypes.c_ulong(-1).value)
    if current < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if personality(current & ~0x00040000) < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


class _QemuSocketPath:
    """One private filesystem Unix socket name owned by a DAP session."""

    def __init__(self):
        # Keep the address short enough for Linux's 108-byte sockaddr_un while
        # retaining filesystem permissions as the access boundary.
        self.directory = tempfile.mkdtemp(prefix="pwnc-qgdb-", dir="/tmp")
        self.path = os.path.join(self.directory, "g")
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        try:
            os.rmdir(self.directory)
        except FileNotFoundError:
            pass


def _is_unix_socket(path):
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except FileNotFoundError:
        return False


def _wait_for_qemu_socket(target, path, timeout=_GDBSERVER_START_TIMEOUT):
    """Wait eventfully for qemu-user to bind its private GDB socket."""
    if _is_unix_socket(path):
        return

    libc = ctypes.CDLL(None, use_errno=True)
    init = libc.inotify_init1
    init.argtypes = [ctypes.c_int]
    init.restype = ctypes.c_int
    add_watch = libc.inotify_add_watch
    add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    add_watch.restype = ctypes.c_int

    descriptor = init(os.O_CLOEXEC)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    pid_descriptor = None
    try:
        mask = 0x00000100 | 0x00000080  # IN_CREATE | IN_MOVED_TO
        if add_watch(descriptor, os.fsencode(os.path.dirname(path)), mask) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), os.path.dirname(path))

        # Close the create-before-watch race with one state check.  There is no
        # timed retry loop: inotify and pidfd are the only wake sources.
        if _is_unix_socket(path):
            return
        if hasattr(os, "pidfd_open"):
            try:
                pid_descriptor = os.pidfd_open(target.pid)
            except OSError:
                pid_descriptor = None
        readers = [descriptor]
        if pid_descriptor is not None:
            readers.append(pid_descriptor)
        ready, _writable, _exceptional = select.select(readers, [], [], timeout)
        if descriptor in ready:
            os.read(descriptor, 4096)
            if _is_unix_socket(path):
                return
        if pid_descriptor in ready or target.poll(block=False) is not None:
            reason = "qemu-user exited before binding its GDB socket"
        else:
            reason = "timed out waiting for qemu-user's GDB socket"
        try:
            diagnostic = target.clean(timeout=0).decode("utf-8", "replace").strip()
        except Exception:
            diagnostic = ""
        if diagnostic:
            reason += ": " + diagnostic
        raise DapError(reason, body={"qemuOutput": diagnostic})
    finally:
        if pid_descriptor is not None:
            os.close(pid_descriptor)
        os.close(descriptor)


def _elf_identity(program):
    """Return the shared pwntools-backed ELF identity, or None for non-ELFs."""
    try:
        with open(program, "rb") as executable:
            if executable.read(4) != b"\x7fELF":
                return None
    except OSError:
        return None
    from pwnc.qemu_user import inspect_elf

    return inspect_elf(program)


def _needs_qemu(program, executable=None):
    identity = _elf_identity(program)
    if executable is not None:
        if identity is None:
            raise ValueError("qemu-user requires an ELF executable")
        return True
    return identity is not None and not identity.native


def _merge_qemu_environment(environment, delta):
    if not delta:
        return environment
    if environment is None:
        environb = getattr(os, "environb", None)
        merged = dict(environb if environb is not None else os.environ)
    else:
        merged = dict(environment)
    merged.update(delta)
    return merged


def _join_solib_search_path(paths):
    if not paths:
        return None
    separator = os.fsencode(os.pathsep) if isinstance(paths[0], bytes) else os.pathsep
    return separator.join(paths)


def _qemu_prepared(
    gdb,
    program,
    args,
    env,
    *,
    qemu,
    sysroot,
    host_aslr,
    qemu_aslr,
):
    """Bind a prepared DAP GDB to qemu-user's stopped initial guest."""
    from pwn import process as pwnprocess
    from pwnc.qemu_user import plan_qemu

    endpoint = _QemuSocketPath()
    target = None
    try:
        plan = plan_qemu(
            program,
            *args,
            executable=qemu,
            sysroot=sysroot,
            qemu_aslr=qemu_aslr,
            gdb=endpoint.path,
            host_aslr=host_aslr,
        )
        environment = _merge_qemu_environment(env, plan.env)
        process_options = {
            "env": environment,
            "aslr": host_aslr,
        }
        if host_aslr is True:
            process_options["preexec_fn"] = _enable_host_aslr_preexec
        target = pwnprocess(plan.argv, **process_options)
        _wait_for_qemu_socket(target=target, path=endpoint.path)
        gdb._connect_remote(
            program,
            endpoint.path,
            sysroot="/" if sysroot is None else sysroot,
            solib_search_path=_join_solib_search_path(plan.solib_search_path),
            qemu_user=True,
        )
        _adopt_target(gdb, target, endpoint.close)
        target = None
        endpoint = None
    finally:
        if target is not None:
            try:
                target.close()
            except Exception:
                pass
        if endpoint is not None:
            endpoint.close()


def _resolve_pid(pid_or_name):
    """Resolve the historical PID-or-exact-name attach argument."""
    if isinstance(pid_or_name, int):
        return pid_or_name

    import shutil
    import subprocess

    pidof = shutil.which("pidof")
    if not pidof:
        raise RuntimeError("pidof not available; pass a PID instead")
    result = subprocess.run(
        [pidof, os.fsdecode(pid_or_name)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("process %r not found" % pid_or_name)
    return int(result.stdout.strip().split()[0])


def _gdbserver_port(target, timeout=_GDBSERVER_START_TIMEOUT):
    """Wait for gdbserver's port announcement, retaining useful failures."""
    deadline = time.monotonic() + timeout
    transcript = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            reason = "timed out waiting for gdbserver to announce a port"
            break
        try:
            # The tube's fd readiness wakes this immediately when gdbserver
            # writes or exits.  Use the real startup deadline instead of
            # periodically probing process state in quarter-second slices.
            line = target.recvline(timeout=remaining)
        except EOFError:
            reason = "gdbserver exited before announcing a port"
            break
        if line:
            if len(transcript) < _GDBSERVER_DIAGNOSTIC_BYTES:
                transcript.extend(line[: _GDBSERVER_DIAGNOSTIC_BYTES - len(transcript)])
            match = re.search(rb"\bListening on port ([0-9]+)\b", line)
            if match is not None:
                return int(match.group(1))
        else:
            reason = (
                "gdbserver exited before announcing a port"
                if target.poll(block=False) is not None
                else "timed out waiting for gdbserver to announce a port"
            )
            break

    try:
        remainder = target.clean(timeout=0.1)
    except Exception:
        remainder = b""
    if remainder and len(transcript) < _GDBSERVER_DIAGNOSTIC_BYTES:
        transcript.extend(remainder[: _GDBSERVER_DIAGNOSTIC_BYTES - len(transcript)])
    diagnostic = bytes(transcript).decode("utf-8", "replace").strip()
    if diagnostic:
        reason += ": " + diagnostic
    raise DapError(reason, body={"gdbserverOutput": diagnostic})


def _finish_inferior_launch(gdb, target, timeout=_GDBSERVER_START_TIMEOUT):
    """Advance the private launcher to the real executable, then stop there."""
    gdb.transport.request(
        "evaluate", {"expression": "tcatch exec", "context": "repl"}
    )
    stop = gdb.cont(timeout=timeout)
    if stop.get("reason") in {"exited", "terminated"}:
        try:
            output = target.clean(timeout=0.25)
        except Exception:
            output = b""
        diagnostic = output.decode("utf-8", "replace").strip()
        reason = "inferior launcher exited before executing the target"
        if diagnostic:
            reason += ": " + diagnostic
        raise DapError(reason, body={**stop, "gdbserverOutput": diagnostic})
    arch = gdb.transport.request("pwncArch")
    gdb._byteorder = (
        ByteOrder.Little if arch.get("byteorder") == "little" else ByteOrder.Big
    )
    gdb._ptrbits = arch.get("ptrbits", 64)
    gdb._sym_type_cache.clear()


def _adopt_target(gdb, target, cleanup=None):
    """Transfer a locally spawned inferior and auxiliaries to *gdb*."""
    with gdb._lifecycle_lock:
        if (
            gdb._state is not GdbState.BINDING
            or gdb._closed
            or gdb.transport.closed
        ):
            raise DapError("GDB session closed while binding its target")
        gdb.target = target
        gdb._target_cleanup = cleanup


def _debug_prepared(gdb, program, args, env, *, host_aslr=None):
    """Bind an initialized one-shot GDB to a new gdbserver target."""
    from pwn import process as pwnprocess

    launcher, launcher_env, launch_config = prepare_launch(program, args, env)
    gdbserver_cmd = [
        "gdbserver",
        "--once",
    ]
    if host_aslr is not None:
        gdbserver_cmd.append(
            "--no-disable-randomization"
            if host_aslr
            else "--disable-randomization"
        )
    gdbserver_cmd.extend([
        "--no-startup-with-shell",
        "127.0.0.1:0",
        launcher,
    ])
    target = None
    try:
        process_options = {"env": launcher_env}
        if host_aslr is not None:
            process_options["aslr"] = host_aslr
        if host_aslr is True:
            process_options["preexec_fn"] = _enable_host_aslr_preexec
        target = pwnprocess(gdbserver_cmd, **process_options)
        port = _gdbserver_port(target)
        # gdbserver is initially stopped in the host-native Python argv/env
        # launcher, which may have a different word size than the inferior.
        # Re-selecting a 32-bit file during that temporary 64-bit target state
        # makes GDB reject gdbserver's register packet.  Reapply immediately
        # after the catch-exec transition instead.
        identity = _elf_identity(program)
        reapply_while_launcher = (
            identity is None
            or identity.bits == ctypes.sizeof(ctypes.c_void_p) * 8
        )
        gdb._connect_remote(
            program,
            "127.0.0.1:%d" % port,
            reapply=reapply_while_launcher,
        )
        _finish_inferior_launch(gdb, target)
        gdb._configure_remote_files(program, "/", None)

        # Do not transfer ownership into an already-closing controller.  A
        # close racing before this point could otherwise miss the local tube.
        _adopt_target(gdb, target)
        target = None
    finally:
        discard_config(launch_config)
        if target is not None:
            try:
                target.close()
            except Exception:
                pass


def _configure_console(gdb, *, headless, console, console_keep_open):
    """Normalize explicit console modes and the historical constructor flags."""
    if headless is not None and type(headless) is not bool:
        raise TypeError("headless must be True, False, or None")
    if isinstance(console, ConsoleConfig):
        wants_console = console.mode is not ConsoleMode.NONE
        if headless is True and wants_console:
            raise ValueError("headless=True conflicts with a non-none ConsoleConfig")
        if headless is False and not wants_console:
            raise ValueError("headless=False conflicts with ConsoleConfig.none()")
        if console_keep_open:
            raise ValueError(
                "console_keep_open is a legacy option; set it on ViewerConfig"
            )
        if wants_console:
            gdb.console(console)
        return

    if console is not None:
        if headless is True:
            raise ValueError("headless=True conflicts with an explicit console")
        gdb.console(console, keep_open=console_keep_open)
    elif headless is False:
        # Legacy opt-in uses the owned PTY bridge and launcher discovery.
        gdb.console(None, keep_open=console_keep_open)


def _select_gdb_for_program(program, gdb_path, qemu):
    """Use gdb-multiarch for an automatic/explicit qemu-user session."""
    if gdb_path != "gdb":
        return gdb_path
    program = os.path.abspath(os.fsdecode(program))
    if not _needs_qemu(program, qemu):
        return gdb_path
    return shutil.which("gdb-multiarch") or gdb_path


def start(
    *,
    gdb_path="gdb",
    gdb_args=None,
    env=None,
    init=True,
    headless=None,
    console=None,
    console_keep_open=False,
    _on_created=None,
):
    """Start and initialize GDB without selecting an inferior.

    With ``init=True`` (the default), GDB loads its normal initialization
    files, including ``~/.gdbinit``.  ``init=False`` passes ``-nx`` for a
    deterministic init-free process.  The returned controller is in
    :attr:`GdbState.PREPARED` and may load
    plugins, create an owned console, and then bind exactly one target through
    :meth:`Gdb.attach`, :meth:`Gdb.connect`, :meth:`Gdb.launch`, or
    :meth:`Gdb.debug`.
    """
    transport = None
    gdb = None
    try:
        if _on_created is not None and not callable(_on_created):
            raise TypeError("_on_created must be callable or None")
        transport = DapTransport(
            gdb_path=gdb_path,
            gdb_args=gdb_args,
            env=env,
            init=init,
        )
        gdb = Gdb(transport)
        if _on_created is not None:
            # Private construction hook used by GdbPool to own and therefore
            # cancel a real GDB while initialization is still in flight.  It
            # runs before the first protocol request and is not a setup hook.
            _on_created(gdb)
        gdb._initialize()
        _configure_console(
            gdb,
            headless=headless,
            console=console,
            console_keep_open=console_keep_open,
        )
        return gdb
    except BaseException:
        _cleanup_failed_construction(gdb, transport)
        raise


def debug(
    program,
    *args,
    gdb_path="gdb",
    gdb_args=None,
    env=None,
    init=True,
    headless=None,
    console=None,
    console_keep_open=False,
    qemu=None,
    sysroot=None,
    host_aslr=None,
    qemu_aslr=None,
):
    """Run *program* under gdbserver or qemu-user and drive it via DAP.

    The target runs in a pwntools process tube (``g.target``) with its own
    stdin/stdout — clean IO separation from gdb's DAP traffic — while gdb attaches
    over ``target remote``. Headless by default; pass an explicit
    :class:`ConsoleConfig` for a borrowed TTY or owned reconnectable PTY.
    ``headless=False`` and ``console=<terminal argv>`` remain compatibility
    shims for an externally displayed owned console.
    """
    g = None
    try:
        gdb_path = _select_gdb_for_program(program, gdb_path, qemu)
        g = start(gdb_path=gdb_path, gdb_args=gdb_args, env=env, init=init)
        g.debug(
            program,
            *args,
            env=env,
            qemu=qemu,
            sysroot=sysroot,
            host_aslr=host_aslr,
            qemu_aslr=qemu_aslr,
        )
        _configure_console(
            g,
            headless=headless,
            console=console,
            console_keep_open=console_keep_open,
        )
        return g
    except BaseException:
        _cleanup_failed_construction(g, None)
        raise


def attach(pid_or_name, program=None, gdb_path="gdb", gdb_args=None, env=None,
           headless=None, console=None, console_keep_open=False, *, init=True):
    """Attach gdb (over DAP) to a running process by PID or name."""
    pid = _resolve_pid(pid_or_name)
    g = None
    try:
        g = start(gdb_path=gdb_path, gdb_args=gdb_args, env=env, init=init)
        g.attach(pid, program)
        _configure_console(
            g,
            headless=headless,
            console=console,
            console_keep_open=console_keep_open,
        )
        return g
    except BaseException:
        _cleanup_failed_construction(g, None)
        raise


def launch(
    program,
    *args,
    gdb_path="gdb",
    gdb_args=None,
    env=None,
    init=True,
    headless=None,
    console=None,
    console_keep_open=False,
    stop_at_main=True,
    qemu=None,
    sysroot=None,
    host_aslr=None,
    qemu_aslr=None,
):
    """Run a native program in GDB, or a foreign ELF under qemu-user.

    Native inferiors stop at ``main`` by default and expose stdio as DAP output
    events. Foreign ELFs use the same clean-IO qemu-user tube as :func:`debug`
    and return stopped before their first guest instruction.
    """
    g = None
    try:
        gdb_path = _select_gdb_for_program(program, gdb_path, qemu)
        g = start(gdb_path=gdb_path, gdb_args=gdb_args, env=env, init=init)
        g.launch(
            program,
            *args,
            env=env,
            stop_at_main=stop_at_main,
            qemu=qemu,
            sysroot=sysroot,
            host_aslr=host_aslr,
            qemu_aslr=qemu_aslr,
        )
        _configure_console(
            g,
            headless=headless,
            console=console,
            console_keep_open=console_keep_open,
        )
        return g
    except BaseException:
        _cleanup_failed_construction(g, None)
        raise


def _cleanup_failed_construction(g, transport):
    """Best-effort cleanup for a constructor that did not return a session."""
    try:
        if g is not None:
            g.close()
        elif transport is not None:
            transport.close()
    except Exception:
        pass


# Imported after the controller/convenience constructors so pool.py can lazily
# call the public targetless ``start()`` without a package initialization cycle.
from .pool import GdbPool, GdbPoolError, PoolConsole, PoolSelection
from .viewer import ViewerRouter
from .discovery import (
    DEFAULT_POOL_NAME,
    PoolAddress,
    PoolAlreadyRunningError,
    PoolDiscoveryError,
    PoolSocketLease,
    acquire_pool_socket,
    discover_manager,
    discover_viewer,
)
from .viewer_client import PoolConnectionError, view

__all__.extend(
    [
        "DEFAULT_POOL_NAME",
        "GdbPool",
        "GdbPoolError",
        "PoolAddress",
        "PoolAlreadyRunningError",
        "PoolConnectionError",
        "PoolConsole",
        "PoolDiscoveryError",
        "PoolSelection",
        "PoolSocketLease",
        "ViewerRouter",
        "acquire_pool_socket",
        "discover_manager",
        "discover_viewer",
        "view",
    ]
)
