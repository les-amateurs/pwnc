"""pwnc.gdb.dap — drive gdb from an external python process over DAP.

A reimplementation of ``pwnc.gdb.mi`` on top of gdb's native Debug Adapter
Protocol interpreter (``gdb --interpreter=dap``). Native DAP handles the control
plane (run/step/break, memory, registers, stacks); a small in-gdb extension
(``_ext.py``) adds the things DAP omits — most importantly structural
``gdb.Type`` layout, reconstructed client-side into ``pwnc.types`` Values.

Public API mirrors ``pwnc.gdb.mi``::

    from pwnc.gdb.dap import debug
    g = debug("./binary")
    g.bp("main"); g.run(); g.wait()
    x = g.sym.counter            # typed pwnc.types Value over live memory
    g.reg.rip = 0x401000         # registers
    data = g.read(addr, 64)      # raw memory
    g.stepi(); g.cont(); g.close()
"""

import atexit
import base64
import os
import queue

from pwnc.types.provider import ByteOrder, BufferProvider
from pwnc.types.primitives import Ptr, Int, Float, Double
from pwnc.types.containers import Array, Enum
from pwnc.types.value import Value, ArrayValue, _typed_value
from pwnc.types.serial import from_descriptor

from .transport import DapTransport, DapError, DapTimeout
from .client import DapBytesProvider

__all__ = ["Gdb", "debug", "attach", "launch", "DapError", "DapTimeout"]


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
        return self._gdb.transport.request("pwncReadRegister", {"name": name})["value"]

    def __setattr__(self, name, value):
        self._gdb.transport.request("pwncWriteRegister",
                                    {"name": name, "value": int(value)})

    def __call__(self):
        return self._gdb.transport.request("pwncReadRegisters")["registers"]


# ── lightweight handles (no gdb-object proxies / no server object store) ────

class DapBreakpoint:
    def __init__(self, gdb, number):
        self._gdb = gdb
        self.number = number

    def delete(self):
        self._gdb.transport.request("pwncDeleteBreakpoint", {"number": self.number})
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

    def older(self):
        return self._gdb.frame(self.level + 1)

    def __repr__(self):
        return "<DapFrame #%d %s @ %#x>" % (self.level, self.name(), self.pc() or 0)


# ── main controller ─────────────────────────────────────────────────────────

class Gdb:
    """gdb controller over DAP with typed memory/symbol access."""

    def __init__(self, transport):
        self.transport = transport
        self.target = None              # pwntools tube (set by debug())
        self._closed = False
        self._bp_callbacks = {}         # gdb bp number -> callback(gdb)
        self._stops = queue.Queue()
        self._cur_thread = None
        self._byteorder = ByteOrder.Little
        self._ptrbits = 64
        self._sym_type_cache = {}       # symbol name -> reconstructed Type
        self._console = None            # Console handle (interactive UI)
        self.sym = SymbolAccessor(self)
        self.reg = Registers(self)
        transport.on("stopped", self._on_stopped)
        transport.on("exited", self._on_exited)
        transport.on("terminated", self._on_terminated)
        atexit.register(self.close)

    # --- async events (reader thread) ---

    def _on_stopped(self, body):
        tid = body.get("threadId")
        if tid is not None:
            self._cur_thread = tid
        self._stops.put(body)

    def _on_exited(self, body):
        self._stops.put({"reason": "exited", "exitCode": body.get("exitCode")})

    def _on_terminated(self, body):
        self._stops.put({"reason": "terminated"})

    # --- bootstrap / connect ---

    def _initialize(self):
        self.transport.request("initialize", {
            "clientID": "pwnc", "adapterID": "gdb", "locale": "en",
            "linesStartAt1": True, "columnsStartAt1": True, "pathFormat": "path",
            "supportsVariableType": True, "supportsMemoryReferences": True,
            "supportsRunInTerminalRequest": False,
        })
        self.transport.wait_initialized()
        ext = os.path.join(os.path.dirname(__file__), "_ext.py")
        self.transport.request("evaluate",
                               {"expression": "source " + ext, "context": "repl"})
        self.transport.request("configurationDone")

    def _post_connect(self):
        arch = self.transport.request("pwncArch")
        self._byteorder = (ByteOrder.Little if arch.get("byteorder") == "little"
                           else ByteOrder.Big)
        self._ptrbits = arch.get("ptrbits", 64)
        try:
            ths = self.transport.request("threads").get("threads", [])
            if ths:
                self._cur_thread = ths[0]["id"]
        except DapError:
            pass
        # Consume the initial (attach) stop so the user's first wait() returns
        # *their* stop, not the connect-time one.
        try:
            self._stops.get(timeout=10)
        except queue.Empty:
            pass

    def _connect_remote(self, program, target):
        if program:
            self.transport.request(
                "evaluate", {"expression": "file " + program, "context": "repl"})
        # Read shared libs/debug info from the local filesystem (identical to the
        # remote's, since gdbserver runs locally) instead of slow remote transfers.
        self.transport.request(
            "evaluate", {"expression": "set sysroot /", "context": "repl"})
        self.transport.request("attach", {"target": target})
        self._post_connect()

    def _connect_pid(self, pid, program=None):
        args = {"pid": pid}
        if program:
            args["program"] = program
        self.transport.request("attach", args)
        self._post_connect()

    def _launch(self, program, args=(), env=None, stop_at_main=True):
        launch_args = {
            "program": program,
            "args": [str(a) for a in args],
            "stopAtBeginningOfMainSubprogram": bool(stop_at_main),
        }
        if env is not None:
            launch_args["env"] = dict(env)
        self.transport.request("launch", launch_args)   # responds immediately
        self._post_connect()                            # consumes the stop-at-main

    # --- execution control ---

    def _tid(self):
        return self._cur_thread if self._cur_thread is not None else 1

    # Resume/step methods block until the next stop and return its dict (running
    # breakpoint callbacks). Use cont_nowait()/interrupt()/wait() for async control.

    def run(self, *args, timeout=None):
        # After attach (gdbserver/pid) the inferior is stopped; "run" == go.
        return self.cont(timeout=timeout)

    def cont(self, timeout=None):
        """Continue, then block until the next stop; returns the stop dict."""
        self.cont_nowait()
        return self.wait(timeout=timeout)

    def cont_nowait(self):
        """Continue without waiting (async). Collect the stop later via wait()."""
        self.transport.request("continue", {"threadId": self._tid()})

    def interrupt(self):
        """Stop a running inferior (async). Collect the stop via wait()."""
        self.transport.request("pause", {"threadId": self._tid()})

    def stepi(self, timeout=None):
        self.transport.request("stepIn",
                               {"threadId": self._tid(), "granularity": "instruction"})
        return self.wait(timeout=timeout)

    def nexti(self, timeout=None):
        self.transport.request("next",
                               {"threadId": self._tid(), "granularity": "instruction"})
        return self.wait(timeout=timeout)

    def step(self, timeout=None):
        self.transport.request("stepIn", {"threadId": self._tid()})
        return self.wait(timeout=timeout)

    def next(self, timeout=None):
        self.transport.request("next", {"threadId": self._tid()})
        return self.wait(timeout=timeout)

    def stepout(self, timeout=None):
        self.transport.request("stepOut", {"threadId": self._tid()})
        return self.wait(timeout=timeout)

    def skip(self):
        return self.transport.request("pwncSkip")["pc"]

    def eval(self, expression):
        return self.transport.request("pwncEval", {"expression": expression})["value"]

    def wait(self, timeout=None):
        """Block until the inferior stops; run breakpoint callbacks.

        cont()/stepi()/... already call this for you; use it directly only after
        the async cont_nowait()/interrupt(). A breakpoint callback gets this
        ``Gdb`` and may read/write freely. If it returns ``False`` the stop is
        delivered to the caller; otherwise execution auto-continues and ``wait``
        keeps waiting. Event-driven over a stop queue, so stops are never lost or
        coalesced.
        """
        while True:
            try:
                stop = self._stops.get(timeout=timeout)
            except queue.Empty:
                raise DapTimeout("timed out waiting for inferior to stop")
            ran = stop_requested = False
            for num in (stop.get("hitBreakpointIds") or []):
                cb = self._bp_callbacks.get(int(num))
                if cb is None:
                    continue
                ran = True
                if cb(self) is False:
                    stop_requested = True
            if ran and not stop_requested:
                self.cont_nowait()      # resume without recursing into cont()/wait()
                continue
            return stop

    # --- breakpoints / watchpoints ---

    def bp(self, location, callback=None, condition=None, temporary=False):
        spec = location if isinstance(location, str) else ("*" + hex(location))
        args = {"spec": spec, "temporary": temporary}
        if condition is not None:                  # omit None: gdb type-checks args
            args["condition"] = condition
        num = self.transport.request("pwncBreakpoint", args)["number"]
        if callback is not None:
            self._bp_callbacks[num] = callback
        return DapBreakpoint(self, num)

    def watch(self, expression, kind="w", condition=None):
        args = {"expression": expression, "kind": kind}
        if condition is not None:
            args["condition"] = condition
        return DapBreakpoint(self, self.transport.request("pwncWatch", args)["number"])

    # --- memory ---

    def read(self, addr, size):
        body = self.transport.request("readMemory",
                                      {"memoryReference": hex(addr), "count": size})
        data = base64.b64decode(body.get("data", "")) if body else b""
        return data[:size]

    def write(self, addr, data):
        self.transport.request("writeMemory", {
            "memoryReference": hex(addr),
            "data": base64.b64encode(bytes(data)).decode("ascii"),
        })

    # --- console / frames / threads ---

    def execute(self, cmd):
        body = self.transport.request("evaluate",
                                      {"expression": cmd, "context": "repl"})
        return body.get("result", "") if body else ""

    def frame(self, level=0):
        body = self.transport.request("stackTrace", {
            "threadId": self._tid(), "startFrame": level, "levels": 1})
        frames = body.get("stackFrames", [])
        if not frames:
            return None
        return DapFrame(self, frames[0], level)

    def thread(self):
        return self._tid()

    def threads(self):
        return self.transport.request("threads").get("threads", [])

    # --- typed symbols ---

    def _resolve_symbol(self, name):
        body = self.transport.request("pwncResolveSymbol", {"name": name})
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
        provider = DapBytesProvider(self.transport, addr, self._byteorder, self._ptrbits)
        # Return a typed value (IntValue/RefValue/...) for primitives so g.sym.X
        # supports arithmetic/deref like struct-field access does; ArrayValue for
        # arrays; a plain Value for structs/unions.
        if isinstance(ptype, (Int, Float, Double, Ptr, Enum)):
            return _typed_value(ptype, provider, 0)
        if isinstance(ptype, Array):
            return ArrayValue(ptype, provider, 0)
        return Value(ptype, provider, 0)

    # --- interactive console (independent start/stop) ---

    def console(self, terminal=None, timeout=10, keep_open=False):
        """Open a gdb CLI console in a terminal window (kitty by default).

        Independent of the session — call it any time, headless or not. The
        console and the script share one gdb/inferior: driving execution from
        the console (typing ``run``/``continue``/stepping) produces stops that
        the script receives, so breakpoint callbacks fire during ``g.wait()``.
        The window tracks resizes (gdb plugins get the right width) and
        auto-closes when gdb exits unless ``keep_open=True``. Idempotent —
        returns the existing console if one is already open.
        """
        if self._console is not None and self._console.alive():
            return self._console
        from .console import start_console
        self._console = start_console(self, terminal, timeout=timeout,
                                      keep_open=keep_open)
        return self._console

    def console_close(self):
        """Close the console window now (regardless of ``keep_open``)."""
        if self._console is not None:
            self._console.kill()
            self._console = None

    # --- lifecycle ---

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.transport.request("disconnect", {"terminateDebuggee": False},
                                   timeout=5)
        except Exception:
            pass
        self.transport.close()
        if self.target is not None:
            try:
                self.target.close()
            except Exception:
                pass
        if self._console is not None:
            # Drop the side channel; the agent closes the window once gdb is
            # gone (or keeps it open if console_keep_open was set).
            try:
                self._console.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ── convenience constructors ────────────────────────────────────────────────

def debug(program, *args, gdb_path="gdb", gdb_args=None, env=None,
          headless=True, console=None, console_keep_open=False):
    """Run *program* under gdbserver and drive it via DAP.

    The target runs in a pwntools process tube (``g.target``) with its own
    stdin/stdout — clean IO separation from gdb's DAP traffic — while gdb attaches
    over ``target remote``. Headless by default; pass ``headless=False`` (and
    optionally ``console=<terminal argv>`` or set ``$PWNC_DAP_TERMINAL``) for an
    interactive gdb console window.
    """
    from pwn import process as pwnprocess

    # --no-startup-with-shell: exec the target directly instead of via /bin/sh.
    # The shell layer interferes with argv[0]/env and, in restricted/container
    # environments, can leave gdbserver wedged in sigsuspend before it ever
    # services the RSP connection (gdb's target-remote then hangs).
    gdbserver_cmd = ["gdbserver", "--once", "--no-startup-with-shell",
                     "127.0.0.1:0", program]
    gdbserver_cmd.extend(str(a) for a in args)
    target = pwnprocess(gdbserver_cmd, env=env)
    line = target.recvline_contains(b"Listening on port")
    port = int(line.split(b"port ")[-1])

    g = Gdb(DapTransport(gdb_path=gdb_path, gdb_args=gdb_args, env=env))
    g._initialize()
    g._connect_remote(os.path.abspath(program), "127.0.0.1:%d" % port)
    g.target = target
    if not headless:
        g.console(console, keep_open=console_keep_open)
    return g


def attach(pid_or_name, program=None, gdb_path="gdb", gdb_args=None, env=None,
           headless=True, console=None, console_keep_open=False):
    """Attach gdb (over DAP) to a running process by PID or name."""
    if isinstance(pid_or_name, int):
        pid = pid_or_name
    else:
        import shutil
        import subprocess
        pidof = shutil.which("pidof")
        if not pidof:
            raise RuntimeError("pidof not available; pass a PID instead")
        result = subprocess.run([pidof, pid_or_name], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("process %r not found" % pid_or_name)
        pid = int(result.stdout.strip().split()[0])

    g = Gdb(DapTransport(gdb_path=gdb_path, gdb_args=gdb_args, env=env))
    g._initialize()
    g._connect_pid(pid, program)
    if not headless:
        g.console(console, keep_open=console_keep_open)
    return g


def launch(program, *args, gdb_path="gdb", gdb_args=None, env=None,
           headless=True, console=None, console_keep_open=False, stop_at_main=True):
    """Run *program* locally under gdb (no gdbserver) and stop at ``main``.

    Simpler than :func:`debug` and dependency-free (no pwntools); the inferior's
    stdio is gdb's, surfaced as DAP output events rather than a tube — so prefer
    :func:`debug` when you need clean byte-level IO with the target (pwn). After
    this returns the inferior is stopped at ``main``; set breakpoints and
    ``cont()``/``wait()`` as usual.
    """
    g = Gdb(DapTransport(gdb_path=gdb_path, gdb_args=gdb_args, env=env))
    g._initialize()
    g._launch(os.path.abspath(program), args, env, stop_at_main)
    if not headless:
        g.console(console, keep_open=console_keep_open)
    return g
