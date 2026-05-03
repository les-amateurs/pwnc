"""pwnc.gdb.mi — GDB MI3 library with typed memory access.

Public API:
    Gdb          — main GDB controller
    debug(prog)  — spawn GDB on a program
    attach(pid)  — attach to a running process
"""

import base64
import io
import os
import pickle

from .process import GdbProcess
from .protocol import Return, Error
from .proxy import PROXY_CLASSES, BreakpointProxy, InferiorProxy, FrameProxy, ThreadProxy
from pwnc.types.provider import BytesProvider, ByteOrder
from pwnc.types.primitives import Int, Float, Double, Ptr
from pwnc.types.containers import Struct, Union, Array, Enum
from pwnc.types.value import Value


# --- Type descriptor → pwnc.types reconstruction ---

def pwnc_type_from_desc(desc, _cache=None):
    """Reconstruct a pwnc.types.Type from a serializable dict descriptor.

    Handles cyclic descriptors (e.g. struct Node with a Node* field):
    the bridge emits the same dict object for every occurrence of the
    same struct, so pickle preserves identity.  We detect this via
    ``id(desc)`` and return the in-progress Struct/Union, which will
    be fully populated by the time the top-level call returns.
    """
    if desc is None:
        return None
    if _cache is None:
        _cache = {}

    desc_id = id(desc)
    if desc_id in _cache:
        return _cache[desc_id]

    kind = desc["kind"]
    if kind == "int":
        return Int(desc["bits"], signed=desc.get("signed", False))
    if kind == "float":
        return Float()
    if kind == "double":
        return Double()
    if kind == "ptr":
        return Ptr(pwnc_type_from_desc(desc["child"], _cache), bits=desc["bits"])
    if kind == "array":
        return Array(pwnc_type_from_desc(desc["child"], _cache), desc["count"])
    if kind == "struct":
        return _struct_from_desc(desc, _cache, Struct)
    if kind == "union":
        return _struct_from_desc(desc, _cache, Union)
    if kind == "enum":
        return Enum(pwnc_type_from_desc(desc["child"], _cache),
                    desc["members"], name=desc.get("name"))
    if kind == "void":
        return None
    return Int(desc.get("bits", 8), signed=False)


def _struct_from_desc(desc, _cache, cls):
    """Build a Struct or Union from a descriptor, handling self-references.

    The object is allocated and cached *before* its fields are resolved
    so that cyclic pointer children find the already-existing object.
    Uses ``_from_layout``-style initialisation to preserve the exact
    field offsets reported by GDB (respecting alignment padding).
    """
    from pwnc.types.base import Type as TypeBase

    obj = object.__new__(cls)
    _cache[id(desc)] = obj          # cache before recursing into fields

    name = desc["name"]
    size = desc.get("size", 0)

    layout = []
    for f in desc["fields"]:
        ftype = pwnc_type_from_desc(f["type"], _cache)
        fname = f["name"]
        byte_off = f.get("offset", 0)
        bit_off = f.get("bit_offset", 0)
        layout.append((fname, ftype, byte_off, byte_off * 8 + bit_off))

    obj.name = name
    obj.mode = "packed"
    obj._fields = [(l[0], l[1]) for l in layout]
    obj._layout = layout
    obj._padding = []
    obj._field_map = {l[0]: i for i, l in enumerate(layout)}
    TypeBase.__init__(obj, size * 8)

    return obj


# --- MI-based bridge connection ---

_RESULT_MARKER = "__PWNC_RESULT__:"


class BridgeConnection:
    """RPC connection to the bridge via MI interpreter-exec commands.

    Each call serializes (method, args, kwargs) as pickle → base64,
    executes it as a GDB python command, and reads the pickled result
    from the console stream output.
    """

    def __init__(self, process, proxy_classes=None):
        self._process = process
        self._proxy_classes = proxy_classes or {}

    def call(self, method, *args, **kwargs):
        # serialize request
        payload = pickle.dumps((method, args, kwargs))
        b64 = base64.b64encode(payload).decode()

        # execute via MI console → runs on GDB main thread
        output = self._process.console(f'python _pwnc_dispatch("{b64}")')

        # find the result marker in output
        for line in output.split('\n'):
            if line.startswith(_RESULT_MARKER):
                result_b64 = line[len(_RESULT_MARKER):]
                result_data = base64.b64decode(result_b64)
                buf = io.BytesIO(result_data)
                unpickler = _ProxyUnpickler(buf, self._proxy_classes, self)
                result = unpickler.load()

                if isinstance(result, Return):
                    return result.value
                elif isinstance(result, Error):
                    raise RuntimeError(f"Bridge error: {result.exception}")
                else:
                    raise RuntimeError(f"Unexpected bridge response: {result}")

        raise RuntimeError(f"No bridge result in output: {output[:200]}")

    def close(self):
        pass


class _ProxyUnpickler(pickle.Unpickler):
    """Unpickler that reconstructs GDB proxy objects."""

    def __init__(self, f, proxy_classes, conn):
        super().__init__(f)
        self.proxy_classes = proxy_classes
        self.conn = conn

    def persistent_load(self, pid):
        type_name, oid = pid
        cls = self.proxy_classes.get(type_name)
        if cls is None:
            raise pickle.UnpicklingError(f"Unknown proxy type: {type_name}")
        return cls(self.conn, oid)


# --- Remote bytes provider ---

class GdbRemoteBytesProvider(BytesProvider):
    """BytesProvider that reads/writes memory via GDB bridge RPC."""

    def __init__(self, conn, base_addr, byteorder, ptrbits=64):
        self._conn = conn
        self._base_addr = base_addr
        self.byteorder = byteorder
        self.ptrbits = ptrbits

    def read(self, offset, size):
        return bytes(self._conn.call("read_memory",
                                     self._base_addr + offset, size))

    def write(self, offset, data):
        self._conn.call("write_memory",
                        self._base_addr + offset, bytes(data))

    def rebase(self, addr):
        return GdbRemoteBytesProvider(self._conn, addr, self.byteorder, self.ptrbits)

    @property
    def address(self):
        return self._base_addr


# --- Symbol accessor ---

class SymbolAccessor:
    """Attribute-style symbol lookup: gdb.sym.main → typed Value."""

    def __init__(self, conn, byteorder, ptrbits=64):
        object.__setattr__(self, '_conn', conn)
        object.__setattr__(self, '_byteorder', byteorder)
        object.__setattr__(self, '_ptrbits', ptrbits)

    def __getattr__(self, name):
        result = self._conn.call("resolve_type", name)
        if result is None:
            raise AttributeError(f"Symbol '{name}' not found")

        # Functions / no-debug-info symbols return (desc, addr, "function").
        # The address IS the value — return a pointer directly.
        if len(result) == 3 and result[2] == "function":
            _, addr, _ = result
            from pwnc.types.provider import BufferProvider
            ptype = Ptr(None, bits=self._ptrbits)
            buf = addr.to_bytes(self._ptrbits // 8, 'little' if self._byteorder == ByteOrder.Little else 'big')
            return ptype.use(BufferProvider(buf, self._byteorder, self._ptrbits))

        desc, addr = result
        if addr is None:
            raise AttributeError(f"Symbol '{name}' has no address")

        if desc is not None:
            ptype = pwnc_type_from_desc(desc)
        else:
            ptype = Ptr(Int(8), bits=self._ptrbits)

        if ptype is None:
            ptype = Ptr(Int(8), bits=self._ptrbits)

        provider = GdbRemoteBytesProvider(self._conn, addr, self._byteorder, self._ptrbits)
        return Value(ptype, provider, 0)


# --- Registers ---

class Registers:
    """Attribute-style register access: gdb.reg.rax → int."""

    def __init__(self, conn):
        object.__setattr__(self, '_conn', conn)

    def __getattr__(self, name):
        return self._conn.call("get_register", name)

    def __setattr__(self, name, value):
        self._conn.call("set_register", name, value)


# --- Main GDB class ---

class Gdb:
    """GDB controller with MI3 interface, bridge RPC, and typed access."""

    def __init__(self, gdb_path="gdb", env=None):
        import atexit
        self.process = GdbProcess(gdb_path=gdb_path, env=env)
        self.conn: BridgeConnection | None = None
        self.sym: SymbolAccessor | None = None
        self.reg: Registers | None = None
        self.target = None  # pwntools process (set by debug())
        self._console_proc = None  # kitty subprocess for console UI
        self._closed = False
        self._bp_callbacks: dict[int, callable] = {}
        atexit.register(self.close)

    def _start_console(self):
        """Spawn a kitty terminal and attach GDB's console UI to it."""
        import subprocess as _sp
        import tempfile

        fifo = os.path.join(tempfile.mkdtemp(), "tty")
        os.mkfifo(fifo)

        self._console_proc = _sp.Popen(
            ["kitty", "-e", "sh", "-c", f"tty > {fifo}; exec sleep infinity < /dev/null > /dev/null 2>&1"],
        )

        with open(fifo) as f:
            tty_path = f.readline().strip()
        os.unlink(fifo)
        os.rmdir(os.path.dirname(fifo))

        self.process.console(f"new-ui console {tty_path}")

    def _start_bridge(self):
        """Load the bridge script inside GDB."""
        bridge_path = os.path.join(os.path.dirname(__file__), "bridge.py")

        # ensure pwnc is importable inside GDB's python
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        self.process.console(
            f'python import sys; sys.path.insert(0, "{project_root}") if "{project_root}" not in sys.path else None'
        )

        # source the bridge
        self.process.console(f'python exec(open("{bridge_path}").read())')

        self.conn = BridgeConnection(self.process, proxy_classes=PROXY_CLASSES)

        # detect byte order and pointer size
        endian = self.conn.call("get_endian")
        bo = ByteOrder.Little if endian == "little" else ByteOrder.Big
        ptrbits = self.conn.call("get_pointer_size")

        self.sym = SymbolAccessor(self.conn, bo, ptrbits)
        self.reg = Registers(self.conn)

    # --- Execution control ---

    def run(self, *args):
        if self.target is not None:
            self.cont()
        else:
            self.process.command("exec-run")

    def cont(self):
        self.process.command("exec-continue")

    def interrupt(self):
        self.process.command("exec-interrupt")

    def stepi(self):
        self.process.command("exec-step-instruction")

    def nexti(self):
        self.process.command("exec-next-instruction")

    def step(self):
        self.process.command("exec-step")

    def next(self):
        self.process.command("exec-next")

    def skip(self):
        self.conn.call("skip_instruction")

    def wait(self):
        """Block until the inferior stops.

        If the stop is a breakpoint-hit with a registered callback,
        the callback is invoked with this Gdb instance.  If the
        callback returns anything other than ``False``, execution
        automatically continues and ``wait`` keeps waiting for the
        next stop.

        Returns the stop-reason dict for the stop that was *not*
        handled by a callback (or where the callback returned
        ``False``).
        """
        while True:
            stop = self.process.wait_for_stop()
            if stop.get("reason") == "breakpoint-hit":
                bkptno = stop.get("bkptno")
                if bkptno is not None:
                    cb = self._bp_callbacks.get(int(bkptno))
                    if cb is not None:
                        result = cb(self)
                        if result is not False:
                            self.cont()
                            continue
            return stop

    # --- Breakpoints ---

    def bp(self, location, callback=None, **kwargs) -> BreakpointProxy:
        """Set a breakpoint.  Returns a BreakpointProxy.

        If *callback* is given it is called as ``callback(gdb)`` each
        time the breakpoint is hit during ``wait()``.  The callback
        receives this ``Gdb`` instance and can freely read/write
        registers, memory, symbols, etc.

        * Return anything (or ``None``) → auto-continue.
        * Return ``False``              → stop; ``wait()`` returns.
        """
        bp = self.conn.call("create_breakpoint", location, **kwargs)
        if callback is not None:
            self._bp_callbacks[bp.number] = callback
        return bp

    # --- Direct access ---

    def inferior(self) -> InferiorProxy:
        return self.conn.call("selected_inferior")

    def frame(self) -> FrameProxy:
        return self.conn.call("selected_frame")

    def thread(self) -> ThreadProxy:
        return self.conn.call("selected_thread")

    # --- Console ---

    def execute(self, cmd: str) -> str:
        return self.process.console(cmd)

    # --- Memory convenience ---

    def read(self, addr, size) -> bytes:
        return bytes(self.conn.call("read_memory", addr, size))

    def write(self, addr, data):
        self.conn.call("write_memory", addr, bytes(data))

    # --- Lifecycle ---

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.process.close()
        if self.target is not None:
            self.target.close()
        if self._console_proc is not None:
            self._console_proc.kill()
            self._console_proc.wait()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --- Convenience constructors ---

def debug(program, *args, gdb_path="gdb", gdb_args=None, env=None,
          headless=False) -> Gdb:
    """Spawn a program under gdbserver and connect GDB to it.

    The target runs in a pwntools process tube (gdb.target) with its
    own stdin/stdout, giving clean IO separation from GDB's MI traffic.

    Unless headless=True, a kitty terminal window is opened with a
    GDB console UI for interactive commands.

    Args:
        program: Path to the executable.
        *args: Arguments passed to the program (not GDB).
        gdb_path: Path to the gdb binary.
        gdb_args: Extra command-line arguments for GDB itself
                  (e.g. ["-ex", "set disable-randomization off"]).
        env: Environment dict for the GDB subprocess.
        headless: If True, skip spawning the kitty console window.
    """
    from pwn import process as pwnprocess

    # Spawn gdbserver with target
    gdbserver_cmd = ["gdbserver", "--once", "localhost:0", program]
    gdbserver_cmd.extend(str(a) for a in args)
    target = pwnprocess(gdbserver_cmd, env=env)

    # Parse port from gdbserver output: "Listening on port XXXX"
    line = target.recvline_contains(b"Listening on port")
    port = int(line.split(b"port ")[-1])

    # Spawn GDB without program, load symbols only
    g = Gdb(gdb_path=gdb_path, env=env)
    extra = list(gdb_args) if gdb_args else []
    g.process.start(extra_args=extra if extra else None)
    g.process.console(f'file {program}')

    # Start bridge, connect to gdbserver
    g._start_bridge()
    g.process.console(f'target remote localhost:{port}')

    if not headless:
        g._start_console()

    g.target = target
    return g


def attach(pid_or_name, gdb_path="gdb", gdb_args=None, env=None,
           headless=False) -> Gdb:
    """Attach GDB to a running process (by PID or name).

    Args:
        pid_or_name: Process ID (int) or process name (str).
        gdb_path: Path to the gdb binary.
        gdb_args: Extra command-line arguments for GDB itself.
        env: Environment dict for the GDB subprocess.
        headless: If True, skip spawning the kitty console window.
    """
    g = Gdb(gdb_path=gdb_path, env=env)
    extra = list(gdb_args) if gdb_args else None

    if isinstance(pid_or_name, int):
        g.process.start(pid=pid_or_name, extra_args=extra)
    else:
        import shutil
        pidof = shutil.which("pidof")
        if pidof:
            import subprocess
            result = subprocess.run([pidof, pid_or_name],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                pid = int(result.stdout.strip().split()[0])
                g.process.start(pid=pid, extra_args=extra)
            else:
                raise RuntimeError(f"Process '{pid_or_name}' not found")
        else:
            raise RuntimeError("pidof not available; pass a PID instead")

    g._start_bridge()

    if not headless:
        g._start_console()

    return g
