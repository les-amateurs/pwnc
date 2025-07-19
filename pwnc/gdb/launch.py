from tempfile import NamedTemporaryFile, mkdtemp
import pathlib
import time
import os
import signal
import subprocess
import inspect
from os import path
from pwnlib.util import misc
from pwnlib import gdb as gdbutils
from pwnlib import elf as elfutils
from pwnlib.tubes.process import process
from pwnlib.tubes.tube import tube

from ..util import *
from .. import config

# hack to get intellisense
try:
    import gdb
except:
    pass


class ObjfileSymbols:
    def __init__(self, objfile: "gdb.Objfile", raw: bool = True):
        self.objfile = objfile
        self.raw = raw

    def symbol_address(self, symbol: str):
        sym = self.objfile.lookup_global_symbol(symbol) or self.objfile.lookup_static_symbol(symbol)
        if sym:
            if self.raw:
                return sym.value().address
            else:
                return sym

    def __getattr__(self, symbol):
        return self.symbol_address(symbol)

    def __getitem__(self, symbol):
        return self.symbol_address(symbol)


class Objfile:
    def __init__(self, objfile: "gdb.Objfile"):
        self.objfile = objfile
        self._sym = ObjfileSymbols(objfile, raw=True)
        self._lookup = ObjfileSymbols(objfile, raw=False)

    @property
    def sym(self):
        return self._sym

    @property
    def lookup(self):
        return self._lookup

    def __repr__(self):
        return "<Objfile for {!r}>".format(self.objfile.filename)


class Objfiles:
    def __init__(self, gdb: "gdb"):
        self.objfiles = {}
        self.elffiles: set[elfutils.ELF] = set()
        self.gdb = gdb

        for objfile in gdb.objfiles():
            self.register_objfile(objfile)

        gdb.events.new_objfile.connect(self.new_objfile)
        gdb.events.free_objfile.connect(self.free_objfile)

    def objfile_for_path(self, name: str):
        for objfile in self.objfiles.keys():
            if path.basename(name) == path.basename(objfile):
                return self.objfiles[objfile]

    def register_elf(self, elf: elfutils.ELF):
        if elf not in self.elffiles:
            self.elffiles.add(elf)
            objfile = self.gdb.lookup_objfile(path.basename(elf.path))
            if objfile:
                elf._objfile = self.objfiles[objfile]

    def register_objfile(self, objfile: "gdb.Objfile"):
        proxy = Objfile(objfile)
        for elf in self.elffiles:
            if path.basename(objfile.filename) == path.basename(elf.path):
                elf._objfile = proxy
        self.objfiles[objfile] = proxy

    def new_objfile(self, event: "gdb.NewObjFileEvent"):
        self.register_objfile(event.new_objfile)

    def free_objfile(self, event: "gdb.FreeObjFileEvent"):
        objfile = event.objfile
        for elf in self.elffiles:
            if elf._objfile.objfile == objfile:
                self._objfile = None
        del self.objfiles[objfile]

    def __getitem__(self, objfile: "gdb.Objfile"):
        if type(objfile) == type(""):
            return self.objfile_for_path(objfile)
        return self.objfiles[objfile]

    def __repr__(self):
        return str(list(self.objfiles.values()))


class HexInt(int):
    def __new__(self, val, *args, **kwargs):
        return super().__new__(self, val, *args, **kwargs)

    def __repr__(self):
        return f"{self:#x}"


class Registers:
    gdb: "Gdb"

    def __init__(self, conn: "Gdb"):
        object.__setattr__(self, "gdb", conn)

    def __getattr__(self, key: str):
        val = self.gdb.parse_and_eval(f"${key}")
        val = HexInt(val)
        return val

    def __setattr__(self, key: str, val: int):
        val = self.gdb.parse_and_eval(f"${key} = {val}")


class Gdb:
    def __init__(self, conn, binary: elfutils.ELF = None, resolve_debuginfo: bool = True, **kwargs):
        gdbref = self
        self.conn = conn
        self.regs = Registers(self)

    def pid(self):
        return int(self.gdb.execute("info proc", to_string=True).splitlines()[0].split(" ")[-1])

    def prompt(self):
        self.conn.run("prompt")

    def continue_nowait(self):
        self.conn.run("continue_nowait")

    def continue_and_wait(self):
        self.conn.run("continue")

    def cont(self):
        self.continue_and_wait()

    def wait_for_stop(self, timeout=None) -> bool:
        return self.conn.run("wait", timeout=timeout)

    def is_running(self):
        return self.conn.run("running")

    def is_exited(self):
        return self.conn.run("exited")

    def interrupt(self):
        self.conn.run("interrupt")

    def bp(self, location, callback=None):
        kind = str(type(location))
        if "gdb.Value" in kind:
            spec = location.format_string(raw=True, styling=False, address=False)
            if spec.startswith("<") and spec.endswith(">"):
                spec = spec[1:-1]
        elif kind == "<class 'str'>":
            spec = location

        if callback is not None:
            bp = self.conn.run("set_breakpoint", spec, callback)
        else:
            bp = self.conn.run("set_breakpoint", spec)
        self.prompt()

    def execute(self, cmd: str, to_string: bool = False, from_tty: bool = False) -> str | None:
        try:
            return self.conn.run("execute", cmd, to_string=to_string, from_tty=from_tty)
        except Exception as e:
            msg = e.args[0]
            err.warn(f"failed to execute cmd (`{cmd}`): {msg}")

    def read_memory(self, address: int, length: int) -> bytes:
        return self.conn.run("read_memory", address, length)

    def ni(self):
        self.conn.run("ni")

    def parse_and_eval(self, expr: str) -> int:
        return self.conn.run("parse_and_eval", expr)

    def close(self):
        self.conn.stop()
        self.closei()

    def closei(self):
        if isinstance(self.instance, int):
            os.kill(self.instance, signal.SIGTERM)
        elif isinstance(self.instance, tube):
            self.instance.close()
        else:
            err.warn(f"unknown instance type: {self.instance}")

    def gui(self):
        terminal = select_terminal(False)
        stdout = str(self.inout / "stdout")
        stderr = str(self.inout / "stderr")
        stdin = str(self.inout / "stdin")
        misc.run_in_new_terminal(
            ["sh", "-c", f"cat {stdout} & cat {stderr} & cat > {stdin}"], terminal=terminal, args=[]
        )


def on(option: bool):
    return "on" if option else "off"


def no(disable: bool):
    return "no-" if disable else ""


def collect_options(fn, kwargs: dict):
    options = {}
    for name, param in inspect.signature(fn).parameters.items():
        if name == "options":
            continue

        if param.kind == param.POSITIONAL_OR_KEYWORD and param.default != param.empty:
            val = kwargs.get(name, None) or param.default
            if val is None:
                try:
                    val = config.load(config.Key("gdb") / name.replace("_", "-"))
                except KeyError:
                    pass

            options[name] = val
    return options


def with_options(fn):
    def wrapper(cls, *args, **kwargs):
        options = collect_options(fn, kwargs)
        return fn(cls, *args, **kwargs, options=options)

    return wrapper


def select_terminal(headless: bool):
    if headless:
        return "sh"
    else:
        return "kitty"


from .protocol import Server


class Bridge:
    def __init__(
        self,
        aslr: bool = True,
        index_cache: bool = None,
        index_cache_path: bool = None,
        **kwargs,
    ):
        self.gdbscript = []
        self.launch_directory = pathlib.Path(mkdtemp())
        self.socket_path = str(self.launch_directory / "socket")
        self.bridge_path = str(pathlib.Path(__file__).parent / "bridge.py")
        self.gdbscript_path = str(self.launch_directory / "gdbscript")
        self.gdb_path = str(gdbutils.binary())
        self.background_server = None

        if aslr is not None:
            self.gdbscript.append("set disable-randomization {:s}".format(on(not aslr)))
        if index_cache is not None:
            if index_cache_path is not None:
                self.gdbscript.append("set index-cache directory {:s}".format(index_cache_path))
            self.gdbscript.append("set index-cache enabled {:s}".format(on(index_cache)))

        self.gdbscript.append("python socket_path = {!r}".format(self.socket_path))
        self.gdbscript.append("source {:s}".format(self.bridge_path))

    def finalize_gdbscript(self):
        with open(self.gdbscript_path, "w+") as fp:
            fp.write("\n".join(self.gdbscript) + "\n")

    def connect(self):
        for i in range(50):
            try:
                connection = Server("script", self.socket_path, False)
                connection.start()
                break
            except FileNotFoundError:
                time.sleep(0.1)
        else:
            print("failed to connect")

        return connection


@with_options
def attach(
    target: str | tuple[str, int],
    elf: elfutils.ELF = None,
    headless: bool = False,
    aslr: bool = True,
    resolve_debuginfo: bool = False,
    index_cache: bool = None,
    gdbscript: str = "",
    args: list = [],
    targs: list = [],
    options: dict = None,
    **kwargs,
):
    bridge = Bridge(**options)
    command = [bridge.gdb_path]
    if elf is not None:
        command += [elf.path]

    if isinstance(target, str):
        pids = subprocess.run(
            ["pgrep", "-fx", command],
            check=False,
            capture_output=True,
            encoding="utf-8",
        ).stdout.splitlines()
        if len(pids) == 0:
            raise FileNotFoundError("process {!r} not found".format(command))

        if len(pids) != 1:
            print("selecting newest pid")

        pid = pids[-1]
        bridge.gdbscript.append("set sysroot /proc/{:s}/root/".format(pid))
        command += ["-p", str(pid)]
    elif isinstance(target, tuple) and len(target) == 2:
        bridge.gdbscript.append(f"target remote {target[0]}:{target[1]}")
    else:
        raise Exception(f"unknown target type: {target}")

    bridge.gdbscript.extend(gdbscript.strip().splitlines())
    bridge.finalize_gdbscript()

    command += args
    command += ["-x", bridge.gdbscript_path]

    terminal = select_terminal(headless)
    inout = None
    if headless:
        inout = Path(mkdtemp())
        os.mkfifo(inout / "stdin")
        os.mkfifo(inout / "stdout")
        os.mkfifo(inout / "stderr")
        a = os.open(inout / "stdin", os.O_RDWR)
        b = os.open(inout / "stdout", os.O_RDWR)
        c = os.open(inout / "stderr", os.O_RDWR)
        instance = process(command, stdin=a, stdout=b, stderr=c)
    else:
        instance = misc.run_in_new_terminal(command, terminal=terminal, args=[] + targs, kill_at_exit=True)

    conn = bridge.connect()
    g = Gdb(conn, binary=elf, **options)
    g.instance = instance
    g.inout = inout
    return g


@with_options
def debug(
    target: str | elfutils.ELF,
    elf: elfutils.ELF = None,
    headless: bool = False,
    aslr: bool = True,
    resolve_debuginfo: bool = False,
    index_cache: bool = None,
    gdbscript: str = "",
    args: list = [],
    targs: list = [],
    port: int = 0,
    options: dict = None,
):
    # command = [bridge.gdbserver_path, str(elf.path), "-x", bridge.gdbscript_path]
    if type(target) == elfutils.ELF:
        target = target.path

    command = ["gdbserver", "--multi", "--no-startup-with-shell"]
    command.append(f"--{no(aslr)}disable-randomization")
    command.append(f"localhost:{port}")
    command.append(target)

    p = process(command)
    pid = p.recvline()
    port = int(p.recvline().rsplit(maxsplit=1)[1])

    conn = attach(("localhost", port), **options)
    p.recvline()

    return conn, p
