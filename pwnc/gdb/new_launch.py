from tempfile import NamedTemporaryFile, mkdtemp
import pathlib
import time
import builtins
import threading
import os
import signal
import subprocess
import shutil
import inspect
from os import path
from pwnlib.util import misc
from pwnlib import gdb as gdbutils
from pwnlib import elf
from pwnlib.tubes.process import process
from pwnlib.tubes.tube import tube
import pwn

from ..commands import unstrip
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
        self.elffiles: set[elf.ELF] = set()
        self.gdb = gdb

        for objfile in gdb.objfiles():
            self.register_objfile(objfile)

        gdb.events.new_objfile.connect(self.new_objfile)
        gdb.events.free_objfile.connect(self.free_objfile)

    def objfile_for_path(self, name: str):
        for objfile in self.objfiles.keys():
            if path.basename(name) == path.basename(objfile):
                return self.objfiles[objfile]

    def register_elf(self, elf: elf.ELF):
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

""" Gdb copied from pwntools """
class Gdb:
    def __init__(self, conn, binary: elf.ELF = None, resolve_debuginfo: bool = True, **kwargs):
        gdbref = self
        self.conn = conn
        # self.gdb: "gdb" = conn.root.gdb
        self.regs = Registers(self)

        # self.stopped = threading.Event()
        # def stop_handler(event):
        #     self.stopped.set()
        # self.events.stop.connect(stop_handler)

        # class ProxyBreakpoint(Breakpoint):
        #     def __init__(self, *args, **kwargs):
        #         super().__init__(conn, *args, **kwargs)
        #         self.count = 0

        #     def stop(self):
        #         val = self.hit()
        #         self.count += 1
        #         if val not in [True, False]:
        #             return True
        #         return val

        #     def wait(self, fn):
        #         def wrapper(*args, **kwargs):
        #             count = self.count
        #             fn(*args, **kwargs)
        #             while self.count == count:
        #                 time.sleep(0.1)

        #         return wrapper

        #     def hit(self):
        #         return True

        # class ProxyFinishBreakpoint(gdbutils.Breakpoint):
        #     def __init__(self, *args, **kwargs):
        #         super().__init__(conn, *args, **kwargs)

        # self.Breakpoint = ProxyBreakpoint
        # self.FinishBreakpoint = ProxyFinishBreakpoint
        # self.objfiles = Objfiles(self.gdb)

        # class ELF(elf.ELF):
        #     def __init__(self, *args, **kwargs):
        #         super().__init__(*args, **kwargs)
        #         self._objfile: Objfile = None
        #         gdbref.objfiles.register_elf(self)

        #     @property
        #     def objfile(self):
        #         if not self._objfile:
        #             raise FileNotFoundError("objfile not loaded yet")
        #         return self._objfile

        #     @property
        #     def libc(self):
        #         for lib in self.libs:
        #             if '/libc.' in lib or '/libc-' in lib:
        #                 return ELF(lib)

        # self.ELF = ELF
        # if binary is not None:
        #     self.file = ELF(binary.path)
        # else:
        #     self.file = None

        # if resolve_debuginfo:
        #     libraries = self.gdb.execute("info sharedlibrary", to_string=True)
        #     libraries = libraries.strip().splitlines()[1:]
        #     if len(libraries) > 0 and not libraries[-1].startswith("0x"):
        #         libraries = libraries[:-1]
        #     libraries = map(lambda line: line.split(), libraries)
        #     libraries = map(lambda line: pathlib.Path(line[-1]), libraries)
        #     libraries = list(libraries)
        #     loaded = list(map(lambda obj: obj.filename, self.gdb.objfiles()))

        #     mappings = self.gdb.execute("info proc mappings", to_string=True).strip().splitlines()[4:]
        #     print(mappings)
        #     mappings = map(lambda line: line.split(), mappings)
        #     mappings = map(lambda line: line if len(line) == 6 else line + ["[anon]"], mappings)
        #     mappings = list(mappings)
        #     mappings = {pathlib.Path(line[-1]).name: int(line[0], 16) for line in reversed(mappings)}

        #     cache = pathlib.Path("_cache")
        #     working_directory = Path(self.gdb.execute("info proc cwd", to_string=True).strip()[:-1].split("cwd = '", maxsplit=1)[1])
        #     print(working_directory)
        #     pid = self.pid()

        #     for library in libraries:
        #         if library not in loaded:
        #             cache.mkdir(exist_ok=True)
        #             cached = cache / pathlib.Path(library).name

        #             if not str(library).startswith("/"):
        #                 library = working_directory / library

        #             if not cached.exists():
        #                 remote_root = pathlib.Path("/") / "proc" / str(pid) / "root"
        #                 if str(library).startswith(str(remote_root)):
        #                     remote_path = library
        #                 else:
        #                     remote_path = remote_root / library.relative_to("/")
        #                 if remote_path.is_symlink():
        #                     linked = remote_path.readlink()
        #                     if str(linked).startswith("/"):
        #                         remote_path = remote_root / linked.relative_to("/")
        #                     else:
        #                         remote_path = (remote_path.parent / remote_path.readlink())

        #                 shutil.copy(remote_path, cached, follow_symlinks=True)

        #             lib = elf.ELF(cached, checksec=False)
        #             if not bool(lib.get_section_by_name('.debug_info') or lib.get_section_by_name('.zdebug_info')):
        #                 try:
        #                     unstrip.handle_unstrip(cached.absolute())
        #                     err.info(f"unstripped {lib}")
        #                 except Exception as e:
        #                     err.warn(f"failed to unstrip {lib}: {e}")
        #             else:
        #                 err.info(f"{lib} is already unstripped")

        #             cmd = ["add-symbol-file", str(cached.absolute())]
        #             if library.name in mappings:
        #                 base = mappings[library.name]
        #             else:
        #                 for mapping in mappings.keys():
        #                     if mapping.startswith(library.name):
        #                         base = mappings[mapping]
        #                         break
        #                 else:
        #                     print(f"failed to locate library {library.name}")

        #             for section in lib.sections:
        #                 # SHF_ALLOC
        #                 if section.header.sh_flags & 2 != 0:
        #                     cmd += ["-s", section.name, "{:#x}".format(base + section.header.sh_addr)]

        #             cmd = " ".join(cmd)
        #             # print(cmd)
        #             self.gdb.execute(cmd)

        # self.gdb.execute("ctx")
        # self.gdb.write(self.gdb.prompt_hook(lambda _: ""))

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

    def bp(self, location, callback = None):
        kind = str(type(location))
        if "gdb.Value" in kind:
            spec = location.format_string(raw=True, styling=False, address=False)
            if spec.startswith("<") and spec.endswith(">"):
                spec = spec[1:-1]
        elif kind == "<class 'str'>":
            spec = location

        if callback is not None:
            bp = self.conn.run("set_breakpoint", spec, self.conn.reverse_registry[callback])
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
        stdin  = str(self.inout / "stdin")
        misc.run_in_new_terminal(["sh", "-c", f"cat {stdout} & cat {stderr} & cat > {stdin}"], terminal=terminal, args=[])

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
    def __init__(self, aslr: bool = True, index_cache: bool = None, index_cache_path: bool = None, **kwargs):
        self.gdbscript = []
        self.launch_directory = pathlib.Path(mkdtemp())
        self.socket_path = str(self.launch_directory / "socket")
        self.bridge_path = str(pathlib.Path(__file__).parent / "new_bridge.py")
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
    elf: elf.ELF = None,

    headless: bool = False,
    aslr: bool = True,
    resolve_debuginfo: bool = False,
    index_cache: bool = None,
    gdbscript: str = "",
    args: list = [],
    targs: list = [],

    options: dict = None,

    **kwargs
):
    bridge = Bridge(**options)
    command = [bridge.gdb_path]
    if elf is not None:
        command += [elf.path]

    if isinstance(target, str):
        pids = subprocess.run(["pgrep", "-fx", command], check=False, capture_output=True, encoding="utf-8").stdout.splitlines()
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
        instance = process(
            command,
            stdin=a,
            stdout=b,
            stderr=c
        )
    else:
        instance = misc.run_in_new_terminal(command, terminal=terminal, args=[] + targs, kill_at_exit=True)

    conn = bridge.connect()
    g = Gdb(conn, binary=elf, **options)
    g.instance = instance
    g.inout = inout
    return g

@with_options
def debug(
    target: str,
    elf: elf.ELF = None,

    headless: bool = False,
    aslr: bool = True,
    resolve_debuginfo: bool = False,
    index_cache: bool = None,
    gdbscript: str = "",
    args: list = [],
    targs: list = [],
    port: int = 0,

    options: dict = None
):
    # command = [bridge.gdbserver_path, str(elf.path), "-x", bridge.gdbscript_path]
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
