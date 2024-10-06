from tempfile import NamedTemporaryFile, mkdtemp
import pathlib
import time
import builtins
import threading
import os
import subprocess
import shutil
import inspect
from os import path
from pwnlib.util.misc import run_in_new_terminal
from pwnlib import gdb as gdbutils
from pwnlib import elf
from rpyc.utils.factory import unix_connect
from rpyc import BgServingThread

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

""" Gdb copied from pwntools """
class Gdb:
    def __init__(self, conn, binary: elf.ELF = None, resolve_debuginfo: bool = True, **kwargs):
        gdbref = self
        self.conn = conn
        self.gdb: "gdb" = conn.root.gdb
        self.pid = int(self.gdb.execute("info proc", to_string=True).splitlines()[0].split(" ")[-1])

        self.stopped = threading.Event()
        def stop_handler(event):
            self.stopped.set()
        self.events.stop.connect(stop_handler)
        
        class ProxyBreakpoint(gdbutils.Breakpoint):
            def __init__(self, *args, **kwargs):
                super().__init__(conn, *args, **kwargs)
        class ProxyFinishBreakpoint(gdbutils.Breakpoint):
            def __init__(self, *args, **kwargs):
                super().__init__(conn, *args, **kwargs)

        self.Breakpoint = ProxyBreakpoint
        self.FinishBreakpoint = ProxyFinishBreakpoint
        self.objfiles = Objfiles(self.gdb)

        class ELF(elf.ELF):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._objfile: Objfile = None
                gdbref.objfiles.register_elf(self)

            @property
            def objfile(self):
                if not self._objfile:
                    raise FileNotFoundError("objfile not loaded yet")
                return self._objfile
                
            @property
            def libc(self):
                for lib in self.libs:
                    if '/libc.' in lib or '/libc-' in lib:
                        return ELF(lib)
                
        self.ELF = ELF
        if binary is not None:
            self.file = ELF(binary.path)
        else:
            self.file = None

        if resolve_debuginfo:
            libraries = self.gdb.execute("info sharedlibrary", to_string=True).strip().splitlines()[1:]
            libraries = map(lambda line: line.split(), libraries)
            libraries = filter(lambda line: not (len(line) == 4 and "*" not in line[2]), libraries)
            libraries = map(lambda line: pathlib.Path(line[-1]), libraries)
            libraries = list(libraries)
            loaded = list(map(lambda obj: obj.filename, self.gdb.objfiles()))
            cache = pathlib.Path("_cache")

            mappings = self.gdb.execute("info proc mappings", to_string=True).strip().splitlines()[4:]
            mappings = map(lambda line: line.split(), mappings)
            mappings = map(lambda line: line if len(line) == 6 else line + ["[anon]"], mappings)
            mappings = list(mappings)
            mappings = {pathlib.Path(line[-1]).name: int(line[0], 16) for line in reversed(mappings)}

            for library in libraries:
                if library not in loaded:
                    cache.mkdir(exist_ok=True)
                    cached = cache / pathlib.Path(library).name
                    if not cached.exists():
                        remote_root = pathlib.Path("/") / "proc" / str(self.pid) / "root"
                        remote_path = remote_root / library.relative_to("/")
                        if remote_path.is_symlink():
                            remote_path = remote_root / remote_path.readlink().relative_to("/")

                        shutil.copy(remote_path, cached, follow_symlinks=True)

                    lib = elf.ELF(cached, checksec=False)
                    if not lib.has_dwarf_info():
                        try:
                            unstrip.handle_unstrip(cached)
                            err.info(f"unstripped {lib}")
                        except Exception as e:
                            err.warn(f"failed to unstrip {lib}: {e}")
                    else:
                        err.info(f"{lib} is already unstripped")

                    cmd = ["add-symbol-file", str(cached.absolute())]
                    base = mappings[library.name]

                    for section in lib.sections:
                        # SHF_ALLOC
                        if section.header.sh_flags & 2 != 0:
                            cmd += ["-s", section.name, "{:#x}".format(base + section.header.sh_addr)]

                    self.gdb.execute(" ".join(cmd), to_string=True)

        self.gdb.execute("ctx")
        self.gdb.write(self.gdb.prompt_hook(lambda: None))

    def wait(self):
        self.stopped.wait()
        self.stopped.clear()

    def interrupt(self):
        self.gdb.execute("interrupt")

    def bp(self, location):
        kind = str(type(location))
        if "gdb.Value" in kind:
            spec = location.format_string(raw=True, styling=False, address=False)
            if spec.startswith("<") and spec.endswith(">"):
                spec = spec[1:-1]
            return self.Breakpoint(spec)

    def __getattr__(self, item):
        return getattr(self.conn.root.gdb, item)

def on(option: bool):
    return "on" if option else "off"

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

class Bridge:
    def __init__(self, aslr: bool = True, index_cache: bool = None, index_cache_path: bool = None, **kwargs):
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
        for i in range(20):
            try:
                connection = unix_connect(self.socket_path)
                break
            except FileNotFoundError:
                time.sleep(0.5)
        else:
            print("failed to connect")

        self.background_server = BgServingThread(connection, callback=lambda: None)
        return connection

@with_options
def attach(command: str,
    elf: elf.ELF = None,

    headless: bool = False,
    aslr: bool = True,
    resolve_debuginfo: bool = False,
    index_cache: bool = None,

    options: dict = None,
):
    pids = subprocess.run(["pgrep", "-f", command], check=False, capture_output=True, encoding="utf-8").stdout.splitlines()
    if len(pids) == 0:
        raise FileNotFoundError("process {!r} not found".format(command))
    
    if len(pids) != 1:
        print("selecting newest pid")

    pid = pids[-1]
    bridge = Bridge(**options)
    bridge.gdbscript.append("set sysroot /proc/{:s}/root/".format(pid))
    bridge.finalize_gdbscript()
    
    command = [bridge.gdb_path]
    if elf is not None:
        command += [elf.path]
    command += ["-p", str(pid), "-x", bridge.gdbscript_path]

    terminal = select_terminal(headless)
    run_in_new_terminal(command, terminal=terminal, args=[], kill_at_exit=True)

    conn = bridge.connect()
    return Gdb(conn, binary=elf, **options)

@with_options
def debug(
    elf: elf.ELF,

    headless: bool = False,
    aslr: bool = True,
    resolve_debuginfo: bool = False,
    index_cache: bool = None,

    options: dict = None
):
    bridge = Bridge(**options)
    bridge.finalize_gdbscript()

    command = [bridge.gdb_path, str(elf.path), "-x", bridge.gdbscript_path]

    terminal = select_terminal(headless)
    run_in_new_terminal(command, terminal=terminal, args=[], kill_at_exit=True)

    conn = bridge.connect()
    return Gdb(conn, binary=elf, **options)