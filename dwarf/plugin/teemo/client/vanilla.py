import gdb
import os
import rpyc
import time
from elftools.elf.elffile import ELFFile
from rpyc import BgServingThread
from rpyc.utils.server import spawn
from rpyc.utils.factory import unix_connect
from .. import config
from . import connection

DEFAULT_PAGE_SIZE = 1 << 12

def err(msg):
    """The wrapper of gef_print for error level message."""
    print("[!] {}".format(msg))
    return

def is_alive():
    """GDB mode determination function for running."""
    try:
        return gdb.selected_inferior().pid > 0
    except gdb.error:
        return False
    return False

def is_remote_debug():
    """GDB mode determination function for remote debugging."""
    try:
        connection = gdb.selected_inferior().connection
        if connection is None:
            return False
        return connection and connection.type == "remote"
    except AttributeError:
        # before gdb 11.x: AttributeError: 'gdb.Inferior' object has no attribute 'connection'
        res = gdb.execute("maintenance print target-stack", to_string=True)
        return "remote" in res

def is_pin():
    """GDB mode determination function for pin and SDE."""
    if not is_remote_debug():
        return False
    try:
        response = gdb.execute("maintenance packet qSupported", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return "intel.name=" in response

def is_qemu():
    """GDB mode determination function for qemu-user or qemu-system."""
    if not is_remote_debug():
        return False
    try:
        response = gdb.execute("maintenance packet Qqemu.sstepbits", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return "ENABLE=" in response

def is_qemu_user():
    """GDB mode determination function for qemu-user gdb stub."""
    if is_qemu() is False:
        return False
    try:
        response = gdb.execute("maintenance packet qOffsets", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return "Text=" in response

def is_qemu_system():
    """GDB mode determination function for qemu-system gdb stub."""
    if is_qemu() is False:
        return False
    try:
        response = gdb.execute("maintenance packet qOffsets", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return 'received: ""' in response

def is_wine():
    """GDB mode determination function for winedbg."""
    return Pid.get_pid_from_tcp_session(filepath="wineserver") is not None

class Pid:
    """A collection of utility functions that obtains a pid."""

    @staticmethod
    def get_tcp_sess(pid):
        # get inode information from opened file descriptor
        inodes = []
        for openfd in os.listdir("/proc/{:d}/fd".format(pid)):
            try:
                fdname = os.readlink("/proc/{:d}/fd/{:s}".format(pid, openfd))
            except (FileNotFoundError, ProcessLookupError, OSError):
                continue
            if fdname.startswith("socket:["):
                inode = fdname[8:-1]
                inodes.append(inode)

        def decode(addr):
            ip, port = addr.split(":")
            import socket
            ip = socket.inet_ntop(socket.AF_INET, bytes.fromhex(ip)[::-1])
            port = int(port, 16)
            return (ip, port)

        # get connection information
        sessions = []
        with open("/proc/{:d}/net/tcp".format(pid)) as fd:
            for line in fd.readlines()[1:]:
                _, laddr, raddr, status, _, _, _, _, _, inode = line.split()[:10]
                if status != "01": # ESTABLISHED
                    continue
                if inode not in inodes:
                    continue
                laddr = decode(laddr)
                raddr = decode(raddr)
                sessions.append({"laddr": laddr, "raddr": raddr})
        return sessions

    @staticmethod
    def get_all_process():
        pids = [int(x) for x in os.listdir("/proc") if x.isdigit()]
        process = []
        for pid in pids:
            try:
                filepath = os.readlink("/proc/{:d}/exe".format(pid))
            except (FileNotFoundError, ProcessLookupError, OSError):
                continue
            process.append({"pid": pid, "filepath": os.path.basename(filepath)})
        return process

    @staticmethod
    def get_pid_from_name(filepath):
        candidate = []
        for process in Pid.get_all_process():
            if filepath in process["filepath"]:
                candidate.append(process)
        if len(candidate) == 1:
            return candidate[0]["pid"]
        return None

    @staticmethod
    def get_pid_from_tcp_session(filepath=None):
        gdb_tcp_sess = [x["raddr"] for x in Pid.get_tcp_sess(os.getpid())]
        if not gdb_tcp_sess:
            return None
        for process in Pid.get_all_process():
            if filepath and not process["filepath"].startswith(filepath):
                continue
            for c in Pid.get_tcp_sess(process["pid"]):
                if c["laddr"] in gdb_tcp_sess:
                    return process["pid"]
        return None

    @staticmethod
    def get_pid_wine():
        ws_pid = Pid.get_pid_from_tcp_session(filepath="wineserver")
        if ws_pid is None:
            return None

        def get_external_pipe_inodes(pid):
            inodes = set()
            if not os.path.exists("/proc/{:d}/".format(pid)):
                return inodes
            # get inode information from opened file descriptor
            for openfd in os.listdir("/proc/{:d}/fd".format(pid)):
                try:
                    fdname = os.readlink("/proc/{:d}/fd/{:s}".format(pid, openfd))
                except (FileNotFoundError, ProcessLookupError, OSError):
                    continue
                if fdname.startswith("pipe:["):
                    inode = fdname[6:-1]
                    if inode in inodes:
                        inodes.remove(inode)
                    else:
                        inodes.add(inode)
            return inodes

        ws_inodes = get_external_pipe_inodes(ws_pid)

        gdb_pid = os.getpid()
        for candidate_pid in range(gdb_pid - 1, ws_pid, -1):
            candidate_inodes = get_external_pipe_inodes(candidate_pid)
            if candidate_inodes & ws_inodes:
                return candidate_pid
        return None

    @staticmethod
    def get_pid(remote=False):
        """Return the PID of the debuggee process."""
        if is_pin():
            return Pid.get_pid_from_tcp_session()
        elif is_qemu_user() or is_qemu_system():
            pid = Pid.get_pid_from_tcp_session("qemu") # strict way
            if pid is None:
                pid = Pid.get_pid_from_name("qemu") # ambiguous way
            return pid
        elif is_wine():
            return Pid.get_pid_wine()
        elif remote is False and is_remote_debug():
            return None # gdbserver etc.
        return gdb.selected_inferior().pid

class PathUtil:
    """A collection of utility functions that obtains a path."""

    @staticmethod
    def append_proc_root(filepath):
        if filepath is None:
            return None
        pid = Pid.get_pid()
        if pid is None:
            return None
        if pid == 0: # under gdbserver, when target exited then pid is 0
            return None
        prefix = "/proc/{}/root".format(pid)
        relative_path = filepath.lstrip("/")
        return os.path.join(prefix, relative_path)

    @staticmethod
    def get_filepath(append_proc_root_prefix=True):
        """Return the local absolute path of the file currently debugged."""
        filepath = gdb.current_progspace().filename

        if is_remote_debug():
            if filepath is None:
                return None
            elif filepath.startswith("target:"):
                return None
            elif filepath.startswith(".gnu_debugdata for target:"):
                return None
            else:
                return filepath
        else:
            # inferior probably did not have name, extract cmdline from info proc
            if filepath is None:
                filepath = PathUtil.get_filepath_from_info_proc()
                if append_proc_root_prefix:
                    # maybe different mnt namespace, so use /proc/<PID>/root
                    filepath = PathUtil.append_proc_root(filepath)
            # not remote, but different PID namespace and attaching by pid. it shows with `target:`
            elif filepath.startswith("target:"):
                # /proc/PID/root is not given when used for purposes such as comparing with entry in vmmap
                filepath = filepath[len("target:"):]
                if append_proc_root_prefix:
                    # maybe different mnt namespace, so use /proc/<PID>/root
                    filepath = PathUtil.append_proc_root(filepath)
            # normal path
            return filepath

    @staticmethod
    def get_filepath_from_info_proc():
        try:
            response = gdb.execute("info proc", to_string=True)
        except gdb.error:
            return None
        for x in response.splitlines():
            if x.startswith("exe = "):
                return x.split(" = ")[1].replace("'", "")
        return None

    @staticmethod
    def get_filename():
        """Return the full filename of the file currently debugged."""
        filename = PathUtil.get_filepath()
        if filename is None:
            return None
        return os.path.basename(filename)

class BinjaCommand(gdb.Command):
    def __init__(self):
        super().__init__("binja", gdb.COMMAND_USER)
        self.binbase: int | None = None
        self.sections = []
        self.service: rpyc.Service = None
        self.previous_loaded_debuginfo = None
        self.epoch = -1
        self.last_stopped_epoch = -1
        self.ready = False

    def update_debuginfo(self, epoch: int):
        print("updating debuginfo")
        return self.do_update_debuginfo()

    def do_update_debuginfo(self):
        debuginfo = os.path.join("/tmp", config.NAME, "info.debug")
        command = f"add-symbol-file {debuginfo} {self.sections}"
        # print(command)

        if gdb.selected_thread() is None:
            return False
        if gdb.selected_thread().is_running():
            return False

        if self.previous_loaded_debuginfo:
            gdb.execute(f"remove-symbol-file {self.previous_loaded_debuginfo}")
        gdb.execute(command, to_string=True)
        self.previous_loaded_debuginfo = debuginfo
        return True

    def frame_addrs(self):
        addrs = []
        frame = gdb.selected_frame()
        while frame != None:
            addr = frame.pc()
            if self.service.root.relocatable:
                addr -= self.binbase
            addrs.append(addr)
            frame = frame.older()
        return addrs

    def debugger_stopped(self):
        try:
            # print("debugger stopped")
            self.service.root.request_functions(self.frame_addrs())
            self.do_update_debuginfo()
        except KeyboardInterrupt:
            print("debuginfo update interrupted")

    def disconnect(self):
        print(f"disconnecting...")
        self.service.close()
        gdb.events.stop.disconnect(self.gdb_stop_handler)
        gdb.events.exited.disconnect(self.gdb_exit_handler)
        gdb.events.gdb_exiting.disconnect(self.gdb_exit_handler)

    def gdb_stop_handler(self, e):
        self.debugger_stopped()

    def gdb_exit_handler(self, e):
        self.disconnect()

    def invoke(self, args, from_tty):
        self.ready = False
        self_reference = self
        class Client(rpyc.Service):
            # this is required, otherwise gdb dies with recursive internal error
            _protocol = connection.GdbConnection

            def exposed_update_debuginfo(self, epoch: int):
                if self_reference.ready:
                    self_reference.update_debuginfo(epoch)

        if self.binbase is None:
            auxv = gdb.execute("info auxv", to_string=True).splitlines()
            auxv = map(lambda line: line.split(maxsplit=1)[1], auxv)
            try:
                auxv = next(filter(lambda line: line.startswith("AT_ENTRY"), auxv))
            except StopIteration:
                err("failed to find binary entrypoint")

            entrypoint = int(auxv.rsplit(maxsplit=1)[-1], 16)
            print(f"{entrypoint = :#x}")

            filepath = PathUtil.get_filepath()
            mappings = gdb.execute("info proc mappings", to_string=True) # lazy
            mappings = mappings.splitlines()
            mappings = filter(lambda line: line.strip().startswith("0x"), mappings)
            mappings = map(lambda line: line.split(maxsplit=5), mappings)
            mappings = list(mappings)
            for start, end, size, offset, perms, objfile in mappings:
                start, end, offset = int(start, 16), int(end, 16), int(offset, 16)
                if offset == 0:
                    base = start
                if start <= entrypoint and entrypoint < end:
                    break
            else:
                err("failed to find binary base")

            print(f"{base = :#x}")
            self.binbase = base
            self.elf = ELFFile(open(filepath, "rb"))

            if self.service is None:
                self.service = unix_connect(str(config.UNIX_SOCK_PATH), service=Client)
                spawn(self.service.serve_all)

            for section in self.elf.iter_sections():
                address = section["sh_addr"]
                if address > 0:
                    if self.service.root.relocatable:
                        address += self.binbase
                    self.sections.append(f"-s {section.name} {address:#x}")
            self.sections = " ".join(self.sections)

        gdb.events.stop.connect(self.gdb_stop_handler)
        gdb.events.exited.connect(self.gdb_exit_handler)
        gdb.events.gdb_exiting.connect(self.gdb_exit_handler)
        self.ready = True
        self.service.root.request_functions(self.frame_addrs())
        self.update_debuginfo(0)
        print("binja initialized")

"""

"""
