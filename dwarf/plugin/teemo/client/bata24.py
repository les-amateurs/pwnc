# need to be careful with what we import, so we do not mess up any other running gdb plugins
import gdb
import os
import rpyc
from rpyc.utils.server import spawn
from rpyc.utils.factory import unix_connect
from . import connection
from .. import config
from . import connection

@register_command
class TeemoCommand(GenericCommand):
    _cmdline_ = "teemo"
    _category_ = "08-d. Qemu-system Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()
    __doc__ = ""

    service = None
    binbase = None
    sections = []
    previous_loaded_debuginfo = None
    elf = None

    def update_debuginfo(self):
        debuginfo = os.path.join("/tmp", config.NAME, "info.debug")
        command = f"add-symbol-file {debuginfo} {self.sections}"
        if self.previous_loaded_debuginfo:
            gdb.execute(f"remove-symbol-file {self.previous_loaded_debuginfo}")
        gdb.execute(command, to_string=True)
        self.previous_loaded_debuginfo = debuginfo

    def debugger_stopped(self):
        frame = gdb.selected_frame()
        while frame != None:
            self.service.root.request_function(frame.pc() - self.binbase)
            frame = frame.older()
        self.update_debuginfo()

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        self_reference = self

        class Client(rpyc.Service):
            # this is required, otherwise gdb dies with recursive internal error
            _protocol = connection.GdbConnection

            def exposed_update_debuginfo(self):
                self_reference.update_debuginfo()

        if self.service is None:
            self.service = unix_connect(str(config.UNIX_SOCK_PATH), service=Client)
            spawn(self.service.serve_all)

        if self.binbase is None:
            self.binbase = ProcessMap.get_section_base_address(Path.get_filepath(append_proc_root_prefix=False))
            if self.binbase is None:
                self.binbase = ProcessMap.get_section_base_address(Path.get_filepath_from_info_proc())
            if self.binbase is None:
                err("Binary base is not found")
                return
            
            self.elf = Elf.get_elf(Path.get_filepath())
            
            for section in self.elf.shdrs:
                if section.sh_addr > 0:
                    self.sections.append(f"-s {section.sh_name} {self.binbase + section.sh_addr:#x}")
            self.sections = " ".join(self.sections)

        gdb.events.stop.connect(lambda e: self.debugger_stopped())