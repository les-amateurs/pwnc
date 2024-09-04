# need to be careful with what we import, so we do not mess up any other running gdb plugins
import gdb
import sys
import os
import elftools

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__))))
import config

__debuginfo__ = os.path.join("/tmp", config.NAME, "info.debug")
__previous_loaded_debuginfo__ = None
__binbase__ = None

def update_debuginfo(event: gdb.StopEvent):
    global __binbase__, __previous_loaded_debuginfo__

    elf = Elf.get_elf(Path.get_filepath())

    if __binbase__ is None:
        __binbase__ = ProcessMap.get_section_base_address(Path.get_filepath(append_proc_root_prefix=False))
        if __binbase__ is None:
            __binbase__ = ProcessMap.get_section_base_address(Path.get_filepath_from_info_proc())
        if __binbase__ is None:
            err("Binary base is not found")
            return
        
    sections = []
    for section in elf.shdrs:
        if section.sh_addr > 0:
            sections.append(f"-s {section.sh_name} {__binbase__ + section.sh_addr:#x}")
    sections = " ".join(sections)

    command = f"add-symbol-file {__debuginfo__} {sections}"
    if __previous_loaded_debuginfo__:
        gdb.execute(f"remove-symbol-file {__previous_loaded_debuginfo__}")
    gdb.execute(command, to_string=True)
    __previous_loaded_debuginfo__ = __debuginfo__

gdb.events.stop.connect(update_debuginfo)