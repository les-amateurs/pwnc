from pwnc.gdb.launch import attach, debug
from pwn import ELF

gdb = debug(ELF("/bin/ls"), resolve_debuginfo=True)
print(gdb.objfiles)
gdb.interrupt()
# print(gdb.file.libc.objfile.objfile.add_separate_debug_file("/home/unvariant/.cache/debuginfod_client/69389d485a9793dbe873f0ea2c93e02efaa9aa3d/debuginfo"))
# print(gdb.file.libc.objfile.lookup.main_arena.value())

input("wait: ")