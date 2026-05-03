from pwnc.gdb.mi import debug, Gdb

g = debug("../../../../tests/mi/libc.so.6")
print(g.sym.main_arena._type)