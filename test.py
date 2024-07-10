from pwn import *
from pwn import gdb as debugger

context.terminal = ["kitty"]
p = debugger.debug("cat", gdbscript="source gdbinit")
import gdbscript as g

start = g.breakpoint("*main")
input("wait: ")
g.cont()

p.interactive()