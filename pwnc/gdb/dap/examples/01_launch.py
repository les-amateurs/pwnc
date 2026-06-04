"""Local launch() session — typed globals, bitfields, pointer chasing, the
breakpoint-callback loop. Dependency-free (no pwntools); fully self-contained.

This is the simplest entry point: launch() runs the program locally under gdb
and stops at main. (For clean byte-level target IO — pwn — use debug(), which
runs the target under gdbserver in a pwntools tube.)
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))

from pwnc.gdb.dap import launch

TARGET = os.path.join(os.path.dirname(__file__), "..", "..", "mi", "examples", "target")

g = launch(TARGET)                      # runs locally, stopped at main
print("stopped at main")

# typed globals
print("counter       =", int(g.sym.counter))           # 0
print("origin        = (%d, %d)" % (g.sym.origin.x, g.sym.origin.y))  # (10, 20)
print("current_color =", int(g.sym.current_color))     # 1 (GREEN)
print("message       =", bytes(g.sym.message[i] for i in range(5)))   # b"hello"

# registers + memory
print("rip           = %#x" % g.reg.rip)
g.write(g.sym.origin._provider.address, (999).to_bytes(4, "little"))
print("origin.x after write =", g.sym.origin.x)        # 999

# breakpoint callback: fires on each hit; return False to stop, else auto-continue
hits = []
g.bp("update_origin", callback=lambda gg: hits.append(int(gg.sym.counter)))
stop = g.cont()                          # cont() waits and returns the stop
print("update_origin hits:", hits, "-> program", stop.get("reason"))

g.close()
print("done")
