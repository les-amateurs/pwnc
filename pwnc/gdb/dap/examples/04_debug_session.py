"""Full DAP debug session: breakpoints, stepping, typed globals, registers,
memory, and frame walking — the pwnc.gdb.dap equivalent of mi example 04.

Reuses the prebuilt mi example target (gcc -g -O0 -o target target.c).
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))

from pwnc.gdb.dap import debug

BINARY = os.path.join(os.path.dirname(__file__), "..", "..", "mi", "examples", "target")

g = debug(BINARY)
print("Connected to gdb over DAP")

bp_main = g.bp("main")
bp_add = g.bp("add")
print(f"Set breakpoints: main (#{bp_main.number}), add (#{bp_add.number})")

g.run()
stop = g.wait()
print(f"\nHit breakpoint at main (reason: {stop.get('reason')})")

print("\n--- Globals at main entry ---")
print(f"counter        = {int(g.sym.counter)}")
print(f"origin.x       = {g.sym.origin.x}")
print(f"origin.y       = {g.sym.origin.y}")
print(f"current_color  = {int(g.sym.current_color)}")
print(f"message[0..4]  = {[g.sym.message[i] for i in range(5)]}")

print("\n--- Registers ---")
print(f"rip = 0x{g.reg.rip:x}")
print(f"rsp = 0x{g.reg.rsp:x}")
print(f"rbp = 0x{g.reg.rbp:x}")

print("\n--- Stepping ---")
for i in range(3):
    g.nexti()
    g.wait()
    print(f"  step {i+1}: rip=0x{g.reg.rip:x}")

g.cont()
stop = g.wait()
print(f"\nHit breakpoint at add (reason: {stop.get('reason')})")

frame = g.frame()
print("\n--- Call stack ---")
f = frame
while f is not None:
    try:
        print(f"  #{f.level} {f.name() or '??'} @ 0x{(f.pc() or 0):x}")
        f = f.older()
    except Exception:
        break

print("\n--- Stack memory at rsp ---")
rsp = g.reg.rsp
data = g.read(rsp, 32)
for off in range(0, 32, 8):
    word = int.from_bytes(data[off:off + 8], "little")
    print(f"  rsp+{off:#04x}: 0x{word:016x}")

bp_add.delete()
g.cont()
stop = g.wait()
print(f"\nProgram finished (reason: {stop.get('reason')})")

g.close()
print("\nSession complete.")
