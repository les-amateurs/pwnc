"""
Full GDB debug session: breakpoints, stepping, typed globals,
registers, memory access, and frame walking.

Requires: gcc -g -O0 -o target target.c
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..')))

from pwnc.gdb.mi import debug

BINARY = os.path.join(os.path.dirname(__file__), "target")

# ── spawn GDB and connect ──

g = debug(BINARY)
print("Connected to GDB")

# ── breakpoints ──

bp_main = g.bp("main")
bp_add  = g.bp("add")
print(f"Set breakpoints: main (#{bp_main.number}), add (#{bp_add.number})")

# ── run to main ──

g.run()
stop = g.wait()
print(f"\nHit breakpoint at main (reason: {stop['reason']})")

# ── read typed globals before they're modified ──

print(f"\n--- Globals at main entry ---")
print(f"counter        = {int(g.sym.counter)}")          # 0
print(f"origin.x       = {g.sym.origin.x}")              # 10
print(f"origin.y       = {g.sym.origin.y}")              # 20
print(f"current_color  = {int(g.sym.current_color)}")    # 1 (GREEN)
print(f"message[0..4]  = {[g.sym.message[i] for i in range(5)]}")  # [104,101,108,108,111] = "hello"

# ── registers ──

print(f"\n--- Registers ---")
print(f"rip = 0x{g.reg.rip:x}")
print(f"rsp = 0x{g.reg.rsp:x}")
print(f"rbp = 0x{g.reg.rbp:x}")

# ── step a few instructions ──

print(f"\n--- Stepping ---")
for i in range(3):
    g.nexti()
    g.wait()
    print(f"  step {i+1}: rip=0x{g.reg.rip:x}")

# ── continue to add() ──

g.cont()
stop = g.wait()
print(f"\nHit breakpoint at add (reason: {stop['reason']})")

# ── frame info ──

frame = g.frame()
print(f"\n--- Current frame ---")
print(f"function: {frame.name()}")
print(f"pc:       0x{frame.pc():x}")
print(f"level:    {frame.level()}")

# ── walk the call stack ──

print(f"\n--- Call stack ---")
f = g.frame()
while f is not None:
    try:
        name = f.name() or "??"
        pc = f.pc()
        print(f"  #{f.level()} {name} @ 0x{pc:x}")
        f = f.older()
    except Exception:
        break

# ── raw memory at rsp ──

print(f"\n--- Stack memory ---")
rsp = g.reg.rsp
data = g.read(rsp, 32)
# show as hex words
for off in range(0, 32, 8):
    word = int.from_bytes(data[off:off+8], 'little')
    print(f"  rsp+{off:#04x}: 0x{word:016x}")

# ── delete add breakpoint, break before exit to inspect final state ──

bp_add.delete()
bp_end = g.bp("update_origin")
g.cont()
g.wait()
# now stopped inside update_origin after the loop ran once
print(f"\n--- Globals mid-execution ---")
print(f"counter       = {int(g.sym.counter)}")
print(f"origin.x      = {g.sym.origin.x}")
print(f"origin.y      = {g.sym.origin.y}")

# let it finish
bp_end.delete()
g.cont()
stop = g.wait()
print(f"\nProgram finished (reason: {stop['reason']})")

# ── cleanup ──

g.close()
print("\nSession complete.")
