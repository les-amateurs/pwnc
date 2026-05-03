"""
Execution control: stepping, skipping instructions, modifying
registers, and using async event callbacks.

Requires: gcc -g -O0 -o target target.c
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..')))

from pwnc.gdb.mi import debug

BINARY = os.path.join(os.path.dirname(__file__), "target")

g = debug(BINARY)

# ── event callbacks ──

libraries = []
g.process.on("library-loaded", lambda r: libraries.append(r.results.get("id", "?")))

# ── run to main ──

g.bp("main")
g.run()
g.wait()
print(f"At main, loaded {len(libraries)} libraries")

# ── stepi: step one machine instruction into calls ──

print("\n--- stepi (3x) ---")
for i in range(3):
    pc_before = g.reg.rip
    g.stepi()
    g.wait()
    pc_after = g.reg.rip
    print(f"  0x{pc_before:x} -> 0x{pc_after:x} (delta={pc_after - pc_before})")

# ── nexti: step one instruction, stepping over calls ──

print("\n--- nexti (3x) ---")
for i in range(3):
    pc_before = g.reg.rip
    g.nexti()
    g.wait()
    pc_after = g.reg.rip
    print(f"  0x{pc_before:x} -> 0x{pc_after:x}")

# ── skip: advance PC past current instruction without executing it ──

print("\n--- skip instruction ---")
pc_before = g.reg.rip
g.skip()
pc_after = g.reg.rip
print(f"  skipped: 0x{pc_before:x} -> 0x{pc_after:x}")
print(f"  (instruction was NOT executed)")

# ── register manipulation ──

print("\n--- register read/write ---")
rax = g.reg.rax
print(f"  rax = 0x{rax:x}")

g.reg.rax = 0xDEADBEEF
print(f"  rax after set = 0x{g.reg.rax:x}")

# restore
g.reg.rax = rax

# ── breakpoint with continue/wait cycle ──

print("\n--- breakpoint on update_origin ---")
bp = g.bp("update_origin")
hit_count = 0

# continue until we've hit update_origin a few times
for i in range(3):
    g.cont()
    stop = g.wait()
    reason = stop.get("reason", "")
    if reason == "breakpoint-hit":
        hit_count += 1
        print(f"  hit #{hit_count}: origin=({g.sym.origin.x}, {g.sym.origin.y})")
    else:
        print(f"  stopped: {reason}")
        break

bp.delete()

# ── run to completion ──

g.cont()
stop = g.wait()
print(f"\nProgram exited: {stop.get('reason', 'unknown')}")

g.close()
print("Done.")
