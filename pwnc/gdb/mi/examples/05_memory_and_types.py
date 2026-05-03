"""
Typed memory access: read and write global variables through
the pwnc.types Value interface backed by GDB remote memory.

Requires: gcc -g -O0 -o target target.c
"""

import os
import sys
from pwnc.gdb.mi import debug

BINARY = os.path.join(os.path.dirname(__file__), "target")

g = debug(BINARY)

# run to main
g.bp("main")
g.run()
g.wait()

# ── read a struct via gdb.sym ──

print("--- struct Point origin ---")
origin = g.sym.origin
print(f"origin.x = {origin.x}")     # 10
print(f"origin.y = {origin.y}")     # 20
print(f"type: {origin._type}")
print(f"bytes: {origin.bytes.hex()}")

# ── read an integer ──

print(f"\n--- int counter ---")
counter = g.sym.counter
print(f"counter = {int(counter)}")   # 0
print(f"size: {counter.nbytes} bytes")

# ── read an enum ──

print(f"\n--- enum Color current_color ---")
color = g.sym.current_color
print(f"current_color = {int(color)}")  # 1 (GREEN)

# ── read a char array ──

print(f"\n--- char message[32] ---")
msg = g.sym.message
chars = []
for i in range(32):
    c = msg[i]
    if c == 0:
        break
    chars.append(chr(c))
print(f'message = "{"".join(chars)}"')  # "hello pwnc"

# ── write to memory via provider ──

print(f"\n--- writing to origin ---")
# Get the address and write directly
origin_val = g.sym.origin
# Write new x value (little-endian i32)
origin_val._provider.write(0, (999).to_bytes(4, 'little', signed=True))
print(f"origin.x after write = {g.sym.origin.x}")  # 999

# ── write via gdb.write() convenience ──

# read origin's address from the provider
origin_addr = origin_val._provider._base_addr
# write y = -42
import struct
g.write(origin_addr + 4, struct.pack("<i", -42))
print(f"origin.y after write = {g.sym.origin.y}")  # -42

# ── continue execution, then check final values ──

print(f"\n--- after execution ---")
g.cont()
g.wait()

print(f"counter = {int(g.sym.counter)}")
print(f"origin.x = {g.sym.origin.x}")
print(f"origin.y = {g.sym.origin.y}")
print(f"current_color = {int(g.sym.current_color)}")

# read final message
msg = g.sym.message
chars = []
for i in range(32):
    c = msg[i]
    if c == 0:
        break
    chars.append(chr(c))
print(f'message = "{"".join(chars)}"')

g.close()
print("\nDone.")
