"""
Demonstrates the protocol layer: bidirectional RPC over Unix sockets
with pickle serialization.

No GDB needed — uses a socketpair for both sides.
"""

import socket
import struct
from pwnc.gdb.mi.protocol import Connection, Call, Return

# ── create a socketpair ──

# both sides get a connected socket — simulates client/server
client_sock, server_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

# ── define server-side handlers ──

memory = bytearray(4096)

# put some data in "memory"
struct.pack_into("<I", memory, 0x100, 0xDEADBEEF)
struct.pack_into("<I", memory, 0x104, 42)

def read_memory(addr, size):
    """Simulate reading process memory."""
    return bytes(memory[addr:addr + size])

def write_memory(addr, data):
    """Simulate writing process memory."""
    memory[addr:addr + len(data)] = data

registers = {"rax": 0, "rbx": 0, "rcx": 0, "rsp": 0x7fff0000, "rip": 0x401000}

def get_register(name):
    return registers.get(name, 0)

def set_register(name, value):
    registers[name] = value

def add(a, b):
    return a + b

# ── create connections ──

server = Connection(
    server_sock,
    handlers={
        "read_memory": read_memory,
        "write_memory": write_memory,
        "get_register": get_register,
        "set_register": set_register,
        "add": add,
    },
)

client = Connection(client_sock, handlers={})

# ── make RPC calls ──

# simple call
result = client.call("add", 10, 32)
print(f"10 + 32 = {result}")
# → 10 + 32 = 42

# read memory
data = client.call("read_memory", 0x100, 4)
val = struct.unpack("<I", data)[0]
print(f"memory[0x100] = 0x{val:08X}")
# → memory[0x100] = 0xDEADBEEF

data = client.call("read_memory", 0x104, 4)
val = struct.unpack("<I", data)[0]
print(f"memory[0x104] = {val}")
# → memory[0x104] = 42

# write memory
client.call("write_memory", 0x200, b"\x01\x02\x03\x04")
print(f"memory[0x200:0x204] = {list(memory[0x200:0x204])}")
# → memory[0x200:0x204] = [1, 2, 3, 4]

# registers
rip = client.call("get_register", "rip")
print(f"rip = 0x{rip:x}")
# → rip = 0x401000

client.call("set_register", "rip", 0x402000)
print(f"rip after set = 0x{registers['rip']:x}")
# → rip after set = 0x402000

# error handling
try:
    client.call("nonexistent_method")
except RuntimeError as e:
    print(f"Error: {e}")
# → Error: Remote error: Unknown method: nonexistent_method

# ── bidirectional calls ──

# server can call client too
client2_sock, server2_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

client2 = Connection(
    client2_sock,
    handlers={"client_ping": lambda: "pong from client"},
)
server2 = Connection(
    server2_sock,
    handlers={"server_ping": lambda: "pong from server"},
)

print(client2.call("server_ping"))  # → pong from server
print(server2.call("client_ping"))  # → pong from client

# ── cleanup ──

client.close()
server.close()
client2.close()
server2.close()

print("\nProtocol demo complete.")
