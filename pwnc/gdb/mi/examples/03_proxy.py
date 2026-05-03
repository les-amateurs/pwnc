"""
Demonstrates proxy descriptors and typed access via the protocol layer.

No GDB needed — uses socketpair with mock handlers to simulate
the bridge.
"""

import socket
import struct
from pwnc.gdb.mi.protocol import Connection
from pwnc.gdb.mi.proxy import (
    PROXY_CLASSES, InferiorProxy, ThreadProxy, BreakpointProxy,
)
from pwnc.gdb.mi import (
    pwnc_type_from_desc, GdbRemoteBytesProvider,
    SymbolAccessor, Registers,
)
from pwnc.types.primitives import Int
from pwnc.types.containers import Struct
from pwnc.types.provider import ByteOrder


# ── simulated GDB state ──

# fake object store (what bridge.py would maintain)
class FakeInferior:
    num = 1
    pid = 12345

class FakeThread:
    num = 1
    name = "main"

objects = {
    100: FakeInferior(),
    200: FakeThread(),
}

memory = bytearray(4096)

# simulate a struct in memory: struct point { int x; int y; }
struct.pack_into("<ii", memory, 0x400, 42, -7)

# simulate a global int
struct.pack_into("<I", memory, 0x500, 0xCAFEBABE)

registers = {"rax": 0x1234, "rbx": 0x5678, "rip": 0x401000, "rsp": 0x7fff0000}


# ── server-side handlers ──

def proxy_get(oid, attr_name):
    obj = objects[oid]
    return getattr(obj, attr_name)

def proxy_call(oid, method_name, args, kwargs):
    obj = objects[oid]
    return getattr(obj, method_name)(*args, **kwargs)

def proxy_set(oid, attr_name, value):
    setattr(objects[oid], attr_name, value)

def resolve_type(name):
    if name == "origin":
        desc = {
            "kind": "struct",
            "name": "point",
            "fields": [
                {"name": "x", "type": {"kind": "int", "bits": 32, "signed": True}, "offset": 0, "bit_offset": 0},
                {"name": "y", "type": {"kind": "int", "bits": 32, "signed": True}, "offset": 4, "bit_offset": 0},
            ],
            "size": 8,
        }
        return (desc, 0x400)
    if name == "counter":
        return ({"kind": "int", "bits": 32, "signed": False}, 0x500)
    return None

def read_memory(addr, size):
    return bytes(memory[addr:addr + size])

def get_register(name):
    return registers[name]

def set_register(name, value):
    registers[name] = value


# ── setup connections ──

cs, ss = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

client = Connection(cs, proxy_classes=PROXY_CLASSES, handlers={})
server = Connection(ss, handlers={
    "proxy.get": proxy_get,
    "proxy.call": proxy_call,
    "proxy.set": proxy_set,
    "resolve_type": resolve_type,
    "read_memory": read_memory,
    "get_register": get_register,
    "set_register": set_register,
})


# ── proxy objects ──

print("=== Proxy Objects ===")

inf = InferiorProxy(client, 100)
print(f"Inferior num: {inf.num}")     # → 1
print(f"Inferior pid: {inf.pid}")     # → 12345

thread = ThreadProxy(client, 200)
print(f"Thread name: {thread.name}")  # → main
print(f"Thread num: {thread.num}")    # → 1


# ── typed symbol access ──

print("\n=== Symbol Access ===")

sym = SymbolAccessor(client, ByteOrder.Little)

# access a struct
origin = sym.origin
print(f"origin.x = {origin.x}")    # → 42
print(f"origin.y = {origin.y}")    # → -7

# access an int
counter = sym.counter
print(f"counter = 0x{int(counter):X}")  # → 0xCAFEBABE

# symbol not found
try:
    _ = sym.nonexistent
except AttributeError as e:
    print(f"Error: {e}")  # → Symbol 'nonexistent' not found


# ── register access ──

print("\n=== Registers ===")

reg = Registers(client)
print(f"rax = 0x{reg.rax:x}")     # → 0x1234
print(f"rip = 0x{reg.rip:x}")     # → 0x401000

reg.rip = 0x402000
print(f"rip after set = 0x{reg.rip:x}")  # → 0x402000


# ── type conversion ──

print("\n=== Type Conversion ===")

# convert a GDB type descriptor to pwnc type
desc = {
    "kind": "struct",
    "name": "elf_header",
    "fields": [
        {"name": "magic", "type": {"kind": "array", "child": {"kind": "int", "bits": 8, "signed": False}, "count": 4}, "offset": 0, "bit_offset": 0},
        {"name": "class_", "type": {"kind": "int", "bits": 8, "signed": False}, "offset": 4, "bit_offset": 0},
        {"name": "data", "type": {"kind": "int", "bits": 8, "signed": False}, "offset": 5, "bit_offset": 0},
        {"name": "entry", "type": {"kind": "ptr", "child": {"kind": "void"}, "bits": 64}, "offset": 8, "bit_offset": 0},
    ],
    "size": 16,
}
elf_type = pwnc_type_from_desc(desc)
print(f"Type: {elf_type.name}, size: {elf_type.nbytes} bytes")
# → Type: elf_header, size: 16 bytes


# ── cleanup ──

client.close()
server.close()
print("\nProxy demo complete.")
