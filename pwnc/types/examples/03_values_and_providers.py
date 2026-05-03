"""
Demonstrates the Value class: lazy access, detach, cast, bytes, and
the BytesProvider interface.
"""

import struct
from pwnc.types import Int, Float, Struct
from pwnc.types.provider import ByteOrder, BytesProvider, BufferProvider

u32 = Int(32)
f32 = Float()

Particle = Struct("Particle", [
    ("id", u32),
    ("x", f32),
    ("y", f32),
    ("z", f32),
])

# ── basic value creation ──

raw = struct.pack("<I3f", 42, 1.0, 2.0, 3.0)
p = Particle.use(raw)

# accessing a container sub-field is lazy (no bytes read yet)
pos_x_value = p.x  # no provider.read() call happens here

# accessing the actual value triggers the read
print(p.id)   # 42
print(p.x)    # 1.0
print(p.y)    # 2.0
print(p.z)    # 3.0

# ── forwarded type properties ──

print(p.id.offset)   # 0
print(p.x.offset)    # 4
print(p.x.nbytes)    # 4
print(p.x.nbits)     # 32

# ── .bytes — raw bytes of a field ──

print(p.id.bytes)    # b'\x2a\x00\x00\x00'
print(p.bytes)       # all 16 bytes of the struct

# ── detach — snapshot the struct into a local copy ──

provider = BufferProvider(raw, ByteOrder.Little)
p = Particle.use(provider)

# before detach, reads go to the provider
print(p.id)  # 42

# detach fetches the full struct and disconnects from the provider
local = p.detach()
print(local.id)  # 42 — now reads from local copy, provider is not touched

# ── cast — reinterpret as a different type ──

val = u32.use(b"\x00\x00\x80\x3f")
print(val)  # 1065353216

as_float = val.cast(f32)
print(as_float)  # 1.0

# cast with another value (uses target's type)
other = f32.use(b"\x00\x00\x00\x00")
as_float2 = val.cast(other)
print(as_float2)  # 1.0

# ── big endian provider ──

be_data = struct.pack(">I3f", 42, 1.0, 2.0, 3.0)
be_provider = BufferProvider(be_data, ByteOrder.Big)
p = Particle.use(be_provider)
print(p.id)  # 42
print(p.x)   # 1.0


# ── custom BytesProvider (e.g., remote memory) ──

class RemoteMemory(BytesProvider):
    """Custom provider that inherits from BytesProvider."""

    def __init__(self, base_addr: int, byteorder: ByteOrder):
        self.base_addr = base_addr
        self.byteorder = byteorder
        # in reality this would talk to gdb, /proc/pid/mem, etc.
        self._fake_memory = bytearray(4096)

    def read(self, offset: int, size: int) -> bytes:
        addr = self.base_addr + offset
        print(f"  [remote read @ {addr:#x}, {size} bytes]")
        return bytes(self._fake_memory[addr : addr + size])

    def write(self, offset: int, data: bytes) -> None:
        addr = self.base_addr + offset
        print(f"  [remote write @ {addr:#x}, {len(data)} bytes]")
        self._fake_memory[addr : addr + len(data)] = data


remote = RemoteMemory(0x7fff0000, ByteOrder.Little)
p = Particle.use(remote)

# lazy — no read yet
_ = p.x

# triggers read
print(p.id)  # [remote read @ 0x7fff0000, 4 bytes] → 0
