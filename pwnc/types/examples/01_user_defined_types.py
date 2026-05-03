"""
Demonstrates creating types programmatically and using them to parse data.
"""

from pwnc.types import Int, Float, Double, Bits, Ptr, Array, Enum, Struct, Union
from pwnc.types import Align, Pad
from pwnc.types.provider import ByteOrder, BufferProvider

# ── primitive types ──

u8 = Int(8)
u16 = Int(16)
u32 = Int(32)
u64 = Int(64)
i32 = Int(32, signed=True)
f32 = Float()
f64 = Double()

print(u32)         # Int(32, unsigned)
print(u32.nbytes)  # 4
print(u32.nbits)   # 32

# parse a value from raw bytes (defaults to little endian)
val = u32.use(b"\x01\x00\x00\x00")
print(val)  # 1

# parse with explicit byte order via a provider
be_provider = BufferProvider(b"\x00\x00\x00\x01", ByteOrder.Big)
val = u32.use(be_provider)
print(val)  # 1

# ── bit fields ──

flags_hi = Bits(4)  # upper 4 bits of a byte
flags_lo = Bits(4)  # lower 4 bits

# ── enums ──

Color = Enum(u32, {
    "RED": 0,
    "GREEN": 1,
    "BLUE": 2,
})

val = Color.use(b"\x01\x00\x00\x00")
print(val)  # Color.GREEN (1)

# ── arrays ──

u8_array = Array(u8, 16)
print(u8_array.nbytes)  # 16

val = u8_array.use(bytes(range(16)))
print(val)       # [0, 1, 2, ..., 15]
print(val[3])    # 3

# ── pointers ──

ptr_u32 = Ptr(u32)          # 64-bit pointer to u32
print(ptr_u32)              # u32*
print(ptr_u32.nbytes)       # 8
print(ptr_u32.nbits)        # 64
print(ptr_u32.child)      # Int(32, unsigned)

ptr32_u8 = Ptr(u8, 32)      # 32-bit pointer to u8
print(ptr32_u8.nbytes)      # 4

# pointer value is read as a raw address (integer)
val = ptr_u32.use(b"\x00\x10\x00\x00\x00\x00\x00\x00")
print(val)  # 0x1000

# pointers in structs
Node = Struct("Node", [
    ("value", u32),
    ("next", Ptr(None)),  # Ptr(None) for opaque/void pointer
])
print(Node.next.offset)   # 4
print(Node.nbytes)        # 12

# ── structs (packed by default) ──

Point = Struct("Point", [
    ("x", f32),
    ("y", f32),
])

print(Point)            # struct Point { float x; float y; }
print(Point.nbytes)     # 8
print(Point.x)          # Float, offset 0
print(Point.x.offset)   # 0
print(Point.y.offset)   # 4

# packed: no padding between fields
Packed = Struct("Packed", [
    ("a", u8),   # offset 0
    ("b", u32),  # offset 1 (immediately after a)
])
print(Packed.a.offset)  # 0
print(Packed.b.offset)  # 1
print(Packed.nbytes)    # 5

# cstyle: natural alignment + trailing padding
CStyle = Struct("CStyle", [
    ("a", u8),   # offset 0
    ("b", u32),  # offset 4 (aligned to 4)
], mode="cstyle")
print(CStyle.a.offset)  # 0
print(CStyle.b.offset)  # 4
print(CStyle.nbytes)    # 8 (trailing padding to struct alignment)

# ── explicit alignment and padding ──

# Align(n) aligns the NEXT field to an n-byte boundary
WithAlign = Struct("WithAlign", [
    ("a", u8),
    Align(8),
    ("b", u32),  # offset 8 (aligned to 8-byte boundary)
])
print(WithAlign.a.offset)  # 0
print(WithAlign.b.offset)  # 8
print(WithAlign.nbytes)    # 12

# Pad(n) inserts n bytes of explicit padding
WithPad = Struct("WithPad", [
    ("a", u8),
    Pad(3),   # 3 bytes of padding
    ("b", u32),   # offset 4
])
print(WithPad.a.offset)  # 0
print(WithPad.b.offset)  # 4
print(WithPad.nbytes)    # 8

# Alignment and Padding work in any mode
Mixed = Struct("Mixed", [
    ("a", u8),
    Pad(1),
    ("b", u16),
    Align(8),
    ("c", u32),
], mode="packed")
print(Mixed.a.offset)  # 0
print(Mixed.b.offset)  # 2
print(Mixed.c.offset)  # 8
print(Mixed.nbytes)    # 12

# ── unions ──

IntOrFloat = Union("IntOrFloat", [
    ("as_int", u32),
    ("as_float", f32),
])

print(IntOrFloat.nbytes)  # 4 (max of members)

val = IntOrFloat.use(b"\x00\x00\x80\x3f")
print(val.as_int)    # 1065353216
print(val.as_float)  # 1.0
