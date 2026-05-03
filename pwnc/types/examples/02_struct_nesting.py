"""
Demonstrates nested struct field access, offset tracking, and root().
"""

from pwnc.types import Int, Struct

u8 = Int(8)
u16 = Int(16)
u32 = Int(32)

Inner = Struct("Inner", [
    ("a", u8),   # offset 0
    ("b", u8),   # offset 1
    ("c", u16),  # offset 2
])

Outer = Struct("Outer", [
    ("header", u32),    # offset 0
    ("inner", Inner),   # offset 4
    ("trailer", u32),   # offset 8
])

# ── type-level field access ──

# accessing a field on a type returns a BoundField with offset context
print(Outer.header)           # type info for header
print(Outer.header.offset)    # 0

print(Outer.inner)            # type info for inner (the Inner struct)
print(Outer.inner.offset)     # 4

# chained access — offset is relative to the ROOT (Outer), not Inner
print(Outer.inner.a.offset)   # 4  (4 + 0)
print(Outer.inner.b.offset)   # 5  (4 + 1)
print(Outer.inner.c.offset)   # 6  (4 + 2)

print(Outer.trailer.offset)   # 8

# ── root() — extract the sub-type without parent context ──

InnerCopy = Outer.inner.root()
print(InnerCopy.a.offset)  # 0 (offset is now relative to Inner, not Outer)
print(InnerCopy.b.offset)  # 1

# ── deeply nested ──

Deep = Struct("Deep", [
    ("padding", u32),
    ("outer", Outer),
])

print(Deep.outer.inner.a.offset)  # 8 (4 + 4 + 0)
print(Deep.outer.inner.c.offset)  # 10 (4 + 4 + 2)

# root() at any level strips the parent context
print(Deep.outer.root().inner.a.offset)        # 4 (relative to Outer)
print(Deep.outer.inner.root().a.offset)         # 0 (relative to Inner)
