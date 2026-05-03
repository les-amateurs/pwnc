"""
Demonstrates bit field types and their use within structs.
"""

from pwnc.types import Int, Bits, Struct, Align, Pad

u8 = Int(8)
u16 = Int(16)
u32 = Int(32)

# ── bit field types ──

# Bits(nbits) represents a bit field within a larger integer
flag_a = Bits(1)
flag_b = Bits(3)
reserved = Bits(4)

print(flag_a.nbits)   # 1
print(flag_b.nbits)   # 3
print(reserved.nbits) # 4

# ── bit fields in packed structs (default) ──
# mirrors C:
#   struct Flags {
#       uint8_t a : 1;
#       uint8_t b : 3;
#       uint8_t reserved : 4;
#       uint16_t value;
#   };

Flags = Struct("Flags", [
    ("a", Bits(1)),
    ("b", Bits(3)),
    ("reserved", Bits(4)),
    ("value", u16),
])

print(Flags)
# struct Flags {  /* 0x03 bytes, packed */
#     /* 0x00:0 */ bits(1) a;
#     /* 0x00:1 */ bits(3) b;
#     /* 0x00:4 */ bits(4) reserved;
#     /* 0x01   */ u16 value;
# }

print(Flags.nbytes)  # 3

# ── bit fields with cstyle alignment ──

FlagsCStyle = Struct("FlagsCStyle", [
    ("a", Bits(1)),
    ("b", Bits(3)),
    ("reserved", Bits(4)),
    ("value", u16),
], mode="cstyle")

print(FlagsCStyle)
# struct FlagsCStyle {  /* 0x04 bytes, cstyle */
#     /* 0x00:0 */ bits(1) a;
#     /* 0x00:1 */ bits(3) b;
#     /* 0x00:4 */ bits(4) reserved;
#     /* 0x01 padding(1) */
#     /* 0x02   */ u16 value;
# }

print(FlagsCStyle.nbytes)  # 4

# ── bit fields with explicit padding ──

FlagsExplicit = Struct("FlagsExplicit", [
    ("a", Bits(1)),
    ("b", Bits(3)),
    ("reserved", Bits(4)),
    Pad(1),         # explicit 1 byte gap
    Align(4),       # align next field to 4 bytes
    ("value", u32),
])

print(FlagsExplicit)
# struct FlagsExplicit {  /* 0x08 bytes, packed */
#     /* 0x00:0 */ bits(1) a;
#     /* 0x00:1 */ bits(3) b;
#     /* 0x00:4 */ bits(4) reserved;
#     /* 0x01 padding(3) */
#     /* 0x04   */ u32 value;
# }

print(FlagsExplicit.nbytes)  # 8

# ── parsing bit fields ──

data = bytes([0b1101_0_1_0_1, 0xff, 0x00])
#                ^^^^         ── reserved = 0b1101 = 13
#                    ^        ── padding? no, b = 0b010 = 2...
# bit layout depends on bit numbering, but the idea:

flags = Flags.use(data)
print(flags.a)         # 1
print(flags.b)         # 2
print(flags.reserved)  # 13
print(flags.value)     # 0x00ff
