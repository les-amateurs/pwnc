"""
Demonstrates pretty printing with depth control and field filtering.
"""

import struct
from pwnc.types import Int, Float, Struct, Array, Enum, Align, Pad

u8 = Int(8)
u16 = Int(16)
u32 = Int(32)
i32 = Int(32, signed=True)
f32 = Float()

Status = Enum(u8, {
    "IDLE": 0,
    "RUNNING": 1,
    "STOPPED": 2,
})

Vec3 = Struct("Vec3", [
    ("x", f32),
    ("y", f32),
    ("z", f32),
])

# cstyle struct with natural alignment
Entity = Struct("Entity", [
    ("id", u32),
    ("status", Status),
    ("name", Array(u8, 16)),
    ("position", Vec3),
    ("velocity", Vec3),
    ("health", i32),
], mode="cstyle")

# ── print type layout ──

print(Entity)
# struct Entity {  /* 0x40 bytes, cstyle */
#     /* 0x00 */ u32 id;
#     /* 0x04 */ enum Status : u8 status;
#     /* 0x05 */ u8 name[16];
#     /* 0x18 */ struct Vec3 {
#         /* 0x00 */     f32 x;
#         /* 0x04 */     f32 y;
#         /* 0x08 */     f32 z;
#     } position;
#     /* 0x24 */ struct Vec3 { ... } velocity;
#     /* 0x30 */ i32 health;
# }

# ── struct with explicit padding/alignment in the output ──

Header = Struct("Header", [
    ("magic", u16),
    Pad(2),
    ("version", u32),
    ("flags", u8),
    Align(8),
    ("offset", u32),
])

print(Header)
# struct Header {  /* 0x14 bytes, packed */
#     /* 0x00 */ u16 magic;
#     /* 0x02 padding(2) */
#     /* 0x04 */ u32 version;
#     /* 0x08 */ u8 flags;
#     /* 0x09 padding(7) */
#     /* 0x10 */ u32 offset;
# }

# ── depth-limited type printing ──

print(Entity.display(depth=1))
# struct Entity {  /* 0x40 bytes, cstyle */
#     /* 0x00 */ u32 id;
#     /* 0x04 */ enum Status : u8 status;
#     /* 0x05 */ u8 name[16];
#     /* 0x18 */ struct Vec3 { ... } position;
#     /* 0x24 */ struct Vec3 { ... } velocity;
#     /* 0x30 */ i32 health;
# }

# ── print values ──

raw = struct.pack("<I", 1)           # id
raw += struct.pack("<B", 1)          # status = RUNNING
raw += b"player\x00" + b"\x00" * 9  # name
raw += b"\x00" * 2                   # cstyle padding
raw += struct.pack("<3f", 1.0, 2.0, 3.0)  # position
raw += struct.pack("<3f", 0.1, 0.0, 0.0)  # velocity
raw += struct.pack("<i", 100)        # health
raw += b"\x00" * 4                   # trailing padding

entity = Entity.use(raw)
print(entity)
# Entity {
#     id = 1
#     status = RUNNING (1)
#     name = [112, 108, 97, 121, 101, 114, 0, ...]
#     position = Vec3 {
#         x = 1.0
#         y = 2.0
#         z = 3.0
#     }
#     velocity = Vec3 {
#         x = 0.1
#         y = 0.0
#         z = 0.0
#     }
#     health = 100
# }

# ── depth-limited value printing ──

print(entity.display(depth=1))
# Entity {
#     id = 1
#     status = RUNNING (1)
#     name = [112, 108, 97, 121, 101, 114, 0, ...]
#     position = Vec3 { ... }
#     velocity = Vec3 { ... }
#     health = 100
# }

# ── filtered printing ──

print(entity.display(filter="position"))
# Entity {
#     position = Vec3 {
#         x = 1.0
#         y = 2.0
#         z = 3.0
#     }
# }

print(entity.display(filter="*loc*"))
# Entity {
#     velocity = Vec3 {
#         x = 0.1
#         y = 0.0
#         z = 0.0
#     }
# }
