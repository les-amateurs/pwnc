"""
Demonstrates loading types from DWARF debug info in an ELF binary.
Both upfront and lazy loading modes.
"""

from pwnc.types.dwarf import DwarfSource
from pwnc.types.provider import ByteOrder, BufferProvider

# ── upfront loading ──
# parses all types from the binary at construction time
# parallelizes across compilation units

source = DwarfSource("./binary_with_debuginfo", lazy=False)

# list all available type names
print(source.names())  # ['_IO_FILE', 'stat', 'Point', ...]

# access a type by name (string indexing or attribute access)
_IO_FILE = source["_IO_FILE"]
_IO_FILE = source._IO_FILE     # equivalent
print(_IO_FILE)
# struct _IO_FILE { /* 0xd8 bytes, packed */
#     /* 0x00 */ i32 _flags;
#     /* 0x08 */ i8* _IO_read_ptr;
#     ...
# }

# access nested fields
print(_IO_FILE._flags.offset)      # 0
print(_IO_FILE._IO_read_ptr.offset) # 8

# use type to parse data
fake_stdout = _IO_FILE.use(b"\x00" * _IO_FILE.nbytes)
print(fake_stdout._flags)  # 0


# ── lazy loading ──
# only indexes type names initially, parses types on first access

lazy_source = DwarfSource("./binary_with_debuginfo", lazy=True)

# names are available immediately (indexed from .debug_info)
print("stat" in lazy_source)  # True

# first access triggers parsing of `stat` and its dependencies
stat = lazy_source.stat        # attribute access works too
stat = lazy_source["stat"]     # equivalent
print(stat)
print(stat.st_size.offset)


# ── working with minelf directly ──

from pwnc.minelf import ELF

elf = ELF(open("./binary_with_debuginfo", "rb").read())
source = DwarfSource(elf, lazy=False)

# same API as above
print(source["main_struct"])


# ── multi-source resolver ──

from pwnc.types import Types, StaticSource, Struct, Int

u32 = Int(32)

types = Types()
types.add(DwarfSource("./binary_a", lazy=False))
types.add(DwarfSource("./binary_b", lazy=True))

# searches sources in registration order
print(types._IO_FILE)          # attribute access
print(types["stat"])           # string indexing
print("stat" in types)         # True
print(types.names())           # merged names from all sources

# user-defined types take precedence over all sources
CustomStruct = Struct("CustomStruct", [("a", u32), ("b", u32)])
types.define("CustomStruct", CustomStruct)
print(types.CustomStruct)      # returns user-defined type

# can also override a source type
types.define("stat", Struct("stat", [("st_size", u32)]))
print(types.stat)              # returns user-defined override, not DWARF's


# ── static source ──

MyType = Struct("MyType", [("x", u32)])
OtherType = Struct("OtherType", [("y", u32)])

# build a source from a list of types (names from type.name)
static = StaticSource([MyType, OtherType])
print(static["MyType"])
print(static.names())          # ["MyType", "OtherType"]

# or from a dict for explicit naming
static = StaticSource({"Renamed": MyType})
print(static["Renamed"])


# ── anonymous struct/union collapsing ──
# given C code:
#   struct foo {
#       int x;
#       union {
#           int a;
#           float b;
#       };
#       int y;
#   };
#
# the anonymous union members are collapsed into foo:

foo = source["foo"]
print(foo)
# struct foo {
#     /* 0x00 */ i32 x;
#     /* 0x04 */ i32 a;
#     /* 0x04 */ f32 b;
#     /* 0x08 */ i32 y;
# }

print(foo.a.offset)  # 4
print(foo.b.offset)  # 4 (overlapping, was in anonymous union)


# ── flexible array members ──
# given C code:
#   struct packet {
#       uint32_t length;
#       uint8_t data[];
#   };

packet_type = source["packet"]
print(packet_type)
# struct packet {
#     /* 0x00 */ u32 length;
#     /* 0x04 */ u8 data[];
# }

print(packet_type.nbytes)       # 4 (Array(u8, 0) has nbytes 0)
print(packet_type.data.count)   # 0
