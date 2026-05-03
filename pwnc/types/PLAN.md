# pwnc/types — Implementation Plan

Generic type library for reading and manipulating binary type information from multiple sources.

## File Structure

```
pwnc/types/
├── __init__.py          # public API exports
├── resolver.py          # Source ABC, Types resolver, StaticSource
├── base.py              # base Type class, BoundField
├── primitives.py        # Int, Bits, Float, Double, Ptr
├── containers.py        # Struct, Union, Array, Enum, Align, Pad
├── value.py             # Value class (lazy access over BytesProvider)
├── provider.py          # ByteOrder, BytesProvider ABC, BufferProvider
├── display.py           # pretty printing (depth/filter control)
└── dwarf/
    ├── __init__.py      # DwarfSource public API (upfront + lazy modes)
    ├── constants.py     # DWARF tags, attributes, forms, encodings
    ├── reader.py        # low-level DWARF data reader (LEB128, forms, etc.)
    ├── abbrev.py        # .debug_abbrev parser
    ├── info.py          # .debug_info DIE parser
    └── builder.py       # DIE → Type conversion (packed with explicit padding)
```

## Core Design

### Types are endianness-agnostic

Types describe shape only: sizes, offsets, field layout. Byte order lives on the
`BytesProvider`. When a `Value` needs to interpret bytes as an integer or float,
it reads `provider.byteorder`.

### ByteOrder

```python
class ByteOrder:
    Little = 0
    Big = 1
```

### BytesProvider (abstract base class)

```python
class BytesProvider(ABC):
    byteorder: ByteOrder

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes: ...

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError  # optional, subclasses override if writable
```

`BufferProvider(data, byteorder)` inherits from `BytesProvider` and wraps
`bytes | bytearray | memoryview`. Custom providers must inherit from
`BytesProvider`.

### Type class

All types implement:

- `nbytes` — byte count, computed at init (rounded up from bits)
- `nbits` — bit count
- `use(data)` → `Value` — accepts bytes/bytearray/memoryview/BytesProvider

### BoundField

Attribute access on a container type returns a `BoundField(type, offset)`.
Chained access accumulates offsets relative to the root:

```
Outer.inner.field.offset  # offset relative to Outer
```

`BoundField.root()` strips parent context, returning the unwrapped type.

### Primitive types

| Class | Constructor | Description |
|-------|-------------|-------------|
| `Int` | `Int(bits, signed=False)` | Arbitrary bit-width integer |
| `Bits` | `Bits(nbits)` | Bit field, subclass of Int |
| `Float` | `Float()` | 32-bit IEEE 754 float |
| `Double` | `Double()` | 64-bit IEEE 754 float |
| `Ptr` | `Ptr(child, bits=64)` | Pointer to another type |

### Container types

| Class | Constructor | Description |
|-------|-------------|-------------|
| `Struct` | `Struct(name, fields, mode="packed")` | Named fields at computed offsets |
| `Union` | `Union(name, fields)` | All fields at offset 0, size = max |
| `Array` | `Array(child, count)` | Fixed-size homogeneous array |
| `Enum` | `Enum(child, members)` | Named integer constants over child type |

### Container construction modes

- **`packed`** (default) — no implicit padding, fields placed sequentially
- **`cstyle`** — C-style natural alignment + trailing padding to struct alignment

### Field list items

The `fields` list for Struct/Union accepts three kinds of items:

- `(name, type)` — a named field
- `Align(n)` — insert padding to align the next field to an n-byte boundary
- `Pad(n)` — insert exactly n bytes of padding

`Align` and `Pad` work in any mode. In `cstyle` mode, implicit padding from
alignment rules is added automatically; explicit `Align`/`Pad` can still
override or extend.

### Value class

- Holds `(type, provider, base_offset)`
- Container field access → new Value with adjusted offset (lazy, no read)
- Primitive field access → triggers `provider.read()`, returns Python int/float
- `detach()` — reads `nbytes` from provider, wraps in local `BufferProvider`
- `cast(target)` — new Value with same provider/offset, target's type
  - target can be a Type or another Value (uses its type)
- `.bytes` — raw bytes from provider
- Forwards `nbytes`, `nbits`, `offset`, `use` from underlying type

### Pretty printing

Type layout printing:

```
struct Header {  /* 0x14 bytes, packed */
    /* 0x00 */ u16 magic;
    /* 0x02 padding(2) */
    /* 0x04 */ u32 version;
}
```

- Padding (implicit or explicit) shown as comment-only lines: `/* [offset] padding([n]) */`
- Bit fields show bit offset: `/* 0x00:4 */`
- Nested structs expand inline (first occurrence) or collapse: `struct Vec3 { ... }`

Value printing:

```
Header {
    magic = 0xdead
    version = 1
}
```

Display control:

- `display(depth=N)` — limit nesting depth
- `display(filter="pattern")` — glob pattern on field names

### Parsing edge cases

**Anonymous struct/union collapsing**: When a member has no name, its fields are
flattened into the parent with adjusted offsets. Top-level anonymous types get a
generated unique name.

**Flexible array members**: Resolved to `Array(child, 0)`. No special FAM
handling — an array with count 0 has `nbytes` of 0 naturally.

## Source (abstract base class)

`Source` is an abstract base class that all type sources inherit from. Once
constructed, a source's set of type names is immutable — if a source contains
types A, B, C, it will always contain those names. The type objects themselves
may be lazily loaded or change internally, but the keys never change. This
invariant is part of the `Source` contract.

```python
class Source(ABC):
    @abstractmethod
    def __getitem__(self, name: str) -> Type: ...

    @abstractmethod
    def __contains__(self, name: str) -> bool: ...

    @abstractmethod
    def names(self) -> list[str]: ...
```

All sources (`DwarfSource`, `StaticSource`, any user-created source) must
inherit from `Source`.

### StaticSource

A source built from an explicit list or dict of types. Inherits from `Source`.

```python
from pwnc.types import StaticSource, Struct, Int

u32 = Int(32)
MyStruct = Struct("MyStruct", [("x", u32), ("y", u32)])

source = StaticSource([MyStruct])           # names inferred from types
source = StaticSource({"Foo": MyStruct})    # explicit name mapping
```

Type names are fixed at construction.

## Types (multi-source resolver)

The `Types` class aggregates multiple sources and resolves types across them.
Sources are searched in registration order — the first source that contains
the requested type wins.

User-defined types can be added directly to the `Types` instance and take
precedence over all sources.

```python
types = Types()
types.add(DwarfSource("./binary", lazy=False))
types.add(another_source)

# user-defined types override everything
types.define("MyStruct", MyStruct)

types["_IO_FILE"]       # searches sources in order
types._IO_FILE          # attribute access (same priority rules as DwarfSource)
types["MyStruct"]       # returns user-defined type (highest priority)
"stat" in types         # membership test across all sources
types.names()           # merged list from user-defined + all sources
```

Attribute access uses `__getattr__`, so `Types`'s own methods and attributes
(`add`, `define`, `names`, `sources`, etc.) take priority over type name lookup.

Resolution order:
1. User-defined types (via `define()`)
2. Sources in registration order (via `add()`)

## DWARF Source

`DwarfSource` inherits from `Source`. Its type names are immutable after
construction (upfront mode) or after the initial index is built (lazy mode).

### Input

Accepts a file path (string) or a `pwnc.minelf.ELF` instance. Uses minelf to
access `.debug_info`, `.debug_abbrev`, `.debug_str` sections.

### Loading modes

**Upfront** (`lazy=False`): Parses all compilation units at construction.
Per-CU parsing is independent and can be parallelized. Results merged into a
single type namespace.

**Lazy** (`lazy=True`): Indexes type names and their DIE offsets on first load.
Parses individual types and their transitive dependencies on first access.

### API

```python
source = DwarfSource("./binary", lazy=False)
source.names()          # list all type names
source["_IO_FILE"]      # get type by name (string indexing)
source._IO_FILE         # get type by name (attribute access)
"stat" in source        # membership test
```

Attribute access uses `__getattr__`, so DwarfSource's own methods and
attributes (`names`, `lazy`, etc.) take priority. Falls back to type lookup
only when the attribute is not found on the object itself.

### DWARF parsing pipeline

1. **abbrev.py** — parse `.debug_abbrev` into abbreviation tables
   (code → tag + attribute specs)
2. **reader.py** — low-level reader: LEB128, DWARF form decoding, cursor over
   section bytes
3. **info.py** — walk `.debug_info` DIEs using abbreviation tables, produce
   a tree of DIE nodes with decoded attributes
4. **builder.py** — convert DIE tree into Type objects:
   - `DW_TAG_base_type` → Int / Float / Double
   - `DW_TAG_structure_type` → Struct (packed, with explicit Pad from DWARF offsets)
   - `DW_TAG_union_type` → Union
   - `DW_TAG_enumeration_type` → Enum
   - `DW_TAG_array_type` + `DW_TAG_subrange_type` → Array
   - `DW_TAG_member` → field entries with offset from `DW_AT_data_member_location`
   - `DW_TAG_typedef`, `DW_TAG_const_type`, `DW_TAG_volatile_type`
     → resolved/unwrapped to underlying type
   - `DW_TAG_pointer_type` → Ptr(child, bits) based on CU address size
   - Forward references resolved via DIE offset → Type mapping

### DWARF types built with packed mode and explicit padding

Types from DWARF are built with `mode="packed"` (the default). The builder
inserts explicit `Pad(n)` directives between fields wherever DWARF attributes
(`DW_AT_data_member_location`) indicate gaps. This ensures the resulting type
layout exactly matches the DWARF data without relying on cstyle alignment
inference. Trailing padding (from `DW_AT_byte_size` exceeding the last field's
end) is also inserted as an explicit `Pad`.

## Out of scope (for now)

- **GDB source** — `ptype /ox` based type loading (lazy only)
- **User-defined source** — programmatic type creation is supported via the
  core API, but no dedicated "source" wrapper is needed
