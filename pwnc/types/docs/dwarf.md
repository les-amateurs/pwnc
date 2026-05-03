# DWARF Source

`DwarfSource` inherits from `Source`. It loads type information from the DWARF
debug info sections of ELF binaries and produces the same Type objects as manual
construction. Its type names are immutable after construction (upfront mode) or
after the initial index is built (lazy mode).

## Usage

```python
from pwnc.types.dwarf import DwarfSource

# from a file path
source = DwarfSource("./binary_with_debuginfo", lazy=False)

# from a minelf ELF instance
from pwnc.minelf import ELF
elf = ELF(open("./binary", "rb").read())
source = DwarfSource(elf, lazy=False)
```

## API

```python
source.names()          # list[str] — all available type names
source["_IO_FILE"]      # Type — get type by name, KeyError if not found
source._IO_FILE         # Type — get type by name via attribute access
"stat" in source        # bool — membership test
```

Types can be accessed via `source["name"]` or `source.name`. Attribute access
uses `__getattr__`, so DwarfSource's own methods and attributes are always
prioritized. If a type name collides with a DwarfSource attribute (e.g. a type
called `names`), use string indexing: `source["names"]`.

## Loading Modes

### Upfront (`lazy=False`)

Parses all compilation units at construction time. Each CU is independent, so
parsing can be parallelized across threads. Results are merged into a single
namespace.

Best for: tools that will access many/all types, one-time analysis.

### Lazy (`lazy=True`)

On first load, builds a lightweight index mapping type names to their DIE
offsets in `.debug_info`. No types are parsed yet. On first access of a type
by name, that type and all its transitive dependencies are parsed.

Best for: interactive use, large binaries where only a few types are needed.

```python
lazy = DwarfSource("./huge_binary", lazy=True)
# fast — just indexes names

io = lazy["_IO_FILE"]
# now parses _IO_FILE and everything it references
```

## DWARF Sections Used

| Section | Purpose |
|---------|---------|
| `.debug_info` | DIE tree with type definitions |
| `.debug_abbrev` | Abbreviation tables (tag + attribute specs per CU) |
| `.debug_str` | String table for `DW_FORM_strp` references |

Sections are read via `minelf`'s `section_from_name()` and `section_content()`.

## Parsing Pipeline

### 1. Abbreviation tables (`abbrev.py`)

Parse `.debug_abbrev` into lookup tables mapping abbreviation codes to:
- DWARF tag (`DW_TAG_structure_type`, etc.)
- Whether the DIE has children
- List of (attribute, form) pairs

Each compilation unit references its own abbreviation table by offset.

### 2. Low-level reader (`reader.py`)

Provides cursor-based reading over raw section bytes:

- **LEB128** — unsigned and signed variable-length integers (used everywhere
  in DWARF)
- **Form decoding** — reads attribute values according to their DWARF form
  (`DW_FORM_addr`, `DW_FORM_data4`, `DW_FORM_strp`, `DW_FORM_ref4`, etc.)
- **String resolution** — looks up `DW_FORM_strp` offsets in `.debug_str`

### 3. DIE parser (`info.py`)

Walks `.debug_info` section, using abbreviation tables to decode each DIE:

- Reads the abbreviation code
- Looks up tag and attribute specs
- Decodes each attribute value using the reader
- Builds a tree structure (DIEs with children)
- Tracks DIE offsets for cross-references (`DW_AT_type` → offset)

### 4. Type builder (`builder.py`)

Converts the DIE tree into pwnc Type objects. All container types are built
with `mode="packed"` and explicit `Pad` directives derived from DWARF offsets.

| DWARF Tag | Result |
|-----------|--------|
| `DW_TAG_base_type` | `Int` or `Float` or `Double` (based on encoding + size) |
| `DW_TAG_structure_type` | `Struct(mode="packed")` with explicit `Pad` from DWARF offsets |
| `DW_TAG_union_type` | `Union` |
| `DW_TAG_enumeration_type` | `Enum` |
| `DW_TAG_array_type` | `Array` |
| `DW_TAG_subrange_type` | Array count (from `DW_AT_upper_bound` or `DW_AT_count`) |
| `DW_TAG_member` | Field entry with offset from `DW_AT_data_member_location` |
| `DW_TAG_typedef` | Resolved to the underlying type |
| `DW_TAG_const_type` | Resolved to the underlying type |
| `DW_TAG_volatile_type` | Resolved to the underlying type |
| `DW_TAG_pointer_type` | `Ptr(child, bits)` based on CU address size |

### Type reference resolution

DWARF types reference each other via DIE offsets (`DW_AT_type` attribute).
The builder maintains an `offset → Type` map. When building a type:

1. If the referenced type is already built, use it directly
2. If not, recursively build the referenced type first
3. Forward references are possible when types are mutually recursive —
   handled by placeholder insertion and backpatching

### DWARF data as ground truth

Types are built with `mode="packed"` and the builder inserts explicit `Pad(n)`
between fields wherever `DW_AT_data_member_location` indicates a gap between
the end of one field and the start of the next. Trailing padding (when
`DW_AT_byte_size` exceeds the last field's end) is also emitted as `Pad`.
This means the resulting layout exactly reproduces the DWARF data without
relying on alignment inference.
