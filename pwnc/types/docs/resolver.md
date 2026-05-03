# Types (Multi-Source Resolver)

The `Types` class aggregates multiple type sources and provides unified access
to types across all of them. User-defined types can be added directly and take
precedence over all sources.

## Source Immutability

Once constructed, a source's set of type names is immutable. If a source
contains types A, B, C at construction, it will always report those names.
The type objects themselves may be lazily loaded or updated internally, but
the set of keys never changes. This allows `Types` to build a stable merged
index.

## Usage

```python
from pwnc.types import Types
from pwnc.types.dwarf import DwarfSource

types = Types()
types.add(DwarfSource("./binary_a", lazy=False))
types.add(DwarfSource("./binary_b", lazy=True))

# user-defined types override all sources
types.define("MyStruct", my_struct_type)
```

## API

```python
types["_IO_FILE"]       # get type by name (string indexing)
types._IO_FILE          # get type by name (attribute access)
"stat" in types         # membership test across all sources
types.names()           # merged list of all type names
types.sources           # list of registered sources
types.define(name, ty)  # add a user-defined type (highest priority)
```

## Resolution Order

1. **User-defined types** (via `define()`) — always checked first
2. **Sources** in registration order (via `add()`) — first match wins

```python
types = Types()
types.add(dwarf_source)        # has _IO_FILE, stat, foo
types.add(another_source)      # has bar, baz
types.define("foo", custom_foo) # overrides dwarf_source's foo

types["foo"]        # returns custom_foo (user-defined wins)
types["_IO_FILE"]   # returns from dwarf_source (first source with it)
types["bar"]        # returns from another_source
```

## Attribute Access

Attribute access uses `__getattr__`, so `Types`'s own methods and attributes
take priority over type name lookup:

| Attribute | Resolves to |
|-----------|-------------|
| `types.add` | The `add` method (always) |
| `types.define` | The `define` method (always) |
| `types.names` | The `names` method (always) |
| `types.sources` | The sources list (always) |
| `types._IO_FILE` | Type lookup (via `__getattr__` fallback) |

If a type name collides with a `Types` attribute, use string indexing:
`types["names"]`.

## Source (Abstract Base Class)

All type sources inherit from the `Source` ABC. The key invariant: once a
source is constructed, its set of type names is immutable. The type objects
themselves may be lazily loaded or change internally, but the keys never change.

```python
from abc import ABC, abstractmethod

class Source(ABC):
    @abstractmethod
    def __getitem__(self, name: str) -> Type:
        """Return a Type or raise KeyError."""
        ...

    @abstractmethod
    def __contains__(self, name: str) -> bool:
        """Return True if this source can resolve the name."""
        ...

    @abstractmethod
    def names(self) -> list[str]:
        """Return all available type names."""
        ...
```

`DwarfSource`, `StaticSource`, and any user-created source must inherit from
`Source`.

## StaticSource

A source built from an explicit list or dict of types:

```python
from pwnc.types import StaticSource, Struct, Int

u32 = Int(32)
MyStruct = Struct("MyStruct", [("x", u32), ("y", u32)])
OtherStruct = Struct("OtherStruct", [("a", u32)])

# from a list — names are taken from each type's name
source = StaticSource([MyStruct, OtherStruct])

# from a dict — explicit name mapping
source = StaticSource({"Foo": MyStruct, "Bar": OtherStruct})

source["MyStruct"]      # works with list form
source["Foo"]           # works with dict form
source.names()          # ["MyStruct", "OtherStruct"] or ["Foo", "Bar"]
```

## Error Handling

- `types["unknown"]` raises `KeyError` if no source contains the type
- `types.unknown` raises `AttributeError` if no source contains the type
