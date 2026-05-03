# Type System

## Base Type

All types share a common interface:

```python
class Type:
    nbytes: int   # byte size (ceil(nbits / 8))
    nbits: int    # bit size

    def use(self, data) -> Value:
        """Create a Value from bytes, bytearray, memoryview, or BytesProvider."""
        ...
```

`nbytes` and `nbits` are computed at type construction time and are immutable.

## Primitive Types

### Int

Arbitrary bit-width integer.

```python
u8  = Int(8)               # 8-bit unsigned
u32 = Int(32)              # 32-bit unsigned
i16 = Int(16, signed=True) # 16-bit signed
```

Properties:
- `nbits` — the bit width passed to the constructor
- `nbytes` — `ceil(nbits / 8)`
- `signed` — whether the integer is signed

### Bits

Bit field type, subclass of `Int`. Used within structs to represent C bit fields.

```python
flag = Bits(1)      # 1-bit field
mode = Bits(3)      # 3-bit field
reserved = Bits(4)  # 4-bit field
```

`Bits` fields pack sequentially within bytes. When followed by a non-Bits field
or a byte boundary, the remaining bits in the current byte are unused.

### Float

32-bit IEEE 754 single-precision float.

```python
f32 = Float()
f32.nbytes  # 4
f32.nbits   # 32
```

### Double

64-bit IEEE 754 double-precision float.

```python
f64 = Double()
f64.nbytes  # 8
f64.nbits   # 64
```

### Ptr

Pointer to another type. Stores the child type and the pointer width.

```python
Ptr(child: Type, bits: int = 64)

p = Ptr(u32)        # 64-bit pointer to u32
p.nbytes             # 8
p.nbits              # 64
p.child            # Int(32, unsigned)

p32 = Ptr(u32, 32)  # 32-bit pointer to u32
p32.nbytes           # 4
```

A `Ptr` is a primitive in terms of value resolution — accessing a pointer field
on a Value reads `nbytes` from the provider and returns the raw address as a
Python int. The `child` type is available for inspection but is not
automatically dereferenced (dereferencing requires a provider that can read
at arbitrary addresses).

In pretty printing, pointers display their child type:

```
    /* 0x08 */ u32* next;
    /* 0x10 */ struct Node* child;
```

When constructed from DWARF, `DW_TAG_pointer_type` maps to `Ptr(child, bits)`
where `bits` is determined by the compilation unit's address size.

## Container Types

### Struct

Ordered collection of named fields at computed offsets.

```python
Struct(name: str, fields: list, mode: str = "packed")
```

**Fields list** accepts three kinds of items:

| Item | Description |
|------|-------------|
| `(name, type)` | A named field |
| `Align(n)` | Align next field to n-byte boundary |
| `Pad(n)` | Insert n bytes of explicit padding |

**Construction modes:**

| Mode | Behavior |
|------|----------|
| `packed` | Fields placed sequentially, no implicit padding |
| `cstyle` | Natural alignment per field, trailing padding to struct alignment |

```python
# packed (default): a at 0, b at 1, total 5 bytes
Struct("S", [("a", u8), ("b", u32)])

# cstyle: a at 0, b at 4 (aligned), total 8 bytes (trailing pad)
Struct("S", [("a", u8), ("b", u32)], mode="cstyle")

# explicit padding in any mode
Struct("S", [("a", u8), Pad(3), ("b", u32)])
Struct("S", [("a", u8), Align(4), ("b", u32)])
```

**Field access** on a Struct type returns a `BoundField`:

```python
MyStruct.field_name          # BoundField with offset relative to MyStruct
MyStruct.inner.field.offset  # offset accumulates through nesting
MyStruct.inner.root()        # unwrap to get the inner type directly
```

### Union

All fields share offset 0. Size is the maximum of all member sizes.

```python
Union("IntOrFloat", [
    ("as_int", u32),
    ("as_float", f32),
])
```

### Array

Fixed-count homogeneous array.

```python
Array(child, count)

buf = Array(u8, 256)   # 256-byte buffer
buf.nbytes              # 256
buf.child               # Int(8, unsigned) — the element type
buf.count               # 256
```

Flexible array members in C are resolved to `Array(child, 0)`. An array with
`count=0` has `nbytes` of 0, so it does not affect the containing struct's size.

### Enum

Named integer constants over a child integer type.

```python
Color = Enum(u32, {
    "RED": 0,
    "GREEN": 1,
    "BLUE": 2,
})

Color.child   # Int(32, unsigned) — the underlying integer type
Color.members # {"RED": 0, "GREEN": 1, "BLUE": 2}
```

The enum's `nbytes` and `nbits` match the child type.

## BoundField

`BoundField` is the return type of field access on container types. It wraps
a type and an accumulated offset from the root container.

```python
bf = Outer.inner.field
bf.offset   # offset relative to Outer (accumulated through chain)
bf.nbytes   # delegated to the wrapped type
bf.nbits    # delegated to the wrapped type
bf.root()   # returns the wrapped type, stripping parent context
```

Chaining preserves the root:

```python
Deep.outer.inner.field.offset  # sum of all intermediate offsets
Deep.outer.root()              # returns the Outer type
Deep.outer.inner.root()        # returns the Inner type
```
