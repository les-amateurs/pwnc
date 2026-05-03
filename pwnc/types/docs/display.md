# Pretty Printing

Both types and values support `__str__` for direct printing and a `display()`
method for controlled output.

## Type Printing

`print(type)` shows the full type layout with offsets, field types, and names.

```
struct Entity {  /* 0x40 bytes, cstyle */
    /* 0x00 */ u32 id;
    /* 0x04 */ enum Status : u8 status;
    /* 0x05 */ u8 name[16];
    /* 0x18 */ struct Vec3 {
        /* 0x00 */ f32 x;
        /* 0x04 */ f32 y;
        /* 0x08 */ f32 z;
    } position;
    /* 0x24 */ struct Vec3 { ... } velocity;
    /* 0x30 */ i32 health;
}
```

### Header line

```
struct Name {  /* 0xNN bytes, mode */
```

Shows the container kind, name, total byte size, and construction mode.

### Field lines

```
    /* 0xOO */ type_name field_name;
```

Each field shows its hex offset within the container, type, and name.

### Padding lines

Padding (explicit `Pad`, implicit from cstyle, or from `Align`) is shown as
a comment-only line:

```
    /* 0x02 padding(2) */
    /* 0x04 */ u32 version;
```

The padding line shows the offset where the gap starts and the number of padding
bytes.

### Bit field offsets

Bit fields show both byte offset and bit offset:

```
    /* 0x00:0 */ bits(1) a;
    /* 0x00:1 */ bits(3) b;
    /* 0x00:4 */ bits(4) reserved;
    /* 0x01 padding(1) */
    /* 0x02   */ u16 value;
```

### Nested struct deduplication

The first occurrence of a nested struct type is expanded inline. Subsequent
occurrences of the same type are collapsed:

```
    /* 0x18 */ struct Vec3 {
        /* 0x00 */ f32 x;
        ...
    } position;
    /* 0x24 */ struct Vec3 { ... } velocity;
```

### Zero-count arrays (flexible array members)

Arrays with count 0 are shown with empty brackets:

```
    /* 0x04 */ u8 data[];
```

## Value Printing

`print(value)` shows field names with their resolved values:

```
Entity {
    id = 1
    status = RUNNING (1)
    name = [112, 108, 97, 121, 101, 114, 0, ...]
    position = Vec3 {
        x = 1.0
        y = 2.0
        z = 3.0
    }
    velocity = Vec3 {
        x = 0.1
        y = 0.0
        z = 0.0
    }
    health = 100
}
```

### Enum values

Enum values show both the symbolic name and the numeric value:

```
status = RUNNING (1)
```

### Array values

Large arrays truncate with `...`:

```
name = [112, 108, 97, 121, 101, 114, 0, ...]
```

## Display Control

The `display()` method provides control over output:

### Depth limiting

```python
type_or_value.display(depth=1)
```

Limits how many levels of nesting are expanded. Nested containers beyond the
depth limit are collapsed:

```
Entity {
    id = 1
    position = Vec3 { ... }
    health = 100
}
```

For types:

```
struct Entity {  /* 0x40 bytes, cstyle */
    /* 0x00 */ u32 id;
    /* 0x18 */ struct Vec3 { ... } position;
    /* 0x30 */ i32 health;
}
```

### Field filtering

```python
type_or_value.display(filter="pattern")
```

Glob pattern matched against field names. Only matching fields are shown:

```python
entity.display(filter="position")
# Entity {
#     position = Vec3 {
#         x = 1.0
#         y = 2.0
#         z = 3.0
#     }
# }

entity.display(filter="*loc*")
# Entity {
#     velocity = Vec3 { ... }
# }
```

### Combined

```python
entity.display(depth=1, filter="*tion*")
```

Depth and filter can be used together.
