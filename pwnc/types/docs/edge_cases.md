# Parsing Edge Cases

## Anonymous Struct/Union Collapsing

When a container has a member that is an anonymous struct or union (no
`DW_AT_name` in DWARF, or no name provided by the user), the anonymous
member's fields are **flattened** into the parent container with adjusted
offsets.

Given this C code:

```c
struct foo {
    int x;
    union {
        int a;
        float b;
    };
    int y;
};
```

The resulting type has `a` and `b` as direct fields of `foo`:

```
struct foo {  /* 0x0c bytes, packed */
    /* 0x00 */ i32 x;
    /* 0x04 */ i32 a;
    /* 0x04 */ f32 b;
    /* 0x08 */ i32 y;
}
```

```python
foo.a.offset  # 4
foo.b.offset  # 4 (overlapping — from the anonymous union)
foo.y.offset  # 8
```

If the anonymous container is at the top level (not inside another container),
it is assigned a generated unique name to remain addressable.

## Flexible Array Members

Flexible array members (C's `type data[]`) are resolved to `Array(child, 0)`.
No special handling is needed — an array with count 0 has `nbytes` of 0, so it
does not affect the containing struct's size.

```c
struct packet {
    uint32_t length;
    uint8_t data[];
};
```

```
struct packet {  /* 0x04 bytes, packed */
    /* 0x00 */ u32 length;
    /* 0x04 */ u8 data[];
}
```

```python
packet.nbytes       # 4
packet.data.nbytes   # 0
packet.data.count    # 0
```
