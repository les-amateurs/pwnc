# pwnc.types Overview

`pwnc.types` is a generic type library for describing, parsing, and inspecting
binary data structures. Types describe shape (sizes, offsets, field layout) and
are endianness-agnostic. Byte order is determined by the underlying bytes
provider at the point of interpretation.

## Architecture

```
┌──────────────────────────────────────────────┐
│                  User Code                   │
│                                              │
│   type = source["_IO_FILE"]                  │
│   val  = type.use(provider)                  │
│   print(val._flags)                          │
└──────────┬──────────────────┬────────────────┘
           │                  │
     ┌─────▼─────┐    ┌──────▼──────┐
     │   Types    │    │   Values    │
     │            │    │             │
     │  Struct    │◄───│  lazy read  │
     │  Union     │    │  detach()   │
     │  Array     │    │  cast()     │
     │  Enum      │    │  .bytes     │
     │  Int/Bits  │    └──────┬──────┘
     │  Float     │           │
     │  Double    │    ┌──────▼──────┐
     │  Ptr       │    │             │
     └─────▲─────┘    │  Provider   │
           │          │             │
     ┌─────┴─────┐    │ ByteOrder   │
     │  Sources   │    │ read/write  │
     │            │    └─────────────┘
     │  DWARF     │
     │  (GDB)     │
     │  (manual)  │
     └─────▲──────┘
           │
     ┌─────┴──────┐
     │   Types    │
     │  resolver  │
     │            │
     │ aggregates │
     │  sources   │
     └────────────┘
```

## Key Concepts

### Types describe shape, not data

A `Type` knows its bit/byte size, its fields (for containers), and how fields
are laid out. It does not hold any data and does not know about endianness.

### Values read lazily from providers

A `Value` pairs a Type with a `BytesProvider` and a base offset. Navigating
into sub-structs creates new Values with adjusted offsets but does not read
bytes. Bytes are only read when a primitive (Int, Float, etc.) is accessed.

### Endianness lives on the provider

The `BytesProvider` carries a `byteorder` attribute (`ByteOrder.Little` or
`ByteOrder.Big`). When a Value interprets raw bytes as a Python int or float,
it consults the provider's byte order.

### Container construction modes

- **packed** (default): fields placed back-to-back, no implicit padding
- **cstyle**: C-style natural alignment rules, trailing padding

Explicit `Align(n)` and `Pad(n)` directives can be placed in any field list
regardless of mode.

## Module Map

| Module | Purpose |
|--------|---------|
| `pwnc.types` | Public API: all type classes, Align, Pad, Ptr, Types, StaticSource |
| `pwnc.types.resolver` | `Source` ABC, `Types` resolver, `StaticSource` |
| `pwnc.types.base` | Base `Type` class, `BoundField` |
| `pwnc.types.primitives` | `Int`, `Bits`, `Float`, `Double`, `Ptr` |
| `pwnc.types.containers` | `Struct`, `Union`, `Array`, `Enum`, `Align`, `Pad` |
| `pwnc.types.value` | `Value` class |
| `pwnc.types.provider` | `ByteOrder`, `BytesProvider` ABC, `BufferProvider` |
| `pwnc.types.display` | Pretty printing engine |
| `pwnc.types.dwarf` | DWARF debug info → Type conversion |
