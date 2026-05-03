# Values and Providers

## ByteOrder

```python
class ByteOrder:
    Little = 0
    Big = 1
```

Used by providers to declare how multi-byte integers and floats are encoded.

## BytesProvider (Abstract Base Class)

`BytesProvider` is an ABC that all providers must inherit from. It defines the
interface for reading (and optionally writing) bytes, along with a `byteorder`
attribute.

```python
from abc import ABC, abstractmethod

class BytesProvider(ABC):
    byteorder: ByteOrder

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Read `size` bytes starting at `offset`."""
        ...

    def write(self, offset: int, data: bytes) -> None:
        """Write `data` at `offset`. Default raises NotImplementedError."""
        raise NotImplementedError
```

`write()` has a default implementation that raises `NotImplementedError`.
Writable providers override it.

### BufferProvider

Built-in provider that inherits from `BytesProvider` and wraps `bytes`,
`bytearray`, or `memoryview`:

```python
provider = BufferProvider(b"\x00" * 256, ByteOrder.Little)
provider = BufferProvider(bytearray(256), ByteOrder.Big)  # writable
```

When `use()` is called with raw bytes instead of a provider, a `BufferProvider`
with `ByteOrder.Little` is created automatically.

### Custom Providers

Inherit from `BytesProvider` to create custom providers:

```python
class GdbMemory(BytesProvider):
    def __init__(self, pid, byteorder):
        self.byteorder = byteorder
        self.pid = pid

    def read(self, offset, size):
        # read from /proc/pid/mem, ptrace, gdb MI, etc.
        ...

    def write(self, offset, data):
        # write to process memory
        ...
```

## Value Class

A `Value` pairs a Type with a BytesProvider and a base offset. Created via
`Type.use(data)`.

### Lazy Access

Navigating into container sub-fields returns new Values without reading bytes.
Bytes are only read when a primitive value is resolved:

```python
p = MyStruct.use(provider)
sub = p.inner          # no read — returns a Value for the inner struct
val = p.inner.field    # reads field's bytes from provider
```

### Properties

Values forward these from their underlying type:

| Property | Description |
|----------|-------------|
| `nbytes` | Byte size of the underlying type |
| `nbits` | Bit size of the underlying type |
| `offset` | Offset relative to the root container |
| `use(data)` | Create a new Value of the same type |

### .bytes

Returns the raw bytes backing this value:

```python
val = u32.use(b"\x01\x00\x00\x00")
val.bytes  # b'\x01\x00\x00\x00'

s = MyStruct.use(data)
s.bytes          # all bytes of the struct
s.some_field.bytes  # just that field's bytes
```

### detach()

Reads the full `nbytes` from the provider and creates a new Value backed by a
local `BufferProvider`. The original provider is no longer referenced:

```python
remote_val = MyStruct.use(remote_provider)
local_val = remote_val.detach()
# local_val reads from a local byte copy, remote_provider is not touched
```

### cast()

Reinterpret the same bytes as a different type:

```python
val = u32.use(b"\x00\x00\x80\x3f")
print(val)              # 1065353216
print(val.cast(f32))    # 1.0

# also accepts a Value (uses its type)
other = f32.use(b"\x00\x00\x00\x00")
print(val.cast(other))  # 1.0
```

Cast preserves the same provider and offset — only the type changes.

### Array Values

Array values support indexing:

```python
arr = Array(u8, 16).use(bytes(range(16)))
arr[0]   # 0
arr[15]  # 15
```

### Printing

`print(value)` shows field names with resolved values:

```
Point {
    x = 1.0
    y = 2.0
}
```

See [Pretty Printing](display.md) for depth and filter control.
