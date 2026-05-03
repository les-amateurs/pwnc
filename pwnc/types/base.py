
class Type:
    def __init__(self, nbits):
        self._nbits = nbits

    @property
    def nbits(self):
        return self._nbits

    @property
    def nbytes(self):
        return (self._nbits + 7) >> 3

    def use(self, data):
        from .value import Value
        from .provider import BytesProvider, BufferProvider, ByteOrder
        if isinstance(data, BytesProvider):
            provider = data
        else:
            provider = BufferProvider(data, ByteOrder.Little)
        return Value(self, provider, 0)

    def display(self, depth=None, filter=None):
        from .display import format_type
        return format_type(self, depth=depth, filter=filter)

    def __str__(self):
        return self.display()

    def __repr__(self):
        return self.__str__()


class BoundField:
    def __init__(self, type, offset, bit_offset):
        self._type = type
        self._offset = offset
        self._bit_offset = bit_offset

    @property
    def offset(self):
        return self._offset

    @property
    def bit_offset(self):
        return self._bit_offset

    @property
    def nbytes(self):
        return self._type.nbytes

    @property
    def nbits(self):
        return self._type.nbits

    def root(self):
        return self._type

    def use(self, data):
        return self._type.use(data)

    def __getattr__(self, name):
        inner = getattr(self._type, name)
        if isinstance(inner, BoundField):
            new_offset = self._offset + inner._offset
            return BoundField(inner._type, new_offset, inner._bit_offset)
        raise AttributeError(f"type {type(self._type).__name__} has no field '{name}'")

    def __str__(self):
        return f"BoundField({self._type}, offset={self._offset})"

    def __repr__(self):
        return self.__str__()
