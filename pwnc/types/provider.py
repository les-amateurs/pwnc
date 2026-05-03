from abc import ABC, abstractmethod


class ByteOrder:
    Little = 0
    Big = 1


class BytesProvider(ABC):
    byteorder: int
    ptrbits: int = 64

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes: ...

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def rebase(self, addr: int) -> 'BytesProvider':
        raise NotImplementedError

    @property
    def address(self) -> int:
        raise TypeError("provider has no memory address")


class BufferProvider(BytesProvider):
    def __init__(self, data, byteorder=ByteOrder.Little, ptrbits=64):
        if isinstance(data, memoryview):
            self._data = data
        elif isinstance(data, bytearray):
            self._data = memoryview(data)
        else:
            self._data = memoryview(bytearray(data))
        self.byteorder = byteorder
        self.ptrbits = ptrbits

    def read(self, offset: int, size: int) -> bytes:
        return bytes(self._data[offset : offset + size])

    def write(self, offset: int, data: bytes) -> None:
        self._data[offset : offset + len(data)] = data
