"""Client-side glue between the DAP transport and pwnc.types.

`DapBytesProvider` adapts native DAP ``readMemory``/``writeMemory`` to the
`pwnc.types.BytesProvider` interface, so a reconstructed `pwnc.types.Value`
reads/writes live target memory and follows pointers (via ``rebase``) over the
DAP channel.
"""

import base64

from pwnc.types.provider import BytesProvider


class DapBytesProvider(BytesProvider):
    """A BytesProvider backed by DAP readMemory/writeMemory."""

    def __init__(self, transport, base_addr, byteorder, ptrbits=64):
        self._t = transport
        self._base = base_addr
        self.byteorder = byteorder
        self.ptrbits = ptrbits

    def read(self, offset, size):
        if size == 0:
            return b""
        addr = self._base + offset
        body = self._t.request("readMemory",
                               {"memoryReference": hex(addr), "count": size})
        data = base64.b64decode(body.get("data", "")) if body else b""
        if len(data) < size:
            raise IOError("short read at %#x: got %d/%d bytes (unreadable memory)"
                          % (addr, len(data), size))
        return data[:size]

    def write(self, offset, data):
        addr = self._base + offset
        self._t.request("writeMemory", {
            "memoryReference": hex(addr),
            "data": base64.b64encode(bytes(data)).decode("ascii"),
        })

    def rebase(self, addr):
        return DapBytesProvider(self._t, addr, self.byteorder, self.ptrbits)

    @property
    def address(self):
        return self._base
