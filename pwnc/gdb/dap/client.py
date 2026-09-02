"""Client-side glue between the DAP transport and pwnc.types.

`DapBytesProvider` adapts native DAP ``readMemory``/``writeMemory`` to the
`pwnc.types.BytesProvider` interface, so a reconstructed `pwnc.types.Value`
reads/writes live target memory and follows pointers (via ``rebase``) over the
DAP channel.
"""

import base64

from pwnc.types.provider import BytesProvider


_DEFAULT_TIMEOUT = object()


class DapBytesProvider(BytesProvider):
    """A BytesProvider backed by DAP readMemory/writeMemory."""

    def __init__(
        self,
        transport,
        base_addr,
        byteorder,
        ptrbits=64,
        *,
        timeout=_DEFAULT_TIMEOUT,
        on_write=None,
    ):
        self._t = transport
        self._base = base_addr
        self.byteorder = byteorder
        self.ptrbits = ptrbits
        self._timeout = timeout
        self._on_write = on_write

    def _request(self, command, arguments):
        if self._timeout is _DEFAULT_TIMEOUT:
            return self._t.request(command, arguments)
        return self._t.request(command, arguments, timeout=self._timeout)

    def read(self, offset, size):
        if size == 0:
            return b""
        addr = self._base + offset
        body = self._request(
            "readMemory",
            {"memoryReference": hex(addr), "count": size},
        )
        data = base64.b64decode(body.get("data", "")) if body else b""
        if len(data) < size:
            raise IOError("short read at %#x: got %d/%d bytes (unreadable memory)"
                          % (addr, len(data), size))
        return data[:size]

    def write(self, offset, data):
        addr = self._base + offset
        raw = bytes(data)
        body = self._request(
            "writeMemory",
            {
                "memoryReference": hex(addr),
                "data": base64.b64encode(raw).decode("ascii"),
            },
        )
        written = body.get("bytesWritten") if body else None
        if written is not None and written != len(raw):
            raise IOError(
                "short write at %#x: wrote %d/%d bytes"
                % (addr, written, len(raw))
            )
        if self._on_write is not None:
            self._on_write(addr, raw)

    def rebase(self, addr):
        return DapBytesProvider(
            self._t,
            addr,
            self.byteorder,
            self.ptrbits,
            timeout=self._timeout,
            on_write=self._on_write,
        )

    @property
    def address(self):
        return self._base
