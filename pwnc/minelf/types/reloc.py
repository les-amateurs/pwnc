from .util import *


def generate(bits: int, little_endian: bool, addend: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [
        ("offset", addrsize),
        ("info", addrsize),
    ]

    if addend:
        fields.append(
            (
                "addend",
                addrsize,
            )
        )

    split = 8 if bits == 32 else 32
    mask = (1 << split) - 1

    class Reloc(structure_parent(little_endian)):
        _fields_ = fields

        @property
        def type(self):
            return self.info & mask

        @type.setter
        def type(self, val: int):
            self.info = (self.info & ~mask) | (val & mask)

        @property
        def sym(self):
            return self.info >> split

        @sym.setter
        def sym(self, val: int):
            self.info = (self.info & mask) | (val << split)

    return Reloc


class Reloc:
    offset: addr
    info: addr


class Reloca:
    offset: addr
    info: addr
    addend: addr
