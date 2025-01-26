from .util import *

def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    if bits == 64:
        fields = [
            ("name", u32),
            ("info", u8),
            ("other", u8),
            ("index", u16),
            ("value", addrsize),
            ("size", addrsize)
        ]
    else:
        fields = [
            ("name", u32),
            ("value", addrsize),
            ("size", u32),
            ("info", u8),
            ("other", u8),
            ("index", u16)
        ]

    class Symbol(structure_parent(little_endian)):
        _fields_ = fields
    return Symbol

class Symbol:
    name: u32
    info: u8
    other: u8
    index: u16
    value: addr
    size: addr