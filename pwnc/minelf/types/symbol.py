from .util import *

class Type:
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    COMMON = 5
    TLS = 6

def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    if bits == 64:
        fields = [
            ("name", u32),
            ("info", u8),
            ("other", u8),
            ("index", u16),
            ("value", addrsize),
            ("size", addrsize),
        ]
    else:
        fields = [
            ("name", u32),
            ("value", addrsize),
            ("size", u32),
            ("info", u8),
            ("other", u8),
            ("index", u16),
        ]

    class Symbol(structure_parent(little_endian)):
        _fields_ = fields

        Type = Type

        @property
        def type(self):
            return self.info & 0xf
        
        @type.setter
        def type(self, val):
            self.info = (self,info >> 4 << 4) | (val & 0xf)

    return Symbol


class Symbol:
    name: u32
    info: u8
    other: u8
    index: u16
    value: addr
    size: addr
    type: Type