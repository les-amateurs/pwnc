from .util import *

def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    fields = [
        ("name_size", u32),
        ("description_size", u32),
        ("type", u32),
    ]

    class Note(structure_parent(little_endian)):
        _fields_ = fields

    return Note

class Note:
    name_size: u32
    description_size: u32
    type: u32