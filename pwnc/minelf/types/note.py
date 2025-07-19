from .util import *


def generate(bits: int, little_endian: bool):
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
