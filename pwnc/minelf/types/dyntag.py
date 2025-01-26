from .util import *

def generate(bits: int, little_endian: bool):
    addrsize = addrsize_from_bits(bits)
    class Dyntag(structure_parent(little_endian)):
        _fields_ = [
            ("tag", addrsize),
            ("val", addrsize),
        ]
    return Dyntag

class Dyntag:
    tag: addr
    val: addr