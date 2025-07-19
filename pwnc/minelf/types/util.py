import ctypes
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64, c_void_p
from ... import err


def addrsize_from_bits(bits: int):
    match bits:
        case 32:
            return u32
        case 64:
            return u64
        case _:
            err.fatal(f"bad bit length: {bits}")


def structure_parent(little_endian: bool):
    if little_endian:
        return ctypes.LittleEndianStructure
    else:
        return ctypes.BigEndianStructure


u8 = c_uint8
u16 = c_uint16
u32 = c_uint32
u64 = c_uint64
addr = c_void_p
