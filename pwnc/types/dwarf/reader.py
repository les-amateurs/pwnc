"""Low-level DWARF data reader: LEB128, form decoding, cursor over section bytes."""

import struct
from .constants import *

# Pre-compiled struct formats — avoids re-parsing format strings on every call
_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")


class DwarfReader:
    """Cursor-based reader over raw section bytes."""

    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset

    def read_bytes(self, n):
        offset = self.offset
        result = bytes(self.data[offset : offset + n])
        self.offset += n
        return result

    def read_u8(self):
        val = self.data[self.offset]
        self.offset += 1
        return val

    def read_u16(self):
        val = _U16.unpack_from(self.data, self.offset)[0]
        self.offset += 2
        return val

    def read_u32(self):
        val = _U32.unpack_from(self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_u64(self):
        val = _U64.unpack_from(self.data, self.offset)[0]
        self.offset += 8
        return val

    def read_addr(self, addr_size):
        if addr_size == 4:
            return self.read_u32()
        elif addr_size == 8:
            return self.read_u64()
        else:
            raise ValueError(f"unsupported address size: {addr_size}")

    def read_uleb128(self):
        result = 0
        shift = 0
        offset = self.offset
        while True:
            byte = self.data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        self.offset = offset
        return result

    def read_sleb128(self):
        result = 0
        shift = 0
        offset = self.offset
        while True:
            byte = self.data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                if byte & 0x40:
                    result |= -(1 << shift)
                break
        self.offset = offset
        return result

    def read_string(self):
        start = self.offset
        offset = self.offset
        while self.data[offset] != 0:
            offset += 1
        result = bytes(self.data[start : offset])
        self.offset = offset + 1  # skip null terminator
        return result

    def read_strp(self, debug_str):
        """Read a DW_FORM_strp: 4-byte offset into .debug_str."""
        str_offset = self.read_u32()
        return _read_string_at(debug_str, str_offset)

    def read_form(self, form, addr_size, debug_str, cu_offset,
                  debug_line_str=None, implicit_value=None, offset_size=4):
        """Read a value according to its DWARF form.

        Parameters:
            form: DWARF form code
            addr_size: address size in bytes (4 or 8)
            debug_str: .debug_str section bytes
            cu_offset: offset of the compilation unit in .debug_info
            debug_line_str: .debug_line_str section bytes (DWARF5, optional)
            implicit_value: pre-stored value for DW_FORM_implicit_const
            offset_size: DWARF offset size (4 for 32-bit DWARF, 8 for 64-bit)
        """
        if form == DW_FORM_addr:
            return self.read_addr(addr_size)

        elif form == DW_FORM_data1:
            return self.read_u8()
        elif form == DW_FORM_data2:
            return self.read_u16()
        elif form == DW_FORM_data4:
            return self.read_u32()
        elif form == DW_FORM_data8:
            return self.read_u64()

        elif form == DW_FORM_sdata:
            return self.read_sleb128()
        elif form == DW_FORM_udata:
            return self.read_uleb128()

        elif form == DW_FORM_string:
            return self.read_string()
        elif form == DW_FORM_strp:
            return self.read_strp(debug_str)

        elif form == DW_FORM_ref1:
            return cu_offset + self.read_u8()
        elif form == DW_FORM_ref2:
            return cu_offset + self.read_u16()
        elif form == DW_FORM_ref4:
            return cu_offset + self.read_u32()
        elif form == DW_FORM_ref8:
            return cu_offset + self.read_u64()
        elif form == DW_FORM_ref_udata:
            return cu_offset + self.read_uleb128()
        elif form == DW_FORM_ref_addr:
            # In DWARF3+, ref_addr uses the offset size (not address size)
            return self.read_addr(offset_size)

        elif form == DW_FORM_flag:
            return self.read_u8() != 0
        elif form == DW_FORM_flag_present:
            return True  # implicit true, no data consumed

        elif form == DW_FORM_block1:
            length = self.read_u8()
            return self.read_bytes(length)
        elif form == DW_FORM_block2:
            length = self.read_u16()
            return self.read_bytes(length)
        elif form == DW_FORM_block4:
            length = self.read_u32()
            return self.read_bytes(length)
        elif form == DW_FORM_block:
            length = self.read_uleb128()
            return self.read_bytes(length)

        elif form == DW_FORM_exprloc:
            length = self.read_uleb128()
            return self.read_bytes(length)

        elif form == DW_FORM_sec_offset:
            return self.read_addr(offset_size)

        elif form == DW_FORM_indirect:
            actual_form = self.read_uleb128()
            return self.read_form(actual_form, addr_size, debug_str, cu_offset,
                                  debug_line_str, implicit_value, offset_size)

        elif form == DW_FORM_ref_sig8:
            return self.read_u64()

        # DWARF5 forms
        elif form == DW_FORM_implicit_const:
            return implicit_value  # value stored in abbreviation table, no data consumed

        elif form == DW_FORM_line_strp:
            str_offset = self.read_u32()
            if debug_line_str is not None:
                return _read_string_at(debug_line_str, str_offset)
            return f"<line_strp@0x{str_offset:x}>"

        elif form == DW_FORM_addrx:
            return self.read_uleb128()  # index into .debug_addr; return raw index

        elif form == DW_FORM_strx:
            return self.read_uleb128()  # index into string offset table; return raw index

        elif form == DW_FORM_strx1:
            return self.read_u8()

        elif form == DW_FORM_strx2:
            return self.read_u16()

        elif form == DW_FORM_strx3:
            b = self.read_bytes(3)
            return b[0] | (b[1] << 8) | (b[2] << 16)

        elif form == DW_FORM_strx4:
            return self.read_u32()

        elif form == DW_FORM_data16:
            return self.read_bytes(16)

        elif form == DW_FORM_loclistx:
            return self.read_uleb128()  # index into .debug_loclists

        elif form == DW_FORM_rnglistx:
            return self.read_uleb128()  # index into .debug_rnglists

        elif form == DW_FORM_ref_sup4:
            return self.read_u32()

        else:
            raise ValueError(f"unsupported DWARF form: 0x{form:02x}")


    def skip_form(self, form, addr_size, offset_size=4):
        """Advance the cursor past a form value without constructing a Python object."""
        o = self.offset
        d = self.data

        if form == DW_FORM_addr:
            self.offset = o + addr_size
        elif form in (DW_FORM_data1, DW_FORM_ref1, DW_FORM_flag,
                      DW_FORM_strx1):
            self.offset = o + 1
        elif form in (DW_FORM_data2, DW_FORM_ref2, DW_FORM_strx2):
            self.offset = o + 2
        elif form in (DW_FORM_data4, DW_FORM_ref4, DW_FORM_strp,
                      DW_FORM_line_strp, DW_FORM_strx4, DW_FORM_ref_sup4):
            self.offset = o + 4
        elif form in (DW_FORM_data8, DW_FORM_ref8, DW_FORM_ref_sig8):
            self.offset = o + 8
        elif form == DW_FORM_data16:
            self.offset = o + 16
        elif form == DW_FORM_sec_offset:
            self.offset = o + offset_size
        elif form == DW_FORM_ref_addr:
            self.offset = o + offset_size
        elif form in (DW_FORM_flag_present, DW_FORM_implicit_const):
            pass  # zero bytes consumed
        elif form in (DW_FORM_udata, DW_FORM_sdata, DW_FORM_ref_udata,
                      DW_FORM_strx, DW_FORM_addrx, DW_FORM_loclistx,
                      DW_FORM_rnglistx):
            # skip ULEB128/SLEB128
            while d[self.offset] & 0x80:
                self.offset += 1
            self.offset += 1
        elif form == DW_FORM_string:
            while d[self.offset] != 0:
                self.offset += 1
            self.offset += 1  # null terminator
        elif form == DW_FORM_exprloc or form == DW_FORM_block:
            length = self.read_uleb128()
            self.offset += length
        elif form == DW_FORM_block1:
            self.offset += 1 + d[o]
        elif form == DW_FORM_block2:
            self.offset = o + 2 + _U16.unpack_from(d, o)[0]
        elif form == DW_FORM_block4:
            self.offset = o + 4 + _U32.unpack_from(d, o)[0]
        elif form == DW_FORM_strx3:
            self.offset = o + 3
        elif form == DW_FORM_indirect:
            actual_form = self.read_uleb128()
            self.skip_form(actual_form, addr_size, offset_size)
        else:
            raise ValueError(f"skip_form: unsupported form 0x{form:02x}")


def _read_string_at(debug_str, offset):
    """Read a null-terminated string from .debug_str at the given offset."""
    start = offset
    while debug_str[offset] != 0:
        offset += 1
    return bytes(debug_str[start:offset])
