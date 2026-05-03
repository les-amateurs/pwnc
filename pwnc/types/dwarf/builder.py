"""Convert DIE tree into pwnc Type objects."""

from .constants import *
from ..primitives import Int, Bits, Float, Double, Ptr
from ..containers import Struct, Union, Array, Enum, Pad


def _s(val):
    """Decode a bytes name to str. Pass through str and None."""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return val


class TypeBuilder:
    """Converts a DIE tree (from a compilation unit) into Type objects.

    Uses a two-phase approach:
    1. Index all DIEs by offset
    2. Build types on demand, resolving references via the index
    """

    _anon_counter = 0

    def __init__(self, addr_size=8):
        self.addr_size = addr_size
        self._types = {}        # die_offset -> Type
        self._die_index = {}    # die_offset -> DIE
        self._names = {}        # name -> Type (for named types)
        self._building = set()  # offsets currently being built (cycle detection)
        self._deferred_ptrs = [] # list of (Ptr, die_offset_of_child) for backpatching

    @classmethod
    def _make_anon_name(cls):
        """Generate a unique name for a top-level anonymous struct/union."""
        cls._anon_counter += 1
        return f"__anon_{cls._anon_counter}"

    def build_cu(self, root_die):
        """Build all types from a compilation unit's root DIE."""
        # Phase 1: index all DIEs by offset
        self._index_dies(root_die)

        # Phase 2: build all type DIEs
        TYPE_TAGS = {
            DW_TAG_base_type, DW_TAG_structure_type, DW_TAG_class_type,
            DW_TAG_union_type, DW_TAG_enumeration_type, DW_TAG_array_type,
            DW_TAG_pointer_type, DW_TAG_reference_type, DW_TAG_rvalue_reference_type,
            DW_TAG_typedef, DW_TAG_const_type, DW_TAG_volatile_type,
            DW_TAG_restrict_type, DW_TAG_subroutine_type, DW_TAG_unspecified_type,
        }

        for die in root_die.children:
            if die.tag in TYPE_TAGS:
                self._build_die(die)

        # Backpatch deferred pointers
        for ptr, child_offset in self._deferred_ptrs:
            if child_offset in self._types:
                ptr.child = self._types[child_offset]

        return dict(self._names)

    def _index_dies(self, die):
        """Recursively index all DIEs by their offset."""
        self._die_index[die.offset] = die
        for child in die.children:
            self._index_dies(child)

    def _build_die(self, die):
        """Build a Type from a DIE, caching by offset."""
        if die.offset in self._types:
            return self._types[die.offset]

        if die.offset in self._building:
            return None

        self._building.add(die.offset)
        ty = self._dispatch_build(die)
        self._building.discard(die.offset)

        if ty is not None:
            self._types[die.offset] = ty
            name = die.attr(DW_AT_name)
            if name is not None and die.tag in (
                DW_TAG_base_type, DW_TAG_structure_type, DW_TAG_class_type,
                DW_TAG_union_type, DW_TAG_enumeration_type,
                DW_TAG_typedef,
            ):
                self._names[name] = ty

        return ty

    def _dispatch_build(self, die):
        tag = die.tag
        if tag == DW_TAG_base_type:
            return self._build_base_type(die)
        elif tag in (DW_TAG_structure_type, DW_TAG_class_type):
            return self._build_structure(die)
        elif tag == DW_TAG_union_type:
            return self._build_union(die)
        elif tag == DW_TAG_enumeration_type:
            return self._build_enum(die)
        elif tag == DW_TAG_array_type:
            return self._build_array(die)
        elif tag in (DW_TAG_pointer_type, DW_TAG_reference_type,
                     DW_TAG_rvalue_reference_type):
            return self._build_pointer(die)
        elif tag == DW_TAG_typedef:
            return self._build_typedef(die)
        elif tag in (DW_TAG_const_type, DW_TAG_volatile_type,
                     DW_TAG_restrict_type):
            return self._build_qualifier(die)
        elif tag == DW_TAG_subroutine_type:
            return None
        elif tag == DW_TAG_unspecified_type:
            return None  # void or similar
        return None

    def _resolve_type_ref(self, die):
        """Resolve DW_AT_type reference to a Type, building it if needed."""
        type_offset = die.attr(DW_AT_type)
        if type_offset is None:
            return None

        if type_offset in self._types:
            return self._types[type_offset]

        ref_die = self._die_index.get(type_offset)
        if ref_die is not None:
            return self._build_die(ref_die)

        return None

    def _build_base_type(self, die):
        encoding = die.attr(DW_AT_encoding)
        byte_size = die.attr(DW_AT_byte_size, 0)
        bit_size = byte_size * 8

        if encoding == DW_ATE_float:
            if byte_size == 4:
                return Float()
            elif byte_size == 8:
                return Double()
            return Int(bit_size, signed=False)

        signed = encoding in (DW_ATE_signed, DW_ATE_signed_char)
        return Int(bit_size, signed=signed)

    def _build_structure(self, die):
        # Forward declaration — skip building
        if die.attr(DW_AT_declaration) and die.attr(DW_AT_byte_size) is None:
            return None

        name = _s(die.attr(DW_AT_name)) or self._make_anon_name()
        byte_size = die.attr(DW_AT_byte_size, 0)

        # Collect all field entries with their DWARF offsets
        layout = []    # (name, type, byte_offset, bit_offset_or_None)
        padding = []   # (offset, size) for padding gaps

        current_end = 0

        for child in die.children:
            if child.tag == DW_TAG_inheritance:
                # C++ base class: flatten base class fields into this struct
                base_type = self._resolve_type_ref(child)
                base_offset = child.attr(DW_AT_data_member_location, 0)
                if base_type is not None and isinstance(base_type, Struct):
                    for inner_name, inner_type, inner_byte_off, inner_bit_off in base_type._layout:
                        adjusted = base_offset + inner_byte_off
                        if adjusted > current_end:
                            padding.append((current_end, adjusted - current_end))
                            current_end = adjusted
                        layout.append((inner_name, inner_type, adjusted, inner_bit_off))
                        if not isinstance(inner_type, Bits):
                            current_end = max(current_end, adjusted + inner_type.nbytes)
                    # Also include base's padding entries
                    for pad_off, pad_size in base_type._padding:
                        padding.append((base_offset + pad_off, pad_size))
                elif base_type is not None and base_offset + base_type.nbytes > current_end:
                    # Non-struct base (unusual): just account for its size
                    current_end = max(current_end, base_offset + base_type.nbytes)
                continue

            if child.tag != DW_TAG_member:
                continue

            # Skip static/constexpr members (DW_AT_declaration or DW_AT_external
            # with DW_AT_const_value, or members without DW_AT_data_member_location
            # in non-union structs)
            if child.attr(DW_AT_declaration):
                continue
            if child.attr(DW_AT_external):
                continue

            member_name = _s(child.attr(DW_AT_name))
            member_type = self._resolve_type_ref(child)
            if member_type is None:
                continue

            member_offset = child.attr(DW_AT_data_member_location, 0)
            bit_size = child.attr(DW_AT_bit_size)

            if member_name is None:
                # Anonymous struct/union: flatten fields into parent
                if isinstance(member_type, Struct):
                    for inner_name, inner_type, inner_byte_off, inner_bit_off in member_type._layout:
                        adjusted = member_offset + inner_byte_off
                        if adjusted > current_end:
                            padding.append((current_end, adjusted - current_end))
                            current_end = adjusted
                        layout.append((inner_name, inner_type, adjusted, inner_bit_off))
                        if not isinstance(inner_type, Bits):
                            current_end = max(current_end, adjusted + inner_type.nbytes)
                elif isinstance(member_type, Union):
                    # All union fields overlap at member_offset
                    if member_offset > current_end:
                        padding.append((current_end, member_offset - current_end))
                    for inner_name, inner_type, _, inner_bit_off in member_type._layout:
                        layout.append((inner_name, inner_type, member_offset, inner_bit_off))
                    current_end = max(current_end, member_offset + member_type.nbytes)
                continue

            if bit_size is not None:
                # Bit field — compute byte offset and bit-within-byte
                member_type = Bits(bit_size)
                bit_offset_attr = child.attr(DW_AT_bit_offset)
                data_bit_offset = child.attr(DW_AT_data_bit_offset)
                storage_size = child.attr(DW_AT_byte_size, 0)

                if data_bit_offset is not None:
                    # DWARF5 style: absolute bit offset from struct start
                    byte_off = data_bit_offset // 8
                    bit_within_byte = data_bit_offset % 8
                elif bit_offset_attr is not None and storage_size > 0:
                    # DWARF4 style: big-endian bit offset from MSB of storage unit
                    # Convert to little-endian bit position from LSB
                    le_bit_pos = (storage_size * 8) - bit_offset_attr - bit_size
                    byte_off = member_offset + (le_bit_pos // 8)
                    bit_within_byte = le_bit_pos % 8
                else:
                    byte_off = member_offset
                    bit_within_byte = 0

                layout.append((member_name, member_type, byte_off, bit_within_byte))
                # Track end position through bitfields
                import math
                bit_end = byte_off * 8 + bit_within_byte + bit_size
                byte_end = math.ceil(bit_end / 8)
                current_end = max(current_end, byte_end)
                continue

            if member_offset > current_end:
                padding.append((current_end, member_offset - current_end))
                current_end = member_offset

            layout.append((member_name, member_type, member_offset, None))
            current_end = member_offset + member_type.nbytes

        # Trailing padding
        if byte_size > current_end:
            padding.append((current_end, byte_size - current_end))

        return Struct._from_layout(name, layout, padding, byte_size)

    def _build_union(self, die):
        if die.attr(DW_AT_declaration) and die.attr(DW_AT_byte_size) is None:
            return None

        name = _s(die.attr(DW_AT_name)) or self._make_anon_name()

        fields = []
        for child in die.children:
            if child.tag != DW_TAG_member:
                continue

            member_name = _s(child.attr(DW_AT_name))
            member_type = self._resolve_type_ref(child)
            if member_type is None or member_name is None:
                continue

            fields.append((member_name, member_type))

        return Union(name, fields)

    def _build_enum(self, die):
        name = _s(die.attr(DW_AT_name))
        byte_size = die.attr(DW_AT_byte_size, 4)
        encoding = die.attr(DW_AT_encoding)

        type_ref = die.attr(DW_AT_type)
        if type_ref is not None:
            child_type = self._resolve_type_ref(die)
            if child_type is None:
                signed = encoding in (DW_ATE_signed, DW_ATE_signed_char) if encoding else False
                child_type = Int(byte_size * 8, signed=signed)
        else:
            signed = encoding in (DW_ATE_signed, DW_ATE_signed_char) if encoding else False
            child_type = Int(byte_size * 8, signed=signed)

        members = {}
        for child in die.children:
            if child.tag != DW_TAG_enumerator:
                continue
            ename = _s(child.attr(DW_AT_name))
            evalue = child.attr(DW_AT_const_value, 0)
            if ename is not None:
                members[ename] = evalue

        return Enum(child_type, members, name=name)

    def _build_array(self, die):
        child_type = self._resolve_type_ref(die)
        if child_type is None:
            child_type = Int(8)

        # Collect all subrange dimensions
        dimensions = []
        for child in die.children:
            if child.tag == DW_TAG_subrange_type:
                upper_bound = child.attr(DW_AT_upper_bound)
                explicit_count = child.attr(DW_AT_count)
                if explicit_count is not None:
                    dimensions.append(explicit_count)
                elif upper_bound is not None:
                    dimensions.append(upper_bound + 1)
                else:
                    dimensions.append(0)  # flexible array

        if not dimensions:
            return Array(child_type, 0)

        # Build nested arrays from innermost to outermost
        # float data[4][4] → Array(Array(float, 4), 4)
        result = child_type
        for dim in reversed(dimensions):
            result = Array(result, dim)
        return result

    def _build_pointer(self, die):
        # Create and cache the pointer BEFORE resolving the child type.
        # This prevents infinite loops when a struct's member pointer type
        # is still in _building while the struct's other members reference it.
        ptr = Ptr(None, self.addr_size * 8)
        self._types[die.offset] = ptr
        self._building.discard(die.offset)

        child_type = self._resolve_type_ref(die)
        if child_type is not None:
            ptr.child = child_type
        else:
            type_offset = die.attr(DW_AT_type)
            if type_offset is not None:
                self._deferred_ptrs.append((ptr, type_offset))
        return ptr

    def _build_typedef(self, die):
        underlying = self._resolve_type_ref(die)
        td_name = _s(die.attr(DW_AT_name))
        if underlying is not None:
            # If the underlying type is an anonymous struct/union (generated name),
            # propagate the typedef name so it displays as e.g.
            # "_IO_lock_t" instead of "__anon_N".
            if td_name and isinstance(underlying, (Struct, Union)):
                if underlying.name.startswith("__anon_"):
                    underlying.name = td_name
            return underlying
        # Opaque typedef (no DW_AT_type) — create a named opaque struct
        # so pointers display as "TypeName*" instead of "u0*"
        if td_name:
            return Struct._from_layout(td_name, [], [], 0)
        return None

    def _build_qualifier(self, die):
        underlying = self._resolve_type_ref(die)
        if underlying is not None:
            return underlying
        return None


def build_types_from_cu(root_die, addr_size=8):
    """Build all types from a compilation unit root DIE."""
    builder = TypeBuilder(addr_size)
    return builder.build_cu(root_die)
