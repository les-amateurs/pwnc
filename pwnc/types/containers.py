from .base import Type, BoundField


class Align:
    def __init__(self, n):
        self.alignment = n


class Pad:
    def __init__(self, n):
        self.size = n


def _align_up(offset, alignment):
    return (offset + alignment - 1) // alignment * alignment


class Struct(Type):
    def __init__(self, name, fields, mode="packed"):
        self.name = name
        self.mode = mode
        self._fields = []       # list of (name, type) tuples for real fields
        self._layout = []       # list of (name, type, byte_offset, bit_offset_or_None)
        self._padding = []      # list of (byte_offset, size) for padding entries
        self._field_map = {}    # name -> index in _layout

        current_byte = 0
        current_bit = 0  # bit offset within current byte (for Bits fields)

        for item in fields:
            if isinstance(item, Align):
                # finish any pending bitfield
                if current_bit != 0:
                    current_byte += 1
                    current_bit = 0
                aligned = _align_up(current_byte, item.alignment)
                if aligned > current_byte:
                    self._padding.append((current_byte, aligned - current_byte))
                    current_byte = aligned
            elif isinstance(item, Pad):
                if current_bit != 0:
                    current_byte += 1
                    current_bit = 0
                self._padding.append((current_byte, item.size))
                current_byte += item.size
            else:
                fname, ftype = item

                self._fields.append((fname, ftype))
                idx = len(self._layout)
                self._layout.append((fname, ftype, current_byte, current_byte * 8 + current_bit))
                self._field_map[fname] = idx
                new_bit = current_bit + ftype.nbits
                current_byte += new_bit >> 3
                current_bit = new_bit & 7

        # close trailing bitfield
        if current_bit != 0:
            current_byte += 1
            current_bit = 0
            
        super().__init__(current_byte * 8)

    @classmethod
    def _from_layout(cls, name, layout, padding, nbytes, mode="packed"):
        """Create a Struct with a pre-built layout (used by DWARF builder)."""
        obj = object.__new__(cls)
        obj.name = name
        obj.mode = mode
        obj._fields = [(f[0], f[1]) for f in layout]
        obj._layout = list(layout)
        obj._padding = list(padding)
        obj._field_map = {f[0]: i for i, f in enumerate(layout)}
        Type.__init__(obj, nbytes * 8)
        return obj

    def _get_field(self, name):
        idx = self._field_map[name]
        fname, ftype, byte_off, bit_off = self._layout[idx]
        return BoundField(ftype, byte_off, bit_off)

    def fields(self):
        """Yield (name, BoundField) pairs in layout order."""
        for fname, ftype, byte_off, bit_off in self._layout:
            yield fname, BoundField(ftype, byte_off, bit_off)

    def __getattr__(self, name):
        try:
            fm = object.__getattribute__(self, "_field_map")
        except AttributeError:
            raise AttributeError(name)
        if name not in fm:
            raise AttributeError(f"struct '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __getitem__(self, name):
        if name not in self._field_map:
            raise KeyError(f"struct '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __str__(self):
        return self.display()

    def __repr__(self):
        return self.__str__()


class Union(Type):
    def __init__(self, name, fields):
        self.name = name
        self._fields = []
        self._layout = []
        self._field_map = {}

        max_size = 0
        for item in fields:
            fname, ftype = item
            self._fields.append((fname, ftype))
            idx = len(self._layout)
            self._layout.append((fname, ftype, 0, None))
            self._field_map[fname] = idx
            if ftype.nbytes > max_size:
                max_size = ftype.nbytes

        super().__init__(max_size * 8)

    def _get_field(self, name):
        idx = self._field_map[name]
        fname, ftype, byte_off, bit_off = self._layout[idx]
        return BoundField(ftype, byte_off, bit_off)

    def fields(self):
        """Yield (name, BoundField) pairs in layout order."""
        for fname, ftype, byte_off, bit_off in self._layout:
            yield fname, BoundField(ftype, byte_off, bit_off)

    def __getattr__(self, name):
        try:
            fm = object.__getattribute__(self, "_field_map")
        except AttributeError:
            raise AttributeError(name)
        if name not in fm:
            raise AttributeError(f"union '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __getitem__(self, name):
        if name not in self._field_map:
            raise KeyError(f"union '{self.name}' has no field '{name}'")
        return self._get_field(name)

    def __str__(self):
        return self.display()

    def __repr__(self):
        return self.__str__()


class Array(Type):
    def __init__(self, child, count):
        self.child = child
        self.count = count
        super().__init__(child.nbits * count)

    def __str__(self):
        if self.count == 0:
            return f"{self.child}[]"
        return f"{self.child}[{self.count}]"

    def __repr__(self):
        return self.__str__()


class Enum(Type):
    def __init__(self, child, members, name=None):
        self.child = child
        self.name = name
        self.members = dict(members)
        self._reverse = {v: k for k, v in self.members.items()}
        super().__init__(child.nbits)

    def __str__(self):
        if self.name:
            return f"enum {self.name} : {self.child}"
        return f"enum : {self.child}"

    def __repr__(self):
        return self.__str__()
