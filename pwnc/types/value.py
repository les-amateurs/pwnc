import struct as _struct
from .provider import BufferProvider, ByteOrder
from .primitives import Int, Bits, Float, Double, Ptr
from .containers import Struct, Union, Array, Enum

class Value:
    def __init__(self, type, provider, base_offset):
        object.__setattr__(self, "_type", type)
        object.__setattr__(self, "_provider", provider)
        object.__setattr__(self, "_base_offset", base_offset)

    @property
    def type(self):
        return self._type
    
    @type.setter
    def type(self, value):
        self._type = value

    @property
    def address(self):
        return self._provider.address + self._base_offset

    @property
    def offset(self):
        return self._base_offset

    @property
    def nbytes(self):
        return self._type.nbytes

    @property
    def nbits(self):
        return self._type.nbits

    @property
    def bytes(self):
        return self._provider.read(self._base_offset, self._type.nbytes)

    @bytes.setter
    def bytes(self, data):
        if len(data) != self._type.nbytes:
            raise ValueError(f"expected {self._type.nbytes} bytes, got {len(data)}")
        self._provider.write(self._base_offset, bytes(data))

    def use(self, data):
        return self._type.use(data)

    def detach(self):
        raw = self._provider.read(self._base_offset, self._type.nbytes)
        new_provider = BufferProvider(bytearray(raw), self._provider.byteorder)
        return Value(self._type, new_provider, 0)

    def cast(self, target):
        if isinstance(target, Value):
            target = target._type
        return type(self)(target, self._provider, self._base_offset)

    def ref(self):
        ptrbits = self._provider.ptrbits
        addr = self.address
        bo = self._provider.byteorder
        byte_order = "little" if bo == ByteOrder.Little else "big"
        data = addr.to_bytes(ptrbits // 8, byte_order)
        buf = BufferProvider(bytearray(data), bo, ptrbits)
        return RefValue(self._type, buf, 0, self._provider)

    def _resolve(self):
        """Resolve this value to a Python object (int, float, etc.)."""

        ty = self._type

        if isinstance(ty, Bits):
            # Need to find the bit position within the containing struct
            # Bits fields are read as part of the byte at base_offset
            # The bit_offset is tracked by the parent Value access
            raw = self._provider.read(self._base_offset, 1)
            byte_val = raw[0]
            # bit_offset is stored on the Value when created from struct access
            bit_off = getattr(self, '_bit_offset', 0)
            mask = (1 << ty.nbits) - 1
            return (byte_val >> bit_off) & mask

        if isinstance(ty, (Int, Ptr)):
            raw = self._provider.read(self._base_offset, ty.nbytes)
            bo = "little" if self._provider.byteorder == ByteOrder.Little else "big"
            val = int.from_bytes(raw, bo)
            if isinstance(ty, Int) and ty.signed:
                # sign extend
                if val >= (1 << (ty.nbits - 1)):
                    val -= (1 << ty.nbits)
            return val

        if isinstance(ty, Float):
            raw = self._provider.read(self._base_offset, 4)
            fmt = "<f" if self._provider.byteorder == ByteOrder.Little else ">f"
            return _struct.unpack(fmt, raw)[0]

        if isinstance(ty, Double):
            raw = self._provider.read(self._base_offset, 8)
            fmt = "<d" if self._provider.byteorder == ByteOrder.Little else ">d"
            return _struct.unpack(fmt, raw)[0]

        if isinstance(ty, Enum):
            # resolve the underlying integer
            inner_val = Value(ty.child, self._provider, self._base_offset)._resolve()
            return inner_val

        # containers return self (not resolved to a primitive)
        return self

    def _write(self, ty, offset, value):
        """Write a Python value to the provider at the given offset."""

        if isinstance(value, Value):
            value = value._resolve()

        if isinstance(ty, Enum):
            ty = ty.child

        bo = self._provider.byteorder

        if isinstance(ty, Bits):
            bit_off = getattr(self, '_bit_offset', 0)
            mask = (1 << ty.nbits) - 1
            raw = bytearray(self._provider.read(offset, 1))
            raw[0] = (raw[0] & ~(mask << bit_off)) | ((value & mask) << bit_off)
            self._provider.write(offset, bytes(raw))
        elif isinstance(ty, (Int, Ptr)):
            byte_order = "little" if bo == ByteOrder.Little else "big"
            if isinstance(ty, Int) and ty.signed and value < 0:
                value = value + (1 << ty.nbits)
            data = value.to_bytes(ty.nbytes, byte_order)
            self._provider.write(offset, data)
        elif isinstance(ty, Float):
            fmt = "<f" if bo == ByteOrder.Little else ">f"
            self._provider.write(offset, _struct.pack(fmt, value))
        elif isinstance(ty, Double):
            fmt = "<d" if bo == ByteOrder.Little else ">d"
            self._provider.write(offset, _struct.pack(fmt, value))
        else:
            raise TypeError(f"cannot write to field of type {type(ty).__name__}")

    def __setattr__(self, name, value):
        for cls in type(self).__mro__:
            if name in cls.__dict__:
                desc = cls.__dict__[name]
                if isinstance(desc, property) and desc.fset is not None:
                    desc.fset(self, value)
                    return
                break

        ty = self._type
        if not isinstance(ty, (Struct, Union)):
            raise AttributeError(f"cannot set fields on {type(ty).__name__} value")

        # Use __getitem__ on the type to get the BoundField (bypasses
        # Struct attribute priority, works for all field names)
        bf = ty[name]
        field_offset = self._base_offset + bf.offset
        field_type = bf._type

        if isinstance(field_type, Bits):
            child_val = Value(field_type, self._provider, field_offset)
            object.__setattr__(child_val, '_bit_offset', bf.bit_offset if bf.bit_offset is not None else 0)
            child_val._write(field_type, field_offset, value)
        elif isinstance(field_type, (Int, Float, Double, Ptr, Enum)):
            self._write(field_type, field_offset, value)
        else:
            raise TypeError(
                f"cannot assign to field '{name}' of type "
                f"{type(field_type).__name__}; only primitive fields are writable"
            )

    def __getattr__(self, name):
        ty = self._type

        if isinstance(ty, (Struct, Union)):
            bf = getattr(ty, name)  # returns BoundField
            new_offset = self._base_offset + bf.offset

            # if child is a primitive or pointer, return a typed value
            if isinstance(bf._type, (Int, Float, Double, Enum, Ptr)):
                return _typed_value(bf._type, self._provider, new_offset,
                                    bf.bit_offset if isinstance(bf._type, Bits) else None)

            # if child is Array, return a ArrayValue
            if isinstance(bf._type, Array):
                return ArrayValue(bf._type, self._provider, new_offset)

            # containers return Value (lazy)
            return type(self)(bf._type, self._provider, new_offset)

        raise AttributeError(f"Value has no attribute '{name}'")

    def __getitem__(self, index):
        if isinstance(index, str):
            return self.__getattr__(index)
        if isinstance(self._type, Ptr):
            if self._type.child is None:
                raise TypeError("cannot dereference void pointer")
            addr = self._resolve()
            child = self._type.child
            target_addr = addr + index * child.nbytes
            new_provider = self._provider.rebase(target_addr)
            if isinstance(child, (Int, Float, Double, Enum, Ptr)):
                return _typed_value(child, new_provider, 0)
            if isinstance(child, Array):
                return ArrayValue(child, new_provider, 0)
            return Value(child, new_provider, 0)
        if isinstance(self._type, Array):
            return ArrayValue(self._type, self._provider, self._base_offset)[index]
        raise TypeError(f"Value of type {type(self._type).__name__} is not subscriptable")

    def __setitem__(self, index, value):
        if isinstance(index, str):
            return self.__setattr__(index, value)
        if isinstance(self._type, Ptr):
            if self._type.child is None:
                raise TypeError("cannot dereference void pointer")
            addr = self._resolve()
            child = self._type.child
            target_addr = addr + index * child.nbytes
            new_provider = self._provider.rebase(target_addr)
            child_val = Value(child, new_provider, 0)
            child_val._write(child, 0, value)
            return
        if isinstance(self._type, Array):
            ArrayValue(self._type, self._provider, self._base_offset)[index] = value
            return
        raise TypeError(f"Value of type {type(self._type).__name__} does not support item assignment")

    def display(self, depth=None, filter=None):
        from .display import format_value
        return format_value(self, depth=depth, filter=filter)

    def __str__(self):
        ty = self._type
        if isinstance(ty, (Int, Float, Double, Ptr)):
            val = self._resolve()
            if isinstance(ty, Ptr):
                return f"0x{val:x}"
            return str(val)

        if isinstance(ty, Enum):
            val = self._resolve()
            name = ty._reverse.get(val)
            if name:
                return f"{name} ({val})"
            return str(val)

        if isinstance(ty, Array):
            return str(ArrayValue(ty, self._provider, self._base_offset))

        return self.display()

    def __repr__(self):
        return self.__str__()

    def __int__(self):
        return self._resolve()

    def __float__(self):
        return float(self._resolve())

    # --- Arithmetic helpers ---

    def _to_python(self):
        val = self._resolve()
        if val is self:
            raise TypeError(f"cannot perform arithmetic on {type(self._type).__name__} value")
        return val

    @staticmethod
    def _other_val(other):
        if isinstance(other, Value):
            return other._to_python()
        return other

    # --- Comparison operators ---

    def __eq__(self, other):
        try:
            return self._to_python() == self._other_val(other)
        except TypeError:
            return NotImplemented

    def __ne__(self, other):
        try:
            return self._to_python() != self._other_val(other)
        except TypeError:
            return NotImplemented

    def __lt__(self, other):
        try:
            return self._to_python() < self._other_val(other)
        except TypeError:
            return NotImplemented

    def __le__(self, other):
        try:
            return self._to_python() <= self._other_val(other)
        except TypeError:
            return NotImplemented

    def __gt__(self, other):
        try:
            return self._to_python() > self._other_val(other)
        except TypeError:
            return NotImplemented

    def __ge__(self, other):
        try:
            return self._to_python() >= self._other_val(other)
        except TypeError:
            return NotImplemented

    def __bool__(self):
        return bool(self._to_python())


class ArrayValue(Value):
    def __init__(self, type, provider, base_offset):
        super().__init__(type, provider, base_offset)

    def __getitem__(self, index):
        child = self._type.child
        elem_offset = self._base_offset + index * child.nbytes

        if isinstance(child, (Int, Float, Double, Enum, Ptr)):
            return _typed_value(child, self._provider, elem_offset)

        return Value(child, self._provider, elem_offset)

    def __setitem__(self, index, value):
        child = self._type.child
        elem_offset = self._base_offset + index * child.nbytes
        elem_val = Value(child, self._provider, elem_offset)
        elem_val._write(child, elem_offset, value)

    def __len__(self):
        return self._type.count

    def __str__(self):
        ty = self._type
        if ty.count == 0:
            return "[]"

        max_show = 8
        items = []
        for i in range(min(ty.count, max_show)):
            items.append(str(self[i]))

        if ty.count > max_show:
            return "[" + ", ".join(items[:-1]) + ", ...]"
        return "[" + ", ".join(items) + "]"


class RefValue(Value):
    def __init__(self, type, provider, base_offset, orig_provider):
        type = Ptr(type, bits=provider.ptrbits)
        super().__init__(type, provider, base_offset)
        object.__setattr__(self, '_orig_provider', orig_provider)

    def cast(self, target):
        if isinstance(target, Value):
            target = target._type
        return RefValue(target, self._provider, self._base_offset,
                        self._orig_provider)

    @property
    def val(self):
        return self._resolve()

    def _wrap(self, raw):
        val = int(raw) & ((1 << self._type.nbits) - 1)
        bo = self._provider.byteorder
        byte_order = "little" if bo == ByteOrder.Little else "big"
        data = val.to_bytes(self._type.nbytes, byte_order)
        buf = BufferProvider(bytearray(data), bo, self._provider.ptrbits)
        return RefValue(self._type.child, buf, 0, self._orig_provider)

    def __getitem__(self, index):
        child = self._type.child
        if child is None:
            raise TypeError("cannot dereference void pointer")
        target_addr = self._resolve() + index * child.nbytes
        new_provider = self._orig_provider.rebase(target_addr)
        if isinstance(child, (Int, Float, Double, Enum, Ptr)):
            return _typed_value(child, new_provider, 0)
        if isinstance(child, Array):
            return ArrayValue(child, new_provider, 0)
        return Value(child, new_provider, 0)

    def __setitem__(self, index, value):
        child = self._type.child
        if child is None:
            raise TypeError("cannot dereference void pointer")
        target_addr = self._resolve() + index * child.nbytes
        new_provider = self._orig_provider.rebase(target_addr)
        child_val = Value(child, new_provider, 0)
        child_val._write(child, 0, value)

    def __neg__(self):    return self._wrap(-self.val)
    def __pos__(self):    return self._wrap(self.val)
    def __invert__(self): return self._wrap(~self.val)
    def __abs__(self):    return self._wrap(abs(self.val))


# ══════════════════════════════════════════════════════════════════
#  Operator helpers for typed Value subclasses
# ══════════════════════════════════════════════════════════════════

import operator

_COMMON_OPS = [
    ('add', operator.add), ('sub', operator.sub), ('mul', operator.mul),
    ('truediv', operator.truediv), ('floordiv', operator.floordiv),
    ('mod', operator.mod), ('pow', operator.pow),
]
_BITWISE_OPS = [
    ('and', operator.and_), ('or', operator.or_), ('xor', operator.xor),
    ('lshift', operator.lshift), ('rshift', operator.rshift),
]


def _make_forward(op):
    def method(self, other):
        return self._wrap(op(self.val, self._other_val(other)))
    return method


def _make_reverse(op):
    def method(self, other):
        return self._wrap(op(self._other_val(other), self.val))
    return method


def _make_inplace(op):
    def method(self, other):
        wrapped = self._wrap(op(self.val, self._other_val(other)))
        self._write(self._type, self._base_offset, wrapped.val)
        return self
    return method


def _install_ops(cls, ops):
    for name, op in ops:
        setattr(cls, f'__{name}__', _make_forward(op))
        setattr(cls, f'__r{name}__', _make_reverse(op))
        setattr(cls, f'__i{name}__', _make_inplace(op))


# ══════════════════════════════════════════════════════════════════
#  Typed Value subclasses
# ══════════════════════════════════════════════════════════════════


class IntValue(Value):
    @property
    def val(self):
        return self._resolve()

    def _wrap(self, raw):
        val = int(raw)
        nbits = self._type.nbits
        mask = (1 << nbits) - 1
        val &= mask
        if self._type.signed and val >= (1 << (nbits - 1)):
            val -= (1 << nbits)
        return self._make_detached(val)

    def _make_detached(self, val):
        ty = self._type
        bo = self._provider.byteorder
        byte_order = "little" if bo == ByteOrder.Little else "big"
        if ty.signed and val < 0:
            val = val + (1 << ty.nbits)
        data = val.to_bytes(ty.nbytes, byte_order)
        return IntValue(ty, BufferProvider(bytearray(data), bo), 0)

    def __neg__(self):
        return self._wrap(-self.val)

    def __pos__(self):
        return self._wrap(self.val)

    def __invert__(self):
        return self._wrap(~self.val)

    def __abs__(self):
        return self._wrap(abs(self.val))


class FloatValue(Value):
    @property
    def val(self):
        return self._resolve()

    def _wrap(self, raw):
        return self._make_detached(float(raw))

    def _make_detached(self, val):
        bo = self._provider.byteorder
        fmt = "<f" if bo == ByteOrder.Little else ">f"
        data = _struct.pack(fmt, val)
        return FloatValue(self._type, BufferProvider(bytearray(data), bo), 0)

    def __neg__(self):
        return self._wrap(-self.val)

    def __pos__(self):
        return self._wrap(self.val)

    def __abs__(self):
        return self._wrap(abs(self.val))


class DoubleValue(Value):
    @property
    def val(self):
        return self._resolve()

    def _wrap(self, raw):
        return self._make_detached(float(raw))

    def _make_detached(self, val):
        bo = self._provider.byteorder
        fmt = "<d" if bo == ByteOrder.Little else ">d"
        data = _struct.pack(fmt, val)
        return DoubleValue(self._type, BufferProvider(bytearray(data), bo), 0)

    def __neg__(self):
        return self._wrap(-self.val)

    def __pos__(self):
        return self._wrap(self.val)

    def __abs__(self):
        return self._wrap(abs(self.val))


class EnumValue(Value):
    @property
    def val(self):
        return self._resolve()

    def _wrap(self, raw):
        val = int(raw)
        child = self._type.child
        nbits = child.nbits
        mask = (1 << nbits) - 1
        val &= mask
        if child.signed and val >= (1 << (nbits - 1)):
            val -= (1 << nbits)
        return self._make_detached(val)

    def _make_detached(self, val):
        child = self._type.child
        bo = self._provider.byteorder
        byte_order = "little" if bo == ByteOrder.Little else "big"
        if child.signed and val < 0:
            val = val + (1 << child.nbits)
        data = val.to_bytes(child.nbytes, byte_order)
        return EnumValue(self._type, BufferProvider(bytearray(data), bo), 0)

    def __neg__(self):
        return self._wrap(-self.val)

    def __pos__(self):
        return self._wrap(self.val)

    def __invert__(self):
        return self._wrap(~self.val)

    def __abs__(self):
        return self._wrap(abs(self.val))


_install_ops(IntValue, _COMMON_OPS + _BITWISE_OPS)
_install_ops(FloatValue, _COMMON_OPS)
_install_ops(DoubleValue, _COMMON_OPS)
_install_ops(EnumValue, _COMMON_OPS + _BITWISE_OPS)
_install_ops(RefValue, _COMMON_OPS + _BITWISE_OPS)


def _ref_add(self, other):
    n = self._other_val(other)
    child = self._type.child
    stride = child.nbytes if child is not None else 1
    return self._wrap(self.val + n * stride)

def _ref_radd(self, other):
    return _ref_add(self, other)

def _ref_iadd(self, other):
    n = self._other_val(other)
    child = self._type.child
    stride = child.nbytes if child is not None else 1
    wrapped = self._wrap(self.val + n * stride)
    self._write(self._type, self._base_offset, wrapped.val)
    return self

def _ref_sub(self, other):
    if isinstance(other, RefValue):
        child = self._type.child
        stride = child.nbytes if child is not None and child.nbytes != 0 else 1
        return (self.val - other.val) // stride
    n = self._other_val(other)
    child = self._type.child
    stride = child.nbytes if child is not None else 1
    return self._wrap(self.val - n * stride)

def _ref_rsub(self, other):
    return self._other_val(other) - self.val

def _ref_isub(self, other):
    n = self._other_val(other)
    child = self._type.child
    stride = child.nbytes if child is not None else 1
    wrapped = self._wrap(self.val - n * stride)
    self._write(self._type, self._base_offset, wrapped.val)
    return self

RefValue.__add__ = _ref_add
RefValue.__radd__ = _ref_radd
RefValue.__iadd__ = _ref_iadd
RefValue.__sub__ = _ref_sub
RefValue.__rsub__ = _ref_rsub
RefValue.__isub__ = _ref_isub


def _typed_value(ty, provider, offset, bit_offset=None):
    if isinstance(ty, Ptr):
        return RefValue(ty.child, provider, offset, provider)
    if isinstance(ty, Enum):
        return EnumValue(ty, provider, offset)
    if isinstance(ty, Float):
        return FloatValue(ty, provider, offset)
    if isinstance(ty, Double):
        return DoubleValue(ty, provider, offset)
    iv = IntValue(ty, provider, offset)
    if isinstance(ty, Bits) and bit_offset is not None:
        object.__setattr__(iv, '_bit_offset', bit_offset)
    return iv
