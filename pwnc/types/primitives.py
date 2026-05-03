from .base import Type

class Int(Type):
    def __init__(self, bits, signed=False):
        super().__init__(bits)
        self.signed = signed

    def __str__(self):
        prefix = "i" if self.signed else "u"
        return f"{prefix}{self.nbits}"

    def __repr__(self):
        sign = "signed" if self.signed else "unsigned"
        return f"Int({self.nbits}, {sign})"


class Bits(Int):
    def __init__(self, nbits):
        super().__init__(nbits, signed=False)

    def __str__(self):
        return f"bits({self.nbits})"

    def __repr__(self):
        return f"Bits({self.nbits})"


class Float(Type):
    def __init__(self):
        super().__init__(32)

    def __str__(self):
        return "f32"

    def __repr__(self):
        return "Float()"


class Double(Type):
    def __init__(self):
        super().__init__(64)

    def __str__(self):
        return "f64"

    def __repr__(self):
        return "Double()"


class Ptr(Type):
    def __init__(self, child = None, bits=64):
        super().__init__(bits)
        self.child = child

    def __str__(self):
        if self.child is None:
            return "void*"
        from .containers import Struct, Union
        if isinstance(self.child, Struct):
            return f"struct {self.child.name}*"
        if isinstance(self.child, Union):
            return f"union {self.child.name}*"
        return f"{self.child}*"

    def __repr__(self):
        return self.__str__()
