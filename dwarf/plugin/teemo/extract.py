from calendar import c
from binaryninja import (
    ArrayType,
    EnumerationType,
    FunctionType,
    IntegerType,
    NamedTypeReferenceClass,
    NamedTypeReferenceType,
    PointerType,
    QualifiedName,
    Type,
    StructureVariant,
    TypeClass,
    BinaryView,
    StructureType
)
from collections import ChainMap
from pathlib import Path
import json
import builtins

import binaryninja

def escape(name: QualifiedName):
    return "::".join(name.name)

# Since this is used to differentiate between types
# using strings as keys is non optimal because we cannot
# guarantee there will be no collisions.
# (although unlikely since such names are probably
# engineered specifically to break this).
def extract_typename(type: Type | None, name: str | QualifiedName | None = None):
    if type is None:
        return ""

    if name is not None and builtins.type(name) == QualifiedName:
            name = escape(name)

    match type.type_class.value:
        case TypeClass.IntegerTypeClass.value:
            return name or type.get_string()
        case TypeClass.StructureTypeClass.value:
            assert isinstance(type, StructureType)

            if type.registered_name is None:
                name = None
            else:
                name = escape(type.registered_name.name)

            match type.type.value:
                case StructureVariant.StructStructureType.value:
                    return name
                case StructureVariant.UnionStructureType.value:
                    return name
                case StructureVariant.ClassStructureType.value:
                    return name
                case _:
                    raise NotImplementedError(f"unknown structure type: {type.type}")
        case TypeClass.PointerTypeClass.value:
            return name or type.get_string()
        case TypeClass.NamedTypeReferenceClass.value:
            # print(type)
            if name is not None:
                return name
            return escape(type.name)
        case TypeClass.EnumerationTypeClass.value:
            # anonymous enum
            if type.registered_name is None:
                return None
            return escape(type.registered_name.name)
        case TypeClass.FunctionTypeClass.value:
            return type.get_string()
        case TypeClass.ArrayTypeClass.value:
            assert isinstance(type, ArrayType)

            return f"{extract_typename(type.element_type)}[{type.count}]"
        case TypeClass.VoidTypeClass.value:
            return ""
        case TypeClass.FloatTypeClass.value:
            return type.get_string()
        case TypeClass.BoolTypeClass.value:
            return type.get_string()
        case _:
            raise NotImplementedError(f"unhandled: {name} {builtins.type(type)}")

class TypeCollection:
    def __init__(self, bv: BinaryView):
        self.bv = bv

        self.structs = {}
        self.unions = {}

        self.enums = {}
        self.integers = {}
        self.floats = {}

        self.typedefs = {}
        self.pointers = {}

        self.prototypes = {}
        self.functions = {}

        self.arrays = {}
        self.variables = {}

        self.anonymous = 0

        self.all = ChainMap(
            self.structs,
            self.unions,
            self.enums,
            self.integers,
            self.floats,
            self.typedefs,
            self.pointers,
            self.prototypes,
            self.functions,
            self.arrays,
            self.variables
        )

    def dump(self, tmp: Path):
        entries = ["structs", "unions", "enums", "integers", "floats", "typedefs", "pointers", "prototypes", "functions", "arrays", "variables"]
        for entry in entries:
            with open(tmp / f"{entry}.json", "w+") as fp:
                json.dump(getattr(self, entry), fp)

    def forget(self, type: Type, name: str | None = None):
        key = extract_typename(type, name)
        if key in self.all:
            del self.all[key]

    def visit(self, type: Type, name: QualifiedName | str | None = None):
        if name is not None and builtins.type(name) == QualifiedName:
            name = escape(name)

        is_anonymous_type = False
        key = extract_typename(type, name)
        if key is None:
            key = f"anon.{self.anonymous}"
            self.anonymous += 1
            is_anonymous_type = True

        if key in self.all or not key:
            return key

        match type.type_class.value:
            case TypeClass.IntegerTypeClass.value:
                assert isinstance(type, IntegerType)

                self.integers[key] = {}
                self.integers[key]["size"] = len(type)
                self.integers[key]["signed"] = type.signed.value
            case TypeClass.StructureTypeClass.value:
                assert isinstance(type, StructureType)

                match type.type.value:
                    case StructureVariant.StructStructureType.value:
                        target = self.structs
                    case StructureVariant.UnionStructureType.value:
                        target = self.unions
                    case StructureVariant.ClassStructureType.value:
                        target = self.structs
                target[key] = {}
                target[key]["size"] = len(type)
                target[key]["anon"] = is_anonymous_type
                # print(type)
                target[key]["fields"] = [(field.offset, field.name, self.visit(field.type, field.name)) for field in type.members]
            case TypeClass.PointerTypeClass.value:
                assert isinstance(type, PointerType)

                self.pointers[key] = {}
                self.pointers[key]["size"] = len(type)
                self.pointers[key]["target"] = self.visit(type.target)
            case TypeClass.NamedTypeReferenceClass.value:
                assert isinstance(type, NamedTypeReferenceType)
                target = type.target(self.bv)

                if type.named_type_class != NamedTypeReferenceClass.TypedefNamedTypeClass:
                    return self.visit(target)

                # if target is None:
                #     print(builtins.type(name))
                #     if type.name is None or escape(type.name) == name:
                #         raise RuntimeError()
                #         # print(type)
                #         return key
                #     # print(type, type.name)
                #     target = self.bv.get_type_by_name(type.name)
                targetkey = self.visit(target)

                # print(type, "+", type.type_class, "+", key, "+", targetkey, "+", type.target(self.bv))
                # print(builtins.type(key))
                self.typedefs[key] = {}
                self.typedefs[key]["target"] = targetkey
            case TypeClass.EnumerationTypeClass.value:
                assert isinstance(type, EnumerationType)

                self.enums[key] = {}
                self.enums[key]["size"] = len(type)
                self.enums[key]["signed"] = type.signed.value
                fields = [[field.name, field.value] for field in type.members]
                base = 0
                for i, field in enumerate(type.members):
                    if field.value is None:
                        fields[i][1] = base
                        base += 1
                    else:
                        base = field.value
                self.enums[key]["fields"] = fields
            case TypeClass.FunctionTypeClass.value:
                assert isinstance(type, FunctionType)

                self.prototypes[key] = {}
                self.prototypes[key]["parameters"] = [(p.name, self.visit(p.type)) for p in type.parameters]
                self.prototypes[key]["ellipsis"] = type.has_variable_arguments.value
                self.prototypes[key]["returntype"] =self. visit(type.return_value)
            case TypeClass.ArrayTypeClass.value:
                assert isinstance(type, ArrayType)

                self.arrays[key] = {}
                self.arrays[key]["count"] = type.count
                self.arrays[key]["target"] = self.visit(type.element_type)
            case TypeClass.VoidTypeClass.value:
                pass
            case TypeClass.FloatTypeClass.value:
                self.floats[key] = {}
                self.floats[key]["size"] = len(type)
            case TypeClass.BoolTypeClass.value:
                self.integers[key] = {}
                self.integers[key]["size"] = len(type)
                self.integers[key]["signed"] = False
            case _:
                raise NotImplementedError(f"unknown type: {type}, name: {name}")

        return key
