from binaryninja import (
    QualifiedName,
    Type,
    StructureVariant,
    TypeClass,
    BinaryView,
)
from collections import ChainMap
from pathlib import Path
import json
import builtins

def escape(name: QualifiedName):
    return name.name[0]

# Since this is used to differentiate between types
# using strings as keys is non optimal because we cannot
# guarantee there will be no collisions.
# (although unlikely since such names are probably
# engineered specifically to break this).
def extract_typename(type: Type, name: str | QualifiedName | None = None):
    if builtins.type(name) == QualifiedName:
        name = escape(name)

    match type.type_class.value:
        case TypeClass.IntegerTypeClass.value:
            return name or type.get_string()
        case TypeClass.StructureTypeClass.value:
            if type.registered_name is None:
                name = None
            else:
                name = escape(type.registered_name.name)
            match type.type.value:
                case StructureVariant.StructStructureType:
                    return name
                case StructureVariant.UnionStructureType:
                    return name
                case _:
                    raise NotImplementedError(f"unknown structure type: {type.type}")
        case TypeClass.PointerTypeClass.value:
            return name or type.get_string()
        case TypeClass.NamedTypeReferenceClass.value:
            return escape(type.name)
        case TypeClass.EnumerationTypeClass.value:
            return escape(type.registered_name.name)
        case TypeClass.FunctionTypeClass.value:
            return type.get_string()
        case TypeClass.ArrayTypeClass.value:
            return f"{extract_typename(type.element_type)}[{type.count}]"
        case TypeClass.VoidTypeClass.value:
            return ""
        case TypeClass.FloatTypeClass.value:
            return type.get_string()
        case _:
            raise NotImplementedError(f"unhandled: {name} {type(type)}")

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
            print(f"dumping {entry}")
            with open(tmp / f"{entry}.json", "w+") as fp:
                json.dump(getattr(self, entry), fp)

    def forget(self, type: Type, name: str | None = None):
        key = extract_typename(type, name)
        if key in self.all:
            del self.all[key]
        
    def visit(self, type: Type, name: str | None = None):
        is_anonymous_type = False
        key = extract_typename(type, name)
        if key is None:
            key = f"anon.{self.anonymous}"
            self.anonymous += 1
            is_anonymous_type = True

        if key in self.all:
            return key
        
        match type.type_class.value:
            case TypeClass.IntegerTypeClass.value:
                self.integers[key] = {}
                self.integers[key]["size"] = len(type)
                self.integers[key]["signed"] = type.signed.value
            case TypeClass.StructureTypeClass.value:
                match type.type.value:
                    case StructureVariant.StructStructureType:
                        target = self.structs
                    case StructureVariant.UnionStructureType:
                        target = self.unions
                    case _:
                        exit(f"unknown structure type")
                target[key] = {}
                target[key]["size"] = len(type)
                target[key]["anon"] = is_anonymous_type
                target[key]["fields"] = list(map(lambda field: (field.offset, field.name, self.visit(field.type)), type.members))
            case TypeClass.PointerTypeClass.value:
                self.pointers[key] = {}
                self.pointers[key]["size"] = len(type)
                self.pointers[key]["target"] = self.visit(type.target)
            case TypeClass.NamedTypeReferenceClass.value:
                target = self.visit(type.target(self.bv))
                # sometimes struct fields generate a random NamedTypeReference ???
                if key == target:
                    return key
                self.typedefs[key] = {}
                self.typedefs[key]["target"] = target
            case TypeClass.EnumerationTypeClass.value:
                self.enums[key] = {}
                self.enums[key]["size"] = len(type)
                self.enums[key]["signed"] = type.signed.value
                self.enums[key]["fields"] = list(map(lambda field: (field.name, field.value), type.members))
            case TypeClass.FunctionTypeClass.value:
                self.prototypes[key] = {}
                self.prototypes[key]["parameters"] = list(map(lambda p: (p.name, self.visit(p.type)), type.parameters))
                self.prototypes[key]["ellipsis"] = type.has_variable_arguments.value
                self.prototypes[key]["returntype"] =self. visit(type.return_value)
            case TypeClass.ArrayTypeClass.value:
                self.arrays[key] = {}
                self.arrays[key]["count"] = type.count
                self.arrays[key]["target"] = self.visit(type.element_type)
            case TypeClass.VoidTypeClass.value:
                pass
            case TypeClass.FloatTypeClass.value:
                self.floats[key] = {}
                self.floats[key]["size"] = len(type)
            case _:
                raise NotImplementedError(f"unknown type: {type}, name: {name}")

        return key