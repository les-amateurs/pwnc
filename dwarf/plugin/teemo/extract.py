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
    StructureType,
)
from collections import ChainMap
from pathlib import Path
import json
import builtins


"""
Annoying thing about all of this are all the small inconsistencies binja has. For example,
the types contained in the default type libraries sometimes references types that simply do not exist.
(Ex. __dev_t or __ino64_t). Not sure why this happens, might be an artifact of updating an old bndb file.
The workaround for this is to keep track of all keys before a type visiting operation, and in the case of
an error delete all new keys. This is to keep the type dictionary free of any partially resolved types
which might cause issues for the dwarf generation.

The other method to deal with this is to hardcode the definitions of some known types that are sometimes missing.
For example we can manually insert types like uint32_t, uint64_t, etc... into the integers type dictionary.

In the future, it might be possible to provide some sane defaults instead of bailing out of resolving the type.
If a pointer child type cannot be resolved it should be fine to simply assume the child type is void, which
is better than bailing out.

TODO: record the pointer offset for structures. For most structs the pointer offset is 0, but in some special cases
it can possibly be non-zero.
TODO: test the code on c++ classes.
TODO: allow undefined types to exist? Not sure if the dwarf spec allows this but if it is possible to reference
external types then it should be fine to allow undefined types, since the user or some other debug info might
be able to supply the correct type definition.
TODO: add more default integer types.
"""


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
            # return type.get_string()
            return name or type.get_string()
        case TypeClass.StructureTypeClass.value:
            assert isinstance(type, StructureType)

            if type.registered_name is None and name is None:
                # print("warning: type.registered_name and name are None")
                pass
            elif type.registered_name is None and name is not None:
                pass
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
            # return type.get_string()
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
            self.variables,
        )

        FIXED_TYPES = [8, 16, 32, 64, 128, 256, 512]
        for width in FIXED_TYPES:
            name = f"int{width}_t"
            names = [name, f"u{name}"]
            for name in names:
                signed = not name.startswith("u")
                self.integers[name] = {"size": width // 8, "signed": signed}
                self.integers[f"__{name}"] = {"size": width // 8, "signed": signed}

        ELF_PLATFORM_TYPES = [("Addr", 32, False)]
        for name, width, signed in ELF_PLATFORM_TYPES:
            self.integers[f"Elf{32}_{name}"] = {"size": width // 8, "signed": signed}
            self.integers[f"Elf{64}_{name}"] = {"size": width // 4, "signed": signed}

    def dump(self, tmp: Path):
        entries = [
            "structs",
            "unions",
            "enums",
            "integers",
            "floats",
            "typedefs",
            "pointers",
            "prototypes",
            "functions",
            "arrays",
            "variables",
        ]
        for entry in entries:
            with open(tmp / f"{entry}.json", "w+") as fp:
                json.dump(getattr(self, entry), fp)

    def forget(self, type: Type, name: str | None = None):
        key = extract_typename(type, name)
        if key in self.all:
            del self.all[key]

    def visit(self, type: Type, name: QualifiedName | str | None = None):
        orig = set(self.all.keys())
        try:
            return self.visit_internal(type, name)
        except LookupError:
            diff = set(self.all.keys()) ^ orig
            for key in diff:
                for map in self.all.maps:
                    if key in map:
                        map.pop(key)
                        break
            print(f"failed to resolve {type}")

    def visit_internal(self, type: Type, name: QualifiedName | str | None = None):
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
                target[key]["fields"] = [
                    (field.offset, field.name, self.visit_internal(field.type))
                    for field in type.members
                ]

            case TypeClass.PointerTypeClass.value:
                assert isinstance(type, PointerType)

                self.pointers[key] = {}
                self.pointers[key]["size"] = len(type)
                self.pointers[key]["target"] = self.visit_internal(type.target)
            case TypeClass.NamedTypeReferenceClass.value:
                assert isinstance(type, NamedTypeReferenceType)
                target = type.target(self.bv)

                if target is None:
                    containers = [
                        library.type_container for library in self.bv.type_libraries
                    ]
                    for container in containers:
                        target = type.target(container)
                        if target is not None:
                            break

                        target = container.get_type_by_name(type.name)
                        if target is not None:
                            break
                    else:
                        """
                        Sometimes the type target cannot be resolved, but the type exists
                        in our type dictionary.
                        """
                        if type.name in self.all:
                            return type.name

                        """
                        While this may not always be the case, c *really* likes to alias
                        types using a double underscore prefix. This catches some cases
                        where an integer type with the double underscore exists but doesn't
                        exist without the double underscore. Its also not possible to tell
                        if the target type is *actually* an integer type since we failed to
                        resolve the target type...

                        Also ensure the type ends with _t which is common for integer typedefs.
                        """
                        if f"__{type.name}" in self.all and escape(type.name).endswith(
                            "_t"
                        ):
                            return f"__{type.name}"

                        print(type.type_class)
                        print(type.named_type_class)
                        print(type, target, type.children)
                        print(type.name)
                        print()
                        raise LookupError

                if (
                    type.named_type_class
                    != NamedTypeReferenceClass.TypedefNamedTypeClass
                ):
                    if (
                        type.named_type_class
                        == NamedTypeReferenceClass.StructNamedTypeClass
                    ):
                        """
                        Structures are special and need a name to be passed in to resolve properly.
                        For some reason sometimes structures are generated that have no registered_name and no
                        name, but are the target of a StructNamedTypeClass. The enclosing StructNamedTypeClass
                        holds the correct name of the structure, but the subtype is somehow missing this information.
                        """
                        if target.registered_name is None:
                            target_name = type.name
                        else:
                            target_name = None
                        target_key = self.visit_internal(target, target_name)
                        # print(target_key)
                        return target_key
                    else:
                        """
                        Other named type references exist, ClassNamedTypeClass, EnumNamedTypeClass,
                        UnionNamedTypeClass, UnknownNamedTypeClass. Delegate to the target in this case.
                        None of these subclasses need special handling in my testing.
                        """
                        return self.visit_internal(target)

                """
                Handle the normal typedef case.
                """
                targetkey = self.visit_internal(target)
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
                self.prototypes[key]["parameters"] = [
                    (p.name, self.visit_internal(p.type)) for p in type.parameters
                ]
                self.prototypes[key]["ellipsis"] = type.has_variable_arguments.value
                self.prototypes[key]["returntype"] = self.visit_internal(
                    type.return_value
                )
            case TypeClass.ArrayTypeClass.value:
                assert isinstance(type, ArrayType)

                self.arrays[key] = {}
                self.arrays[key]["count"] = type.count
                self.arrays[key]["target"] = self.visit_internal(type.element_type)
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
