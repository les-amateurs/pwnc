from collections import ChainMap

from pytest import param
from pwnc import minelf
import binaryninja as binaryninja
import rpyc
import json
c = rpyc.connect("0.0.0.0", 18812)

bv: binaryninja.BinaryView = c.root.bv
bn: binaryninja = c.root.binaryninja

print(f"connected to {bv.file.filename}")

anonymous = 0
structs = {}
unions = {}
enums = {}
integers = {}
typedefs = {}
pointers = {}
prototypes = {}
arrays = {}
floats = {}

variables = {}
functions = {}
sections = {}

def escape(name: binaryninja.QualifiedName):
    return name.name[0]

def extract_typename(kind: binaryninja.Type, name: str | None = None):
    match kind.type_class.value:
        case binaryninja.TypeClass.IntegerTypeClass.value:
            return name or kind.get_string()
        case binaryninja.TypeClass.StructureTypeClass.value:
            if kind.registered_name is None:
                name = None
            else:
                name = escape(kind.registered_name.name)
            match kind.type.value:
                case binaryninja.StructureVariant.StructStructureType:
                    return name
                case binaryninja.StructureVariant.UnionStructureType:
                    return name
                case _:
                    exit(f"unknown structure type")
        case binaryninja.TypeClass.PointerTypeClass.value:
            return name or kind.get_string()
        case binaryninja.TypeClass.NamedTypeReferenceClass.value:
            return escape(kind.name)
        case binaryninja.TypeClass.EnumerationTypeClass.value:
            return escape(kind.registered_name.name)
        case binaryninja.TypeClass.FunctionTypeClass.value:
            return kind.get_string()
        case binaryninja.TypeClass.ArrayTypeClass.value:
            return f"{extract_typename(kind.element_type)}[{kind.count}]"
        case binaryninja.TypeClass.VoidTypeClass.value:
            return ""
        case binaryninja.TypeClass.FloatTypeClass.value:
            return kind.get_string()
        case _:
            print(f"unhandled: {name} {type(kind)}")
            exit(1)

def visit(kind: binaryninja.Type, name: str | None = None):
    global anonymous

    anon = False
    key = extract_typename(kind, name)
    if key is None:
        key = f"anon.{anonymous}"
        anonymous += 1
        anon = True

    if  key in structs or \
        key in enums or \
        key in integers or \
        key in typedefs or \
        key in pointers or \
        key in prototypes or \
        key in arrays:
        return key
    
    match kind.type_class.value:
        case binaryninja.TypeClass.IntegerTypeClass.value:
            integers[key] = {}
            integers[key]["size"] = len(kind)
            integers[key]["signed"] = kind.signed.value
        case binaryninja.TypeClass.StructureTypeClass.value:
            match kind.type.value:
                case binaryninja.StructureVariant.StructStructureType:
                    target = structs
                case binaryninja.StructureVariant.UnionStructureType:
                    target = unions
                case _:
                    exit(f"unknown structure type")
            target[key] = {}
            target[key]["size"] = len(kind)
            target[key]["anon"] = anon
            target[key]["fields"] = list(map(lambda field: (field.offset, field.name, visit(field.type)), kind.members))
        case binaryninja.TypeClass.PointerTypeClass.value:
            pointers[key] = {}
            pointers[key]["size"] = len(kind)
            pointers[key]["target"] = visit(kind.target)
        case binaryninja.TypeClass.NamedTypeReferenceClass.value:
            target = visit(kind.target(bv))
            if key == target:
                return key
            typedefs[key] = {}
            typedefs[key]["target"] = target
        case binaryninja.TypeClass.EnumerationTypeClass.value:
            enums[key] = {}
            enums[key]["size"] = len(kind)
            enums[key]["signed"] = kind.signed.value
            enums[key]["fields"] = list(map(lambda field: (field.name, field.value), kind.members))
        case binaryninja.TypeClass.FunctionTypeClass.value:
            prototypes[key] = {}
            prototypes[key]["parameters"] = list(map(lambda p: (p.name, visit(p.type)), kind.parameters))
            prototypes[key]["ellipsis"] = kind.has_variable_arguments.value
            prototypes[key]["returntype"] = visit(kind.return_value)
        case binaryninja.TypeClass.ArrayTypeClass.value:
            arrays[key] = {}
            arrays[key]["count"] = kind.count
            arrays[key]["target"] = visit(kind.element_type)
        case binaryninja.TypeClass.VoidTypeClass.value:
            pass
        case binaryninja.TypeClass.FloatTypeClass.value:
            floats[key] = {}
            floats[key]["size"] = len(kind)
        case _:
            exit(kind, name, type(kind))

    return key

def get_section_at(addr: int):
    binja_sections = bv.get_sections_at(addr)
    if len(binja_sections) == 0:
        return None
    section = binja_sections[0]
    if section.name not in sections:    
        sections[section.name] = {}
        sections[section.name]["addr"] = section.start
        sections[section.name]["size"] = section.end - section.start

    return section

for name, kind in bv.types:
    visit(kind, escape(name))

for name, symbols in bv.symbols.items():
    for symbol in symbols:
        if symbol.type.value != binaryninja.SymbolType.DataSymbol.value:
            continue

        variable = bv.get_data_var_at(symbol.address)
        variables[symbol.address] = {}
        variables[symbol.address]["name"] = name
        variables[symbol.address]["size"] = len(variable)
        variables[symbol.address]["typename"] = visit(variable.type)
        if section := get_section_at(symbol.address):
            variables[symbol.address]["section"] = section.name

for function in bv.functions:
    if function.symbol.type.value != binaryninja.SymbolType.FunctionSymbol.value:
        continue

    key = function.start
    end = max(map(lambda range: range.end, function.address_ranges))

    functions[key] = {}
    functions[key]["name"] = function.name
    functions[key]["start"] = function.start
    functions[key]["end"] = end

    arguments = []
    for parameter in function.parameter_vars:
        location = {}
        match parameter.source_type.value:
            case binaryninja.VariableSourceType.RegisterVariableSourceType.value:
                location["Register"] = bv.arch.get_reg_name(parameter.storage)
            case binaryninja.VariableSourceType.StackVariableSourceType.value:
                location["StackVariable"] = parameter.storage
            case _:
                print(f"unhandled variable source type: {parameter.source_type}")

        arguments.append((location, parameter.name, visit(parameter.type)))

    functions[key]["arguments"] = arguments

    calls = []
    for call_site in function.call_sites:
        insn = call_site.llil
        block = insn.il_basic_block
        match insn.operation.value:
            case binaryninja.LowLevelILOperation.LLIL_CALL.value:
                call = {}
                call["return_pc"] = block[insn.instr_index + 1 - block.start].address
                call["target"] = insn.dest.value.value
                calls.append(call)

    functions[key]["calls"] = calls

    functions[key]["ellipsis"] = function.type.has_variable_arguments.value
    functions[key]["returntype"] = visit(function.type.return_value)
    
    locals = []
    for variable in function.vars:
        if variable.storage <= 0:
            local = {}
            local["name"] = variable.name
            local["typename"] = visit(variable.type)
            local["offset"] = variable.storage
            locals.append(local)

    functions[key]["locals"] = locals

    frame = []
    frame.append((0, 0))
    previous_frame_offset = 0

    rsp = bv.arch.get_reg_index("rsp")
    if llil := function.llil_if_available:
        for insn in llil.instructions:
            value = insn.get_possible_reg_values_after(rsp)
            match value.type.value:
                case binaryninja.RegisterValueType.UndeterminedValue.value:
                    offset = 0
                case binaryninja.RegisterValueType.StackFrameOffset.value:
                    offset = value.offset
                case _:
                    print("failed to locate rsp offset")
                    break

            if offset != previous_frame_offset:
                frame.append((insn.address - function.start, offset))
                previous_frame_offset = offset

        functions[key]["frame"] = sorted(frame, key=lambda e: e[0])

    if section := get_section_at(function.start):
        functions[key]["section"] = section.name

json.dump(structs, open("structs.json", "w+"))
json.dump(unions, open("unions.json", "w+"))
json.dump(enums, open("enums.json", "w+"))
json.dump(integers, open("integers.json", "w+"))
json.dump(typedefs, open("typedefs.json", "w+"))
json.dump(pointers, open("pointers.json", "w+"))
json.dump(prototypes, open("prototypes.json", "w+"))
json.dump(arrays, open("arrays.json", "w+"))
json.dump(floats, open("floats.json", "w+"))

json.dump(variables, open("variables.json", "w+"))
json.dump(functions, open("functions.json", "w+"))
json.dump(sections, open("sections.json", "w+"))