"""Build cross-architecture ELF fixtures and matching Teemo IR documents."""

from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile

PLUGIN_DIR = Path(__file__).parents[1] / "plugin"
import sys

if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))

from teemo.ir import (
    Address,
    AddressRange,
    Architecture,
    Binary,
    Declaration,
    Document,
    Endianness,
    Function,
    Label,
    Line,
    Location,
    LocationExpression,
    Scope,
    Section,
    Source,
    Variable,
)

FIXTURE_SOURCE = Path(__file__).parent / "fixtures" / "src" / "scopes.c"
ORPHAN_ENTROPY_SOURCE = Path(__file__).parent / "fixtures" / "src" / "orphan_entropy.S"
PSEUDOCODE = """enum Mode { MODE_ZERO = 0, MODE_ACTIVE = 7 };
struct Node { int value; struct Node *next; };
volatile int global_counter;
int analyzed(int argc, char **argv, struct Node *node)
{
    volatile int stack_local = argc + node->value;
    int shadow = stack_local;
    if ((argc & 1) != 0)
    {
        int shadow = node->value + 11;
        stack_local += shadow;
    }
    for (int index = 0; index < 3; ++index)
    {
        int loop_local = index + shadow;
        stack_local += loop_local;
    }
    global_sink = stack_local;
    return stack_local + global_counter;
}
"""


@dataclass(frozen=True)
class Target:
    architecture: Architecture
    triple: str
    qemu: str
    register_arguments: tuple[str, str, str] | None
    local_cfa_offset: int
    extra_flags: tuple[str, ...] = ()


TARGETS = {
    "x86_64": Target(Architecture.X86_64, "x86_64-linux-gnu", "qemu-x86_64", ("rdi", "rsi", "rdx"), -20),
    "x86": Target(Architecture.X86, "i386-linux-gnu", "qemu-i386", None, -24),
    "arm": Target(Architecture.ARM, "armv7-linux-gnueabihf", "qemu-arm", ("r0", "r1", "r2"), -12, ("-marm",)),
    "aarch64": Target(Architecture.AARCH64, "aarch64-linux-gnu", "qemu-aarch64", ("x0", "x1", "x2"), -4),
}


def compile_fixture(
    output: Path,
    target: Target,
    *,
    pie: bool,
    orphan_import: bool = False,
    security_annotations: bool = False,
) -> int | None:
    command = [
        "clang",
        f"--target={target.triple}",
        "-fuse-ld=lld",
        "-nostdlib",
        "-fno-stack-protector",
        "-fno-builtin",
        "-ffreestanding",
        "-fno-omit-frame-pointer",
        "-O1",
        "-g0",
        "-Wl,--build-id=sha1",
        "-Wl,-e,_start",
        *target.extra_flags,
    ]
    if orphan_import:
        command.extend(
            (
                "-DTEEMO_ORPHAN_IMPORT_FIXTURE=1",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-Wl,--unresolved-symbols=ignore-all",
            )
        )
        if target.architecture == Architecture.X86_64:
            # Keep the orphan's only import evidence in raw instruction LLIL:
            # ``call *slot(%rip)`` plus an R_X86_64_GLOB_DAT relocation.  The
            # source applies that form only to the orphan so other imports can
            # still exercise ordinary PLT analysis.
            command.append("-fno-optimize-sibling-calls")
    if security_annotations:
        command.extend(
            (
                "-DTEEMO_SECURITY_ANNOTATION_FIXTURE=1",
                "-fstack-protector-all",
                "-Wl,--unresolved-symbols=ignore-all",
            )
        )
    if pie:
        command.extend(("-pie", "-Wl,--no-dynamic-linker"))
    else:
        command.extend(("-static", "-Wl,-no-pie"))
    command.append(str(FIXTURE_SOURCE))
    if orphan_import:
        command.append(str(ORPHAN_ENTROPY_SOURCE))
    command.extend(("-o", str(output)))
    subprocess.run(command, check=True, capture_output=True, text=True)
    if not orphan_import:
        return None
    orphan_address = _symbol_address(output, "teemo_orphan_win")
    subprocess.run(
        ["llvm-objcopy", "--strip-symbol=teemo_orphan_win", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    return orphan_address


def _symbol_address(path: Path, name: str) -> int:
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if section.header.sh_type not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                continue
            for symbol in section.iter_symbols():
                if symbol.name == name:
                    return int(symbol.entry.st_value)
    raise RuntimeError(f"fixture {path} has no symbol {name!r}")


def document_for_fixture(path: Path, target: Target) -> Document:
    inspected = _inspect_elf(path)
    function_start, function_size, function_section_name = inspected["symbols"]["analyzed"]
    function_end = function_start + function_size
    instructions = _instruction_spans(path, function_start, function_end)
    if len(instructions) < 12:
        raise RuntimeError(f"too few decoded instructions in fixture {path}")

    selected_names = {function_section_name}
    selected_names.update(inspected["symbols"][name][2] for name in ("global_counter", "global_sink", "global_node"))
    sections = []
    section_ids = {}
    for name in sorted(selected_names, key=lambda value: inspected["sections"][value][0]):
        address, size, flags = inspected["sections"][name]
        identifier = f"section:{name.lstrip('.')}"
        section_ids[name] = identifier
        sections.append(
            Section(
                identifier,
                name,
                address,
                size,
                readable=True,
                writable=bool(flags & 0x1),
                executable=bool(flags & 0x4),
            )
        )

    text_id = section_ids[function_section_name]
    function_range = _range(function_start, function_end, text_id)
    source_id = "source:analyzed"
    pointer_size = target.architecture.address_size
    types = _types(pointer_size)

    first_end = instructions[0][1]
    parameters = []
    parameter_specs = (
        ("argc", "type:int"),
        ("argv", "type:char_pp"),
        ("node", "type:node_ptr"),
    )
    for index, (name, type_id) in enumerate(parameter_specs):
        if target.register_arguments is None:
            expression = LocationExpression.cfa_offset(index * pointer_size)
        else:
            expression = LocationExpression.register_location(target.register_arguments[index])
        parameters.append(
            Variable(
                id=f"variable:analyzed:{name}",
                name=name,
                kind="parameter",
                type_id=type_id,
                locations=[
                    Location(_range(function_start, first_end, text_id), expression),
                    Location(
                        _range(first_end, function_end, text_id),
                        LocationExpression.unavailable("entry argument storage is no longer proven"),
                    ),
                ],
                declaration=Declaration(source_id, 4, 14 + index * 10),
            )
        )

    prologue_end = _local_ready_address(path, target, instructions)
    stack_local = Variable(
        id="variable:analyzed:stack_local",
        name="stack_local",
        kind="local",
        type_id="type:volatile_int",
        locations=[
            Location(
                _range(function_start, prologue_end, text_id),
                LocationExpression.unavailable("stack slot is not initialized"),
            ),
            Location(
                _range(prologue_end, function_end, text_id),
                LocationExpression.cfa_offset(target.local_cfa_offset),
            ),
        ],
        declaration=Declaration(source_id, 6, 18),
    )
    outer_shadow = _unavailable_variable(
        "variable:analyzed:shadow:outer",
        "shadow",
        "type:int",
        function_range,
        source_id,
        7,
    )

    branch_start = instructions[len(instructions) // 4][0]
    branch_end = instructions[len(instructions) // 2][0]
    loop_first_start = instructions[len(instructions) * 3 // 5][0]
    loop_first_end = instructions[len(instructions) * 7 // 10][0]
    loop_second_start = instructions[len(instructions) * 3 // 4][0]
    loop_second_end = instructions[len(instructions) * 9 // 10][0]
    if loop_first_end >= loop_second_start:
        loop_first_end = instructions[len(instructions) * 2 // 3][0]

    branch_range = _range(branch_start, branch_end, text_id)
    loop_ranges = [
        _range(loop_first_start, loop_first_end, text_id),
        _range(loop_second_start, loop_second_end, text_id),
    ]
    inner_shadow = _unavailable_variable(
        "variable:analyzed:shadow:inner",
        "shadow",
        "type:int",
        branch_range,
        source_id,
        10,
    )
    loop_local = Variable(
        id="variable:analyzed:loop_local",
        name="loop_local",
        kind="local",
        type_id="type:int",
        locations=[
            Location(value, LocationExpression.unavailable("optimized value has no proven storage"))
            for value in loop_ranges
        ],
        declaration=Declaration(source_id, 15, 13),
    )
    scope = Scope(
        "scope:analyzed:root",
        [function_range],
        variables=[stack_local, outer_shadow],
        children=[
            Scope("scope:analyzed:if", [branch_range], variables=[inner_shadow]),
            Scope("scope:analyzed:loop", loop_ranges, variables=[loop_local]),
        ],
    )

    function = Function(
        id="function:analyzed",
        name="analyzed",
        ranges=[function_range],
        return_type="type:int",
        parameters=parameters,
        scope=scope,
        external=True,
        declaration=Declaration(source_id, 4, 1),
        calling_convention="cdecl" if target.architecture == Architecture.X86 else "sysv",
    )

    globals_ = []
    for name, type_id, line in (
        ("global_counter", "type:volatile_int", 3),
        ("global_sink", "type:volatile_int", 18),
        ("global_node", "type:node", 2),
    ):
        address, _size, section_name = inspected["symbols"][name]
        globals_.append(
            Variable(
                id=f"global:{name}",
                name=name,
                kind="global",
                type_id=type_id,
                static_location=LocationExpression(
                    kind="address",
                    address=Address(address, section_ids[section_name]),
                ),
                declaration=Declaration(source_id, line, 1),
                external=True,
            )
        )

    lines = _line_records(instructions, text_id, source_id, prologue_end)
    label_address = instructions[len(instructions) * 3 // 5][0]
    return Document(
        producer="Teemo compiled cross-architecture fixture",
        binary=Binary(
            filename=path.name,
            architecture=target.architecture,
            endianness=Endianness.LITTLE,
            entry_point=inspected["entry"],
            image_base=inspected["image_base"],
            build_id=inspected["build_id"],
        ),
        sections=sections,
        types=types,
        globals=globals_,
        functions=[function],
        labels=[
            Label(
                "label:analyzed:loop",
                "teemo_loop_body",
                Address(label_address, text_id),
                function_id=function.id,
                declaration=Declaration(source_id, 13, 5),
            )
        ],
        sources=[Source(source_id, "teemo/scopes.c", "c", True, PSEUDOCODE)],
        lines=lines,
    )


def _types(pointer_size: int) -> list[dict[str, object]]:
    word_name = "unsigned long"
    return [
        {"id": "type:int", "kind": "base", "name": "int", "byte_size": 4, "encoding": "signed"},
        {"id": "type:bool", "kind": "base", "name": "bool", "byte_size": 1, "encoding": "boolean"},
        {"id": "type:float", "kind": "base", "name": "float", "byte_size": 4, "encoding": "float"},
        {"id": "type:uchar", "kind": "base", "name": "unsigned char", "byte_size": 1, "encoding": "unsigned_char"},
        {"id": "type:char", "kind": "base", "name": "char", "byte_size": 1, "encoding": "signed_char"},
        {"id": "type:word_base", "kind": "base", "name": word_name, "byte_size": pointer_size, "encoding": "unsigned"},
        {"id": "type:char_ptr", "kind": "pointer", "byte_size": pointer_size, "target": "type:char"},
        {"id": "type:char_pp", "kind": "pointer", "byte_size": pointer_size, "target": "type:char_ptr"},
        {"id": "type:node_ptr", "kind": "pointer", "byte_size": pointer_size, "target": "type:node"},
        {
            "id": "type:bytes4",
            "kind": "array",
            "byte_size": 4,
            "element_type": "type:uchar",
            "dimensions": [{"lower_bound": 0, "count": 4}],
        },
        {
            "id": "type:payload",
            "kind": "union",
            "name": "Payload",
            "byte_size": 4,
            "declaration_only": False,
            "members": [
                {"name": "number", "type_id": "type:int", "offset": 0},
                {"name": "bytes", "type_id": "type:bytes4", "offset": 0},
            ],
        },
        {
            "id": "type:node",
            "kind": "structure",
            "name": "Node",
            "byte_size": 8 if pointer_size == 4 else 16,
            "declaration_only": False,
            "members": [
                {"name": "value", "type_id": "type:int", "offset": 0},
                {"name": "next", "type_id": "type:node_ptr", "offset": 4 if pointer_size == 4 else 8},
            ],
            "bases": [],
        },
        {
            "id": "type:base_class",
            "kind": "class",
            "name": "Base",
            "byte_size": 4,
            "declaration_only": False,
            "members": [{"name": "base_value", "type_id": "type:int", "offset": 0}],
            "bases": [],
        },
        {
            "id": "type:derived_class",
            "kind": "class",
            "name": "Derived",
            "byte_size": 8,
            "declaration_only": False,
            "members": [{"name": "payload", "type_id": "type:payload", "offset": 4}],
            "bases": [{"type_id": "type:base_class", "offset": 0}],
        },
        {
            "id": "type:mode",
            "kind": "enum",
            "name": "Mode",
            "byte_size": 4,
            "underlying_type": "type:int",
            "enumerators": [{"name": "MODE_ZERO", "value": 0}, {"name": "MODE_ACTIVE", "value": 7}],
        },
        {"id": "type:word", "kind": "typedef", "name": "target_word", "target": "type:word_base"},
        {"id": "type:volatile_int", "kind": "qualified", "qualifier": "volatile", "target": "type:int"},
        {
            "id": "type:analyzed_prototype",
            "kind": "function",
            "return_type": "type:int",
            "parameters": [
                {"name": "argc", "type_id": "type:int", "artificial": False},
                {"name": "argv", "type_id": "type:char_pp", "artificial": False},
                {"name": "node", "type_id": "type:node_ptr", "artificial": False},
            ],
            "variadic": False,
            "calling_convention": "sysv",
        },
    ]


def _unavailable_variable(
    identifier: str,
    name: str,
    type_id: str,
    address_range: AddressRange,
    source_id: str,
    line: int,
) -> Variable:
    return Variable(
        id=identifier,
        name=name,
        kind="local",
        type_id=type_id,
        locations=[Location(address_range, LocationExpression.unavailable("optimized value has no proven storage"))],
        declaration=Declaration(source_id, line, 9),
    )


def _line_records(
    instructions: list[tuple[int, int]],
    section_id: str,
    source_id: str,
    local_ready: int,
) -> list[Line]:
    source_lines = (4, 6, 7, 8, 10, 11, 13, 15, 16, 18, 19)
    raw = []
    count = len(instructions)
    ready_index = next(index for index, (start, _end) in enumerate(instructions) if start == local_ready)
    remaining = max(1, count - ready_index)
    for index, (start, end) in enumerate(instructions):
        if index < ready_index:
            phase = 0
        else:
            phase = min(
                len(source_lines) - 1,
                1 + (index - ready_index) * (len(source_lines) - 1) // remaining,
            )
        line = source_lines[phase]
        # Give the loop update two separate machine-code runs on one source line.
        if count * 3 // 5 <= index < count * 2 // 3 or count * 3 // 4 <= index < count * 5 // 6:
            line = 16
        raw.append((start, end, line))

    coalesced: list[tuple[int, int, int]] = []
    for start, end, line in raw:
        if coalesced and coalesced[-1][1] == start and coalesced[-1][2] == line:
            previous = coalesced[-1]
            coalesced[-1] = (previous[0], end, line)
        else:
            coalesced.append((start, end, line))
    runs: defaultdict[int, int] = defaultdict(int)
    result = []
    for start, end, line in coalesced:
        discriminator = runs[line]
        runs[line] += 1
        result.append(
            Line(
                _range(start, end, section_id),
                source_id,
                line,
                column=5,
                statement=True,
                discriminator=discriminator,
            )
        )
    return result


def _instruction_spans(path: Path, start: int, end: int) -> list[tuple[int, int]]:
    output = subprocess.run(
        ["llvm-objdump", "-d", "--disassemble-symbols=analyzed", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    addresses = [
        int(match.group(1), 16) for line in output.splitlines() if (match := re.match(r"^\s*([0-9a-fA-F]+):\s", line))
    ]
    addresses = sorted({address for address in addresses if start <= address < end})
    if not addresses or addresses[0] != start:
        raise RuntimeError(f"llvm-objdump did not decode analyzed at {start:#x}")
    return list(zip(addresses, addresses[1:] + [end]))


def _local_ready_address(
    path: Path,
    target: Target,
    instructions: list[tuple[int, int]],
) -> int:
    output = subprocess.run(
        ["llvm-objdump", "-d", "--disassemble-symbols=analyzed", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    store_address = None
    for line in output.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+):\s", line)
        fields = line.split("\t")
        if match is None or len(fields) < 2:
            continue
        assembly = " ".join(field.strip() for field in fields[1:] if field.strip()).lower()
        if target.architecture in {Architecture.X86, Architecture.X86_64}:
            is_store = assembly.startswith("mov") and bool(re.search(r",\s*-?0x[0-9a-f]+\(%[er]bp\)\s*$", assembly))
        else:
            is_store = assembly.startswith("str") and "[sp" in assembly
        if is_store:
            store_address = int(match.group(1), 16)
            break
    if store_address is None:
        raise RuntimeError(f"cannot find stack_local initialization in {path}")
    for index, (start, end) in enumerate(instructions):
        if start == store_address:
            return instructions[index + 1][0] if index + 1 < len(instructions) else end
    raise RuntimeError(f"stack_local initialization is outside analyzed in {path}")


def _inspect_elf(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise RuntimeError(f"fixture has no symbol table: {path}")
        symbols = {}
        for name in ("analyzed", "global_counter", "global_sink", "global_node"):
            symbol = symtab.get_symbol_by_name(name)[0]
            section = elf.get_section(symbol.entry.st_shndx)
            symbols[name] = (
                int(symbol.entry.st_value),
                int(symbol.entry.st_size),
                section.name,
            )
        sections = {
            section.name: (
                int(section.header.sh_addr),
                int(section.header.sh_size),
                int(section.header.sh_flags),
            )
            for section in elf.iter_sections()
            if section.name
        }
        load_addresses = [
            int(segment.header.p_vaddr) for segment in elf.iter_segments() if segment.header.p_type == "PT_LOAD"
        ]
        build_id = None
        note = elf.get_section_by_name(".note.gnu.build-id")
        if note is not None:
            for value in note.iter_notes():
                if value["n_name"] == "GNU" and value["n_type"] == "NT_GNU_BUILD_ID":
                    build_id = str(value["n_desc"])
                    break
        return {
            "entry": int(elf.header.e_entry),
            "image_base": min(load_addresses, default=0),
            "build_id": build_id,
            "symbols": symbols,
            "sections": sections,
        }


def _range(start: int, end: int, section_id: str) -> AddressRange:
    return AddressRange(Address(start, section_id), Address(end, section_id))
