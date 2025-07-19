from pwnc.minelf import *

elf = ELF(open("libtroll.so", "rb").read())
tags: list = elf.section_content(elf.section_from_name(b".dynamic"), elf.Dyntag)
for tag in tags:
    if tag.tag == 0x1e or tag.tag == 0x6ffffffb:
        tag.val = 0
elf.write("libtroll.so")