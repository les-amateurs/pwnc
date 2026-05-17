from pwn import *
from pwnc.shellcode import nasm, asm as PwncAsm

def asm(code: str, maybe_arch: str | None = None):
    arch = maybe_arch or context.arch
    if arch == "i386":
        return nasm("bits 32\n" + code, "bin")
    if arch == "x86_64":
        return nasm("bits 64\n" + code, "bin")
    else:
        return PwncAsm(code, arch)

class config:
    file: str = """ [config.file] """
    libc: str = """ [config.libc] """
    port: int = """ [config.port] """ # type: ignore

file = None
if config.file:
    file = ELF(config.file, checksec=False)
    context.binary = file

libc = None
if config.libc:
    libc = ELF(config.libc, checksec=False)

def connect():
    pass

gdbscript = """
c
"""