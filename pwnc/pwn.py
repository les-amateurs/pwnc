from pwn import context
from . import shellcode


def asm(code: str):
    return shellcode.asm(code, context.arch)


def dockerd():
    pass


def send():
    pass


def sendline():
    pass
