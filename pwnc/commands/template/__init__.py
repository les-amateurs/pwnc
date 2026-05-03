from ...util import *

def command(args: Args, extra: list[str]):
    file_path = "{!r}".format(args.file)
    libc_path = "{!r}".format(args.libc)

    context = \
f"""
file = ELF({file_path}, checksec=False)
libc = ELF({libc_path}, checksec=False)
"""