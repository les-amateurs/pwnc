from struct import pack
from . import debian
from . import ubuntu
from ... import minelf

supported_distros = [
    debian,
    ubuntu,
]

def locate_package(elf: minelf.ELF):
    for distro in supported_distros:
        if not distro.provides(elf):
            continue

        package = distro.locate(elf)
        if package:
            return package