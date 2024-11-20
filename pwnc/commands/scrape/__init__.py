from struct import pack
from . import debian
from . import ubuntu
from .package import Package
from ... import minelf

supported_distros = [
    debian,
    ubuntu,
]

def locate_package(elf: minelf.ELF)-> Package:
    for distro in supported_distros:
        if not distro.provides(elf):
            continue

        package = distro.locate(elf)
        if package:
            return package