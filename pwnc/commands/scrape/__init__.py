from . import debian
from . import ubuntu
from .package import Package
from ...util import *
from ... import minelf

supported_distros = [
    debian,
    ubuntu,
]


def locate_package(elf: minelf.ELF) -> Package:
    for distro in supported_distros:
        if not distro.provides(elf):
            name = distro.__name__.rsplit(".", maxsplit=1)[1]
            err.warn(f"not a {name} package")
            continue

        package = distro.locate(elf)
        if package:
            return package
