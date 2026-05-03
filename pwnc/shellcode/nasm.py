from ..util import err, run
from tempfile import NamedTemporaryFile
import shutil

RECOGNIZED_MODES = [16, 32, 64]
RECOGNIZED_FORMATS = ["elf32", "elfx32", "elf64", "bin"]

"""
Some considerations, currently will only generate object
files for elf modes. It is possible to generate PIE shellcode,
although of course relocations will be impossible to apply.
"""


def nasm(code: str, format: str, extra: list[str] = []):
    if format not in RECOGNIZED_FORMATS:
        err.warn(f"format not one of RECOGNIZED_FORMATS ({RECOGNIZED_FORMATS})")

    if not shutil.which("nasm"):
        err.fatal("nasm not found")

    with NamedTemporaryFile("w+", suffix=".asm") as tmp_asm:
        tmp_asm.write(code)
        tmp_asm.flush()

        with NamedTemporaryFile("rb+") as tmp_out:
            cmd = ["nasm", tmp_asm.name, "-f", format, "-o", tmp_out.name] + extra
            run(cmd, shell=False)
            with open(tmp_out.name, "rb") as f:
                final = f.read()

    return final
