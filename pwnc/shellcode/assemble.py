from ..util import err, run
from ..minelf import ELF
from tempfile import NamedTemporaryFile
import shutil

RECOGNIZED_ARCHES = [
    "arm",
    "armeb",
    "aarch64",
    "aarch64_be",
    "aarch64_32",
    "arc",
    "avr",
    "bpfel",
    "bpfeb",
    "csky",
    "dxil",
    "hexagon",
    "loongarch32",
    "loongarch64",
    "m68k",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "msp430",
    "powerpc",
    "powerpcle",
    "powerpc64",
    "powerpc64le",
    "r600",
    "amdgcn",
    "riscv32",
    "riscv64",
    "sparc",
    "sparc64",
    "sparcel",
    "s390x",
    "tce",
    "tcele",
    "thumb",
    "thumbeb",
    "x86",
    "x86_64",
    "xcore",
    "xtensa",
    "nvptx",
    "nvptx64",
    "le32",
    "le64",
    "amdil",
    "amdil64",
    "hsail",
    "hsail64",
    "spir",
    "spir64",
    "spirv",
    "spirv32",
    "spirv64",
    "kalimba",
    "shave",
    "lanai",
    "wasm32",
    "wasm64",
    "renderscript32",
    "renderscript64",
    "ve",
    "spu_2",
]


def asm(code: str, arch: str, extra: list[str] = []):
    if arch not in RECOGNIZED_ARCHES:
        err.warn(f"arch not one of RECOGNIZED_ARCHES ({RECOGNIZED_ARCHES})")

    if not shutil.which("zig"):
        err.fatal("zig not found")

    if arch in ["x86", "x86_64"]:
        extra.append("-masm=intel")

    with NamedTemporaryFile("w+", suffix=".S") as tmp_asm:
        tmp_asm.write(code)
        tmp_asm.flush()

        with NamedTemporaryFile("rb+") as tmp_out:
            cmd = [
                "zig",
                "cc",
                tmp_asm.name,
                "-target",
                f"{arch}-freestanding-none",
                "-o",
                tmp_out.name,
            ] + extra
            run(cmd, shell=False)
            with open(tmp_out.name, "rb") as f:
                final = f.read()

    elf = ELF(final)
    alloc = []
    for section in elf.sections:
        if section.flags & elf.Section.Flags.ALLOC:
            alloc.append(section)

    if not alloc:
        err.fatal("unable to find any ALLOC sections")

    first = alloc[0]
    if not first.flags & elf.Section.Flags.EXECINSTR:
        err.warn("first ALLOC section is not executable?")

    flat = b""
    base = first.address
    for section in alloc:
        flat = flat.ljust(section.address - base)
        flat += elf.section_content(section)

    return flat
