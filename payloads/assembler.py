"""Relocation-free raw shellcode assembly using LLVM's multi-target assembler."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from io import BytesIO
from pathlib import Path

from .errors import AssemblyError
from .target import ABI, Architecture, Endian, Target


_LLVM_TRIPLES: dict[tuple[Architecture, Endian, ABI], str] = {
    (Architecture.X86, Endian.LITTLE, ABI.I386_SYSV): "i386-linux-gnu",
    (Architecture.X86_64, Endian.LITTLE, ABI.AMD64_SYSV): "x86_64-linux-gnu",
    (Architecture.ARM, Endian.LITTLE, ABI.ARM_EABI): "armv7-linux-gnueabi",
    (Architecture.ARM, Endian.BIG, ABI.ARM_EABI): "armeb-linux-gnueabi",
    (Architecture.THUMB, Endian.LITTLE, ABI.ARM_EABI): "thumbv7-linux-gnueabi",
    (Architecture.THUMB, Endian.BIG, ABI.ARM_EABI): "thumbebv7-linux-gnueabi",
    (Architecture.ARM64, Endian.LITTLE, ABI.AARCH64_AAPCS): "aarch64-linux-gnu",
    (Architecture.ARM64, Endian.BIG, ABI.AARCH64_AAPCS): "aarch64_be-linux-gnu",
    (Architecture.MIPS32, Endian.LITTLE, ABI.MIPS_O32): "mipsel-linux-gnu",
    (Architecture.MIPS32, Endian.BIG, ABI.MIPS_O32): "mips-linux-gnu",
    (Architecture.MIPS64, Endian.LITTLE, ABI.MIPS_N64): "mips64el-linux-gnuabi64",
    (Architecture.MIPS64, Endian.BIG, ABI.MIPS_N64): "mips64-linux-gnuabi64",
    (Architecture.RISCV32, Endian.LITTLE, ABI.RISCV_ILP32): "riscv32-linux-gnu",
    (Architecture.RISCV64, Endian.LITTLE, ABI.RISCV_LP64): "riscv64-linux-gnu",
    (Architecture.POWERPC32, Endian.BIG, ABI.POWERPC_SYSV): "powerpc-linux-gnu",
    (Architecture.POWERPC32, Endian.LITTLE, ABI.POWERPC_SYSV): "powerpcle-linux-gnu",
    (Architecture.POWERPC64, Endian.BIG, ABI.POWERPC64_ELFV1): "powerpc64-linux-gnu",
    (Architecture.POWERPC64, Endian.LITTLE, ABI.POWERPC64_ELFV2): "powerpc64le-linux-gnu",
    (Architecture.SPARC32, Endian.BIG, ABI.SPARC_SYSV): "sparc-linux-gnu",
    (Architecture.SPARC64, Endian.BIG, ABI.SPARC64_SYSV): "sparcv9-linux-gnu",
    (Architecture.S390X, Endian.BIG, ABI.S390X_SYSV): "s390x-linux-gnu",
}


def llvm_triple(target: Target) -> str:
    try:
        return _LLVM_TRIPLES[(target.arch, target.endian, target.abi)]
    except KeyError as exc:
        raise AssemblyError(f"LLVM assembly is not configured for {target.name}") from exc


class LLVMAssembler:
    """Assemble one executable section and reject unresolved relocations."""

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which("llvm-mc") or "llvm-mc"

    @property
    def available(self) -> bool:
        return Path(self.executable).is_file() or shutil.which(self.executable) is not None

    def assemble(self, source: str, target: Target) -> bytes:
        if not self.available:
            raise AssemblyError("llvm-mc was not found; install LLVM or pass an explicit executable path")
        with tempfile.TemporaryDirectory(prefix="pwnc-payload-asm-") as directory:
            object_path = Path(directory, "payload.o")
            command = [
                self.executable,
                f"-triple={llvm_triple(target)}",
                "-filetype=obj",
                "-o",
                str(object_path),
            ]
            if target.abi is ABI.MIPS_O32:
                command.append("-target-abi=o32")
            elif target.abi is ABI.MIPS_N64:
                command.append("-target-abi=n64")
            process = subprocess.run(command, input=source, text=True, capture_output=True, check=False)
            if process.returncode:
                diagnostics = process.stderr.strip() or process.stdout.strip() or "no diagnostics"
                raise AssemblyError(f"llvm-mc failed for {target.name}: {diagnostics}")
            try:
                raw_object = object_path.read_bytes()
            except OSError as exc:
                raise AssemblyError(f"llvm-mc did not produce an object: {exc}") from exc
        return self._extract_text(raw_object, target)

    @staticmethod
    def _extract_text(raw_object: bytes, target: Target) -> bytes:
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.relocation import RelocationSection
        except ImportError as exc:  # pragma: no cover - installed transitively with pwntools
            raise AssemblyError("pyelftools is required to extract raw shellcode") from exc

        try:
            elf = ELFFile(BytesIO(raw_object))
            text = elf.get_section_by_name(".text")
            if text is None:
                raise AssemblyError("assembler object has no .text section")
            text_index = next(index for index, section in enumerate(elf.iter_sections()) if section.name == ".text")
            for section in elf.iter_sections():
                targets_text = isinstance(section, RelocationSection) and section["sh_info"] == text_index
                if targets_text and section.num_relocations():
                    raise AssemblyError(
                        f"shellcode for {target.name} contains {section.num_relocations()} unresolved relocation(s)"
                    )
            data = text.data()
        except AssemblyError:
            raise
        except Exception as exc:
            raise AssemblyError(f"unable to extract shellcode object for {target.name}: {exc}") from exc
        if not data:
            raise AssemblyError("assembler emitted an empty .text section")
        return data


__all__ = ["LLVMAssembler", "llvm_triple"]
