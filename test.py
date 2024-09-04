from pathlib import Path
from pwnc.minelf import ELF
from subprocess import run
from shutil import copyfile

paths = open("libc-paths.txt").read().splitlines()
paths = map(Path, paths)
paths = list(paths)

failures = 0
failed = []
patched = []

for path in paths:
    print(f"PATH @ {path}")
    raw_elf_bytes = open(path, "rb").read()
    elf = ELF(raw_elf_bytes)
    if elf.header.machine != 0x3e:
        continue
    
    copyfile(path, "./libc.so.6.test")
    handle = run("pwnq unstrip ./libc.so.6.test", shell=True, capture_output=True, encoding="utf-8")
    if handle.returncode != 0:
        print(f"FAILED @ {path}")
        if "bias" in (handle.stdout + handle.stderr):
            patched.append(str(path))
        else:
            failed.append(str(path))

with open("failed.txt", "w+") as fp:
    fp.write("\n".join(failed))
with open("patched.txt", "w+") as fp:
    fp.write("\n".join(patched))

total = len(paths)
print(f"{len(failed) / total * 100:.2f}% failed")
print(f"{len(patched) / total * 100:.2f}% are patchelfed")