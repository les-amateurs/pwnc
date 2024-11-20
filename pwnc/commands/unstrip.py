from re import T
from .. util import *
from pathlib import Path
from .scrape import locate_package
from .. import minelf
import shutil

# https://wiki.archlinux.org/title/Debuginfod
DEBUGINFOD_SERVERS = [
    "https://debuginfod.elfutils.org/"
]

def unstrip(stripped: Path, debuginfo: Path):
    err.info(f"debuginfo path = {debuginfo}")
    if not shutil.which("eu-unstrip"):
        err.require("eu-unstrip")

    handle = run(f"eu-unstrip {stripped} {debuginfo} --force -o {stripped}", check=False)
    if handle.returncode == 0:
        err.info(f"sucessfully unstripped file")
    else:
        err.fatal(f"failed to unstrip file")

def unstrip_from_package(file: Path, save: bool):
    with open(file, "rb") as fp:
        raw_elf_bytes = fp.read()
    elf = minelf.ELF(raw_elf_bytes)

    package = locate_package(elf)
    if package is None:
        err.fatal(f"failed to locate package for {file}")
    err.info(package.storage)
    package.unpack()

    debuginfo_path = None

    buildid: str = elf.buildid.hex()
    err.info(f"using buildid strategy ({buildid})")
    file = f"{buildid[:2]}/{buildid[2:]}.debug"
    debuginfo = package.find(file)
    
    if len(debuginfo) == 1:
        debuginfo_path = debuginfo[0]
    else:
        err.warn(f"failed to find {file} in {package.storage}")

    if debuginfo_path is None:
        err.warn("recursively searching files for match")
        files = list(package.storage.rglob("*.so*"))
        for file in files:
            with open(file, "rb") as fp:
                file_bytes = fp.read()
            maybe_elf = minelf.ELF(file_bytes)
            try:
                maybe_elf.check()
            except:
                err.warn(f"malformed elf {file}")
                continue

            if maybe_elf.buildid == elf.buildid:
                err.info(f"found match {file}")
                debuginfo_path = file
                break
        else:
            err.warn("recursive search failed")

    if debuginfo_path is None:
        err.fatal("failed to find debuginfo file")

    if save:
        cache = Path("_cache") / buildid
        cache.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copytree(package.storage, cache, dirs_exist_ok=True, ignore_dangling_symlinks=True)
        except:
            import os
            os.system("/bin/zsh")

    return debuginfo_path

def handle_unstrip(file: Path, save: bool = False):
    debuginfo_path = None

    if debuginfo_path is None and not save:
        handle = run(f"debuginfod-find debuginfo {file}", check=False, capture_output=True)

        if handle.returncode == 0:
            debuginfo_path = Path(handle.stdout.strip())
        else:
            err.info(f"failed to download debuginfo for {file}")

    if debuginfo_path is None:
        debuginfo_path = unstrip_from_package(file, save)

    unstrip(file, debuginfo_path)

def command(args: Args):
    if not shutil.which("debuginfod-find"):
        err.require("debuginfod-find")

    handle_unstrip(args.file, save=args.save)