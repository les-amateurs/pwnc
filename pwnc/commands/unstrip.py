from .. types import *
from .. import err
from ..util import run
from pathlib import Path
from pwnlib.elf import ELF
from pwnlib.libcdb import search_by_hash, HASHES
from pwnlib.util.fiddling import enhex
from pwnlib.util.hashes import sha1filehex, sha256filehex, md5filehex
import shutil
import builtins

def buildidfilehex(path: Path):
    return enhex(ELF(path, checksec=False).buildid or b'')

def hashes():
    match type(HASHES):
        case builtins.list:
            return {
                "build_id": buildidfilehex,
                "sha1": sha1filehex,
                "sha256": sha256filehex,
                "md5": md5filehex,
            }
        case builtins.dict:
            return HASHES


# https://wiki.archlinux.org/title/Debuginfod
DEBUGINFOD_SERVERS = [
    "https://debuginfod.elfutils.org/"
]

def command(args: Args):
    if args.file.name.startswith("libc.so"):
        args.libc = True

    if not shutil.which("debuginfod-find"):
        err.require("debuginfod-find")
    
    """
    Use debuginfod-find as it provides some extra flexibility
    """
    handle = run(f"debuginfod-find debuginfo {args.file}", check=False, capture_output=True)

    if handle.returncode != 0:
        err.info(f"failed to download debuginfo for {args.file}")

    debuginfo_path = Path(handle.stdout.strip())
    err.info(f"debuginfo path = {debuginfo_path}")

    if not shutil.which("eu-unstrip"):
        err.require("eu-unstrip")

    run(f"eu-unstrip {args.file} {debuginfo_path} -o {args.file}")
    err.info(f"sucessfully unstripped file")