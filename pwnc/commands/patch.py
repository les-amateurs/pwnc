from ..types import *
from ..util import run
from .. import err
import shutil

"""
TODO: write a better patchelf implementation(?) and removes external dependency

Currently patchelf can break some binaries:
- symbols or debuginfo stop working
- segments are rearranged
- most of the time GNU_RELRO segment no longer properly protects some segments
"""

def command(args: Args):
    if not shutil.which("patchelf"):
        err.require("patchelf")

    if args.interp:
        run(f"patchelf --no-sort --set-interpreter {args.interp} {args.file}")

    if args.rpath:
        run(f"patchelf --no-sort --set-rpath {args.rpath} {args.file}")