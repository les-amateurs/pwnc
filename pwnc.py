#!/usr/bin/env python3

from argparse import ArgumentParser, BooleanOptionalAction
from pathlib import Path
import pwnc.commands.unstrip as unstrip
import pwnc.commands.patch as patch
import pwnc.commands.kernel as kernel
import logging

logging.basicConfig(level=logging.INFO)

usage = """\
pwnc (options) [command]
"""

description = """\

"""

def get_main_parser():
    parser = ArgumentParser(
        prog="pwnc",
        usage=usage,
        description=description,
    )

    subparsers = parser.add_subparsers()
    # make required (py3.7 API change); vis. https://bugs.python.org/issue16308
    subparsers.required = True
    subparsers.dest = "subcommand"

    subparser = subparsers.add_parser("unstrip", help="unstrip binaries by adding debuginfo")
    subparser.add_argument("file", type=lambda file: Path(file))
    subparser.add_argument("--libc", action=BooleanOptionalAction)

    subparser = subparsers.add_parser("patch", help="patch binaries")
    subparser.add_argument("--interp")
    subparser.add_argument("--rpath")
    subparser.add_argument("file", type=lambda file: Path(file))

    subparser = subparsers.add_parser("kmod", help="kernel module helpers")
    subparser.add_argument("--set", type=str, action='append', nargs=2, default=[])
    subparser.add_argument("-o", type=lambda file: Path(file))
    subparser.add_argument("file", type=lambda file: Path(file))

    return parser

if __name__ == "__main__":
    parser = get_main_parser()
    args = parser.parse_args()

    match args.subcommand:
        case "unstrip":
            unstrip.command(args)
        case "patch":
            patch.command(args)
        case "kmod":
            kernel.module.command(args)