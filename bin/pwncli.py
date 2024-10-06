#!/usr/bin/env python3

from argparse import ArgumentParser, BooleanOptionalAction
import argcomplete
from pathlib import Path
import logging
import pwnc.config

logging.basicConfig(level=logging.INFO)

usage = """\
pwnc (options) [command]
"""

description = """\

"""

def PathArg(file):
    return Path(file)

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

    subparser = subparsers.add_parser("unpack", help="unpack and initialize from distribution")
    subparser.add_argument("file", type=PathArg)

    subparser = subparsers.add_parser("unstrip", help="unstrip binaries by adding debuginfo")
    subparser.add_argument("file", type=PathArg)
    subparser.add_argument("--libc", action="store_true")
    subparser.add_argument("--save", action="store_true")

    subparser = subparsers.add_parser("patch", help="patch binaries")
    subparser.add_argument("--bits", choices=[32, 64], help="override elf 32 or 64")
    subparser.add_argument("--endian", choices=["big", "little"], help="override endianness")
    subparser.add_argument("--rpath", type=str, help="new rpath") 
    subparser.add_argument("--interp", type=str, help="new interpreter path")
    subparser.add_argument("file", type=PathArg)
    subparser.add_argument("outfile", type=PathArg, nargs="?")

    kernel = subparsers.add_parser("kernel", help="kernel pwn setup")
    kernel = kernel.add_subparsers()
    kernel.required = True
    kernel.dest = "subcommand.kernel"

    subparser = kernel.add_parser("init", help="kernel pwn setup")
    subparser.add_argument("-i", type=PathArg, help="path to initramfs", dest="initramfs")

    subparser = kernel.add_parser("module", help="kernel module helpers")
    subparser.add_argument("--set", type=str, action='append', nargs=2, default=[])
    subparser.add_argument("-o", type=PathArg)
    subparser.add_argument("file", type=PathArg)

    subparser = kernel.add_parser("compress", help="compress rootfs back into initramfs")

    return parser

parser = get_main_parser()
argcomplete.autocomplete(parser)
args = parser.parse_args()

command = dict(args._get_kwargs())

match command.get("subcommand"):
    case "unpack":
        import pwnc.commands.unpack
        pwnc.commands.unpack.command(args)
    case "unstrip":
        import pwnc.commands.unstrip
        pwnc.commands.unstrip.command(args)
    case "patch":
        import pwnc.commands.patch
        pwnc.commands.patch.command(args)
    case "kernel":
        import pwnc.commands.kernel
        match command.get("subcommand.kernel"):
            case "init":
                pwnc.commands.kernel.init.command(args)
            case "compress":
                pass
            case "module":
                pwnc.commands.kernel.module.command(args)