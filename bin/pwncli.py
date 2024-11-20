#!/usr/bin/env python3

from argparse import ArgumentParser, BooleanOptionalAction
import argcomplete
from pathlib import Path
import logging
import pwnc.commands.docker.extract
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

    subparser = subparsers.add_parser("errno", help="interpret errno code")
    subparser.add_argument("code")

    kernel = subparsers.add_parser("kernel", help="kernel pwn setup").add_subparsers()
    kernel.required = True
    kernel.dest = "subcommand.kernel"

    subparser = kernel.add_parser("init", help="kernel pwn setup")
    subparser.add_argument("-i", type=PathArg, help="path to initramfs", dest="initramfs")

    subparser = kernel.add_parser("module", help="kernel module helpers")
    subparser.add_argument("--set", type=str, action='append', nargs=2, default=[])
    subparser.add_argument("-o", type=PathArg)
    subparser.add_argument("file", type=PathArg)

    subparser = kernel.add_parser("compress", help="compress rootfs into initramfs file")
    subparser.add_argument("--rootfs", type=PathArg, required=False)
    subparser.add_argument("--initramfs", type=PathArg, required=False)
    subparser.add_argument("--gzipped", action="store_true")
    subparser.add_argument("--gzip-level", type=int, choices=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])

    subparser = kernel.add_parser("decompress", help="decompress initramfs file into rootfs")
    subparser.add_argument("--rootfs", type=PathArg, required=False)
    subparser.add_argument("--initramfs", type=PathArg, required=False)
    subparser.add_argument("--ignore", action="store_true")
    subparser.add_argument("--save", action="store_true")

    docker = subparsers.add_parser("docker", help="docker utils").add_subparsers()
    docker.required = True
    docker.dest = "subcommand.docker"

    subparser = docker.add_parser("extract", help="extract files from docker image")
    subparser.add_argument("-i", type=str, dest="image")

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
    case "errno":
        import pwnc.commands.errno
        pwnc.commands.errno.command(args)
    case "kernel":
        import pwnc.commands.kernel
        match command.get("subcommand.kernel"):
            case "init":
                pwnc.commands.kernel.init.command(args)
            case "compress":
                pwnc.commands.kernel.compress.command(args)
            case "decompress":
                pwnc.commands.kernel.decompress.command(args)
            case "module":
                pwnc.commands.kernel.module.command(args)
    case "docker":
        import pwnc.commands.docker
        match command.get("subcommand.docker"):
            case "extract":
                pwnc.commands.docker.extract.command(args)