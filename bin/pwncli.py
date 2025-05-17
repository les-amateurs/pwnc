#!/usr/bin/env python3

from argparse import ArgumentParser, BooleanOptionalAction, ArgumentTypeError
import argcomplete
import colorama
from pathlib import Path
import logging
import pwnc.config
from pwnc import util

logger = logging.getLogger("pwnc")
logger.setLevel(logging.INFO)
channel = logging.StreamHandler()


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    ERROR = (
        colorama.Fore.WHITE
        + colorama.Back.RED
        + "ERROR"
        + colorama.Fore.RESET
        + colorama.Back.RESET
    )
    WARNING = colorama.Fore.YELLOW + "!" + colorama.Fore.RESET
    INFO = colorama.Fore.BLUE + "*" + colorama.Fore.RESET
    DEBUG = colorama.Fore.GREEN + "+" + colorama.Fore.RESET

    FORMATS = {
        logging.ERROR: f"[{ERROR}] %(msg)s",
        logging.WARNING: f"[{WARNING}] %(msg)s",
        logging.INFO: f"[{INFO}] %(msg)s",
        logging.DEBUG: f"[{DEBUG}] %(msg)s",
        "DEFAULT": "%(msg)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


channel.setFormatter(CustomFormatter())
logger.addHandler(channel)

usage = """\
pwnc (options) [command]
"""

description = """\

"""


def PathArg(file):
    return Path(file)


def DockerImageArg(**kwargs):
    try:
        out: str = util.run("docker images", capture_output=True).stdout
    except:
        return None
    lines = out.splitlines()[1:]
    images = list(map(lambda l: ":".join(l.split(maxsplit=2)[:2]), lines))
    return images

def PositiveInteger(arg):
    try:
        i = int(arg)
    except:
        raise ArgumentTypeError(f"Expected integer")
    
    if i < 0:
        raise ArgumentTypeError(f"Must be positive")
    
    return i


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

    """
    Command: unpack
    """
    subparser = subparsers.add_parser(
        "unpack", help="unpack and initialize from distribution"
    )
    subparser.add_argument("file", type=PathArg)
    subparser.add_argument("name", type=PathArg, nargs="?", default=None)

    """
    Command: unstrip
    """
    subparser = subparsers.add_parser(
        "unstrip", help="unstrip binaries by adding debuginfo"
    )
    subparser.add_argument("file", type=PathArg)
    subparser.add_argument("--libc", action="store_true")
    subparser.add_argument("--save", action="store_true")
    subparser.add_argument("--force", action="store_true")

    """
    Command: patch
    """
    subparser = subparsers.add_parser("patch", help="patch binaries")
    subparser.add_argument("--bits", choices=[32, 64], help="override elf 32 or 64")
    subparser.add_argument(
        "--endian", choices=["big", "little"], help="override endianness"
    )
    subparser.add_argument("--rpath", type=str, help="new rpath")
    subparser.add_argument("--interp", type=str, help="new interpreter path")
    subparser.add_argument("file", type=PathArg)
    subparser.add_argument("outfile", type=PathArg, nargs="?")

    """
    Command: errno
    """
    subparser = subparsers.add_parser("errno", help="interpret errno code")
    subparser.add_argument("code")

    """
    Command: kernel
    """
    kernel = subparsers.add_parser("kernel", help="kernel pwn setup").add_subparsers()
    kernel.required = True
    kernel.dest = "subcommand.kernel"

    subparser = kernel.add_parser("init", help="kernel pwn setup")
    subparser.add_argument(
        "-i", type=PathArg, help="path to initramfs", dest="initramfs"
    )

    subparser = kernel.add_parser("module", help="kernel module helpers")
    subparser.add_argument("--set", type=str, action="append", nargs=2, default=[])
    subparser.add_argument("-o", type=PathArg)
    subparser.add_argument("file", type=PathArg)

    subparser = kernel.add_parser(
        "compress", help="compress rootfs into initramfs file"
    )
    subparser.add_argument("--rootfs", type=PathArg, required=False)
    subparser.add_argument("--initramfs", type=PathArg, required=False)
    subparser.add_argument("--gzipped", action="store_true")
    subparser.add_argument(
        "--gzip-level", type=int, choices=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    )

    subparser = kernel.add_parser(
        "decompress", help="decompress initramfs file into rootfs"
    )
    subparser.add_argument("--rootfs", type=PathArg, required=False)
    subparser.add_argument("--initramfs", type=PathArg, required=False)
    subparser.add_argument("--ignore", action="store_true")
    subparser.add_argument("--save", action="store_true")

    subparser = kernel.add_parser("template", help="kernel exploit template")
    subparser.add_argument("kind", type=str, choices=["common"])

    """
    Command: docker
    """
    docker = subparsers.add_parser("docker", help="docker utils").add_subparsers()
    docker.required = True
    docker.dest = "subcommand.docker"

    subparser = docker.add_parser("extract", help="extract files from docker image")
    subparser.add_argument("image", type=str).completer = DockerImageArg
    subparser.add_argument("file", type=str)

    """
    Command: shellc
    """
    subparser = subparsers.add_parser("shellc", help="compile c to shellcode")
    subparser.add_argument(
        "backend",
        type=str,
        choices=["gcc", "musl", "zig"],
        default="gcc",
        help="compiler backend",
    )
    subparser.add_argument("files", nargs="*", help="input files")
    subparser.add_argument(
        "-o", type=PathArg, required=True, dest="output", help="output file"
    )

    group = subparser.add_mutually_exclusive_group()
    group.set_defaults(pie=True)
    group.add_argument(
        "-pie",
        action="store_true",
        dest="pie",
        help="build position independent executable",
    )
    group.add_argument(
        "-no-pie",
        action="store_false",
        dest="pie",
        help="do not build position independent executable",
    )

    subparser.add_argument("-target", type=str, help="target triple")

    """
    Command: elf
    """
    subparser = subparsers.add_parser("elf", help="build elf from shellcode")
    subparser.add_argument(
        "-m", type=str, required=True, dest="machine", help="elf machine"
    )
    subparser.add_argument(
        "-b", type=int, required=False, dest="bits", choices=[32, 64], help="elf bits"
    )
    subparser.add_argument(
        "-e",
        type=str,
        required=False,
        dest="endian",
        choices=["little", "big"],
        help="elf endianness",
    )
    subparser.add_argument("file", type=PathArg)

    """
    Command: swarm
    """
    swarm = subparsers.add_parser("swarm", help="synchronized terminal control").add_subparsers()
    swarm.required = True
    swarm.dest = "subcommand.swarm"

    subparser = swarm.add_parser("start", help="start swarm")
    subparser.add_argument("count", type=PositiveInteger)

    subparser = swarm.add_parser("kill", help="kill swarm")

    subparser = swarm.add_parser("config", help="config swarm")
    subparser.add_argument("--font-size", type=PositiveInteger)

    subparser = swarm.add_parser("exec", help="execute command on swarm")
    subparser.add_argument("command", type=str)

    subparser = swarm.add_parser("signal", help="signal swarm")
    subparser.add_argument("signal", type=str, nargs="?")

    return parser


parser = get_main_parser()
argcomplete.autocomplete(parser)
args, extra = parser.parse_known_args()

command = dict(args._get_kwargs())

try:
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
                case "template":
                    pwnc.commands.kernel.template.command(args)
        case "docker":
            import pwnc.commands.docker.extract

            match command.get("subcommand.docker"):
                case "extract":
                    pwnc.commands.docker.extract.command(args)
        case "shellc":
            import pwnc.commands.shellc

            pwnc.commands.shellc.command(args, extra)
        case "elf":
            import pwnc.commands.elf

            pwnc.commands.elf.command(args)
        case "swarm":
            import pwnc.commands.swarm
            pwnc.commands.swarm.command(args)
except RuntimeError:
    pass