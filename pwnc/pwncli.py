#!/usr/bin/env python3

import sys
from argparse import ArgumentParser, ArgumentTypeError
from pathlib import Path

import argcomplete

from pwnc import util

usage = """\
pwnc (options) [command]
"""

description = """\

"""


class PwncArgumentParser(ArgumentParser):
    """Preserve a sandbox target argv after the conventional ``--`` marker."""

    def parse_known_args(self, args=None, namespace=None):
        values = list(sys.argv[1:] if args is None else args)
        sandbox_start = values[:2] == ["sandbox", "start"]
        target_command = None
        if sandbox_start:
            try:
                separator = values.index("--", 2)
            except ValueError:
                pass
            else:
                target_command = values[separator + 1 :]
                values = values[:separator]

        parsed, extra = super().parse_known_args(values, namespace)
        if sandbox_start:
            parsed.target_command = target_command
            parsed.sandbox_unparsed = tuple(extra)
        return parsed, extra


def PathArg(file):
    return Path(file)

def TemplateArg(**kwargs):
    from pwnc.commands.template import TEMPLATES
    templates =  filter(lambda path: path.is_dir(), TEMPLATES.iterdir())
    templates = map(lambda path: path.name, templates)
    return list(templates)

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
        raise ArgumentTypeError("Expected integer")
    
    if i < 0:
        raise ArgumentTypeError("Must be positive")
    
    return i


def get_main_parser():
    parser = PwncArgumentParser(
        prog="pwnc",
        usage=usage,
        description=description,
    )

    subparsers = parser.add_subparsers()
    # make required (py3.7 API change); vis. https://bugs.python.org/issue16308
    subparsers.required = True
    subparsers.dest = "subcommand"

    """
    Command: init
    """
    subparser = subparsers.add_parser("init", help="setup solve environment")
    subparser.add_argument("template", type=str, default="default", nargs="?").completer = TemplateArg
    subparser.add_argument("--privileged", action="store_true")
    subparser.add_argument("--overwrite", action="store_true")

    """
    Command: template
    """
    subparser = subparsers.add_parser("template", help="instantiate templates")
    subparser.add_argument("template")
    subparser.add_argument("--file", type=PathArg, required=False)
    subparser.add_argument("--libc", type=PathArg, required=False)
    subparser.add_argument("--linker", type=PathArg, required=False)
    subparser.add_argument("--port", type=PositiveInteger, required=False)
    subparser.add_argument("--overwrite", action="store_true")

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
    Command: search
    """
    subparser = subparsers.add_parser(
        "search", help="search for libcs"
    )

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
        "--gzip-level", type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8, 9], default=1
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

    """
    Command: gdb
    """
    gdb = subparsers.add_parser("gdb", help="GDB session tools").add_subparsers()
    gdb.required = True
    gdb.dest = "subcommand.gdb"

    subparser = gdb.add_parser("view", help="connect this terminal to a prepared GDB pool")
    subparser.add_argument("--socket", type=PathArg, dest="socket_path")
    subparser.add_argument("--config", type=PathArg, dest="config_path")
    subparser.add_argument("--name", default="default", help="logical pool name")
    subparser.add_argument("--keep-open", action="store_true")
    subparser.add_argument(
        "--reconnect",
        action="store_true",
        help="switch to a warm pooled GDB when the selected GDB exits",
    )
    subparser.add_argument("--tty", type=PathArg, help="display in this TTY instead of the current terminal")

    """
    Command: sandbox
    """
    sandbox = subparsers.add_parser("sandbox", help="run isolated local challenges").add_subparsers()
    sandbox.required = True
    sandbox.dest = "subcommand.sandbox"

    def sandbox_client_options(command_parser, *, json_output=True):
        command_parser.add_argument("--socket", type=PathArg, dest="socket_path")
        command_parser.add_argument("--config", type=PathArg, dest="config_path")
        command_parser.add_argument("--name", default="default", help="logical sandbox manager name")
        if json_output:
            command_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    subparser = sandbox.add_parser("manager", help="run the persistent sandbox manager")
    subparser.add_argument("--socket", type=PathArg, dest="socket_path")
    subparser.add_argument("--config", type=PathArg, dest="config_path")
    subparser.add_argument("--name", default="default", help="logical sandbox manager name")
    subparser.add_argument(
        "--gdb-pool-size",
        type=PositiveInteger,
        default=0,
        help="number of prepared GDB processes (zero disables the pool)",
    )
    subparser.add_argument("--gdb-name", default="default", help="logical prepared GDB pool name")
    subparser.add_argument("--gdb-path", default="gdb", help="GDB executable used for every prepared process")
    subparser.add_argument(
        "--gdb-execute",
        action="append",
        metavar="COMMAND",
        help="GDB command run on every prepared process before publication (repeatable)",
    )
    subparser.add_argument(
        "--no-gdb-init",
        action="store_false",
        dest="gdb_init",
        default=True,
        help="do not source the normal GDB init files",
    )

    subparser = sandbox.add_parser("start", help="start a configured challenge")
    sandbox_client_options(subparser)
    subparser.add_argument(
        "--profile",
        dest="profile_override",
        help="profile to use (also disambiguates a default-profile command override)",
    )
    state = subparser.add_mutually_exclusive_group()
    state.set_defaults(paused=None)
    state.add_argument("--paused", action="store_true", dest="paused", help="stop at the target exec boundary")
    state.add_argument("--running", action="store_false", dest="paused", help="start without an exec stop")
    stdio = subparser.add_mutually_exclusive_group()
    stdio.set_defaults(stdio=None)
    stdio.add_argument("--pipe", action="store_const", const="pipe", dest="stdio")
    stdio.add_argument("--pty", action="store_const", const="pty", dest="stdio")
    stdio.add_argument("--no-stdio", action="store_const", const="none", dest="stdio")
    subparser.add_argument(
        "--timeout",
        type=float,
        help="maximum seconds to wait for the startup reply (default: no deadline)",
    )
    subparser.add_argument(
        "--env",
        action="append",
        metavar="KEY=VALUE",
        help="override an environment variable (repeatable)",
    )
    subparser.add_argument("profile", nargs="?", help="configured profile name")
    subparser.set_defaults(target_command=None, sandbox_unparsed=())

    subparser = sandbox.add_parser("list", help="list manager-owned challenges")
    sandbox_client_options(subparser)

    subparser = sandbox.add_parser("show", help="show one challenge")
    sandbox_client_options(subparser)
    subparser.add_argument("sandbox_id")

    subparser = sandbox.add_parser("connect", help="interact with an exposed network service")
    sandbox_client_options(subparser, json_output=False)
    subparser.add_argument("sandbox_id")
    subparser.add_argument("port", nargs="?", help="configured port name; optional for a single port")
    subparser.add_argument("--timeout", type=float)

    subparser = sandbox.add_parser("stdio", help="interact with challenge stdio")
    sandbox_client_options(subparser, json_output=False)
    subparser.add_argument("sandbox_id")
    subparser.add_argument("--timeout", type=float)

    subparser = sandbox.add_parser("attach", help="attach the selected prepared GDB")
    sandbox_client_options(subparser)
    subparser.add_argument("sandbox_id")

    for action, help_text in (
        ("resume", "continue a challenge paused at exec"),
        ("kill", "send SIGKILL to a challenge"),
    ):
        subparser = sandbox.add_parser(action, help=help_text)
        sandbox_client_options(subparser)
        subparser.add_argument("sandbox_id")

    subparser = sandbox.add_parser("signal", help="send a signal to a challenge")
    sandbox_client_options(subparser)
    subparser.add_argument("sandbox_id")
    subparser.add_argument("signal", help="signal number or name, such as TERM")

    subparser = sandbox.add_parser("stop", aliases=["close"], help="stop and remove one challenge")
    sandbox_client_options(subparser)
    subparser.add_argument("sandbox_id")

    subparser = sandbox.add_parser("wait", help="wait for one challenge to exit")
    sandbox_client_options(subparser)
    subparser.add_argument("sandbox_id")
    subparser.add_argument("--timeout", type=float)

    subparser = sandbox.add_parser("shutdown", help="stop the manager and all of its challenges")
    sandbox_client_options(subparser)

    subparser = sandbox.add_parser("check", help="check manager discovery and connectivity")
    sandbox_client_options(subparser)

    return parser


def main():
    parser = get_main_parser()
    argcomplete.autocomplete(parser)
    args, extra = parser.parse_known_args()

    command = dict(args._get_kwargs())

    try:
        match command.get("subcommand"):
            case "init":
                import pwnc.commands.init

                pwnc.commands.init.command(args)
            case "template":
                import pwnc.commands.template

                pwnc.commands.template.command(args)
            case "unpack":
                import pwnc.commands.unpack

                pwnc.commands.unpack.command(args)
            case "unstrip":
                import pwnc.commands.unstrip

                pwnc.commands.unstrip.command(args)
            case "search":
                import pwnc.commands.search
                
                pwnc.commands.search.command(args)
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
            case "gdb":
                from pwnc.commands.gdb_view import command as gdb_view

                match command.get("subcommand.gdb"):
                    case "view":
                        return gdb_view(args)
            case "sandbox":
                if extra:
                    parser.error(f"unrecognized arguments: {' '.join(extra)}")
                from pwnc.commands.sandbox import command as sandbox_command

                return sandbox_command(args)
    except RuntimeError as e:
        print(e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
