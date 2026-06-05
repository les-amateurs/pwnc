import subprocess
import os
import stat
import shutil
import re
import secrets
from argparse import Namespace as Args
from pathlib import Path
from os.path import expanduser
from . import err
from . import config
from . import cache


def run(
    cmd: str | list[str],
    check: bool = True,
    capture_output: bool = False,
    encoding: str | None = "utf-8",
    cwd: Path | None = None,
    shell: bool = True,
    stdout=None,
    stdin=None,
    input: bytes | None = None,
    extra_env: dict = None,
):
    env = os.environ.copy()
    if extra_env is not None:
        env.update(extra_env)
    return subprocess.run(
        cmd,
        shell=shell,
        check=check,
        capture_output=capture_output,
        encoding=encoding,
        cwd=cwd,
        stdout=stdout,
        stdin=stdin,
        input=input,
        env=env,
    )


def backup(file: Path):
    backup_directory = Path("_backup")
    backup_directory.mkdir(parents=True, exist_ok=True)
    backup = backup_directory / str(file).replace(os.path.sep, "-")
    shutil.copyfile(file, backup, follow_symlinks=True)


def ensure_exists(file: Path):
    if not file.exists():
        err.fatal(f"{file} does not exist")


def random_tmpdir(prefix="tmp-"):
    """
    Caller is responsible for cleaning up the directory.
    """
    token = secrets.token_hex(16)
    tmpdir = Path(f"{prefix}{token}")
    tmpdir.mkdir(exist_ok=False)
    return tmpdir


def find_recursive(pattern: str, callback = None, target = None) -> list[Path]:
    regex = re.compile(pattern)
    matches = []
    for path, dirlist, filelist in os.walk(target or "."):
        path = Path(path)
        for file in filelist:
            if regex.search(file):
                full = path / file
                if callback and not callback(full):
                    continue
                matches.append(full)
    return matches


def sanitize_path(path: Path):
    if not path.is_absolute():
        path = Path("/") / path
    return Path(os.path.normpath(path)).relative_to("/")


def resolve_path(root: Path, path: Path):
    root = Path(root)
    path = Path(path)
    if root.is_symlink():
        err.fatal(f"root cannot be a symlink: {root}")
    resolved = Path("/")
    parts = list(reversed(path.parts))
    while parts:
        part = parts.pop()
        if part == "..":
            resolved = resolved.parent
        elif part == ".":
            pass
        else:
            new = resolved / part
            real = root / new.relative_to("/")
            if real.is_symlink():
                link = real.readlink()
                parts.extend(list(reversed(link.parts)))
            elif not real.parent.is_dir():
                raise NotADirectoryError("Not a directory: resolving {!r}".format(real.as_posix()))
            else:
                resolved = new
    return root / resolved.relative_to("/")


def make_executable(file: Path):
    mode = file.stat().st_mode
    wanted = mode | stat.S_IXGRP | stat.S_IXOTH | stat.S_IXUSR
    if mode != wanted:
        file.chmod(wanted)