import subprocess
import os
import shutil

from argparse import Namespace as Args
from pathlib import Path
from os.path import expanduser

from . import err
from . import config

def run(cmd: str, check=True, capture_output=False, encoding="utf-8", cwd=None):
    return subprocess.run(cmd, shell=True, check=check, capture_output=capture_output, encoding=encoding, cwd=cwd)

def backup(file: Path):
    backup_directory = Path("_backup")
    backup_directory.mkdir(parents=True, exist_ok=True)
    backup = backup_directory / str(file).replace(os.path.sep, "-")
    shutil.copyfile(file, backup, follow_symlinks=True)

def ensure_exists(file: Path):
    if not file.exists():
        err.fatal(f"{file} does not exist")