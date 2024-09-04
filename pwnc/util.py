import subprocess
import os
import shutil

from argparse import Namespace as Args
from pathlib import Path

from . import err

def run(cmd: str, check=True, capture_output=False, encoding="utf-8", cwd=None):
    return subprocess.run(cmd, shell=True, check=check, capture_output=capture_output, encoding=encoding, cwd=cwd)

def backup(file: Path):
    backup_directory = Path("_backup")
    backup_directory.mkdir(parents=True, exist_ok=True)
    backup = backup_directory / str(file).replace(os.path.sep, "-")
    shutil.copyfile(file, backup, follow_symlinks=True)