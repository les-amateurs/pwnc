#!/usr/bin/env python3

from pathlib import Path
from subprocess import run
import os
import sys

path = Path(sys.argv[1]).absolute()
kind = run(f"file {path}", shell=True, check=True, capture_output=True, encoding="utf-8").stdout.strip()
if "package" not in kind:
    print(f"removing {path}, {kind}")
    exit(1)
    os.remove(path)