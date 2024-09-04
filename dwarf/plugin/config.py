from pathlib import Path

NAME = "teemo"
# bad to hardcode this, can request from tempfile
TMPDIR = Path("/tmp") / NAME
MAIN_SERVER_DIR = TMPDIR / "main.sock"
# UNIX_SOCK_DIR = TMPDIR / NAME / "sock"
UNIX_SOCK_PATH = TMPDIR / NAME / "comm.sock"