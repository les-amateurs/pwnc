"""Lossless public ``debug()`` inferior-launch regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb import dap as dap_module
from pwnc.gdb.dap import DapError, debug


GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")

SOURCE = r"""
#include <stdio.h>
#include <string.h>

extern char **environ;

static void dump(const char *kind, int index, const unsigned char *value) {
    printf("%s%d=", kind, index);
    for (size_t i = 0; value[i] != '\0'; ++i)
        printf("%02x", value[i]);
    putchar('\n');
}

int main(int argc, char **argv) {
    printf("ARGC=%d\n", argc);
    for (int i = 0; i < argc; ++i)
        dump("ARG", i, (const unsigned char *) argv[i]);
    int envc = 0;
    while (environ[envc] != NULL)
        ++envc;
    printf("ENVC=%d\n", envc);
    for (int i = 0; i < envc; ++i)
        dump("ENV", i, (const unsigned char *) environ[i]);
    fflush(stdout);
    return 0;
}
"""


@pytest.fixture(params=["-m64", "-m32"], ids=["x86-64", "x86"])
def argv_binary(tmp_path, request):
    if not shutil.which("gcc"):
        pytest.skip("GCC is required")
    source = tmp_path / "argv fixture.c"
    binary = tmp_path / "argv fixture '$;\"\\[]"
    source.write_text(SOURCE)
    try:
        subprocess.run(
            [
                "gcc",
                request.param,
                "-g",
                "-O0",
                "-no-pie",
                "-o",
                str(binary),
                str(source),
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as error:
        pytest.skip(f"compiler does not support {request.param}: {error.stderr!r}")
    return binary


def _hex(value: str | bytes) -> bytes:
    if isinstance(value, str):
        value = os.fsencode(value)
    return value.hex().encode("ascii")


def test_debug_round_trips_argv_and_environment_without_a_shell(argv_binary, tmp_path) -> None:
    if (
        shutil.which(GDB_PATH) is None
        and not (os.path.isfile(GDB_PATH) and os.access(GDB_PATH, os.X_OK))
    ) or not shutil.which("gdbserver"):
        pytest.skip("live GDB and gdbserver are required")

    shell_marker = tmp_path / "shell-evaluation-must-not-happen"
    arguments = [
        "",
        " ",
        "space argument",
        "tab\targument",
        "line\nbreak",
        "*?[abc]",
        "$HOME",
        f";touch {shell_marker}",
        f"$(touch {shell_marker})",
        "quote'\"backslash\\",
        "--looks-like-an-option",
        b"raw-\xff-byte",
    ]
    environment = {
        "PWNC_EXACT_ONE": "space\ttab\nline;$HOME*",
        "PWNC_EXACT_TWO": "quote'\"backslash\\",
        "_PWNC_DAP_INFERIOR_CONFIG": "target value, not launcher control",
        b"PWNC_RAW": b"raw-\xff-value",
    }

    gdb = debug(
        str(argv_binary),
        *arguments,
        env=environment,
        gdb_path=GDB_PATH,
        init=False,
    )
    try:
        stop = gdb.run(timeout=15.0)
        assert stop["reason"] in {"exited", "terminated"}
        output = gdb.target.recvall(timeout=2.0)
    finally:
        gdb.close()

    assert not shell_marker.exists()
    assert f"ARGC={len(arguments) + 1}".encode() in output
    expected_arguments = [os.fsencode(str(argv_binary)), *map(os.fsencode, arguments)]
    for index, argument in enumerate(expected_arguments):
        assert b"ARG%d=" % index + _hex(argument) in output

    assert f"ENVC={len(environment)}".encode() in output
    expected_environment = {_hex(os.fsencode(key) + b"=" + os.fsencode(value)) for key, value in environment.items()}
    actual_environment = {
        line.split(b"=", 1)[1]
        for line in output.splitlines()
        if line.startswith(b"ENV") and not line.startswith(b"ENVC=")
    }
    assert actual_environment == expected_environment


class _FailedGdbserverTube:
    def __init__(self):
        self._lines = [
            b"can't handle command-line argument containing whitespace\n",
            b"Exiting\n",
        ]

    def recvline(self, timeout):
        if self._lines:
            return self._lines.pop(0)
        raise EOFError

    def clean(self, timeout):
        return b""

    def poll(self, block=False):
        return 1


def test_gdbserver_startup_eof_is_a_bounded_dap_error_with_diagnostic() -> None:
    with pytest.raises(DapError, match="whitespace") as caught:
        dap_module._gdbserver_port(_FailedGdbserverTube(), timeout=0.5)
    assert caught.value.body == {
        "gdbserverOutput": ("can't handle command-line argument containing whitespace\nExiting")
    }
