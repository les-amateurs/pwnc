"""End-to-end tests for pwnc.gdb.dap, driving a real gdb over DAP.

Uses the verified local launch() path (no gdbserver/pwntools needed). Skips
cleanly if gdb (with DAP) is unavailable. Runnable directly or under pytest:

    uv run --with colorama --with toml python3 tests/dap/test_e2e.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

MI_TARGET = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "pwnc", "gdb", "mi", "examples", "target"))

_BF_SRC = r"""
struct Flags { unsigned a:4; unsigned b:4; unsigned c:8; };
struct Flags flags = { 0xA, 0x5, 0x42 };
struct Node { int val; struct Node *next; };
struct Node n2 = { 22, 0 };
struct Node n1 = { 11, &n2 };
int main(void){ volatile int x = flags.a + n1.val; return x; }
"""


def _have_gdb_dap():
    # gdb 14+ ships the DAP interpreter; assume present if gdb is.
    return shutil.which("gdb") is not None


def _skip(reason):
    try:
        import pytest
        pytest.skip(reason)
    except ImportError:
        print("SKIP:", reason)
        raise SystemExit(0)


def test_typed_globals_and_control():
    if not _have_gdb_dap():
        _skip("gdb with DAP not available")
    from pwnc.gdb.dap import launch

    g = launch(MI_TARGET, init=False)
    try:
        assert int(g.sym.counter) == 0
        assert g.sym.origin.x == 10 and g.sym.origin.y == 20
        assert int(g.sym.current_color) == 1
        assert bytes(g.sym.message[i] for i in range(5)) == b"hello"   # __index__

        old = g.reg.rax
        g.reg.rax = 0xdead
        assert g.reg.rax == 0xdead
        g.reg.rax = old

        before = g.reg.rip
        g.nexti()                          # nexti() waits by default
        assert g.reg.rip != before

        assert g.frame().name() == "main"

        g.write(g.sym.origin._provider.address, (999).to_bytes(4, "little"))
        assert g.sym.origin.x == 999

        # event-driven breakpoint-callback loop: must not hang or lose stops
        hits = []
        g.bp("update_origin", callback=lambda gg: hits.append(int(gg.sym.counter)))
        stop = g.cont()                    # cont() waits and returns the stop
        assert len(hits) == 5, hits
        assert stop.get("reason") in ("exited", "terminated"), stop
    finally:
        g.close()


def test_bitfields_and_pointers():
    if not _have_gdb_dap():
        _skip("gdb with DAP not available")
    if not shutil.which("gcc"):
        _skip("gcc not available to build the bitfield/pointer fixture")
    from pwnc.gdb.dap import launch

    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "bf.c")
    binpath = os.path.join(tmp, "bf")
    with open(src, "w") as f:
        f.write(_BF_SRC)
    subprocess.run(["gcc", "-g", "-O0", "-no-pie", "-o", binpath, src], check=True)

    g = launch(binpath, init=False)
    try:
        fl = g.sym.flags
        assert (int(fl.a), int(fl.b), int(fl.c)) == (0xA, 0x5, 0x42)
        fl.a = 3                              # bitfield write preserves neighbor
        assert int(g.sym.flags.a) == 3 and int(g.sym.flags.b) == 0x5

        n1 = g.sym.n1
        assert int(n1.val) == 11
        assert int(n1.next[0].val) == 22      # pointer deref via provider.rebase
    finally:
        g.close()


def test_remote_attach_path():
    """The debug() path: gdbserver + DAP target-remote attach (no pwntools)."""
    if not _have_gdb_dap():
        _skip("gdb with DAP not available")
    if not shutil.which("gdbserver"):
        _skip("gdbserver not available")
    import socket
    import time
    from pwnc.gdb.dap import Gdb
    from pwnc.gdb.dap.transport import DapTransport

    sk = socket.socket(); sk.bind(("127.0.0.1", 0)); port = sk.getsockname()[1]; sk.close()
    gs = subprocess.Popen(
        ["gdbserver", "--once", "--no-startup-with-shell", "127.0.0.1:%d" % port, MI_TARGET],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1)
        g = Gdb(DapTransport("gdb", init=False))
        g._initialize()
        g._connect_remote(MI_TARGET, "127.0.0.1:%d" % port)
        try:
            g.bp("main")
            assert g.run().get("reason") == "breakpoint"   # run() waits + returns
            assert int(g.sym.counter) == 0 and g.sym.origin.x == 10
        finally:
            g.close()
    finally:
        gs.kill()


if __name__ == "__main__":
    test_typed_globals_and_control()
    print("PASS test_typed_globals_and_control")
    test_bitfields_and_pointers()
    print("PASS test_bitfields_and_pointers")
    test_remote_attach_path()
    print("PASS test_remote_attach_path")
    print("=== dap e2e OK ===")
