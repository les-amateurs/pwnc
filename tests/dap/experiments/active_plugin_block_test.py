"""Live proof of the active, synchronous, unmodified-GEF stack boundary.

Runtime injection pauses inside GEF's own ``HistoryCommand`` call chain.  The
test then shows that nested GDB work cannot run until that synchronous stack
returns.  This is bounded evidence for why AST lowering only our frames cannot
suspend an arbitrary already-active plugin frame.
"""

import hashlib
import os
import shutil
import sys
import threading
from pathlib import Path

REPOSITORY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
sys.path.insert(0, REPOSITORY)

from pwnc.gdb.dap.transport import DapTransport

TIMEOUT = 15.0
DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_GEF_SHA256 = (
    "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
)


def _skip(reason):
    try:
        import pytest

        pytest.skip(reason)
    except ImportError:
        print(f"SKIP: {reason}")
        raise SystemExit(0) from None


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _initialize(transport, gef_path):
    transport.request(
        "initialize",
        {
            "clientID": "pwnc-active-plugin-boundary",
            "adapterID": "gdb",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "pathFormat": "path",
        },
        timeout=TIMEOUT,
    )
    transport.wait_initialized(timeout=TIMEOUT)
    for source in (
        gef_path,
        Path(__file__).with_name("active_plugin_block_ext.py"),
    ):
        transport.request(
            "evaluate",
            {"expression": "source " + str(source.resolve()), "context": "repl"},
            timeout=TIMEOUT,
        )


def test_active_sync_plugin_blocks_recursive_gdb_work(
    gdb_path="gdb", gef_path=DEFAULT_GEF
):
    gef_path = Path(gef_path).resolve()
    if (
        not shutil.which(gdb_path)
        and not os.path.isfile(gdb_path)
    ) or not gef_path.is_file():
        _skip("live GDB and bata24 GEF are required")

    digest_before = _sha256(gef_path)
    assert digest_before == EXPECTED_GEF_SHA256, (
        "active-plugin boundary probe requires the agreed bata24 GEF source: "
        f"expected {EXPECTED_GEF_SHA256}, got {digest_before}"
    )
    stat_before = gef_path.stat()
    transport = DapTransport(gdb_path)
    waiting = threading.Event()
    returned = threading.Event()
    waiting_body = {}
    returned_body = {}

    def on_waiting(body):
        waiting_body.update(body)
        waiting.set()

    def on_returned(body):
        returned_body.update(body)
        returned.set()

    transport.on("pwncActivePluginWaiting", on_waiting)
    transport.on("pwncActivePluginReturned", on_returned)
    try:
        _initialize(transport, gef_path)

        started = transport.request("pwncActivePluginStart", timeout=TIMEOUT)
        assert started["queued"] is True
        assert waiting.wait(TIMEOUT), "GEF never reached its injected callback wait"
        assert started["dapThreadId"] != waiting_body["gdbThreadId"]
        assert waiting_body["command"].startswith("show commands ")
        assert waiting_body["depth"] == 1

        # This models gdb.execute from that synchronous host callback.  Its
        # GDB-thread work is accepted but cannot interleave with GEF's still-live
        # invoke stack.
        nested_gdb_work = transport.send(
            "evaluate",
            {"expression": "show pagination", "context": "repl"},
        )
        assert not nested_gdb_work.done()
        assert not returned.wait(0.2)
        assert not nested_gdb_work.done()

        # The injected one-second fuse eventually permits GEF to return.  Only
        # after that does the queued nested request complete.
        assert returned.wait(TIMEOUT)
        nested_result = transport.result(nested_gdb_work, timeout=TIMEOUT)
        assert "pagination" in nested_result["result"].lower()
        assert returned_body["gdbThreadId"] == waiting_body["gdbThreadId"]
        assert returned_body["timeNs"] > waiting_body["timeNs"]
    finally:
        transport.close()

    stat_after = gef_path.stat()
    assert _sha256(gef_path) == digest_before
    assert stat_after.st_size == stat_before.st_size
    assert stat_after.st_mtime_ns == stat_before.st_mtime_ns


if __name__ == "__main__":
    test_active_sync_plugin_blocks_recursive_gdb_work()
    print("PASS active unmodified-GEF boundary probe")
