"""Tests for pwnc.gdb.dap.transport — pure framing/error bits plus a gdb-gated
real request/response/event/error round-trip.

    uv run --with colorama --with toml python3 tests/dap/test_transport.py
"""

import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap.transport import DapTransport, DapError, DapTimeout, spawn_argv


def _skip(reason):
    try:
        import pytest
        pytest.skip(reason)
    except ImportError:
        print("SKIP:", reason)
        raise SystemExit(0)


# --- pure (no gdb) --------------------------------------------------------

def test_spawn_argv():
    assert spawn_argv("gdb") == ["gdb", "-q", "--interpreter=dap"]
    assert spawn_argv("/x/gdb", ["-ex", "set foo"]) == \
        ["/x/gdb", "-q", "--interpreter=dap", "-ex", "set foo"]
    assert spawn_argv("gdb", init=False) == \
        ["gdb", "-q", "-nx", "--interpreter=dap"]


@pytest.mark.parametrize("value", [None, 0, 1, "yes"])
def test_spawn_argv_requires_a_boolean_init(value):
    with pytest.raises(TypeError, match="init"):
        spawn_argv("gdb", init=value)


@pytest.mark.parametrize("value", [None, 0, 1, "yes"])
def test_transport_requires_a_boolean_init_before_spawning(value):
    with pytest.raises(TypeError, match="init"):
        DapTransport("not-a-real-gdb", init=value)


def test_error_types():
    e = DapError("boom", command="evaluate", body={"x": 1})
    assert e.command == "evaluate" and e.body == {"x": 1}
    assert isinstance(DapTimeout("t"), DapError)


# --- gdb-gated real round-trip --------------------------------------------

def test_initialize_event_and_request_and_error():
    if not shutil.which("gdb"):
        _skip("gdb not available")
    t = DapTransport("gdb", init=False)
    try:
        seen = []
        t.on("initialized", lambda b: seen.append("initialized"))
        caps = t.request("initialize", {
            "clientID": "pwnc", "adapterID": "gdb", "linesStartAt1": True,
            "columnsStartAt1": True, "pathFormat": "path",
        }, timeout=20)
        assert caps.get("supportsReadMemoryRequest") is True       # response body
        t.wait_initialized(timeout=10)
        assert seen == ["initialized"]                             # event dispatch

        ext = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..", "pwnc", "gdb", "dap", "_ext.py"))
        t.request("evaluate", {"expression": "source " + ext, "context": "repl"})
        arch = t.request("pwncArch")                               # custom request
        assert "ptrbits" in arch and "byteorder" in arch

        # error mapping: an unknown command must raise DapError (not hang)
        try:
            t.request("definitelyNotARequest", {}, timeout=10)
            assert False, "expected DapError"
        except DapError as e:
            assert e.command == "definitelyNotARequest"
    finally:
        t.close()


def test_init_controls_real_gdb_user_init_file_with_isolated_home(tmp_path):
    if not shutil.which("gdb"):
        pytest.skip("gdb not available")

    home = tmp_path / "home"
    home.mkdir()
    marker = "pwnc-isolated-gdbinit-loaded"
    contents = f"set prompt {marker}\n"
    init_file = home / ".gdbinit"
    init_file.write_text(contents)

    environment = os.environ.copy()
    environment["HOME"] = os.fspath(home)
    xdg_config = tmp_path / "xdg-config"
    xdg_config.mkdir()
    environment["XDG_CONFIG_HOME"] = os.fspath(xdg_config)

    prompts = {}
    for enabled in (True, False):
        options = {} if enabled else {"init": False}
        transport = DapTransport("gdb", env=environment, **options)
        try:
            transport.request(
                "initialize",
                {
                    "clientID": "pwnc-init-test",
                    "adapterID": "gdb",
                    "linesStartAt1": True,
                    "columnsStartAt1": True,
                    "pathFormat": "path",
                },
                timeout=20,
            )
            transport.wait_initialized(timeout=10)
            response = transport.request(
                "evaluate",
                {"expression": "show prompt", "context": "repl"},
                timeout=10,
            )
            prompts[enabled] = response["result"]
        finally:
            transport.close()

    assert marker in prompts[True]
    assert marker not in prompts[False]
    assert init_file.read_text() == contents


if __name__ == "__main__":
    test_spawn_argv(); print("PASS test_spawn_argv")
    test_error_types(); print("PASS test_error_types")
    test_initialize_event_and_request_and_error()
    print("PASS test_initialize_event_and_request_and_error")
    print("=== dap transport OK ===")
