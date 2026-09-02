"""Primary interactive-console tests: a REAL kitty gdb console under Xvfb, driven
via kitty remote control. Exercises the console()/console_close() lifecycle, that
console-typed commands flow through the script's callbacks, interleaved control
from both sides, plugin sizing, and auto-close vs keep-open.

Run (this sandbox is headless, so Xvfb is the verification harness only):

    LIBGL_ALWAYS_SOFTWARE=1 xvfb-run -a uv run --with colorama --with toml \
        python3 tests/dap/test_console.py
"""

import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

_LOOP_SRC = ("void ping(){} int counter=41; int main(){ counter=42;"
             " for(int i=0;i<100000;i++){ ping(); for(volatile int j=0;j<3000;j++); }"
             " return 0; }\n")
_BIN = None


def _skip(reason):
    try:
        import pytest
        pytest.skip(reason)
    except ImportError:
        print("SKIP:", reason)
        raise SystemExit(0)


def _need_gui():
    if not shutil.which("gdb") or not shutil.which("gcc"):
        _skip("gdb/gcc not available")
    if not shutil.which("kitty"):
        _skip("kitty not installed")
    if not os.environ.get("DISPLAY"):
        _skip("no DISPLAY — run under `xvfb-run -a` (Xvfb is the test harness)")


def _binary():
    global _BIN
    if _BIN:
        return _BIN
    import tempfile
    d = tempfile.mkdtemp(prefix="pwnc_kconsole_")
    src, b = os.path.join(d, "loopv.c"), os.path.join(d, "loopv")
    with open(src, "w") as f:
        f.write(_LOOP_SRC)
    subprocess.run(["gcc", "-g", "-O0", "-no-pie", "-o", b, src], check=True)
    _BIN = b
    return b


def _kitty_argv(ksock):
    return ["kitty", "--config", "NONE", "-o", "allow_remote_control=yes",
            "-o", "scrollback_lines=2000", "--listen-on", "unix:" + ksock, "-e"]


def _ksend(ksock, text):
    subprocess.run(["kitty", "@", "--to", "unix:" + ksock, "send-text", text],
                   check=True, timeout=10)


def _kget(ksock):
    out = subprocess.run(["kitty", "@", "--to", "unix:" + ksock, "get-text"],
                         capture_output=True, text=True, timeout=10)
    return out.stdout


def _wait_prompt(ksock, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if "(gdb)" in _kget(ksock):
            return True
        time.sleep(0.3)
    return False


def _open(g, ksock, **kw):
    con = g.console(_kitty_argv(ksock), timeout=25, **kw)
    assert _wait_prompt(ksock), "gdb console prompt never appeared in kitty"
    return con


def _ksock(tag):
    return "/tmp/pwnc-kitty-%d-%s.sock" % (os.getpid(), tag)


# ── tests ───────────────────────────────────────────────────────────────────

def test_headless_default_opens_no_console():
    _need_gui()
    from pwnc.gdb.dap import launch
    g = launch(_binary(), init=False)                      # headless default
    try:
        assert g._console is None
    finally:
        g.close()


def test_console_driven_continue_fires_callback():
    _need_gui()
    from pwnc.gdb.dap import launch
    ksock = _ksock("cb")
    g = launch(_binary(), init=False)
    try:
        _open(g, ksock)
        hits = []

        def cb(gg):
            hits.append(int(gg.reg.rip))
            return False                        # stop at the first hit

        g.bp("ping", callback=cb)
        _ksend(ksock, "continue\r")             # user types in the kitty console
        stop = g.wait(timeout=25)
        assert stop.get("reason") == "breakpoint", stop
        assert hits, "callback never fired for a console-typed continue"
    finally:
        g.close()


def test_interleaved_script_and_console():
    _need_gui()
    from pwnc.gdb.dap import launch
    ksock = _ksock("inter")
    g = launch(_binary(), init=False)
    try:
        _open(g, ksock)
        # console sets a breakpoint; the SCRIPT continues into it
        _ksend(ksock, "break ping\r")
        for _ in range(60):
            if "ping" in g.execute("info breakpoints"):
                break
            time.sleep(0.1)
        assert "ping" in g.execute("info breakpoints")
        stop = g.cont()
        assert stop.get("reason") == "breakpoint" and g.frame().name() == "ping", stop
        # console single-steps; the script collects the stop
        p = g.reg.rip
        _ksend(ksock, "stepi\r")
        g.wait(timeout=15)
        assert g.reg.rip != p
        # script single-steps
        p2 = g.reg.rip
        g.stepi()
        assert g.reg.rip != p2
        # shared state: console `print counter` matches the script's view
        before = _kget(ksock)
        _ksend(ksock, "print counter\r")
        time.sleep(0.6)
        shown = _kget(ksock)[len(before):]
        assert "42" in shown, shown
        assert int(g.sym.counter) == 42
    finally:
        g.close()


def test_plugin_sizing_matches_window():
    _need_gui()
    from pwnc.gdb.dap import launch
    ksock = _ksock("size")
    g = launch(_binary(), init=False)
    try:
        _open(g, ksock)
        before = _kget(ksock)
        _ksend(ksock, "show width\r")
        time.sleep(0.6)
        shown = _kget(ksock)[len(before):]
        m = re.search(r"line is (\d+)", shown)
        assert m, "could not read console width: %r" % shown
        width = int(m.group(1))
        # gdb's console width was set from the real kitty window (not the 80 default)
        assert width > 0 and width != 80, width
    finally:
        g.close()


def test_auto_close_on_exit():
    _need_gui()
    from pwnc.gdb.dap import launch
    g = launch(_binary(), init=False)
    con = _open(g, _ksock("close"))
    g.close()                                   # gdb gone -> agent exits -> window closes
    end = time.time() + 8
    while time.time() < end and con.proc.poll() is None:
        time.sleep(0.2)
    assert con.proc.poll() is not None, "kitty window did not auto-close on gdb exit"


def test_keep_open_keeps_window():
    _need_gui()
    from pwnc.gdb.dap import launch
    g = launch(_binary(), init=False)
    con = _open(g, _ksock("keep"), keep_open=True)
    try:
        g.close()
        time.sleep(2)
        assert con.proc.poll() is None, "kitty window closed despite keep_open=True"
    finally:
        con.kill()                              # explicit teardown still works


def test_console_close_keeps_session():
    _need_gui()
    from pwnc.gdb.dap import launch
    ksock = _ksock("cc")
    g = launch(_binary(), init=False)
    try:
        con = g.console(_kitty_argv(ksock), timeout=25)
        assert _wait_prompt(ksock)
        g.console_close()                       # graceful close, session stays up
        end = time.time() + 6
        while time.time() < end and con.proc.poll() is None:
            time.sleep(0.2)
        assert con.proc.poll() is not None, "console_close did not close the window"
        assert g._console is con
        assert con.endpoint_alive and not con.viewer_connected
        assert int(g.sym.main) > 0              # gdb session still responsive
        g.execute("info breakpoints")
    finally:
        g.close()


def test_history_saved_on_session_close():
    _need_gui()
    from pwnc.gdb.dap import launch
    histfile = "/tmp/pwnc-hist-%d" % os.getpid()
    try:
        os.unlink(histfile)
    except OSError:
        pass
    ksock = _ksock("hist")
    g = launch(_binary(), init=False)
    g.console(_kitty_argv(ksock), timeout=25)
    assert _wait_prompt(ksock)
    _ksend(ksock, "set history filename %s\r" % histfile)
    time.sleep(0.4)
    _ksend(ksock, "print 0xFEEDFACE\r")         # a command typed in the console
    time.sleep(0.6)
    g.close()                                   # clean session exit -> gdb saves history
    time.sleep(1.0)
    assert os.path.exists(histfile), "history not written on clean session close"
    with open(histfile) as history:
        assert "feedface" in history.read().lower()


_TESTS = [v for k, v in sorted(globals().items())
          if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    failed = 0
    for fn in _TESTS:
        try:
            fn()
            print("PASS", fn.__name__)
        except SystemExit:
            raise
        except BaseException as e:
            failed += 1
            print("FAIL", fn.__name__, "->", repr(e))
        subprocess.run(["pkill", "-9", "kitty"], capture_output=True)
    print("=== %d/%d passed ===" % (len(_TESTS) - failed, len(_TESTS)))
    sys.exit(1 if failed else 0)
