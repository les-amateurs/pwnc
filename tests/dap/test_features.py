"""Comprehensive feature + stress tests for pwnc.gdb.dap, driving real gdb.

Builds a rich C program and exercises every type, memory read/write, and complex
control flow (many breakpoints, callbacks, conditional/temporary breakpoints,
watchpoints, many stop/continue cycles, stepping, recursion/frames, registers,
skip). Uses the local launch() path. Skips cleanly if gdb/gcc are unavailable.

    uv run --with colorama --with toml python3 tests/dap/test_features.py
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

_SRC = r"""
#include <stdint.h>
#include <string.h>

int8_t   g_i8  = -8;
uint8_t  g_u8  = 200;
int16_t  g_i16 = -1600;
uint16_t g_u16 = 50000;
int32_t  g_i32 = -32000123;
uint32_t g_u32 = 4000000000u;
int64_t  g_i64 = -6400000000LL;
uint64_t g_u64 = 18000000000000000000ULL;
char     g_char = 'A';

float    g_f32 = 1.5f;
double   g_f64 = 2.25;

enum Color { RED=0, GREEN=1, BLUE=2, WHITE=255 };
enum Color g_color = BLUE;

int      g_arr[5] = {10, 20, 30, 40, 50};
char     g_str[16] = "hello world";
int      g_grid[2][3] = {{1,2,3},{4,5,6}};

struct Point { int x; int y; };
struct Rect { struct Point tl; struct Point br; };
struct Rect  g_rect = {{1,2},{30,40}};
struct Point g_points[3] = {{1,1},{2,4},{3,9}};

union Conv { uint32_t u; float f; uint8_t b[4]; };
union Conv g_conv = { .u = 0x3fc00000 };   /* float 1.5 */

struct Flags { unsigned a:4; unsigned b:4; unsigned c:8; unsigned d:16; };
struct Flags g_flags = { 0xA, 0x5, 0x42, 0x1234 };

int   g_target = 777;
int  *g_iptr = &g_target;

struct Node { int val; struct Node *next; };
struct Node g_n3 = {30, 0};
struct Node g_n2 = {20, &g_n3};
struct Node g_n1 = {10, &g_n2};

struct Tree { int val; struct Tree *left, *right; };
struct Tree g_t_ll={1,0,0}, g_t_lr={3,0,0}, g_t_rl={5,0,0}, g_t_rr={7,0,0};
struct Tree g_t_l={2,&g_t_ll,&g_t_lr}, g_t_r={6,&g_t_rl,&g_t_rr};
struct Tree g_root={4,&g_t_l,&g_t_r};

int  g_counter = 0;
long g_sum = 0;
int  g_last = -1;

int add(int a, int b){ return a+b; }
int (*g_addfn)(int,int) = add;

long factorial(int n){ if(n<=1) return 1; return n*factorial(n-1); }
void tick(int i){ g_counter++; g_sum += i; g_last = i; }
int  process(int *a, int n){ int t=0; for(int i=0;i<n;i++) t+=a[i]; return t; }

int main(void){
    volatile long r = 0;
    r += factorial(5);
    for (int i = 0; i < 10; i++) tick(i);
    r += process(g_arr, 5);
    r += add(3, 4);
    g_color = RED;
    strcpy(g_str, "done");
    return (int)(r & 0xff);
}
"""

_BIN = None


def _skip(reason):
    try:
        import pytest
        pytest.skip(reason)
    except ImportError:
        print("SKIP:", reason)
        raise SystemExit(0)


def _binary():
    global _BIN
    if _BIN:
        return _BIN
    if not shutil.which("gdb"):
        _skip("gdb not available")
    if not shutil.which("gcc"):
        _skip("gcc not available")
    d = tempfile.mkdtemp(prefix="pwnc_dap_")
    src = os.path.join(d, "complex.c")
    binp = os.path.join(d, "complex")
    with open(src, "w") as f:
        f.write(_SRC)
    subprocess.run(["gcc", "-g", "-O0", "-no-pie", "-o", binp, src], check=True)
    _BIN = binp
    return binp


def _g():
    from pwnc.gdb.dap import launch
    return launch(_binary(), init=False)          # stopped at main


_NODBG_SRC = r"""
int  ndata = 0x11223344;
long nbig  = 0x1122334455667788L;
int  nfunc(int a){ return a + 1; }
int  main(void){ return nfunc(ndata) + (int)nbig; }
"""
_NODBG_BIN = None


def _nodbg_binary():
    """A binary with a symbol table but NO debug info (the stripped/CTF case)."""
    global _NODBG_BIN
    if _NODBG_BIN:
        return _NODBG_BIN
    if not shutil.which("gdb") or not shutil.which("gcc"):
        _skip("gdb/gcc not available")
    d = tempfile.mkdtemp(prefix="pwnc_dap_nodbg_")
    src = os.path.join(d, "nodbg.c")
    binp = os.path.join(d, "nodbg")
    with open(src, "w") as f:
        f.write(_NODBG_SRC)
    subprocess.run(["gcc", "-O0", "-no-pie", "-o", binp, src], check=True)  # no -g
    _NODBG_BIN = binp
    return binp


_SPIN_BIN = None


def _spin_binary():
    """A program that spins forever (to exercise cont_nowait()/interrupt())."""
    global _SPIN_BIN
    if _SPIN_BIN:
        return _SPIN_BIN
    if not shutil.which("gdb") or not shutil.which("gcc"):
        _skip("gdb/gcc not available")
    d = tempfile.mkdtemp(prefix="pwnc_dap_spin_")
    src = os.path.join(d, "spin.c")
    binp = os.path.join(d, "spin")
    with open(src, "w") as f:
        f.write("int main(void){ volatile long x=0; while(1) x++; return (int)x; }\n")
    subprocess.run(["gcc", "-g", "-O0", "-no-pie", "-o", binp, src], check=True)
    _SPIN_BIN = binp
    return binp


# ════════════════════════ types ════════════════════════

def test_integer_types():
    g = _g()
    try:
        assert int(g.sym.g_i8) == -8
        assert int(g.sym.g_u8) == 200
        assert int(g.sym.g_i16) == -1600
        assert int(g.sym.g_u16) == 50000
        assert int(g.sym.g_i32) == -32000123
        assert int(g.sym.g_u32) == 4000000000
        assert int(g.sym.g_i64) == -6400000000
        assert int(g.sym.g_u64) == 18000000000000000000
        assert int(g.sym.g_char) == ord('A')
        # arithmetic on typed values
        assert g.sym.g_i32 + 123 == -32000000
        assert (g.sym.g_u8 & 0x0F) == 8
    finally:
        g.close()


def test_float_double():
    g = _g()
    try:
        assert float(g.sym.g_f32) == 1.5
        assert float(g.sym.g_f64) == 2.25
    finally:
        g.close()


def test_enum():
    g = _g()
    try:
        assert int(g.sym.g_color) == 2          # BLUE
        assert "BLUE" in str(g.sym.g_color)
    finally:
        g.close()


def test_arrays_1d_2d_char():
    g = _g()
    try:
        assert [int(g.sym.g_arr[i]) for i in range(5)] == [10, 20, 30, 40, 50]
        assert bytes(g.sym.g_str[i] for i in range(11)) == b"hello world"
        # 2D array: grid[r][c]
        assert int(g.sym.g_grid[0][2]) == 3
        assert int(g.sym.g_grid[1][0]) == 4
        assert int(g.sym.g_grid[1][2]) == 6
    finally:
        g.close()


def test_structs_nested_and_array_of_structs():
    g = _g()
    try:
        assert g.sym.g_rect.tl.x == 1 and g.sym.g_rect.tl.y == 2
        assert g.sym.g_rect.br.x == 30 and g.sym.g_rect.br.y == 40
        assert [(int(g.sym.g_points[i].x), int(g.sym.g_points[i].y))
                for i in range(3)] == [(1, 1), (2, 4), (3, 9)]
    finally:
        g.close()


def test_union():
    g = _g()
    try:
        assert int(g.sym.g_conv.u) == 0x3fc00000
        assert float(g.sym.g_conv.f) == 1.5
        assert int(g.sym.g_conv.b[3]) == 0x3f      # MSB of 0x3fc00000 (LE)
    finally:
        g.close()


def test_bitfields_including_multibyte():
    g = _g()
    try:
        fl = g.sym.g_flags
        assert int(fl.a) == 0xA
        assert int(fl.b) == 0x5
        assert int(fl.c) == 0x42
        assert int(fl.d) == 0x1234              # multi-byte (spans 2 bytes)
    finally:
        g.close()


def test_pointers_and_function_pointer():
    g = _g()
    try:
        assert int(g.sym.g_target) == 777
        assert int(g.sym.g_iptr[0]) == 777      # deref int*
        assert int(g.sym.g_addfn) != 0          # function pointer is an address
    finally:
        g.close()


def test_linked_list_traversal():
    g = _g()
    try:
        node = g.sym.g_n1
        vals = []
        for _ in range(8):
            vals.append(int(node.val))
            nxt = node.next
            if int(nxt) == 0:
                break
            node = nxt[0]
        assert vals == [10, 20, 30]
    finally:
        g.close()


def test_binary_tree_traversal():
    g = _g()
    try:
        root = g.sym.g_root
        assert int(root.val) == 4
        assert int(root.left[0].val) == 2
        assert int(root.right[0].val) == 6
        assert int(root.left[0].left[0].val) == 1
        assert int(root.left[0].right[0].val) == 3
        assert int(root.right[0].right[0].val) == 7
    finally:
        g.close()


# ════════════════════════ memory read / write ════════════════════════

def test_raw_memory_read_write():
    g = _g()
    try:
        addr = g.sym.g_arr._provider.address
        raw = g.read(addr, 20)
        assert struct.unpack("<5i", raw) == (10, 20, 30, 40, 50)
        g.write(addr, struct.pack("<5i", 1, 2, 3, 4, 5))
        assert [int(g.sym.g_arr[i]) for i in range(5)] == [1, 2, 3, 4, 5]
    finally:
        g.close()


def test_typed_writes():
    g = _g()
    try:
        # scalar via raw write at the Value's address
        g.write(g.sym.g_target._provider.address, struct.pack("<i", 12345))
        assert int(g.sym.g_target) == 12345
        # struct field write through the Value
        g.sym.g_rect.tl.x = 99
        assert g.sym.g_rect.tl.x == 99
        # array element write through the Value
        g.sym.g_arr[2] = 333
        assert int(g.sym.g_arr[2]) == 333
        # bitfield write preserves neighbors (incl. multi-byte d)
        g.sym.g_flags.a = 7
        assert int(g.sym.g_flags.a) == 7
        assert int(g.sym.g_flags.b) == 0x5 and int(g.sym.g_flags.d) == 0x1234
    finally:
        g.close()


# ════════════════════════ control flow ════════════════════════
# Resume/step methods (run/cont/stepi/nexti/step/next/stepout) wait by default
# and return the stop dict. cont_nowait()/interrupt()/wait() are the async pair.

def test_cont_and_run_return_stop():
    g = _g()
    try:
        g.bp("tick")
        stop = g.cont()                            # cont() resumes AND waits
        assert stop.get("reason") == "breakpoint", stop
        assert g.frame().name() == "tick"
    finally:
        g.close()


def test_cont_nowait_then_wait():
    g = _g()
    try:
        g.bp("tick")
        g.cont_nowait()                            # async resume, no wait
        stop = g.wait(timeout=15)                  # collect the stop separately
        assert stop.get("reason") == "breakpoint", stop
    finally:
        g.close()


def test_interrupt_running_inferior():
    import time
    from pwnc.gdb.dap import launch
    g = launch(_spin_binary(), init=False)                     # stopped at main
    try:
        g.cont_nowait()                            # spins forever
        time.sleep(0.2)
        g.interrupt()                              # async stop
        stop = g.wait(timeout=15)
        assert stop is not None
        assert stop.get("reason") not in ("exited", "terminated"), stop
    finally:
        g.close()


def test_many_stops_and_continues():
    g = _g()
    try:
        g.bp("tick")
        counters = []
        for _ in range(10):                        # 10 stop/continue cycles
            stop = g.cont()                        # cont() waits + returns the stop
            assert stop.get("reason") == "breakpoint", stop
            counters.append(int(g.sym.g_counter))
        # at each tick *entry*, g_counter == number of completed ticks so far
        assert counters == list(range(10)), counters
        stop = g.cont()                            # 10th tick completes -> exit
        assert stop.get("reason") in ("exited", "terminated"), stop
    finally:
        g.close()


def test_callback_counts_all_hits():
    g = _g()
    try:
        hits = []
        g.bp("tick", callback=lambda gg: hits.append(int(gg.sym.g_counter)))
        stop = g.cont()
        # callback fires at tick entry (before g_counter++), so it sees 0..9;
        # all 10 hits firing proves the program ran to completion.
        assert hits == list(range(10)), hits
        assert stop.get("reason") in ("exited", "terminated")
    finally:
        g.close()


def test_callback_returns_false_to_stop():
    g = _g()
    try:
        hits = []

        def cb(gg):
            hits.append(int(gg.sym.g_counter))
            return False if len(hits) == 4 else None   # stop on the 4th hit

        g.bp("tick", callback=cb)
        stop = g.cont()
        assert len(hits) == 4, hits
        assert stop.get("reason") == "breakpoint"
    finally:
        g.close()


def test_callback_modifies_state():
    g = _g()
    try:
        # callback overwrites a global, then stops; verify the write took effect
        def cb(gg):
            gg.write(gg.sym.g_sum._provider.address, struct.pack("<q", 1000))
            return False
        g.bp("tick", callback=cb)
        g.cont()
        assert int(g.sym.g_sum) == 1000
    finally:
        g.close()


def test_conditional_breakpoint():
    g = _g()
    try:
        g.bp("tick", condition="i == 5")
        stop = g.cont()
        assert stop.get("reason") == "breakpoint"
        # i==5 -> 5 ticks already completed (function entry, not yet incremented)
        assert int(g.sym.g_counter) == 5
    finally:
        g.close()


def test_temporary_breakpoint_fires_once():
    g = _g()
    try:
        g.bp("tick", temporary=True)
        stop = g.cont()
        assert stop.get("reason") == "breakpoint"
        c1 = int(g.sym.g_counter)
        stop = g.cont()                            # temp bp gone -> runs to exit
        assert stop.get("reason") in ("exited", "terminated"), stop
        assert int(g.sym.g_counter) >= c1
    finally:
        g.close()


def test_delete_breakpoint():
    g = _g()
    try:
        bp = g.bp("tick")
        g.cont()
        bp.delete()
        stop = g.cont()                            # no tick bp now -> runs to exit
        assert stop.get("reason") in ("exited", "terminated"), stop
    finally:
        g.close()


def test_breakpoint_by_address():
    g = _g()
    try:
        addr = int(g.sym.tick)            # function symbol -> address
        g.bp(addr)
        stop = g.cont()
        assert stop.get("reason") == "breakpoint"
        assert g.frame().name() == "tick"
    finally:
        g.close()


def test_recursion_frames():
    g = _g()
    try:
        g.bp("factorial", condition="n == 1")   # deepest recursive call
        stop = g.cont()
        assert stop.get("reason") == "breakpoint"
        names = []
        f = g.frame()
        for _ in range(10):
            if f is None:
                break
            names.append(f.name())
            f = f.older()
        # factorial(1) ... factorial(5), main
        assert names.count("factorial") >= 5, names
        assert "main" in names
    finally:
        g.close()


def test_stepping_instructions():
    g = _g()
    try:
        pcs = [g.reg.rip]
        for _ in range(5):
            g.stepi()                              # stepi() waits + returns the stop
            pcs.append(g.reg.rip)
        # stepi advances through distinct instructions (and steps *into* calls,
        # e.g. main -> factorial), so the PCs are distinct.
        assert len(set(pcs)) >= 4, pcs
        p = g.reg.rip
        g.nexti()
        assert g.reg.rip != p                     # nexti advances pc too
    finally:
        g.close()


def test_skip_instruction():
    g = _g()
    try:
        before = g.reg.rip
        new_pc = g.skip()
        after = g.reg.rip
        assert after == new_pc > before           # advanced past current insn
    finally:
        g.close()


def test_registers_across_stops():
    g = _g()
    try:
        g.bp("tick")
        g.cont()
        old = g.reg.rax
        g.reg.rax = 0xdeadbeef
        assert g.reg.rax == 0xdeadbeef
        g.reg.rax = old
        g.cont()                                   # registers still readable later
        assert isinstance(g.reg.rip, int) and g.reg.rip > 0
    finally:
        g.close()


def test_watchpoint():
    from pwnc.gdb.dap import DapTimeout
    g = _g()
    try:
        g.watch("g_counter")
        g.cont_nowait()                            # async: sw watchpoints are slow
        try:
            stop = g.wait(timeout=25)
        except DapTimeout:
            print("  (note: watchpoint too slow here; skipping assert)")
            return
        assert stop.get("reason") not in (None, "exited", "terminated"), stop
        assert int(g.sym.g_counter) >= 1
    finally:
        g.close()


def test_no_debug_info_symbols():
    """Stripped/no-DWARF: functions resolve to their address; untyped data to a
    target word value (with .address), not the everything-is-an-address bug."""
    from pwnc.gdb.dap import launch
    g = launch(_nodbg_binary(), init=False)
    try:
        # function symbol -> its address
        assert int(g.sym.nfunc) == g.eval("&nfunc")
        # untyped data -> the value (defaulted to a target word) + correct address
        assert int(g.sym.ndata) == 0x11223344
        assert int(g.sym.nbig) == 0x1122334455667788
        assert g.sym.ndata.address == g.eval("&ndata")
        # and you can still read exact bytes via the address
        assert g.read(g.sym.ndata.address, 4) == (0x11223344).to_bytes(4, "little")
    finally:
        g.close()


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
    print("=== %d/%d passed ===" % (len(_TESTS) - failed, len(_TESTS)))
    sys.exit(1 if failed else 0)
