"""Interactive gdb console in a separate terminal window.

Opens a real gdb CLI console (kitty by default) alongside the script. The two
share one gdb/inferior: you can type gdb commands in the window (run, continue,
break, stepi, print, ...) and the script's breakpoint callbacks still fire. The
window tracks resizes (width-aware plugins like pwndbg/GEF render correctly) and
auto-closes when gdb exits unless console_keep_open=True.

Requires a display (a real terminal window). Uses the mi example target.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))

from pwnc.gdb.dap import launch

TARGET = os.path.join(os.path.dirname(__file__), "..", "..", "mi", "examples", "target")

# headless=False opens the console at startup; or call g.console() any time.
# Set $PWNC_DAP_TERMINAL or pass console=[...] to use a terminal other than kitty.
g = launch(TARGET, headless=False)
print("A gdb console window opened — try typing 'continue' in it.")

# Script-side instrumentation: fires on every update_origin hit, whether the
# continue came from g.cont() here or from 'continue' typed in the console.
def on_update(gg):
    print("  [callback] update_origin: origin = (%d, %d)"
          % (gg.sym.origin.x, gg.sym.origin.y))
    return None                       # auto-continue (transparent); False = stop

g.bp("update_origin", callback=on_update)

# Drive from the script (the console window shows it live). Equivalently, type
# 'continue' in the console window — the same callback fires either way.
stop = g.cont()                       # runs through update_origin, callback prints
print("program", stop.get("reason"))

# To hand control to the console and just let callbacks fire as YOU drive, park
# the script instead:  while g.wait().get("reason") not in ("exited","terminated"): pass

g.console_close()                     # close the window now (or pass console_keep_open=True
g.close()                             # to keep it up after gdb exits)
