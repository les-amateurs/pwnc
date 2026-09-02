"""Interactive GDB console through an owned, reconnectable PTY.

This example uses xterm only to demonstrate an explicit shell-free launcher;
Kitty, another terminal, ViewerConfig.current(), or a custom launcher object work
the same way.  The console and script share one GDB/inferior, and the stable PTY
endpoint can accept a new viewer if the first window exits.

Requires a display (a real terminal window). Uses the mi example target.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))

from pwnc.gdb.dap import (
    ArgvTerminalLauncher,
    ConsoleConfig,
    ViewerConfig,
    launch,
)

TARGET = os.path.join(os.path.dirname(__file__), "..", "..", "mi", "examples", "target")

viewer = ViewerConfig.external(
    ArgvTerminalLauncher(["xterm", "-e", "{command}"])
)
g = launch(TARGET, console=ConsoleConfig.owned(viewer=viewer))
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

g.console_close()                     # close viewer; endpoint remains reconnectable until GDB exits
g.close()
