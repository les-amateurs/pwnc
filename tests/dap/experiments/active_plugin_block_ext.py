"""Inject a bounded host-callback wait into unmodified bata24 GEF.

GEF must be sourced before this file.  No plugin source is changed: the probe
replaces the runtime ``gdb.execute`` attribute and pauses only when GEF's
HistoryCommand makes its first nested ``show commands`` call.
"""

import threading
import time

import gdb
from gdb.dap.server import request, send_event

_pwnc_original_execute = gdb.execute
_pwnc_local = threading.local()
_pwnc_paused_once = False


def _pwnc_injected_execute(command, *args, **kwargs):
    global _pwnc_paused_once

    depth = getattr(_pwnc_local, "depth", 0)
    _pwnc_local.depth = depth + 1
    try:
        # The outer depth-0 command is `history -n`.  This branch is reached
        # from the untouched GEF HistoryCommand.invoke stack.
        if (
            depth == 1
            and command.startswith("show commands ")
            and not _pwnc_paused_once
        ):
            _pwnc_paused_once = True
            send_event(
                "pwncActivePluginWaiting",
                {
                    "command": command,
                    "depth": depth,
                    "gdbThreadId": threading.get_ident(),
                    "timeNs": time.monotonic_ns(),
                },
            )
            # A fuse keeps this negative experiment bounded.  A real callback
            # waiting for nested GDB work here would deadlock permanently.
            threading.Event().wait(1.0)
        return _pwnc_original_execute(command, *args, **kwargs)
    finally:
        _pwnc_local.depth = depth


gdb.execute = _pwnc_injected_execute


def _pwnc_run_gef_history():
    try:
        gdb.execute("history -n", from_tty=False, to_string=True)
    finally:
        send_event(
            "pwncActivePluginReturned",
            {
                "gdbThreadId": threading.get_ident(),
                "timeNs": time.monotonic_ns(),
            },
        )


@request("pwncActivePluginStart", on_dap_thread=True, expect_stopped=False)
def _pwnc_start_plugin(**extra):
    """Acknowledge first, then enter GEF from GDB's main event loop."""

    dap_thread_id = threading.get_ident()
    gdb.post_event(_pwnc_run_gef_history)
    return {
        "queued": True,
        "dapThreadId": dap_thread_id,
    }
