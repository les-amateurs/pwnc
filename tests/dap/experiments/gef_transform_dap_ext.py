"""DAP-side active-GEF host re-entry boundary probe.

This is runtime injection only.  It waits inside bata24 GEF's untouched
``HistoryCommand.get_history`` frame after notifying the external host.  A
host can send another DAP request immediately, but the request's GDB-main
portion cannot execute until the active command returns.
"""

import itertools
import threading
import time

import gdb
from gdb.dap.server import request, send_event

_ORIGINAL_EXECUTE = gdb.execute
_LOCAL = threading.local()
_LOCK = threading.RLock()
_EVENT_IDS = itertools.count(1)
_EVENTS = []
_INTERCEPTED = False
_FUSE_SECONDS = 0.75


def _record(kind, **fields):
    with _LOCK:
        event = {
            "seq": next(_EVENT_IDS),
            "kind": kind,
            "threadId": threading.get_ident(),
            "timeNs": time.monotonic_ns(),
        }
        event.update(fields)
        _EVENTS.append(event)
    return event


def _intercept(command, *args, **kwargs):
    global _INTERCEPTED

    depth = getattr(_LOCAL, "depth", 0)
    _LOCAL.depth = depth + 1
    try:
        if depth == 1 and command.startswith("show commands ") and not _INTERCEPTED:
            _INTERCEPTED = True
            entered = _record("host-callback-emitted", command=command, depth=depth)
            send_event("gefTransformHostCallback", entered)
            # The wait releases Python's GIL, so the external DAP thread and
            # host can run.  It deliberately does not recursively service the
            # GDB event queue.
            threading.Event().wait(_FUSE_SECONDS)
            returned = _record("host-callback-fuse-returned", depth=depth)
            send_event("gefTransformFuseReturned", returned)
        return _ORIGINAL_EXECUTE(command, *args, **kwargs)
    finally:
        _LOCAL.depth = depth


def _run_history():
    gdb.execute = _intercept
    _record("gef-enter")
    try:
        gdb.execute("history -n", from_tty=False, to_string=True)
    except Exception as error:  # noqa: BLE001 - report arbitrary plugin failure
        _record(
            "gef-error",
            errorType=type(error).__name__,
            errorMessage=str(error),
        )
    finally:
        _record("gef-return")
        gdb.execute = _ORIGINAL_EXECUTE
        send_event("gefTransformGefReturned", _EVENTS[-1])


@request("gefTransformStart", on_dap_thread=True, expect_stopped=False)
def _start(**extra):
    gdb.post_event(_run_history)
    return {
        "queued": True,
        "dapThreadId": threading.get_ident(),
        "fuseSeconds": _FUSE_SECONDS,
    }


@request("gefTransformSnapshot", on_dap_thread=True, expect_stopped=False)
def _snapshot(**extra):
    with _LOCK:
        events = list(_EVENTS)
    return {"events": events, "intercepted": _INTERCEPTED}
