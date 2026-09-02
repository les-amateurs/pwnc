"""GDB-side thread audit shared by native and side-socket DAP probes."""

import os
import signal
import threading

import gdb
import gdb.dap.startup as startup
from gdb.dap.server import request


def _thread_record(thread):
    native_id = getattr(thread, "native_id", None)
    return {
        "class": type(thread).__module__ + "." + type(thread).__qualname__,
        "ident": thread.ident,
        "isGdbThread": isinstance(thread, gdb.Thread),
        "isMainThread": thread is threading.main_thread(),
        "name": thread.name,
        "nativeId": native_id,
        "pid": os.getpid(),
    }


def _signal_mask():
    if not hasattr(signal, "pthread_sigmask"):
        return None
    current = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    return sorted(item.name for item in current)


@request("pwncDapThreadAudit", on_dap_thread=True, expect_stopped=False)
def dap_thread_audit(**_args):
    current = threading.current_thread()
    record = _thread_record(current)
    record.update(
        {
            "matchesCapturedDapThread": current is startup._dap_thread,
            "signalMask": _signal_mask(),
        }
    )
    return record


@request("pwncMainThreadAudit", expect_stopped=False)
def main_thread_audit(**_args):
    current = threading.current_thread()
    record = _thread_record(current)
    record.update(
        {
            # This request is dispatched by stock DAP's
            # send_gdb_with_response -> gdb.post_event path.
            "gdbApiCall": gdb.selected_inferior().num,
            "matchesCapturedGdbThread": current is startup._gdb_thread,
            "signalMask": _signal_mask(),
        }
    )
    return record
