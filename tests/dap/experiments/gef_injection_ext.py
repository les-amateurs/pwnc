"""Runtime-only instrumentation for an unmodified bata24 GEF source.

The injection may be sourced before or after GEF.  It replaces the module
attribute ``gdb.execute`` but never edits or reloads GEF.  Installing it first
also covers plugin references captured during loading; GEF's HistoryCommand
performs dynamic lookups either way, so its synchronous nested command calls
become observable without changing the plugin's source.
"""

import itertools
import threading

import gdb
from gdb.dap.server import request

_pwnc_gef_lock = threading.RLock()
_pwnc_gef_sequence = itertools.count(1)
_pwnc_gef_events = []
_pwnc_gef_local = threading.local()
_pwnc_gef_original_execute = gdb.execute


def _pwnc_gef_record(kind, **fields):
    with _pwnc_gef_lock:
        event = {
            "seq": next(_pwnc_gef_sequence),
            "kind": kind,
            "threadId": threading.get_ident(),
        }
        event.update(fields)
        _pwnc_gef_events.append(event)
    return event


def _pwnc_gef_execute(command, *args, **kwargs):
    depth = getattr(_pwnc_gef_local, "depth", 0)
    _pwnc_gef_record(
        "execute-enter",
        command=command,
        depth=depth,
        toString=bool(kwargs.get("to_string", False)),
        fromTty=kwargs.get("from_tty"),
    )
    _pwnc_gef_local.depth = depth + 1
    try:
        result = _pwnc_gef_original_execute(command, *args, **kwargs)
    except BaseException as error:
        _pwnc_gef_record(
            "execute-error",
            command=command,
            depth=depth,
            errorType=type(error).__name__,
            errorMessage=str(error),
        )
        raise
    else:
        _pwnc_gef_record(
            "execute-return",
            command=command,
            depth=depth,
            resultType=type(result).__name__,
        )
        return result
    finally:
        _pwnc_gef_local.depth = depth


gdb.execute = _pwnc_gef_execute


@request("pwncGefInjectionSnapshot", on_dap_thread=True, expect_stopped=False)
def _pwnc_gef_snapshot(**extra):
    with _pwnc_gef_lock:
        events = list(_pwnc_gef_events)
    return {
        "installed": gdb.execute is _pwnc_gef_execute,
        "events": events,
    }
