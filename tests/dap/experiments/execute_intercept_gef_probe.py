"""Real-plugin companion probe; source this only after the GEF fixture."""

from __future__ import annotations

import json as _pwnc_json
import threading as _pwnc_threading

import gdb as _pwnc_gdb


_pwnc_original_execute = _pwnc_gdb.execute
_pwnc_events: list[dict[str, object]] = []
_pwnc_depth = 0


def _pwnc_intercepted_execute(
    command: str, *args: object, **kwargs: object
) -> object:
    global _pwnc_depth

    depth = _pwnc_depth
    _pwnc_events.append(
        {
            "kind": "enter",
            "command": command,
            "depth": depth,
            "to_string": kwargs.get("to_string", False),
            "from_tty": kwargs.get("from_tty"),
            "thread": _pwnc_threading.get_ident(),
        }
    )
    _pwnc_depth += 1
    try:
        result = _pwnc_original_execute(command, *args, **kwargs)
        _pwnc_events.append(
            {
                "kind": "return",
                "command": command,
                "depth": depth,
                "result_type": type(result).__name__,
                "thread": _pwnc_threading.get_ident(),
            }
        )
        return result
    finally:
        _pwnc_depth -= 1


_pwnc_gdb.execute = _pwnc_intercepted_execute
_pwnc_error: dict[str, str] | None = None
_pwnc_output: object = None
try:
    # GEF's HistoryCommand is harmless without an inferior and calls
    # gdb.execute("show commands ...", to_string=True) from its conventional
    # synchronous GenericCommand.invoke stack.
    _pwnc_output = _pwnc_gdb.execute("history -n", to_string=True)
except BaseException as error:
    _pwnc_error = {
        "type": type(error).__name__,
        "module": type(error).__module__,
        "message": str(error),
    }

_pwnc_report = {
    "gdb_version": _pwnc_gdb.VERSION,
    "error": _pwnc_error,
    "output_type": type(_pwnc_output).__name__,
    "output": _pwnc_output,
    "events": _pwnc_events,
    "threads": sorted({event["thread"] for event in _pwnc_events}),
}
_pwnc_gdb.write(
    "PWNC_EXECUTE_INTERCEPT_GEF_REPORT="
    + _pwnc_json.dumps(_pwnc_report, sort_keys=True)
    + "\n"
)
