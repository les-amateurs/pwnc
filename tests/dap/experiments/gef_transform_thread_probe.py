"""GDB-side probes for re-entry while an untouched GEF frame is active.

Load this file *after* bata24 GEF, then invoke ``gef-transform-probe MODE``.
The wrapper pauses at ``HistoryCommand.get_history``'s first nested
``gdb.execute("show commands ...")`` call.  Each mode tries a different way
to execute ``show pagination`` before the active HistoryCommand returns.

This intentionally keeps the unsafe worker-thread call in a disposable GDB
process.  GDB documents that only ``gdb.post_event`` (and a few other named
APIs) may be called outside GDB's own thread; ordinary GDB APIs are not
thread-safe.
"""

import json
import os
import threading
import time

import gdb

_ORIGINAL_EXECUTE = gdb.execute
_LOCAL = threading.local()
_REPORT = {}


def _event(kind, **fields):
    item = {
        "kind": kind,
        "threadId": threading.get_ident(),
        "timeNs": time.monotonic_ns(),
    }
    item.update(fields)
    _REPORT.setdefault("events", []).append(item)
    return item


def _try_execute(label, command="show pagination"):
    _event(label + "-enter")
    try:
        value = _ORIGINAL_EXECUTE(command, from_tty=False, to_string=True)
    except Exception as error:  # noqa: BLE001 - characterize unsafe GDB call
        _event(
            label + "-error",
            errorType=type(error).__name__,
            errorMessage=str(error),
        )
    else:
        _event(label + "-return", output=value.strip())


def _intercept(command, *args, **kwargs):
    depth = getattr(_LOCAL, "depth", 0)
    _LOCAL.depth = depth + 1
    try:
        mode = _REPORT.get("mode")
        if depth == 1 and command.startswith("show commands ") and not _REPORT.get("intercepted"):
            _REPORT["intercepted"] = True
            _event("gef-nested-execute-intercepted", command=command, depth=depth)

            if mode == "inline":
                # This is legal recursive execution, but it is not a host
                # callback: it stays on the active GDB Python thread.
                _try_execute("inline")

            elif mode == "post-event":
                completed = threading.Event()

                def posted():
                    _try_execute("post-event")
                    completed.set()

                gdb.post_event(posted)
                _event("post-event-enqueued")
                _REPORT["completedWhileGefActive"] = completed.wait(0.25)
                _event(
                    "post-event-wait-ended",
                    completed=_REPORT["completedWhileGefActive"],
                )

            elif mode in {
                "worker-direct",
                "gdb-thread-direct",
                "worker-custom",
                "gdb-thread-custom",
            }:
                completed = threading.Event()
                worker_command = (
                    os.environ.get("PWNC_GEF_TRANSFORM_WORKER_COMMAND", "show pagination")
                    if mode.endswith("custom")
                    else "show pagination"
                )

                def worker_body():
                    try:
                        _try_execute("worker-direct", worker_command)
                    finally:
                        completed.set()

                thread_cls = gdb.Thread if mode.startswith("gdb-thread") else threading.Thread
                worker = thread_cls(target=worker_body, name="gef-transform-worker")
                worker.daemon = True
                worker.start()
                _REPORT["workerClass"] = thread_cls.__module__ + "." + thread_cls.__name__
                _REPORT["completedWhileGefActive"] = completed.wait(0.5)
                _event(
                    "worker-wait-ended",
                    completed=_REPORT["completedWhileGefActive"],
                    workerAlive=worker.is_alive(),
                )

            else:
                raise RuntimeError(f"unknown probe mode: {mode}")

        return _ORIGINAL_EXECUTE(command, *args, **kwargs)
    finally:
        _LOCAL.depth = depth


class _GefTransformProbe(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-probe", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        mode = argument.strip()
        if mode not in {
            "inline",
            "post-event",
            "worker-direct",
            "gdb-thread-direct",
            "worker-custom",
            "gdb-thread-custom",
        }:
            raise gdb.GdbError(f"invalid mode: {mode}")

        _REPORT.clear()
        _REPORT.update(
            {
                "mode": mode,
                "commandThreadId": threading.get_ident(),
                "events": [],
            }
        )
        gdb.execute = _intercept
        _event("gef-enter")
        try:
            # Enter through the wrapper so its thread-local depth distinguishes
            # the outer dispatch from HistoryCommand's nested execute calls.
            gdb.execute("history -n", from_tty=False, to_string=True)
        except Exception as error:  # noqa: BLE001 - report arbitrary plugin failure
            _REPORT["outerError"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
        finally:
            _event("gef-return")
            gdb.execute = _ORIGINAL_EXECUTE


class _GefTransformReport(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-report", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        # An extra event-loop turn has occurred between the probe and report
        # commands, so a post_event callback has had an opportunity to run.
        _REPORT["reportThreadId"] = threading.get_ident()
        print("PWNC_GEF_TRANSFORM_THREAD_REPORT=" + json.dumps(_REPORT, sort_keys=True))


_GefTransformProbe()
_GefTransformReport()
