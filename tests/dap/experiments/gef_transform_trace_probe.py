"""Trace- and code-object probes against a live bata24 GEF command.

The probes demonstrate the distinction between *running injected code in the
active frame's thread* and *capturing that frame as a resumable continuation*.
Python tracing provides the former, not the latter.  Replacing a function's
code object similarly affects future calls, not its already-created frame.
"""

import inspect
import json
import sys
import threading
import time

import gdb

_ORIGINAL_EXECUTE = gdb.execute
_REPORT = {}
_SUSPENSION = None


def _event(kind, **fields):
    item = {
        "kind": kind,
        "threadId": threading.get_ident(),
        "timeNs": time.monotonic_ns(),
    }
    item.update(fields)
    _REPORT.setdefault("events", []).append(item)
    return item


def _history_code():
    return globals()["HistoryCommand"].get_history.__code__


class _TraceSuspend(Exception):
    pass


class _GefTransformTraceProbe(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-trace-probe", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        mode = argument.strip()
        if mode not in {"inline", "unwind", "replace-code"}:
            raise gdb.GdbError(f"invalid mode: {mode}")

        global _SUSPENSION
        _REPORT.clear()
        _REPORT.update(
            {
                "mode": mode,
                "commandThreadId": threading.get_ident(),
                "events": [],
            }
        )
        _SUSPENSION = None
        original_code = _history_code()
        active_frame = []
        fired = [False]
        nested = []

        def replacement(self):
            _event("replacement-called")
            return ["replacement-result"]

        replacement_code = replacement.__code__

        def execute_wrapper(command, *args, **kwargs):
            if command.startswith("show commands "):
                nested.append(command)
                _event("original-active-code-nested-execute", command=command)
            return _ORIGINAL_EXECUTE(command, *args, **kwargs)

        def tracer(frame, event, arg):
            global _SUSPENSION
            if frame.f_code is not original_code or event != "call" or fired[0]:
                return tracer
            fired[0] = True
            active_frame.append(frame)
            _event(
                "trace-entered-history",
                traceEvent=event,
                codeName=frame.f_code.co_name,
                line=frame.f_lineno,
            )
            if mode == "inline":
                value = _ORIGINAL_EXECUTE("show pagination", from_tty=False, to_string=True)
                _event("trace-inline-execute-return", output=value.strip())
            elif mode == "unwind":
                _SUSPENSION = _TraceSuspend("synthetic suspension")
                _event("trace-raising-suspension")
                raise _SUSPENSION
            else:
                globals()["HistoryCommand"].get_history.__code__ = replacement_code
                _event(
                    "trace-replaced-function-code",
                    activeFrameStillOriginal=frame.f_code is original_code,
                    functionNowReplacement=(globals()["HistoryCommand"].get_history.__code__ is replacement_code),
                )
            return tracer

        gdb.execute = execute_wrapper
        sys.settrace(tracer)
        try:
            _event("gef-enter")
            _ORIGINAL_EXECUTE("history -n", from_tty=False, to_string=True)
        except Exception as error:  # noqa: BLE001 - report arbitrary plugin failure
            _REPORT["outerError"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
        finally:
            sys.settrace(None)
            gdb.execute = _ORIGINAL_EXECUTE
            _event("gef-return")

        _REPORT["traceFired"] = fired[0]
        _REPORT["activeFrameCount"] = len(active_frame)
        _REPORT["nestedOriginalExecuteCount"] = len(nested)
        if active_frame:
            frame = active_frame[0]
            _REPORT["frameType"] = type(frame).__name__
            _REPORT["frameIsGenerator"] = inspect.isgenerator(frame)
            _REPORT["frameHasSend"] = hasattr(frame, "send")
            _REPORT["frameHasThrow"] = hasattr(frame, "throw")
            _REPORT["frameLastInstruction"] = frame.f_lasti
            try:
                frame.f_lineno = frame.f_lineno
            except ValueError as error:
                _REPORT["externalLineJump"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
            else:
                _REPORT["externalLineJump"] = {"type": None, "message": None}

        if mode == "unwind":
            traceback_frames = []
            traceback = _SUSPENSION.__traceback__ if _SUSPENSION else None
            while traceback is not None:
                traceback_frames.append(traceback.tb_frame.f_code.co_name)
                traceback = traceback.tb_next
            _REPORT["retainedTracebackFrames"] = traceback_frames

        if mode == "replace-code":
            instance = globals()["__gef_command_instances__"]["history"]
            _REPORT["futureCallResult"] = instance.get_history()
            globals()["HistoryCommand"].get_history.__code__ = original_code


class _GefTransformTraceReport(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-trace-report", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        print("PWNC_GEF_TRANSFORM_TRACE_REPORT=" + json.dumps(_REPORT, sort_keys=True))


_GefTransformTraceProbe()
_GefTransformTraceReport()
