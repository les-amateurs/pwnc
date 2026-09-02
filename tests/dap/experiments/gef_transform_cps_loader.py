"""Targeted source-time CPS experiment for untouched-on-disk bata24 GEF.

This is deliberately an experiment, not a proposed general plugin loader.  It
reads the original GEF source, transforms the concrete
``GenericCommand.invoke -> HistoryCommand.do_invoke -> get_history`` chain in
memory, and executes the resulting code under the original filename.  The
source file itself is never written.

``PWNC_GEF_TRANSFORM_CPS_MODE=inline`` drives every yielded ``gdb.execute``
effect before returning to GDB.  That stays synchronous but has no external
callback suspension.  ``...=defer`` returns at the first effect and resumes it
with ``gef-transform-cps-resume``.  That permits intervening GDB work, but the
outer ``gdb.execute("history -n")`` has already returned, demonstrating the
unavoidable GDB C callback boundary.
"""

import ast
import hashlib
import inspect
import json
import os
import threading
import time

import gdb

_pwnc_cps_gef_path = os.path.realpath(os.environ.get("PWNC_GEF_TRANSFORM_GEF", "/home/ctf/bata24-gef/gef.py"))
_pwnc_cps_mode = os.environ.get("PWNC_GEF_TRANSFORM_CPS_MODE", "defer")
if _pwnc_cps_mode not in {"inline", "defer"}:
    raise RuntimeError("invalid PWNC_GEF_TRANSFORM_CPS_MODE")

with open(_pwnc_cps_gef_path, "rb") as _pwnc_cps_stream:
    _pwnc_cps_source_bytes = _pwnc_cps_stream.read()
_pwnc_cps_source_sha256 = hashlib.sha256(_pwnc_cps_source_bytes).hexdigest()
_pwnc_cps_source = _pwnc_cps_source_bytes.decode("utf-8")
_pwnc_cps_original_execute = gdb.execute
_pwnc_cps_events = []
_pwnc_cps_pending = None
_pwnc_cps_transformed = {
    "genericInvoke": 0,
    "historyDoInvoke": 0,
    "historyExecuteCalls": 0,
}


def _pwnc_cps_event(kind, **fields):
    event = {
        "kind": kind,
        "threadId": threading.get_ident(),
        "timeNs": time.monotonic_ns(),
    }
    event.update(fields)
    _pwnc_cps_events.append(event)
    return event


def _pwnc_cps_make_effect(*args, **kwargs):
    effect = {"args": args, "kwargs": kwargs}
    _pwnc_cps_event("effect-created", command=args[0])
    return effect


def _pwnc_cps_execute_effect(effect):
    _pwnc_cps_event("effect-execute-enter", command=effect["args"][0])
    result = _pwnc_cps_original_execute(*effect["args"], **effect["kwargs"])
    _pwnc_cps_event("effect-execute-return", command=effect["args"][0])
    return result


def _pwnc_cps_finish(generator, effect, *, defer_allowed):
    global _pwnc_cps_pending

    while True:
        if defer_allowed and _pwnc_cps_mode == "defer":
            if _pwnc_cps_pending is not None:
                raise RuntimeError("only one CPS command may be pending")
            _pwnc_cps_pending = {"generator": generator, "effect": effect}
            _pwnc_cps_event(
                "command-suspended",
                command=effect["args"][0],
            )
            return None

        result = _pwnc_cps_execute_effect(effect)
        try:
            effect = generator.send(result)
        except StopIteration as stopped:
            _pwnc_cps_event("command-generator-complete")
            return stopped.value


def _pwnc_cps_drive_command(value):
    if not inspect.isgenerator(value):
        return value
    try:
        effect = next(value)
    except StopIteration as stopped:
        return stopped.value
    return _pwnc_cps_finish(value, effect, defer_allowed=True)


class _PwncCpsTransform(ast.NodeTransformer):
    def __init__(self):
        self.class_name = None
        self.function_name = None

    def visit_ClassDef(self, node):
        previous = self.class_name
        self.class_name = node.name
        node = self.generic_visit(node)
        self.class_name = previous
        return node

    def visit_FunctionDef(self, node):
        previous = self.function_name
        self.function_name = node.name
        node = self.generic_visit(node)
        self.function_name = previous
        return node

    def visit_Call(self, node):
        node = self.generic_visit(node)
        if (
            self.class_name == "HistoryCommand"
            and self.function_name == "get_history"
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "gdb"
        ):
            _pwnc_cps_transformed["historyExecuteCalls"] += 1
            return ast.copy_location(
                ast.Yield(
                    ast.Call(
                        func=ast.Name(id="_pwnc_cps_make_effect", ctx=ast.Load()),
                        args=node.args,
                        keywords=node.keywords,
                    )
                ),
                node,
            )
        if (
            self.class_name == "HistoryCommand"
            and self.function_name == "do_invoke"
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get_history"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
        ):
            _pwnc_cps_transformed["historyDoInvoke"] += 1
            return ast.copy_location(ast.YieldFrom(node), node)
        return node

    def visit_Expr(self, node):
        node = self.generic_visit(node)
        if (
            self.class_name == "GenericCommand"
            and self.function_name == "invoke"
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "do_invoke"
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "self"
        ):
            _pwnc_cps_transformed["genericInvoke"] += 1
            return ast.copy_location(
                ast.Return(
                    ast.Call(
                        func=ast.Name(id="_pwnc_cps_drive_command", ctx=ast.Load()),
                        args=[node.value],
                        keywords=[],
                    )
                ),
                node,
            )
        return node


_pwnc_cps_tree = ast.parse(_pwnc_cps_source, filename=_pwnc_cps_gef_path)
_pwnc_cps_tree = _PwncCpsTransform().visit(_pwnc_cps_tree)
ast.fix_missing_locations(_pwnc_cps_tree)
if _pwnc_cps_transformed != {
    "genericInvoke": 1,
    "historyDoInvoke": 1,
    "historyExecuteCalls": 1,
}:
    raise RuntimeError(f"unexpected bata24 GEF AST shape: {_pwnc_cps_transformed!r}")
_pwnc_cps_code = compile(_pwnc_cps_tree, _pwnc_cps_gef_path, "exec")
exec(_pwnc_cps_code, globals(), globals())  # noqa: S102 - this is the loader experiment


class _PwncCpsRun(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-cps-run", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        _pwnc_cps_event("outer-gdb-execute-enter")
        value = _pwnc_cps_original_execute("history -n", from_tty=False, to_string=True)
        _pwnc_cps_event(
            "outer-gdb-execute-return",
            output=value.strip(),
            pending=_pwnc_cps_pending is not None,
        )


class _PwncCpsResume(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-cps-resume", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        global _pwnc_cps_pending
        if _pwnc_cps_pending is None:
            raise gdb.GdbError("no CPS command is pending")

        # This is the work an external callback wanted to perform.  It is safe
        # now only because the original GDB command boundary has returned.
        _pwnc_cps_event("intervening-gdb-work-enter")
        output = _pwnc_cps_original_execute("show pagination", from_tty=False, to_string=True)
        _pwnc_cps_event("intervening-gdb-work-return", output=output.strip())

        pending = _pwnc_cps_pending
        _pwnc_cps_pending = None
        first_result = _pwnc_cps_execute_effect(pending["effect"])
        try:
            next_effect = pending["generator"].send(first_result)
        except StopIteration:
            _pwnc_cps_event("command-generator-complete")
        else:
            _pwnc_cps_finish(pending["generator"], next_effect, defer_allowed=False)
        _pwnc_cps_event("deferred-command-resumed-to-completion")


class _PwncCpsReport(gdb.Command):
    def __init__(self):
        super().__init__("gef-transform-cps-report", gdb.COMMAND_USER)

    def invoke(self, argument, from_tty):
        report = {
            "mode": _pwnc_cps_mode,
            "gefPath": _pwnc_cps_gef_path,
            "gefSha256": _pwnc_cps_source_sha256,
            "transformed": dict(_pwnc_cps_transformed),
            "pending": _pwnc_cps_pending is not None,
            "events": list(_pwnc_cps_events),
        }
        print("PWNC_GEF_TRANSFORM_CPS_REPORT=" + json.dumps(report, sort_keys=True))


_PwncCpsRun()
_PwncCpsResume()
_PwncCpsReport()
