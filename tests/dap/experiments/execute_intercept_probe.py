"""Run inside GDB to probe the semantics needed by a re-entrant DAP bridge.

This is deliberately an executable experiment rather than a unit-test double.
The companion ``execute_intercept_driver.py`` starts a real GDB, extracts the
JSON report emitted below, and checks the behavioral claims we rely on.
"""

from __future__ import annotations

import asyncio
import gc
import inspect
import json
import threading
import warnings

import gdb


events: list[dict[str, object]] = []
original_execute = gdb.execute
captured_execute = gdb.execute
wrapper_depth = 0


def record(kind: str, **fields: object) -> None:
    events.append(
        {
            "kind": kind,
            "thread": threading.get_ident(),
            **fields,
        }
    )


class PauseSignal(Exception):
    pass


def intercepted_execute(command: str, *args: object, **kwargs: object) -> object:
    """Record nested calls and provide one synthetic host-callback boundary."""

    global wrapper_depth

    depth = wrapper_depth
    record("execute-enter", command=command, depth=depth)
    wrapper_depth += 1
    try:
        if command.strip() == "pwnc-probe-suspend":
            record("pause-raise", command=command, depth=depth)
            raise PauseSignal("synthetic host callback suspension")
        result = original_execute(command, *args, **kwargs)
        record("execute-return", command=command, depth=depth)
        return result
    except BaseException as error:
        record(
            "execute-raise",
            command=command,
            depth=depth,
            exception_type=type(error).__name__,
            exception_module=type(error).__module__,
            message=str(error),
        )
        raise
    finally:
        wrapper_depth -= 1
        record("execute-exit", command=command, depth=depth)


# Command classes are intentionally conventional synchronous plugin commands,
# except for the two explicitly testing generator/coroutine invoke methods.
class InnerCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-inner", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool) -> None:
        record("inner-enter", argument=argument, from_tty=from_tty)
        gdb.execute("set $pwnc_probe_nested = 33")
        record("inner-exit")


class OuterCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-outer", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool) -> None:
        record("outer-enter", argument=argument, from_tty=from_tty)
        gdb.execute("pwnc-probe-inner dynamic-child")
        record("outer-exit")


class CapturedOuterCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-captured-outer", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool) -> None:
        record("captured-outer-enter", argument=argument, from_tty=from_tty)
        captured_execute("pwnc-probe-inner captured-child")
        record("captured-outer-exit")


generator_body_started = False
generator_body_resumed = False


class GeneratorInvokeCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-generator", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool):
        global generator_body_resumed, generator_body_started

        generator_body_started = True
        record("generator-body-start")
        yield "suspended"
        generator_body_resumed = True
        record("generator-body-resume")


async_body_started = False
async_body_resumed = False


class AsyncInvokeCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-async", gdb.COMMAND_USER)

    async def invoke(self, argument: str, from_tty: bool) -> None:
        global async_body_resumed, async_body_started

        async_body_started = True
        record("async-body-start")
        await asyncio.sleep(0)
        async_body_resumed = True
        record("async-body-resume")


replay_outer_prefix_count = 0
replay_outer_suffix_count = 0
replay_inner_prefix_count = 0
replay_inner_suffix_count = 0


class ReplayInnerCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-replay-inner", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool) -> None:
        global replay_inner_prefix_count, replay_inner_suffix_count

        replay_inner_prefix_count += 1
        record("replay-inner-prefix", invocation=replay_inner_prefix_count)
        gdb.execute("pwnc-probe-suspend")
        replay_inner_suffix_count += 1
        record("replay-inner-suffix", invocation=replay_inner_suffix_count)


class ReplayOuterCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-replay-outer", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool) -> None:
        global replay_outer_prefix_count, replay_outer_suffix_count

        replay_outer_prefix_count += 1
        record("replay-outer-prefix", invocation=replay_outer_prefix_count)
        gdb.execute("pwnc-probe-replay-inner")
        replay_outer_suffix_count += 1
        record("replay-outer-suffix", invocation=replay_outer_suffix_count)


catching_prefix_count = 0
catching_suffix_count = 0
catching_exception: dict[str, str] | None = None


class CatchingCommand(gdb.Command):
    def __init__(self) -> None:
        super().__init__("pwnc-probe-catching", gdb.COMMAND_USER)

    def invoke(self, argument: str, from_tty: bool) -> None:
        global catching_exception, catching_prefix_count, catching_suffix_count

        catching_prefix_count += 1
        try:
            gdb.execute("pwnc-probe-suspend")
        except BaseException as error:
            catching_exception = {
                "type": type(error).__name__,
                "module": type(error).__module__,
                "message": str(error),
            }
            record("catching-command-caught", **catching_exception)
        catching_suffix_count += 1


InnerCommand()
OuterCommand()
CapturedOuterCommand()
GeneratorInvokeCommand()
AsyncInvokeCommand()
ReplayInnerCommand()
ReplayOuterCommand()
CatchingCommand()


assignment_error: dict[str, str] | None = None
try:
    gdb.execute = intercepted_execute
except BaseException as error:
    assignment_error = {
        "type": type(error).__name__,
        "module": type(error).__module__,
        "message": str(error),
    }

monkeypatch_installed = gdb.execute is intercepted_execute


# A dynamic lookup sees the replacement.  A function object captured before
# assignment continues to call the C implementation directly.
event_start = len(events)
gdb.execute("set $pwnc_probe_dynamic = 11")
dynamic_events = events[event_start:]

event_start = len(events)
captured_execute("set $pwnc_probe_captured = 22")
captured_events = events[event_start:]


# Show the complete synchronous nesting order and then the two partial-bypass
# cases: captured outer dispatch and a plugin's captured nested dispatch.
event_start = len(events)
gdb.execute("pwnc-probe-outer top")
dynamic_nested_events = events[event_start:]

event_start = len(events)
captured_execute("pwnc-probe-outer captured-top")
captured_top_events = events[event_start:]

event_start = len(events)
gdb.execute("pwnc-probe-captured-outer top")
captured_child_events = events[event_start:]


# GDB accepts both callables as invoke methods at registration time.  Probe
# whether it drives the returned generator/coroutine (it currently does not).
generator_error: dict[str, str] | None = None
try:
    gdb.execute("pwnc-probe-generator")
except BaseException as error:
    generator_error = {
        "type": type(error).__name__,
        "module": type(error).__module__,
        "message": str(error),
    }

with warnings.catch_warnings(record=True) as caught_warnings:
    warnings.simplefilter("always")
    async_error: dict[str, str] | None = None
    try:
        gdb.execute("pwnc-probe-async")
    except BaseException as error:
        async_error = {
            "type": type(error).__name__,
            "module": type(error).__module__,
            "message": str(error),
        }
    gc.collect()
    async_warnings = [
        {"category": warning.category.__name__, "message": str(warning.message)}
        for warning in caught_warnings
    ]


# Throwing at the intercepted leaf crosses two Python-command/GDB boundaries.
# Invoke it twice to test whether "replay" resumes the old frame or creates a
# new call and repeats the already-executed prefixes.
replay_errors: list[dict[str, str]] = []
for attempt in range(2):
    try:
        gdb.execute("pwnc-probe-replay-outer")
    except BaseException as error:
        replay_errors.append(
            {
                "attempt": str(attempt + 1),
                "type": type(error).__name__,
                "module": type(error).__module__,
                "message": str(error),
            }
        )


# A command may explicitly catch the synthetic exception while it is still on
# the same Python side of the next GDB command boundary.  That is continuation
# by plugin cooperation, not suspension of an arbitrary plugin stack.
catching_error: dict[str, str] | None = None
try:
    gdb.execute("pwnc-probe-catching")
except BaseException as error:
    catching_error = {
        "type": type(error).__name__,
        "module": type(error).__module__,
        "message": str(error),
    }


report = {
    "gdb_version": gdb.VERSION,
    "monkeypatch": {
        "assignment_error": assignment_error,
        "installed": monkeypatch_installed,
        "module_lookup_is_wrapper": gdb.execute is intercepted_execute,
        "captured_reference_is_original": captured_execute is original_execute,
        "dynamic_value": int(gdb.parse_and_eval("$pwnc_probe_dynamic")),
        "captured_value": int(gdb.parse_and_eval("$pwnc_probe_captured")),
        "dynamic_events": dynamic_events,
        "captured_events": captured_events,
    },
    "nesting": {
        "dynamic": dynamic_nested_events,
        "captured_top": captured_top_events,
        "captured_child": captured_child_events,
        "nested_value": int(gdb.parse_and_eval("$pwnc_probe_nested")),
    },
    "invoke_shapes": {
        "generator_is_generator_function": inspect.isgeneratorfunction(
            GeneratorInvokeCommand.invoke
        ),
        "generator_error": generator_error,
        "generator_body_started": generator_body_started,
        "generator_body_resumed": generator_body_resumed,
        "async_is_coroutine_function": inspect.iscoroutinefunction(
            AsyncInvokeCommand.invoke
        ),
        "async_error": async_error,
        "async_body_started": async_body_started,
        "async_body_resumed": async_body_resumed,
        "async_warnings": async_warnings,
    },
    "exception_replay": {
        "errors": replay_errors,
        "outer_prefix_count": replay_outer_prefix_count,
        "outer_suffix_count": replay_outer_suffix_count,
        "inner_prefix_count": replay_inner_prefix_count,
        "inner_suffix_count": replay_inner_suffix_count,
        "catching_error": catching_error,
        "catching_exception": catching_exception,
        "catching_prefix_count": catching_prefix_count,
        "catching_suffix_count": catching_suffix_count,
    },
    "all_threads": sorted({event["thread"] for event in events}),
    "events": events,
}

gdb.write("PWNC_EXECUTE_INTERCEPT_REPORT=" + json.dumps(report, sort_keys=True) + "\n")
