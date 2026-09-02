"""Semantic tests for the async-to-generator lowering experiment."""

import ast
import inspect
import sys
import traceback

import pytest
from ast_lowering_runtime import (
    CancelledError,
    LoweringError,
    Scheduler,
    TaskState,
    exec_lowered,
    lower_ast,
)


def test_locals_nested_calls_return_values_and_plain_generator_shape():
    namespace = exec_lowered(
        """
async def child(value):
    doubled = await effect("double", value)
    return doubled + 1

async def parent(value):
    local = value + 3
    nested = await child(local)
    echoed = await effect("echo", nested, marker="kept")
    return local, nested, echoed
"""
    )

    parent = namespace["parent"]
    child = namespace["child"]
    assert not inspect.iscoroutinefunction(parent)
    assert inspect.isgeneratorfunction(parent)
    assert inspect.isgeneratorfunction(child)

    seen = []
    scheduler = Scheduler(
        {
            "double": lambda value: seen.append(("double", value)) or value * 2,
            "echo": lambda value, marker: seen.append(("echo", value, marker)) or value,
        }
    )
    assert scheduler.run(parent(5)) == (8, 17, 17)
    assert seen == [("double", 8), ("echo", 17, "kept")]


def test_no_await_function_is_still_lazy_and_resumable():
    namespace = exec_lowered(
        """
events = []
async def pure(value):
    events.append(value)
    return value + 1
"""
    )
    pending = namespace["pure"](9)
    assert inspect.isgenerator(pending)
    assert namespace["events"] == []
    assert Scheduler().run(pending) == 10
    assert namespace["events"] == [9]


def test_decorators_defaults_and_annotations_survive_lowering():
    namespace = exec_lowered(
        """
events = []
default_offset = 4

def mark(function):
    events.append(("decorated", function.__name__))
    function.was_decorated = True
    return function

@mark
async def calculate(value: int, offset: int = default_offset) -> tuple[int, int]:
    return value, offset

default_offset = 99
"""
    )
    calculate = namespace["calculate"]
    assert inspect.isgeneratorfunction(calculate)
    assert calculate.was_decorated is True
    assert calculate.__defaults__ == (4,)
    assert calculate.__annotations__ == {
        "value": int,
        "offset": int,
        "return": tuple[int, int],
    }
    assert namespace["events"] == [("decorated", "calculate")]
    assert Scheduler().run(calculate(7)) == (7, 4)


def test_non_await_metadata_on_nested_async_def_is_preserved():
    namespace = exec_lowered(
        """
events = []

def mark(function):
    events.append(("decorated", function.__name__))
    return function

async def outer():
    @mark
    async def inner(value: int = 4) -> int:
        return value
    return await inner()
"""
    )

    assert namespace["events"] == []
    assert Scheduler().run(namespace["outer"]()) == 4
    assert namespace["events"] == [("decorated", "inner")]


def test_nested_decorators_and_defaults_keep_native_evaluation_order():
    namespace = exec_lowered(
        """
events = []

def decorate(label):
    events.append(("decorator expression", label))
    def apply(function):
        events.append(("decorator application", label))
        return function
    return apply

def make_default():
    events.append("default")
    return 7

async def outer():
    @decorate("top")
    @decorate("bottom")
    async def inner(value=make_default()):
        return value
    await effect("defined")
    return inner
"""
    )
    task = Scheduler().start(namespace["outer"]())
    assert namespace["events"] == []

    assert task.resume().name == "defined"
    assert namespace["events"] == [
        ("decorator expression", "top"),
        ("decorator expression", "bottom"),
        "default",
        ("decorator application", "bottom"),
        ("decorator application", "top"),
    ]

    assert task.resume() is None
    assert task.state is TaskState.DONE
    inner = task.result
    assert inner.__defaults__ == (7,)
    assert Scheduler().run(inner()) == 7


def test_future_annotations_remain_unevaluated_after_lowering():
    namespace = exec_lowered(
        """\
from __future__ import annotations

events = []
def annotation():
    events.append("evaluated")
    return int

async def operation(value: annotation()) -> annotation():
    return value
"""
    )

    operation = namespace["operation"]
    assert namespace["events"] == []
    assert operation.__annotations__ == {
        "value": "annotation()",
        "return": "annotation()",
    }
    assert namespace["events"] == []


def test_callback_exception_crosses_nested_calls_and_try_except_finally():
    namespace = exec_lowered(
        """
events = []
async def leaf():
    try:
        return await effect("explode")
    finally:
        events.append("leaf finally")

async def root():
    try:
        await leaf()
    except ValueError as exc:
        events.append(("caught", str(exc)))
        return "recovered"
    finally:
        events.append("root finally")
"""
    )

    def explode():
        raise ValueError("callback failed")

    assert Scheduler({"explode": explode}).run(namespace["root"]()) == "recovered"
    assert namespace["events"] == [
        "leaf finally",
        ("caught", "callback failed"),
        "root finally",
    ]


def test_uncaught_callback_exception_is_re_raised_by_scheduler():
    namespace = exec_lowered(
        """
async def root():
    await effect("explode")
"""
    )

    def explode():
        raise RuntimeError("uncaught")

    with pytest.raises(RuntimeError, match="uncaught"):
        Scheduler({"explode": explode}).run(namespace["root"]())


def test_traceback_preserves_supplied_filename_and_await_source_line():
    filename = "/virtual/plugins/callback_plugin.py"
    source = """\
async def broken():
    local = "still here"
    return await effect("explode", local)
"""
    namespace = exec_lowered(source, filename=filename)

    def explode(_local):
        raise RuntimeError("trace me")

    with pytest.raises(RuntimeError, match="trace me") as caught:
        Scheduler({"explode": explode}).run(namespace["broken"]())

    lowered_frames = [frame for frame in traceback.extract_tb(caught.value.__traceback__) if frame.filename == filename]
    assert [(frame.name, frame.lineno) for frame in lowered_frames] == [("broken", 3)]
    assert lowered_frames[0].line == 'return await effect("explode", local)'


def test_nested_traceback_preserves_original_lines_and_pep657_spans():
    filename = "/virtual/plugins/nested_callbacks.py"
    source = """\
async def child():
    return await effect("explode")

async def parent():
    return await child()
"""
    namespace = exec_lowered(source, filename=filename)

    def explode():
        raise RuntimeError("nested traceback")

    with pytest.raises(RuntimeError, match="nested traceback") as caught:
        Scheduler({"explode": explode}).run(namespace["parent"]())

    frames = [frame for frame in traceback.extract_tb(caught.value.__traceback__) if frame.filename == filename]
    expected_lines = {
        "parent": "    return await child()",
        "child": '    return await effect("explode")',
    }
    assert [(frame.name, frame.lineno) for frame in frames] == [
        ("parent", 5),
        ("child", 2),
    ]
    for frame in frames:
        source_line = expected_lines[frame.name]
        assert frame.line == source_line.strip()
        assert frame.colno == source_line.index("await")
        assert frame.end_colno == len(source_line)


def test_cancellation_unwinds_finally_and_records_cancelled_state():
    namespace = exec_lowered(
        """
events = []
async def root():
    try:
        events.append("started")
        await effect("pause")
        events.append("resumed")
    finally:
        events.append("finally")
"""
    )
    task = Scheduler().start(namespace["root"]())
    pending = task.resume()
    assert pending is not None and pending.name == "pause"

    task.cancel()
    assert task.state is TaskState.CANCELLED
    assert isinstance(task.exception, CancelledError)
    assert namespace["events"] == ["started", "finally"]


def test_close_unwinds_finally_without_resuming_the_effect():
    namespace = exec_lowered(
        """
events = []
async def root():
    try:
        events.append("started")
        await effect("pause")
    finally:
        events.append("closed")
"""
    )
    task = Scheduler().start(namespace["root"]())
    task.resume()
    task.close()
    assert task.state is TaskState.CLOSED
    assert namespace["events"] == ["started", "closed"]


def test_cooperative_cancel_drives_awaited_cleanup_before_becoming_terminal():
    namespace = exec_lowered(
        """
events = []
async def root():
    try:
        await effect("pause")
    finally:
        try:
            events.append("cleanup-1-enter")
            await effect("cleanup-1")
        finally:
            events.append("cleanup-2-enter")
            await effect("cleanup-2")
        events.append("cleanup-done")
"""
    )
    task = Scheduler().start(namespace["root"]())
    assert task.resume().name == "pause"

    assert task.cancel().name == "cleanup-1"
    assert task.state is TaskState.WAITING
    assert task.resume(value=None).name == "cleanup-2"
    assert task.state is TaskState.WAITING
    assert task.resume(value=None) is None
    assert task.state is TaskState.CANCELLED
    assert isinstance(task.exception, CancelledError)
    assert namespace["events"] == [
        "cleanup-1-enter",
        "cleanup-2-enter",
        "cleanup-done",
    ]


def test_cancelled_nested_cleanup_failure_runs_outer_finally_and_wins():
    namespace = exec_lowered(
        """
events = []
async def root():
    try:
        await effect("pause")
    finally:
        try:
            events.append("cleanup-1-enter")
            await effect("cleanup-1")
        finally:
            events.append("cleanup-2-enter")
            await effect("cleanup-2")
            events.append("cleanup-2-done")
"""
    )
    task = Scheduler().start(namespace["root"]())
    assert task.resume().name == "pause"
    assert task.cancel().name == "cleanup-1"

    cleanup_error = ValueError("cleanup failed")
    assert task.resume(error=cleanup_error).name == "cleanup-2"
    assert task.resume() is None
    assert task.state is TaskState.FAILED
    assert task.exception is cleanup_error
    assert namespace["events"] == [
        "cleanup-1-enter",
        "cleanup-2-enter",
        "cleanup-2-done",
    ]


def test_force_close_retries_finite_generator_exit_yields_until_frame_released():
    namespace = exec_lowered(
        """
events = []
async def root():
    try:
        await effect("pause")
    finally:
        try:
            events.append("discarded-cleanup-1")
            await effect("discarded-cleanup-1")
        finally:
            events.append("discarded-cleanup-2")
            await effect("discarded-cleanup-2")
"""
    )
    task = Scheduler().start(namespace["root"]())
    assert task.resume().name == "pause"

    with pytest.raises(RuntimeError, match="live frame after 2 forced close attempts"):
        task.force_close(max_attempts=2)
    assert namespace["events"] == [
        "discarded-cleanup-1",
        "discarded-cleanup-2",
    ]
    assert task.generator.gi_frame is not None

    task.force_close(max_attempts=1)
    assert task.state is TaskState.CLOSED
    assert task.generator.gi_frame is None


def test_force_close_exposes_attempt_exhaustion_without_losing_live_frame():
    namespace = exec_lowered(
        """
keep_ignoring = True
events = []
async def root():
    try:
        await effect("pause")
    finally:
        while keep_ignoring:
            try:
                await effect("stubborn-cleanup")
            except GeneratorExit:
                events.append("ignored GeneratorExit")
"""
    )
    task = Scheduler().start(namespace["root"]())
    assert task.resume().name == "pause"

    with pytest.raises(RuntimeError, match="live frame after 2 forced close attempts"):
        task.force_close(max_attempts=2)
    assert task.state is TaskState.FAILED
    assert task.generator.gi_frame is not None
    assert namespace["events"] == ["ignored GeneratorExit"]

    namespace["keep_ignoring"] = False
    task.force_close(max_attempts=1)
    assert task.state is TaskState.CLOSED
    assert task.generator.gi_frame is None
    assert namespace["events"] == [
        "ignored GeneratorExit",
        "ignored GeneratorExit",
    ]


def test_force_close_propagates_cleanup_failure_from_closed_frame():
    namespace = exec_lowered(
        """
async def root():
    try:
        await effect("pause")
    finally:
        raise ValueError("cleanup failed")
"""
    )
    task = Scheduler().start(namespace["root"]())
    assert task.resume().name == "pause"

    with pytest.raises(ValueError, match="cleanup failed") as caught:
        task.force_close()
    assert task.state is TaskState.FAILED
    assert task.exception is caught.value
    assert task.generator.gi_frame is None


def test_nested_async_definition_retains_ordinary_python_closure():
    namespace = exec_lowered(
        """
def factory(scale):
    label = "captured"
    async def calculate(value):
        offset = await effect("offset", value)
        return label, scale * value + offset
    return calculate
"""
    )
    calculate = namespace["factory"](7)
    assert inspect.isgeneratorfunction(calculate)
    assert Scheduler({"offset": lambda value: value + 1}).run(calculate(3)) == (
        "captured",
        25,
    )


def test_lowered_async_method_retains_class_cell_for_zero_argument_super():
    namespace = exec_lowered(
        """
class Base:
    def value(self):
        return 40

class Child(Base):
    async def value(self):
        adjustment = await effect("adjustment")
        return super().value() + adjustment, __class__.__name__
"""
    )

    child = namespace["Child"]()
    result = Scheduler({"adjustment": lambda: 2}).run(child.value())
    assert result == (42, "Child")


def test_nonlocal_cell_mutation_crosses_lowered_suspension():
    namespace = exec_lowered(
        """
def counter():
    value = 1
    async def increment():
        nonlocal value
        value += await effect("increment")
        return value
    return increment, lambda: value
"""
    )
    increment, current = namespace["counter"]()
    scheduler = Scheduler({"increment": lambda: 4})

    assert scheduler.run(increment()) == 5
    assert current() == 5
    assert scheduler.run(increment()) == 9
    assert current() == 9


def test_await_in_class_header_uses_enclosing_async_scope_only():
    namespace = exec_lowered(
        """
async def build():
    class Derived(
        await effect("base"),
        metaclass=await effect("metaclass"),
    ):
        marker = "class body stayed synchronous"
    return Derived
"""
    )

    class Base:
        pass

    class Meta(type):
        pass

    seen = []
    scheduler = Scheduler(
        {
            "base": lambda: seen.append("base") or Base,
            "metaclass": lambda: seen.append("metaclass") or Meta,
        }
    )
    derived = scheduler.run(namespace["build"]())
    assert seen == ["base", "metaclass"]
    assert issubclass(derived, Base)
    assert isinstance(derived, Meta)
    assert derived.marker == "class body stayed synchronous"


def test_effect_handler_can_recursively_start_more_lowered_work():
    namespace = exec_lowered(
        """
async def operation(depth, trace):
    trace.append(("operation", depth))
    if depth == 0:
        return await effect("leaf")
    nested = await effect("host", depth, trace)
    trace.append(("resumed", depth, nested))
    return nested + 1
"""
    )
    trace = []
    scheduler = None

    def host(depth, same_trace):
        trace.append(("host", depth))
        return scheduler.run(namespace["operation"](depth - 1, same_trace))

    scheduler = Scheduler({"host": host, "leaf": lambda: 10})
    assert scheduler.run(namespace["operation"](2, trace)) == 12
    assert trace == [
        ("operation", 2),
        ("host", 2),
        ("operation", 1),
        ("host", 1),
        ("operation", 0),
        ("resumed", 1, 10),
        ("resumed", 2, 11),
    ]


def test_independent_tasks_can_be_manually_resumed_in_interleaved_order():
    namespace = exec_lowered(
        """
async def worker(label):
    first = await effect("first", label)
    second = await effect("second", label, first)
    return label, first, second
"""
    )
    scheduler = Scheduler()
    left = scheduler.start(namespace["worker"]("left"))
    right = scheduler.start(namespace["worker"]("right"))

    assert left.resume().args == ("left",)
    assert right.resume().args == ("right",)
    assert left.state is TaskState.WAITING
    assert right.state is TaskState.WAITING

    right_second = right.resume(value=20)
    left_second = left.resume(value=10)
    assert right_second.name == "second" and right_second.args == ("right", 20)
    assert left_second.name == "second" and left_second.args == ("left", 10)

    assert left.resume(value=11) is None
    assert left.state is TaskState.DONE
    assert left.result == ("left", 10, 11)
    assert right.state is TaskState.WAITING

    assert right.resume(value=21) is None
    assert right.state is TaskState.DONE
    assert right.result == ("right", 20, 21)


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (
            "async def f(items):\n    async for item in items:\n        pass\n",
            "async for is not supported",
        ),
        (
            "async def f(manager):\n    async with manager:\n        pass\n",
            "async with is not supported",
        ),
        (
            "async def f(items):\n    return [item async for item in items]\n",
            "async comprehensions are not supported",
        ),
        (
            "async def f(items):\n    return [await effect('x', item) for item in items]\n",
            "await inside comprehensions is not supported",
        ),
        (
            "async def f():\n    yield 1\n",
            "async generators are not supported",
        ),
        (
            "def f():\n    await effect('x')\n",
            "await is only valid inside a lowered async def",
        ),
    ],
)
def test_unsupported_async_semantics_are_rejected_early(source, message):
    with pytest.raises(LoweringError, match=message) as caught:
        lower_ast(source, filename="unsupported_example.py")
    assert caught.value.filename == "unsupported_example.py"
    assert caught.value.lineno == 2
    assert caught.value.offset is not None


@pytest.mark.parametrize(
    ("source", "message", "line"),
    [
        (
            "async def outer():\n    callback = lambda: await effect('x')\n",
            "await is only valid inside a lowered async def",
            2,
        ),
        (
            "async def outer():\n    def callback():\n        return await effect('x')\n",
            "await is only valid inside a lowered async def",
            3,
        ),
        (
            "async def outer():\n    class Callback:\n        value = await effect('x')\n",
            "await is only valid inside a lowered async def",
            3,
        ),
    ],
)
def test_nested_synchronous_scopes_cannot_capture_await(source, message, line):
    with pytest.raises(LoweringError, match=message) as caught:
        lower_ast(source, filename="nested_sync_scope.py")
    assert caught.value.filename == "nested_sync_scope.py"
    assert caught.value.lineno == line


def test_lowering_error_reports_original_unicode_source_and_character_offset():
    source = """\
async def outer():
    def callback():
        café = 1; await effect("x")
"""
    with pytest.raises(LoweringError, match="await is only valid") as caught:
        lower_ast(source, filename="unicode_scope.py")

    source_line = source.splitlines(keepends=True)[2]
    assert caught.value.filename == "unicode_scope.py"
    assert caught.value.lineno == 3
    assert caught.value.text == source_line
    assert caught.value.offset == source_line.index("await") + 1
    assert caught.value.end_lineno == 3
    assert caught.value.end_offset == source_line.index("await") + len('await effect("x")') + 1


@pytest.mark.parametrize(
    ("source", "message", "line"),
    [
        (
            "@await effect('decorator')\nasync def operation():\n    pass\n",
            "await in function decorators is not supported",
            1,
        ),
        (
            "async def outer():\n    @await effect('decorator')\n    async def operation():\n        pass\n",
            "await in function decorators is not supported",
            2,
        ),
        (
            "async def operation(value=await effect('default')):\n    pass\n",
            "await in function defaults is not supported",
            1,
        ),
        (
            "async def outer():\n    async def operation(*, value=await effect('default')):\n        pass\n",
            "await in function defaults is not supported",
            2,
        ),
        (
            "async def outer():\n    def operation(value=await effect('default')):\n        pass\n",
            "await in function defaults is not supported",
            2,
        ),
        (
            "async def outer():\n    callback = lambda value=await effect('default'): value\n",
            "await in lambda defaults is not supported",
            2,
        ),
        (
            "async def operation(value: await effect('annotation')):\n    pass\n",
            "await in function annotations is not supported",
            1,
        ),
        (
            "async def outer():\n    async def operation() -> await effect('annotation'):\n        pass\n",
            "await in function annotations is not supported",
            2,
        ),
        (
            "async def operation[T: await effect('bound')]():\n    pass\n",
            "await in function type parameters is not supported",
            1,
        ),
        (
            "async def outer():\n    async def operation[T: await effect('bound')]():\n        pass\n",
            "await in function type parameters is not supported",
            2,
        ),
        (
            "async def outer():\n    @await effect('decorator')\n    class Callback:\n        pass\n",
            "await in class decorators is not supported",
            2,
        ),
        (
            "async def outer():\n    class Callback[T: await effect('bound')]:\n        pass\n",
            "await in class type parameters is not supported",
            2,
        ),
        (
            "async def outer():\n    value: await effect('annotation') = 1\n",
            "await in annotations is not supported",
            2,
        ),
    ],
)
def test_await_in_metadata_is_rejected_independent_of_nesting(source, message, line):
    if "type parameters" in message and sys.version_info < (3, 12):
        pytest.skip("PEP 695 type-parameter syntax requires Python 3.12+")
    with pytest.raises(LoweringError, match=message) as caught:
        lower_ast(source, filename="metadata_await.py")
    assert caught.value.filename == "metadata_await.py"
    assert caught.value.lineno == line
    assert caught.value.offset is not None


def test_lowered_tree_contains_no_native_async_or_await_nodes():
    tree = lower_ast(
        """
async def child():
    return await effect("value")
"""
    )
    assert not any(isinstance(node, (ast.AsyncFunctionDef, ast.Await)) for node in ast.walk(tree))
    assert any(isinstance(node, ast.YieldFrom) for node in ast.walk(tree))
