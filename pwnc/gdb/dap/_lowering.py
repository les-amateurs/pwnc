"""Lower ``async def``/``await`` source into synchronous generators.

This module deliberately has no asyncio dependency. Coroutine syntax is used
only as source-level notation for a cooperative effect protocol: lowered
functions are ordinary generator functions, ``await`` becomes ``yield from``,
and :class:`Task` exposes explicit suspension and resumption.

Only frames compiled by this lowerer are suspendable. An arbitrary synchronous
Python frame cannot have its stack captured or resumed by this machinery.
"""

from __future__ import annotations

import ast
import inspect
import linecache
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass
from enum import Enum, auto
from types import CodeType
from typing import Any

_RUNTIME_AWAIT = "__pwnc_ast_lowering_await__"
_MISSING = object()


class LoweringError(SyntaxError):
    """Raised when source uses async semantics this runtime cannot lower."""


class EffectProtocolError(RuntimeError):
    """Raised when a lowered task yields something other than an Effect."""


class CancelledError(BaseException):
    """Cooperative cancellation injected at a suspension point."""


@dataclass(frozen=True, slots=True)
class Effect:
    """A request yielded by lowered code to the synchronous scheduler."""

    name: str
    args: tuple[Any, ...] = ()
    kwargs: Mapping[str, Any] | None = None

    def call_kwargs(self) -> dict[str, Any]:
        return dict(self.kwargs or {})


def effect(name: str, *args: Any, **kwargs: Any) -> Effect:
    """Construct an effect which source code can write as ``await effect(...)``."""

    return Effect(name=name, args=args, kwargs=kwargs)


def _lowered_await(value: Any) -> Generator[Effect, Any, Any]:
    """Generator adapter targeted by the Await -> YieldFrom transform."""

    if isinstance(value, Effect):
        return (yield value)
    if inspect.isgenerator(value):
        return (yield from value)
    if inspect.iscoroutine(value):
        value.close()
        raise TypeError("native coroutine reached the lowered runtime; lower its async def too")
    raise TypeError(f"lowered await accepts only an Effect or another lowered generator, not {type(value).__name__}")


class _Validator(ast.NodeVisitor):
    def __init__(self, filename: str, source: str):
        self.filename = filename
        self._source_lines = source.splitlines(keepends=True)
        self._async_depth = 0

    @staticmethod
    def _character_offset(line: str, byte_offset: int) -> int:
        prefix = line.encode("utf-8")[:byte_offset]
        return len(prefix.decode("utf-8")) + 1

    def _reject(self, node: ast.AST, message: str) -> None:
        error = LoweringError(message)
        error.filename = self.filename
        error.lineno = getattr(node, "lineno", None)
        if error.lineno is None or error.lineno > len(self._source_lines):
            error.offset = getattr(node, "col_offset", 0) + 1
            error.text = None
        else:
            error.text = self._source_lines[error.lineno - 1]
            error.offset = self._character_offset(
                error.text,
                getattr(node, "col_offset", 0),
            )

        error.end_lineno = getattr(node, "end_lineno", None)
        end_col_offset = getattr(node, "end_col_offset", None)
        if error.end_lineno is not None and error.end_lineno <= len(self._source_lines) and end_col_offset is not None:
            end_line = self._source_lines[error.end_lineno - 1]
            error.end_offset = self._character_offset(end_line, end_col_offset)
        raise error

    def _visit_nodes(self, nodes: list[ast.AST | None]) -> None:
        for node in nodes:
            if node is not None:
                self.visit(node)

    def _reject_await_in(self, nodes: list[ast.AST | None], context: str) -> None:
        for root in nodes:
            if root is None:
                continue
            awaited = next(
                (child for child in ast.walk(root) if isinstance(child, ast.Await)),
                None,
            )
            if awaited is not None:
                self._reject(
                    awaited,
                    f"await in {context} is not supported by AST lowering",
                )

    @staticmethod
    def _annotations(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST | None]:
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        return [*(argument.annotation for argument in arguments), node.returns]

    def _visit_function_metadata(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = [*node.args.defaults, *node.args.kw_defaults]
        annotations = self._annotations(node)
        type_params = list(getattr(node, "type_params", ()))

        groups = (
            (list(node.decorator_list), "function decorators"),
            (defaults, "function defaults"),
            (annotations, "function annotations"),
            (type_params, "function type parameters"),
        )
        for nodes, context in groups:
            self._reject_await_in(nodes, context)
            self._visit_nodes(nodes)

    def _visit_body(self, body: list[ast.stmt], async_depth: int) -> None:
        old_depth = self._async_depth
        self._async_depth = async_depth
        try:
            self._visit_nodes(body)
        finally:
            self._async_depth = old_depth

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_metadata(node)
        # A synchronous function body cannot inherit suspension permission from
        # an enclosing lowered async function.
        self._visit_body(node.body, async_depth=0)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        # Decorators/defaults/annotations/type parameters are deliberately a
        # non-suspending subset.  Only the function body establishes a lowered
        # async scope.
        self._visit_function_metadata(node)
        self._visit_body(node.body, async_depth=self._async_depth + 1)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        defaults = [*node.args.defaults, *node.args.kw_defaults]
        self._reject_await_in(defaults, "lambda defaults")
        self._visit_nodes(defaults)
        old_depth = self._async_depth
        self._async_depth = 0
        try:
            self.visit(node.body)
        finally:
            self._async_depth = old_depth

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Class headers execute in the enclosing scope, but the class body is a
        # distinct synchronous scope and cannot suspend an enclosing operation.
        type_params = list(getattr(node, "type_params", ()))
        self._reject_await_in(list(node.decorator_list), "class decorators")
        self._reject_await_in(type_params, "class type parameters")
        self._visit_nodes([*node.decorator_list, *node.bases])
        self._visit_nodes([keyword.value for keyword in node.keywords])
        self._visit_nodes(type_params)
        self._visit_body(node.body, async_depth=0)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._reject_await_in([node.annotation], "annotations")
        self.generic_visit(node)

    def visit_TypeAlias(self, node) -> None:
        type_params = list(getattr(node, "type_params", ()))
        self._reject_await_in(type_params, "type alias type parameters")
        self._reject_await_in([node.value], "annotations")
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._reject(node, "async for is not supported by AST lowering")

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._reject(node, "async with is not supported by AST lowering")

    def visit_Await(self, node: ast.Await) -> None:
        if not self._async_depth:
            self._reject(node, "await is only valid inside a lowered async def")
        self.generic_visit(node)

    def visit_Yield(self, node: ast.Yield) -> None:
        if self._async_depth:
            self._reject(node, "async generators are not supported by AST lowering")
        self.generic_visit(node)

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        if self._async_depth:
            self._reject(node, "yield from inside async def is not supported by AST lowering")
        self.generic_visit(node)

    def _visit_comprehension(self, node: ast.AST) -> None:
        generators = node.generators
        if any(generator.is_async for generator in generators):
            self._reject(node, "async comprehensions are not supported by AST lowering")
        if any(isinstance(child, ast.Await) for child in ast.walk(node)):
            self._reject(node, "await inside comprehensions is not supported by AST lowering")
        self.generic_visit(node)

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension


class _Lowerer(ast.NodeTransformer):
    def __init__(self) -> None:
        self._async_depth = 0

    def _visit_statements(self, statements: list[ast.stmt]) -> list[ast.stmt]:
        result = []
        for statement in statements:
            transformed = self.visit(statement)
            if transformed is None:
                continue
            if isinstance(transformed, list):
                result.extend(transformed)
            else:
                result.append(transformed)
        return result

    def _visit_function_metadata(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        node.decorator_list = [self.visit(decorator) for decorator in node.decorator_list]
        node.args = self.visit(node.args)
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        if hasattr(node, "type_params"):
            node.type_params = [self.visit(parameter) for parameter in node.type_params]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self._visit_function_metadata(node)
        old_depth = self._async_depth
        self._async_depth = 0
        try:
            node.body = self._visit_statements(node.body)
        finally:
            self._async_depth = old_depth
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.FunctionDef:
        self._visit_function_metadata(node)
        old_depth = self._async_depth
        self._async_depth += 1
        try:
            node.body = self._visit_statements(node.body)
        finally:
            self._async_depth = old_depth

        # Even ``async def pure(): return 1`` must return a resumable object rather
        # than executing at call time.  An unreachable yield makes that invariant
        # explicit while preserving a leading docstring.
        generator_marker = ast.If(
            test=ast.Constant(value=False),
            body=[ast.Expr(value=ast.Yield(value=ast.Constant(value=None)))],
            orelse=[],
        )
        ast.copy_location(generator_marker, node)
        insertion = 1 if node.body and _is_docstring(node.body[0]) else 0
        body = [*node.body]
        body.insert(insertion, generator_marker)

        fields: dict[str, Any] = {
            "name": node.name,
            "args": node.args,
            "body": body,
            "decorator_list": node.decorator_list,
            "returns": node.returns,
            "type_comment": node.type_comment,
        }
        if hasattr(node, "type_params"):
            fields["type_params"] = node.type_params
        lowered = ast.FunctionDef(**fields)
        return ast.copy_location(lowered, node)

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        node.args = self.visit(node.args)
        old_depth = self._async_depth
        self._async_depth = 0
        try:
            node.body = self.visit(node.body)
        finally:
            self._async_depth = old_depth
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        node.decorator_list = [self.visit(decorator) for decorator in node.decorator_list]
        node.bases = [self.visit(base) for base in node.bases]
        for keyword in node.keywords:
            keyword.value = self.visit(keyword.value)
        if hasattr(node, "type_params"):
            node.type_params = [self.visit(parameter) for parameter in node.type_params]
        old_depth = self._async_depth
        self._async_depth = 0
        try:
            node.body = self._visit_statements(node.body)
        finally:
            self._async_depth = old_depth
        return node

    def visit_Await(self, node: ast.Await) -> ast.YieldFrom:
        if not self._async_depth:
            raise AssertionError("validator allowed await outside a lowered async body")
        value = self.visit(node.value)
        adapter = ast.Call(
            func=ast.Name(id=_RUNTIME_AWAIT, ctx=ast.Load()),
            args=[value],
            keywords=[],
        )
        return ast.copy_location(ast.YieldFrom(value=adapter), node)


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def lower_ast(source: str, filename: str = "<pwnc-dap-lowered>") -> ast.Module:
    """Parse, validate, and lower source to an executable synchronous AST."""

    tree = ast.parse(source, filename=filename, mode="exec")
    _Validator(filename, source).visit(tree)
    lowered = _Lowerer().visit(tree)
    return ast.fix_missing_locations(lowered)


def compile_lowered(source: str, filename: str = "<pwnc-dap-lowered>") -> CodeType:
    # Do not leak this implementation module's ``__future__`` flags into the
    # caller's source; annotations and other compile-time semantics must match
    # the submitted module.
    code = compile(lower_ast(source, filename), filename, "exec", dont_inherit=True)
    # Virtual plugin filenames do not have a file for traceback to read. Cache
    # the original source so diagnostics show user code rather than generated
    # lowering details (or an empty line).
    linecache.cache[filename] = (
        len(source),
        None,
        source.splitlines(keepends=True),
        filename,
    )
    return code


def exec_lowered(
    source: str,
    namespace: dict[str, Any] | None = None,
    filename: str = "<pwnc-dap-lowered>",
) -> dict[str, Any]:
    """Execute lowered source and return its namespace."""

    namespace = {} if namespace is None else namespace
    namespace.setdefault("effect", effect)
    namespace.setdefault("CancelledError", CancelledError)
    namespace[_RUNTIME_AWAIT] = _lowered_await
    exec(compile_lowered(source, filename), namespace)  # noqa: S102 - intentional source lowering
    return namespace


class TaskState(Enum):
    NEW = auto()
    WAITING = auto()
    DONE = auto()
    FAILED = auto()
    CANCELLED = auto()
    CLOSED = auto()


class Task:
    """A manually resumable lowered generator used by Scheduler and tests."""

    def __init__(self, generator: Generator[Effect, Any, Any]):
        if not inspect.isgenerator(generator):
            raise TypeError("Task requires a lowered generator")
        self.generator = generator
        self.state = TaskState.NEW
        self.effect: Effect | None = None
        self.result: Any = None
        self.exception: BaseException | None = None

    @property
    def terminal(self) -> bool:
        return self.state in {
            TaskState.DONE,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.CLOSED,
        }

    def resume(self, value: Any = _MISSING, error: BaseException | None = None) -> Effect | None:
        if self.terminal:
            raise RuntimeError(f"cannot resume a {self.state.name.lower()} task")
        if value is not _MISSING and error is not None:
            raise ValueError("resume accepts a value or an error, not both")
        if self.state is TaskState.NEW and (value is not _MISSING or error is not None):
            raise RuntimeError("a new task must be started before sending a value or error")

        self.effect = None
        try:
            if error is not None:
                yielded = self.generator.throw(error)
            elif self.state is TaskState.NEW:
                yielded = next(self.generator)
            else:
                yielded = self.generator.send(None if value is _MISSING else value)
        except StopIteration as stopped:
            self.state = TaskState.DONE
            self.result = stopped.value
            return None
        except CancelledError as cancelled:
            self.state = TaskState.CANCELLED
            self.exception = cancelled
            return None
        except BaseException as exc:  # noqa: BLE001 - task records cancellation/system exceptions too
            self.state = TaskState.FAILED
            self.exception = exc
            return None

        if not isinstance(yielded, Effect):
            protocol_error = EffectProtocolError(f"lowered task yielded {type(yielded).__name__}; expected Effect")
            try:
                self.generator.close()
            finally:
                self.state = TaskState.FAILED
                self.exception = protocol_error
            return None

        self.state = TaskState.WAITING
        self.effect = yielded
        return yielded

    def cancel(self) -> Effect | None:
        """Inject cancellation at the current suspension point."""

        if self.terminal:
            return None
        if self.state is TaskState.NEW:
            # An unstarted generator has no active try/finally block to unwind.
            self.generator.close()
            self.state = TaskState.CANCELLED
            self.exception = CancelledError()
            return None
        return self.resume(error=CancelledError())

    def close(self) -> None:
        """Force-close the generator, running active finally blocks."""

        if self.terminal:
            return
        try:
            self.generator.close()
        except BaseException as exc:
            self.state = TaskState.FAILED
            self.exception = exc
            raise
        else:
            self.state = TaskState.CLOSED
            self.effect = None

    def force_close(self, max_attempts: int = 32) -> None:
        """Bound attempts to discard effects yielded while handling GeneratorExit.

        ``generator.close()`` raises ``RuntimeError`` and leaves the frame
        suspended when a ``finally`` block yields.  Reinjecting GeneratorExit
        can advance through a finite number of such cleanup yields.  This is a
        hard-abort path for a disconnected transport, not cooperative cleanup:
        callers should use :meth:`cancel` and drive yielded effects when the
        peer is still available.

        Pathological code can yield forever while handling GeneratorExit.  The
        attempt bound makes that state explicit; terminating the owning GDB
        process is the only absolute cleanup once the bound is exhausted.
        """

        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self.generator.gi_frame is None:
            if not self.terminal:
                self.state = TaskState.CLOSED
                self.effect = None
            return

        last_error: BaseException | None = None
        for _attempt in range(max_attempts):
            if self.generator.gi_frame is None:
                self.state = TaskState.CLOSED
                self.effect = None
                self.exception = None
                return
            try:
                self.generator.close()
            except BaseException as error:
                last_error = error
                if self.generator.gi_frame is None:
                    # A cleanup exception which escaped while closing the frame
                    # is final. Retrying would see only the closed frame and
                    # incorrectly turn that failure into CLOSED.
                    self.state = TaskState.FAILED
                    self.effect = None
                    self.exception = error
                    raise

        if self.generator.gi_frame is None:
            self.state = TaskState.CLOSED
            self.effect = None
            self.exception = None
            return

        error = RuntimeError(f"lowered task still owns a live frame after {max_attempts} forced close attempts")
        if last_error is not None:
            error.__cause__ = last_error
        self.state = TaskState.FAILED
        self.effect = None
        self.exception = error
        raise error


class Scheduler:
    """A tiny, wholly synchronous effect scheduler."""

    def __init__(self, handlers: Mapping[str, Callable[..., Any]] | None = None):
        self.handlers = dict(handlers or {})

    def start(self, generator: Generator[Effect, Any, Any]) -> Task:
        return Task(generator)

    def run(self, generator: Generator[Effect, Any, Any]) -> Any:
        task = self.start(generator)
        current = task.resume()
        while not task.terminal:
            assert current is not None
            try:
                handler = self.handlers[current.name]
            except KeyError:
                error: BaseException = LookupError(f"no handler for effect {current.name!r}")
                current = task.resume(error=error)
                continue

            try:
                result = handler(*current.args, **current.call_kwargs())
            except BaseException as error:  # noqa: BLE001 - injected back into the suspended task
                current = task.resume(error=error)
            else:
                current = task.resume(value=result)

        if task.state is TaskState.DONE:
            return task.result
        assert task.exception is not None
        raise task.exception
