"""Deterministic production stress tests against exact, unmodified bata24 GEF.

The normal-CI cases exercise real GDB DAP routing, callable capabilities, deep
host/GDB alternation, and the JSON-depth boundary.  The longer same-process
session churn is opt-in through ``PWNC_GEF_STRESS_TESTS=1``.

GEF itself is never patched or reloaded.  The optional observation shim is a
separate source file injected into GDB before or after the pinned GEF source.
"""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import gc
import hashlib
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap import DapError, Gdb
from pwnc.gdb.dap.transport import DapTransport


TIMEOUT = 30.0
FANOUT = 16
PUBLIC_RECURSION_DEPTH = 16
POSITIVE_JSON_DEPTH = 31
REJECTED_JSON_DEPTH = 32
GEF_PATH = Path(os.environ.get("PWNC_TEST_GEF", "/home/ctf/bata24-gef/gef.py"))
GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
GDB_PATH = os.environ.get("PWNC_TEST_GDB", "gdb")
FIXTURES = Path(__file__).with_name("fixtures")
EXPERIMENTS = Path(__file__).with_name("experiments")
_GEF_SOURCE_ERROR_MARKERS = (
    "Traceback (most recent call last)",
    "Error occurred in Python",
    "Python Exception",
    "Exception raised",
    "Detailed stacktrace",
)


def _gdb_available() -> bool:
    return shutil.which(GDB_PATH) is not None or (
        os.path.isfile(GDB_PATH) and os.access(GDB_PATH, os.X_OK)
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_stat(path: Path) -> tuple[int, ...]:
    """Metadata that a read-only source operation must preserve.

    Access time is excluded because merely hashing or sourcing the fixture may
    update it on a filesystem without ``noatime``.
    """

    stat = path.stat()
    return (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )


@pytest.fixture
def exact_gef() -> Path:
    if not GEF_PATH.is_file():
        pytest.skip("exact bata24 GEF fixture is not installed")
    if not _gdb_available():
        pytest.skip("live GDB with DAP support is required")

    digest_before = _sha256(GEF_PATH)
    assert digest_before == GEF_SHA256, (
        "the installed GEF fixture is not the agreed unmodified bata24 source: "
        f"expected {GEF_SHA256}, got {digest_before}"
    )
    stat_before = _stable_stat(GEF_PATH)
    try:
        yield GEF_PATH.resolve()
    finally:
        assert _sha256(GEF_PATH) == digest_before
        assert _stable_stat(GEF_PATH) == stat_before


def _isolated_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    temporary = root / "tmp"
    home.mkdir(parents=True)
    temporary.mkdir(parents=True)
    environment = os.environ.copy()
    environment["HOME"] = os.fspath(home)
    environment["TMPDIR"] = os.fspath(temporary)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.setdefault("TERM", "xterm")
    return environment


def _source(gdb: Gdb, path: Path) -> str:
    return gdb.execute("source " + os.fspath(path.resolve()))


def _assert_clean_gef_output(label: str, output: str) -> None:
    assert output.strip(), f"GEF returned no output for {label!r}"
    for marker in _GEF_SOURCE_ERROR_MARKERS:
        assert marker not in output, f"{label!r} leaked {marker!r}:\n{output}"
    assert not any(
        line.lstrip().startswith("[!]") for line in output.splitlines()
    ), f"{label!r} leaked a GEF error diagnostic:\n{output}"


def _open_session(
    gef_path: Path,
    root: Path,
    *,
    injection_order: str | None,
) -> tuple[Gdb, DapTransport]:
    transport = DapTransport(
        gdb_path=GDB_PATH,
        env=_isolated_environment(root),
        init=False,
    )
    gdb = None
    try:
        gdb = Gdb(transport)
        gdb._initialize()
        injection = EXPERIMENTS / "gef_injection_ext.py"
        if injection_order == "before":
            _source(gdb, injection)
            gef_source_output = _source(gdb, gef_path)
        elif injection_order == "after":
            gef_source_output = _source(gdb, gef_path)
            _source(gdb, injection)
        elif injection_order is None:
            gef_source_output = _source(gdb, gef_path)
        else:
            raise ValueError(f"unknown injection order: {injection_order!r}")
        _assert_clean_gef_output("bata24 source", gef_source_output)
        assert "GEF" in gef_source_output
        assert "ready" in gef_source_output.lower()
        gdb.execute("set pagination off")
        gdb.execute("set confirm off")
        gdb.execute("gef config gef.disable_color True")
        gdb.execute('gef config context.layout ""')
        _source(gdb, FIXTURES / "callback_operations.py")
        missing = gdb.execute("gef missing")
        _assert_clean_gef_output("gef missing", missing)
        assert "No missing command" in missing
    except BaseException as initialization_error:
        try:
            if gdb is not None:
                gdb.close()
            else:
                transport.close()
        except BaseException as cleanup_error:  # noqa: BLE001
            initialization_error.add_note(
                "session-construction cleanup also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        raise
    return gdb, transport


def _close_and_assert_session(gdb: Gdb, transport: DapTransport) -> None:
    """Close without masking a body failure; audit clean close on success."""

    active_error = sys.exception()
    cleanup_error = None
    try:
        gdb.close()
    except BaseException as error:  # noqa: BLE001 - preserve body exception
        cleanup_error = error

    violations = []
    if transport.proc.poll() is None:
        violations.append("GDB process is still alive")
    if not transport.closed:
        violations.append("transport is not closed")
    if transport.close_survivors:
        violations.append(
            "close survivors: " + repr(transport.close_survivors)
        )
    if transport.pending_count:
        violations.append(f"{transport.pending_count} pending DAP requests")
    if transport.worker_errors:
        violations.append("worker errors: " + repr(transport.worker_errors))
    if cleanup_error is not None:
        violations.insert(
            0,
            "GDB close raised "
            f"{type(cleanup_error).__name__}: {cleanup_error}",
        )

    if active_error is not None:
        for violation in violations:
            active_error.add_note("session cleanup: " + violation)
        return
    if cleanup_error is not None:
        raise cleanup_error
    assert not violations, "; ".join(violations)


def _wait_dispatcher_quiescent(gdb: Gdb, timeout: float = TIMEOUT) -> None:
    dispatcher = gdb.operations
    with dispatcher._condition:
        quiescent = dispatcher._condition.wait_for(
            lambda: (
                dispatcher._starting_operations == 0
                and not dispatcher._operations
                and not dispatcher._workers
                and not dispatcher._reply_futures
                and not dispatcher._capability_scopes
                and not dispatcher._start_cells
                and not dispatcher._early_callbacks
                and not dispatcher._early_outcomes
                and dispatcher._active_ordinary == 0
                and dispatcher._active_cleanup == 0
            ),
            timeout=timeout,
        )
    assert quiescent, "operation dispatcher did not become quiescent"
    assert dispatcher.active_operations == 0
    assert dispatcher.active_callbacks == 0


def _assert_transport_quiescent(transport: DapTransport) -> None:
    assert transport.pending_count == 0
    assert not transport.worker_errors


def _assert_recursive_result(result: dict, max_depth: int) -> None:
    current = result
    for depth in range(max_depth + 1):
        assert current["depth"] == depth
        assert "pagination" in current["before"].lower()
        assert "confirm" in current["after"].lower()
        value = current["value"]
        assert value["fromDepth"] == depth
        if depth == max_depth:
            assert value["leaf"] is True
        else:
            current = value["child"]


def _run_recursive_probe(gdb: Gdb, max_depth: int) -> tuple[dict, list[int]]:
    callback_threads: dict[int, int] = {}
    gef_outputs: list[str] = []

    def callback(depth: int, *, max_depth: int) -> dict:
        callback_threads[depth] = threading.get_ident()
        gef_outputs.append(gdb.execute("history -n"))
        if depth < max_depth:
            child = gdb.run_operation(
                "pwnc.test.recursive",
                {"depth": depth + 1, "max_depth": max_depth},
                callbacks={"pwnc.test.callback": callback},
                timeout=TIMEOUT,
            )
            return {"fromDepth": depth, "child": child}
        return {"fromDepth": depth, "leaf": True}

    result = gdb.run_operation(
        "pwnc.test.recursive",
        {"depth": 0, "max_depth": max_depth},
        callbacks={"pwnc.test.callback": callback},
        timeout=TIMEOUT,
    )
    assert len(gef_outputs) == max_depth + 1
    return result, [callback_threads[depth] for depth in range(max_depth + 1)]


def _assert_recursive_observation(
    gdb: Gdb,
    transport: DapTransport,
    *,
    max_depth: int,
    callback_threads: list[int],
) -> None:
    trace = gdb.use(timeout=TIMEOUT).call("pwnc.test.snapshot")
    operation_threads = {
        event["threadId"]
        for event in trace
        if event["kind"] in {"operation-enter", "operation-return"}
    }
    assert len(operation_threads) == 1
    assert len(callback_threads) == max_depth + 1
    assert len(set(callback_threads)) == max_depth + 1
    assert set(callback_threads).isdisjoint(operation_threads)
    assert set(callback_threads).isdisjoint(
        {
            transport.reader_thread_id,
            transport.router_thread_id,
            transport.writer_thread_id,
            transport.event_thread_id,
        }
    )

    injection = transport.request("pwncGefInjectionSnapshot", timeout=TIMEOUT)
    history_enters = [
        event
        for event in injection["events"]
        if event["kind"] == "execute-enter" and event["command"] == "history -n"
    ]
    nested_history = [
        event
        for event in injection["events"]
        if event["kind"] == "execute-enter"
        and event["depth"] >= 1
        and event["command"].startswith("show commands")
    ]
    assert len(history_enters) == max_depth + 1
    assert len(nested_history) >= max_depth + 1
    assert {event["threadId"] for event in history_enters + nested_history} == operation_threads

    snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
    assert snapshot["activeCount"] == 0
    assert snapshot["tombstoneCount"] == (max_depth + 1) + 1
    assert all(item["outcome"] == "done" for item in snapshot["tombstones"].values())
    _wait_dispatcher_quiescent(gdb)
    _assert_transport_quiescent(transport)
    assert not gdb.operations.errors
    assert not gdb.operations.rejections


def test_unmodified_bata24_parallel_callable_fanout(
    exact_gef: Path,
    tmp_path: Path,
) -> None:
    """Sixteen simultaneous GEF callbacks share one serialized GDB main lane."""

    gdb, transport = _open_session(
        exact_gef,
        tmp_path / "fanout",
        injection_order=None,
    )
    barrier = threading.Barrier(FANOUT)
    results: list[dict | None] = [None] * FANOUT
    errors: list[tuple[int, BaseException]] = []
    callback_threads: list[int] = []
    result_lock = threading.Lock()

    def host_callback(
        depth: int,
        sync_callback,
        _recursive_callback,
        *,
        max_depth: int,
        binary,
    ) -> dict:
        assert depth == max_depth
        assert binary == (b"pwnc", b"callback")
        with result_lock:
            callback_threads.append(threading.get_ident())
        barrier.wait(timeout=TIMEOUT)
        version = gdb.execute("gef version --compact")
        assert "gdb:" in version
        assert "python:" in version
        return {
            "index": depth,
            "sync": sync_callback(depth, increment=1000),
            "gef": True,
        }

    def run_root(index: int) -> None:
        try:
            value = gdb.use(timeout=TIMEOUT).call(
                "pwnc.test.capabilities",
                host_callback,
                index,
                max_depth=index,
            )
        except BaseException as error:  # noqa: BLE001 - synchronous boundary
            with result_lock:
                errors.append((index, error))
        else:
            results[index] = value

    roots = [
        threading.Thread(
            target=run_root,
            args=(index,),
            name=f"bata24-fanout-root-{index}",
        )
        for index in range(FANOUT)
    ]
    try:
        for root in roots:
            root.start()
        deadline = time.monotonic() + TIMEOUT
        for root in roots:
            root.join(max(0.0, deadline - time.monotonic()))

        assert not [root.name for root in roots if root.is_alive()]
        assert not errors
        assert results == [
            {"index": index, "sync": index + 1000, "gef": True}
            for index in range(FANOUT)
        ]
        assert len(callback_threads) == FANOUT
        assert len(set(callback_threads)) == FANOUT
        assert gdb.operations.peak_active_callbacks >= FANOUT

        snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
        assert snapshot["tombstoneCount"] == FANOUT * 2
        assert all(item["outcome"] == "done" for item in snapshot["tombstones"].values())
        _wait_dispatcher_quiescent(gdb)
        _assert_transport_quiescent(transport)
        assert not gdb.operations.errors
        assert not gdb.operations.rejections
    finally:
        active_error = sys.exception()
        barrier.abort()
        try:
            _close_and_assert_session(gdb, transport)
        finally:
            cleanup_deadline = time.monotonic() + TIMEOUT
            for root in roots:
                if root.ident is not None:
                    root.join(max(0.0, cleanup_deadline - time.monotonic()))
            survivors = [root.name for root in roots if root.is_alive()]
            if survivors:
                message = "fanout roots survived cleanup: " + ", ".join(survivors)
                if active_error is None:
                    raise AssertionError(message)
                active_error.add_note(message)


def test_unmodified_bata24_recursive_callable_depth_16(
    exact_gef: Path,
    tmp_path: Path,
) -> None:
    """Deep public capabilities alternate native host stacks and GEF calls."""

    gdb, transport = _open_session(
        exact_gef,
        tmp_path / "callable-depth-16",
        injection_order="before",
    )
    callback_threads: list[int] = []
    try:

        def host_callback(
            depth: int,
            sync_callback,
            recursive_callback,
            *,
            max_depth: int,
            binary,
        ) -> dict:
            callback_threads.append(threading.get_ident())
            assert max_depth == PUBLIC_RECURSION_DEPTH
            assert binary == (b"pwnc", b"callback")
            version = gdb.execute("gef version --compact")
            assert "gdb:" in version
            assert "python:" in version
            result = {
                "depth": depth,
                "sync": sync_callback(depth, increment=1000),
            }
            if depth == max_depth:
                result["leaf"] = binary
            else:
                result["child"] = recursive_callback(depth + 1)
            return result

        result = gdb.use(timeout=TIMEOUT).call(
            "pwnc.test.capabilities",
            host_callback,
            0,
            max_depth=PUBLIC_RECURSION_DEPTH,
        )
        current = result
        for depth in range(PUBLIC_RECURSION_DEPTH + 1):
            assert current["depth"] == depth
            assert current["sync"] == depth + 1000
            if depth == PUBLIC_RECURSION_DEPTH:
                assert current["leaf"] == (b"pwnc", b"callback")
            else:
                current = current["child"]

        assert len(callback_threads) == PUBLIC_RECURSION_DEPTH + 1
        assert len(set(callback_threads)) == PUBLIC_RECURSION_DEPTH + 1
        assert set(callback_threads).isdisjoint(
            {
                transport.reader_thread_id,
                transport.router_thread_id,
                transport.writer_thread_id,
                transport.event_thread_id,
            }
        )
        assert gdb.operations.peak_active_callbacks >= PUBLIC_RECURSION_DEPTH + 1

        trace = gdb.use(timeout=TIMEOUT).call("pwnc.test.snapshot")
        recursive_enters = [
            event
            for event in trace
            if event["kind"] == "capability-recursive-enter"
        ]
        assert [event["depth"] for event in recursive_enters] == list(
            range(1, PUBLIC_RECURSION_DEPTH + 1)
        )

        snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
        assert snapshot["tombstoneCount"] == 2 * PUBLIC_RECURSION_DEPTH + 3
        assert all(
            item["outcome"] == "done"
            for item in snapshot["tombstones"].values()
        )
        _wait_dispatcher_quiescent(gdb)
        _assert_transport_quiescent(transport)
        assert not gdb.operations.errors
        assert not gdb.operations.rejections
    finally:
        _close_and_assert_session(gdb, transport)


def test_unmodified_bata24_recursive_depth_31_succeeds(
    exact_gef: Path,
    tmp_path: Path,
) -> None:
    """The deepest nested-result tree allowed by the 64-level JSON guard works."""

    gdb, transport = _open_session(
        exact_gef,
        tmp_path / "depth-31",
        injection_order="before",
    )
    try:
        result, callback_threads = _run_recursive_probe(gdb, POSITIVE_JSON_DEPTH)
        _assert_recursive_result(result, POSITIVE_JSON_DEPTH)
        _assert_recursive_observation(
            gdb,
            transport,
            max_depth=POSITIVE_JSON_DEPTH,
            callback_threads=callback_threads,
        )
    finally:
        _close_and_assert_session(gdb, transport)


def test_unmodified_bata24_recursive_depth_32_is_bounded_and_quiescent(
    exact_gef: Path,
    tmp_path: Path,
) -> None:
    """One level beyond the JSON boundary rejects and cooperatively unwinds."""

    gdb, transport = _open_session(
        exact_gef,
        tmp_path / "depth-32",
        injection_order="after",
    )
    try:
        started = time.monotonic()
        with pytest.raises(DapError, match="JSON nesting limit"):
            _run_recursive_probe(gdb, REJECTED_JSON_DEPTH)
        assert time.monotonic() - started < TIMEOUT

        # GDB rejected a callback reply after it had accepted the operation
        # tree.  Closing the dispatcher performs cooperative cancellation while
        # leaving the DAP transport alive so both halves can be inspected.
        survivors = gdb.operations.close(timeout=TIMEOUT)
        assert not survivors
        _wait_dispatcher_quiescent(gdb)

        snapshot = transport.request("pwncOperationSnapshot", timeout=TIMEOUT)
        assert snapshot["activeCount"] == 0
        assert snapshot["tombstoneCount"] == REJECTED_JSON_DEPTH + 1
        outcomes = {item["outcome"] for item in snapshot["tombstones"].values()}
        # Deepest children may complete before an ancestor's increasingly
        # nested callback result crosses the limit.  The remaining tree must
        # still contain a terminal rejection/cancellation and fully unwind.
        assert outcomes <= {"done", "failed", "cancelled"}
        assert outcomes & {"failed", "cancelled"}
        _assert_transport_quiescent(transport)
        assert gdb.operations.errors
        assert not gdb.operations.rejections
    finally:
        _close_and_assert_session(gdb, transport)


@pytest.mark.skipif(
    os.environ.get("PWNC_GEF_STRESS_TESTS") != "1",
    reason="set PWNC_GEF_STRESS_TESTS=1 to run same-process Bata24 session churn",
)
def test_unmodified_bata24_same_process_session_soak(
    exact_gef: Path,
    tmp_path: Path,
) -> None:
    """Repeated GEF sessions return the host process to its exact baseline."""

    if not sys.platform.startswith("linux") or not Path("/proc/self/fd").is_dir():
        pytest.skip("Linux /proc fd accounting is required for the GEF soak")
    try:
        cycles = int(os.environ.get("PWNC_GEF_STRESS_CYCLES", "10"))
    except ValueError as error:
        pytest.fail(f"PWNC_GEF_STRESS_CYCLES must be an integer: {error}")
    if cycles <= 0:
        pytest.fail("PWNC_GEF_STRESS_CYCLES must be positive")

    gc.collect()
    baseline_threads = set(threading.enumerate())
    baseline_fds = len(os.listdir("/proc/self/fd"))

    for cycle in range(cycles):
        gdb, transport = _open_session(
            exact_gef,
            tmp_path / f"cycle-{cycle}",
            injection_order="before" if cycle % 2 else "after",
        )
        try:
            result, callback_threads = _run_recursive_probe(gdb, 8)
            _assert_recursive_result(result, 8)
            _assert_recursive_observation(
                gdb,
                transport,
                max_depth=8,
                callback_threads=callback_threads,
            )
        finally:
            _close_and_assert_session(gdb, transport)

        gc.collect()
        assert set(threading.enumerate()) == baseline_threads
        assert len(os.listdir("/proc/self/fd")) == baseline_fds
