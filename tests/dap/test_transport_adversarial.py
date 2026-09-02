"""Adversarial regressions for synchronous DAP transport ownership.

These tests use a deliberately inert executable in place of GDB and inject
valid DAP frames at the reader/router boundary.  That keeps failure timing
deterministic while exercising the production queues, futures, workers, and
shutdown machinery.
"""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import json
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pwnc.gdb.dap.transport as transport_module
from pwnc.gdb.dap.callbacks import OperationDispatcher
from pwnc.gdb.dap.transport import DapError, DapOverload, DapTransport, _Inbound


TIMEOUT = 3.0


@pytest.fixture
def inert_gdb(tmp_path):
    """An executable that keeps all three transport pipes open but says nothing."""
    executable = tmp_path / "inert-gdb"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import time\n"
        "time.sleep(60)\n"
    )
    executable.chmod(0o755)
    return executable


def _response_payload(future, *, command=None, server_seq=100_000, body=None):
    return json.dumps(
        {
            "seq": server_seq,
            "type": "response",
            "request_seq": future._dap_seq,
            "success": True,
            "command": command or future._dap_command,
            "body": {} if body is None else body,
        },
        separators=(",", ":"),
    ).encode()


def _event_payload(index):
    return json.dumps(
        {
            "seq": 200_000 + index,
            "type": "event",
            "event": "pwncAdversarial",
            "body": {"index": index},
        },
        separators=(",", ":"),
    ).encode()


def _output_payload(output, *, server_seq=250_000):
    return json.dumps(
        {
            "seq": server_seq,
            "type": "event",
            "event": "output",
            "body": {"category": "stdout", "output": output},
        },
        separators=(",", ":"),
    ).encode()


def _operation_done_payload(operation_id, result):
    return json.dumps(
        {
            "seq": 300_000 + operation_id,
            "type": "event",
            "event": "pwncOperationDone",
            "body": {"operationId": operation_id, "result": result},
        },
        separators=(",", ":"),
    ).encode()


def _inject_response(transport, future, **kwargs):
    assert transport._queue_inbound(
        _Inbound("frame", _response_payload(future, **kwargs)),
        timeout=TIMEOUT,
    )


def _wait_until(predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


def _pending_command(transport, command):
    with transport._state_lock:
        return next(
            (
                future
                for future in transport._pending.values()
                if future._dap_command == command
            ),
            None,
        )


def test_startup_output_claim_uses_wire_barrier_and_is_exactly_once(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    delivered = []
    delivered_tail = threading.Event()
    outcome = []

    def observe(body):
        delivered.append(body["output"])
        if "tail-before-marker" in body["output"]:
            delivered_tail.set()

    def claim():
        try:
            outcome.append(transport.claim_startup_output(timeout=TIMEOUT))
        except BaseException as error:  # noqa: BLE001 - relay test failure
            outcome.append(error)

    try:
        transport.on("output", observe)
        assert transport._queue_inbound(
            _Inbound("frame", _output_payload("early init log\n")),
            timeout=TIMEOUT,
        )
        assert _wait_until(lambda: bytes(transport._startup_output) == b"early init log\n")

        thread = threading.Thread(target=claim)
        thread.start()
        assert _wait_until(
            lambda: _pending_command(transport, "pwncConsoleOutputBarrier")
            is not None
        )
        future = _pending_command(transport, "pwncConsoleOutputBarrier")
        with transport._state_lock:
            marker = transport._startup_barrier_marker
        assert marker is not None

        # The output-reader event is allowed to beat the request response.
        # Prefix text remains visible, while the private marker is stripped.
        assert transport._queue_inbound(
            _Inbound(
                "frame",
                _output_payload("tail-before-marker\n" + marker + "\n"),
            ),
            timeout=TIMEOUT,
        )
        _inject_response(transport, future, server_seq=250_001)
        thread.join(TIMEOUT)

        assert not thread.is_alive()
        assert outcome == ["early init log\ntail-before-marker\n"]
        assert delivered_tail.wait(TIMEOUT)
        assert marker not in "".join(delivered)
        assert transport.claim_startup_output(timeout=TIMEOUT) == ""
    finally:
        transport.close()


def test_startup_output_is_bounded_and_can_be_restored_after_attach_failure(
    inert_gdb,
) -> None:
    transport = DapTransport(str(inert_gdb), startup_output_bytes=8)

    def complete_claim():
        outcome = []
        thread = threading.Thread(
            target=lambda: outcome.append(
                transport.claim_startup_output(timeout=TIMEOUT)
            )
        )
        thread.start()
        assert _wait_until(
            lambda: _pending_command(transport, "pwncConsoleOutputBarrier")
            is not None
        )
        future = _pending_command(transport, "pwncConsoleOutputBarrier")
        with transport._state_lock:
            marker = transport._startup_barrier_marker
        _inject_response(transport, future)
        assert transport._queue_inbound(
            _Inbound("frame", _output_payload(marker + "\n")),
            timeout=TIMEOUT,
        )
        thread.join(TIMEOUT)
        assert not thread.is_alive()
        return outcome[0]

    try:
        assert transport._queue_inbound(
            _Inbound("frame", _output_payload("0123456789")),
            timeout=TIMEOUT,
        )
        assert _wait_until(lambda: transport._startup_output_truncated)
        first = complete_claim()
        assert first.startswith(transport_module._STARTUP_OUTPUT_TRUNCATED)
        assert first.endswith("23456789")

        transport.restore_startup_output("retry\n")
        second = complete_claim()
        assert second == "retry\n"
        assert transport.claim_startup_output(timeout=TIMEOUT) == ""
    finally:
        transport.close()


def test_future_callback_is_not_dropped_at_reentrant_worker_limit(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb), max_callback_workers=1)
    release_reentrant = threading.Event()
    reentrant_entered = threading.Event()
    future_callback_called = threading.Event()

    def blocking_reentrant_handler(_body):
        reentrant_entered.set()
        assert release_reentrant.wait(TIMEOUT)

    def future_callback(_future):
        future_callback_called.set()

    try:
        transport.on(
            "pwncAdversarial",
            blocking_reentrant_handler,
            reentrant=True,
        )
        assert transport._queue_inbound(
            _Inbound("frame", _event_payload(0)),
            timeout=TIMEOUT,
        )
        assert reentrant_entered.wait(TIMEOUT)

        future = transport.send("completion-must-have-separate-admission")
        future.add_done_callback(future_callback)
        _inject_response(transport, future, server_seq=1)
        assert future.result(TIMEOUT)["success"] is True

        # The only bounded reentrant slot is still occupied.  Future callback
        # delivery has no rejection channel and therefore must use separately
        # guaranteed admission rather than being discarded at this limit.
        assert future_callback_called.wait(TIMEOUT)
        assert not release_reentrant.is_set()
    finally:
        release_reentrant.set()
        transport.close()


def test_inline_future_hook_precedes_following_wire_event(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    order = []
    event_called = threading.Event()
    future = transport.send("ordered-response")
    future._add_inline_done_callback(lambda _future: order.append("response"))

    def on_event(_body):
        order.append("event")
        event_called.set()

    transport.on("pwncAdversarial", on_event)
    try:
        assert transport._queue_inbound(
            _Inbound("frame", _response_payload(future, server_seq=2)),
            timeout=TIMEOUT,
        )
        assert transport._queue_inbound(
            _Inbound("frame", _event_payload(2)),
            timeout=TIMEOUT,
        )
        assert event_called.wait(TIMEOUT)
        assert order == ["response", "event"]
    finally:
        transport.close()


def test_late_future_callback_is_delivered_after_transport_close(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    future = transport.send("finished-before-close")
    _inject_response(transport, future)
    raw_response = future.result(TIMEOUT)
    transport.close()

    called = threading.Event()
    observed = []

    def callback(done):
        observed.append(done.result())
        called.set()

    future.add_done_callback(callback)
    assert called.wait(TIMEOUT)
    assert observed == [raw_response]


def test_concurrent_close_from_callbacks_has_no_callback_wait_cycle(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb), max_callback_workers=4)
    rendezvous = threading.Barrier(2)
    callbacks_done = threading.Event()
    result_lock = threading.Lock()
    errors = []
    elapsed = []

    def close_from_callback(_future):
        try:
            rendezvous.wait(TIMEOUT)
            started = time.monotonic()
            transport.close(timeout=2.0)
            duration = time.monotonic() - started
            with result_lock:
                elapsed.append(duration)
                if len(elapsed) + len(errors) == 2:
                    callbacks_done.set()
        except BaseException as error:  # noqa: BLE001 - capture worker result
            with result_lock:
                errors.append(error)
                if len(elapsed) + len(errors) == 2:
                    callbacks_done.set()

    futures = [transport.send(f"close-{index}") for index in range(2)]
    for future in futures:
        future.add_done_callback(close_from_callback)

    try:
        for index, future in enumerate(futures):
            _inject_response(transport, future, server_seq=10 + index)
            assert future.result(TIMEOUT)["success"] is True

        # A close leader must not join a callback that is itself waiting for
        # that same close operation to finish.
        completed_without_cycle = callbacks_done.wait(1.0)
        if not completed_without_cycle:
            callbacks_done.wait(TIMEOUT)
        assert completed_without_cycle
        assert not errors
        assert len(elapsed) == 2
        assert max(elapsed) < 1.0
    finally:
        try:
            transport.close(timeout=TIMEOUT)
        except DapError:
            pass


def test_public_set_running_or_notify_cancel_cannot_orphan_request(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    try:
        future = transport.send("must-remain-correlated")

        # A transport may reject this executor-only Future method.  If it
        # permits the transition, a subsequent failed cancellation must leave
        # the request registered so its real response can still complete it.
        try:
            transitioned = future.set_running_or_notify_cancel()
        except RuntimeError:
            transitioned = False
        else:
            assert transitioned is True
            assert future.cancel() is False

        assert transport.pending_count == 1
        _inject_response(transport, future, body={"correlated": True})
        assert future.result(TIMEOUT)["body"] == {"correlated": True}
        assert transport.pending_count == 0
    finally:
        transport.close()


def test_failed_close_is_replayed_to_later_callers(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    real_reader = transport._reader

    class ImmortalInfrastructureThread:
        name = "injected-immortal-reader"
        ident = -1

        @staticmethod
        def join(_timeout=None):
            return None

        @staticmethod
        def is_alive():
            return True

    transport._reader = ImmortalInfrastructureThread()
    try:
        with pytest.raises(DapError, match="injected-immortal-reader") as first:
            transport.close(timeout=0.5)
        with pytest.raises(DapError, match="injected-immortal-reader") as replay:
            transport.close(timeout=0.5)
        assert str(replay.value) == str(first.value)
    finally:
        real_reader.join(TIMEOUT)
        if transport.proc.poll() is None:
            transport.proc.kill()
            transport.proc.wait(TIMEOUT)


def test_explicit_pending_request_limit_reopens_after_completion(inert_gdb) -> None:
    transport = DapTransport(
        str(inert_gdb),
        queue_messages=8,
        max_pending_requests=2,
    )
    try:
        first = transport.send("first")
        second = transport.send("second")
        assert transport.pending_count == 2

        with pytest.raises(DapOverload):
            transport.send("rejected-at-limit")
        assert transport.pending_count == 2

        _inject_response(transport, first, server_seq=20)
        assert first.result(TIMEOUT)["success"] is True
        assert transport.pending_count == 1

        admitted = transport.send("admitted-after-completion")
        assert transport.pending_count == 2
        assert admitted._dap_seq == second._dap_seq + 1
    finally:
        transport.close()


def test_mismatched_response_command_is_terminal_protocol_failure(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    try:
        first = transport.send("expected-command")
        collateral = transport.send("also-pending")
        _inject_response(
            transport,
            first,
            command="wrong-command",
            server_seq=30,
        )

        with pytest.raises(DapError):
            first.result(TIMEOUT)
        with pytest.raises(DapError):
            collateral.result(TIMEOUT)
        assert _wait_until(lambda: transport.closed)
        assert transport.pending_count == 0
        reason = transport.terminal_reason or ""
        assert "expected-command" in reason
        assert "wrong-command" in reason
        with pytest.raises(DapError):
            transport.send("not-admitted-after-protocol-failure")
    finally:
        transport.close()


def test_future_callbacks_remain_ordered_across_completion_boundary(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb), max_callback_workers=4)
    first_entered = threading.Event()
    release_first = threading.Event()
    second_called = threading.Event()
    order = []

    def first_callback(_future):
        order.append("first-enter")
        first_entered.set()
        assert release_first.wait(TIMEOUT)
        order.append("first-exit")

    def second_callback(_future):
        order.append("second")
        second_called.set()

    try:
        future = transport.send("ordered-callbacks")
        future.add_done_callback(first_callback)
        _inject_response(transport, future, server_seq=40)
        assert future.result(TIMEOUT)["success"] is True
        assert first_entered.wait(TIMEOUT)

        # This callback is registered after completion, while the callback
        # registered before completion is still active.
        future.add_done_callback(second_callback)
        assert not second_called.wait(0.15)

        release_first.set()
        assert second_called.wait(TIMEOUT)
        assert order == ["first-enter", "first-exit", "second"]
    finally:
        release_first.set()
        transport.close()


def test_worker_error_history_is_a_bounded_recent_tail(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb), error_history=8)
    try:
        for index in range(100):
            transport._record_worker_error(RuntimeError(f"worker-{index}"))
        errors = transport.worker_errors
        assert len(errors) == 8
        assert [str(error) for error in errors] == [
            f"worker-{index}" for index in range(92, 100)
        ]
    finally:
        transport.close()


def test_saturated_inbound_queue_cannot_strand_router_during_close(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb), queue_messages=1)
    route_entered = threading.Event()
    release_route = threading.Event()
    close_done = threading.Event()
    close_errors = []
    original_route_message = transport._route_message

    def blocked_route(message):
        route_entered.set()
        assert release_route.wait(TIMEOUT)
        original_route_message(message)

    transport._route_message = blocked_route
    assert transport._queue_inbound(
        _Inbound("frame", _event_payload(0)),
        timeout=TIMEOUT,
    )
    assert route_entered.wait(TIMEOUT)
    transport._inbound.put_nowait(_Inbound("frame", _event_payload(1)))
    assert transport._inbound.full()
    producer_done = threading.Event()
    producer_result = []

    def blocked_producer():
        producer_result.append(
            transport._queue_inbound(_Inbound("frame", _event_payload(2)))
        )
        producer_done.set()

    producer = threading.Thread(target=blocked_producer, name="adversarial-producer")
    producer.start()
    assert not producer_done.wait(0.05)

    def close_transport():
        try:
            transport.close(timeout=2.0)
        except BaseException as error:  # noqa: BLE001 - capture thread result
            close_errors.append(error)
        finally:
            close_done.set()

    closer = threading.Thread(target=close_transport, name="adversarial-closer")
    closer.start()
    try:
        assert transport._router_stop.wait(TIMEOUT)
        # Stop control broadcasts the queue condition, so a bounded producer
        # is cancelled without periodic timeout probes or waiting for the
        # router to drain a data slot.
        assert producer_done.wait(TIMEOUT)
        assert producer_result == [False]
        release_route.set()
        assert close_done.wait(TIMEOUT)
        closer.join(TIMEOUT)
        assert not closer.is_alive()
        assert not close_errors
        assert transport._router_done.is_set()
        assert not transport._router.is_alive()
    finally:
        release_route.set()
        producer.join(TIMEOUT)
        closer.join(TIMEOUT)
        if transport.proc.poll() is None:
            transport.proc.kill()
            transport.proc.wait(TIMEOUT)


def test_idle_wakeable_lanes_block_without_timed_gets(
    inert_gdb,
    monkeypatch,
) -> None:
    real_get = transport_module._WakeableQueue.get
    observed = []
    observed_lock = threading.Lock()
    lane_names = {
        "pwnc-dap-router",
        "pwnc-dap-writer",
        "pwnc-dap-events",
    }

    def recording_get(queue_instance, block=True, timeout=None):
        name = threading.current_thread().name
        if name in lane_names:
            with observed_lock:
                observed.append((name, block, timeout))
        return real_get(queue_instance, block=block, timeout=timeout)

    monkeypatch.setattr(transport_module._WakeableQueue, "get", recording_get)
    transport = DapTransport(str(inert_gdb))
    try:
        def every_lane_blocked():
            with observed_lock:
                return lane_names.issubset(name for name, _block, _timeout in observed)

        assert _wait_until(every_lane_blocked)
        with observed_lock:
            calls = list(observed)
        for name in lane_names:
            lane_calls = [
                (block, timeout)
                for call_name, block, timeout in calls
                if call_name == name
            ]
            assert lane_calls
            assert lane_calls == [(True, None)]
    finally:
        transport.close()


def test_constructor_thread_start_failure_reaps_process_and_started_threads(
    inert_gdb,
    monkeypatch,
) -> None:
    real_popen = transport_module.subprocess.Popen
    real_start = threading.Thread.start
    spawned_processes = []
    started_transport_threads = []

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        spawned_processes.append(process)
        return process

    def failing_start(thread, *args, **kwargs):
        if thread.name == "pwnc-dap-events":
            raise RuntimeError("injected event-thread start failure")
        result = real_start(thread, *args, **kwargs)
        if thread.name.startswith("pwnc-dap-"):
            started_transport_threads.append(thread)
        return result

    monkeypatch.setattr(transport_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(threading.Thread, "start", failing_start)

    with pytest.raises(RuntimeError, match="injected event-thread start failure"):
        DapTransport(str(inert_gdb))

    assert len(spawned_processes) == 1
    assert spawned_processes[0].poll() is not None
    assert len(started_transport_threads) == 4
    assert all(not thread.is_alive() for thread in started_transport_threads)


def test_post_close_callback_affinity_does_not_use_stale_thread_ids(
    inert_gdb,
) -> None:
    transport = DapTransport(str(inert_gdb))
    future = transport.send("thread-id-reuse")
    _inject_response(transport, future, server_seq=70)
    assert future.result(TIMEOUT)["success"] is True
    transport.close()

    # Deterministically model the OS reusing a dead infrastructure ident for
    # this ordinary caller.  Object identity, unlike an integer ident, cannot
    # alias the dead completion thread.
    transport._completion_thread_id = threading.get_ident()
    called = []
    future.add_done_callback(lambda done: called.append(done.result()))
    assert len(called) == 1
    assert called[0]["command"] == "thread-id-reuse"


def test_future_worker_start_failure_terminalizes_then_delivers_callback(
    inert_gdb,
    monkeypatch,
) -> None:
    transport = DapTransport(str(inert_gdb))
    real_start = threading.Thread.start
    called = threading.Event()
    callback_thread = []

    def selective_failure(thread, *args, **kwargs):
        if thread.name.startswith("pwnc-dap-future-"):
            raise RuntimeError("injected Future callback start failure")
        return real_start(thread, *args, **kwargs)

    monkeypatch.setattr(threading.Thread, "start", selective_failure)
    future = transport.send("callback-start-failure")
    future.add_done_callback(
        lambda _done: (callback_thread.append(threading.current_thread()), called.set())
    )
    try:
        _inject_response(transport, future, server_seq=71)
        assert future.result(TIMEOUT)["success"] is True
        assert called.wait(TIMEOUT)
        assert callback_thread == [transport._completion_dispatcher]
        assert _wait_until(lambda: transport.closed)
        assert "could not start Future callback worker" in (
            transport.terminal_reason or ""
        )
    finally:
        transport.close()


def test_unexpected_close_failure_is_reaped_stored_and_replayed(
    inert_gdb,
    monkeypatch,
) -> None:
    transport = DapTransport(str(inert_gdb))

    def fail_terminate():
        raise RuntimeError("injected terminate failure")

    monkeypatch.setattr(transport.proc, "terminate", fail_terminate)
    with pytest.raises(RuntimeError, match="injected terminate failure"):
        transport.close(timeout=TIMEOUT)
    assert transport.proc.poll() is not None
    assert not transport._completion_dispatcher.is_alive()
    assert not transport._router.is_alive()
    with pytest.raises(RuntimeError, match="injected terminate failure"):
        transport.close(timeout=TIMEOUT)


def test_callback_owned_close_reports_its_still_live_worker(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    close_returned = threading.Event()
    release = threading.Event()

    def callback(_future):
        transport.close(timeout=TIMEOUT)
        close_returned.set()
        assert release.wait(TIMEOUT)

    future = transport.send("callback-owned-close")
    future.add_done_callback(callback)
    try:
        _inject_response(transport, future, server_seq=72)
        assert future.result(TIMEOUT)["success"] is True
        assert close_returned.wait(TIMEOUT)
        assert any(
            name.startswith("pwnc-dap-future-")
            for name in transport.close_survivors
        )
    finally:
        release.set()
        transport.close()


def test_terminal_listener_is_exact_once_lock_free_and_late_safe(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    called = threading.Event()
    observed = []
    state_lock_was_free = []

    def listener(reason):
        acquired = threading.Event()

        def probe_state_lock():
            with transport._state_lock:
                acquired.set()

        probe = threading.Thread(target=probe_state_lock)
        probe.start()
        state_lock_was_free.append(acquired.wait(TIMEOUT))
        probe.join(TIMEOUT)
        observed.append(reason)
        called.set()

    unsubscribe = transport.add_terminal_listener(listener)
    cancelled = []
    cancel_unsubscribe = transport.add_terminal_listener(cancelled.append)
    assert cancel_unsubscribe() is True
    assert cancel_unsubscribe() is False

    transport.close()
    assert called.wait(TIMEOUT)
    assert observed == ["transport closed"]
    assert state_lock_was_free == [True]
    assert cancelled == []
    assert unsubscribe() is False
    assert transport.wait_closed(0)

    late = []
    late_unsubscribe = transport.add_terminal_listener(late.append)
    assert late == ["transport closed"]
    assert late_unsubscribe() is False


def test_terminal_listener_failure_isolated_from_reentrant_and_later_delivery(
    inert_gdb,
) -> None:
    transport = DapTransport(str(inert_gdb))
    order = []
    nested_unsubscribes = []

    def failing_listener(_reason):
        order.append("failing")
        raise RuntimeError("injected terminal listener failure")

    def nested_listener(_reason):
        order.append("nested")

    def registering_listener(_reason):
        order.append("registering")
        nested_unsubscribes.append(
            transport.add_terminal_listener(nested_listener)
        )

    def later_listener(_reason):
        order.append("later")

    transport.add_terminal_listener(failing_listener)
    transport.add_terminal_listener(registering_listener)
    transport.add_terminal_listener(later_listener)

    transport.close()

    assert order == ["failing", "registering", "nested", "later"]
    assert len(nested_unsubscribes) == 1
    assert nested_unsubscribes[0]() is False
    failures = [
        error
        for error in transport.worker_errors
        if isinstance(error, RuntimeError)
        and str(error) == "injected terminal listener failure"
    ]
    assert len(failures) == 1

    # Repeated close must not redeliver either the snapshotted listeners or the
    # listener registered reentrantly while terminal delivery was in progress.
    transport.close()
    assert order == ["failing", "registering", "nested", "later"]


def test_terminal_listener_follows_wire_prior_ordered_event(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    handler_entered = threading.Event()
    release_handler = threading.Event()
    terminal_called = threading.Event()
    order = []

    def handler(_body):
        order.append("event-enter")
        handler_entered.set()
        assert release_handler.wait(TIMEOUT)
        order.append("event-exit")

    def terminal(_reason):
        order.append("terminal")
        terminal_called.set()

    transport.on("pwncAdversarial", handler)
    transport.add_terminal_listener(terminal)
    try:
        assert transport._queue_inbound(
            _Inbound("frame", _event_payload(90)),
            timeout=TIMEOUT,
        )
        assert transport._queue_inbound(
            _Inbound("eof", "ordered EOF"),
            timeout=TIMEOUT,
        )
        assert handler_entered.wait(TIMEOUT)
        assert transport.wait_closed(TIMEOUT)
        assert not terminal_called.wait(0.05)
        late = []
        late_called = threading.Event()

        def late_terminal(_reason):
            order.append("late-terminal")
            late.append(True)
            late_called.set()

        late_unsubscribe = transport.add_terminal_listener(late_terminal)
        assert late == []
        release_handler.set()
        assert terminal_called.wait(TIMEOUT)
        assert late_called.wait(TIMEOUT)
        assert order == [
            "event-enter",
            "event-exit",
            "terminal",
            "late-terminal",
        ]
        assert late == [True]
        assert late_unsubscribe() is False
    finally:
        release_handler.set()
        transport.close()


def test_start_response_and_done_before_eof_complete_the_operation(inert_gdb) -> None:
    transport = DapTransport(str(inert_gdb))
    dispatcher = OperationDispatcher(transport)
    accept_entered = threading.Event()
    release_accept = threading.Event()
    finished = threading.Event()
    outcome = []
    real_accept = dispatcher._accept_started_operation

    def gated_accept(started, spec, *, orphaned=False):
        accept_entered.set()
        assert release_accept.wait(TIMEOUT)
        return real_accept(started, spec, orphaned=orphaned)

    dispatcher._accept_started_operation = gated_accept

    def run_operation():
        try:
            outcome.append(dispatcher.run("wire-complete-before-eof"))
        except BaseException as error:  # noqa: BLE001 - relay exact result
            outcome.append(error)
        finally:
            finished.set()

    runner = threading.Thread(target=run_operation)
    runner.start()
    try:
        assert _wait_until(lambda: transport.pending_count == 1)
        with transport._state_lock:
            start_future = next(iter(transport._pending.values()))
        _inject_response(
            transport,
            start_future,
            body={"operationId": 41, "operationName": "wire-complete-before-eof"},
        )
        assert accept_entered.wait(TIMEOUT)
        assert transport._queue_inbound(
            _Inbound("frame", _operation_done_payload(41, "received-result")),
            timeout=TIMEOUT,
        )
        assert transport._queue_inbound(
            _Inbound("eof", "EOF after complete operation"),
            timeout=TIMEOUT,
        )
        assert transport.wait_closed(TIMEOUT)
        assert _wait_until(lambda: dispatcher._terminal_error is not None)
        release_accept.set()
        assert finished.wait(TIMEOUT)
        runner.join(TIMEOUT)
        assert outcome == ["received-result"]
    finally:
        release_accept.set()
        dispatcher.close()
        transport.close()
        runner.join(TIMEOUT)


def test_start_response_then_eof_without_outcome_fails_and_retires_start(
    inert_gdb,
) -> None:
    transport = DapTransport(str(inert_gdb))
    dispatcher = OperationDispatcher(transport)
    accept_entered = threading.Event()
    release_accept = threading.Event()
    finished = threading.Event()
    outcome = []
    real_accept = dispatcher._accept_started_operation

    def gated_accept(started, spec, *, orphaned=False):
        accept_entered.set()
        assert release_accept.wait(TIMEOUT)
        return real_accept(started, spec, orphaned=orphaned)

    dispatcher._accept_started_operation = gated_accept

    def run_operation():
        try:
            outcome.append(dispatcher.run("wire-start-before-eof"))
        except BaseException as error:  # noqa: BLE001 - relay exact result
            outcome.append(error)
        finally:
            finished.set()

    runner = threading.Thread(target=run_operation)
    runner.start()
    try:
        assert _wait_until(lambda: transport.pending_count == 1)
        with transport._state_lock:
            start_future = next(iter(transport._pending.values()))
        _inject_response(
            transport,
            start_future,
            body={"operationId": 42, "operationName": "wire-start-before-eof"},
        )
        assert accept_entered.wait(TIMEOUT)
        assert transport._queue_inbound(
            _Inbound("eof", "EOF before operation outcome"),
            timeout=TIMEOUT,
        )
        assert transport.wait_closed(TIMEOUT)
        assert _wait_until(lambda: dispatcher._terminal_error is not None)

        release_accept.set()
        assert finished.wait(TIMEOUT)
        runner.join(TIMEOUT)
        assert len(outcome) == 1
        assert isinstance(outcome[0], DapError)
        assert "EOF before operation outcome" in str(outcome[0])
        assert dispatcher.active_operations == 0
        with dispatcher._condition:
            assert dispatcher._starting_operations == 0
            assert not dispatcher._early_callbacks
            assert not dispatcher._early_outcomes
            assert dispatcher._subscriptions_active is False
        with transport._state_lock:
            assert not any(
                event.startswith("pwncOperation")
                for event in transport._handlers
            )
    finally:
        release_accept.set()
        dispatcher.close()
        transport.close()
        runner.join(TIMEOUT)
