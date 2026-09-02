"""Injected operations for the production synchronous-callback live tests.

This file is sourced into GDB after pwnc's callback extension.  It uses only
the runtime registration hooks installed on the ``gdb`` module; no test code
or plugin source is transformed.
"""

import threading

import gdb

_pwnc_callback_test_trace = []


def _pwnc_callback_test_record(kind, **fields):
    item = {
        "index": len(_pwnc_callback_test_trace),
        "kind": kind,
        "threadId": threading.get_ident(),
    }
    item.update(fields)
    _pwnc_callback_test_trace.append(item)
    return item


_PWNC_CALLBACK_TEST_SOURCE = r"""
async def _pwnc_test_recursive(depth=0, max_depth=0):
    _pwnc_callback_test_record("operation-enter", depth=depth)
    before = gdb.execute("show pagination", from_tty=False, to_string=True)
    value = await effect("pwnc.test.callback", depth, max_depth=max_depth)
    after = gdb.execute("show confirm", from_tty=False, to_string=True)
    _pwnc_callback_test_record("operation-return", depth=depth)
    return {
        "depth": depth,
        "value": value,
        "before": before.strip(),
        "after": after.strip(),
    }


async def _pwnc_test_snapshot():
    return list(_pwnc_callback_test_trace)


async def _pwnc_test_cleanup(token="cleanup"):
    try:
        await effect("pwnc.test.hold", token)
    finally:
        first = await effect("pwnc.test.cleanup", token, cleanup_index=1)
        second = await effect("pwnc.test.cleanup", token, cleanup_index=2)
        _pwnc_callback_test_record(
            "cleanup-finished",
            token=token,
            first=first,
            second=second,
        )


async def _pwnc_test_capabilities(host_callback, depth=0, max_depth=0):
    _pwnc_callback_test_record("capability-operation-enter", depth=depth)

    def sync_callback(value, increment=0):
        _pwnc_callback_test_record("capability-sync", value=value)
        return value + increment

    async def recursive_callback(next_depth):
        _pwnc_callback_test_record("capability-recursive-enter", depth=next_depth)
        return await invoke(
            host_callback,
            next_depth,
            sync_callback,
            recursive_callback,
            max_depth=max_depth,
            binary=(b"pwnc", b"callback"),
        )

    result = await invoke(
        host_callback,
        depth,
        sync_callback,
        recursive_callback,
        max_depth=max_depth,
        binary=(b"pwnc", b"callback"),
    )
    _pwnc_callback_test_record("capability-operation-return", depth=depth)
    return result


async def _pwnc_test_capability_errors(host_callback, mode):
    def gdb_failure(message):
        raise ValueError("GDB callback failure: " + message)

    try:
        return await invoke(host_callback, gdb_failure, mode=mode)
    except RuntimeError as error:
        return {
            "caught": type(error).__name__,
            "message": str(error),
        }


async def _pwnc_test_capability_cleanup(host_callback, token="cleanup"):
    try:
        await invoke(host_callback, "hold", token=token)
    finally:
        first = await invoke(
            host_callback,
            "cleanup",
            token=token,
            cleanup_index=1,
        )
        second = await invoke(
            host_callback,
            "cleanup",
            token=token,
            cleanup_index=2,
        )
        _pwnc_callback_test_record(
            "capability-cleanup-finished",
            token=token,
            first=first,
            second=second,
        )
"""


_pwnc_callback_test_namespace = {
    "effect": gdb.pwnc_effect,
    "gdb": gdb,
    "_pwnc_callback_test_record": _pwnc_callback_test_record,
    "_pwnc_callback_test_trace": _pwnc_callback_test_trace,
}
gdb.pwnc_exec_lowered(
    _PWNC_CALLBACK_TEST_SOURCE,
    namespace=_pwnc_callback_test_namespace,
    filename="<pwnc-production-callback-test>",
)
gdb.pwnc_register_operation(
    "pwnc.test.recursive",
    _pwnc_callback_test_namespace["_pwnc_test_recursive"],
    replace=True,
)
gdb.pwnc_register_operation(
    "pwnc.test.snapshot",
    _pwnc_callback_test_namespace["_pwnc_test_snapshot"],
    replace=True,
)
gdb.pwnc_register_operation(
    "pwnc.test.cleanup",
    _pwnc_callback_test_namespace["_pwnc_test_cleanup"],
    replace=True,
)
gdb.pwnc_register_operation(
    "pwnc.test.capabilities",
    _pwnc_callback_test_namespace["_pwnc_test_capabilities"],
    replace=True,
)
gdb.pwnc_register_operation(
    "pwnc.test.capability-errors",
    _pwnc_callback_test_namespace["_pwnc_test_capability_errors"],
    replace=True,
)
gdb.pwnc_register_operation(
    "pwnc.test.capability-cleanup",
    _pwnc_callback_test_namespace["_pwnc_test_capability_cleanup"],
    replace=True,
)
