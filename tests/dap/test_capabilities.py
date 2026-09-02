"""Focused tests for the host/GDB callable capability wire codec."""

# ruff: noqa: I001 -- repository tests add the checkout to sys.path.

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pwnc.gdb.dap._capabilities import (
    WIRE_TAG,
    CapabilityCodec,
    CapabilityLimitError,
    CapabilityRef,
    CodecLimits,
    ForeignCapabilityError,
    InvalidCapabilityError,
    StaleCapabilityError,
)


ROOT = "root-test"
HOST = "host-test"
GDB = "gdb-test"


class Proxy:
    def __init__(self, ref):
        self.ref = ref

    def __call__(self, *args, **kwargs):
        return self.ref, args, kwargs


def codec(owner=HOST, **kwargs):
    return CapabilityCodec(owner, ROOT, token_factory=_tokens(), **kwargs)


def _tokens():
    lock = threading.Lock()
    next_id = 0

    def token():
        nonlocal next_id
        with lock:
            next_id += 1
            return f"cap-{next_id}"

    return token


def test_recursive_value_roundtrip_preserves_supported_types() -> None:
    value = {
        "none": None,
        "bool": True,
        "int": 2**130,
        "float": 1.25,
        "str": "snowman: \N{SNOWMAN}",
        "bytes": b"\x00\xff",
        "bytearray": bytearray(b"mutable"),
        "memoryview": memoryview(b"view"),
        "list": [1, (2, b"three")],
    }
    scope = codec()

    wire = json.loads(json.dumps(scope.encode(value)))
    decoded = scope.decode(wire)

    assert decoded == {
        "none": None,
        "bool": True,
        "int": 2**130,
        "float": 1.25,
        "str": "snowman: \N{SNOWMAN}",
        "bytes": b"\x00\xff",
        "bytearray": b"mutable",
        "memoryview": b"view",
        "list": [1, (2, b"three")],
    }
    assert type(decoded["list"][1]) is tuple


def test_reserved_tag_dicts_are_escaped_without_ambiguity() -> None:
    value = {
        WIRE_TAG: {"kind": "callable", "owner": "user-data"},
        "nested": {WIRE_TAG: "also-user-data", "other": 1},
    }
    scope = codec()

    encoded = scope.encode(value)

    assert encoded[WIRE_TAG]["kind"] == "dict"
    assert scope.decode(encoded) == value
    with pytest.raises(InvalidCapabilityError, match="outside an envelope"):
        scope.decode({WIRE_TAG: {"kind": "bytes", "data": ""}, "other": 1})


def test_local_and_peer_callable_roundtrip_and_identity() -> None:
    host = codec(peer_owner=GDB, proxy_factory=Proxy)
    gdb = codec(owner=GDB, peer_owner=HOST, proxy_factory=Proxy)

    def host_callback(value):
        return value + 1

    wire = host.encode({"callbacks": [host_callback, host_callback]})
    assert wire["callbacks"][0] == wire["callbacks"][1]
    assert host.ref_for(host_callback) == CapabilityRef(HOST, ROOT, "cap-1")
    assert host.decode(wire)["callbacks"] == [host_callback, host_callback]

    decoded = gdb.decode(wire)
    first, second = decoded["callbacks"]
    assert first is second
    assert first.ref == CapabilityRef(HOST, ROOT, "cap-1")
    assert gdb.ref_for(first) == first.ref

    returned_wire = gdb.encode(first)
    assert returned_wire == wire["callbacks"][0]
    assert host.decode(returned_wire) is host_callback


def test_gdb_owned_callable_takes_the_same_reverse_path() -> None:
    host = codec(peer_owner=GDB, proxy_factory=Proxy)
    gdb = codec(owner=GDB, peer_owner=HOST, proxy_factory=Proxy)

    def gdb_callback():
        return "gdb"

    wire = gdb.encode(gdb_callback)
    remote = host.decode(wire)

    assert isinstance(remote, Proxy)
    assert host.encode(remote) == wire
    assert gdb.decode(host.encode(remote)) is gdb_callback


def test_peer_binding_is_one_time_and_exposes_scope_metadata() -> None:
    scope = codec()
    factory = Proxy

    assert scope.owner == HOST
    assert scope.root == ROOT
    assert scope.peer_owner is None
    assert scope.bind_peer(GDB, factory) is scope
    assert scope.bind_peer(GDB, factory) is scope
    assert scope.peer_owner == GDB
    with pytest.raises(RuntimeError, match="immutable"):
        scope.bind_peer("another-peer", factory)


def test_capability_references_are_immutable_hash_keys() -> None:
    ref = CapabilityRef(HOST, ROOT, "cap-1")
    mapping = {ref: "value"}

    with pytest.raises(AttributeError):
        ref.owner = GDB
    with pytest.raises(AttributeError):
        ref.root = "another-root"
    with pytest.raises(AttributeError):
        ref.capability_id = "cap-2"
    assert mapping[CapabilityRef(HOST, ROOT, "cap-1")] == "value"


def test_forged_foreign_cross_root_and_released_local_refs_are_rejected() -> None:
    scope = codec(peer_owner=GDB, proxy_factory=Proxy)

    def callback():
        pass

    ref = scope.register_local(callback)
    assert scope.resolve_local(ref) is callback
    with pytest.raises(InvalidCapabilityError, match="unknown local"):
        scope.resolve_local(CapabilityRef(HOST, ROOT, "not-registered"))
    with pytest.raises(ForeignCapabilityError, match="different root"):
        scope.resolve_local(CapabilityRef(HOST, "root-other", ref.id))
    with pytest.raises(ForeignCapabilityError, match="not owned"):
        scope.resolve_local(CapabilityRef(GDB, ROOT, ref.id))
    with pytest.raises(InvalidCapabilityError, match="not been decoded"):
        scope.encode_ref(CapabilityRef(GDB, ROOT, "not-received"))

    assert scope.release_local(ref) is True
    assert scope.release_local(ref) is False
    with pytest.raises(StaleCapabilityError, match="released"):
        scope.resolve_local(ref)


def test_peer_validator_runs_for_cached_proxy_and_can_revoke_it() -> None:
    valid = True
    calls = []

    def validate(ref):
        calls.append(ref)
        return valid

    scope = codec(peer_owner=GDB, proxy_factory=Proxy, peer_validator=validate)
    ref = CapabilityRef(GDB, ROOT, "remote-cap")
    wire = {WIRE_TAG: {"kind": "callable", "owner": GDB, "root": ROOT, "id": "remote-cap"}}

    first = scope.decode(wire)
    assert scope.decode(wire) is first
    assert calls == [ref, ref]
    valid = False
    with pytest.raises(InvalidCapabilityError, match="validator"):
        scope.decode(wire)


def test_explicit_peer_invalidation_makes_descriptor_and_proxy_stale() -> None:
    scope = codec(peer_owner=GDB, proxy_factory=Proxy)
    wire = {WIRE_TAG: {"kind": "callable", "owner": GDB, "root": ROOT, "id": "remote-cap"}}
    proxy = scope.decode(wire)

    assert scope.invalidate_peer(proxy) is True
    with pytest.raises(StaleCapabilityError, match="invalidated"):
        scope.decode(wire)
    with pytest.raises(StaleCapabilityError, match="invalidated"):
        scope.encode(proxy)
    assert scope.invalidate_peer(proxy) is False
    with pytest.raises(InvalidCapabilityError, match="unknown peer"):
        scope.invalidate_peer(CapabilityRef(GDB, ROOT, "never-seen"))


def test_close_invalidates_all_operations_and_is_idempotent() -> None:
    scope = codec()

    def callback():
        pass

    scope.encode(callback)
    assert scope.close() is True
    assert scope.close() is False
    assert scope.closed is True
    with pytest.raises(StaleCapabilityError, match="closed"):
        scope.encode(None)
    with pytest.raises(StaleCapabilityError, match="closed"):
        scope.resolve_local(CapabilityRef(HOST, ROOT, "cap-1"))


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_nonfinite_floats_are_rejected_on_encode_and_decode(value) -> None:
    scope = codec()
    with pytest.raises(TypeError, match="non-finite"):
        scope.encode(value)
    with pytest.raises(TypeError, match="valid JSON wire value"):
        scope.decode(value)


def test_cycles_and_unsupported_values_are_rejected() -> None:
    scope = codec()
    cyclic = []
    cyclic.append(cyclic)

    with pytest.raises(TypeError, match="cycle"):
        scope.encode(cyclic)
    with pytest.raises(TypeError, match="valid JSON wire value"):
        scope.decode(cyclic)
    with pytest.raises(TypeError, match="unsupported value"):
        scope.encode({1, 2})
    with pytest.raises(TypeError, match="non-text key"):
        scope.encode({1: "bad"})
    with pytest.raises(TypeError, match="non-text key"):
        scope.decode({1: "bad"})


def test_depth_node_byte_and_capability_limits() -> None:
    depth_scope = codec(limits=CodecLimits(max_depth=1))
    assert depth_scope.decode(depth_scope.encode([1])) == [1]
    with pytest.raises(CapabilityLimitError, match="nesting"):
        depth_scope.encode([[1]])

    node_scope = codec(limits=CodecLimits(max_nodes=2))
    with pytest.raises(CapabilityLimitError, match="node"):
        node_scope.encode([1, 2])

    byte_scope = codec(limits=CodecLimits(max_bytes=8))
    with pytest.raises(CapabilityLimitError, match="bytes"):
        byte_scope.encode("a value larger than eight bytes")

    cap_scope = codec(limits=CodecLimits(max_capabilities=1))
    cap_scope.encode(lambda: 1)
    with pytest.raises(CapabilityLimitError, match="capability count"):
        cap_scope.encode(lambda: 2)

    limits = CodecLimits()
    with pytest.raises(AttributeError, match="immutable"):
        limits.max_bytes = 0


def test_malformed_envelopes_and_noncanonical_base64_are_rejected() -> None:
    scope = codec(peer_owner=GDB, proxy_factory=Proxy)
    cases = [
        {WIRE_TAG: None},
        {WIRE_TAG: {"kind": "unknown"}},
        {WIRE_TAG: {"kind": "bytes", "data": "!!!!"}},
        {WIRE_TAG: {"kind": "bytes", "data": "YQ"}},
        {WIRE_TAG: {"kind": "tuple", "items": "not-a-list"}},
        {WIRE_TAG: {"kind": "dict", "items": []}},
        {WIRE_TAG: {"kind": "callable", "owner": GDB, "root": ROOT, "id": "x", "extra": 1}},
    ]
    for wire in cases:
        with pytest.raises(InvalidCapabilityError):
            scope.decode(wire)


def test_cross_root_and_foreign_peer_wire_refs_are_rejected_before_factory() -> None:
    seen = []
    scope = codec(peer_owner=GDB, proxy_factory=lambda ref: seen.append(ref) or Proxy(ref))

    with pytest.raises(ForeignCapabilityError, match="different root"):
        scope.decode({WIRE_TAG: {"kind": "callable", "owner": GDB, "root": "another-root", "id": "cap"}})
    with pytest.raises(ForeignCapabilityError, match="configured peer"):
        scope.decode({WIRE_TAG: {"kind": "callable", "owner": "third-party", "root": ROOT, "id": "cap"}})
    assert seen == []


def test_concurrent_registration_keeps_one_stable_identity() -> None:
    scope = codec()

    def callback():
        pass

    refs = []
    lock = threading.Lock()

    def encode():
        ref = scope.encode(callback)[WIRE_TAG]
        with lock:
            refs.append(ref)

    threads = [threading.Thread(target=encode) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(refs) == 16
    assert refs == [refs[0]] * len(refs)
    assert scope.local_capability_count == 1


def test_module_can_be_loaded_directly_without_package_imports() -> None:
    path = Path(__file__).parents[2] / "pwnc" / "gdb" / "dap" / "_capabilities.py"
    spec = importlib.util.spec_from_file_location("_pwnc_capabilities_direct_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    scope = module.CapabilityCodec("direct-host", "direct-root")
    assert scope.decode(scope.encode((b"direct", 1))) == (b"direct", 1)
