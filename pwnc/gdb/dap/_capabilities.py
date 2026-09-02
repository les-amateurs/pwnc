"""Strict JSON-wire values and scoped callable capabilities.

The module deliberately has no package-local imports.  It can therefore be
imported normally by the host and loaded directly by path inside GDB's embedded
Python interpreter.

Callable objects never cross the wire as code or serialized Python objects.
They are represented by opaque, root-scoped references.  A codec resolves its
own references back to the original callable and asks ``proxy_factory`` to
materialize references owned by its peer.
"""

# ruff: noqa: I001, RUF022, RUF023, UP031 -- embedded-GDB compatibility

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import secrets
import threading


WIRE_TAG = "__pwnc_capability_v1__"

DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_NODES = 100_000
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_CAPABILITIES = 4_096
DEFAULT_MAX_TOKEN_CHARS = 256

_TOKEN = re.compile(r"\A[A-Za-z0-9._~-]+\Z")
_MISSING = object()


class CapabilityError(ValueError):
    """Base class for malformed, foreign, or unavailable capabilities."""


class CapabilityLimitError(CapabilityError):
    """A value or capability registry exceeded a configured safety limit."""


class InvalidCapabilityError(CapabilityError):
    """A capability descriptor is malformed or fails validation."""


class ForeignCapabilityError(InvalidCapabilityError):
    """A capability belongs to neither this codec nor its configured peer."""


class StaleCapabilityError(InvalidCapabilityError):
    """A capability or its containing scope is no longer live."""


class CodecLimits:
    """Safety limits applied independently by every codec scope."""

    __slots__ = (
        "_sealed",
        "max_depth",
        "max_nodes",
        "max_bytes",
        "max_capabilities",
        "max_token_chars",
    )

    def __init__(
        self,
        *,
        max_depth=DEFAULT_MAX_DEPTH,
        max_nodes=DEFAULT_MAX_NODES,
        max_bytes=DEFAULT_MAX_BYTES,
        max_capabilities=DEFAULT_MAX_CAPABILITIES,
        max_token_chars=DEFAULT_MAX_TOKEN_CHARS,
    ):
        object.__setattr__(self, "_sealed", False)
        self.max_depth = _require_limit(max_depth, "max_depth", allow_zero=True)
        self.max_nodes = _require_limit(max_nodes, "max_nodes")
        self.max_bytes = _require_limit(max_bytes, "max_bytes")
        self.max_capabilities = _require_limit(max_capabilities, "max_capabilities")
        self.max_token_chars = _require_limit(max_token_chars, "max_token_chars")
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError("CodecLimits instances are immutable")
        object.__setattr__(self, name, value)

    def __repr__(self):
        return "CodecLimits(max_depth=%r, max_nodes=%r, max_bytes=%r, max_capabilities=%r, max_token_chars=%r)" % (
            self.max_depth,
            self.max_nodes,
            self.max_bytes,
            self.max_capabilities,
            self.max_token_chars,
        )


class CapabilityRef:
    """An opaque callable reference: owner, operation root, and random id."""

    __slots__ = ("_capability_id", "_owner", "_root")

    def __init__(self, owner, root, capability_id):
        # Codec-specific length checks happen when a reference enters a codec.
        self._owner = _require_token(owner, "capability owner", 4096)
        self._root = _require_token(root, "capability root", 4096)
        self._capability_id = _require_token(capability_id, "capability id", 4096)

    @property
    def owner(self):
        return self._owner

    @property
    def root(self):
        return self._root

    @property
    def capability_id(self):
        return self._capability_id

    @property
    def id(self):
        """The opaque id, named as it appears in the wire descriptor."""

        return self.capability_id

    def __eq__(self, other):
        if not isinstance(other, CapabilityRef):
            return NotImplemented
        return self.owner == other.owner and self.root == other.root and self.capability_id == other.capability_id

    def __hash__(self):
        return hash((self.owner, self.root, self.capability_id))

    def __repr__(self):
        return "CapabilityRef(owner=%r, root=%r, capability_id=%r)" % (
            self.owner,
            self.root,
            self.capability_id,
        )


class _Budget:
    __slots__ = ("field", "limits", "nodes")

    def __init__(self, field, limits):
        self.field = field
        self.limits = limits
        self.nodes = 0

    def visit(self, depth, path):
        if depth > self.limits.max_depth:
            raise CapabilityLimitError(
                "%s exceeds the nesting limit %d at %s" % (self.field, self.limits.max_depth, path)
            )
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            raise CapabilityLimitError("%s exceeds the node limit %d" % (self.field, self.limits.max_nodes))


def _require_limit(value, name, allow_zero=False):
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError("%s must be a %s integer" % (name, qualifier))
    return value


def _require_token(value, field, max_chars):
    if type(value) is not str or not value or len(value) > max_chars or _TOKEN.fullmatch(value) is None:
        raise InvalidCapabilityError("%s must be 1..%d URL-safe opaque characters" % (field, max_chars))
    return value


def new_token(nbytes=24):
    """Return a cryptographically opaque URL-safe owner, root, or id token."""

    if type(nbytes) is not int or nbytes < 16:
        raise ValueError("nbytes must be an integer of at least 16")
    return secrets.token_urlsafe(nbytes)


class CapabilityCodec:
    """Encode one live root scope's values and callable capabilities.

    ``owner`` and ``root`` identify locally-created capabilities.  ``peer_owner``
    is bound either at construction or exactly once with :meth:`bind_peer`.
    Decoding a peer capability calls ``proxy_factory(ref)`` once and caches the
    returned callable by descriptor identity.  Re-encoding that proxy emits the
    original peer descriptor.

    ``peer_validator`` and ``local_validator`` may reject forged or revoked
    references by returning exactly ``False`` or by raising.  They are invoked
    on every resolution, including cached values.
    """

    def __init__(
        self,
        owner,
        root,
        *,
        peer_owner=None,
        proxy_factory=None,
        peer_validator=None,
        local_validator=None,
        limits=None,
        token_factory=new_token,
    ):
        if limits is None:
            limits = CodecLimits()
        if not isinstance(limits, CodecLimits):
            raise TypeError("limits must be a CodecLimits instance")
        self._limits = limits
        self._owner = _require_token(owner, "owner", limits.max_token_chars)
        self._root = _require_token(root, "root", limits.max_token_chars)
        self._peer_owner = None
        self._proxy_factory = None
        self._peer_validator = None
        self._local_validator = local_validator
        if local_validator is not None and not callable(local_validator):
            raise TypeError("local_validator must be callable or None")
        if not callable(token_factory):
            raise TypeError("token_factory must be callable")
        self._token_factory = token_factory

        self._lock = threading.RLock()
        self._closed = False
        self._locals_by_identity = {}
        self._local_values = {}
        self._retired_local_ids = set()
        self._peer_proxies = {}
        self._peer_by_identity = {}
        self._retired_peer_refs = set()

        if peer_owner is not None or proxy_factory is not None or peer_validator is not None:
            if peer_owner is None or proxy_factory is None:
                raise TypeError("peer_owner and proxy_factory must be supplied together")
            self.bind_peer(peer_owner, proxy_factory, validator=peer_validator)

    @property
    def owner(self):
        return self._owner

    @property
    def root(self):
        return self._root

    @property
    def peer_owner(self):
        with self._lock:
            return self._peer_owner

    @property
    def limits(self):
        return self._limits

    @property
    def closed(self):
        with self._lock:
            return self._closed

    @property
    def local_capability_count(self):
        with self._lock:
            return len(self._local_values)

    @property
    def peer_capability_count(self):
        with self._lock:
            return len(self._peer_proxies)

    def bind_peer(self, owner, proxy_factory, *, validator=None):
        """Bind the one permitted peer owner and its proxy factory.

        Repeating the exact binding is harmless; changing it is rejected.
        """

        owner = _require_token(owner, "peer owner", self._limits.max_token_chars)
        if owner == self._owner:
            raise ValueError("peer owner must differ from local owner")
        if not callable(proxy_factory):
            raise TypeError("proxy_factory must be callable")
        if validator is not None and not callable(validator):
            raise TypeError("validator must be callable or None")
        with self._lock:
            self._require_live_locked()
            if self._peer_owner is None:
                self._peer_owner = owner
                self._proxy_factory = proxy_factory
                self._peer_validator = validator
                return self
            if (
                self._peer_owner != owner
                or self._proxy_factory is not proxy_factory
                or self._peer_validator is not validator
            ):
                raise RuntimeError("peer binding is immutable")
        return self

    def register_local(self, value):
        """Register a local callable and return its stable scoped reference."""

        if not callable(value):
            raise TypeError("local capability must be callable")
        identity = id(value)
        with self._lock:
            self._require_live_locked()
            peer_entry = self._peer_by_identity.get(identity)
            if peer_entry is not None and peer_entry[0] is value:
                raise ForeignCapabilityError("a peer proxy cannot be registered as a local capability")
            existing = self._locals_by_identity.get(identity)
            if existing is not None and existing[0] is value:
                return existing[1]
            self._require_capacity_locked()
            capability_id = self._fresh_id_locked()
            ref = CapabilityRef(self._owner, self._root, capability_id)
            self._locals_by_identity[identity] = (value, ref)
            self._local_values[capability_id] = (value, ref)
            return ref

    def ref_for(self, value):
        """Return the live local or peer reference for an object, or ``None``."""

        identity = id(value)
        with self._lock:
            self._require_live_locked()
            peer_entry = self._peer_by_identity.get(identity)
            if peer_entry is not None and peer_entry[0] is value:
                self._validate_peer_locked(peer_entry[1])
                return peer_entry[1]
            local_entry = self._locals_by_identity.get(identity)
            if local_entry is not None and local_entry[0] is value:
                self._validate_local_locked(local_entry[1], value)
                return local_entry[1]
            return None

    def resolve_local(self, ref):
        """Resolve a self-owned reference or reject it as foreign/forged/stale."""

        ref = self._coerce_ref(ref)
        with self._lock:
            self._require_live_locked()
            return self._resolve_local_locked(ref)

    def encode_ref(self, ref):
        """Encode a known local or peer reference as its wire envelope."""

        ref = self._coerce_ref(ref)
        with self._lock:
            self._require_live_locked()
            if ref.owner == self._owner:
                self._resolve_local_locked(ref)
            elif ref.owner == self._peer_owner:
                self._validate_peer_locked(ref)
                if ref not in self._peer_proxies:
                    raise InvalidCapabilityError("peer capability has not been decoded by this scope")
            else:
                raise ForeignCapabilityError("capability owner is not local or the configured peer")
        return self._callable_envelope(ref)

    def encode(self, value, *, field="value"):
        """Return a bounded JSON-native wire representation of ``value``."""

        if type(field) is not str or not field:
            raise TypeError("field must be nonempty text")
        budget = _Budget(field, self._limits)
        ancestors = set()
        with self._lock:
            self._require_live_locked()
            encoded = self._encode_value(value, budget, ancestors, 0, field)
        self._check_wire_size(encoded, field)
        return encoded

    def decode(self, wire, *, field="value"):
        """Decode a bounded wire value, resolving callable capabilities."""

        if type(field) is not str or not field:
            raise TypeError("field must be nonempty text")
        self._check_wire_size(wire, field)
        budget = _Budget(field, self._limits)
        ancestors = set()
        with self._lock:
            self._require_live_locked()
            return self._decode_value(wire, budget, ancestors, 0, field)

    def release_local(self, value_or_ref):
        """Revoke a local capability.  Return whether it was live."""

        with self._lock:
            self._require_live_locked()
            if isinstance(value_or_ref, CapabilityRef):
                ref = self._validate_ref_tokens(value_or_ref)
                if ref.owner != self._owner or ref.root != self._root:
                    raise ForeignCapabilityError("cannot release a foreign capability")
                capability_id = ref.capability_id
            else:
                entry = self._locals_by_identity.get(id(value_or_ref))
                if entry is None or entry[0] is not value_or_ref:
                    return False
                capability_id = entry[1].capability_id
            entry = self._local_values.pop(capability_id, None)
            if entry is None:
                return False
            value, ref = entry
            identity_entry = self._locals_by_identity.get(id(value))
            if identity_entry is not None and identity_entry[0] is value:
                self._locals_by_identity.pop(id(value), None)
            self._retired_local_ids.add(ref.capability_id)
            return True

    def invalidate_peer(self, value_or_ref):
        """Mark a known peer capability stale.  Return whether it was cached."""

        with self._lock:
            self._require_live_locked()
            if isinstance(value_or_ref, CapabilityRef):
                ref = self._validate_ref_tokens(value_or_ref)
            else:
                entry = self._peer_by_identity.get(id(value_or_ref))
                if entry is None or entry[0] is not value_or_ref:
                    return False
                ref = entry[1]
            if ref.owner != self._peer_owner or ref.root != self._root:
                raise ForeignCapabilityError("cannot invalidate a foreign capability")
            if ref in self._retired_peer_refs:
                return False
            if ref not in self._peer_proxies:
                raise InvalidCapabilityError("cannot invalidate an unknown peer capability")
            self._peer_proxies.pop(ref)
            # Keep the identity entry as a bounded tombstone.  Otherwise a
            # caller retaining the old proxy could have it silently registered
            # as a new local callable on its next encode.
            self._retired_peer_refs.add(ref)
            return True

    def close(self):
        """Invalidate the complete root scope and release retained callables."""

        with self._lock:
            if self._closed:
                return False
            self._closed = True
            self._retired_local_ids.update(self._local_values)
            self._retired_peer_refs.update(self._peer_proxies)
            self._locals_by_identity.clear()
            self._local_values.clear()
            self._peer_proxies.clear()
            self._peer_by_identity.clear()
            return True

    def _require_live_locked(self):
        if self._closed:
            raise StaleCapabilityError("capability scope is closed")

    def _require_capacity_locked(self):
        active = len(self._local_values) + len(self._peer_proxies)
        if active >= self._limits.max_capabilities:
            raise CapabilityLimitError("capability count exceeds limit %d" % self._limits.max_capabilities)

    def _fresh_id_locked(self):
        for _attempt in range(32):
            capability_id = self._token_factory()
            capability_id = _require_token(
                capability_id,
                "generated capability id",
                self._limits.max_token_chars,
            )
            if capability_id not in self._local_values and capability_id not in self._retired_local_ids:
                return capability_id
        raise RuntimeError("token_factory repeatedly returned duplicate capability ids")

    def _validate_ref_tokens(self, ref):
        if not isinstance(ref, CapabilityRef):
            raise TypeError("expected a CapabilityRef")
        _require_token(ref.owner, "capability owner", self._limits.max_token_chars)
        _require_token(ref.root, "capability root", self._limits.max_token_chars)
        _require_token(ref.capability_id, "capability id", self._limits.max_token_chars)
        return ref

    def _coerce_ref(self, ref):
        return self._validate_ref_tokens(ref)

    def _resolve_local_locked(self, ref):
        self._validate_ref_tokens(ref)
        if ref.owner != self._owner:
            raise ForeignCapabilityError("capability is not owned by this codec")
        if ref.root != self._root:
            raise ForeignCapabilityError("capability belongs to a different root")
        entry = self._local_values.get(ref.capability_id)
        if entry is None:
            if ref.capability_id in self._retired_local_ids:
                raise StaleCapabilityError("local capability has been released")
            raise InvalidCapabilityError("unknown local capability id")
        value, canonical_ref = entry
        if canonical_ref != ref:
            raise InvalidCapabilityError("local capability descriptor does not match its registration")
        self._validate_local_locked(ref, value)
        return value

    def _validate_local_locked(self, ref, value):
        if self._local_validator is not None:
            accepted = self._local_validator(ref, value)
            if accepted is False:
                raise StaleCapabilityError("local capability was rejected by its validator")

    def _validate_peer_locked(self, ref):
        self._validate_ref_tokens(ref)
        if self._peer_owner is None:
            raise ForeignCapabilityError("no peer owner is bound")
        if ref.owner != self._peer_owner:
            raise ForeignCapabilityError("capability owner does not match the configured peer")
        if ref.root != self._root:
            raise ForeignCapabilityError("peer capability belongs to a different root")
        if ref in self._retired_peer_refs:
            raise StaleCapabilityError("peer capability has been invalidated")
        if self._peer_validator is not None:
            accepted = self._peer_validator(ref)
            if accepted is False:
                raise InvalidCapabilityError("peer capability was rejected by its validator")

    @staticmethod
    def _callable_envelope(ref):
        return {
            WIRE_TAG: {
                "kind": "callable",
                "owner": ref.owner,
                "root": ref.root,
                "id": ref.capability_id,
            }
        }

    def _encode_value(self, value, budget, ancestors, depth, path):
        budget.visit(depth, path)
        if value is None or type(value) in (bool, int, str):
            return value
        if type(value) is float:
            if not math.isfinite(value):
                raise TypeError("%s contains a non-finite float at %s" % (budget.field, path))
            return value

        identity = id(value)
        peer_entry = self._peer_by_identity.get(identity)
        if peer_entry is not None and peer_entry[0] is value:
            self._validate_peer_locked(peer_entry[1])
            return self._callable_envelope(peer_entry[1])
        if callable(value):
            return self._callable_envelope(self.register_local(value))

        if isinstance(value, (bytes, bytearray, memoryview)):
            try:
                raw = bytes(value)
            except (TypeError, ValueError) as error:
                raise TypeError("%s contains an invalid bytes-like value at %s" % (budget.field, path)) from error
            return {
                WIRE_TAG: {
                    "kind": "bytes",
                    "data": base64.b64encode(raw).decode("ascii"),
                }
            }

        if type(value) in (list, tuple, dict):
            if identity in ancestors:
                raise TypeError("%s contains a cycle at %s" % (budget.field, path))
            ancestors.add(identity)
            try:
                if type(value) is list:
                    return [
                        self._encode_value(child, budget, ancestors, depth + 1, "%s[%d]" % (path, index))
                        for index, child in enumerate(value)
                    ]
                if type(value) is tuple:
                    items = [
                        self._encode_value(child, budget, ancestors, depth + 1, "%s[%d]" % (path, index))
                        for index, child in enumerate(value)
                    ]
                    return {WIRE_TAG: {"kind": "tuple", "items": items}}

                items = []
                result = {}
                escaped = WIRE_TAG in value
                for key, child in value.items():
                    budget.visit(depth + 1, "%s.<key>" % path)
                    if type(key) is not str:
                        raise TypeError("%s contains a non-text key at %s" % (budget.field, path))
                    encoded = self._encode_value(child, budget, ancestors, depth + 1, "%s.%s" % (path, key))
                    if escaped:
                        items.append([key, encoded])
                    else:
                        result[key] = encoded
                if escaped:
                    return {WIRE_TAG: {"kind": "dict", "items": items}}
                return result
            finally:
                ancestors.remove(identity)

        raise TypeError("%s contains unsupported value %s at %s" % (budget.field, type(value).__name__, path))

    def _decode_value(self, value, budget, ancestors, depth, path):
        budget.visit(depth, path)
        if value is None or type(value) in (bool, int, str):
            return value
        if type(value) is float:
            if not math.isfinite(value):
                raise TypeError("%s contains a non-finite float at %s" % (budget.field, path))
            return value
        if type(value) is not list and type(value) is not dict:
            raise TypeError("%s contains non-JSON wire value %s at %s" % (budget.field, type(value).__name__, path))

        identity = id(value)
        if identity in ancestors:
            raise TypeError("%s contains a cycle at %s" % (budget.field, path))
        ancestors.add(identity)
        try:
            if type(value) is list:
                return [
                    self._decode_value(child, budget, ancestors, depth + 1, "%s[%d]" % (path, index))
                    for index, child in enumerate(value)
                ]

            if WIRE_TAG in value:
                if len(value) != 1:
                    raise InvalidCapabilityError(
                        "%s uses reserved key %r outside an envelope at %s" % (budget.field, WIRE_TAG, path)
                    )
                return self._decode_envelope(value[WIRE_TAG], budget, ancestors, depth, path)

            result = {}
            for key, child in value.items():
                budget.visit(depth + 1, "%s.<key>" % path)
                if type(key) is not str:
                    raise TypeError("%s contains a non-text key at %s" % (budget.field, path))
                result[key] = self._decode_value(child, budget, ancestors, depth + 1, "%s.%s" % (path, key))
            return result
        finally:
            ancestors.remove(identity)

    def _decode_envelope(self, body, budget, ancestors, depth, path):
        if type(body) is not dict:
            raise InvalidCapabilityError("%s has a malformed reserved envelope at %s" % (budget.field, path))
        kind = body.get("kind", _MISSING)
        if kind == "callable":
            if set(body) != {"kind", "owner", "root", "id"}:
                raise InvalidCapabilityError("%s has malformed callable descriptor keys at %s" % (budget.field, path))
            ref = CapabilityRef(body["owner"], body["root"], body["id"])
            self._validate_ref_tokens(ref)
            if ref.root != self._root:
                raise ForeignCapabilityError("capability descriptor belongs to a different root")
            if ref.owner == self._owner:
                return self._resolve_local_locked(ref)
            self._validate_peer_locked(ref)
            existing = self._peer_proxies.get(ref, _MISSING)
            if existing is not _MISSING:
                return existing
            self._require_capacity_locked()
            proxy = self._proxy_factory(ref)
            if not callable(proxy):
                raise TypeError("proxy_factory must return a callable")
            # A factory may recursively decode the same reference.  Honor the
            # first cached object and never change identity afterward.
            existing = self._peer_proxies.get(ref, _MISSING)
            if existing is not _MISSING:
                return existing
            proxy_identity = id(proxy)
            collision = self._peer_by_identity.get(proxy_identity)
            if collision is not None and collision[0] is proxy and collision[1] != ref:
                raise InvalidCapabilityError("proxy_factory reused one object for distinct capabilities")
            local_collision = self._locals_by_identity.get(proxy_identity)
            if local_collision is not None and local_collision[0] is proxy:
                raise InvalidCapabilityError("proxy_factory returned a registered local callable")
            self._peer_proxies[ref] = proxy
            self._peer_by_identity[proxy_identity] = (proxy, ref)
            return proxy

        if kind == "bytes":
            if set(body) != {"kind", "data"} or type(body.get("data")) is not str:
                raise InvalidCapabilityError("%s has a malformed bytes envelope at %s" % (budget.field, path))
            try:
                raw = base64.b64decode(body["data"].encode("ascii"), validate=True)
            except (UnicodeEncodeError, binascii.Error, ValueError) as error:
                raise InvalidCapabilityError("%s has invalid base64 bytes at %s" % (budget.field, path)) from error
            if base64.b64encode(raw).decode("ascii") != body["data"]:
                raise InvalidCapabilityError("%s has non-canonical base64 bytes at %s" % (budget.field, path))
            return raw

        if kind == "tuple":
            if set(body) != {"kind", "items"} or type(body.get("items")) is not list:
                raise InvalidCapabilityError("%s has a malformed tuple envelope at %s" % (budget.field, path))
            return tuple(
                self._decode_value(child, budget, ancestors, depth + 1, "%s[%d]" % (path, index))
                for index, child in enumerate(body["items"])
            )

        if kind == "dict":
            if set(body) != {"kind", "items"} or type(body.get("items")) is not list:
                raise InvalidCapabilityError("%s has a malformed dict envelope at %s" % (budget.field, path))
            result = {}
            for index, pair in enumerate(body["items"]):
                budget.visit(depth + 1, "%s.<key>" % path)
                if type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str:
                    raise InvalidCapabilityError(
                        "%s has a malformed escaped dict item at %s[%d]" % (budget.field, path, index)
                    )
                key = pair[0]
                if key in result:
                    raise InvalidCapabilityError(
                        "%s has duplicate escaped dict key %r at %s" % (budget.field, key, path)
                    )
                result[key] = self._decode_value(pair[1], budget, ancestors, depth + 1, "%s.%s" % (path, key))
            if WIRE_TAG not in result:
                raise InvalidCapabilityError(
                    "%s uses an unnecessary escaped dict envelope at %s" % (budget.field, path)
                )
            return result

        raise InvalidCapabilityError("%s has unknown reserved envelope kind %r at %s" % (budget.field, kind, path))

    def _check_wire_size(self, wire, field):
        try:
            encoded = json.dumps(
                wire,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            raise TypeError("%s is not a valid JSON wire value: %s" % (field, error)) from error
        if len(encoded) > self._limits.max_bytes:
            raise CapabilityLimitError(
                "%s encodes to %d bytes; limit is %d" % (field, len(encoded), self._limits.max_bytes)
            )


__all__ = [
    "WIRE_TAG",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_NODES",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_CAPABILITIES",
    "DEFAULT_MAX_TOKEN_CHARS",
    "CapabilityError",
    "CapabilityLimitError",
    "InvalidCapabilityError",
    "ForeignCapabilityError",
    "StaleCapabilityError",
    "CodecLimits",
    "CapabilityRef",
    "CapabilityCodec",
    "new_token",
]
