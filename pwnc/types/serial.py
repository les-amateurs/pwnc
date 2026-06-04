"""Serializable descriptors for :mod:`pwnc.types`.

A *descriptor* is a JSON-safe document describing a :class:`pwnc.types.Type`,
used to ship a type across a process boundary (notably the gdb DAP bridge in
``pwnc.gdb.dap``) without pickle. The producer that walks a debugger's native
types (e.g. ``gdb.Type``) emits this same schema, and :func:`from_descriptor`
reconstructs a real ``pwnc.types`` ``Type`` from it.

Schema
------
A document is::

    {"root": <ref>, "types": {<id>: <node>, ...}}

``types`` is an *intern table* holding aggregate nodes (struct/union/enum) keyed
by an integer id. A ``<ref>`` is either an inline primitive node or an interned
reference ``{"kind": "ref", "id": <id>}``. Using explicit refs (instead of
relying on object identity, as the old pickle-based bridge did) lets
self-referential and mutually recursive types serialize as plain JSON.

Nodes::

    {"kind": "int",    "bits": N, "signed": bool}
    {"kind": "bits",   "bits": N}                       # bitfield storage unit
    {"kind": "float"}                                   # 32-bit IEEE-754
    {"kind": "double"}                                  # 64-bit IEEE-754
    {"kind": "ptr",    "bits": N, "child": <ref>}       # child {"kind":"void"} => void*
    {"kind": "array",  "count": N, "child": <ref>}
    {"kind": "void"}
    {"kind": "struct", "id": K, "name": str, "size": N,
        "fields": [{"name": str, "type": <ref>, "byte": B, "bit": b?}, ...],
        "padding": [[off, size], ...]?}
    {"kind": "union",  "id": K, "name": str, "size": N,
        "fields": [{"name": str, "type": <ref>}, ...]}
    {"kind": "enum",   "id": K, "name": str|None, "child": <ref>,
        "members": {str: int, ...}}

A struct field's ``"bit"`` is the bit position *within its byte* (0-7) and is
present only for bitfields (field type ``{"kind": "bits"}``); it maps directly
to the bit offset the ``Value`` layer uses to mask/shift. Ordinary (byte-aligned)
fields omit ``"bit"``. This bit-within-byte convention matches
:meth:`Struct.from_layout` and the DWARF builder, *not* the absolute bit offset
that ``Struct.__init__`` happens to store.
"""

from .primitives import Int, Bits, Float, Double, Ptr
from .containers import Struct, Union, Array, Enum

__all__ = ["to_descriptor", "from_descriptor"]


def to_descriptor(t):
    """Serialize a :class:`pwnc.types.Type` to a JSON-safe descriptor document.

    Aggregates (struct/union/enum) are interned by object identity so that
    self-referential and shared types are emitted once and referenced by id.
    """
    types = {}
    ids = {}          # id(obj) -> interned int id
    counter = [0]

    def intern(obj):
        i = counter[0]
        counter[0] += 1
        ids[id(obj)] = i
        return i

    def node(ty):
        if ty is None:
            return {"kind": "void"}
        # Bits is a subclass of Int, so it must be checked first.
        if isinstance(ty, Bits):
            return {"kind": "bits", "bits": ty.nbits}
        if isinstance(ty, Int):
            return {"kind": "int", "bits": ty.nbits, "signed": bool(ty.signed)}
        if isinstance(ty, Double):
            return {"kind": "double"}
        if isinstance(ty, Float):
            return {"kind": "float"}
        if isinstance(ty, Ptr):
            return {"kind": "ptr", "bits": ty.nbits, "child": node(ty.child)}
        if isinstance(ty, Array):
            return {"kind": "array", "count": ty.count, "child": node(ty.child)}
        if isinstance(ty, Struct):
            if id(ty) in ids:
                return {"kind": "ref", "id": ids[id(ty)]}
            tid = intern(ty)
            entry = {"kind": "struct", "id": tid, "name": ty.name,
                     "size": ty.nbytes, "fields": []}
            types[tid] = entry          # register before recursing (cycles)
            for fname, ftype, byte_off, bit_off in ty._layout:
                fnode = {"name": fname, "type": node(ftype), "byte": byte_off}
                if isinstance(ftype, Bits):
                    fnode["bit"] = bit_off if bit_off is not None else 0
                entry["fields"].append(fnode)
            if ty._padding:
                entry["padding"] = [[off, size] for off, size in ty._padding]
            return {"kind": "ref", "id": tid}
        if isinstance(ty, Union):
            if id(ty) in ids:
                return {"kind": "ref", "id": ids[id(ty)]}
            tid = intern(ty)
            entry = {"kind": "union", "id": tid, "name": ty.name,
                     "size": ty.nbytes, "fields": []}
            types[tid] = entry
            for fname, ftype, _byte, _bit in ty._layout:
                entry["fields"].append({"name": fname, "type": node(ftype)})
            return {"kind": "ref", "id": tid}
        if isinstance(ty, Enum):
            if id(ty) in ids:
                return {"kind": "ref", "id": ids[id(ty)]}
            tid = intern(ty)
            types[tid] = {"kind": "enum", "id": tid, "name": ty.name,
                          "child": node(ty.child), "members": dict(ty.members)}
            return {"kind": "ref", "id": tid}
        raise TypeError(f"cannot serialize type {type(ty).__name__}")

    return {"root": node(t), "types": types}


def from_descriptor(doc):
    """Reconstruct a :class:`pwnc.types.Type` from a descriptor document.

    Cycles are handled the same way the DWARF builder handles them: a pointer to
    an aggregate that is still being built becomes a ``Ptr(None)`` placeholder
    recorded for backpatching once the target exists. Every cycle in C passes
    through a pointer, so this always terminates.
    """
    raw_types = doc.get("types") or {}
    # JSON object keys are strings after a round trip; normalize to int.
    types = {int(k): v for k, v in raw_types.items()}
    built = {}        # int id -> Type
    deferred = []     # (Ptr, target_id) backpatch list

    def build_ref(ref):
        if ref is None:
            return None
        if ref.get("kind") == "ref":
            return build_id(ref["id"])
        return build_node(ref)

    def build_id(tid):
        tid = int(tid)
        if tid in built:
            return built[tid]
        return build_node(types[tid])

    def build_node(n):
        if n is None:
            return None
        kind = n["kind"]
        if kind == "void":
            return None
        if kind == "ref":
            return build_id(n["id"])
        if kind == "bits":
            return Bits(n["bits"])
        if kind == "int":
            return Int(n["bits"], signed=n.get("signed", False))
        if kind == "float":
            return Float()
        if kind == "double":
            return Double()
        if kind == "ptr":
            child = n.get("child")
            if child is not None and child.get("kind") == "ref" \
                    and int(child["id"]) not in built:
                # Break (possible) cycles: placeholder, backpatch after the
                # target aggregate has been built.
                p = Ptr(None, n["bits"])
                deferred.append((p, int(child["id"])))
                return p
            return Ptr(build_ref(child), n["bits"])
        if kind == "array":
            return Array(build_ref(n["child"]), n["count"])
        if kind == "enum":
            tid = int(n["id"])
            if tid in built:
                return built[tid]
            e = Enum(build_ref(n["child"]), dict(n["members"]), name=n.get("name"))
            built[tid] = e
            return e
        if kind == "union":
            tid = int(n["id"])
            if tid in built:
                return built[tid]
            fields = [(f["name"], build_ref(f["type"])) for f in n["fields"]]
            u = Union(n["name"], fields)
            built[tid] = u
            return u
        if kind == "struct":
            tid = int(n["id"])
            if tid in built:
                return built[tid]
            layout = []
            for f in n["fields"]:
                ftype = build_ref(f["type"])
                bit = f["bit"] if "bit" in f else None
                layout.append((f["name"], ftype, f["byte"], bit))
            padding = [tuple(p) for p in n.get("padding", [])]
            s = Struct.from_layout(n["name"], layout, padding, n["size"])
            built[tid] = s              # cache after build (fields can't ref by value)
            return s
        raise ValueError(f"unknown type node kind: {kind!r}")

    root = build_ref(doc["root"])
    # Resolve deferred pointer children. build_id may append more deferred
    # entries (a target struct with its own pointer fields), so iterate by index.
    i = 0
    while i < len(deferred):
        ptr, tid = deferred[i]
        i += 1
        ptr.child = build_id(tid)
    return root
