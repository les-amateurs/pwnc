"""pwnc DAP server extension — runs *inside* gdb's DAP interpreter.

This module is sourced into the running ``gdb --interpreter=dap`` server (the
client does ``evaluate(context="repl", "source <this file>")`` right after the
DAP ``initialize`` handshake). It registers a handful of custom DAP requests for
the things native DAP does not expose — most importantly structural ``gdb.Type``
layout — using the same ``@request`` machinery as gdb's own handlers, so they run
on the gdb thread via ``post_event`` and inherit cancellation/threading for free.

It depends only on ``gdb`` and ``gdb.dap`` and emits plain JSON-able dicts in the
``pwnc.types.serial`` descriptor schema; the client reconstructs real
``pwnc.types`` Values from them. No ``pwnc`` import happens inside gdb.
"""

import gdb
from gdb.dap.server import request


# ── gdb.Type  →  pwnc.types.serial descriptor ──────────────────────────────
#
# Produces a self-contained document: {"root": <ref>, "types": {id: node}}.
# Named struct/union/enum are interned by tag (so cycles like `struct Node`
# and shared types are emitted once); anonymous aggregates get fresh ids
# (fixing the mi `<anon>` collision). See pwnc/types/serial.py for the schema.

_MAX_DEPTH = 256   # safety net for pathological/recursive anonymous types


class _Encoder:
    def __init__(self):
        self.types = {}        # int id -> node
        self.by_tag = {}       # tag str -> int id
        self._counter = 0

    def _new_id(self):
        i = self._counter
        self._counter += 1
        return i

    def ref(self, gdb_type, depth=0):
        """Return a <ref> (inline node or {"kind":"ref","id":K}) for gdb_type."""
        if gdb_type is None:
            return {"kind": "void"}
        if depth > _MAX_DEPTH:
            return {"kind": "void"}

        t = gdb_type.strip_typedefs()
        code = t.code

        if code == gdb.TYPE_CODE_INT:
            return {"kind": "int", "bits": t.sizeof * 8, "signed": bool(t.is_signed)}
        if code == gdb.TYPE_CODE_CHAR:
            return {"kind": "int", "bits": 8, "signed": bool(t.is_signed)}
        if code == gdb.TYPE_CODE_BOOL:
            return {"kind": "int", "bits": (t.sizeof or 1) * 8, "signed": False}
        if code == gdb.TYPE_CODE_FLT:
            return {"kind": "float"} if t.sizeof == 4 else {"kind": "double"}
        if code == gdb.TYPE_CODE_PTR:
            try:
                child = self.ref(t.target(), depth + 1)
            except gdb.error:
                child = {"kind": "void"}
            return {"kind": "ptr", "bits": t.sizeof * 8, "child": child}
        if code == gdb.TYPE_CODE_ARRAY:
            try:
                low, high = t.range()
                count = high - low + 1
            except gdb.error:
                count = 0
            return {"kind": "array", "count": count,
                    "child": self.ref(t.target(), depth + 1)}
        if code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            return self._aggregate(t, code, depth)
        if code == gdb.TYPE_CODE_ENUM:
            return self._enum(t)
        if code == gdb.TYPE_CODE_VOID:
            return {"kind": "void"}
        # Unknown/uninteresting (functions, methods, ...): opaque byte blob.
        return {"kind": "int", "bits": (t.sizeof or 1) * 8, "signed": False}

    def _aggregate(self, t, code, depth):
        tag = t.tag or t.name
        if tag is not None and tag in self.by_tag:
            return {"kind": "ref", "id": self.by_tag[tag]}

        tid = self._new_id()
        if tag is not None:
            self.by_tag[tag] = tid

        is_struct = code == gdb.TYPE_CODE_STRUCT
        node = {"kind": "struct" if is_struct else "union",
                "id": tid, "name": tag or f"<anon{tid}>",
                "size": t.sizeof or 0, "fields": []}
        self.types[tid] = node          # register before recursing (cycles)

        try:
            fields = list(t.fields())
        except (gdb.error, TypeError):
            fields = []

        for f in fields:
            # Skip static members / declarations (no storage position).
            bitpos = getattr(f, "bitpos", None)
            if bitpos is None:
                continue
            if is_struct:
                fld = {"name": f.name, "type": self.ref(f.type, depth + 1),
                       "byte": bitpos // 8}
                bitsize = getattr(f, "bitsize", 0)
                if bitsize:
                    # bitfield: store unit + bit-within-byte (Value's convention)
                    fld["type"] = {"kind": "bits", "bits": bitsize}
                    fld["bit"] = bitpos % 8
                node["fields"].append(fld)
            else:
                node["fields"].append(
                    {"name": f.name, "type": self.ref(f.type, depth + 1)})
        return {"kind": "ref", "id": tid}

    def _enum(self, t):
        tag = t.tag or t.name
        if tag is not None and tag in self.by_tag:
            return {"kind": "ref", "id": self.by_tag[tag]}
        tid = self._new_id()
        if tag is not None:
            self.by_tag[tag] = tid
        members = {}
        try:
            for f in t.fields():
                members[f.name] = f.enumval
        except (gdb.error, TypeError):
            pass
        try:
            child = self.ref(t.target())
        except gdb.error:
            child = {"kind": "int", "bits": (t.sizeof or 4) * 8, "signed": False}
        self.types[tid] = {"kind": "enum", "id": tid, "name": tag,
                           "child": child, "members": members}
        return {"kind": "ref", "id": tid}


def _encode_doc(gdb_type):
    enc = _Encoder()
    root = enc.ref(gdb_type)
    return {"root": root, "types": enc.types}


# ── symbol / type resolution ───────────────────────────────────────────────

def _lookup_symbol(name):
    sym = None
    try:
        result = gdb.lookup_symbol(name)
        sym = result[0]
    except gdb.error:
        pass
    if sym is None:
        try:
            sym = gdb.lookup_global_symbol(name)
        except gdb.error:
            pass
    if sym is None:
        try:
            sym = gdb.lookup_static_symbol(name)
        except gdb.error:
            pass
    return sym


# Executable sections — used to classify no-debug-info symbols as functions.
_CODE_SECTIONS = (".text", ".plt", ".plt.sec", ".plt.got", ".init", ".fini")


def _in_code_section(info_symbol_output):
    return any(("section %s" % s) in info_symbol_output for s in _CODE_SECTIONS)


def _word_descriptor():
    """Target-word unsigned int doc — the default 'type' for untyped data."""
    bits = gdb.lookup_type("void").pointer().sizeof * 8
    return {"root": {"kind": "int", "bits": bits, "signed": False}, "types": {}}


def _addr_of(name):
    try:
        return int(gdb.parse_and_eval("&" + name))
    except gdb.error:
        return None


@request("pwncResolveSymbol", expect_stopped=False)
def pwnc_resolve_symbol(*, name: str, **extra):
    """Resolve a symbol to (address, type-descriptor).

    Returns ``{"found": bool, "address": int|None, "kind": "data"|"function",
    "type": <descriptor-doc>|None}``. For functions and no-debug-info symbols
    the address *is* the value (the client returns a pointer); for data the
    client binds the type over memory at ``address``.
    """
    sym = _lookup_symbol(name)
    if sym is not None:
        # Functions: the address IS the value — return it, don't read code bytes
        # as data (the bug where g.sym.func returned the first opcode byte).
        is_func = bool(getattr(sym, "is_function", False))
        if not is_func and sym.type is not None:
            try:
                is_func = sym.type.strip_typedefs().code == gdb.TYPE_CODE_FUNC
            except gdb.error:
                pass
        if is_func:
            try:
                addr = int(sym.value().address)
            except Exception:
                try:
                    addr = int(gdb.parse_and_eval("&" + name))
                except gdb.error:
                    addr = None
            if addr is not None:
                return {"found": True, "address": addr, "kind": "function", "type": None}

        try:
            addr = int(sym.value().address)
        except Exception:
            addr = None
        try:
            doc = _encode_doc(sym.type)
        except Exception:
            doc = None
        if addr is not None:
            return {"found": True, "address": addr, "kind": "data", "type": doc}

    # Fallback: gdb's expression evaluator finds minsyms / PLT / shared-lib /
    # stripped symbols that lookup_*symbol misses. These frequently have NO type
    # ("<text variable>", "<data variable>", or "unknown type"). Classify
    # function vs data by gdb's own label / the symbol's section rather than
    # lumping everything together. An untyped *data* symbol's real width is
    # unknown, so default it to a target word (use value.address / g.read for
    # exact bytes); a *code* symbol returns its address (kind="function").
    try:
        val = gdb.parse_and_eval(name)
        type_str = str(val.type)
        code = val.type.strip_typedefs().code
    except gdb.error as e:
        if "unknown type" not in str(e):
            return {"found": False}
        val, type_str, code = None, "", None

    is_func = ("text variable" in type_str) or (code == gdb.TYPE_CODE_FUNC)

    if val is None and not is_func:
        # No value/type at all — decide purely by the symbol's section.
        addr = _addr_of(name)
        if addr is None:
            return {"found": False}
        try:
            info = gdb.execute("info symbol %#x" % addr, to_string=True)
        except gdb.error:
            info = ""
        if _in_code_section(info):
            return {"found": True, "address": addr, "kind": "function", "type": None}
        return {"found": True, "address": addr, "kind": "data",
                "type": _word_descriptor()}

    if is_func:
        addr = _addr_of(name)
        if addr is None:
            return {"found": False}
        return {"found": True, "address": addr, "kind": "function", "type": None}

    # No-debug *data* ("<data variable, no debug info>" / ERROR type): known
    # address, unknown width -> default to a target word.
    if code == gdb.TYPE_CODE_ERROR or "data variable" in type_str:
        addr = _addr_of(name)
        if addr is None:
            return {"found": False}
        return {"found": True, "address": addr, "kind": "data",
                "type": _word_descriptor()}

    # Regular typed value (e.g. a shared-library variable with real debug info).
    try:
        addr = int(val.address) if val.address else int(val)
    except Exception:
        return {"found": False}
    try:
        doc = _encode_doc(val.type)
    except Exception:
        doc = None
    return {"found": True, "address": addr, "kind": "data", "type": doc}


@request("pwncTypeOf", expect_stopped=False)
def pwnc_type_of(*, expression: str, **extra):
    """Return ``{"type": <doc>, "address": int|None}`` for an expression.

    Used to lay a type over arbitrary memory (e.g. ``g.cast``)."""
    val = gdb.parse_and_eval(expression)
    doc = _encode_doc(val.type)
    try:
        addr = int(val.address) if val.address else None
    except Exception:
        addr = None
    return {"type": doc, "address": addr}


# ── registers ──────────────────────────────────────────────────────────────

def _read_one_register(frame, name):
    try:
        return int(frame.read_register(name))
    except (gdb.error, ValueError):
        return int(gdb.parse_and_eval("$" + name))


@request("pwncReadRegister")
def pwnc_read_register(*, name: str, **extra):
    return {"value": _read_one_register(gdb.selected_frame(), name)}


@request("pwncReadRegisters")
def pwnc_read_registers(**extra):
    """Snapshot all integer registers as ``{name: int}`` in one round-trip."""
    frame = gdb.selected_frame()
    regs = {}
    for reg in frame.architecture().registers():
        try:
            regs[reg.name] = int(frame.read_register(reg))
        except (gdb.error, ValueError):
            pass
    return {"registers": regs}


@request("pwncWriteRegister")
def pwnc_write_register(*, name: str, value: int, **extra):
    gdb.execute("set $%s = %d" % (name, int(value)))
    return {}


# ── execution helpers ──────────────────────────────────────────────────────

@request("pwncSkip")
def pwnc_skip(**extra):
    """Advance $pc past the current instruction without executing it."""
    frame = gdb.selected_frame()
    pc = frame.pc()
    insn = frame.architecture().disassemble(pc, count=1)[0]
    new_pc = pc + insn["length"]
    gdb.execute("set $pc = %d" % new_pc)
    return {"pc": new_pc}


@request("pwncEval")
def pwnc_eval(*, expression: str, **extra):
    return {"value": int(gdb.parse_and_eval(expression))}


# ── breakpoints / watchpoints ──────────────────────────────────────────────

@request("pwncBreakpoint", expect_stopped=False)
def pwnc_breakpoint(*, spec: str, condition: str = None, temporary: bool = False,
                    **extra):
    """Create a breakpoint, returning its gdb number (for callback dispatch)."""
    bp = gdb.Breakpoint(spec, temporary=temporary)
    if condition:
        bp.condition = condition
    return {"number": bp.number}


_WP_CLASS = {"r": gdb.WP_READ, "w": gdb.WP_WRITE, "a": gdb.WP_ACCESS}


@request("pwncWatch")
def pwnc_watch(*, expression: str, kind: str = "w", condition: str = None,
               **extra):
    bp = gdb.Breakpoint(expression, type=gdb.BP_WATCHPOINT,
                        wp_class=_WP_CLASS.get(kind, gdb.WP_WRITE))
    if condition:
        bp.condition = condition
    return {"number": bp.number}


@request("pwncDeleteBreakpoint", expect_stopped=False)
def pwnc_delete_breakpoint(*, number: int, **extra):
    for bp in gdb.breakpoints():
        if bp.number == number:
            bp.delete()
            return {"deleted": True}
    return {"deleted": False}


# ── target info ────────────────────────────────────────────────────────────

@request("pwncArch", expect_stopped=False)
def pwnc_arch(**extra):
    ptrbits = gdb.lookup_type("void").pointer().sizeof * 8
    byteorder = "little"
    try:
        if "big" in gdb.execute("show endian", to_string=True):
            byteorder = "big"
    except gdb.error:
        pass
    return {"byteorder": byteorder, "ptrbits": ptrbits}
