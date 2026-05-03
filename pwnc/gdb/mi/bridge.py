"""GDB-side bridge script — runs inside the GDB Python interpreter.

Provides RPC access to GDB's Python API. Handlers are invoked via
MI interpreter-exec commands, avoiding GDB's thread-safety issues.
"""

import base64
import io
import os
import pickle
import traceback

from pwnc.gdb.mi.protocol import Call, Return, Error, Release

import gdb


# --- Object store for proxy references ---

object_store = {}


# --- Proxy serialization ---

PROXY_TYPES = (
    gdb.InferiorThread,
    gdb.Inferior,
    gdb.Progspace,
    gdb.Frame,
    gdb.Symbol,
    gdb.Block,
    gdb.Breakpoint,
)


class BridgePickler(pickle.Pickler):
    def persistent_id(self, obj):
        for cls in PROXY_TYPES:
            if isinstance(obj, cls):
                oid = id(obj)
                object_store[oid] = obj
                return (type(obj).__name__, oid)
        return None


# --- RPC handlers ---

handlers = {}


def handler(name):
    def decorator(fn):
        handlers[name] = fn
        return fn
    return decorator


# --- Generic proxy handlers ---

@handler("proxy.call")
def proxy_call(oid, method_name, args, kwargs):
    obj = object_store[oid]
    return getattr(obj, method_name)(*args, **kwargs)


@handler("proxy.get")
def proxy_get(oid, attr_name):
    obj = object_store[oid]
    return getattr(obj, attr_name)


@handler("proxy.set")
def proxy_set(oid, attr_name, value):
    obj = object_store[oid]
    setattr(obj, attr_name, value)


@handler("proxy.release")
def proxy_release(oid):
    object_store.pop(oid, None)


# --- Utility handlers ---

@handler("selected_inferior")
def selected_inferior():
    return gdb.selected_inferior()


@handler("selected_frame")
def selected_frame():
    return gdb.selected_frame()


@handler("selected_thread")
def selected_thread():
    return gdb.selected_thread()


@handler("lookup_symbol")
def lookup_symbol(name):
    return gdb.lookup_symbol(name)


@handler("read_memory")
def read_memory(addr, size):
    inf = gdb.selected_inferior()
    return bytes(inf.read_memory(addr, size))


@handler("write_memory")
def write_memory(addr, data):
    inf = gdb.selected_inferior()
    inf.write_memory(addr, data)


@handler("skip_instruction")
def skip_instruction():
    frame = gdb.selected_frame()
    arch = frame.architecture()
    pc = frame.pc()
    insn = arch.disassemble(pc, count=1)[0]
    new_pc = pc + insn['length']
    gdb.execute(f"set $pc = {new_pc}")


@handler("get_register")
def get_register(name):
    frame = gdb.selected_frame()
    return int(frame.read_register(name))


@handler("set_register")
def set_register(name, value):
    gdb.execute(f"set ${name} = {value}")


@handler("create_breakpoint")
def create_breakpoint(spec, **kwargs):
    return gdb.Breakpoint(spec, **kwargs)


# --- GDB type → pwnc type descriptor ---

@handler("resolve_type")
def resolve_type(name):
    """Look up a symbol, return (type_desc, address) for pwnc.types construction."""
    sym = None
    try:
        result = gdb.lookup_symbol(name)
        sym = result[0]
    except gdb.error:
        pass

    if sym is None:
        try:
            sym = gdb.lookup_global_symbol(name)
        except Exception:
            pass

    if sym is None:
        try:
            sym = gdb.lookup_static_symbol(name)
        except Exception:
            pass

    if sym is not None:
        try:
            addr = int(sym.value().address)
        except Exception:
            addr = None
        try:
            desc = gdb_type_to_pwnc(sym.type)
        except Exception:
            desc = None
        return (desc, addr)

    # Fallback: use GDB's expression evaluator, which searches minsyms,
    # PLT entries, and shared-library symbols that lookup_*symbol misses.
    try:
        val = gdb.parse_and_eval(name)
    except gdb.error as e:
        if "unknown type" in str(e):
            val = gdb.parse_and_eval(f"&{name}")
            addr = int(val)
            return (None, addr, "function")
        else:
            return None

    t = val.type.strip_typedefs()

    # For symbols without debug info or function types, get address via &name.
    # Return "function" flag so the client returns the address directly
    # rather than reading memory at the address.
    if t.code in (gdb.TYPE_CODE_ERROR, gdb.TYPE_CODE_FUNC):
        addr_val = gdb.parse_and_eval(f"&{name}")
        addr = int(addr_val)
        return (None, addr, "function")

    # Regular value (variable in a shared library)
    addr = int(val.address) if val.address else int(val)
    try:
        desc = gdb_type_to_pwnc(t)
    except Exception:
        desc = None
    return (desc, addr)


def gdb_type_to_pwnc(gdb_type, _cache=None):
    """Convert a gdb.Type to a serializable dict describing a pwnc.types.Type.

    _cache maps struct/union tags to their (possibly incomplete) result
    dicts.  When a pointer target is a struct already in _cache, the
    cached dict is reused — creating a circular reference that pickle
    serialises natively.  By the time the top-level call returns every
    cached dict is fully populated.
    """
    if _cache is None:
        _cache = {}

    t = gdb_type.strip_typedefs()
    code = t.code

    if code == gdb.TYPE_CODE_INT:
        return {"kind": "int", "bits": t.sizeof * 8, "signed": t.is_signed}
    elif code == gdb.TYPE_CODE_CHAR:
        return {"kind": "int", "bits": 8, "signed": t.is_signed}
    elif code == gdb.TYPE_CODE_BOOL:
        return {"kind": "int", "bits": t.sizeof * 8, "signed": False}
    elif code == gdb.TYPE_CODE_FLT:
        if t.sizeof == 4:
            return {"kind": "float"}
        else:
            return {"kind": "double"}
    elif code == gdb.TYPE_CODE_PTR:
        return {"kind": "ptr", "child": gdb_type_to_pwnc(t.target(), _cache), "bits": t.sizeof * 8}
    elif code == gdb.TYPE_CODE_ARRAY:
        target = t.target()
        low, high = t.range()
        count = high - low + 1
        return {"kind": "array", "child": gdb_type_to_pwnc(target, _cache), "count": count}
    elif code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        tag = t.tag or t.name or "<anon>"
        if tag in _cache:
            return _cache[tag]
        kind = "struct" if code == gdb.TYPE_CODE_STRUCT else "union"
        result = {"kind": kind, "name": tag, "fields": [], "size": t.sizeof}
        _cache[tag] = result          # cache BEFORE processing fields
        for f in t.fields():
            result["fields"].append({
                "name": f.name,
                "type": gdb_type_to_pwnc(f.type, _cache),
                "offset": f.bitpos // 8,
                "bit_offset": f.bitpos % 8,
            })
        return result
    elif code == gdb.TYPE_CODE_ENUM:
        members = {f.name: f.enumval for f in t.fields()}
        try:
            child_desc = gdb_type_to_pwnc(t.target(), _cache)
        except Exception:
            child_desc = {"kind": "int", "bits": t.sizeof * 8, "signed": False}
        return {"kind": "enum", "child": child_desc,
                "members": members, "name": t.tag or t.name}
    elif code == gdb.TYPE_CODE_VOID:
        return {"kind": "void"}
    else:
        return {"kind": "int", "bits": t.sizeof * 8, "signed": False}


@handler("get_endian")
def get_endian():
    endian = gdb.execute("show endian", to_string=True)
    if "little" in endian:
        return "little"
    return "big"


@handler("get_pointer_size")
def get_pointer_size():
    void_ptr = gdb.lookup_type("void").pointer()
    return void_ptr.sizeof * 8


# --- Dispatch entry point ---
# Called via MI: -interpreter-exec console "python _pwnc_dispatch('...')"
# Payload is a base64-encoded pickle of (method, args, kwargs).
# Response is printed as base64-encoded pickle, read from console stream.

def _pwnc_dispatch(b64_payload):
    """Dispatch an RPC call. Runs on GDB's main thread via MI."""
    try:
        payload = base64.b64decode(b64_payload)
        method, args, kwargs = pickle.loads(payload)

        h = handlers.get(method)
        if h is None:
            result = Error(id=0, exception=f"Unknown method: {method}")
        else:
            try:
                value = h(*args, **kwargs)
                result = Return(id=0, value=value)
            except Exception:
                result = Error(id=0, exception=traceback.format_exc())

        # Pickle the result with proxy serialization
        buf = io.BytesIO()
        p = BridgePickler(buf)
        p.dump(result)
        encoded = base64.b64encode(buf.getvalue()).decode()
        # Print with a marker so client can find it in console output
        print(f"__PWNC_RESULT__:{encoded}", flush=True)
    except Exception:
        err = base64.b64encode(
            pickle.dumps(Error(id=0, exception=traceback.format_exc()))
        ).decode()
        print(f"__PWNC_RESULT__:{err}", flush=True)
