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

import importlib
import os
import re
import signal
import sys

import gdb
from gdb.dap.server import request


def _install_clean_dap_quit():
    """Keep GDB's normal exit path from looking like batch execution.

    GDB 14 through 17 route the DAP server's final ``quit`` through an
    ``exec_and_log`` helper which calls ``gdb.execute(..., to_string=True)``.
    Capturing command output temporarily enables GDB's batch flag.  Since
    ``quit_force`` only writes command history when an interactive UI exists,
    that temporary flag makes it skip the real, shared CLI history even when a
    secondary ``new-ui console`` is attached.

    Replace only the final ``quit`` invocation with an uncaptured execution.
    All other DAP commands keep their upstream implementation and logging.  In
    GDB 14 the JSON writer resolves the helper in ``gdb.dap.startup``; newer
    versions resolve an imported alias in ``gdb.dap.server``, so cover both.
    """
    for module_name in ("gdb.dap.startup", "gdb.dap.server"):
        module = importlib.import_module(module_name)
        if getattr(module, "_pwnc_clean_quit_installed", False):
            continue
        original = getattr(module, "exec_and_log", None)
        if not callable(original):
            continue

        def exec_and_log(command, *args, _original=original, **kwargs):
            if command == "quit":
                return gdb.execute(command, from_tty=True, to_string=False)
            return _original(command, *args, **kwargs)

        module.exec_and_log = exec_and_log
        module._pwnc_clean_quit_installed = True


_install_clean_dap_quit()


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

@request("pwncEventBarrier", on_dap_thread=True, expect_stopped=False)
def pwnc_event_barrier(**extra):
    """Order a response after every previously emitted DAP event.

    The host pairs this with its ordered event lane before starting a new
    execution request.  This makes stops produced internally by synchronous
    plugin commands (for example Bata24 ``next-ret -n``) distinguishable from
    the next public continue/step operation.
    """
    return {}


@request("pwncConsoleOutputBarrier", expect_stopped=False)
def pwnc_console_output_barrier(*, marker: str, **extra):
    """Flush startup output and append an unambiguous fd-1 marker.

    Native DAP's output reader turns this marker into an OutputEvent only after
    every previously buffered line.  The host removes it and uses its arrival
    as the boundary for the transcript replayed into a secondary console.
    """
    if not isinstance(marker, str) or not re.fullmatch(
        r"__PWNC_STARTUP_OUTPUT_[0-9a-f]{64}__",
        marker,
    ):
        raise ValueError("invalid startup-output barrier marker")
    _pwnc_flush_output()
    _pwnc_write_all(1, (marker + "\n").encode("ascii"))
    return {}


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

@request("pwncRemoteFileSettings", expect_stopped=False)
def pwnc_remote_file_settings(*, sysroot: str = None,
                              solibSearchPath: str = None, **extra):
    """Set remote path parameters without lossy GDB CLI string parsing."""

    result = {}
    if sysroot is not None:
        gdb.set_parameter("sysroot", sysroot)
        result["sysroot"] = str(gdb.parameter("sysroot"))
    if solibSearchPath is not None:
        gdb.set_parameter("solib-search-path", solibSearchPath)
        result["solibSearchPath"] = str(gdb.parameter("solib-search-path"))
    return result


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


# ── interactive console ─────────────────────────────────────────────────────

# Native DAP saves the protocol's original fd 0/1 before replacing the
# process-wide descriptors with /dev/null and its inferior-output pipe.  A
# secondary ``new-ui`` gets its own GDB ui_file streams, but that does not help
# plugins which call APIs such as ``os.get_terminal_size()`` (implicitly fd 1)
# or write progress directly to fd 0.  Keep one selected console PTY as the
# process stdio compatibility endpoint without touching DAP's saved wire.
_pwnc_console_tty = None
_pwnc_console_saved_stdio = None
_pwnc_console_gef_attempt = None
_pwnc_console_gef_redirected = False
_pwnc_console_gef_namespace = None


def _pwnc_private_dup(fd):
    duplicate = os.dup(fd)
    try:
        os.set_inheritable(duplicate, False)
    except BaseException:
        os.close(duplicate)
        raise
    return duplicate


def _pwnc_duplicate_stdio():
    stdin_copy = _pwnc_private_dup(0)
    try:
        stdout_copy = _pwnc_private_dup(1)
    except BaseException:
        os.close(stdin_copy)
        raise
    return stdin_copy, stdout_copy


def _pwnc_close_stdio_pair(pair):
    for fd in pair:
        try:
            os.close(fd)
        except OSError:
            pass


def _pwnc_restore_stdio_pair(pair):
    first_error = None
    for target, source in enumerate(pair):
        try:
            os.dup2(source, target, inheritable=True)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise first_error


def _pwnc_flush_output():
    for stream_name in ("STDOUT", "STDERR"):
        try:
            gdb.flush(stream=getattr(gdb, stream_name))
        except (AttributeError, gdb.error):
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (AttributeError, OSError, ValueError):
            pass


def _pwnc_flush_stdout():
    # Retain the narrower historical helper name for the stdio binding sites.
    _pwnc_flush_output()


def _pwnc_write_all(fd, data):
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("console output write made no progress")
        offset += written


def _pwnc_begin_console_stdio(tty_fd, canonical_tty):
    """Bind fd 0/1 transactionally and return a commit/rollback token."""
    global _pwnc_console_tty
    global _pwnc_console_saved_stdio
    global _pwnc_console_gef_attempt

    _pwnc_flush_stdout()
    rollback = _pwnc_duplicate_stdio()
    first_binding = _pwnc_console_saved_stdio is None
    previous_tty = _pwnc_console_tty
    try:
        os.dup2(tty_fd, 0, inheritable=True)
        os.dup2(tty_fd, 1, inheritable=True)
    except BaseException:
        try:
            _pwnc_restore_stdio_pair(rollback)
        finally:
            _pwnc_close_stdio_pair(rollback)
        raise

    if first_binding:
        # In addition to permitting restoration, retaining the original fd 1
        # writer prevents native DAP's output-reader thread from seeing a
        # permanent EOF if another component later redirects fd 2.
        _pwnc_console_saved_stdio = rollback
    _pwnc_console_tty = canonical_tty
    _pwnc_console_gef_attempt = None
    return first_binding, rollback, previous_tty


def _pwnc_commit_console_stdio(token):
    first_binding, rollback, _previous_tty = token
    if not first_binding:
        _pwnc_close_stdio_pair(rollback)


def _pwnc_rollback_console_stdio(token):
    global _pwnc_console_tty
    global _pwnc_console_saved_stdio
    global _pwnc_console_gef_attempt

    first_binding, rollback, previous_tty = token
    try:
        _pwnc_restore_stdio_pair(rollback)
    finally:
        if first_binding:
            _pwnc_console_saved_stdio = None
        _pwnc_close_stdio_pair(rollback)
        _pwnc_console_tty = previous_tty
        _pwnc_console_gef_attempt = None


def _pwnc_restore_console_stdio(_event=None):
    """Restore native DAP's process descriptors during GDB shutdown."""
    global _pwnc_console_tty
    global _pwnc_console_saved_stdio
    global _pwnc_console_gef_attempt
    global _pwnc_console_gef_redirected
    global _pwnc_console_gef_namespace

    saved = _pwnc_console_saved_stdio
    if saved is None:
        return
    _pwnc_console_saved_stdio = None
    try:
        _pwnc_flush_stdout()
        _pwnc_restore_stdio_pair(saved)
    finally:
        _pwnc_close_stdio_pair(saved)
        _pwnc_console_tty = None
        _pwnc_console_gef_attempt = None
        _pwnc_console_gef_redirected = False
        _pwnc_console_gef_namespace = None


def _pwnc_gef_api(namespace):
    """Return GEF's configuration API from a module-like namespace."""
    if namespace is None:
        return None
    config = namespace.get("Config")
    context_command = namespace.get("ContextCommand")
    if config is None or context_command is None:
        return None
    if not callable(getattr(config, "set_gef_setting", None)):
        return None
    if not callable(getattr(config, "get_gef_setting", None)):
        return None
    return config, context_command


def _pwnc_find_gef_api():
    """Find both directly sourced and normally imported GEF instances.

    A plain ``source gef.py`` executes in GDB's shared script namespace.  Real
    configurations also commonly load GEF with ``importlib`` so that a small
    wrapper can extend it; those classes live only in the imported module's
    namespace.  Prefer the conventional module names, then retain a discovered
    fallback so ordinary stop events do not repeatedly scan ``sys.modules``.
    """
    global _pwnc_console_gef_namespace

    namespaces = [globals()]
    for module_name in ("bata24", "gef"):
        module = sys.modules.get(module_name)
        if module is not None:
            namespaces.append(getattr(module, "__dict__", None))
    if _pwnc_console_gef_namespace is not None:
        namespaces.append(_pwnc_console_gef_namespace)

    seen = set()
    for namespace in namespaces:
        if namespace is None or id(namespace) in seen:
            continue
        seen.add(id(namespace))
        api = _pwnc_gef_api(namespace)
        if api is not None:
            _pwnc_console_gef_namespace = namespace
            return api

    # Imported wrappers are free to choose another module name.  This fallback
    # runs only until a matching namespace is retained above.
    for module in tuple(sys.modules.values()):
        namespace = getattr(module, "__dict__", None)
        if namespace is None or id(namespace) in seen:
            continue
        seen.add(id(namespace))
        api = _pwnc_gef_api(namespace)
        if api is not None:
            _pwnc_console_gef_namespace = namespace
            return api
    return None


def _pwnc_configure_gef_console():
    """Point an unmodified loaded GEF at the selected console, once per load."""
    global _pwnc_console_gef_attempt
    global _pwnc_console_gef_redirected

    tty = _pwnc_console_tty
    if tty is None:
        return False

    # Object identity makes a later GEF reload a new configuration generation.
    api = _pwnc_find_gef_api()
    if api is None:
        return False
    config, context_command = api
    signature = (tty, config, context_command)
    if _pwnc_console_gef_attempt == signature:
        return _pwnc_console_gef_redirected

    _pwnc_console_gef_attempt = signature
    _pwnc_console_gef_redirected = False
    setter = getattr(config, "set_gef_setting", None)
    getter = getattr(config, "get_gef_setting", None)
    if not callable(setter) or not callable(getter):
        return False
    try:
        setter("context.redirect", tty)
        _pwnc_console_gef_redirected = getter("context.redirect") == tty
    except Exception:
        _pwnc_console_gef_redirected = False
    return _pwnc_console_gef_redirected


def _pwnc_configure_console_on_stop(_event):
    # This handler is registered before plugins sourced after pwnc's bootstrap,
    # so a newly loaded GEF receives its redirect before its own automatic
    # context stop handler runs.  Headless sessions take only the first guard.
    if _pwnc_console_tty is not None:
        _pwnc_configure_gef_console()


def _pwnc_return_to_dap_ui_after_prompt():
    """Return GDB's global UI affinity to native DAP after CLI input.

    ``new-ui``'s stdin callback leaves GDB's process-global ``current_ui`` on
    the console UI.  A later native-DAP ``gdb.post_event`` callback otherwise
    inherits that UI's already-PROMPTED state, which changes synchronous nested
    commands such as GEF's ``next-ret -n`` into asynchronous operations.

    GDB's own SIGQUIT async handler is intentionally a no-op, but all async
    signal handlers are dispatched on ``main_ui``.  Mark it from the console's
    before-prompt event: once this stdin callback returns to the event loop,
    GDB performs the UI handoff before accepting another event.  This is an
    event-driven synchronization point; it neither polls nor replaces GDB's
    CLI or DAP command machinery.
    """
    if _pwnc_console_tty is None:
        return
    sigquit = getattr(signal, "SIGQUIT", None)
    if sigquit is None:
        return
    try:
        os.kill(os.getpid(), sigquit)
    except OSError:
        # The console remains useful on a platform or embedding which does not
        # provide GDB's normal Unix SIGQUIT event handler.  Such a target cannot
        # use this compatibility handoff, but a prompt must never fail for it.
        pass


gdb.events.stop.connect(_pwnc_configure_console_on_stop)
gdb.events.before_prompt.connect(_pwnc_return_to_dap_ui_after_prompt)
gdb.events.gdb_exiting.connect(_pwnc_restore_console_stdio)


@request("pwncNewUI", expect_stopped=False)
def pwnc_new_ui(*, tty: str, interp: str = "console", save_history: bool = True,
                startup_output: str = "", **extra):
    """Attach a second gdb UI (a CLI console) to *tty* — e.g. a terminal window.

    expect_stopped=False so the console can be opened while the inferior runs.
    Enables command-history saving explicitly so commands typed in the console
    persist when the session exits cleanly, including when the caller selected
    init-free startup with ``init=False``.
    """
    # ``new-ui`` is a CLI-only API.  Do not interpolate arbitrary request text
    # into it: first open and canonicalize the terminal, then restrict both CLI
    # words to the character set produced by real tty names/interpreters.
    if not isinstance(interp, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", interp):
        raise ValueError("invalid GDB UI interpreter")
    if not isinstance(tty, str) or not tty:
        raise ValueError("tty must be a non-empty path")
    if not isinstance(startup_output, str):
        raise TypeError("startup_output must be text")
    startup_bytes = startup_output.encode("utf-8")
    if len(startup_bytes) > 16 * 1024 * 1024:
        raise ValueError("startup_output exceeds the 16 MiB console limit")
    flags = os.O_RDWR | os.O_NOCTTY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tty, flags)
    try:
        if not os.isatty(fd):
            raise ValueError("new-ui target is not a tty")
        canonical_tty = os.ttyname(fd)
        if not re.fullmatch(r"/[-A-Za-z0-9_./]+", canonical_tty):
            raise ValueError("tty canonicalized to an unsafe path")

        # Reconstruct the missing beginning of the CLI transcript before GDB
        # creates the UI and renders its first prompt.  Owned consoles already
        # have an active drain lane, so even a large retained startup log cannot
        # fill the PTY and block GDB's main thread here.
        _pwnc_write_all(fd, startup_bytes)

        # Bind before creating the UI so plugin prompt hooks observe the real
        # terminal geometry on their very first render.  The DAP protocol uses
        # descriptors it saved during native startup and is unaffected.
        token = _pwnc_begin_console_stdio(fd, canonical_tty)
        try:
            # ``new-ui`` renders the new console prompt before reporting its
            # own "New UI allocated" confirmation on the invoking UI.  Capture
            # that administrative confirmation so it cannot appear after the
            # prompt on the terminal we just bound to fd 1.
            gdb.execute(
                "new-ui %s %s" % (interp, canonical_tty),
                to_string=True,
            )
        except BaseException:
            _pwnc_rollback_console_stdio(token)
            raise
        else:
            _pwnc_commit_console_stdio(token)
    finally:
        os.close(fd)
    if save_history:
        try:
            gdb.execute("set history save on")
        except gdb.error:
            pass
    return {
        "tty": canonical_tty,
        "stdio": True,
        "gefRedirect": _pwnc_configure_gef_console(),
    }


@request("pwncSetWinsize", expect_stopped=False)
def pwnc_set_winsize(*, rows: int, cols: int, **extra):
    """Tell gdb the console terminal's size so width-aware plugins render right.

    gdb's own terminal is the DAP pipe (width auto-detect is meaningless there),
    so the console relays the selected TTY size here on attach and on SIGWINCH.
    """
    gdb.execute("set width %d" % int(cols))
    gdb.execute("set height %d" % int(rows))
    return {}
