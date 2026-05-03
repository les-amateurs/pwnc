"""Client-side proxy descriptors and proxy classes for GDB objects."""


# --- Descriptors ---

class RemoteMethod:
    """Descriptor for proxy methods — calls method on the remote GDB object."""

    def __init__(self, name=None):
        self.name = name

    def __set_name__(self, owner, name):
        if self.name is None:
            self.name = name

    def __get__(self, obj, cls=None):
        if obj is None:
            return self
        name = self.name
        def method(*args, **kwargs):
            return obj._conn.call("proxy.call", obj._oid, name, args, kwargs)
        return method


class RemoteProperty:
    """Descriptor for read-only proxy properties."""

    def __init__(self, name=None):
        self.name = name

    def __set_name__(self, owner, name):
        if self.name is None:
            self.name = name

    def __get__(self, obj, cls=None):
        if obj is None:
            return self
        return obj._conn.call("proxy.get", obj._oid, self.name)


class RemoteRWProperty:
    """Descriptor for read-write proxy properties."""

    def __init__(self, name=None):
        self.name = name

    def __set_name__(self, owner, name):
        if self.name is None:
            self.name = name

    def __get__(self, obj, cls=None):
        if obj is None:
            return self
        return obj._conn.call("proxy.get", obj._oid, self.name)

    def __set__(self, obj, value):
        obj._conn.call("proxy.set", obj._oid, self.name, value)


# --- Base ---

class ProxyBase:
    """Base class for all proxy objects."""

    def __init__(self, conn, oid):
        object.__setattr__(self, '_conn', conn)
        object.__setattr__(self, '_oid', oid)

    def __del__(self):
        try:
            self._conn.call("proxy.release", self._oid)
        except Exception:
            pass

    def __repr__(self):
        return f"<{type(self).__name__} oid={self._oid}>"


# --- Proxy classes ---

class ThreadProxy(ProxyBase):
    name        = RemoteProperty()
    num         = RemoteProperty()
    global_num  = RemoteProperty()
    ptid        = RemoteProperty()
    inferior    = RemoteProperty()

    is_valid    = RemoteMethod()
    switch      = RemoteMethod()
    is_stopped  = RemoteMethod()
    is_running  = RemoteMethod()
    is_exited   = RemoteMethod()
    handle      = RemoteMethod()


class InferiorProxy(ProxyBase):
    num          = RemoteProperty()
    pid          = RemoteProperty()
    was_attached = RemoteProperty()
    progspace    = RemoteProperty()

    is_valid       = RemoteMethod()
    threads        = RemoteMethod()
    architecture   = RemoteMethod()
    read_memory    = RemoteMethod()
    write_memory   = RemoteMethod()
    search_memory  = RemoteMethod()


class ProgspaceProxy(ProxyBase):
    filename = RemoteProperty()

    is_valid           = RemoteMethod()
    block_for_pc       = RemoteMethod()
    find_pc_line       = RemoteMethod()
    objfiles           = RemoteMethod()
    solib_name         = RemoteMethod()


class FrameProxy(ProxyBase):
    is_valid            = RemoteMethod()
    name                = RemoteMethod()
    architecture        = RemoteMethod()
    type                = RemoteMethod()
    unwind_stop_reason  = RemoteMethod()
    level               = RemoteMethod()
    pc                  = RemoteMethod()
    block               = RemoteMethod()
    function            = RemoteMethod()
    older               = RemoteMethod()
    newer               = RemoteMethod()
    find_sal            = RemoteMethod()
    read_register       = RemoteMethod()
    read_var            = RemoteMethod()
    select              = RemoteMethod()


class SymbolProxy(ProxyBase):
    name          = RemoteProperty()
    linkage_name  = RemoteProperty()
    print_name    = RemoteProperty()
    type          = RemoteProperty()
    symtab        = RemoteProperty()
    line          = RemoteProperty()
    needs_frame   = RemoteProperty()
    is_argument   = RemoteProperty()
    is_constant   = RemoteProperty()
    is_function   = RemoteProperty()
    is_variable   = RemoteProperty()

    is_valid      = RemoteMethod()
    value         = RemoteMethod()


class BlockProxy(ProxyBase):
    start        = RemoteProperty()
    end          = RemoteProperty()
    function     = RemoteProperty()
    superblock   = RemoteProperty()
    global_block = RemoteProperty()
    static_block = RemoteProperty()
    is_global    = RemoteProperty()
    is_static    = RemoteProperty()

    is_valid     = RemoteMethod()


class BreakpointProxy(ProxyBase):
    # read-only
    pending    = RemoteProperty()
    number     = RemoteProperty()
    type       = RemoteProperty()
    visible    = RemoteProperty()
    temporary  = RemoteProperty()
    location   = RemoteProperty()
    expression = RemoteProperty()
    # read-write
    enabled      = RemoteRWProperty()
    silent       = RemoteRWProperty()
    thread       = RemoteRWProperty()
    ignore_count = RemoteRWProperty()
    hit_count    = RemoteRWProperty()
    condition    = RemoteRWProperty()
    commands     = RemoteRWProperty()

    is_valid = RemoteMethod()
    delete   = RemoteMethod()


# --- Registry ---

PROXY_CLASSES = {
    "InferiorThread": ThreadProxy,
    "Inferior": InferiorProxy,
    "Progspace": ProgspaceProxy,
    "Frame": FrameProxy,
    "Symbol": SymbolProxy,
    "Block": BlockProxy,
    "Breakpoint": BreakpointProxy,
}
