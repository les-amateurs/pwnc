try:
    import gdb
except:
    pass

_should_stop = None

class HookStop:
    def __init__(self):
        self.orig_stop = gdb.events.stop
        gdb.events.stop = self
        self.events = []
        self.breakpoints = {}
        self.triggered_breakpoints = set()
        self.handler_hooks = {}

    def connect(self, handler):
        def hook_handler(event, *args, **kwargs):
            if isinstance(event, gdb.BreakpointEvent):
                self.triggered_breakpoints.update(event.breakpoints)
            self.events.append((event, handler))

        self.orig_stop.connect(hook_handler)
        self.handler_hooks[handler] = hook_handler

    def disconnect(self, handler):
        hook_handler = self.handler_hooks[handler]
        del self.handler_hooks[handler]
        return self.orig_stop.disconnect(hook_handler)

    def trigger(self):
        global _should_stop

        events = self.events
        triggered_breakpoints = self.triggered_breakpoints
        print(triggered_breakpoints)

        self.events = []
        self.should_stop = True
        self.triggered_breakpoints = set()

        # before = gdb.execute("gef config context.layout", to_string=True).splitlines()[1].split(" = ", maxsplit=1)[1][1:-1]
        before = "regs stack code args source mem_access trace extra"
        gdb.execute("gef config context.layout \"\"")
        should_stop = True
        for triggered_breakpoint in triggered_breakpoints:
            request_stop = self.breakpoints[triggered_breakpoint]()
            if request_stop is None:
                request_stop = True
            should_stop = should_stop and request_stop
        # print(before)
        # gdb.execute(f"gef config context.layout \"{before}\"")

        if should_stop:
            for event, handler in events:
                handler(event)
        _should_stop = should_stop

hook = HookStop()
gdb.events.before_prompt.connect(hook.trigger)
gdb.execute(
"""
define hook-stop
python
if not _should_stop:
    gdb.post_event(lambda: gdb.execute("continue"))
end
end
"""
)

def bp(loc: str, callback = None):
    bp = gdb.Breakpoint(loc)
    if callback:
        hook.breakpoints[bp] = callback
    return bp

def hook_malloc():
    rdi = gdb.parse_and_eval("$rdi")
    print(rdi)
    gdb.execute("next-ret -n")
    rax = gdb.parse_and_eval("$rax")
    print(rax)
    return False

bp("malloc.c:3480", hook_malloc)