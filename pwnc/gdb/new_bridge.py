"""GDB Python API bridge."""
import gdb
from pwnc.gdb import protocol
from threading import Event
import time

class Result:
    def __init__(self):
        self.event = Event()
        self.item = None

    def submit(self, item):
        self.item = item
        self.event.set()

    def wait(self):
        self.event.wait()

async def my_execute(command, to_string=False, from_tty=True, auto=True):
    # gdb.write(gdb.prompt_hook(lambda: None))
    gdb.write(command + "\n")
    gdb.flush()

    try:
        ret = gdb.execute(command, to_string=to_string, from_tty=from_tty)
    except:
        ret = None

    gdb.write(gdb.prompt_hook(lambda: None))
    gdb.flush()
    return ret

async def my_ni():
    def nexti():
        gdb.execute("ni")
    gdb.post_event(lambda: nexti())

async def my_set_breakpoint(loc, callback = None):
    if callback:
        class Bp(gdb.Breakpoint):
            def stop(self):
                Cache.reset_gef_caches()
                return s.run(callback)
                # callbacks.append(callback)
                return True
        Bp(loc)
    else:
        gdb.Breakpoint(loc)

async def my_eval(expr):
    return int(gdb.parse_and_eval(expr))

async def my_interrupt():
    gdb.post_event(lambda: gdb.execute("interrupt"))

async def my_continue_nowait():
    gdb.post_event(lambda: gdb.execute("continue &"))

async def my_continue_wait():
    # print("continue and wait")
    stopped = Event()
    waiters.append(stopped)
    gdb.post_event(lambda: gdb.execute("continue &"))
    stopped.wait()

async def my_wait(timeout=None):
    thread = gdb.selected_thread()
    if thread is None:
        return
    if thread.is_stopped():
        return

    stopped = Event()
    waiters.append(stopped)
    tout = not stopped.wait(timeout=timeout)
    if tout:
        waiters.pop()
    return tout

async def my_running():
    if gdb.selected_thread() is None:
        return False
    return gdb.selected_thread().is_running()

async def my_exited():
    return gdb.selected_thread() is None

async def my_read_memory(addr: int, size: int):
    return gdb.selected_inferior().read_memory(addr, size).tobytes()

callbacks: list[str] = []
waiters: list[Event] = []

def stopped(e: gdb.Event):
    stop = True

    if callbacks:
        print(gdb.selected_thread().is_running())
        for callback in callbacks:
            stop = stop and s.run(callback)
        callbacks.clear()

    if stop:
        if waiters:
            def unblock():
                for waiter in waiters:
                    waiter.set()
                waiters.clear()
            gdb.post_event(unblock)
    else:
        gdb.post_event(lambda: gdb.execute("continue &"))

def exited(e: gdb.Event):
    for waiter in waiters:
        waiter.set()

s = protocol.Server("bridge", socket_path, True)
s.register("execute", my_execute)
s.register("ni", my_ni)
s.register("set_breakpoint", my_set_breakpoint)
s.register("parse_and_eval", my_eval)
s.register("continue_nowait", my_continue_nowait)
s.register("continue", my_continue_wait)
s.register("wait", my_wait)
s.register("interrupt", my_interrupt)
s.register("running", my_running)
s.register("exited", my_exited)
s.register("read_memory", my_read_memory)

gdb.events.stop.connect(stopped)
gdb.events.exited.connect(exited)

def late_start(e = None):
    gdb.events.before_prompt.disconnect(late_start)
    s.start()

gdb.events.before_prompt.connect(late_start)
