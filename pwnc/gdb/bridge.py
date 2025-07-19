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


def my_execute(command, to_string=False, from_tty=True, auto=True):
    try:
        gdb.newest_frame()
    except gdb.error as e:
        print("bad")
        print(e)

    # gdb.write(gdb.prompt_hook(lambda: None))
    gdb.write(command + "\n")
    gdb.flush()

    try:
        ret = gdb.execute(command, to_string=to_string, from_tty=from_tty)
    except gdb.error as e:
        print("wtf")
        print(e)
        ret = None

    gdb.write(gdb.prompt_hook(lambda: None))
    gdb.flush()
    return ret


def my_ni():
    def nexti():
        gdb.execute("ni")

    gdb.post_event(lambda: nexti())


def my_set_breakpoint(loc, callback=None):
    if callback:

        class Bp(gdb.Breakpoint):
            def stop(self):
                # if "Cache" in globals():
                #     Cache.reset_gef_caches()
                print("RUNNING BP CALLBACK")
                should_stop = callback()
                # print(f"BP REQUESTING STOP = {stop}")
                return should_stop

        Bp(loc)
    else:
        gdb.Breakpoint(loc)


def my_eval(expr):
    print(f"evaling {expr}")
    return int(gdb.parse_and_eval(expr))


def my_interrupt():
    gdb.post_event(lambda: gdb.execute("interrupt"))


def my_continue_nowait():
    gdb.post_event(lambda: gdb.execute("continue &"))


def my_continue_wait():
    print("continue and wait")
    stopped = Event()
    waiters.append(stopped)

    def continuing():
        print("RUNNING CONTINUE")
        gdb.execute("continue &")
        print("DONE RUNNING CONTINUE")

    gdb.post_event(continuing)
    print("waiting...")
    stopped.wait()
    print("CONTINUE UNBLOCKED")
    gdb.execute("info thread")


def my_wait(timeout=None):
    thread = gdb.selected_thread()
    if thread is None:
        print("thread is none")
        return
    if thread.is_stopped():
        return

    stopped = Event()
    waiters.append(stopped)
    tout = not stopped.wait(timeout=timeout)
    if tout:
        waiters.pop()
    return tout


def my_running():
    if gdb.selected_thread() is None:
        return False
    return gdb.selected_thread().is_running()


def my_exited():
    return gdb.selected_thread() is None


def my_read_memory(addr: int, size: int):
    return gdb.selected_inferior().read_memory(addr, size).tobytes()


def my_prompt():
    gdb.write(gdb.prompt_hook(lambda: None))


waiters: list[Event] = []


def unblock():
    for waiter in waiters:
        waiter.set()
    waiters.clear()


def stopped(e: gdb.Event):
    print("STOPPPED")
    if isinstance(e, gdb.BreakpointEvent):
        print(e.breakpoint.silent)
        print(e.breakpoints)

    if waiters:
        thread = gdb.selected_thread()
        if thread and thread.is_stopped():
            print("UNBLOCKING")
            unblock()
        else:
            gdb.post_event(unblock)


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
s.register("prompt", my_prompt)

gdb.events.stop.connect(stopped)
gdb.events.exited.connect(exited)


def late_start(e=None):
    gdb.events.before_prompt.disconnect(late_start)
    s.start()


gdb.events.before_prompt.connect(late_start)
