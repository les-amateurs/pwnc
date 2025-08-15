"""GDB Python API bridge."""

import gdb
import pwnc.gdb.protocol
import threading
import time


class Result:
    def __init__(self):
        self.event = threading.Event()
        self.item = None

    def submit(self, item):
        self.item = item
        self.event.set()

    def wait(self):
        self.event.wait()


def execute_command(command, to_string, from_tty):
    try:
        ret = gdb.execute(command, to_string=to_string, from_tty=from_tty)
    except gdb.error as e:
        print("wtf")
        print(e)
        ret = None
    return ret


def my_execute(command, to_string=False, from_tty=True, safe=False):
    try:
        gdb.newest_frame()
    except gdb.error as e:
        print("bad 1")
        print(e)

    try:
        gdb.selected_frame()
    except gdb.error as e:
        print("bad 2")
        print(e)

    # gdb.write(gdb.prompt_hook(lambda: None))
    gdb.write(command + "\n")
    gdb.flush()

    if safe:
        result = Result()
        def safe_execute_command():
            print("SAFE")
            try:
                gdb.newest_frame()
            except gdb.error as e:
                print("bad 1")
                print(e)

            try:
                gdb.selected_frame()
            except gdb.error as e:
                print("bad 2")
                print(e)
            ret = execute_command(command, to_string=to_string, from_tty=from_tty)
            result.submit(ret)
        gdb.post_event(safe_execute_command)
        result.wait()
        ret = result.item
    else:
        ret = execute_command(command, to_string=to_string, from_tty=from_tty)
        print("wtf")

    gdb.write(gdb.prompt_hook(lambda: None))
    gdb.flush()
    return ret


def my_ni():
    def nexti():
        gdb.execute("nexti")
    stopped = threading.Event()
    waiters.append(stopped)
    gdb.post_event(nexti)
    stopped.wait()


def my_si():
    def stepi():
        gdb.execute("stepi")
    stopped = threading.Event()
    waiters.append(stopped)
    gdb.post_event(stepi)
    stopped.wait()


def my_set_breakpoint(loc, callback=None):
    if callback:
        class Bp(gdb.Breakpoint):
            def stop(self):
                # if "Cache" in globals():
                #     Cache.reset_gef_caches()
                # print("RUNNING BP CALLBACK")
                should_stop = callback()
                if should_stop is None:
                    return True
                # print(f"BP REQUESTING STOP = {should_stop}")
                return should_stop

        bp = Bp(loc)
    else:
        bp = gdb.Breakpoint(loc)
    return bp.number


def my_eval(expr):
    # print(f"evaling {expr}")
    return int(gdb.parse_and_eval(expr))


"""
The interrupt command behaves differently from gdb.interrupt() ...
"""
def my_interrupt():
    gdb.post_event(lambda: gdb.execute("interrupt"))


"""
https://www.eclipse.org/lists/cdt-dev/msg34353.html

For some reason, executing a stepping command inside of post_event
puts gdb in a weird state where it considers all other stepping
instructions as also async, even without the ampersand modifier.
"""

def my_continue_nowait():
    gdb.post_event(lambda: gdb.execute("continue &"))


def my_continue_wait(timeout: int | None = None):
    # print("continue and wait")
    stopped = threading.Event()
    waiters.append(stopped)

    def continuing():
        # print("RUNNING CONTINUE")
        gdb.execute("continue")
        # print("DONE RUNNING CONTINUE")
    gdb.post_event(continuing)
    # gdb.execute("source continue.py")

    stopped.wait(timeout=timeout)
    
    if timeout is not None:
        gdb.execute("interrupt")


def my_wait(timeout=None):
    thread = gdb.selected_thread()
    if thread is None:
        print("thread is none")
        return
    if thread.is_stopped():
        return

    stopped = threading.Event()
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


def my_write_memory(addr: int, data: bytes):
    gdb.selected_inferior().write_memory(addr, data)


def my_prompt():
    gdb.write(gdb.prompt_hook(lambda: None))


waiters: list[threading.Event] = []


def unblock():
    for waiter in waiters:
        waiter.set()
    waiters.clear()


def stopped(e: gdb.Event):
    # print("STOPPPED")
    if waiters:
        thread = gdb.selected_thread()
        if thread and thread.is_stopped():
            # print("UNBLOCKING")
            unblock()
        else:
            gdb.post_event(unblock)


def exited(e: gdb.Event):
    for waiter in waiters:
        waiter.set()


s = pwnc.gdb.protocol.Server("bridge", socket_path, True)
s.register("execute", my_execute)
s.register("ni", my_ni)
s.register("si", my_si)
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
