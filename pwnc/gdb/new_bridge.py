"""GDB Python API bridge."""
import gdb
from pwnc.gdb import protocol
from threading import Event

class Result:
    def __init__(self):
        self.event = Event()
        self.item = None

    def submit(self, item):
        self.item = item
        self.event.set()

    def wait(self):
        self.event.wait()

async def my_execute(command, to_string=False, from_tty=False):
    gdb.write(gdb.prompt_hook(lambda: None))
    gdb.write(command + "\n")
    # result = Result()
    # def execute():
        # ret = gdb.execute(command, to_string=to_string, from_tty=from_tty)
        # result.submit(ret)
    # gdb.post_event(lambda: execute())
    # while not result.event.is_set():
        # time.sleep(.5)
    gdb.write(gdb.prompt_hook(lambda: None))
    return gdb.execute(command, to_string=to_string, from_tty=from_tty)
    return result.item

async def my_set_breakpoint(loc, callback = None):
    if callback:
        class Bp(gdb.Breakpoint):
            def stop(self):
                print("stop called")
                val = s.run(callback)
                print(f"val is {val}")
                return val
            
        Bp(loc)
    else:
        gdb.Breakpoint(loc)

async def my_eval(expr):
    return int(gdb.parse_and_eval(expr))

async def my_interrupt():
    gdb.post_event(lambda: gdb.execute("interrupt"))

async def my_continue_nowait():
    gdb.post_event(lambda: gdb.execute("continue &"))

import time
async def test():
    return gdb.execute("heap bins", to_string=True)

async def my_deferred_execute(command, to_string=False, from_tty=False):
    # gdb.write(gdb.prompt_hook(lambda: None))
    # gdb.write(command + "\n")
    # result = Result()
    def execute():
        ret = gdb.execute(command, to_string=to_string, from_tty=from_tty)
        print(ret)
        gdb.execute("continue &")
    gdb.post_event(lambda: execute())
    # gdb.write(gdb.prompt_hook(lambda: None))

s = protocol.Server("bridge", socket_path, True)
s.register("execute", my_execute)
s.register("deferred_execute", my_deferred_execute)
s.register("set_breakpoint", my_set_breakpoint)
s.register("eval", my_eval)
s.register("test", test)