import threading

try:
    import gdb
except ImportError:
    pass

class StupidHackNi(gdb.Command):
    def __init__(self):
        super().__init__("stupid-hack-ni", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        def nexti():
            gdb.execute("nexti")

        waiter = threading.Event()

        def stop(e=None):
            waiter.set()

        gdb.events.stop.connect(stop)
        gdb.post_event(nexti)
        waiter.wait()
        gdb.events.stop.disconnect(stop)

        while True:
            try:
                output = gdb.execute("info thread", to_string=True)
                if "(running)" not in output:
                    break
            except gdb.error:
                pass
        return
    
class StupidHackSi(gdb.Command):
    def __init__(self):
        super().__init__("stupid-hack-si", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        def stepi():
            gdb.execute("stepi")

        waiter = threading.Event()

        def stop(e=None):
            waiter.set()

        gdb.events.stop.connect(stop)
        gdb.post_event(stepi)
        waiter.wait()
        gdb.events.stop.disconnect(stop)

        while True:
            try:
                output = gdb.execute("info thread", to_string=True)
                if "(running)" not in output:
                    break
            except gdb.error:
                pass
        return
    
StupidHackNi()
StupidHackSi()

gdb.execute("define ni\nstupid-hack-ni\nend")
gdb.execute("define si\nstupid-hack-si\nend")