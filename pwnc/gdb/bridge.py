"""GDB Python API bridge."""

import gdb

import socket
from threading import Condition, Event
import time

from rpyc.core.protocol import Connection
from rpyc.core.service import Service
from rpyc.lib import spawn
from rpyc.lib.compat import select_error
from rpyc.utils.server import ThreadedServer

print("bridge loaded")


class Result:
    def __init__(self):
        self.event = Event()
        self.item = None


class GdbService(Service):
    """A public interface for Pwntools."""

    exposed_gdb = gdb  # ``gdb`` module.

    def exposed_set_breakpoint(self, client, has_stop, *args, **kwargs):
        """Create a breakpoint and connect it with the client-side mirror."""
        if has_stop:

            class Breakpoint(gdb.Breakpoint):
                def stop(self):
                    return client.stop()

            Breakpoint(*args, **kwargs)
        else:
            gdb.Breakpoint(*args, **kwargs)

    def exposed_set_finish_breakpoint(self, client, has_stop, has_out_of_scope, *args, **kwargs):
        """Create a finish breakpoint and connect it with the client-side mirror."""

        class FinishBreakpoint(gdb.FinishBreakpoint):
            if has_stop:

                def stop(self):
                    return client.stop()

            if has_out_of_scope:

                def out_of_scope(self):
                    client.out_of_scope()

        return FinishBreakpoint(*args, **kwargs)

    def exposed_execute(self, cmd, to_string=False, from_tty=False):
        result = Result()

        def execute():
            res = gdb.execute(cmd, to_string=to_string, from_tty=from_tty)
            result.item = res
            result.event.set()

        gdb.post_event(lambda: execute())
        result.event.wait()
        return result.item

    def exposed_quit(self):
        """Terminate GDB."""
        gdb.post_event(lambda: gdb.execute("quit"))


spawn(
    ThreadedServer(
        service=GdbService(),
        socket_path=socket_path,
        protocol_config={
            "allow_all_attrs": True,
            "allow_setattr": True,
        },
    ).start
)
