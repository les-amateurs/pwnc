import gdb
import time
import socket
from threading import Condition
from rpyc.core.protocol import Connection
from rpyc.lib.compat import select_error

# ServeResult and GdbConnection stolen from pwntools gdb bridge
class ServeResult:
    """Result of serving requests on GDB thread."""
    def __init__(self):
        self.cv = Condition()
        self.done = False
        self.exc = None

    def set(self, exc):
        with self.cv:
            self.done = True
            self.exc = exc
            self.cv.notify()

    def wait(self):
        with self.cv:
            while not self.done:
                self.cv.wait()
            if self.exc is not None:
                raise self.exc


class GdbConnection(Connection):
    """A Connection implementation that serves requests on GDB thread.

    Serving on GDB thread might not be ideal from the responsiveness
    perspective, however, it is simple and reliable.
    """
    SERVE_TIME = 0.1  # Number of seconds to serve.
    IDLE_TIME = 0.1  # Number of seconds to wait after serving.

    def serve_gdb_thread(self, serve_result):
        """Serve requests on GDB thread."""
        try:
            deadline = time.time() + self.SERVE_TIME
            while True:
                timeout = deadline - time.time()
                if timeout < 0:
                    break
                super().serve(timeout=timeout)
        except Exception as exc:
            serve_result.set(exc)
        else:
            serve_result.set(None)

    def serve_all(self):
        """Modified version of rpyc.core.protocol.Connection.serve_all."""
        try:
            while not self.closed:
                serve_result = ServeResult()
                gdb.post_event(lambda: self.serve_gdb_thread(serve_result))
                serve_result.wait()
                time.sleep(self.IDLE_TIME)
        except (socket.error, select_error, IOError):
            if not self.closed:
                raise
        except EOFError:
            pass
        finally:
            self.close()