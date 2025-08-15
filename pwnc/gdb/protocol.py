import socket
import os
import threading
import io
import base64
import queue
import builtins
from typing import Callable
from ..util import err


class Method:
    def __init__(self, fn, name: str, args: list, kwargs: dict):
        self.fn = fn
        self.name = name
        self.args = args
        self.kwargs = kwargs

    def __repr__(self):
        return f"Method(name={self.name})"

    def __call__(self):
        return self.fn(*self.args, **self.kwargs)


class Callback:
    def __init__(self, method: str, server: "Server"):
        self.server = server
        self.method = method

    def __await__(self):
        return (yield self)

    def __call__(self, *args, **kwargs):
        return self.server.run(self.method, *args, **kwargs)


class Server:
    class ForwardedException(Exception):
        pass

    class StopException(Exception):
        pass

    class EmptyMessageException(Exception):
        pass

    def __init__(self, name: str, socket_path: str, listen: bool, registry: dict[str, Callable] = {}):
        # print(f"server pid = {threading.get_native_id()}")
        self.name = name
        self.socket_path = socket_path
        self.listen = listen
        self.registry = registry.copy()
        self.reverse_registry = dict(((v, k) for k, v in registry.items()))
        self.values = queue.Queue()
        self.routines = list()
        self.thread: threading.Thread = None
        self.callback_id = 0
        self.reader: io.BufferedReader = None
        self.remote = False
        self.blocked = False
        self.native_id = None

        if listen:
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(socket_path)
            # err.info("listening...")
            self.listener.listen(1)
            self.sock, _ = self.listener.accept()
        else:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(socket_path)
        self.reader = io.BufferedReader(io.FileIO(self.sock.fileno()))

    def start(self):
        self.thread = threading.Thread(target=self.receiver, daemon=True)
        self.thread.start()

    def stop(self):
        self.send_raw(base64.b64encode(b"stop"))
        self.reader.close()

    def register(self, name: str, fn):
        self.registry[name] = fn
        self.reverse_registry[fn] = name

    def serialize(self, val):
        if isinstance(val, str):
            tag = b"str"
            packet = [base64.b64encode(val.encode())]
        elif isinstance(val, bytes):
            tag = b"bytes"
            packet = [base64.b64encode(val)]
        elif isinstance(val, bool):
            tag = b"bool"
            packet = [base64.b64encode(str(val).encode())]
        elif isinstance(val, int):
            tag = b"int"
            packet = [base64.b64encode(str(int(val)).encode())]
        elif isinstance(val, list) or isinstance(val, tuple):
            if len(val) == 0:
                tag = b"empty"
                packet = []
            else:
                tag = b"list"
                packet = [self.serialize(len(val))]
                for v in val:
                    packet.append(self.serialize(v))
        elif callable(val):
            if val not in self.reverse_registry:
                callback_id = self.callback_id
                self.callback_id += 1
                self.register(f"anon-{callback_id}", val)
            tag = b"callback"
            packet = [self.serialize(self.reverse_registry[val])]
        elif val is None:
            tag = b"none"
            packet = []
        else:
            raise TypeError(f"Unknown type: {type(val)}")

        packet = [base64.b64encode(tag)] + packet
        return b"\n".join(packet)

    def next_line(self):
        try:
            line = self.reader.readline()
        except OSError:
            line = None
        if not line:
            # print("stopping...")
            raise Server.EmptyMessageException
        line = base64.b64decode(line)
        # print(f"{self.name} got line {line}")
        return line

    def _deserialize(self):
        tag = self.next_line()
        # print(f"tag = {tag}")
        match tag:
            case b"str":
                return self.next_line().decode(errors="ignore")
            case b"bytes":
                return self.next_line()
            case b"int":
                return int(self.next_line())
            case b"bool":
                line = self.next_line()
                return True if line == b"True" else False
            case b"list":
                size = self._deserialize()
                items = [self._deserialize() for _ in range(size)]
                return items
            case b"empty":
                return []
            case b"call":
                method = self._deserialize()
                args = self._deserialize()
                kwords = self._deserialize()
                kwargs = self._deserialize()
                kwargs = dict(zip(kwords, kwargs))
                return Method(self.registry[method], method, args, kwargs)
            case b"callback":
                method = self._deserialize()
                return Callback(method, self)
            case b"none":
                return None
            case b"stop":
                raise Server.StopException

    def deserialize(self, from_remote=False):
        if (self.remote and not self.blocked) and from_remote:
            return self.values.get()

        val = self._deserialize()
        if (self.remote and not self.blocked) and not from_remote:
            # print(f"forwarding {val}")
            self.values.put(val)
            raise Server.ForwardedException
        else:
            return val

    def receiver(self):
        # print(f"thread pid = {threading.get_native_id()}")
        self.native_id = threading.get_native_id()

        while True:
            try:
                # print("reciever waiting for value...")
                val = self.deserialize()
            except Server.EmptyMessageException:
                break
            except Server.StopException:
                break
            except Server.ForwardedException:
                continue

            # print(f"reciever got: {val}")
            if isinstance(val, Method):
                prev_blocked = self.blocked
                self.blocked = True
                self.send(val())
                self.blocked = prev_blocked
            else:
                err.warn(f"WTF: {val}")

        # err.info("stopping...")
        try:
            self.send_raw(base64.b64encode(b"stop"))
        except OSError:
            # err.warn("peer already stopped")
            pass

        builtins.exit()

    def send_raw(self, packet: bytes):
        try:
            self.sock.send(packet + b"\n")
        except OSError as e:
            # err.warn(f"send error: {e}")
            pass

    def send(self, val):
        packet = self.serialize(val)
        self.send_raw(packet)
        # print(f"{self.name} SENT {val}")

    def run(self, method: str, *args, **kwargs):
        # print(method)
        # print(f"remote = {self.remote}")
        remote_orig = self.remote
        if threading.get_native_id() != self.native_id:
            # print("setting remote")
            self.remote = True

        try:
            parts = [
                base64.b64encode(b"call"),
                self.serialize(method),
                self.serialize(args),
                self.serialize(list(kwargs.keys())),
                self.serialize(list(kwargs.values())),
            ]
            packet = b"\n".join(parts)
            self.send_raw(packet)
            # print(f"[{self.name}] running remote: {method}")

            while True:
                try:
                    # print("attempting to deserialize value")
                    # print(f"remote = {self.remote}")
                    val = self.deserialize(True)
                except Server.StopException:
                    break
                except Server.EmptyMessageException:
                    break

                # print(f"[{self.name}] received val = {val}")
                if isinstance(val, Method):
                    ret = val()
                    # print(f"[{self.name}] {val} finished with {ret}")
                    self.send(ret)
                else:
                    # print(f"[{self.name}] (RUN) returning val = {val}")
                    return val
        finally:
            self.remote = remote_orig
