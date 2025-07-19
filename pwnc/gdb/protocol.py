# class Thing:
#     def __await__(self):
#         return (yield self)

# async def a():
#     val = await Thing()
#     print(val)
#     return 5

# future = a()
# print(dir(future))
# print(future.send)
# print(future.cr_suspended)
# future.send(None)
# print(future.cr_suspended)
# future.send(2)

# exit(0)

import socket
import os
import threading
import io
import base64
import queue
from typing import Coroutine


class Method:
    def __init__(self, fn, args: list, kwargs: dict):
        # print(fn, args, kwargs)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def __call__(self):
        return self.fn(*self.args, **self.kwargs)


class Callback:
    def __init__(self, method: str, server: "Server"):
        self.server = server
        self.method = method

    def __await__(self):
        return (yield self)

    def __call__(self, *args, **kwargs):
        return self.server.invoke(self.method, *args, **kwargs)


class Result:
    def __init__(self):
        self.event = threading.Event()
        self.val = None

    def __await__(self):
        return (yield self)


class Server:
    def __init__(self, name: str, socket_path: str, listen: bool):
        self.name = name
        self.socket_path = socket_path
        self.listen = listen
        self.registry = dict()
        self.reverse_registry = dict()
        self.values = queue.LifoQueue()
        self.routines = list()
        self.thread: threading.Thread = None

        if listen:
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(socket_path)
            print("listening...")
            self.listener.listen(1)
            self.sock, _ = self.listener.accept()
        else:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(socket_path)

    def start(self):
        self.thread = threading.Thread(target=self.receiver, daemon=True)
        self.thread.start()

    def stop(self):
        self.sock.send(base64.b64encode(b"stop") + b"\n" + b"A" * 512)

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
            tag = b"callback"
            packet = [self.serialize(self.reverse_registry[val])]
        elif val is None:
            tag = b"none"
            packet = []
        else:
            raise Exception(f"Unknown type: {type(val)}")

        packet = [base64.b64encode(tag)] + packet
        return b"\n".join(packet)

    def deserialize(self, next_line):
        tag = next_line()
        match tag:
            case b"str":
                return next_line().decode(errors="ignore")
            case b"bytes":
                return next_line()
            case b"int":
                return int(next_line())
            case b"bool":
                line = next_line()
                return True if line == b"True" else False
            case b"list":
                size = self.deserialize(next_line)
                items = [self.deserialize(next_line) for _ in range(size)]
                return items
            case b"empty":
                return []
            case b"call":
                method = self.deserialize(next_line)
                args = self.deserialize(next_line)
                kwords = self.deserialize(next_line)
                kwargs = self.deserialize(next_line)
                kwargs = dict(zip(kwords, kwargs))
                return Method(self.registry[method], args, kwargs)
            case b"callback":
                method = self.deserialize(next_line)
                return Callback(method, self)
            case b"none":
                return None
            case b"stop":
                raise StopIteration

    def receiver(self):
        reader = io.BufferedReader(io.FileIO(self.sock.fileno()))

        def next_line():
            line = reader.readline()
            if not line:
                # print("stopping...")
                raise StopIteration
            line = base64.b64decode(line)
            # print(f"{self.name} got line {line}")
            return line

        while True:
            try:
                val = self.deserialize(next_line)
            except StopIteration:
                break

            if isinstance(val, Method):
                # print(f"{self.name} got {self.reverse_registry[val.fn]}")
                routine: Coroutine = val()
                # print(f"{self.name} calling {self.reverse_registry[val.fn]}")
                assert routine.cr_suspended == False
                self.routines.append(routine)

                # if not routine.cr_suspended:
                #     try:
                #         # print("starting routine")
                #         # print(dir(routine))
                #         routine.send(None)
                #         # print("routine done")
                #         self.routines.append(routine)
                #     except StopIteration as e:
                #         # print(f"{self.name} routine finished immediately")
                #         self.send(e.value)
                # else:
                #     self.routines.append(routine)

            # print(f"{self.name} received: {val}")
            try:
                routine = self.routines.pop()
                if routine.cr_suspended == False:
                    routine.send(None)
                else:
                    thing = routine.send(val)
                # print(f"{self.name} thing = {thing}")
                self.routines.append(routine)
            except StopIteration as e:
                # print(f"{self.name} completed with {e.value}")
                # print(f"{self.name} routines = {self.routines}")
                self.send(e.value)
            except IndexError:
                # means we've exhausted all the routines and we are done
                continue

            # if self.routines:
            #     routine = self.routines.pop()
            #     if not routine.cr_suspended:
            #         try:
            #             coro = routine.send(None)
            #             self.routines.append(routine)
            #         except StopIteration as e:
            #             # print(f"{self.name} routine finished immediately")
            #             self.send(e.value)
            #     else:
            #         self.routines.append(routine)

        try:
            self.sock.send(base64.b64encode(b"stop") + b"\n" + b"A" * 512)
        except OSError:
            # print("peer already stopped")
            pass

        exit()

    def send(self, val):
        packet = self.serialize(val)
        self.sock.send(packet + b"\n")
        # print(f"{self.name} SENT {val}")

    def run(self, method: str, *args, **kwargs):
        routine = self.invoke(method, *args, **kwargs)
        try:
            res = routine.send(None)
            self.routines.append(routine)
            # print(f"waiting for completion")
            res.event.wait()
            # print(f"completed")
            return res.val
        except StopIteration as e:
            return e.value

    async def invoke(self, method: str, *args, **kwargs):
        parts = [
            base64.b64encode(b"call"),
            self.serialize(method),
            self.serialize(args),
            self.serialize(list(kwargs.keys())),
            self.serialize(list(kwargs.values())),
        ]
        packet = b"\n".join(parts)
        self.sock.send(packet + b"\n")
        # print(f"{self.name} waiting for response")
        result = Result()
        val = await result
        result.val = val
        result.event.set()
        return val
