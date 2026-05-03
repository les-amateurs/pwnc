"""Pickle-based bidirectional RPC over Unix socket."""

import io
import os
import pickle
import queue
import socket
import struct
import threading
import traceback
from dataclasses import dataclass
from typing import Any


# --- Message types ---

@dataclass
class Call:
    id: int
    method: str
    args: tuple
    kwargs: dict

@dataclass
class Return:
    id: int
    value: Any

@dataclass
class Error:
    id: int
    exception: str

@dataclass
class Release:
    oid: int


# --- Custom pickler/unpickler for proxy serialization ---

# These are set up by bridge.py (GDB side) and proxy.py (client side)
# to enable transparent proxy object serialization.

class BridgePickler(pickle.Pickler):
    """Pickler that replaces GDB objects with proxy references.

    Used on the GDB side. proxy_types and object_store are injected
    by the bridge at setup time.
    """

    def __init__(self, f, object_store, proxy_types=None):
        super().__init__(f)
        self.object_store = object_store
        self.proxy_types = proxy_types or ()

    def persistent_id(self, obj):
        for cls in self.proxy_types:
            if isinstance(obj, cls):
                oid = id(obj)
                self.object_store[oid] = obj
                return (type(obj).__name__, oid)
        return None


_MSG_CLASSES = {'Call': Call, 'Return': Return, 'Error': Error, 'Release': Release}


class BridgeUnpickler(pickle.Unpickler):
    """Unpickler that reconstructs proxy references into proxy objects.

    Used on the client side. proxy_classes is injected by the client.
    Also resolves protocol message classes via find_class so that
    messages from the bridge (which may define its own class variants)
    are unpickled into our local dataclass versions.
    """

    def __init__(self, f, proxy_classes=None, conn=None):
        super().__init__(f)
        self.proxy_classes = proxy_classes or {}
        self.conn = conn

    def find_class(self, module, name):
        if name in _MSG_CLASSES:
            return _MSG_CLASSES[name]
        return super().find_class(module, name)

    def persistent_load(self, pid):
        type_name, oid = pid
        cls = self.proxy_classes.get(type_name)
        if cls is None:
            raise pickle.UnpicklingError(f"Unknown proxy type: {type_name}")
        return cls(self.conn, oid)


# --- Connection ---

class Connection:
    """Bidirectional RPC connection over a socket.

    Supports nested calls: while waiting for a Return, the receiver
    may get an incoming Call and dispatch it locally.
    """

    def __init__(self, sock, object_store=None, proxy_types=None,
                 proxy_classes=None, handlers=None):
        self.sock = sock
        self.object_store = object_store if object_store is not None else {}
        self.proxy_types = proxy_types or ()
        self.proxy_classes = proxy_classes or {}
        self.handlers = handlers if handlers is not None else {}
        self._call_id = 0
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._pending: dict[int, queue.Queue] = {}
        self._closed = False
        self._receiver = threading.Thread(target=self._recv_loop, daemon=True)
        self._receiver.start()

    def call(self, method: str, *args, **kwargs) -> Any:
        """Make a synchronous RPC call and return the result."""
        with self._lock:
            cid = self._call_id
            self._call_id += 1
            q = queue.Queue()
            self._pending[cid] = q

        msg = Call(id=cid, method=method, args=args, kwargs=kwargs)
        self._send(msg)

        # wait for response, handling nested calls
        while True:
            item = q.get()
            if isinstance(item, Return):
                with self._lock:
                    self._pending.pop(cid, None)
                return item.value
            elif isinstance(item, Error):
                with self._lock:
                    self._pending.pop(cid, None)
                raise RuntimeError(f"Remote error: {item.exception}")
            elif isinstance(item, Call):
                # nested callback from remote side
                self._handle_call(item)
            else:
                with self._lock:
                    self._pending.pop(cid, None)
                raise RuntimeError(f"Unexpected message: {item}")

    def _handle_call(self, msg: Call):
        """Execute a local handler for an incoming Call and send Return/Error."""
        handler = self.handlers.get(msg.method)
        if handler is None:
            self._send(Error(id=msg.id, exception=f"Unknown method: {msg.method}"))
            return
        try:
            result = handler(*msg.args, **msg.kwargs)
            self._send(Return(id=msg.id, value=result))
        except Exception:
            self._send(Error(id=msg.id, exception=traceback.format_exc()))

    def _send(self, msg):
        """Pickle a message and send it with a 4-byte length prefix."""
        buf = io.BytesIO()
        pickler = BridgePickler(buf, self.object_store, self.proxy_types)
        pickler.dump(msg)
        data = buf.getvalue()
        header = struct.pack('>I', len(data))
        with self._send_lock:
            self.sock.sendall(header + data)

    def _recv_one(self) -> Any:
        """Receive one length-prefixed pickle message."""
        header = self._recvall(4)
        if header is None:
            return None
        length = struct.unpack('>I', header)[0]
        data = self._recvall(length)
        if data is None:
            return None
        buf = io.BytesIO(data)
        unpickler = BridgeUnpickler(buf, self.proxy_classes, self)
        return unpickler.load()

    def _recvall(self, n: int) -> bytes | None:
        """Receive exactly n bytes from the socket."""
        parts = []
        remaining = n
        while remaining > 0:
            try:
                chunk = self.sock.recv(remaining)
            except (OSError, ConnectionError):
                return None
            if not chunk:
                return None
            parts.append(chunk)
            remaining -= len(chunk)
        return b''.join(parts)

    def _recv_loop(self):
        """Background receiver: dispatch incoming messages."""
        while not self._closed:
            msg = self._recv_one()
            if msg is None:
                self._closed = True
                # wake all pending calls
                with self._lock:
                    for q in self._pending.values():
                        q.put(Error(id=-1, exception="Connection closed"))
                break

            if isinstance(msg, (Return, Error)):
                with self._lock:
                    q = self._pending.get(msg.id)
                if q is not None:
                    q.put(msg)
            elif isinstance(msg, Call):
                # incoming call from remote side
                # if there's a pending call waiting, route it there
                # for nested callback support; otherwise handle directly
                with self._lock:
                    # find any pending call to route nested callbacks through
                    pending_q = None
                    if self._pending:
                        # route to the most recent pending call
                        pending_q = list(self._pending.values())[-1]

                if pending_q is not None:
                    pending_q.put(msg)
                else:
                    self._handle_call(msg)
            elif isinstance(msg, Release):
                self.object_store.pop(msg.oid, None)

    def close(self):
        """Close the connection."""
        self._closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
