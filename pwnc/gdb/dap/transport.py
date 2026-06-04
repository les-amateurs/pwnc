"""DAP JSON-RPC transport over a ``gdb --interpreter=dap`` subprocess.

One framed, request-id-correlated channel (the thing the mi console-scrape
transport never was): ``Content-Length``-delimited JSON, each request matched to
its response by ``seq``/``request_seq`` via a Future, async events dispatched to
registered handlers, structured errors, and timeouts on every wait.
"""

import json
import os
import subprocess
import threading
from concurrent.futures import Future, TimeoutError as _FTimeout
from itertools import count


DEFAULT_TIMEOUT = 30.0


class DapError(RuntimeError):
    """A DAP request returned ``success: false`` (or the channel failed)."""

    def __init__(self, message, command=None, body=None):
        super().__init__(message)
        self.command = command
        self.body = body


class DapTimeout(DapError):
    """A DAP request did not get a response within the timeout."""


def spawn_argv(gdb_path="gdb", gdb_args=None):
    argv = [gdb_path, "-q", "-nx", "--interpreter=dap"]
    if gdb_args:
        argv.extend(gdb_args)
    return argv


class DapTransport:
    """Owns the gdb subprocess and speaks DAP over its stdio."""

    def __init__(self, gdb_path="gdb", gdb_args=None, env=None):
        self.proc = subprocess.Popen(
            spawn_argv(gdb_path, gdb_args),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, bufsize=0,
        )
        self._seq = count(1)
        self._lock = threading.Lock()       # protects _pending
        self._wlock = threading.Lock()      # serialize writes to stdin
        self._pending = {}                  # seq -> Future
        self._handlers = {}                 # event name -> [callable(body)]
        self._initialized = threading.Event()
        self._closed = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    # ── public API ──────────────────────────────────────────────────────

    def on(self, event, handler):
        """Register *handler(body)* for a DAP event (may register several)."""
        self._handlers.setdefault(event, []).append(handler)

    def request(self, command, arguments=None, timeout=DEFAULT_TIMEOUT):
        """Send a request and return its response ``body`` (raises on failure).

        Note that gdb sends a response for every request — including the
        ``response=False`` execution commands (next/stepIn/...) which respond
        immediately on acceptance; the resulting stop arrives later as a
        ``stopped`` event.
        """
        seq = next(self._seq)
        fut = Future()
        with self._lock:
            if self._closed:
                raise DapError("transport closed", command=command)
            self._pending[seq] = fut
        msg = {"seq": seq, "type": "request", "command": command}
        if arguments is not None:
            msg["arguments"] = arguments
        self._send(msg)
        try:
            resp = fut.result(timeout=timeout)
        except _FTimeout:
            with self._lock:
                self._pending.pop(seq, None)
            raise DapTimeout("timed out waiting for %r response" % command,
                             command=command)
        if not resp.get("success", False):
            raise DapError(resp.get("message") or "request failed",
                           command=command, body=resp.get("body"))
        return resp.get("body")

    def wait_initialized(self, timeout=DEFAULT_TIMEOUT):
        if not self._initialized.wait(timeout):
            raise DapTimeout("gdb DAP did not send 'initialized'")

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
        self._fail_pending("transport closed")

    # ── internals ───────────────────────────────────────────────────────

    def _send(self, msg):
        data = json.dumps(msg).encode("utf-8")
        header = ("Content-Length: %d\r\n\r\n" % len(data)).encode("ascii")
        with self._wlock:
            try:
                self.proc.stdin.write(header + data)
                self.proc.stdin.flush()
            except (OSError, ValueError) as e:
                raise DapError("write failed: %s" % e)

    def _read_loop(self):
        f = self.proc.stdout
        try:
            while True:
                length = None
                while True:
                    line = f.readline()
                    if not line:
                        return self._fail_pending("gdb DAP stream closed")
                    line = line.strip()
                    if not line:
                        break               # blank line ends the header block
                    if b":" in line:
                        k, v = line.split(b":", 1)
                        if k.strip().lower() == b"content-length":
                            length = int(v.strip())
                if not length:
                    continue
                body = self._readn(f, length)
                if body is None:
                    return self._fail_pending("gdb DAP stream closed")
                try:
                    msg = json.loads(body.decode("utf-8"))
                except ValueError:
                    continue
                self._dispatch(msg)
        except Exception as e:                # pragma: no cover - defensive
            self._fail_pending("reader crashed: %s" % e)

    @staticmethod
    def _readn(f, n):
        chunks = []
        while n > 0:
            chunk = f.read(n)
            if not chunk:
                return None
            chunks.append(chunk)
            n -= len(chunk)
        return b"".join(chunks)

    def _dispatch(self, msg):
        kind = msg.get("type")
        if kind == "response":
            seq = msg.get("request_seq")
            with self._lock:
                fut = self._pending.pop(seq, None)
            if fut is not None and not fut.done():
                fut.set_result(msg)
        elif kind == "event":
            event = msg.get("event")
            body = msg.get("body") or {}
            if event == "initialized":
                self._initialized.set()
            for handler in list(self._handlers.get(event, ())):
                try:
                    handler(body)
                except Exception:
                    pass
        elif kind == "request":
            # Reverse request from the adapter (e.g. runInTerminal). gdb does
            # not need these for our flow; decline so it never blocks on us.
            self._send({
                "seq": next(self._seq), "type": "response",
                "request_seq": msg.get("seq"), "command": msg.get("command"),
                "success": False, "message": "not supported",
            })

    def _fail_pending(self, reason):
        with self._lock:
            self._closed = True
            pending = list(self._pending.items())
            self._pending.clear()
        for _seq, fut in pending:
            if not fut.done():
                fut.set_exception(DapError(reason))
        self._initialized.set()
