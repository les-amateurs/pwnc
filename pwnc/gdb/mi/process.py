"""GDB subprocess management in MI3 mode."""

import os
import subprocess
import threading
from concurrent.futures import Future
from typing import Callable

from .parser import (
    parse_output, Record, ResultRecord, ExecAsync, StatusAsync,
    NotifyAsync, ConsoleStream, TargetStream, LogStream,
)


class GdbProcess:
    """Manages a GDB subprocess running in MI3 interpreter mode."""

    def __init__(self, gdb_path="gdb", env=None):
        self._gdb_path = gdb_path
        self._env = env
        self.proc: subprocess.Popen | None = None
        self._token = 0
        self._pending: dict[int, Future] = {}
        self._reader_thread: threading.Thread | None = None
        self._callbacks: dict[str, list[Callable]] = {}
        self._console_buf: list[str] = []
        self._console_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._stop_result: dict | None = None
        self._lock = threading.Lock()

    def start(self, program=None, args=None, core=None, pid=None,
              extra_args=None):
        """Spawn the GDB subprocess in MI3 mode."""
        cmd = [self._gdb_path, "--interpreter=mi3", "-q"]

        if extra_args:
            cmd.extend(extra_args)

        if program:
            cmd.append(program)

        if core:
            cmd.extend(["--core", core])

        if pid is not None:
            cmd.extend(["-p", str(pid)])

        if args:
            cmd.append("--args")
            cmd.extend(args)

        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env,
        )

        self._reader_thread = threading.Thread(
            target=self._reader_loop, daemon=True
        )
        self._reader_thread.start()

        # wait for initial (gdb) prompt
        self._wait_ready()

    def _wait_ready(self):
        """Wait for GDB to finish loading and be ready for commands."""
        # Send a no-op MI command and wait for its result. This ensures
        # all startup output (gdbinit, GEF, etc.) has been processed.
        token = self._next_token()
        future = Future()
        with self._lock:
            self._pending[token] = future
        line = f"{token}-gdb-set mi-async on\n"
        self.proc.stdin.write(line.encode())
        self.proc.stdin.flush()
        future.result(timeout=30)

    def _next_token(self) -> int:
        with self._lock:
            t = self._token
            self._token += 1
            return t

    def command(self, mi_cmd: str, **params) -> ResultRecord:
        """Send an MI command and wait for the result record.

        Args:
            mi_cmd: MI command without the leading '-' (e.g. "exec-run")
            **params: Currently unused, reserved for future param formatting
        """
        token = self._next_token()
        future = Future()

        with self._lock:
            self._pending[token] = future

        line = f"{token}-{mi_cmd}\n"
        self.proc.stdin.write(line.encode())
        self.proc.stdin.flush()

        return future.result()

    def console(self, cli_cmd: str) -> str:
        """Execute a CLI command via the MI interpreter-exec and return output."""
        # escape the command for MI
        escaped = cli_cmd.replace('\\', '\\\\').replace('"', '\\"')
        token = self._next_token()
        future = Future()

        with self._lock:
            self._pending[token] = future
        with self._console_lock:
            self._console_buf.clear()

        line = f'{token}-interpreter-exec console "{escaped}"\n'
        self.proc.stdin.write(line.encode())
        self.proc.stdin.flush()

        future.result()  # wait for completion

        with self._console_lock:
            output = ''.join(self._console_buf)
            self._console_buf.clear()
        return output

    def send_raw(self, data: str):
        """Send raw data to GDB's stdin."""
        self.proc.stdin.write(data.encode())
        self.proc.stdin.flush()

    def on(self, event: str, callback: Callable):
        """Register a callback for async events."""
        self._callbacks.setdefault(event, []).append(callback)

    def wait_for_stop(self) -> dict:
        """Block until a *stopped async record is received.

        Returns the stop record's results dict.
        """
        self._stop_event.clear()
        self._stop_result = None
        self._stop_event.wait()
        return self._stop_result

    def _reader_loop(self):
        """Read MI output lines from GDB stdout and dispatch."""
        while True:
            raw = self.proc.stdout.readline()
            if not raw:
                # GDB exited
                self._cleanup_pending()
                break

            line = raw.decode('utf-8', errors='replace')
            record = parse_output(line)
            if record is None:
                continue

            self._dispatch(record)

    def _dispatch(self, record: Record):
        """Route a parsed record to the appropriate handler."""
        if isinstance(record, ResultRecord):
            with self._lock:
                future = self._pending.pop(record.token, None)
            if future is not None:
                if record.cls == "error":
                    future.set_exception(
                        RuntimeError(record.results.get("msg", "GDB error"))
                    )
                else:
                    future.set_result(record)

        elif isinstance(record, ExecAsync):
            if record.cls == "stopped":
                self._stop_result = record.results
                self._stop_event.set()
            cbs = self._callbacks.get(record.cls, [])
            for cb in cbs:
                cb(record)

        elif isinstance(record, (StatusAsync, NotifyAsync)):
            cbs = self._callbacks.get(record.cls, [])
            for cb in cbs:
                cb(record)

        elif isinstance(record, ConsoleStream):
            with self._console_lock:
                self._console_buf.append(record.text)
            cbs = self._callbacks.get("console", [])
            for cb in cbs:
                cb(record)

        elif isinstance(record, TargetStream):
            cbs = self._callbacks.get("target", [])
            for cb in cbs:
                cb(record)

        elif isinstance(record, LogStream):
            cbs = self._callbacks.get("log", [])
            for cb in cbs:
                cb(record)

    def _cleanup_pending(self):
        """Cancel all pending futures when GDB exits."""
        with self._lock:
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(RuntimeError("GDB process exited"))
            self._pending.clear()

    def close(self):
        """Terminate the GDB subprocess."""
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.write(b"-gdb-exit\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
                self.proc.wait()
