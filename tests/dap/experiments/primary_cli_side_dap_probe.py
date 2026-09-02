#!/usr/bin/env python3
"""Audit a native primary GDB CLI with stock DAP on a side fd.

This is deliberately an experiment, not production transport code.  It starts
GDB's ordinary CLI on a controlling PTY and bootstraps the ``gdb.dap`` package
shipped by that exact GDB over an inherited socketpair.  No DAP interpreter and
no ``new-ui`` are created.

The probe exercises the properties needed by pwnc's proposed console rewrite.
It is intentionally a compatibility gate rather than a success-only demo: the
architecture is rejected if an untouched execution-driving plugin command does
not behave exactly as it does under GDB's native DAP interpreter.

* unmodified bata24 GEF sees the real and dynamically resized PTY geometry;
* automatic GEF context reaches the primary PTY for DAP- and CLI-driven stops;
* stock structured DAP requests and native CLI/GEF commands both keep working;
* untouched Bata24 ``next-ret -n`` can drive execution inside a host callback;
* an asynchronous stop redraw preserves a partially typed readline buffer;
* closing and reconnecting a viewer fd does not close the retained GDB PTY; and
* DAP disconnect produces an orderly GDB exit.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path


DEFAULT_GEF = Path("/home/ctf/bata24-gef/gef.py")
EXPECTED_GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
REPOSITORY = Path(__file__).resolve().parents[3]
THREAD_AUDIT_EXTENSION = Path(__file__).with_name("dap_thread_audit_ext.py")
RPC_PROBE_EXTENSION = Path(__file__).with_name("rpc_probe_ext.py")

TIMEOUT = 20.0
INITIAL_SIZE = (47, 137)
FIRST_STOP_SIZE = (43, 149)
SECOND_STOP_SIZE = (39, 127)
REDRAW_SEQUENCE = b"\x1b[99~"
PARTIAL_COMMAND = b"echo PWNC_PARTIAL_INPUT"
DETACHED_OUTPUT = b"PWNC_DETACHED_OUTPUT"

_FRAME_LIMIT = 64 * 1024 * 1024
_HEADER_END = b"\r\n\r\n"
_ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")

_FIXTURE_SOURCE = r"""
#include <stdint.h>

volatile uint64_t pwnc_primary_cli_value = 0x1122334455667788ULL;
volatile int pwnc_keep_spinning = 1;

__attribute__((noinline)) void pwnc_marker_one(void) {
    pwnc_primary_cli_value ^= 0x10;
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline)) void pwnc_marker_two(void) {
    pwnc_primary_cli_value ^= 0x20;
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline)) void pwnc_marker_three(void) {
    pwnc_primary_cli_value ^= 0x40;
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline)) void pwnc_spin(void) {
    while (pwnc_keep_spinning)
        __asm__ volatile("" ::: "memory");
}

int main(void) {
    pwnc_marker_one();
    pwnc_marker_two();
    pwnc_marker_three();
    pwnc_spin();
    return (int)(pwnc_primary_cli_value & 0);
}
"""


class ProbeFailure(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _clean_terminal(data: bytes) -> bytes:
    return _ANSI.sub(b"", data).replace(b"\r", b"")


def _assert_context(data: bytes, *, cols: int, marker: bytes) -> None:
    clean = _clean_terminal(data)
    lowered = clean.lower()
    for fragment in (b"registers", b"stack", b"code", marker.lower()):
        if fragment not in lowered:
            raise ProbeFailure(
                "automatic GEF context is missing %r at width %d\n%s"
                % (fragment, cols, clean[-4000:].decode("utf-8", "replace"))
            )
    if b"-" * cols not in clean.splitlines():
        widths = sorted(
            {
                len(line)
                for line in clean.splitlines()
                if line and not line.strip(b"-")
            }
        )
        raise ProbeFailure(
            "GEF context did not contain a %d-column terminal rule; saw %r"
            % (cols, widths[-12:])
        )


def _write_fixture(directory: Path) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None:
        raise ProbeFailure("gcc is required for the primary-CLI DAP probe")
    source = directory / "primary_cli_side_dap.c"
    binary = directory / "primary_cli_side_dap"
    source.write_text(_FIXTURE_SOURCE)
    built = subprocess.run(
        [
            compiler,
            "-g",
            "-O0",
            "-fno-omit-frame-pointer",
            "-fno-pie",
            "-no-pie",
            "-o",
            os.fspath(binary),
            os.fspath(source),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if built.returncode:
        raise ProbeFailure(
            "failed to compile the primary-CLI fixture:\n"
            + built.stderr.decode("utf-8", "replace")
        )
    return binary


def _write_inputrc(directory: Path) -> Path:
    """Bind a private sequence to readline's non-clearing redraw function."""
    path = directory / "inputrc"
    path.write_text(
        "set editing-mode emacs\n"
        '"\\e[99~": redraw-current-line\n'
    )
    return path


def _bootstrap(child_socket_fd: int) -> str:
    # Keep every object globally reachable in GDB.  In particular, retaining
    # the pipe write end leaves the stock DAP output-reader asleep rather than
    # spinning on EOF.  Console and inferior output intentionally stay on the
    # primary PTY instead of being converted to DAP output events.
    return (
        "python import os,socket,gdb.dap,gdb.dap.server,gdb.dap.startup; "
        f"pwnc_side_socket=socket.socket(fileno={child_socket_fd}); "
        "pwnc_side_pipe=os.pipe(); "
        "pwnc_side_server=gdb.dap.server.Server("
        "pwnc_side_socket.makefile('rb',buffering=0),"
        "pwnc_side_socket.makefile('wb',buffering=0),"
        "os.fdopen(pwnc_side_pipe[0],'r')); "
        "gdb.dap.startup.start_dap(pwnc_side_server.main_loop)"
    )


class Harness:
    def __init__(
        self,
        gdb_path: str,
        *,
        environment: dict[str, str],
        initial_size: tuple[int, int],
    ) -> None:
        self.gdb_path = os.path.abspath(gdb_path)
        self.environment = dict(environment)
        self.initial_size = initial_size

        self.pid: int | None = None
        self.broker_fd: int | None = None
        self.viewer_fd: int | None = None
        self.socket: socket.socket | None = None
        self._pidfd: int | None = None
        self._waited = False

        self._next_seq = 1
        self._dap_input = bytearray()
        self.responses: dict[int, dict] = {}
        self.events: list[dict] = []
        self.pty_output = bytearray()
        self.socket_eof = False

    def start(self) -> None:
        parent_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        master_fd, slave_fd = os.openpty()
        rows, cols = self.initial_size
        _set_winsize(slave_fd, rows, cols)
        os.set_inheritable(child_socket.fileno(), True)

        pid = os.fork()
        if pid == 0:
            try:
                parent_socket.close()
                os.setsid()
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                for target in (0, 1, 2):
                    os.dup2(slave_fd, target)
                if slave_fd > 2:
                    os.close(slave_fd)
                os.close(master_fd)
                argv = [
                    self.gdb_path,
                    "-q",
                    "-nx",
                    "-ex",
                    _bootstrap(child_socket.fileno()),
                ]
                os.execve(self.gdb_path, argv, self.environment)
            except BaseException as error:  # pragma: no cover - child diagnostic
                try:
                    os.write(2, ("side-DAP child startup failed: %r\n" % (error,)).encode())
                finally:
                    os._exit(127)

        child_socket.close()
        os.close(slave_fd)
        self.pid = pid
        self.broker_fd = master_fd
        self.viewer_fd = os.dup(master_fd)
        self.socket = parent_socket
        self.socket.setblocking(False)
        os.set_blocking(self.viewer_fd, False)
        if hasattr(os, "pidfd_open"):
            self._pidfd = os.pidfd_open(pid)

    @property
    def alive(self) -> bool:
        if self.pid is None or self._waited:
            return False
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return False
        return True

    def request(self, command: str, arguments: dict | None = None) -> int:
        sequence = self._next_seq
        self._next_seq += 1
        message = {"seq": sequence, "type": "request", "command": command}
        if arguments is not None:
            message["arguments"] = arguments
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        frame = b"Content-Length: " + str(len(payload)).encode("ascii") + _HEADER_END + payload
        self._send_socket(frame)
        return sequence

    def _send_socket(self, data: bytes) -> None:
        if self.socket is None:
            raise ProbeFailure("DAP socket is not open")
        pending = memoryview(data)
        deadline = time.monotonic() + TIMEOUT
        while pending:
            try:
                sent = self.socket.send(pending)
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProbeFailure("timed out writing a DAP frame")
                select.select([], [self.socket], [], remaining)
                continue
            if sent <= 0:
                raise ProbeFailure("DAP socket closed during a write")
            pending = pending[sent:]

    def write_terminal(self, data: bytes) -> None:
        if self.broker_fd is None:
            raise ProbeFailure("primary PTY is not open")
        pending = memoryview(data)
        deadline = time.monotonic() + TIMEOUT
        while pending:
            try:
                written = os.write(self.broker_fd, pending)
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProbeFailure("timed out writing the primary PTY")
                select.select([], [self.broker_fd], [], remaining)
                continue
            pending = pending[written:]

    def resize(self, rows: int, cols: int) -> None:
        if self.broker_fd is None or self.pid is None:
            raise ProbeFailure("cannot resize a closed primary PTY")
        _set_winsize(self.broker_fd, rows, cols)
        # A controlling PTY normally sends this to its foreground group.  Send
        # it explicitly as well so the experiment is deterministic if a GDB
        # version temporarily changes the terminal's foreground ownership.
        os.kill(self.pid, signal.SIGWINCH)

    def detach_viewer(self) -> None:
        if self.viewer_fd is not None:
            os.close(self.viewer_fd)
            self.viewer_fd = None

    def reconnect_viewer(self) -> None:
        if self.viewer_fd is not None:
            raise ProbeFailure("viewer is already connected")
        if self.broker_fd is None:
            raise ProbeFailure("retained PTY broker is closed")
        self.viewer_fd = os.dup(self.broker_fd)
        os.set_blocking(self.viewer_fd, False)

    def _read_ready(self, timeout: float) -> bool:
        readers: list[object] = []
        if self.socket is not None and not self.socket_eof:
            readers.append(self.socket)
        if self.viewer_fd is not None:
            readers.append(self.viewer_fd)
        if not readers:
            return False
        ready, _, _ = select.select(readers, [], [], max(0.0, timeout))
        if not ready:
            return False

        for source in ready:
            if source is self.socket:
                self._read_socket()
            else:
                self._read_pty()
        return True

    def _read_socket(self) -> None:
        assert self.socket is not None
        try:
            chunk = self.socket.recv(65536)
        except BlockingIOError:
            return
        if not chunk:
            self.socket_eof = True
            return
        self._dap_input.extend(chunk)
        self._decode_messages()

    def _decode_messages(self) -> None:
        while True:
            marker = self._dap_input.find(_HEADER_END)
            if marker < 0:
                return
            header = bytes(self._dap_input[:marker]).decode("ascii", "strict")
            lengths = [
                line.split(":", 1)[1].strip()
                for line in header.split("\r\n")
                if line.lower().startswith("content-length:")
            ]
            if len(lengths) != 1:
                raise ProbeFailure("invalid DAP Content-Length header")
            length = int(lengths[0])
            if length < 0 or length > _FRAME_LIMIT:
                raise ProbeFailure("invalid DAP frame length %d" % length)
            end = marker + len(_HEADER_END) + length
            if len(self._dap_input) < end:
                return
            payload = bytes(self._dap_input[marker + len(_HEADER_END) : end])
            del self._dap_input[:end]
            message = json.loads(payload)
            kind = message.get("type")
            if kind == "response":
                self.responses[message["request_seq"]] = message
            elif kind == "event":
                self.events.append(message)
            else:
                raise ProbeFailure("unexpected DAP message: %r" % (message,))

    def _read_pty(self) -> None:
        assert self.viewer_fd is not None
        try:
            chunk = os.read(self.viewer_fd, 65536)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno == errno.EIO:
                return
            raise
        if chunk:
            self.pty_output.extend(chunk)

    def wait_for(self, predicate, label: str, timeout: float = TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                tail = _clean_terminal(bytes(self.pty_output[-4000:])).decode(
                    "utf-8", "replace"
                )
                raise ProbeFailure("timed out waiting for %s\nPTY tail:\n%s" % (label, tail))
            self._read_ready(remaining)

    def response(self, sequence: int, timeout: float = TIMEOUT) -> dict:
        self.wait_for(
            lambda: sequence in self.responses,
            "DAP response %d" % sequence,
            timeout,
        )
        response = self.responses[sequence]
        if not response.get("success"):
            raise ProbeFailure("DAP request failed: %r" % (response,))
        return response

    def evaluate(self, expression: str, timeout: float = TIMEOUT) -> str:
        sequence = self.request(
            "evaluate", {"expression": expression, "context": "repl"}
        )
        response = self.response(sequence, timeout)
        return (response.get("body") or {}).get("result", "")

    def wait_stop(
        self,
        *,
        event_start: int,
        responses: tuple[int, ...] = (),
        timeout: float = TIMEOUT,
    ) -> dict:
        redraw_sent = False

        def selected_stop() -> dict | None:
            for event in self.events[event_start:]:
                if event.get("event") == "stopped":
                    return event
            return None

        deadline = time.monotonic() + timeout
        while True:
            stop = selected_stop()
            if stop is not None and not redraw_sent:
                # This private readline binding is the only UI/control-plane
                # bridge.  The bytes queue while GDB is still running stop
                # hooks, then redraw the native prompt and live edit buffer.
                self.write_terminal(REDRAW_SEQUENCE)
                redraw_sent = True
            if stop is not None and all(item in self.responses for item in responses):
                for item in responses:
                    if not self.responses[item].get("success"):
                        raise ProbeFailure("DAP request failed: %r" % self.responses[item])
                return stop
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeFailure("timed out waiting for a structured stopped event")
            self._read_ready(remaining)

    def drain_until_quiet(self, *, timeout: float = 5.0, quiet: float = 0.25) -> None:
        deadline = time.monotonic() + timeout
        saw_data = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            ready = self._read_ready(min(quiet, remaining))
            if ready:
                saw_data = True
                continue
            if saw_data:
                return

    def wait_prompt(self, *, start: int = 0, timeout: float = TIMEOUT) -> bytes:
        def found() -> bool:
            clean = _clean_terminal(bytes(self.pty_output[start:]))
            return b"(gdb) " in clean or b"gef> " in clean or b"gef\xe2\x9e\xa4  " in clean

        self.wait_for(found, "native GDB prompt", timeout)
        self.drain_until_quiet()
        return bytes(self.pty_output[start:])

    def wait_exit(self, timeout: float = TIMEOUT) -> int:
        if self.pid is None:
            raise ProbeFailure("GDB was not started")
        if not self._waited:
            if self._pidfd is not None:
                ready, _, _ = select.select([self._pidfd], [], [], timeout)
                if not ready:
                    raise ProbeFailure("GDB did not exit within %.1fs" % timeout)
            pid, status = os.waitpid(self.pid, 0)
            if pid != self.pid:
                raise ProbeFailure("waitpid returned the wrong GDB process")
            self._waited = True
            return status
        return 0

    def close(self) -> None:
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
        self.detach_viewer()
        if self.broker_fd is not None:
            try:
                os.close(self.broker_fd)
            except OSError:
                pass
            self.broker_fd = None
        if self.pid is not None and not self._waited:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.wait_exit(3.0)
            except ProbeFailure:
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.wait_exit(3.0)
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None


def _initialize(harness: Harness) -> None:
    event_start = len(harness.events)
    sequence = harness.request(
        "initialize",
        {
            "clientID": "pwnc-primary-cli-side-dap-probe",
            "adapterID": "gdb",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "pathFormat": "path",
            "supportsVariablePaging": True,
            "supportsMemoryReferences": True,
        },
    )
    harness.response(sequence)
    harness.wait_for(
        lambda: any(
            event.get("event") == "initialized"
            for event in harness.events[event_start:]
        ),
        "DAP initialized event",
    )


def _assert_size(result: str, expected: tuple[int, int]) -> None:
    match = re.search(r"\((\d+),\s*(\d+)\)", result)
    if match is None:
        raise ProbeFailure("could not parse GEF terminal size from %r" % result)
    actual = (int(match.group(1)), int(match.group(2)))
    if actual != expected:
        raise ProbeFailure("GEF terminal size is %r, expected %r" % (actual, expected))


def _initialize_arguments(client_id: str) -> dict:
    return {
        "clientID": client_id,
        "adapterID": "gdb",
        "linesStartAt1": True,
        "columnsStartAt1": True,
        "pathFormat": "path",
    }


def _native_thread_audit(gdb_path: str, environment: dict[str, str]) -> dict:
    """Collect the baseline from GDB's real ``--interpreter=dap`` path."""
    sys.path.insert(0, os.fspath(REPOSITORY))
    try:
        from pwnc.gdb.dap.transport import DapTransport
    finally:
        try:
            sys.path.remove(os.fspath(REPOSITORY))
        except ValueError:
            pass

    transport = DapTransport(gdb_path=gdb_path, env=environment, init=False)
    try:
        transport.request(
            "initialize",
            _initialize_arguments("pwnc-native-dap-thread-audit"),
            timeout=TIMEOUT,
        )
        transport.wait_initialized(timeout=TIMEOUT)
        transport.request(
            "evaluate",
            {
                "expression": "source " + os.fspath(THREAD_AUDIT_EXTENSION),
                "context": "repl",
            },
            timeout=TIMEOUT,
        )
        return {
            "dap": transport.request("pwncDapThreadAudit", timeout=TIMEOUT),
            "main": transport.request("pwncMainThreadAudit", timeout=TIMEOUT),
        }
    finally:
        transport.close()


def _side_thread_audit(harness: Harness) -> dict:
    harness.evaluate("source " + os.fspath(THREAD_AUDIT_EXTENSION))
    dap = harness.response(harness.request("pwncDapThreadAudit")).get("body") or {}
    main = harness.response(harness.request("pwncMainThreadAudit")).get("body") or {}
    return {"dap": dap, "main": main}


def _assert_thread_parity(native: dict, side: dict) -> None:
    """Prove the bootstrap retains stock DAP's two-thread contract."""
    for label, audit in (("native", native), ("side", side)):
        dap = audit["dap"]
        main = audit["main"]
        if not dap.get("isGdbThread") or not dap.get("matchesCapturedDapThread"):
            raise ProbeFailure("%s DAP loop is not GDB's captured gdb.Thread: %r" % (label, dap))
        if dap.get("isMainThread"):
            raise ProbeFailure("%s DAP loop unexpectedly runs on GDB's main thread" % label)
        if not main.get("isMainThread") or not main.get("matchesCapturedGdbThread"):
            raise ProbeFailure("%s DAP main-thread dispatch is invalid: %r" % (label, main))
        if main.get("isGdbThread"):
            raise ProbeFailure("%s GDB main thread was misclassified as gdb.Thread" % label)
        if dap.get("pid") != main.get("pid"):
            raise ProbeFailure("%s audit crossed process boundaries" % label)
        if dap.get("ident") == main.get("ident"):
            raise ProbeFailure("%s DAP and GDB main threads have the same identity" % label)
        if main.get("gdbApiCall") != 1:
            raise ProbeFailure("%s main-thread GDB API dispatch failed: %r" % (label, main))

    common_fields = {
        "dap": (
            "class",
            "isGdbThread",
            "isMainThread",
            "matchesCapturedDapThread",
            "name",
            "signalMask",
        ),
        "main": (
            "class",
            "gdbApiCall",
            "isGdbThread",
            "isMainThread",
            "matchesCapturedGdbThread",
            "name",
            "signalMask",
        ),
    }
    for role, fields in common_fields.items():
        native_shape = {field: native[role].get(field) for field in fields}
        side_shape = {field: side[role].get(field) for field in fields}
        if side_shape != native_shape:
            raise ProbeFailure(
                "%s thread semantics differ between native and side DAP:\n"
                "native=%r\nside=%r" % (role, native_shape, side_shape)
            )


def _wait_event_body(harness: Harness, name: str, predicate, label: str) -> dict:
    selected = None

    def found() -> bool:
        nonlocal selected
        for event in harness.events:
            if event.get("event") != name:
                continue
            body = event.get("body") or {}
            if predicate(body):
                selected = body
                return True
        return False

    harness.wait_for(found, label)
    assert selected is not None
    return selected


def _run_nested_side_rpc(
    harness: Harness,
    *,
    side_thread_audit: dict,
    max_depth: int = 2,
) -> dict:
    """Exercise recursively suspended callbacks on the side-socket server."""
    harness.evaluate("source " + os.fspath(RPC_PROBE_EXTENSION))

    def operation(depth: int, parent: int | None = None) -> dict:
        started = harness.response(
            harness.request(
                "rpcProbeStart",
                {"depth": depth, "parentOperationId": parent},
            )
        ).get("body") or {}
        operation_id = int(started["operationId"])
        callback = _wait_event_body(
            harness,
            "rpcProbeCallback",
            lambda body: body.get("operationId") == operation_id,
            "nested RPC callback at depth %d" % depth,
        )
        if callback.get("method") != "probe.callback":
            raise ProbeFailure("side RPC emitted an unexpected callback: %r" % callback)

        evaluated = harness.evaluate("rpc-probe-plugin side-depth-%d" % depth)
        if "RPC_PROBE_PLUGIN side-depth-%d" % depth not in evaluated:
            raise ProbeFailure("nested side RPC could not execute a synchronous GDB command")

        if depth < max_depth:
            nested = operation(depth + 1, operation_id)
            value = {"fromDepth": depth, "nested": nested}
        else:
            value = {"fromDepth": depth, "leaf": True}

        reply = harness.response(
            harness.request(
                "rpcProbeReply",
                {
                    "operationId": operation_id,
                    "callbackId": callback["callbackId"],
                    "value": value,
                },
            )
        ).get("body") or {}
        if reply.get("status") != "resume-queued":
            raise ProbeFailure("nested side RPC reply was not queued: %r" % reply)
        done = _wait_event_body(
            harness,
            "rpcProbeDone",
            lambda body: body.get("operationId") == operation_id,
            "nested RPC completion at depth %d" % depth,
        )
        return done["result"]

    result = operation(0)
    snapshot = harness.response(harness.request("rpcProbeSnapshot")).get("body") or {}
    operations = snapshot.get("operations") or {}
    if len(operations) != max_depth + 1:
        raise ProbeFailure("nested side RPC retained the wrong operation count: %r" % operations)
    if any(item.get("status") != "done" for item in operations.values()):
        raise ProbeFailure("nested side RPC left an unfinished operation: %r" % operations)

    trace = snapshot.get("trace") or []
    dap_id = side_thread_audit["dap"]["ident"]
    main_id = side_thread_audit["main"]["ident"]
    dap_kinds = {"dap-start-accepted", "dap-reply-accepted"}
    main_kinds = {
        "operation-enter",
        "operation-before-returned",
        "callback-emitted",
        "callback-resume-dispatched",
        "operation-resumed",
        "operation-after-returned",
        "operation-done",
        "plugin-enter",
        "plugin-nested-execute",
        "plugin-return",
    }
    if not trace or not any(item.get("kind") in dap_kinds for item in trace):
        raise ProbeFailure("nested side RPC produced no DAP-thread trace")
    for item in trace:
        kind = item.get("kind")
        if kind in dap_kinds and item.get("threadId") != dap_id:
            raise ProbeFailure("side RPC DAP work escaped gdb.Thread: %r" % item)
        if kind in main_kinds and item.get("threadId") != main_id:
            raise ProbeFailure("side RPC GDB work escaped the main thread: %r" % item)

    return {
        "depth": max_depth,
        "operations": len(operations),
        "resultDepth": result.get("depth"),
        "threadPartition": True,
    }


def _run_callback_next_ret(
    harness: Harness,
    *,
    thread_id: int,
    cols: int,
) -> dict:
    """Run Bata24's execution-driving ``next-ret -n`` inside a callback."""
    started = harness.response(
        harness.request(
            "rpcProbeStart",
            {"depth": 100, "parentOperationId": None},
        )
    ).get("body") or {}
    operation_id = int(started["operationId"])
    callback = _wait_event_body(
        harness,
        "rpcProbeCallback",
        lambda body: body.get("operationId") == operation_id,
        "execution-control callback",
    )

    # This is the wire-equivalent of an ordinary pwnc host callback calling
    # gdb.execute("next-ret -n").  The untouched Bata24 command repeatedly
    # invokes synchronous ``ni`` itself, then renders context before returning.
    # It exercises substantially more re-entrancy than one DAP continue.
    internal_event_start = len(harness.events)
    next_ret_output = harness.evaluate("next-ret -n")
    # Newer GDB DAP servers defer events raised inside a request until after
    # its response.  Consume that already-queued batch before auditing it.
    harness.drain_until_quiet(timeout=8.0, quiet=0.5)
    internal_stops = [
        event
        for event in harness.events[internal_event_start:]
        if event.get("event") == "stopped"
    ]
    lowered_output = next_ret_output.lower()
    if not all(fragment in lowered_output for fragment in ("registers", "stack", "code")):
        raise ProbeFailure(
            "Bata24 next-ret did not return its context output; result=%r PTY=%r"
            % (
                next_ret_output[-4000:],
                _clean_terminal(bytes(harness.pty_output[-4000:])).decode(
                    "utf-8", "replace"
                ),
            )
        )
    instruction = harness.evaluate("x/i $pc").lower()
    if "ret" not in instruction:
        raise ProbeFailure("Bata24 next-ret did not stop on a return instruction: %r" % instruction)

    # The original callback must still own the suspended operation after the
    # stop, and normal synchronous GDB/plugin calls must remain available.
    snapshot = harness.response(harness.request("rpcProbeSnapshot")).get("body") or {}
    operation = (snapshot.get("operations") or {}).get(str(operation_id)) or {}
    if operation.get("status") != "waiting-host":
        raise ProbeFailure("continue corrupted the suspended callback state: %r" % operation)
    evaluated = harness.evaluate("rpc-probe-plugin callback-after-next-ret")
    if "RPC_PROBE_PLUGIN callback-after-next-ret" not in evaluated:
        raise ProbeFailure("callback could not use GDB after next-ret returned")

    value = {
        "internalStops": len(internal_stops),
        "nextRet": True,
    }
    reply = harness.response(
        harness.request(
            "rpcProbeReply",
            {
                "operationId": operation_id,
                "callbackId": callback["callbackId"],
                "value": value,
            },
        )
    ).get("body") or {}
    if reply.get("status") != "resume-queued":
        raise ProbeFailure("execution-control callback reply was not queued: %r" % reply)
    done = _wait_event_body(
        harness,
        "rpcProbeDone",
        lambda body: body.get("operationId") == operation_id,
        "execution-control callback completion",
    )
    result = done.get("result") or {}
    if result.get("callbackResult") != value:
        raise ProbeFailure("execution-control callback returned the wrong value: %r" % result)

    # Prove real execution and DAP event routing still work after the nested
    # instruction loop and callback resumption have both unwound.  Slice from
    # the current event index so next-ret's intentional intermediate stops
    # cannot be mistaken for this new stop.
    output_start = len(harness.pty_output)
    event_start = len(harness.events)
    continued = harness.request("continue", {"threadId": thread_id})
    stop = harness.wait_stop(event_start=event_start, responses=(continued,))
    harness.drain_until_quiet(timeout=8.0, quiet=0.5)
    output = bytes(harness.pty_output[output_start:])
    _assert_context(output, cols=cols, marker=b"pwnc_marker_two")
    if (stop.get("body") or {}).get("reason") != "breakpoint":
        raise ProbeFailure("post-callback continue produced an unexpected stop: %r" % stop)
    harness.wait_prompt(start=output_start)

    threads = harness.response(harness.request("threads")).get("body") or {}
    if not threads.get("threads"):
        raise ProbeFailure("DAP became unusable after callback-driven continue")
    return {
        "context": True,
        "internalStops": len(internal_stops),
        "nextRet": True,
        "operationResumed": True,
        "postCallbackRequest": True,
        "postCommandContinue": True,
    }


def run_probe(gdb_path: str, gef_path: Path = DEFAULT_GEF) -> dict:
    gdb = shutil.which(gdb_path) if os.path.sep not in gdb_path else gdb_path
    if gdb is None or not os.access(gdb, os.X_OK):
        raise ProbeFailure("GDB is not executable: %s" % gdb_path)
    gef_path = gef_path.resolve()
    if not gef_path.is_file():
        raise ProbeFailure("bata24 GEF is required: %s" % gef_path)
    digest_before = _sha256(gef_path)
    if digest_before != EXPECTED_GEF_SHA256:
        raise ProbeFailure(
            "unexpected bata24 GEF SHA-256: %s (expected %s)"
            % (digest_before, EXPECTED_GEF_SHA256)
        )

    with tempfile.TemporaryDirectory(prefix="pwnc-primary-cli-dap-") as temporary:
        directory = Path(temporary)
        binary = _write_fixture(directory)
        inputrc = _write_inputrc(directory)
        environment = dict(os.environ)
        environment.update(
            {
                "HOME": os.fspath(directory),
                "INPUTRC": os.fspath(inputrc),
                "TMPDIR": os.fspath(directory),
                "TERM": "xterm-256color",
            }
        )
        native_thread_audit = _native_thread_audit(os.fspath(gdb), environment)

        harness = Harness(
            os.fspath(gdb),
            environment=environment,
            initial_size=INITIAL_SIZE,
        )
        process_exited = False
        try:
            harness.start()
            harness.wait_prompt()
            _initialize(harness)
            side_thread_audit = _side_thread_audit(harness)
            _assert_thread_parity(native_thread_audit, side_thread_audit)
            nested_callbacks = _run_nested_side_rpc(
                harness,
                side_thread_audit=side_thread_audit,
            )

            harness.evaluate("set pagination off")
            harness.evaluate("set confirm off")
            harness.evaluate("source " + os.fspath(gef_path))
            version = harness.evaluate("show version").splitlines()[0]
            gef_version = harness.evaluate("gef version")
            if "GEF" not in gef_version.upper():
                raise ProbeFailure("native GDB did not execute the sourced GEF command")

            _assert_size(
                harness.evaluate("python print(GefUtil.get_terminal_size())"),
                INITIAL_SIZE,
            )
            harness.resize(*FIRST_STOP_SIZE)
            _assert_size(
                harness.evaluate("python print(GefUtil.get_terminal_size())"),
                FIRST_STOP_SIZE,
            )
            harness.drain_until_quiet()

            # Leave a live readline edit buffer in place.  The DAP launch is
            # intentionally concurrent with it, and the redraw sequence must
            # restore this exact text after automatic context finishes.
            harness.write_terminal(PARTIAL_COMMAND)
            harness.drain_until_quiet()
            launch_output_start = len(harness.pty_output)
            launch_event_start = len(harness.events)
            launch = harness.request(
                "launch",
                {
                    "program": os.fspath(binary),
                    "stopAtBeginningOfMainSubprogram": True,
                },
            )
            configured = harness.request("configurationDone")
            launch_stop = harness.wait_stop(
                event_start=launch_event_start,
                responses=(launch, configured),
            )
            harness.drain_until_quiet(timeout=8.0, quiet=0.5)
            launch_output = bytes(harness.pty_output[launch_output_start:])
            _assert_context(
                launch_output,
                cols=FIRST_STOP_SIZE[1],
                marker=b"main",
            )
            clean_launch = _clean_terminal(launch_output)
            final_rule = clean_launch.rfind(b"-" * FIRST_STOP_SIZE[1])
            final_partial = clean_launch.rfind(PARTIAL_COMMAND)
            if final_partial <= final_rule:
                raise ProbeFailure(
                    "readline did not redraw the partial command after DAP-driven context"
                )
            # GDB 14/15 report the temporary stop-at-main breakpoint as
            # "breakpoint"; GDB 16/17 report the same hitBreakpointIds=[-1]
            # stop as the generic "stopped" reason.
            if (launch_stop.get("body") or {}).get("reason") not in {
                "breakpoint",
                "stopped",
            }:
                raise ProbeFailure("unexpected initial stop: %r" % launch_stop)

            # Clear the preserved edit buffer without submitting it.
            harness.write_terminal(b"\x15")
            harness.drain_until_quiet()

            threads_response = harness.response(harness.request("threads"))
            threads = (threads_response.get("body") or {}).get("threads") or []
            if not threads:
                raise ProbeFailure("structured DAP threads returned no live thread")
            thread_id = threads[0]["id"]
            stack_response = harness.response(
                harness.request(
                    "stackTrace",
                    {"threadId": thread_id, "startFrame": 0, "levels": 1},
                )
            )
            frames = (stack_response.get("body") or {}).get("stackFrames") or []
            if not frames:
                raise ProbeFailure("structured DAP stackTrace returned no frame")
            memory_reference = frames[0].get("instructionPointerReference")
            if not memory_reference:
                raise ProbeFailure("top DAP frame has no instructionPointerReference")
            memory_response = harness.response(
                harness.request(
                    "readMemory",
                    {"memoryReference": memory_reference, "offset": 0, "count": 8},
                )
            )
            memory = base64.b64decode((memory_response.get("body") or {}).get("data", ""))
            if len(memory) != 8:
                raise ProbeFailure("structured DAP readMemory returned %d bytes" % len(memory))

            harness.evaluate("break pwnc_marker_one")
            harness.evaluate("break pwnc_marker_two")
            harness.evaluate("break pwnc_marker_three")
            harness.resize(*SECOND_STOP_SIZE)
            _assert_size(
                harness.evaluate("python print(GefUtil.get_terminal_size())"),
                SECOND_STOP_SIZE,
            )
            harness.drain_until_quiet()

            dap_output_start = len(harness.pty_output)
            dap_event_start = len(harness.events)
            continued = harness.request("continue", {"threadId": thread_id})
            dap_stop = harness.wait_stop(
                event_start=dap_event_start,
                responses=(continued,),
            )
            harness.drain_until_quiet(timeout=8.0, quiet=0.5)
            dap_output = bytes(harness.pty_output[dap_output_start:])
            _assert_context(
                dap_output,
                cols=SECOND_STOP_SIZE[1],
                marker=b"pwnc_marker_one",
            )
            if (dap_stop.get("body") or {}).get("reason") != "breakpoint":
                raise ProbeFailure("unexpected DAP-driven stop: %r" % dap_stop)
            harness.wait_prompt(start=dap_output_start)

            callback_next_ret = _run_callback_next_ret(
                harness,
                thread_id=thread_id,
                cols=SECOND_STOP_SIZE[1],
            )

            cli_output_start = len(harness.pty_output)
            cli_event_start = len(harness.events)
            harness.write_terminal(b"continue\n")
            cli_stop = harness.wait_stop(event_start=cli_event_start)
            harness.drain_until_quiet(timeout=8.0, quiet=0.5)
            cli_output = bytes(harness.pty_output[cli_output_start:])
            _assert_context(
                cli_output,
                cols=SECOND_STOP_SIZE[1],
                marker=b"pwnc_marker_three",
            )
            if (cli_stop.get("body") or {}).get("reason") != "breakpoint":
                raise ProbeFailure("unexpected CLI-driven stop: %r" % cli_stop)
            harness.wait_prompt(start=cli_output_start)

            native_gef_start = len(harness.pty_output)
            harness.write_terminal(b"gef version\n")
            native_gef = harness.wait_prompt(start=native_gef_start)
            if b"GEF" not in _clean_terminal(native_gef).upper():
                raise ProbeFailure("native readline did not execute a GEF command")

            # Stock DAP continue is initiated on its gdb.Thread and posts the
            # actual resume to GDB's main thread.  Pause then crosses the same
            # boundary in the other direction and must interrupt a live
            # inferior rather than waiting for it to stop by itself.
            pause_output_start = len(harness.pty_output)
            pause_event_start = len(harness.events)
            spin_continue = harness.request("continue", {"threadId": thread_id})
            harness.response(spin_continue)
            # Stock GDB DAP intentionally suppresses the continued event for
            # this request.  Queue pause immediately after the continue
            # response instead: if foreground execution entered GDB's nested
            # event loop, the main thread can service this later posted event;
            # if it did not, this request will time out behind continue.
            paused = harness.request("pause", {"threadId": thread_id})
            pause_stop = harness.wait_stop(
                event_start=pause_event_start,
                responses=(paused,),
            )
            harness.drain_until_quiet(timeout=8.0, quiet=0.5)
            pause_output = bytes(harness.pty_output[pause_output_start:])
            _assert_context(
                pause_output,
                cols=SECOND_STOP_SIZE[1],
                marker=b"pwnc_spin",
            )
            if (pause_stop.get("body") or {}).get("reason") != "pause":
                raise ProbeFailure("DAP pause produced an unexpected stop: %r" % pause_stop)
            harness.wait_prompt(start=pause_output_start)

            # A viewer owns only a duplicate/relay connection.  Dropping it
            # must leave the broker's PTY master, GDB, DAP, and pending output
            # alive for a later viewer.
            harness.detach_viewer()
            if not harness.alive:
                raise ProbeFailure("GDB died when the terminal viewer detached")
            harness.evaluate(
                "python import os; os.write(1, %r)" % (DETACHED_OUTPUT + b"\n",)
            )
            if not harness.alive:
                raise ProbeFailure("GDB died while its viewer was detached")
            reconnect_start = len(harness.pty_output)
            harness.reconnect_viewer()
            harness.wait_for(
                lambda: DETACHED_OUTPUT in harness.pty_output[reconnect_start:],
                "retained PTY backlog after viewer reconnect",
            )
            harness.drain_until_quiet()
            if not harness.evaluate("show version").strip():
                raise ProbeFailure("DAP stopped responding after viewer reconnect")

            disconnect = harness.request(
                "disconnect", {"terminateDebuggee": True}
            )
            harness.response(disconnect)
            harness.wait_exit()
            process_exited = True
        finally:
            harness.close()

    digest_after = _sha256(gef_path)
    if digest_after != digest_before:
        raise ProbeFailure("bata24 GEF changed during the probe")

    return {
        "automaticCliContext": True,
        "automaticDapContext": True,
        "callbackNextRet": callback_next_ret,
        "dapSideSocket": True,
        "gefPath": os.fspath(gef_path),
        "gefSha256": digest_after,
        "gdbVersion": version,
        "initialSize": list(INITIAL_SIZE),
        "nativeGefCli": True,
        "nestedCallbacks": nested_callbacks,
        "newUi": False,
        "partialReadlineRedraw": True,
        "primaryCli": True,
        "processExited": process_exited,
        "resizedStops": [list(FIRST_STOP_SIZE), list(SECOND_STOP_SIZE)],
        "structuredDap": ["threads", "stackTrace", "readMemory", "continue", "pause"],
        "threadParity": {
            "dapClass": side_thread_audit["dap"]["class"],
            "dapSignalMask": side_thread_audit["dap"]["signalMask"],
            "mainClass": side_thread_audit["main"]["class"],
            "mainDispatch": True,
            "nativeMatchesSide": True,
        },
        "viewerReconnect": True,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="test native primary GDB CLI with stock DAP on a private side socket"
    )
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--gef", type=Path, default=DEFAULT_GEF)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = run_probe(args.gdb, args.gef)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("PASS primary CLI + side-socket stock DAP")
        for key in sorted(result):
            print("%s: %s" % (key, result[key]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
