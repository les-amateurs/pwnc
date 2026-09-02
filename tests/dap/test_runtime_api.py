"""Live coverage for the ergonomic GDB runtime, history, and viewer boundary."""

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from payloads import ChainWord, Payload, PayloadKind, ROPChain, resolve_target
from pwnc.gdb.dap import VerificationError, ViewerConnectionError, launch


TIMEOUT = 20.0
GEF_PATH = Path("/home/ctf/bata24-gef/gef.py")
GEF_SHA256 = "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"

SOURCE = r"""
#include <stdlib.h>

struct Point { int x; int y; };
struct Point point = { 10, 20 };
char placement[128];
volatile void *allocation;

__attribute__((noinline)) void marker(int phase) {
    volatile int scoped = phase + point.x;
    __asm__ volatile("" : "+r"(scoped) :: "memory");
}

int main(int argc, char **argv) {
    allocation = malloc(0x90);
    marker(1);
    free((void *)allocation);
    marker(2);
    allocation = malloc(0x90);
    marker(3);
    return argc == 123 ? argv[0][0] : 0;
}
"""


def _build_runtime(root: Path, *, pie: bool) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None or shutil.which("gdb") is None:
        pytest.skip("gcc and GDB DAP are required")
    source = root / "runtime.c"
    binary = root / ("runtime-pie" if pie else "runtime")
    source.write_text(SOURCE, encoding="utf-8")
    link_flags = ["-fPIE", "-pie"] if pie else ["-fno-pie", "-no-pie"]
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-g3",
            "-O0",
            "-fno-omit-frame-pointer",
            *link_flags,
            "-o",
            binary,
            source,
        ],
        check=True,
        capture_output=True,
        timeout=TIMEOUT,
    )
    return binary


@pytest.fixture(scope="module")
def runtime_binary(tmp_path_factory) -> Path:
    return _build_runtime(tmp_path_factory.mktemp("runtime-api"), pie=False)


@pytest.fixture(scope="module")
def runtime_pie_binary(tmp_path_factory) -> Path:
    return _build_runtime(tmp_path_factory.mktemp("runtime-api-pie"), pie=True)


def test_runtime_facts_marks_snapshots_and_verification(runtime_binary: Path) -> None:
    gdb = launch(runtime_binary, init=False)
    try:
        assert gdb.arch.arch.value == "x86_64"
        assert gdb.main is not None and gdb.main.build_id
        assert gdb.libc is not None and gdb.loader is not None
        assert gdb.main.sym.point == int(gdb.sym.point.ref())
        assert gdb.maps.require(gdb.reg.rip).executable
        assert gdb.modules.at(gdb.reg.rip) == gdb.main

        facts = gdb.thread_facts(frames=4, libc=True)
        assert facts.top is not None and facts.top.name == "main"
        assert facts.reg.rip == gdb.reg.rip
        assert {value.name for value in facts.top.arguments} >= {"argc", "argv"}
        assert facts.libc.tls is not None

        point = gdb.memory.capture(gdb.main.sym.point, "struct Point")
        assert (int(point.value.x), int(point.value.y)) == (10, 20)
        mark = gdb.mark(point.value, label="point")
        assert mark.kind.value == "typed"
        before = gdb.snapshot("before", frames=2, libc=False)
        gdb.memory.view(gdb.main.sym.point, "struct Point").x = 0x1234
        after = gdb.snapshot("after", frames=2, libc=False)
        difference = before.diff(after)
        assert difference.changed
        assert difference.marks_changed[0].bytes[0].offset == 0
        assert difference.marks_changed[0].typed_fields["x"].before["value"] == 10
        assert difference.marks_changed[0].typed_fields["x"].after["value"] == 0x1234
        captured_point = after.marks[0]
        assert {field.path for field in captured_point.typed_fields} == {"x", "y"}
        assert any(event.kind == "memory-write" for event in gdb.history.events)

        payload = Payload(b"DATA", resolve_target("amd64"), PayloadKind.DATA, "annotated data")
        payload_mark = gdb.memory.place(gdb.main.sym.placement, payload)
        assert payload_mark.payload.description == "annotated data"
        assert gdb.verify.mark(payload_mark).require().ok
        gdb.write(gdb.main.sym.placement, b"FAIL")
        failed = gdb.verify.mark(payload_mark)
        assert not failed.ok
        assert gdb.history.events[-1].kind == "verification-failed"
        with pytest.raises(VerificationError):
            failed.require()

        chain = ROPChain(
            resolve_target("amd64"),
            (ChainWord(gdb.main.sym.marker, "marker target"),),
            "annotated chain",
        )
        chain_mark = gdb.write(gdb.main.sym.placement + 16, chain)
        assert chain_mark.payload.spans[0].role == "marker target"
        assert gdb.verify.base("main", gdb.main.load_bias).ok
        assert gdb.verify.symbol("libc", "system", gdb.libc.sym.system).ok
        assert gdb.verify.typed(gdb.main.sym.point, "struct Point", {"x": 0x1234, "y": 20}).ok

        assert not gdb.heap.available
        assert gdb.heap.try_chunk(gdb.main.sym.point) is None
        unavailable_heap = gdb.snapshot(
            "without-bata24", modules=False, maps=False, threads=False, marks=False, heap=True
        )
        assert "heap:arenas" in unavailable_heap.errors
        with pytest.raises(ViewerConnectionError):
            gdb.viewer.open(executable="/definitely/not/a/pwnc-runtime-viewer", capture=False)
        assert not gdb.viewer.connected
    finally:
        gdb.close()


def test_pie_module_identity_and_relocation(runtime_pie_binary: Path) -> None:
    gdb = launch(runtime_pie_binary, init=False)
    try:
        main = gdb.main
        assert main is not None and main.build_id
        assert main.load_bias not in {None, 0}
        assert main.sym.point == int(gdb.sym.point.ref())
        assert gdb.modules.at(main.sym.main) == main
        assert gdb.maps.require(main.sym.main).executable
        snapshot = gdb.snapshot("pie", threads=False)
        captured_main = next(module for module in snapshot.modules if module.kind == "main")
        assert captured_main.load_bias == main.load_bias
        assert captured_main.build_id == main.build_id
    finally:
        gdb.close()


def test_structured_bata_heap_tracks_reuse_generation(runtime_binary: Path, tmp_path: Path) -> None:
    if not GEF_PATH.is_file() or hashlib.sha256(GEF_PATH.read_bytes()).hexdigest() != GEF_SHA256:
        pytest.skip("the exact unmodified bata24 fixture is unavailable")
    environment = os.environ.copy()
    environment["HOME"] = os.fspath(tmp_path)
    environment.setdefault("TERM", "xterm")
    gdb = launch(runtime_binary, init=False, env=environment)
    try:
        gdb.execute("source " + os.fspath(GEF_PATH), timeout=TIMEOUT)
        gdb.runtime.refresh()
        assert gdb.runtime.to_json()["bata24"]["adapter"] == "bata24-direct-v1"
        assert gdb.heap.available
        gdb.bp("marker")

        assert gdb.cont(timeout=TIMEOUT)["reason"] == "breakpoint"
        first_pointer = int(gdb.sym.allocation)
        first = gdb.heap.chunk(first_pointer)
        assert first.state == "allocated" and first.generation == 0
        marked = first.mark("victim")
        assert marked.allocation_id == first.allocation_id
        allocated_snapshot = gdb.snapshot(
            "heap-allocated", modules=False, maps=False, threads=False, marks=[marked], heap=True
        )

        assert gdb.cont(timeout=TIMEOUT)["reason"] == "breakpoint"
        freed = gdb.heap.chunk(first_pointer)
        assert freed.free and freed.generation == 0
        freed_snapshot = gdb.snapshot(
            "heap-freed", modules=False, maps=False, threads=False, marks=[marked], heap=True
        )
        freed_diff = allocated_snapshot.diff(freed_snapshot)
        assert freed_diff.heap_chunks_changed[0].fields["state"].after == freed.state

        assert gdb.cont(timeout=TIMEOUT)["reason"] == "breakpoint"
        reused_pointer = int(gdb.sym.allocation)
        reused = gdb.heap.chunk(reused_pointer)
        if reused.base == first.base:
            assert reused.generation == 1
            assert reused.allocation_id != first.allocation_id
            reused_snapshot = gdb.snapshot(
                "heap-reused", modules=False, maps=False, threads=False, marks=[marked], heap=True
            )
            reused_diff = freed_snapshot.diff(reused_snapshot)
            assert reused_diff.heap_chunks_removed[0].allocation_id == first.allocation_id
            assert reused_diff.heap_chunks_added[0].allocation_id == reused.allocation_id
        event_kinds = {event.kind for event in gdb.history.events}
        assert {"heap-allocation", "heap-free"} <= event_kinds
    finally:
        gdb.close()


def test_json_publisher_is_event_driven_and_bounded(runtime_binary: Path, tmp_path: Path) -> None:
    path = os.fspath(tmp_path / "viewer.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen()
    received = []
    done = threading.Event()

    def receive() -> None:
        connection, _ = listener.accept()
        buffer = b""
        try:
            while len(received) < 4:
                chunk = connection.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    received.append(json.loads(line))
        finally:
            connection.close()
            done.set()

    receiver = threading.Thread(target=receive)
    receiver.start()
    gdb = launch(runtime_binary, init=False)
    try:
        assert not gdb.viewer.connected and gdb.viewer.stats.queued == 0
        gdb.viewer.connect(path, capture=False)
        gdb.mark(gdb.main.sym.point, 8, "point")
        gdb.snapshot("ipc", threads=False)
        assert done.wait(TIMEOUT)
        assert [message["type"] for message in received] == ["hello", "event", "event", "snapshot"]
        snapshot = received[-1]["snapshot"]
        assert snapshot["name"] == "ipc" and snapshot["marks"][0]["label"] == "point"
        assert gdb.viewer.stats.sent_messages == 4
        schema_path = Path(__file__).parents[2] / "native" / "runtime_viewer" / "protocol-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["properties"]["version"]["const"] == 1
        try:
            import jsonschema
        except ImportError:
            pass
        else:
            jsonschema.Draft202012Validator.check_schema(schema)
            for message in received:
                jsonschema.validate(message, schema)
    finally:
        gdb.close()
        listener.close()
        receiver.join(TIMEOUT)


def test_reconnect_announces_before_queued_runtime_data(runtime_binary: Path, tmp_path: Path) -> None:
    path = os.fspath(tmp_path / "viewer-reconnect-order.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen()
    first_messages = []
    received = (threading.Event(), threading.Event())

    def receive() -> None:
        for index in range(2):
            connection, _ = listener.accept()
            buffer = b""
            try:
                while b"\n" not in buffer:
                    chunk = connection.recv(65536)
                    if not chunk:
                        return
                    buffer += chunk
                line, _remainder = buffer.split(b"\n", 1)
                first_messages.append(json.loads(line))
                received[index].set()
                if index == 0:
                    while connection.recv(65536):
                        pass
            finally:
                connection.close()

    receiver = threading.Thread(target=receive)
    receiver.start()
    gdb = launch(runtime_binary, init=False)
    try:
        gdb.viewer.connect(path, capture=False)
        assert received[0].wait(TIMEOUT)
        gdb.viewer.disconnect()
        gdb.snapshot("queued-while-disconnected", threads=False)
        gdb.viewer.reconnect(capture=False)
        assert received[1].wait(TIMEOUT)
        assert [message["type"] for message in first_messages] == ["hello", "hello"]
        assert {message["session_id"] for message in first_messages} == {gdb.viewer.session_id}
    finally:
        gdb.close()
        listener.close()
        receiver.join(TIMEOUT)


def test_snapshots_reach_the_native_multi_session_model(runtime_binary: Path, tmp_path: Path) -> None:
    viewer = Path(__file__).parents[2] / "native" / "runtime_viewer" / "build" / "pwnc-runtime-viewer"
    second_binary = Path(__file__).parents[2] / "pwnc" / "gdb" / "mi" / "examples" / "target"
    if not os.access(viewer, os.X_OK) or not second_binary.is_file():
        pytest.skip("build native/runtime_viewer before running its end-to-end lane")
    socket_path = tmp_path / "native-viewer.sock"
    model_path = tmp_path / "native-model.json"
    ready_read, ready_write = os.pipe()
    process = subprocess.Popen(
        [
            viewer,
            "--headless",
            "--socket",
            socket_path,
            "--ready-fd",
            str(ready_write),
            "--exit-after-snapshots",
            "3",
            "--model-out",
            model_path,
        ],
        pass_fds=(ready_write,),
    )
    os.close(ready_write)
    sessions = []
    try:
        assert select.select([ready_read], [], [], TIMEOUT)[0]
        assert os.read(ready_read, 1) == b"R"
        for index, binary in enumerate((runtime_binary, second_binary)):
            gdb = launch(binary, init=False)
            sessions.append(gdb)
            gdb.viewer.connect(socket_path, capture=False)
            gdb.mark(gdb.reg.rip, 1, f"pc-{index}")
            if index == 0:
                point = gdb.memory.capture(gdb.main.sym.point, "struct Point")
                gdb.mark(point.value, label="native-point")
                gdb.memory.place(
                    gdb.main.sym.placement,
                    Payload(b"VIEW", resolve_target("amd64"), PayloadKind.DATA, "native payload"),
                )
                gdb.snapshot("native-0-before", threads=False)
                gdb.memory.view(gdb.main.sym.point, "struct Point").x = 0xBEEF
                gdb.snapshot("native-0-after", threads=False)
            else:
                gdb.snapshot("native-1", threads=False)
        assert process.wait(TIMEOUT) == 0
        model = json.loads(model_path.read_text(encoding="utf-8"))
        assert len(model["sessions"]) == 2
        assert len({item["info"]["main"]["build_id"] for item in model["sessions"]}) == 2
        rich_session = next(item for item in model["sessions"] if len(item["snapshots"]) == 2)
        assert [snapshot["name"] for snapshot in rich_session["snapshots"]] == [
            "native-0-before",
            "native-0-after",
        ]
        latest_marks = rich_session["snapshots"][1]["marks"]
        typed_mark = next(mark for mark in latest_marks if mark["kind"] == "typed")
        assert typed_mark["type"].startswith("struct Point")
        assert {field["path"] for field in typed_mark["typed_fields"]} == {"x", "y"}
        assert any(mark["payload"] and mark["payload"]["description"] == "native payload" for mark in latest_marks)
        assert rich_session["diffs"][1]["changed"] is True
        assert rich_session["diffs"][1]["marks"]["changed"]
    finally:
        os.close(ready_read)
        for gdb in sessions:
            gdb.close()
        if process.poll() is None:
            process.terminate()
            process.wait(TIMEOUT)


def test_native_viewer_reconnect_retains_unique_snapshots(runtime_binary: Path, tmp_path: Path) -> None:
    viewer = Path(__file__).parents[2] / "native" / "runtime_viewer" / "build" / "pwnc-runtime-viewer"
    if not os.access(viewer, os.X_OK):
        pytest.skip("build native/runtime_viewer before running its reconnect lane")
    socket_path = tmp_path / "reconnect-viewer.sock"
    model_path = tmp_path / "reconnect-model.json"
    ready_read, ready_write = os.pipe()
    process = subprocess.Popen(
        [
            viewer,
            "--headless",
            "--socket",
            socket_path,
            "--ready-fd",
            str(ready_write),
            "--exit-after-snapshots",
            "2",
            "--model-out",
            model_path,
        ],
        pass_fds=(ready_write,),
    )
    os.close(ready_write)
    gdb = None
    try:
        assert select.select([ready_read], [], [], TIMEOUT)[0]
        assert os.read(ready_read, 1) == b"R"
        gdb = launch(runtime_binary, init=False)
        session_id = gdb.viewer.session_id
        gdb.viewer.connect(socket_path, capture=False)
        gdb.snapshot("before-reconnect", threads=False)
        gdb.viewer.disconnect()
        gdb.viewer.reconnect(capture=False)
        gdb.snapshot("after-reconnect", threads=False)
        assert process.wait(TIMEOUT) == 0
        model = json.loads(model_path.read_text(encoding="utf-8"))
        assert len(model["sessions"]) == 1
        session = model["sessions"][0]
        assert session["id"] == session_id
        assert [snapshot["name"] for snapshot in session["snapshots"]] == [
            "before-reconnect",
            "after-reconnect",
        ]
    finally:
        os.close(ready_read)
        if gdb is not None:
            gdb.close()
        if process.poll() is None:
            process.terminate()
            process.wait(TIMEOUT)
