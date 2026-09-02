from __future__ import annotations

import errno
import fcntl
import os
import selectors
import shutil
import signal
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from pwnc.sandbox._shim import (
    CommandKind,
    ErrorFlags,
    ErrorStage,
    EventKind,
    ExitFlags,
    ReadyFlags,
    ShimListener,
    build_shim,
    shim_argv,
)

TIMEOUT = 10.0


def _zig_target() -> str:
    machine = os.uname().machine.lower()
    targets = {
        "x86_64": "x86_64-linux-musl",
        "amd64": "x86_64-linux-musl",
        "aarch64": "aarch64-linux-musl",
        "arm64": "aarch64-linux-musl",
        "i386": "x86-linux-musl",
        "i486": "x86-linux-musl",
        "i586": "x86-linux-musl",
        "i686": "x86-linux-musl",
        "riscv64": "riscv64-linux-musl",
        "ppc64le": "powerpc64le-linux-musl",
    }
    try:
        return targets[machine]
    except KeyError:
        pytest.skip(f"no Zig fixture target for {machine}")


def _compile_c(tmp_path: Path, name: str, source: str) -> Path:
    zig = shutil.which("zig")
    if zig is None:
        pytest.skip("zig is required for native shim tests")
    output = tmp_path / name
    result = subprocess.run(
        [zig, "cc", "-target", _zig_target(), "-static", "-O2", "-std=c11", "-x", "c", "-o", output, "-"],
        input=source,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return output


def _wait_process(process: subprocess.Popen, timeout: float = TIMEOUT) -> int:
    if not hasattr(os, "pidfd_open"):
        return process.wait(timeout=timeout)
    descriptor = os.pidfd_open(process.pid)
    selector = selectors.DefaultSelector()
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        assert selector.select(timeout), f"process {process.pid} did not exit"
    finally:
        selector.close()
        os.close(descriptor)
    return process.wait()


def _close_process_pipes(process: subprocess.Popen) -> None:
    seen: set[int] = set()
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is None or id(stream) in seen:
            continue
        seen.add(id(stream))
        try:
            stream.close()
        except OSError:
            pass


def _next(connection, expected: EventKind):
    event = connection.recv(TIMEOUT)
    assert event.kind is expected, event
    return event


def _preexec_handshake(connection) -> None:
    hello = _next(connection, EventKind.HELLO)
    assert hello.pid == 0
    assert hello.value == 0
    assert hello.detail == 0
    assert hello.flags == 0
    assert hello.pidfd is None
    peer_pid, peer_uid, peer_gid = connection.peer_credentials()
    assert peer_pid > 0
    assert peer_uid >= 0
    assert peer_gid >= 0
    connection.acknowledge_hello()


def _status_fields(pid: int) -> dict[str, str]:
    result = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        name, separator, value = line.partition(":")
        if separator:
            result[name] = value.strip()
    return result


def _elf_entry(path: Path) -> int:
    header = path.read_bytes()[:64]
    assert header[:4] == b"\x7fELF"
    word_size = {1: 4, 2: 8}[header[4]]
    byteorder = {1: "little", 2: "big"}[header[5]]
    assert int.from_bytes(header[16:18], byteorder) == 2, "entry-point fixture must be ET_EXEC"
    return int.from_bytes(header[24 : 24 + word_size], byteorder)


def _kill_and_reap(connection, process: subprocess.Popen) -> None:
    connection.kill()
    acknowledgement = _next(connection, EventKind.ACK)
    assert acknowledgement.value == CommandKind.KILL
    assert acknowledgement.detail == signal.SIGKILL
    exited = _next(connection, EventKind.EXIT)
    assert exited.flags & ExitFlags.SIGNAL
    assert exited.value == signal.SIGKILL
    assert _wait_process(process) == 128 + signal.SIGKILL


@pytest.fixture
def shim(tmp_path: Path) -> Path:
    return build_shim(cache_root=tmp_path / "cache")


def test_build_is_content_addressed_static_and_executable(tmp_path: Path) -> None:
    first = build_shim(cache_root=tmp_path / "cache")
    second = build_shim(cache_root=tmp_path / "cache")
    assert first == second
    assert first.stat().st_ino == second.stat().st_ino
    assert first.read_bytes().startswith(b"\x7fELF")
    assert os.access(first, os.X_OK)

    # A static executable has no PT_INTERP entry.  ``readelf`` is preferable
    # to ``ldd`` here because ldd may execute an untrusted dynamic loader.
    readelf = shutil.which("readelf")
    if readelf is not None:
        headers = subprocess.run([readelf, "-lW", first], capture_output=True, text=True, check=True).stdout
        assert "INTERP" not in headers


def test_hello_ack_is_required_before_nonpaused_target_can_exec(tmp_path: Path, shim: Path) -> None:
    marker = tmp_path / "must-not-exist"
    target = _compile_c(
        tmp_path,
        "preexec-gate-target",
        r"""
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static void marker(void) __attribute__((constructor));
static void marker(void) {
    const char *path = getenv("PWNC_PREEXEC_MARKER");
    if (path != NULL) {
        int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (descriptor >= 0) close(descriptor);
    }
}

int main(void) { return 0; }
""",
    )
    environment = dict(os.environ)
    environment["PWNC_PREEXEC_MARKER"] = os.fspath(marker)
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(listener.path, target, pause=False, shim=shim),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                hello = _next(connection, EventKind.HELLO)
                assert hello.pid == 0
                assert not marker.exists()
                # Closing without HELLO_ACK makes the trusted shim fail closed;
                # it never forks or executes the challenge.
            assert _wait_process(process) == 125
            assert not marker.exists()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def test_paused_ready_precedes_constructor_and_commands_reap(tmp_path: Path, shim: Path) -> None:
    target = _compile_c(
        tmp_path,
        "constructor-marker",
        r"""
#include <stdlib.h>
#include <unistd.h>

static void marker(void) __attribute__((constructor));
static void marker(void) {
    const char *text = getenv("PWNC_MARKER_FD");
    if (text != 0) {
        int descriptor = atoi(text);
        (void)write(descriptor, "C", 1);
    }
}

int main(void) { return 23; }
""",
    )
    marker_read, marker_write = os.pipe()
    listener_path = tmp_path / "control.sock"
    with ShimListener(listener_path) as listener:
        environment = dict(os.environ)
        environment["PWNC_MARKER_FD"] = str(marker_write)
        process = subprocess.Popen(
            shim_argv(listener.path, target, pause=True, shim=shim),
            env=environment,
            pass_fds=(marker_write,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(marker_write)
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                ready = _next(connection, EventKind.READY)
                assert ready.flags & ReadyFlags.PAUSED
                assert ready.flags & ReadyFlags.PIDFD
                assert connection.host_pid == ready.pid

                selector = selectors.DefaultSelector()
                try:
                    selector.register(marker_read, selectors.EVENT_READ)
                    assert not selector.select(0), "constructor ran before READY"
                    connection.continue_()
                    acknowledgement = _next(connection, EventKind.ACK)
                    assert acknowledgement.value == CommandKind.CONTINUE
                    assert acknowledgement.detail == signal.SIGCONT
                    assert selector.select(TIMEOUT), "constructor did not run after CONTINUE"
                finally:
                    selector.close()
                assert os.read(marker_read, 1) == b"C"

                exited = _next(connection, EventKind.EXIT)
                assert exited.flags & ExitFlags.NORMAL
                assert exited.value == 23
                assert exited.returncode == 23
            assert _wait_process(process) == 23
            assert process.stderr.read() == b""
        finally:
            os.close(marker_read)
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def test_ready_target_is_unprivileged_no_new_privs_and_allows_unrelated_ptrace(tmp_path: Path, shim: Path) -> None:
    target = _compile_c(
        tmp_path,
        "parked-target",
        r"""
#include <signal.h>
#include <unistd.h>
int main(void) { for (;;) pause(); }
""",
    )
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(listener.path, target, pause=True, shim=shim),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                _next(connection, EventKind.READY)
                host_pid = connection.host_pid
                assert host_pid is not None
                fields = _status_fields(host_pid)
                assert fields["CapInh"] == "0000000000000000"
                assert fields["CapPrm"] == "0000000000000000"
                assert fields["CapEff"] == "0000000000000000"
                assert fields["CapAmb"] == "0000000000000000"
                assert fields["NoNewPrivs"] == "1"

                # This subprocess is in a sibling process branch, not an
                # ancestor of the shim's child.  Under Yama scope 1 its attach
                # therefore exercises PR_SET_PTRACER_ANY rather than the
                # ordinary descendant exception.
                tracer_source = r"""
import ctypes, ctypes.util, os, signal, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
pid = int(sys.argv[1])
if libc.ptrace(16, pid, None, None) != 0:
    raise OSError(ctypes.get_errno(), "PTRACE_ATTACH")
got, status = os.waitpid(pid, 0)
if got != pid or not os.WIFSTOPPED(status):
    raise RuntimeError(f"unexpected attach status: {status:#x}")
if libc.ptrace(17, pid, None, signal.SIGSTOP) != 0:
    raise OSError(ctypes.get_errno(), "PTRACE_DETACH")
"""
                traced = subprocess.run(
                    [sys.executable, "-c", tracer_source, str(host_pid)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=TIMEOUT,
                )
                assert traced.returncode == 0, traced.stderr

                gdb = shutil.which("gdb")
                if gdb is not None:
                    attached = subprocess.run(
                        [
                            gdb,
                            "-q",
                            "-nx",
                            "-batch",
                            "-ex",
                            "set pagination off",
                            "-ex",
                            f"attach {host_pid}",
                            "-ex",
                            'printf "PWNC_PC=0x%lx\\n", (unsigned long)$pc',
                            "-ex",
                            "info registers",
                            "-ex",
                            "detach",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=TIMEOUT,
                    )
                    assert attached.returncode == 0, attached.stderr
                    pc_line = next(line for line in attached.stdout.splitlines() if line.startswith("PWNC_PC="))
                    assert int(pc_line.partition("=")[2], 16) == _elf_entry(target)

                connection.signal(signal.SIGSTOP)
                acknowledgement = _next(connection, EventKind.ACK)
                assert acknowledgement.value == CommandKind.SIGNAL
                assert acknowledgement.detail == signal.SIGSTOP
                _kill_and_reap(connection, process)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def test_nonpaused_supervision_preserves_argv_environment_cwd_and_stdio(tmp_path: Path, shim: Path) -> None:
    target = _compile_c(
        tmp_path,
        "identity-target",
        r"""
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static int put_blob(const void *data, size_t size) {
    uint32_t length = htonl((uint32_t)size);
    if (write(1, &length, sizeof(length)) != sizeof(length)) return -1;
    const char *cursor = data;
    while (size) {
        ssize_t written = write(1, cursor, size);
        if (written <= 0) return -1;
        cursor += written;
        size -= (size_t)written;
    }
    return 0;
}

int main(int argc, char **argv) {
    uint32_t count = htonl((uint32_t)argc);
    if (write(1, &count, sizeof(count)) != sizeof(count)) return 90;
    for (int index = 0; index < argc; index++) if (put_blob(argv[index], strlen(argv[index]))) return 91;

    size_t env_count = 0;
    while (environ[env_count]) env_count++;
    count = htonl((uint32_t)env_count);
    if (write(1, &count, sizeof(count)) != sizeof(count)) return 92;
    for (size_t index = 0; index < env_count; index++) if (put_blob(environ[index], strlen(environ[index]))) return 93;

    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd)) || put_blob(cwd, strlen(cwd))) return 94;
    char input[4096];
    ssize_t input_size = read(0, input, sizeof(input));
    if (input_size < 0 || put_blob(input, (size_t)input_size)) return 95;
    (void)write(2, "fixture-stderr", 14);
    return 7;
}
""",
    )
    arguments = ("space value", "", "--literal")
    environment = {
        "PATH": "/usr/bin:/bin",
        "EXACT_ONE": "alpha beta",
        "EXACT_TWO": "",
    }
    input_data = b"binary\x00stdin\n"

    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(listener.path, target, arguments, pause=False, shim=shim),
            cwd=tmp_path,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                ready = _next(connection, EventKind.READY)
                assert not ready.paused
                assert ready.flags & ReadyFlags.PIDFD
                connection.acknowledge_ready()
                acknowledgement = _next(connection, EventKind.ACK)
                assert acknowledgement.value == CommandKind.READY_ACK
                assert acknowledgement.detail == 0
                assert process.stdin is not None
                process.stdin.write(input_data)
                process.stdin.close()
                exited = _next(connection, EventKind.EXIT)
                assert exited.returncode == 7
            assert _wait_process(process) == 7
            assert process.stdout is not None
            encoded = process.stdout.read()
            assert process.stderr is not None
            assert process.stderr.read() == b"fixture-stderr"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)

    offset = 0

    def take_u32() -> int:
        nonlocal offset
        value = struct.unpack_from("!I", encoded, offset)[0]
        offset += 4
        return value

    def take_blob() -> bytes:
        nonlocal offset
        length = take_u32()
        value = encoded[offset : offset + length]
        offset += length
        return value

    argv_count = take_u32()
    observed_argv = [take_blob() for _ in range(argv_count)]
    env_count = take_u32()
    observed_environment = {take_blob() for _ in range(env_count)}
    observed_cwd = take_blob()
    observed_input = take_blob()
    assert offset == len(encoded)
    assert observed_argv == [os.fsencode(target), *[os.fsencode(argument) for argument in arguments]]
    assert observed_environment == {os.fsencode(f"{name}={value}") for name, value in environment.items()}
    assert observed_cwd == os.fsencode(tmp_path)
    assert observed_input == input_data


def test_nonpaused_ready_keeps_short_lived_target_identity_until_ack(tmp_path: Path, shim: Path) -> None:
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(listener.path, "/bin/true", pause=False, shim=shim),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                ready = _next(connection, EventKind.READY)
                assert not ready.paused
                assert ready.pidfd is not None
                assert fcntl.fcntl(ready.pidfd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC

                selector = selectors.DefaultSelector()
                try:
                    selector.register(ready.pidfd, selectors.EVENT_READ)
                    assert selector.select(TIMEOUT), "short-lived target did not exit"
                finally:
                    selector.close()

                host_pid = connection.host_pid
                assert host_pid is not None
                assert _status_fields(host_pid)["State"].startswith("Z")
                connection.acknowledge_ready()
                acknowledgement = _next(connection, EventKind.ACK)
                assert acknowledgement.value == CommandKind.READY_ACK
                assert acknowledgement.detail == 0
                assert _next(connection, EventKind.EXIT).returncode == 0
            assert _wait_process(process) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def test_supervisor_resets_inherited_ignored_sigchld(tmp_path: Path, shim: Path) -> None:
    launcher = _compile_c(
        tmp_path,
        "ignore-sigchld-launcher",
        r"""
#include <errno.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 90;
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) return 91;
    execv(argv[1], &argv[1]);
    return errno == 0 ? 92 : errno;
}
""",
    )
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            [launcher, *shim_argv(listener.path, "/bin/true", pause=False, shim=shim)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                _next(connection, EventKind.READY)
                connection.acknowledge_ready()
                assert _next(connection, EventKind.ACK).value == CommandKind.READY_ACK
                assert _next(connection, EventKind.EXIT).returncode == 0
            assert _wait_process(process) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def test_nonpaused_ready_handshake_forwards_supervisor_signals(tmp_path: Path, shim: Path) -> None:
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(listener.path, "/bin/sleep", ("60",), pause=False, shim=shim),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                ready = _next(connection, EventKind.READY)
                assert ready.pidfd is not None
                os.kill(process.pid, signal.SIGTERM)

                selector = selectors.DefaultSelector()
                try:
                    selector.register(ready.pidfd, selectors.EVENT_READ)
                    assert selector.select(TIMEOUT), "SIGTERM was not forwarded during READY handshake"
                finally:
                    selector.close()
                assert connection.host_pid is not None

                connection.acknowledge_ready()
                assert _next(connection, EventKind.ACK).value == CommandKind.READY_ACK
                exited = _next(connection, EventKind.EXIT)
                assert exited.returncode == -signal.SIGTERM
            assert _wait_process(process) == 128 + signal.SIGTERM
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def test_exec_failure_is_structured_and_fatal(tmp_path: Path, shim: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(listener.path, missing, pause=True, shim=shim),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                failed = _next(connection, EventKind.ERROR)
                assert failed.detail == ErrorStage.CHILD_EXEC
                assert failed.value == errno.ENOENT
                assert failed.flags & ErrorFlags.FATAL
                exited = _next(connection, EventKind.EXIT)
                assert exited.returncode == 127
            assert _wait_process(process) == 127
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


@pytest.mark.parametrize(("host_aslr", "expected"), [(False, b"off\n"), (True, b"on\n")])
def test_host_aslr_is_applied_per_target_before_exec(
    tmp_path: Path, shim: Path, host_aslr: bool, expected: bytes
) -> None:
    target = _compile_c(
        tmp_path,
        "personality-target",
        r"""
#include <stdio.h>
#include <sys/personality.h>
int main(void) {
    int current = personality(0xffffffffUL);
    if (current < 0) return 90;
    puts((current & ADDR_NO_RANDOMIZE) ? "off" : "on");
    return 0;
}
""",
    )
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(listener.path, target, pause=False, host_aslr=host_aslr, shim=shim),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                _next(connection, EventKind.READY)
                connection.acknowledge_ready()
                assert _next(connection, EventKind.ACK).value == CommandKind.READY_ACK
                assert _next(connection, EventKind.EXIT).returncode == 0
            assert _wait_process(process) == 0
            assert process.stdout is not None
            assert process.stdout.read() == expected
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def test_exec_auto_falls_back_to_the_exact_trusted_executable(tmp_path: Path, shim: Path) -> None:
    missing = tmp_path / "image-qemu-is-missing"
    fallback = _compile_c(tmp_path, "host-qemu-fallback", "int main(void) { return 37; }")
    with ShimListener(tmp_path / "control.sock") as listener:
        process = subprocess.Popen(
            shim_argv(
                listener.path,
                missing,
                pause=False,
                fallback_executable=fallback,
                shim=shim,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                _next(connection, EventKind.READY)
                connection.acknowledge_ready()
                assert _next(connection, EventKind.ACK).value == CommandKind.READY_ACK
                assert _next(connection, EventKind.EXIT).returncode == 37
            assert _wait_process(process) == 37
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            _close_process_pipes(process)


def _docker_available_with_ubuntu() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    return (
        subprocess.run(
            [docker, "image", "inspect", "ubuntu:24.04"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


@pytest.mark.skipif(not _docker_available_with_ubuntu(), reason="Docker with local ubuntu:24.04 is unavailable")
def test_docker_socket_translates_pidfd_and_drops_added_sys_ptrace(tmp_path: Path, shim: Path) -> None:
    # The socket is reachable by arbitrary image users only within this unique
    # bind-mounted directory.  The protocol intentionally has no authentication.
    tmp_path.chmod(0o755)
    cidfile = tmp_path / "container.id"
    with ShimListener(tmp_path / "control.sock") as listener:
        listener.path.chmod(0o666)
        command = [
            shutil.which("docker") or "docker",
            "run",
            "--rm",
            "--network=none",
            "--cap-add=SYS_PTRACE",
            "--cidfile",
            os.fspath(cidfile),
            "--mount",
            f"type=bind,src={tmp_path},dst=/pwnc-control",
            "--mount",
            f"type=bind,src={shim},dst=/pwnc-shim,readonly",
            "--entrypoint",
            "/pwnc-shim",
            "ubuntu:24.04",
            "--control",
            "/pwnc-control/control.sock",
            "--pause",
            "--",
            "/bin/true",
        ]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with listener.accept(TIMEOUT) as connection:
                _preexec_handshake(connection)
                ready = _next(connection, EventKind.READY)
                assert ready.pid > 0
                host_pid = connection.host_pid
                assert host_pid is not None
                assert host_pid != ready.pid
                fields = _status_fields(host_pid)
                assert fields["CapInh"] == "0000000000000000"
                assert fields["CapPrm"] == "0000000000000000"
                assert fields["CapEff"] == "0000000000000000"
                assert fields["CapAmb"] == "0000000000000000"
                assert fields["NoNewPrivs"] == "1"
                connection.continue_()
                assert _next(connection, EventKind.ACK).value == CommandKind.CONTINUE
                assert _next(connection, EventKind.EXIT).returncode == 0
            assert _wait_process(process) == 0
        finally:
            if process.poll() is None:
                if cidfile.exists():
                    subprocess.run(
                        [shutil.which("docker") or "docker", "kill", cidfile.read_text().strip()],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                process.kill()
                process.wait()
            _close_process_pipes(process)
