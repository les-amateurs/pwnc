from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from pwn import ELF

from pwnc.sandbox._shim import build_shim
from pwnc.sandbox.config import SandboxProjectConfig
from pwnc.sandbox.docker import DockerBackend
from pwnc.sandbox.errors import SandboxCapabilityError
from pwnc.sandbox.manager import SandboxManager
from pwnc.sandbox.model import (
    DockerSpec,
    QemuSpec,
    SandboxMount,
    SandboxPort,
    SandboxSnapshot,
    SandboxSpec,
    SandboxState,
    SandboxStdio,
)
from pwnc.sandbox.stdio import connect_stdio

TIMEOUT = 20.0
LIVE_DOCKER = os.environ.get("PWNC_SANDBOX_DOCKER_TESTS") == "1"


def _docker_command(docker: str, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        (docker, *arguments),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )


def _snapshot(manager: SandboxManager, operation: str, **arguments) -> SandboxSnapshot:
    return SandboxSnapshot.from_wire(manager.dispatch(operation, arguments))


def _copy_host_dynamic_executable(executable: Path, root: Path, destination: str) -> None:
    """Copy one host executable and its exact ``ldd`` closure into a scratch root."""

    completed = subprocess.run(
        ("ldd", os.fspath(executable)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    sources = {executable.resolve()}
    for raw_line in completed.stdout.decode("utf-8", "replace").splitlines():
        line = raw_line.strip()
        if "=>" in line:
            candidate = line.split("=>", 1)[1].strip().split(" ", 1)[0]
        else:
            candidate = line.split(" ", 1)[0]
        if candidate.startswith("/"):
            sources.add(Path(candidate))

    executable_target = root / destination.lstrip("/")
    executable_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(executable.resolve(), executable_target)
    for source in sources - {executable.resolve()}:
        target = root / os.fspath(source).lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source.resolve(), target)


def _assert_host_no_aslr_security_options(record: dict) -> None:
    options = record["HostConfig"]["SecurityOpt"]
    assert options[0] == "no-new-privileges=true"
    assert len(options) == 2
    name, separator, payload = options[1].partition("=")
    assert (name, separator) == ("seccomp", "=")
    profile = json.loads(payload)
    assert any(
        rule.get("names") == ["personality"]
        and rule.get("action") == "SCMP_ACT_ALLOW"
        and rule.get("args", [{}])[0].get("value") == 0x40000
        for rule in profile["syscalls"]
    )


@pytest.mark.skipif(
    not LIVE_DOCKER,
    reason="set PWNC_SANDBOX_DOCKER_TESTS=1 for Manager + Docker + native shim integration",
)
def test_live_manager_paused_exec_stdio_proxy_exit_and_exact_cleanup(tmp_path):
    assert sys.platform == "linux", "PWNC_SANDBOX_DOCKER_TESTS=1 requires Linux"
    docker = shutil.which("docker")
    zig = shutil.which("zig")
    assert docker is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires docker"
    assert zig is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires Zig"
    version = _docker_command(docker, "version")
    assert version.returncode == 0, version.stderr.decode("utf-8", "replace")

    build_context = tmp_path / "build"
    build_context.mkdir()
    state_directory = tmp_path / "state"
    state_directory.mkdir()
    marker = state_directory / "constructor-ran"
    source = build_context / "target.c"
    source.write_text(
        r"""
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

__attribute__((constructor)) static void constructor_barrier(void) {
    int marker = open("/state/constructor-ran", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (marker >= 0) {
        (void)write(marker, "ran", 3);
        close(marker);
    }
    (void)write(STDERR_FILENO, "CTOR-STDERR\n", 12);
}

int main(void) {
    char input[128];
    char output[160];
    char finish;
    int enabled = 1;
    struct sockaddr_in address = {0};
    (void)write(STDOUT_FILENO, "MAIN-STDOUT\n", 12);
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 20;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(31337);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) return 21;
    if (listen(server, 4) != 0) return 22;
    (void)write(STDOUT_FILENO, "NET-READY\n", 10);
    int client;
    do {
        client = accept(server, NULL, NULL);
    } while (client < 0 && errno == EINTR);
    if (client < 0) return 23;
    ssize_t length = read(client, input, sizeof(input));
    if (length <= 0) return 24;
    int output_length = snprintf(output, sizeof(output), "NET:%.*s", (int)length, input);
    if (output_length <= 0 || write(client, output, (size_t)output_length) != output_length) return 25;
    close(client);
    close(server);
    (void)write(STDOUT_FILENO, "NET-DONE\n", 9);
    if (read(STDIN_FILENO, &finish, 1) != 1) return 26;
    (void)write(STDERR_FILENO, "BYE-STDERR\n", 11);
    return 37;
}
""",
        encoding="utf-8",
    )
    target = build_context / "target"
    compiled = subprocess.run(
        (zig, "cc", "-O2", "-static", "-o", os.fspath(target), os.fspath(source)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    (build_context / "Dockerfile").write_text(
        """FROM scratch
COPY target /target
ENTRYPOINT ["/hostile-image-entrypoint-must-not-run"]
HEALTHCHECK --interval=1s --timeout=1s --retries=1 CMD ["/hostile-image-healthcheck-must-not-run"]
VOLUME ["/anonymous"]
""",
        encoding="utf-8",
    )
    shim = build_shim(cache_root=tmp_path / "shim-cache", zig=zig)

    spec = SandboxSpec(
        profile="default",
        command=("/target",),
        docker=DockerSpec(build_context=build_context),
        stdio=SandboxStdio.PIPE,
        ports=(SandboxPort("pwn", 31337),),
        mounts=(SandboxMount(state_directory, "/state", read_only=False),),
        pause_at_exec=True,
        allow_egress=False,
        host_aslr=False,
    )
    project = SandboxProjectConfig(
        path=tmp_path / "pwnc.toml",
        default_profile="default",
        socket=None,
        profiles={"default": spec},
    )

    backends: list[DockerBackend] = []

    def backend_factory(**options) -> DockerBackend:
        backend = DockerBackend(docker_executable=docker, **options)
        backends.append(backend)
        return backend

    runtime_base = Path(tempfile.mkdtemp(prefix="pdl-", dir="/tmp"))
    manager = SandboxManager(
        project,
        runtime_dir=runtime_base,
        backend_factory=backend_factory,
        shim_builder=lambda: shim,
        startup_timeout=TIMEOUT,
        operation_timeout=TIMEOUT,
    )
    tube = None
    container_id = None
    network_id = None
    anonymous_volume = None
    image_ids: tuple[str, ...] = ()
    try:
        started = manager.start()
        assert started.state is SandboxState.PAUSED
        assert started.paused is True
        assert started.host_pid is not None
        assert started.container_id is not None
        assert started.stdio_socket is not None
        assert not marker.exists()

        session = manager._session(started.id)
        instance = session.instance
        assert instance is not None
        assert started.host_pid != instance.host_pid
        assert instance.target_host_pid == started.host_pid
        assert Path(f"/proc/{started.host_pid}").is_dir()
        assert Path(f"/proc/{instance.host_pid}").is_dir()
        assert len(backends) == 1
        container_id = instance.container_id
        network_id = backends[0].internal_network_id
        image_ids = backends[0].built_image_ids
        assert network_id is not None
        assert image_ids

        inspected = _docker_command(docker, "inspect", container_id)
        assert inspected.returncode == 0, inspected.stderr.decode("utf-8", "replace")
        record = json.loads(inspected.stdout)[0]
        assert record["State"]["Pid"] == instance.host_pid
        assert record["HostConfig"]["CapDrop"] == ["ALL"]
        assert {capability.removeprefix("CAP_") for capability in record["HostConfig"]["CapAdd"]} == {"SYS_PTRACE"}
        _assert_host_no_aslr_security_options(record)
        assert record["HostConfig"]["PortBindings"] == {}
        assert record["Config"]["Entrypoint"] == ["/run/pwnc/shim"]
        assert record["Config"]["Healthcheck"]["Test"] == ["NONE"]
        volumes = [
            mount for mount in record["Mounts"] if mount["Type"] == "volume" and mount["Destination"] == "/anonymous"
        ]
        assert len(volumes) == 1
        anonymous_volume = volumes[0]["Name"]
        control_mounts = [mount for mount in record["Mounts"] if mount["Destination"] == "/run/pwnc/control/c"]
        assert len(control_mounts) == 1
        assert control_mounts[0]["Type"] == "bind"
        assert control_mounts[0]["RW"] is False
        assert not Path(f"/proc/{started.host_pid}/root/run/pwnc/control/i").exists()

        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        resumed = _snapshot(manager, "resume", sandbox_id=started.id)
        assert resumed.state is SandboxState.RUNNING
        assert resumed.paused is False
        initial_lines = {tube.recvline(timeout=TIMEOUT) for _ in range(3)}
        assert initial_lines == {b"CTOR-STDERR\n", b"MAIN-STDOUT\n", b"NET-READY\n"}
        assert marker.read_text(encoding="utf-8") == "ran"

        binding = resumed.bindings["pwn"]
        assert binding.host == "127.0.0.1"
        with socket.create_connection((binding.host, binding.host_port), timeout=TIMEOUT) as connection:
            connection.sendall(b"manager-live")
            assert connection.recv(160) == b"NET:manager-live"
        assert tube.recvline(timeout=TIMEOUT) == b"NET-DONE\n"
        tube.send(b"x")
        assert tube.recvline(timeout=TIMEOUT) == b"BYE-STDERR\n"

        exited = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
        assert exited.state is SandboxState.EXITED
        assert exited.exit_code == 37
        assert exited.host_pid == started.host_pid
        closed = manager.close_sandbox(started.id)
        assert closed.state is SandboxState.CLOSED
        assert manager.list() == ()
    finally:
        if tube is not None:
            tube.close()
        for backend in backends:
            if not image_ids:
                image_ids = backend.built_image_ids
        try:
            try:
                manager.close()
            finally:
                for backend in backends:
                    backend.close()
        except BaseException:
            if container_id is not None:
                _docker_command(docker, "rm", "--force", "--volumes", container_id)
            for image_id in image_ids:
                _docker_command(docker, "image", "rm", image_id)
            raise
        finally:
            shutil.rmtree(runtime_base, ignore_errors=True)

    assert container_id is not None
    assert network_id is not None
    assert all(backend.built_image_ids == () for backend in backends)
    assert _docker_command(docker, "inspect", container_id).returncode != 0
    assert _docker_command(docker, "network", "inspect", network_id).returncode != 0
    assert anonymous_volume is not None
    remaining_volume = _docker_command(docker, "volume", "inspect", anonymous_volume).returncode == 0
    try:
        assert remaining_volume is False
    finally:
        if remaining_volume:
            _docker_command(docker, "volume", "rm", "--force", anonymous_volume)
    remaining_images = [
        image_id for image_id in image_ids if _docker_command(docker, "image", "inspect", image_id).returncode == 0
    ]
    try:
        assert remaining_images == []
    finally:
        # Inspect before this fallback so manual cleanup cannot mask a backend
        # ownership regression in the live assertion above.
        for image_id in remaining_images:
            _docker_command(docker, "image", "rm", image_id)


@pytest.mark.skipif(
    not LIVE_DOCKER,
    reason="set PWNC_SANDBOX_DOCKER_TESTS=1 for Manager + Docker + qemu-user integration",
)
@pytest.mark.parametrize("qemu_source", ["image", "host"])
def test_live_manager_qemu_stops_before_guest_code_and_bridges_gdb(tmp_path, qemu_source):
    assert sys.platform == "linux", "PWNC_SANDBOX_DOCKER_TESTS=1 requires Linux"
    docker = shutil.which("docker")
    zig = shutil.which("zig")
    emulator_text = shutil.which("qemu-aarch64")
    static_emulator = os.environ.get("PWNC_QEMU_AARCH64_STATIC") or shutil.which("qemu-aarch64-static")
    gdb = shutil.which("gdb-multiarch")
    assert docker is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires docker"
    assert zig is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires Zig"
    assert emulator_text is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires qemu-aarch64"
    assert gdb is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires gdb-multiarch"
    if qemu_source == "host" and static_emulator is None:
        pytest.skip("host-source live coverage needs qemu-aarch64-static or PWNC_QEMU_AARCH64_STATIC")
    version = _docker_command(docker, "version")
    assert version.returncode == 0, version.stderr.decode("utf-8", "replace")

    build_context = tmp_path / "qemu-build"
    rootfs = build_context / "rootfs"
    rootfs.mkdir(parents=True)
    state_directory = tmp_path / "qemu-state"
    state_directory.mkdir()
    marker = state_directory / "constructor-ran"
    source = build_context / "target.c"
    source.write_text(
        r"""
#include <fcntl.h>
#include <unistd.h>

__attribute__((constructor)) static void constructor_barrier(void) {
    int marker = open("/state/constructor-ran", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (marker >= 0) {
        (void)write(marker, "ran", 3);
        close(marker);
    }
    (void)write(STDERR_FILENO, "AARCH64-CTOR\n", 13);
}

int main(void) {
    (void)write(STDOUT_FILENO, "AARCH64-MAIN\n", 13);
    return 41;
}
""",
        encoding="utf-8",
    )
    target = rootfs / "target"
    compiled = subprocess.run(
        (
            zig,
            "cc",
            "-target",
            "aarch64-linux-musl",
            "-fPIE",
            "-pie",
            "-O0",
            "-o",
            os.fspath(target),
            os.fspath(source),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    if qemu_source == "image":
        emulator = Path(emulator_text)
        _copy_host_dynamic_executable(emulator, rootfs, "/opt/challenge-qemu/qemu-aarch64")
    (build_context / "Dockerfile").write_text(
        """FROM scratch
COPY rootfs /
ENV PATH="/opt/challenge-qemu:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENTRYPOINT ["/hostile-image-entrypoint-must-not-run"]
""",
        encoding="utf-8",
    )
    shim = build_shim(cache_root=tmp_path / "qemu-shim-cache", zig=zig)

    spec = SandboxSpec(
        profile="foreign",
        command=("/target",),
        docker=DockerSpec(build_context=build_context),
        qemu=(
            QemuSpec(
                architecture="aarch64",
                source="image",
                guest_aslr=False,
            )
            if qemu_source == "image"
            else QemuSpec(
                architecture="aarch64",
                source="host",
                binary=static_emulator,
                guest_aslr=False,
            )
        ),
        stdio=SandboxStdio.PIPE,
        mounts=(SandboxMount(state_directory, "/state", read_only=False),),
        pause_at_exec=True,
        allow_egress=False,
        host_aslr=False,
    )
    project = SandboxProjectConfig(
        path=tmp_path / "pwnc.toml",
        default_profile="foreign",
        socket=None,
        profiles={"foreign": spec},
    )

    backends: list[DockerBackend] = []

    def backend_factory(**options) -> DockerBackend:
        backend = DockerBackend(docker_executable=docker, **options)
        backends.append(backend)
        return backend

    from pwnc.gdb.dap import start as start_gdb

    prepared_gdb = start_gdb(gdb_path=gdb, init=False)
    gdb_pool = SimpleNamespace(current=prepared_gdb, close=prepared_gdb.close)
    gdb_console = SimpleNamespace(selection=SimpleNamespace(gdb=prepared_gdb, generation=1))
    runtime_base = Path(tempfile.mkdtemp(prefix="pql-", dir="/tmp"))
    manager = SandboxManager(
        project,
        runtime_dir=runtime_base,
        backend_factory=backend_factory,
        shim_builder=lambda: shim,
        startup_timeout=TIMEOUT,
        operation_timeout=TIMEOUT,
        gdb_pool=gdb_pool,
        gdb_console=gdb_console,
    )
    tube = None
    container_id = None
    image_ids: tuple[str, ...] = ()
    try:
        started = manager.start()
        assert started.state is SandboxState.PAUSED
        assert started.paused is True
        assert started.host_pid is not None
        assert started.container_id is not None
        assert started.stdio_socket is not None
        assert started.debug is not None
        assert started.debug.transport == "tcp"
        assert started.debug.architecture == "aarch64"
        assert started.debug.host == "127.0.0.1"
        assert started.debug.port > 0
        assert not marker.exists(), "QEMU must stop before the guest constructor or first instruction"

        session = manager._session(started.id)
        instance = session.instance
        assert instance is not None
        assert instance.target_host_pid == started.host_pid
        container_id = instance.container_id
        assert len(backends) == 1
        image_ids = backends[0].built_image_ids
        assert image_ids

        inspected = _docker_command(docker, "inspect", container_id)
        assert inspected.returncode == 0, inspected.stderr.decode("utf-8", "replace")
        record = json.loads(inspected.stdout)[0]
        assert record["HostConfig"]["CapDrop"] == ["ALL"]
        assert not record["HostConfig"].get("CapAdd")
        _assert_host_no_aslr_security_options(record)
        assert record["HostConfig"]["PortBindings"] == {}
        arguments = record["Config"]["Cmd"]
        assert arguments[:2] == ["--control", "/run/pwnc/control/c"]
        assert "--no-pause" in arguments
        expected_emulator = "qemu-aarch64" if qemu_source == "image" else "/run/pwnc/qemu-user"
        assert expected_emulator in arguments
        assert ["-R", "0x1000000000"] == arguments[arguments.index("-R") : arguments.index("-R") + 2]
        assert ["-g", "/run/pwnc/debug/gdb.sock"] == arguments[arguments.index("-g") : arguments.index("-g") + 2]

        tube = connect_stdio(started.stdio_socket, timeout=TIMEOUT)
        attached = manager.attach(started.id)
        assert attached == {
            "sandbox_id": started.id,
            "host_pid": started.host_pid,
            "generation": 1,
            "transport": "qemu-gdb",
            "target": f"{started.debug.host}:{started.debug.port}",
            "architecture": "aarch64",
        }
        assert prepared_gdb.reg.pc > 0
        assert prepared_gdb.remote_file_settings["sysroot"] == (
            f"/proc/{started.host_pid}/root/"
        )
        assert '"' not in prepared_gdb.remote_file_settings["sysroot"]
        relocation = dict(prepared_gdb.qemu_user_relocation)
        assert relocation["pie"] is True
        assert relocation["source"] == "qOffsets"
        assert relocation["symbolsReloaded"] is True
        expected_main = relocation["loadBias"] + ELF(target, checksec=False).symbols["main"]
        assert int(prepared_gdb.sym.main) == expected_main
        with pytest.raises(SandboxCapabilityError, match="original guest-stub pause"):
            manager.attach(started.id)
        prepared_gdb.bp("main")
        stop = prepared_gdb.run(timeout=TIMEOUT)
        assert stop["reason"] == "breakpoint"
        assert expected_main <= prepared_gdb.reg.pc < expected_main + 64
        stop = prepared_gdb.run(timeout=TIMEOUT)
        assert stop["reason"] in {"exited", "terminated"}
        assert {tube.recvline(timeout=TIMEOUT) for _ in range(2)} == {b"AARCH64-CTOR\n", b"AARCH64-MAIN\n"}
        assert marker.read_text(encoding="utf-8") == "ran"

        exited = _snapshot(manager, "wait", sandbox_id=started.id, wait_timeout=TIMEOUT)
        assert exited.state is SandboxState.EXITED
        assert exited.exit_code == 41
        closed = manager.close_sandbox(started.id)
        assert closed.state is SandboxState.CLOSED
        assert manager.list() == ()
    finally:
        if tube is not None:
            tube.close()
        for backend in backends:
            if not image_ids:
                image_ids = backend.built_image_ids
        try:
            try:
                manager.close()
            finally:
                for backend in backends:
                    backend.close()
        except BaseException:
            if container_id is not None:
                _docker_command(docker, "rm", "--force", "--volumes", container_id)
            for image_id in image_ids:
                _docker_command(docker, "image", "rm", image_id)
            raise
        finally:
            shutil.rmtree(runtime_base, ignore_errors=True)
            prepared_gdb.close()

    assert container_id is not None
    assert all(backend.built_image_ids == () for backend in backends)
    assert _docker_command(docker, "inspect", container_id).returncode != 0
    remaining_images = [
        image_id for image_id in image_ids if _docker_command(docker, "image", "inspect", image_id).returncode == 0
    ]
    try:
        assert remaining_images == []
    finally:
        for image_id in remaining_images:
            _docker_command(docker, "image", "rm", image_id)
