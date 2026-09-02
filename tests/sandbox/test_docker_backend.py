from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import pwnc.sandbox.docker as docker_module
from pwnc.sandbox.docker import DockerAttach, DockerBackend, DockerTCPProxy
from pwnc.sandbox.errors import SandboxBackendError, SandboxCapabilityError, SandboxConfigError
from pwnc.sandbox.model import DockerSpec, QemuSpec, SandboxPort, SandboxSpec, SandboxStdio

CONTAINER_ID = "1" * 64
NETWORK_ID = "2" * 64
IMAGE_ID = "sha256:" + "3" * 64


class FakeAttachProcess:
    _next_pid = 1_000_000

    def __init__(self, argv, *, stdout_data: bytes = b"", **kwargs):
        self.args = tuple(argv)
        self.kwargs = kwargs
        self.pid = FakeAttachProcess._next_pid
        FakeAttachProcess._next_pid += 1
        self.stdin = io.BytesIO() if kwargs.get("stdin") == subprocess.PIPE else None
        self.stdout = io.BytesIO(stdout_data) if kwargs.get("stdout") == subprocess.PIPE else None
        self.stderr = io.BytesIO() if kwargs.get("stderr") == subprocess.PIPE else None
        self.returncode = None
        self._done = threading.Event()

    def poll(self):
        return self.returncode

    def wait(self):
        self._done.wait()
        assert self.returncode is not None
        return self.returncode

    def terminate(self):
        self.returncode = 0
        self._done.set()

    def kill(self):
        self.returncode = -9
        self._done.set()


class FakeDockerCLI:
    def __init__(self):
        self.commands: list[tuple[str, ...]] = []
        self.attachments: list[FakeAttachProcess] = []
        self.event_streams: list[FakeAttachProcess] = []
        self.operations: list[tuple[str, tuple[str, ...]]] = []
        self.failure: tuple[str, ...] | None = None
        self.failures: set[tuple[str, ...]] = set()
        self.inspect_pid = 4242
        self.inspect_ports: dict[str, list[dict[str, str]] | None] = {
            "31337/tcp": [{"HostIp": "127.0.0.1", "HostPort": "49152"}]
        }
        self.container_id = CONTAINER_ID
        self.published = False

    def run(self, argv: tuple[str, ...], timeout: float | None = None):
        del timeout
        self.commands.append(argv)
        self.operations.append(("run", argv))
        injected = self.failure is not None and argv[1 : 1 + len(self.failure)] == self.failure
        injected = injected or any(argv[1 : 1 + len(prefix)] == prefix for prefix in self.failures)
        if injected:
            return subprocess.CompletedProcess(argv, 17, b"", b"injected failure")
        if argv[1:3] == ("network", "create"):
            return subprocess.CompletedProcess(argv, 0, (NETWORK_ID + "\n").encode(), b"")
        if argv[1] == "build":
            return subprocess.CompletedProcess(argv, 0, (IMAGE_ID + "\n").encode(), b"")
        if argv[1] == "create":
            self.published = "--publish" in argv
            return subprocess.CompletedProcess(argv, 0, (self.container_id + "\n").encode(), b"")
        if argv[1] == "inspect":
            document = [
                {
                    "Id": self.container_id,
                    "State": {"Pid": self.inspect_pid},
                    "NetworkSettings": {
                        "Ports": self.inspect_ports if self.published else {},
                        "Networks": {
                            "pwnc": {
                                "NetworkID": NETWORK_ID,
                                "IPAddress": "172.30.0.2",
                            }
                        },
                    },
                }
            ]
            return subprocess.CompletedProcess(argv, 0, json.dumps(document).encode(), b"")
        if argv[1] == "wait":
            return subprocess.CompletedProcess(argv, 0, b"23\n", b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def popen(self, argv, **kwargs):
        argv = tuple(argv)
        self.operations.append(("popen", argv))
        if argv[1] == "events":
            process = FakeAttachProcess(argv, stdout_data=b"create\nstart\n", **kwargs)
            self.event_streams.append(process)
            return process
        if self.failure in {("attach",), ("start",)}:
            raise OSError("injected attached start failure")
        process = FakeAttachProcess(argv, stdout_data=b"INITIAL BANNER\n", **kwargs)
        self.attachments.append(process)
        return process

    def matching(self, *prefix: str) -> list[tuple[str, ...]]:
        return [command for command in self.commands if command[1 : 1 + len(prefix)] == prefix]


@pytest.fixture
def fake_cli():
    return FakeDockerCLI()


def make_spec(
    *,
    stdio: SandboxStdio = SandboxStdio.PIPE,
    allow_egress: bool = False,
    pause_at_exec: bool = False,
    image: str | None = "challenge:test",
    build_context: Path | None = None,
    extra_args: tuple[str, ...] = (),
    ports: tuple[SandboxPort, ...] = (SandboxPort("pwn", 31337),),
    qemu: QemuSpec | None = None,
    host_aslr: bool | None = None,
) -> SandboxSpec:
    return SandboxSpec(
        command=("/challenge/run", "argument with spaces", "$(not-a-shell)"),
        docker=DockerSpec(image=image, build_context=build_context, extra_args=extra_args),
        stdio=stdio,
        ports=ports,
        allow_egress=allow_egress,
        pause_at_exec=pause_at_exec,
        profile="unit",
        qemu=qemu,
        host_aslr=host_aslr,
    )


def backend(fake_cli: FakeDockerCLI, **kwargs) -> DockerBackend:
    return DockerBackend(
        session_id="unit-session",
        runner=fake_cli.run,
        popen=fake_cli.popen,
        **kwargs,
    )


def option_value(argv: tuple[str, ...], option: str) -> str:
    index = argv.index(option)
    return argv[index + 1]


def test_secure_create_uses_exact_ids_and_parses_one_inspect(fake_cli):
    service = backend(fake_cli)
    instance = service.spawn(make_spec())

    network_create = fake_cli.matching("network", "create")
    assert len(network_create) == 1
    assert "--internal" in network_create[0]
    assert option_value(network_create[0], "--driver") == "bridge"
    assert network_create[0][-1].startswith("pwnc-unit-session-")

    create = fake_cli.matching("create")[0]
    assert option_value(create, "--pull") == "never"
    assert option_value(create, "--user") == f"{os.getuid()}:{os.getgid()}"
    assert option_value(create, "--cap-drop") == "ALL"
    assert "--cap-add" not in create
    assert option_value(create, "--security-opt") == "no-new-privileges=true"
    assert option_value(create, "--network") == NETWORK_ID
    assert "--publish" not in create
    assert "--interactive" in create
    assert "--tty" not in create
    assert option_value(create, "--entrypoint") == "/challenge/run"
    assert "--no-healthcheck" in create
    image_separator = create.index("--")
    assert create[image_separator + 1 :] == (
        "challenge:test",
        "argument with spaces",
        "$(not-a-shell)",
    )
    assert "--privileged" not in create
    assert len(fake_cli.matching("inspect")) == 1
    assert fake_cli.matching("start") == []

    assert instance.container_id == CONTAINER_ID
    assert instance.host_pid == 4242
    assert instance.target_host_pid is None
    assert instance.bindings["pwn"].host == "127.0.0.1"
    assert 1 <= instance.bindings["pwn"].host_port <= 65535
    assert len(instance.proxies) == 1
    assert instance.attach is not None
    assert instance.attach.process.args == (
        "docker",
        "start",
        "--attach",
        "--interactive",
        CONTAINER_ID,
    )
    event_index = next(index for index, operation in enumerate(fake_cli.operations) if operation[1][1] == "events")
    start_index = next(
        index
        for index, operation in enumerate(fake_cli.operations)
        if operation[0] == "popen" and operation[1][1] == "start"
    )
    inspect_index = next(index for index, operation in enumerate(fake_cli.operations) if operation[1][1] == "inspect")
    assert event_index < start_index < inspect_index
    assert instance.attach.stdout is not None
    assert instance.attach.stdout.readline() == b"INITIAL BANNER\n"

    instance.close()
    service.close()
    assert fake_cli.matching("kill") == [("docker", "kill", CONTAINER_ID)]
    assert fake_cli.matching("rm") == [("docker", "rm", "--force", "--volumes", CONTAINER_ID)]
    assert fake_cli.matching("network", "rm") == [("docker", "network", "rm", NETWORK_ID)]
    # A named image is caller-owned.  Only images built by this backend are
    # session resources eligible for exact-ID removal.
    assert fake_cli.matching("image", "rm") == []


def test_image_reference_cannot_be_reparsed_as_a_docker_security_option(fake_cli):
    service = backend(fake_cli)
    instance = service.spawn(make_spec(image="--privileged", ports=()))

    create = fake_cli.matching("create")[0]
    separator = create.index("--")
    assert create[separator + 1] == "--privileged"
    assert create.index("--privileged") > separator

    instance.close()
    service.close()


@pytest.mark.parametrize(
    ("mode", "interactive", "tty_enabled", "attached"),
    [
        (SandboxStdio.PIPE, True, False, True),
        (SandboxStdio.PTY, True, True, True),
        (SandboxStdio.NONE, False, False, False),
    ],
)
def test_stdio_modes_are_explicit(fake_cli, mode, interactive, tty_enabled, attached):
    service = backend(fake_cli)
    instance = service.spawn(make_spec(stdio=mode))
    create = fake_cli.matching("create")[0]

    assert ("--interactive" in create) is interactive
    assert ("--tty" in create) is tty_enabled
    assert (instance.attach is not None) is attached
    if mode is SandboxStdio.PIPE:
        process = fake_cli.attachments[0]
        assert process.kwargs["stdin"] == subprocess.PIPE
        assert process.kwargs["stdout"] == subprocess.PIPE
        assert process.kwargs["stderr"] == subprocess.STDOUT
        assert instance.attach is not None
        assert instance.attach.stderr is None
        assert process.kwargs["start_new_session"] is True
    elif mode is SandboxStdio.PTY:
        process = fake_cli.attachments[0]
        assert all(isinstance(process.kwargs[name], int) for name in ("stdin", "stdout", "stderr"))
        assert process.kwargs["start_new_session"] is True
        assert instance.attach is not None
        assert isinstance(instance.attach.master_fd, int)
        instance.resize(41, 132)
        assert os.get_terminal_size(instance.attach.master_fd) == os.terminal_size((132, 41))
    else:
        assert fake_cli.attachments == []

    service.close()


def test_allow_egress_uses_builtin_bridge_without_owned_network(fake_cli):
    service = backend(fake_cli)
    instance = service.spawn(make_spec(allow_egress=True, stdio=SandboxStdio.NONE))

    assert fake_cli.matching("network", "create") == []
    assert option_value(fake_cli.matching("create")[0], "--network") == "bridge"
    assert option_value(fake_cli.matching("create")[0], "--publish") == "127.0.0.1::31337/tcp"
    assert instance.bindings["pwn"].host_port == 49152
    assert instance.proxies == ()
    service.close()
    assert fake_cli.matching("network", "rm") == []


def test_fixed_loopback_port_is_preserved(fake_cli):
    fake_cli.inspect_ports = {"31337/tcp": [{"HostIp": "127.0.0.1", "HostPort": "44444"}]}
    service = backend(fake_cli)
    instance = service.spawn(make_spec(ports=(SandboxPort("pwn", 31337, host_port=44444),), stdio=SandboxStdio.NONE))

    assert "--publish" not in fake_cli.matching("create")[0]
    assert instance.bindings["pwn"].host_port == 44444
    service.close()


def test_pause_shim_mounts_private_paths_and_only_pause_adds_ptrace(fake_cli, tmp_path):
    shim = tmp_path / "shim"
    shim.write_bytes(b"shim")
    shim.chmod(0o755)
    control_directory = tmp_path / "control"
    control_directory.mkdir()
    control_socket = control_directory / "manager.sock"
    service = backend(fake_cli, shim_path=shim, control_socket=control_socket)

    instance = service.spawn(make_spec(pause_at_exec=True, stdio=SandboxStdio.NONE))
    create = fake_cli.matching("create")[0]
    mount_values = [create[index + 1] for index, item in enumerate(create) if item == "--mount"]
    assert f"type=bind,source={shim},target=/run/pwnc/shim,readonly" in mount_values
    assert f"type=bind,source={control_socket},target=/run/pwnc/control/manager.sock,readonly" in mount_values
    assert all(f"source={control_directory},target=/run/pwnc/control" not in mount for mount in mount_values)
    assert option_value(create, "--cap-add") == "SYS_PTRACE"
    assert option_value(create, "--entrypoint") == "/run/pwnc/shim"
    assert "--no-healthcheck" in create
    wrapper = create[create.index("challenge:test") + 1 :]
    assert wrapper == (
        "--control",
        "/run/pwnc/control/manager.sock",
        "--pause",
        "--",
        "/challenge/run",
        "argument with spaces",
        "$(not-a-shell)",
    )
    assert instance.shim_control_socket == control_socket
    assert instance.paused is True
    service.close()


def test_nonpaused_shim_does_not_receive_ptrace_capability(fake_cli, tmp_path):
    shim = tmp_path / "shim"
    shim.write_bytes(b"shim")
    shim.chmod(0o755)
    control = tmp_path / "control"
    control.mkdir()
    service = backend(fake_cli, shim_path=shim, control_socket=control / "manager.sock")

    service.spawn(make_spec(stdio=SandboxStdio.NONE))
    create = fake_cli.matching("create")[0]
    assert "--cap-add" not in create
    assert option_value(create, "--entrypoint") == "/run/pwnc/shim"
    wrapper = create[create.index("challenge:test") + 1 :]
    assert "--pause" not in wrapper
    assert "--no-pause" in wrapper
    service.close()


def test_paused_image_qemu_uses_private_stub_mount_without_host_ptrace(fake_cli, tmp_path):
    shim = tmp_path / "shim"
    shim.write_bytes(b"shim")
    shim.chmod(0o755)
    control = tmp_path / "control"
    control.mkdir()
    service = backend(fake_cli, shim_path=shim, control_socket=control / "manager.sock")
    spec = make_spec(
        stdio=SandboxStdio.NONE,
        pause_at_exec=True,
        host_aslr=False,
        qemu=QemuSpec(
            "aarch64",
            source="image",
            binary="/opt/challenge/qemu-aarch64",
            sysroot="/guest-root",
            guest_aslr=False,
        ),
    )

    instance = service.spawn(spec)
    create = fake_cli.matching("create")[0]
    assert "--cap-add" not in create
    security_options = [create[index + 1] for index, item in enumerate(create) if item == "--security-opt"]
    assert security_options == [
        "no-new-privileges=true",
        f"seccomp={docker_module._HOST_NO_ASLR_SECCOMP}",
    ]
    mounts = [create[index + 1] for index, item in enumerate(create) if item == "--mount"]
    assert any("target=/run/pwnc/debug" in mount and not mount.endswith(",readonly") for mount in mounts)
    wrapper = create[create.index("challenge:test") + 1 :]
    assert wrapper[:6] == (
        "--control",
        "/run/pwnc/control/manager.sock",
        "--no-pause",
        "--host-aslr",
        "off",
        "--",
    )
    qemu = wrapper[6:]
    assert qemu[:3] == ("/opt/challenge/qemu-aarch64", "-g", "/run/pwnc/debug/gdb.sock")
    assert qemu[3:7] == ("-R", "0x1000000000", "-L", "/guest-root")
    assert qemu[7:] == ("/challenge/run", "argument with spaces", "$(not-a-shell)")
    assert instance.debug is not None
    assert instance.debug.architecture == "aarch64"
    assert instance.debug.host == "127.0.0.1"
    assert instance.qemu_bridge is not None
    service.close()


def test_each_paused_qemu_runtime_owns_a_unique_debug_directory(fake_cli, tmp_path):
    shim = tmp_path / "shim"
    shim.write_bytes(b"shim")
    shim.chmod(0o755)
    control = tmp_path / "control"
    control.mkdir()
    service = backend(fake_cli, shim_path=shim, control_socket=control / "manager.sock")
    spec = make_spec(
        stdio=SandboxStdio.NONE,
        pause_at_exec=True,
        qemu=QemuSpec("aarch64", source="image", binary="/usr/bin/qemu-aarch64"),
    )
    first = service._qemu_runtime(spec)
    second = service._qemu_runtime(spec)
    assert first is not None and first.bridge is not None
    assert second is not None and second.bridge is not None
    try:
        assert first.bridge.directory != second.bridge.directory
        assert first.bridge.directory.parent == control
        assert second.bridge.directory.parent == control
    finally:
        first.bridge.close()
        second.bridge.close()
        service.close()


def test_running_image_qemu_omits_stub_on_pre_qemu10_compatible_path(fake_cli, tmp_path):
    shim = tmp_path / "shim"
    shim.write_bytes(b"shim")
    shim.chmod(0o755)
    control = tmp_path / "control"
    control.mkdir()
    service = backend(fake_cli, shim_path=shim, control_socket=control / "manager.sock")
    instance = service.spawn(
        make_spec(
            stdio=SandboxStdio.NONE,
            qemu=QemuSpec("riscv64", source="image", binary="/usr/bin/qemu-riscv64"),
        )
    )
    create = fake_cli.matching("create")[0]
    wrapper = create[create.index("challenge:test") + 1 :]
    assert "-g" not in wrapper
    assert "suspend=n" not in " ".join(wrapper)
    assert instance.debug is None
    assert instance.qemu_bridge is None
    service.close()


@pytest.mark.parametrize("source", ["image", "auto"])
def test_omitted_image_qemu_binary_uses_the_image_path(source):
    spec = make_spec(qemu=QemuSpec("arm64", source=source))

    assert DockerBackend._image_qemu_executable(spec) == "qemu-aarch64"


def test_host_qemu_is_static_resolved_and_mounted_read_only(monkeypatch, fake_cli, tmp_path):
    shim = tmp_path / "shim"
    shim.write_bytes(b"shim")
    shim.chmod(0o755)
    emulator = tmp_path / "qemu-aarch64-static"
    emulator.write_bytes(b"qemu")
    emulator.chmod(0o755)
    control = tmp_path / "control"
    control.mkdir()
    calls = []

    def resolve(architecture, *, executable=None, static=None):
        calls.append((architecture, executable, static))
        return type("Resolved", (), {"path": os.fspath(emulator)})()

    monkeypatch.setattr(docker_module, "resolve_qemu", resolve)
    service = backend(fake_cli, shim_path=shim, control_socket=control / "manager.sock")
    instance = service.spawn(
        make_spec(
            stdio=SandboxStdio.NONE,
            pause_at_exec=True,
            qemu=QemuSpec("aarch64", source="host", binary=os.fspath(emulator)),
        )
    )
    assert calls == [("aarch64", os.fspath(emulator), True)]
    create = fake_cli.matching("create")[0]
    mounts = [create[index + 1] for index, item in enumerate(create) if item == "--mount"]
    assert f"type=bind,source={emulator},target=/run/pwnc/qemu-user,readonly" in mounts
    wrapper = create[create.index("challenge:test") + 1 :]
    assert "/run/pwnc/qemu-user" in wrapper
    assert instance.debug is not None
    assert instance.debug.emulator == os.fspath(emulator)
    service.close()


def test_explicit_host_aslr_enable_fails_before_docker_when_kernel_policy_is_off(monkeypatch, fake_cli):
    monkeypatch.setattr(docker_module.Path, "read_text", lambda _path, **_kwargs: "0\n")
    service = backend(fake_cli)
    with pytest.raises(SandboxCapabilityError, match="randomize_va_space=0"):
        service.spawn(make_spec(stdio=SandboxStdio.NONE, host_aslr=True))
    assert fake_cli.commands == []


def test_host_aslr_requires_the_shim_instead_of_being_silently_ignored(fake_cli):
    service = backend(fake_cli)
    with pytest.raises(SandboxConfigError, match="host_aslr requires.*shim_path"):
        service.spawn(make_spec(stdio=SandboxStdio.NONE, host_aslr=False))
    service.close()


@pytest.mark.parametrize("host_aslr", [None, True])
def test_builtin_seccomp_profile_is_preserved_unless_disabling_host_aslr(host_aslr, fake_cli, tmp_path):
    shim = tmp_path / "shim"
    shim.write_bytes(b"shim")
    shim.chmod(0o755)
    control = tmp_path / "control"
    control.mkdir()
    service = backend(fake_cli, shim_path=shim, control_socket=control / "manager.sock")

    service.spawn(make_spec(stdio=SandboxStdio.NONE, host_aslr=host_aslr))
    create = fake_cli.matching("create")[0]
    security_options = [create[index + 1] for index, item in enumerate(create) if item == "--security-opt"]
    assert security_options == ["no-new-privileges=true"]
    service.close()


def test_host_aslr_seccomp_profile_is_the_pinned_moby_default_plus_exact_disable_values():
    data = json.loads(docker_module._HOST_NO_ASLR_SECCOMP.read_text(encoding="utf-8"))
    added_values = {0x40000, 0x40008, 0x60000, 0x60008}

    def is_pwnc_addition(rule):
        arguments = rule.get("args", ())
        return (
            rule.get("names") == ["personality"]
            and rule.get("action") == "SCMP_ACT_ALLOW"
            and len(arguments) == 1
            and arguments[0].get("index") == 0
            and arguments[0].get("op") == "SCMP_CMP_EQ"
            and arguments[0].get("value") in added_values
        )

    additions = [rule for rule in data["syscalls"] if is_pwnc_addition(rule)]
    assert {rule["args"][0]["value"] for rule in additions} == added_values
    assert len(additions) == len(added_values)

    data["syscalls"] = [rule for rule in data["syscalls"] if not is_pwnc_addition(rule)]
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canonical).hexdigest() == "9da637d2ab0a204fcbd91bd88f1be9e004a3acab61c571a9f5b8870e588a17d2"

    # The pinned official profile deliberately leaves AF_ALG (38) unmatched
    # by its allowed socket-family ranges.  The derived profile must preserve
    # that security boundary while adding only personality values.
    socket_rules = [rule for rule in data["syscalls"] if "socket" in rule.get("names", ())]
    assert all(
        not (
            rule.get("action") == "SCMP_ACT_ALLOW"
            and any(
                argument.get("index") == 0
                and (
                    (argument.get("op") == "SCMP_CMP_EQ" and argument.get("value") == 38)
                    or (argument.get("op") == "SCMP_CMP_LT" and 38 < argument.get("value"))
                    or (argument.get("op") == "SCMP_CMP_GT" and 38 > argument.get("value"))
                )
                for argument in rule.get("args", ())
            )
        )
        for rule in socket_rules
    )


def test_pause_requires_shim_without_creating_resources(fake_cli):
    service = backend(fake_cli)
    with pytest.raises(SandboxConfigError, match="requires.*shim_path"):
        service.spawn(make_spec(pause_at_exec=True, stdio=SandboxStdio.NONE))
    # Validation occurs after the per-session network is allocated, so the
    # transactional path must remove that exact network immediately.
    assert fake_cli.matching("network", "rm") == [("docker", "network", "rm", NETWORK_ID)]


@pytest.mark.parametrize(
    "argument",
    [
        "--privileged",
        "--tty",
        "-it",
        "--user=0:0",
        "-u0",
        "--cap-add=ALL",
        "--network=host",
        "-p0.0.0.0:31337:31337",
        "--security-opt=no-new-privileges=false",
        "--mount=type=bind,source=/,target=/host",
        "--health-cmd=/hostile",
        "--no-healthcheck",
        "--use-api-socket",
        "--",
    ],
)
def test_extra_args_cannot_override_backend_owned_security(fake_cli, argument):
    service = backend(fake_cli)
    with pytest.raises(SandboxConfigError, match="owned|terminate"):
        service.spawn(make_spec(extra_args=(argument,), stdio=SandboxStdio.NONE))
    assert fake_cli.matching("create") == []


def test_extra_args_reject_positional_image_before_creating_resources(fake_cli):
    service = backend(fake_cli)

    with pytest.raises(SandboxConfigError, match="positional arguments"):
        service.spawn(make_spec(extra_args=("attacker-controlled:image",), stdio=SandboxStdio.NONE))

    assert fake_cli.commands == []


def test_extra_args_allow_attached_resource_option_value(fake_cli):
    service = backend(fake_cli)
    instance = service.spawn(make_spec(extra_args=("--memory=128m",), stdio=SandboxStdio.NONE))

    create = fake_cli.matching("create")[0]
    assert create.index("--memory=128m") < create.index("--")
    instance.close()
    service.close()


@pytest.mark.parametrize("failure", [("create",), ("start",), ("inspect",), ("attach",)])
def test_failure_after_network_creation_is_transactional(fake_cli, failure):
    fake_cli.failure = failure
    service = backend(fake_cli)

    with pytest.raises((SandboxBackendError, OSError)):
        service.spawn(make_spec())

    if failure == ("create",):
        assert fake_cli.matching("kill") == []
        assert fake_cli.matching("rm") == []
    else:
        assert fake_cli.matching("kill") == [("docker", "kill", CONTAINER_ID)]
        assert fake_cli.matching("rm") == [("docker", "rm", "--force", "--volumes", CONTAINER_ID)]
    assert fake_cli.matching("network", "rm") == [("docker", "network", "rm", NETWORK_ID)]


def test_inspect_rejects_non_loopback_or_ambiguous_binding_and_cleans_up(fake_cli):
    fake_cli.inspect_ports = {
        "31337/tcp": [
            {"HostIp": "0.0.0.0", "HostPort": "49152"},
            {"HostIp": "127.0.0.1", "HostPort": "49152"},
            {"HostIp": "127.0.0.1", "HostPort": "49153"},
        ]
    }
    service = backend(fake_cli)
    with pytest.raises(SandboxBackendError, match="2 matching bindings"):
        service.spawn(make_spec(stdio=SandboxStdio.NONE, allow_egress=True))
    assert fake_cli.matching("kill") == [("docker", "kill", CONTAINER_ID)]
    assert fake_cli.matching("rm") == [("docker", "rm", "--force", "--volumes", CONTAINER_ID)]


def test_wait_is_one_blocking_exact_id_command_and_is_cached(fake_cli):
    service = backend(fake_cli)
    instance = service.spawn(make_spec(stdio=SandboxStdio.NONE))

    assert instance.wait(timeout=12.5) == 23
    assert instance.wait(timeout=0) == 23
    assert fake_cli.matching("wait") == [("docker", "wait", CONTAINER_ID)]
    instance.close()
    # An observed exit avoids a redundant kill but still removes by exact ID.
    assert fake_cli.matching("kill") == []
    assert fake_cli.matching("rm") == [("docker", "rm", "--force", "--volumes", CONTAINER_ID)]
    service.close()


def test_build_context_is_built_once_without_pull_and_created_by_image_id(fake_cli, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    service = backend(fake_cli)
    spec = make_spec(image=None, build_context=tmp_path, stdio=SandboxStdio.NONE)

    first = service.spawn(spec)
    first.close()
    service.spawn(spec)

    builds = fake_cli.matching("build")
    assert len(builds) == 1
    assert "--quiet" in builds[0]
    assert "--pull=false" in builds[0]
    assert builds[0][-1] == os.fspath(tmp_path)
    creates = fake_cli.matching("create")
    assert len(creates) == 2
    assert all(IMAGE_ID in create for create in creates)
    assert all(option_value(create, "--pull") == "never" for create in creates)
    assert service.built_image_ids == (IMAGE_ID,)
    service.close()
    assert service.built_image_ids == ()
    assert fake_cli.matching("image", "rm") == [("docker", "image", "rm", IMAGE_ID)]

    # Backend cleanup is idempotent, including its owned image lifecycle.
    service.close()
    assert fake_cli.matching("image", "rm") == [("docker", "image", "rm", IMAGE_ID)]

    commands = fake_cli.commands
    last_container_rm = max(
        index
        for index, command in enumerate(commands)
        if command == ("docker", "rm", "--force", "--volumes", CONTAINER_ID)
    )
    network_rm = commands.index(("docker", "network", "rm", NETWORK_ID))
    image_rm = commands.index(("docker", "image", "rm", IMAGE_ID))
    assert last_container_rm < network_rm < image_rm


def test_distinct_build_specs_with_same_result_remove_unique_image_id_once(fake_cli, tmp_path):
    first_context = tmp_path / "first"
    second_context = tmp_path / "second"
    first_context.mkdir()
    second_context.mkdir()
    (first_context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (second_context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    service = backend(fake_cli)

    first = service.spawn(make_spec(image=None, build_context=first_context, stdio=SandboxStdio.NONE))
    first.close()
    second = service.spawn(make_spec(image=None, build_context=second_context, stdio=SandboxStdio.NONE))
    second.close()

    assert len(fake_cli.matching("build")) == 2
    assert service.built_image_ids == (IMAGE_ID,)
    service.close()
    assert fake_cli.matching("image", "rm") == [("docker", "image", "rm", IMAGE_ID)]
    assert service.built_image_ids == ()


def test_failed_owned_image_removal_is_tracked_and_retryable(fake_cli, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    service = backend(fake_cli)
    instance = service.spawn(make_spec(image=None, build_context=tmp_path, stdio=SandboxStdio.NONE))
    instance.close()
    fake_cli.failure = ("image", "rm")

    with pytest.raises(SandboxBackendError, match="Docker backend cleanup failed"):
        service.close()

    assert service.built_image_ids == (IMAGE_ID,)
    assert fake_cli.matching("image", "rm") == [("docker", "image", "rm", IMAGE_ID)]

    fake_cli.failure = None
    service.close()
    assert service.built_image_ids == ()
    assert fake_cli.matching("image", "rm") == [
        ("docker", "image", "rm", IMAGE_ID),
        ("docker", "image", "rm", IMAGE_ID),
    ]


def test_owned_image_waits_for_failed_container_cleanup(fake_cli, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    service = backend(fake_cli)
    service.spawn(make_spec(image=None, build_context=tmp_path, stdio=SandboxStdio.NONE))
    fake_cli.failure = ("rm",)

    with pytest.raises(SandboxBackendError, match="Docker backend cleanup failed"):
        service.close()

    assert service.built_image_ids == (IMAGE_ID,)
    assert fake_cli.matching("network", "rm") == []
    assert fake_cli.matching("image", "rm") == []

    fake_cli.failure = None
    service.close()
    assert fake_cli.matching("network", "rm") == [("docker", "network", "rm", NETWORK_ID)]
    assert fake_cli.matching("image", "rm") == [("docker", "image", "rm", IMAGE_ID)]


def test_built_image_from_failed_spawn_is_removed_when_backend_closes(fake_cli, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    service = backend(fake_cli)
    fake_cli.failure = ("create",)

    with pytest.raises(SandboxBackendError, match="create challenge container"):
        service.spawn(make_spec(image=None, build_context=tmp_path, stdio=SandboxStdio.NONE))

    assert service.built_image_ids == (IMAGE_ID,)
    assert fake_cli.matching("network", "rm") == [("docker", "network", "rm", NETWORK_ID)]
    fake_cli.failure = None
    service.close()
    assert fake_cli.matching("image", "rm") == [("docker", "image", "rm", IMAGE_ID)]
    assert service.built_image_ids == ()


def test_failed_spawn_removal_retains_exact_container_for_close_retry(fake_cli, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    service = backend(fake_cli)
    fake_cli.failures = {("start",), ("rm",)}

    with pytest.raises(SandboxBackendError, match="start container"):
        service.spawn(make_spec(image=None, build_context=tmp_path, stdio=SandboxStdio.NONE))

    exact_removal = ("docker", "rm", "--force", "--volumes", CONTAINER_ID)
    assert fake_cli.matching("rm") == [exact_removal]
    assert fake_cli.matching("network", "rm") == []
    assert fake_cli.matching("image", "rm") == []
    assert service.built_image_ids == (IMAGE_ID,)

    fake_cli.failures.clear()
    service.close()
    assert fake_cli.matching("rm") == [exact_removal, exact_removal]
    assert fake_cli.matching("network", "rm") == [("docker", "network", "rm", NETWORK_ID)]
    assert fake_cli.matching("image", "rm") == [("docker", "image", "rm", IMAGE_ID)]
    assert service.built_image_ids == ()


def test_constructor_rejects_root_host_identity(monkeypatch, fake_cli):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    with pytest.raises(SandboxCapabilityError, match="cannot run as root"):
        backend(fake_cli)


def test_internal_udp_publication_fails_before_docker_resources(fake_cli):
    service = backend(fake_cli)
    with pytest.raises(SandboxCapabilityError, match="TCP ports only"):
        service.spawn(
            make_spec(
                stdio=SandboxStdio.NONE,
                ports=(SandboxPort("datagram", 31337, protocol="udp"),),
            )
        )
    assert fake_cli.commands == []


def test_fixed_proxy_port_collision_fails_before_network_or_container(fake_cli):
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.bind(("127.0.0.1", 0))
    occupied.listen()
    occupied_port = occupied.getsockname()[1]
    service = backend(fake_cli)
    try:
        with pytest.raises(SandboxBackendError, match="cannot reserve loopback TCP port"):
            service.spawn(
                make_spec(
                    stdio=SandboxStdio.NONE,
                    ports=(SandboxPort("pwn", 31337, host_port=occupied_port),),
                )
            )
    finally:
        occupied.close()
    assert fake_cli.commands == []


def test_tcp_proxy_close_wait_is_event_driven_without_abandonment_timeout():
    proxy = DockerTCPProxy(SandboxPort("eventful", 31337))
    wait_timeouts = []

    class RecordingCondition:
        def __init__(self, condition):
            self.condition = condition

        def __enter__(self):
            self.condition.acquire()
            return self

        def __exit__(self, exc_type, exc, traceback):
            del exc_type, exc, traceback
            self.condition.release()

        def wait_for(self, predicate, timeout=None):
            wait_timeouts.append(timeout)
            return self.condition.wait_for(predicate, timeout)

        def notify_all(self):
            self.condition.notify_all()

    proxy._condition = RecordingCondition(proxy._condition)
    proxy.close()

    assert wait_timeouts == [None]
    assert proxy._closed


def test_tcp_proxy_close_failure_retains_listener_for_retry(monkeypatch):
    proxy = DockerTCPProxy(SandboxPort("retry", 31337))
    listener = proxy._listener
    original_close = DockerTCPProxy._close_socket
    failed = False

    def fail_listener_once(sock, *, checked=False):
        nonlocal failed
        if sock is listener and checked and not failed:
            failed = True
            raise OSError("injected listener close failure")
        return original_close(sock, checked=checked)

    monkeypatch.setattr(DockerTCPProxy, "_close_socket", staticmethod(fail_listener_once))

    with pytest.raises(SandboxBackendError, match="TCP proxy.*cleanup failed"):
        proxy.close()

    assert proxy._listener is listener
    assert not proxy._closed
    proxy.close()
    assert proxy._closed


def test_tcp_proxy_close_failure_retains_exact_connection_for_retry():
    proxy = DockerTCPProxy(SandboxPort("connection-retry", 31337))

    class FailOnceSocket:
        def __init__(self):
            self.close_calls = 0
            self.closed = False

        def shutdown(self, how):
            del how

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError("injected connection close failure")
            self.closed = True

    connection = FailOnceSocket()
    with proxy._condition:
        proxy._connections.add(connection)

    with pytest.raises(SandboxBackendError, match="TCP proxy.*cleanup failed"):
        proxy.close()

    assert proxy._connections == {connection}
    assert not proxy._closed
    proxy.close()
    assert connection.closed
    assert proxy._connections == set()
    assert proxy._closed


def test_tcp_proxy_concurrent_close_waits_for_same_exact_workers():
    proxy = DockerTCPProxy(SandboxPort("concurrent", 31337))
    worker_started = threading.Event()
    release_worker = threading.Event()
    first_acquired = threading.Event()
    second_attempted = threading.Event()
    first_done = threading.Event()
    second_done = threading.Event()
    failures = []

    class RecordingLock:
        def __init__(self):
            self.lock = threading.Lock()
            self.meta_lock = threading.Lock()
            self.attempts = 0

        def __enter__(self):
            with self.meta_lock:
                self.attempts += 1
                attempt = self.attempts
            if attempt == 2:
                second_attempted.set()
            self.lock.acquire()
            if attempt == 1:
                first_acquired.set()
            return self

        def __exit__(self, exc_type, exc, traceback):
            del exc_type, exc, traceback
            self.lock.release()

    proxy._close_lock = RecordingLock()

    def hold_worker():
        worker_started.set()
        release_worker.wait()
        with proxy._condition:
            proxy._workers.discard(threading.current_thread())
            proxy._condition.notify_all()

    worker = threading.Thread(target=hold_worker, daemon=True)
    with proxy._condition:
        proxy._workers.add(worker)
    worker.start()
    assert worker_started.wait(5)

    def close(done):
        try:
            proxy.close()
        except BaseException as error:  # noqa: BLE001 - replay in the test thread
            failures.append(error)
        finally:
            done.set()

    first = threading.Thread(target=close, args=(first_done,), daemon=True)
    second = threading.Thread(target=close, args=(second_done,), daemon=True)
    first.start()
    assert first_acquired.wait(5)
    second.start()
    assert second_attempted.wait(5)
    assert not second_done.is_set()

    release_worker.set()
    assert first_done.wait(5)
    assert second_done.wait(5)
    first.join()
    second.join()
    assert failures == []
    assert not worker.is_alive()
    assert proxy._closing_workers == ()
    assert proxy._closed


def test_tcp_proxy_close_wakes_an_in_progress_upstream_connect(monkeypatch):
    proxy = DockerTCPProxy(SandboxPort("connecting", 31337))
    proxy._destination = ("127.0.0.1", 31337)
    client, peer = socket.socketpair()
    selecting = threading.Event()
    close_wake = threading.Event()
    worker_done = threading.Event()

    class PendingSocket:
        def __init__(self):
            self.closed = False

        def setblocking(self, enabled):
            del enabled

        def connect_ex(self, destination):
            del destination
            return errno.EINPROGRESS

        def shutdown(self, how):
            del how

        def close(self):
            self.closed = True

    pending = PendingSocket()

    class SelectorKey:
        data = "close"

    class WakeSelector:
        def register(self, fileobj, events, data):
            del fileobj, events, data

        def select(self, timeout):
            assert timeout == 3.0
            selecting.set()
            assert close_wake.wait(5)
            return [(SelectorKey(), docker_module.selectors.EVENT_READ)]

        def close(self):
            pass

    original_shutdown = DockerTCPProxy._shutdown

    def signal_close_wake(sock, how=socket.SHUT_RDWR):
        if sock is proxy._wake_w:
            close_wake.set()
        original_shutdown(sock, how)

    monkeypatch.setattr(docker_module.socket, "socket", lambda *args, **kwargs: pending)
    monkeypatch.setattr(docker_module.selectors, "DefaultSelector", WakeSelector)
    monkeypatch.setattr(DockerTCPProxy, "_shutdown", staticmethod(signal_close_wake))

    def serve():
        try:
            proxy._serve(client)
        finally:
            worker_done.set()

    worker = threading.Thread(target=serve, daemon=True)
    with proxy._condition:
        proxy._connections.add(client)
        proxy._workers.add(worker)
    worker.start()
    assert selecting.wait(5)

    proxy.close()

    assert worker_done.wait(5)
    assert pending.closed
    assert not worker.is_alive()
    assert proxy._closed
    peer.close()


def test_docker_attach_failures_retain_exact_handles_and_process_for_retry(monkeypatch):
    process = FakeAttachProcess(("docker", "attach"))

    class FailOnceHandle:
        def __init__(self):
            self.close_calls = 0
            self.closed = False

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError("injected handle close failure")
            self.closed = True

    handle = FailOnceHandle()
    attach = DockerAttach(process=process, mode=SandboxStdio.PIPE, stdin=handle)
    terminate_calls = 0

    def terminate(exact_process):
        nonlocal terminate_calls
        assert exact_process is process
        terminate_calls += 1
        if terminate_calls == 1:
            raise OSError("injected process termination failure")

    monkeypatch.setattr(docker_module, "_terminate_process", terminate)

    with pytest.raises(SandboxBackendError, match="attach cleanup failed"):
        attach.close()

    assert attach.stdin is handle
    assert attach.process is process
    assert not attach._process_closed
    assert not attach._closed

    attach.close()
    assert attach.stdin is None
    assert handle.closed
    assert terminate_calls == 2
    assert attach._process_closed
    assert attach._closed


def test_backend_retains_instance_until_attach_proxy_and_exact_id_cleanup_succeed(fake_cli):
    service = backend(fake_cli)
    instance = service.spawn(make_spec(stdio=SandboxStdio.NONE, ports=()))

    class CloseResource:
        def __init__(self, *, fail_once):
            self.fail_once = fail_once
            self.close_calls = 0
            self.closed = False

        def close(self):
            self.close_calls += 1
            if self.fail_once and self.close_calls == 1:
                raise OSError("injected resource close failure")
            self.closed = True

    attach = CloseResource(fail_once=True)
    failed_proxy = CloseResource(fail_once=True)
    successful_proxy = CloseResource(fail_once=False)
    instance.attach = attach
    instance.proxies = (failed_proxy, successful_proxy)

    with pytest.raises(SandboxBackendError, match="backend cleanup failed"):
        service.close()

    assert service._instances[CONTAINER_ID] is instance
    assert instance.container_id == CONTAINER_ID
    assert instance.attach is attach
    assert instance.proxies == (failed_proxy,)
    assert instance._container_removed
    assert not instance._closed
    assert successful_proxy.closed
    assert fake_cli.matching("rm") == [("docker", "rm", "--force", "--volumes", CONTAINER_ID)]
    assert fake_cli.matching("network", "rm") == []
    with pytest.raises(SandboxBackendError, match="backend is closed"):
        service.spawn(make_spec(stdio=SandboxStdio.NONE, ports=()))

    service.close()
    assert instance._closed
    assert service._instances == {}
    assert attach.closed
    assert failed_proxy.closed
    assert successful_proxy.close_calls == 1
    assert fake_cli.matching("rm") == [("docker", "rm", "--force", "--volumes", CONTAINER_ID)]
    assert fake_cli.matching("network", "rm") == [("docker", "network", "rm", NETWORK_ID)]


def test_partial_proxy_reservation_failure_is_backend_owned_until_retry(monkeypatch, fake_cli):
    created = []

    class ReservedProxy:
        def __init__(self, port):
            if created:
                raise SandboxBackendError("injected second proxy construction failure")
            self.port = port
            self.close_calls = 0
            self.closed = False
            created.append(self)

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError("injected reserved proxy close failure")
            self.closed = True

    monkeypatch.setattr(docker_module, "DockerTCPProxy", ReservedProxy)
    service = backend(fake_cli)

    with pytest.raises(SandboxBackendError, match="second proxy construction failure"):
        service.spawn(
            make_spec(
                stdio=SandboxStdio.NONE,
                ports=(SandboxPort("first", 31337), SandboxPort("second", 31338)),
            )
        )

    assert len(created) == 1
    assert len(service._pending_cleanup) == 1
    assert service._pending_cleanup[0].proxies == (created[0],)
    assert fake_cli.commands == []

    service.close()
    assert created[0].closed
    assert created[0].close_calls == 2
    assert service._pending_cleanup == []


def test_tcp_proxy_preserves_binary_data_and_half_closes_with_bounded_copies():
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen()
    internal_port = upstream.getsockname()[1]
    received = bytearray()
    server_done = threading.Event()

    def serve():
        connection, _address = upstream.accept()
        with connection:
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
                connection.sendall(chunk)
        upstream.close()
        server_done.set()

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    proxy = DockerTCPProxy(SandboxPort("binary", internal_port))
    proxy.start("127.0.0.1")
    accept_thread = proxy._accept_thread
    payload = bytes(range(256)) * 1024
    echoed = bytearray()
    try:
        with socket.create_connection((proxy.binding.host, proxy.binding.host_port), timeout=5) as client:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                echoed.extend(chunk)
        assert server_done.wait(5)
        assert bytes(received) == payload
        assert bytes(echoed) == payload
        assert proxy.error is None
    finally:
        proxy.close()
    assert accept_thread is not None
    assert not accept_thread.is_alive()
    assert proxy._accept_thread is None


LIVE_DOCKER = os.environ.get("PWNC_SANDBOX_DOCKER_TESTS") == "1"


@pytest.mark.skipif(not LIVE_DOCKER, reason="set PWNC_SANDBOX_DOCKER_TESTS=1 for exact-ID Docker integration")
def test_live_four_containers_share_internal_port_with_unique_loopback_bindings(tmp_path):
    docker = shutil.which("docker")
    zig = shutil.which("zig")
    assert docker is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires docker"
    assert zig is not None, "PWNC_SANDBOX_DOCKER_TESTS=1 requires Zig"
    version = subprocess.run((docker, "version"), stdin=subprocess.DEVNULL, capture_output=True, check=False)
    assert version.returncode == 0, version.stderr.decode("utf-8", "replace")

    source = tmp_path / "probe.c"
    source.write_text(
        r"""
#include <arpa/inet.h>
#include <errno.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char start;
    char input[128];
    char output[256];
    struct sockaddr_in address = {0};
    struct __user_cap_header_struct cap_header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct cap_data[2] = {{0}};
    int enabled = 1;
    int default_route = 0;
    if (argc != 2) return 10;
    printf("BOOT %s\n", argv[1]);
    fflush(stdout);
    if (read(STDIN_FILENO, &start, 1) != 1) return 10;
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 11;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(31337);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) return 12;
    if (listen(server, 8) != 0) return 13;
    FILE *routes = fopen("/proc/net/route", "r");
    if (routes != NULL) {
        char route[512];
        while (fgets(route, sizeof(route), routes) != NULL) {
            char interface[64];
            unsigned long destination;
            if (sscanf(route, "%63s %lx", interface, &destination) == 2 && destination == 0) {
                default_route = 1;
            }
        }
        fclose(routes);
    }
    if (syscall(SYS_capget, &cap_header, &cap_data) != 0) return 15;
    unsigned long long effective = cap_data[0].effective | ((unsigned long long)cap_data[1].effective << 32);
    printf("READY %ld %ld %d %llu %d\n", (long)getuid(), (long)getgid(), prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
           effective, default_route);
    fflush(stdout);
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            return 14;
        }
        ssize_t length = read(client, input, sizeof(input));
        if (length > 0) {
            int written = snprintf(output, sizeof(output), "%s:%.*s", argv[1], (int)length, input);
            if (written > 0) write(client, output, (size_t)written);
        }
        close(client);
    }
}
""",
        encoding="utf-8",
    )
    probe = tmp_path / "probe"
    compile_result = subprocess.run(
        (zig, "cc", "-O2", "-static", "-o", os.fspath(probe), os.fspath(source)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    assert compile_result.returncode == 0, compile_result.stderr.decode("utf-8", "replace")
    (tmp_path / "Dockerfile").write_text(
        """FROM scratch
COPY probe /probe
ENTRYPOINT ["/hostile-image-entrypoint-must-not-run"]
HEALTHCHECK --interval=1s --timeout=1s --retries=1 CMD ["/hostile-image-healthcheck-must-not-run"]
VOLUME ["/anonymous"]
""",
        encoding="utf-8",
    )

    service = DockerBackend(session_id=f"live-{os.getpid()}-{os.urandom(4).hex()}", docker_executable=docker)
    instances = []
    anonymous_volumes: set[str] = set()
    image_ids: tuple[str, ...] = ()
    network_id = None
    try:
        docker_spec = DockerSpec(build_context=tmp_path)

        def spec(index: int) -> SandboxSpec:
            return SandboxSpec(
                command=("/probe", f"container-{index}"),
                docker=docker_spec,
                stdio=SandboxStdio.PIPE,
                ports=(SandboxPort("pwn", 31337),),
                allow_egress=False,
                profile="live",
            )

        # The four processes coexist on the same per-session internal network.
        # Each host listener asks the kernel for port zero while the container
        # remains attached only to Docker's true internal network.  No port is
        # preselected, scanned, or exposed directly by Docker.
        with ThreadPoolExecutor(max_workers=4) as executor:
            instances = list(executor.map(service.spawn, (spec(index) for index in range(4))))
        image_ids = service.built_image_ids
        network_id = service.internal_network_id

        host_ports = [instance.bindings["pwn"].host_port for instance in instances]
        assert len(set(host_ports)) == 4
        assert all(instance.bindings["pwn"].host == "127.0.0.1" for instance in instances)
        assert all(instance.host_pid > 1 for instance in instances)

        for instance in instances:
            assert instance.attach is not None
            assert instance.attach.stdin is not None
            assert instance.attach.stdout is not None
            boot = instance.attach.stdout.readline().decode("ascii").split()
            assert boot[0] == "BOOT"
            assert boot[1].startswith("container-")
            instance.attach.stdin.write(b"S")
            instance.attach.stdin.flush()
            fields = instance.attach.stdout.readline().decode("ascii").split()
            assert fields == ["READY", str(os.getuid()), str(os.getgid()), "1", "0", "0"]

        assert network_id is not None
        inspected_network = subprocess.run(
            (docker, "network", "inspect", network_id),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        assert inspected_network.returncode == 0, inspected_network.stderr.decode("utf-8", "replace")
        network_record = json.loads(inspected_network.stdout)[0]
        assert network_record["Internal"] is True
        assert network_record["Labels"]["io.pwnc.sandbox.session"] == service.session_id

        for instance in instances:
            inspected_container = subprocess.run(
                (docker, "inspect", instance.container_id),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
            )
            assert inspected_container.returncode == 0, inspected_container.stderr.decode("utf-8", "replace")
            container_record = json.loads(inspected_container.stdout)[0]
            host_config = container_record["HostConfig"]
            assert host_config["CapDrop"] == ["ALL"]
            assert host_config["CapAdd"] is None
            assert host_config["SecurityOpt"] == ["no-new-privileges=true"]
            assert host_config["UsernsMode"] == ""
            assert host_config["NetworkMode"] == network_id
            assert host_config["PortBindings"] == {}
            assert container_record["Config"]["Entrypoint"] == ["/probe"]
            assert container_record["Config"]["Healthcheck"]["Test"] == ["NONE"]
            volumes = [
                mount
                for mount in container_record["Mounts"]
                if mount["Type"] == "volume" and mount["Destination"] == "/anonymous"
            ]
            assert len(volumes) == 1
            anonymous_volumes.add(volumes[0]["Name"])

        for index, instance in enumerate(instances):
            binding = instance.bindings["pwn"]
            with socket.create_connection((binding.host, binding.host_port), timeout=5) as connection:
                connection.sendall(b"nonce")
                assert connection.recv(256) == f"container-{index}:nonce".encode()

        egress_instance = service.spawn(
            SandboxSpec(
                command=("/probe", "egress-container"),
                docker=docker_spec,
                stdio=SandboxStdio.PIPE,
                ports=(SandboxPort("pwn", 31337),),
                allow_egress=True,
                profile="live",
            )
        )
        instances.append(egress_instance)
        inspected_egress = subprocess.run(
            (docker, "inspect", egress_instance.container_id),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        assert inspected_egress.returncode == 0, inspected_egress.stderr.decode("utf-8", "replace")
        egress_record = json.loads(inspected_egress.stdout)[0]
        assert egress_record["Config"]["Entrypoint"] == ["/probe"]
        assert egress_record["Config"]["Healthcheck"]["Test"] == ["NONE"]
        egress_volumes = [
            mount
            for mount in egress_record["Mounts"]
            if mount["Type"] == "volume" and mount["Destination"] == "/anonymous"
        ]
        assert len(egress_volumes) == 1
        anonymous_volumes.add(egress_volumes[0]["Name"])
        assert len(anonymous_volumes) == len(instances)
        assert egress_instance.proxies == ()
        assert egress_instance.attach is not None
        assert egress_instance.attach.stdin is not None
        assert egress_instance.attach.stdout is not None
        assert egress_instance.attach.stdout.readline() == b"BOOT egress-container\n"
        egress_instance.attach.stdin.write(b"S")
        egress_instance.attach.stdin.flush()
        fields = egress_instance.attach.stdout.readline().decode("ascii").split()
        assert fields == ["READY", str(os.getuid()), str(os.getgid()), "1", "0", "1"]
        binding = egress_instance.bindings["pwn"]
        assert binding.host == "127.0.0.1"
        assert binding.host_port not in host_ports
        with socket.create_connection((binding.host, binding.host_port), timeout=5) as connection:
            connection.sendall(b"native")
            assert connection.recv(256) == b"egress-container:native"
    finally:
        try:
            if not image_ids:
                image_ids = service.built_image_ids
            service.close()
        except BaseException:
            # Preserve a failing exact-cleanup assertion without polluting the
            # developer's daemon for later tests.
            for instance in instances:
                subprocess.run(
                    (docker, "rm", "--force", "--volumes", instance.container_id),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            for image_id in image_ids:
                subprocess.run(
                    (docker, "image", "rm", image_id),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            raise

    assert network_id is not None
    assert service.built_image_ids == ()
    for instance in instances:
        result = subprocess.run(
            (docker, "inspect", instance.container_id),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        assert result.returncode != 0
    result = subprocess.run(
        (docker, "network", "inspect", network_id),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    assert result.returncode != 0
    remaining_volumes = []
    try:
        for volume_name in anonymous_volumes:
            result = subprocess.run(
                (docker, "volume", "inspect", volume_name),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                remaining_volumes.append(volume_name)
        assert remaining_volumes == []
    finally:
        for volume_name in remaining_volumes:
            subprocess.run(
                (docker, "volume", "rm", "--force", volume_name),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    remaining_images = []
    try:
        for image_id in image_ids:
            result = subprocess.run(
                (docker, "image", "inspect", image_id),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                remaining_images.append(image_id)
        assert remaining_images == []
    finally:
        # This runs only after observing daemon state, so it cannot make a
        # broken backend cleanup path pass while still keeping the live suite
        # self-cleaning on assertion failure.
        for image_id in remaining_images:
            subprocess.run(
                (docker, "image", "rm", image_id),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
