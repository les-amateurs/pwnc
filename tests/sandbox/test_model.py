from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from pwnc.sandbox.model import (
    DockerSpec,
    QemuSpec,
    SandboxBackend,
    SandboxDebug,
    SandboxMount,
    SandboxPort,
    SandboxSnapshot,
    SandboxSpec,
    SandboxState,
    SandboxStdio,
)


def docker_spec():
    return DockerSpec(image="challenge@sha256:" + "1" * 64)


def test_spec_is_immutable_and_normalizes_collections(tmp_path):
    environment = {"A": "B"}
    spec = SandboxSpec(
        command=["/challenge", "arg"],
        docker=docker_spec(),
        stdio="pty",
        ports=[SandboxPort("pwn", 31337)],
        mounts=[SandboxMount(tmp_path, "/challenge", read_only=True)],
        env=environment,
    )
    environment["A"] = "changed"

    assert spec.command == ("/challenge", "arg")
    assert spec.stdio is SandboxStdio.PTY
    assert spec.env == {"A": "B"}
    assert spec.ports[0].bind_host == "127.0.0.1"
    with pytest.raises(TypeError):
        spec.env["C"] = "D"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.1", "localhost"])
def test_ports_reject_non_loopback_bindings(host):
    with pytest.raises(ValueError, match="loopback"):
        SandboxPort("pwn", 31337, bind_host=host)


def test_duplicate_port_names_and_mount_targets_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="port names"):
        SandboxSpec(
            command=("/challenge",),
            docker=docker_spec(),
            ports=(SandboxPort("same", 1), SandboxPort("same", 2)),
        )
    with pytest.raises(ValueError, match="mount targets"):
        SandboxSpec(
            command=("/challenge",),
            docker=docker_spec(),
            mounts=(
                SandboxMount(tmp_path, "/data"),
                SandboxMount(tmp_path / "other", "/data"),
            ),
        )


def test_docker_source_is_exactly_image_or_build_context(tmp_path):
    with pytest.raises(ValueError, match="exactly one"):
        DockerSpec()
    with pytest.raises(ValueError, match="exactly one"):
        DockerSpec(image="image", build_context=tmp_path)
    assert DockerSpec(build_context=tmp_path).build_context == tmp_path.absolute()


def test_mount_source_is_host_absolute_and_target_is_container_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mount = SandboxMount(Path("relative"), "/inside")
    assert mount.source == tmp_path / "relative"
    with pytest.raises(ValueError, match="absolute container"):
        SandboxMount(tmp_path, "relative")


def test_qemu_spec_is_immutable_and_normalizes_source():
    qemu = QemuSpec(
        architecture="aarch64",
        source="HOST",
        binary="qemu-aarch64-static",
        sysroot="/opt/aarch64-sysroot",
        guest_aslr=False,
    )

    assert qemu.source == "host"
    assert qemu.architecture == "aarch64"
    assert qemu.binary == "qemu-aarch64-static"
    assert qemu.sysroot == "/opt/aarch64-sysroot"
    assert qemu.guest_aslr is False
    with pytest.raises(FrozenInstanceError):
        qemu.source = "image"


def test_qemu_and_host_aslr_tri_state_defaults_and_explicit_values():
    default_qemu = QemuSpec("x86_64")
    default_spec = SandboxSpec(command=("/challenge",), docker=docker_spec())
    configured = SandboxSpec(
        command=("/challenge",),
        docker=docker_spec(),
        qemu=QemuSpec("riscv64", guest_aslr=True),
        host_aslr=False,
    )

    assert default_qemu.source == "auto"
    assert default_qemu.binary is None
    assert default_qemu.sysroot is None
    assert default_qemu.guest_aslr is None
    assert default_spec.qemu is None
    assert default_spec.host_aslr is None
    assert configured.qemu.guest_aslr is True
    assert configured.host_aslr is False


@pytest.mark.parametrize(
    ("arguments", "error", "match"),
    [
        ({"architecture": ""}, ValueError, "architecture"),
        ({"architecture": "not an architecture"}, ValueError, "architecture"),
        ({"architecture": "x86_64\0"}, ValueError, "architecture"),
        ({"architecture": 64}, TypeError, "architecture"),
        ({"architecture": "x86_64", "source": "container"}, ValueError, "source"),
        ({"architecture": "x86_64", "source": ""}, ValueError, "source"),
        ({"architecture": "x86_64", "source": 1}, TypeError, "source"),
        ({"architecture": "x86_64", "binary": ""}, ValueError, "binary"),
        ({"architecture": "x86_64", "binary": "qemu\0bad"}, ValueError, "binary"),
        ({"architecture": "x86_64", "binary": 1}, TypeError, "binary"),
        (
            {"architecture": "x86_64", "source": "image", "binary": "qemu-x86_64"},
            ValueError,
            "absolute container path",
        ),
        ({"architecture": "x86_64", "sysroot": ""}, ValueError, "sysroot"),
        ({"architecture": "x86_64", "sysroot": "root\0fs"}, ValueError, "sysroot"),
        ({"architecture": "x86_64", "sysroot": 1}, TypeError, "sysroot"),
        ({"architecture": "x86_64", "guest_aslr": 0}, TypeError, "guest_aslr"),
        ({"architecture": "x86_64", "guest_aslr": "false"}, TypeError, "guest_aslr"),
    ],
)
def test_qemu_spec_validation_is_strict(arguments, error, match):
    with pytest.raises(error, match=match):
        QemuSpec(**arguments)


@pytest.mark.parametrize("source", ["auto", "host", "image"])
def test_qemu_binary_and_sysroot_are_optional_for_every_source(source):
    qemu = QemuSpec(architecture="arm", source=source)

    assert qemu.binary is None
    assert qemu.sysroot is None


def test_sandbox_spec_rejects_untyped_qemu_and_nonboolean_host_aslr():
    with pytest.raises(TypeError, match="qemu"):
        SandboxSpec(command=("/challenge",), docker=docker_spec(), qemu={"architecture": "arm"})
    for value in (0, 1, "true"):
        with pytest.raises(TypeError, match="host_aslr"):
            SandboxSpec(command=("/challenge",), docker=docker_spec(), host_aslr=value)


def test_debug_descriptor_is_immutable_normalized_and_round_trips():
    debug = SandboxDebug(
        transport="TCP",
        architecture="aarch64",
        emulator="/usr/bin/qemu-aarch64",
        host="127.0.0.1",
        port=43137,
    )
    snapshot = SandboxSnapshot(
        id="s-qemu",
        profile="default",
        backend=SandboxBackend.DOCKER,
        state=SandboxState.PAUSED,
        created_at=1.0,
        debug=debug,
    )

    assert debug.transport == "tcp"
    assert debug.to_wire() == {
        "transport": "tcp",
        "architecture": "aarch64",
        "emulator": "/usr/bin/qemu-aarch64",
        "host": "127.0.0.1",
        "port": 43137,
    }
    assert SandboxSnapshot.from_wire(snapshot.to_wire()) == snapshot
    with pytest.raises(FrozenInstanceError):
        debug.port = 1


@pytest.mark.parametrize(
    ("arguments", "error", "match"),
    [
        (
            {"transport": "", "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1", "port": 1},
            ValueError,
            "transport",
        ),
        (
            {"transport": 1, "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1", "port": 1},
            TypeError,
            "transport",
        ),
        (
            {"transport": "tcp", "architecture": "bad arch", "emulator": "qemu", "host": "127.0.0.1", "port": 1},
            ValueError,
            "architecture",
        ),
        (
            {"transport": "tcp", "architecture": "arm", "emulator": "", "host": "127.0.0.1", "port": 1},
            ValueError,
            "emulator",
        ),
        ({"transport": "tcp", "architecture": "arm", "emulator": "qemu", "host": "", "port": 1}, ValueError, "host"),
        (
            {"transport": "tcp", "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1", "port": 0},
            ValueError,
            "port",
        ),
        (
            {"transport": "tcp", "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1", "port": 65536},
            ValueError,
            "port",
        ),
        (
            {"transport": "tcp", "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1", "port": True},
            TypeError,
            "port",
        ),
        (
            {"transport": "tcp", "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1", "port": "1"},
            TypeError,
            "port",
        ),
        (
            {"transport": "tcp\0", "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1", "port": 1},
            ValueError,
            "transport",
        ),
        (
            {"transport": "tcp", "architecture": "arm", "emulator": "qemu\0", "host": "127.0.0.1", "port": 1},
            ValueError,
            "emulator",
        ),
        (
            {"transport": "tcp", "architecture": "arm", "emulator": "qemu", "host": "127.0.0.1\0", "port": 1},
            ValueError,
            "host",
        ),
    ],
)
def test_debug_descriptor_validation_is_strict(arguments, error, match):
    with pytest.raises(error, match=match):
        SandboxDebug(**arguments)


def test_snapshot_wire_compatibility_defaults_missing_or_null_debug_to_none():
    snapshot = SandboxSnapshot(
        id="s-legacy",
        profile="default",
        backend="docker",
        state="running",
        created_at=1.0,
    )
    legacy = snapshot.to_wire()
    del legacy["debug"]

    assert SandboxSnapshot.from_wire(legacy).debug is None
    legacy["debug"] = None
    assert SandboxSnapshot.from_wire(legacy).debug is None

    with pytest.raises(TypeError, match="debug"):
        SandboxSnapshot(
            id="s-invalid",
            profile="default",
            backend="docker",
            state="running",
            created_at=1.0,
            debug={
                "transport": "tcp",
                "architecture": "arm",
                "emulator": "qemu-arm",
                "host": "127.0.0.1",
                "port": 1234,
            },
        )
