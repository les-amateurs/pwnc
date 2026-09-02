from __future__ import annotations

import os
from pathlib import Path

import pytest

from pwnc.sandbox.config import (
    load_profile,
    load_project_config,
    parse_project_config,
    resolve_project_config,
)
from pwnc.sandbox.errors import SandboxConfigError
from pwnc.sandbox.model import QemuSpec, SandboxBackend, SandboxStdio


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _minimal(profile: str = "default", *, image: str = "challenge:local") -> str:
    return f"""
[sandbox]
default-profile = {profile!r}

[sandbox.{profile}]
command = ["/challenge/run"]

[sandbox.{profile}.docker]
image = {image!r}
"""


def test_loads_complete_profile_and_resolves_every_host_path_from_config(tmp_path):
    project = tmp_path / "project"
    nested = project / "work" / "deeper"
    nested.mkdir(parents=True)
    path = _write(
        project / "pwnc.toml",
        """
[sandbox]
default-profile = "local"
socket = ".state/manager.sock"

[sandbox.local]
backend = "docker"
command = ["/challenge/run", "--flag", "two words"]
stdio = "pty"
cwd = "/challenge"
pause-at-exec = true
allow-egress = true
read-only-root = true
host-aslr = false

[sandbox.local.qemu]
source = "host"
architecture = "aarch64"
binary = "qemu-aarch64-static"
sysroot = "/opt/aarch64-sysroot"
guest-aslr = true

[sandbox.local.env]
FLAG = "value"
EMPTY = ""

[sandbox.local.docker]
build = "container/.."
dockerfile = "docker/Dockerfile.challenge"
pull = "always"
platform = "linux/amd64"
extra-args = ["--memory=128m"]

[[sandbox.local.ports]]
name = "pwn"
internal = 31337
protocol = "tcp"
bind = "::1"
host-port = 43133

[[sandbox.local.mounts]]
source = "fixtures/../flag.txt"
target = "/flag"
read-only = false
""",
    )

    loaded = load_project_config(start=nested)
    spec = loaded.profile()

    assert loaded.path == path.resolve()
    assert loaded.default_profile == "local"
    assert loaded.socket == (project / ".state" / "manager.sock").resolve()
    assert spec.profile == "local"
    assert spec.backend is SandboxBackend.DOCKER
    assert spec.command == ("/challenge/run", "--flag", "two words")
    assert spec.stdio is SandboxStdio.PTY
    assert spec.cwd == "/challenge"
    assert spec.pause_at_exec
    assert spec.allow_egress
    assert spec.read_only_root
    assert spec.host_aslr is False
    assert spec.qemu == QemuSpec(
        architecture="aarch64",
        source="host",
        binary="qemu-aarch64-static",
        sysroot="/opt/aarch64-sysroot",
        guest_aslr=True,
    )
    assert dict(spec.env) == {"FLAG": "value", "EMPTY": ""}
    assert spec.docker.image is None
    assert spec.docker.build_context == project.resolve()
    assert spec.docker.dockerfile == (project / "docker" / "Dockerfile.challenge").resolve()
    assert spec.docker.pull == "always"
    assert spec.docker.platform == "linux/amd64"
    assert spec.docker.extra_args == ("--memory=128m",)
    assert spec.ports[0].name == "pwn"
    assert spec.ports[0].internal_port == 31337
    assert spec.ports[0].bind_host == "::1"
    assert spec.ports[0].host_port == 43133
    assert spec.mounts[0].source == (project / "flag.txt").resolve()
    assert spec.mounts[0].target == "/flag"
    assert not spec.mounts[0].read_only

    with pytest.raises(TypeError):
        spec.env["NEW"] = "no"
    with pytest.raises(TypeError):
        loaded.profiles["new"] = spec


def test_image_profile_defaults_and_explicit_directory_resolution(tmp_path):
    path = _write(tmp_path / "pwnc.toml", _minimal())

    assert resolve_project_config(tmp_path) == path.resolve()
    loaded = load_project_config(tmp_path)
    spec = loaded.profile()
    assert spec.backend is SandboxBackend.DOCKER
    assert spec.stdio is SandboxStdio.PIPE
    assert spec.docker.image == "challenge:local"
    assert spec.docker.pull == "never"
    assert not spec.pause_at_exec
    assert not spec.allow_egress
    assert not spec.read_only_root
    assert spec.host_aslr is None
    assert spec.qemu is None
    assert not spec.ports
    assert not spec.mounts
    assert not spec.env
    assert load_profile(config_path=path) == spec


def test_profile_selection_and_helpful_available_profile_error(tmp_path):
    path = _write(
        tmp_path / "pwnc.toml",
        _minimal("first", image="one")
        + """
[sandbox.second]
command = ["/second"]

[sandbox.second.docker]
image = "two"
""",
    )
    loaded = load_project_config(path)
    assert loaded.profile().docker.image == "one"
    assert loaded.profile("second").docker.image == "two"
    with pytest.raises(SandboxConfigError, match="available profiles: first, second"):
        loaded.profile("missing")


def test_resolution_is_project_only_read_only_and_never_creates_config(tmp_path, monkeypatch):
    project = tmp_path / "empty"
    project.mkdir()
    monkeypatch.chdir(project)

    with pytest.raises(SandboxConfigError, match="could not find pwnc.toml"):
        resolve_project_config()
    with pytest.raises(SandboxConfigError, match="could not find pwnc.toml"):
        load_project_config()
    assert not (project / "pwnc.toml").exists()


def test_nearest_project_wins_and_explicit_relative_path_uses_cwd(tmp_path, monkeypatch):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    nested = inner / "a" / "b"
    nested.mkdir(parents=True)
    outer_config = _write(outer / "pwnc.toml", _minimal(image="outer"))
    inner_config = _write(inner / "pwnc.toml", _minimal(image="inner"))

    assert resolve_project_config(start=nested) == inner_config.resolve()
    monkeypatch.chdir(outer)
    assert resolve_project_config("pwnc.toml") == outer_config.resolve()


@pytest.mark.parametrize(
    ("data", "match"),
    [
        ({}, r"\[sandbox\]: table is missing"),
        ({"sandbox": []}, r"\[sandbox\]: must be a TOML table"),
        ({"sandbox": {}}, "must define at least one"),
        (
            {"sandbox": {"default-profile": "missing", "x": {"command": ["x"], "docker": {"image": "x"}}}},
            "profile 'missing' does not exist",
        ),
        ({"sandbox": {"typo": True}}, "unknown setting 'typo'"),
        (
            {"sandbox": {"default": {"command": ["x"], "docker": {"image": "x"}, "typo": 1}}},
            r"unknown key\(s\): 'typo'",
        ),
        (
            {"sandbox": {"default": {"command": ["x"], "docker": {"image": "x", "typo": 1}}}},
            r"unknown key\(s\): 'typo'",
        ),
        (
            {
                "sandbox": {
                    "default": {
                        "command": ["x"],
                        "docker": {"image": "x"},
                        "ports": [{"name": "pwn", "internal": 1, "typo": 1}],
                    }
                }
            },
            r"unknown key\(s\): 'typo'",
        ),
        (
            {
                "sandbox": {
                    "default": {
                        "command": ["x"],
                        "docker": {"image": "x"},
                        "qemu": {"architecture": "arm", "typo": 1},
                    }
                }
            },
            r"unknown key\(s\): 'typo'",
        ),
        (
            {
                "sandbox": {
                    "default": {
                        "command": ["x"],
                        "docker": {"image": "x"},
                        "mounts": [{"source": ".", "target": "/x", "typo": 1}],
                    }
                }
            },
            r"unknown key\(s\): 'typo'",
        ),
    ],
)
def test_structure_and_unknown_keys_are_strict(data, match, tmp_path):
    with pytest.raises(SandboxConfigError, match=match):
        parse_project_config(data, tmp_path / "pwnc.toml")


@pytest.mark.parametrize(
    ("profile", "match"),
    [
        ({"docker": {"image": "x"}}, "missing required key 'command'"),
        ({"command": "x", "docker": {"image": "x"}}, "command: must be a TOML array"),
        ({"command": [], "docker": {"image": "x"}}, "sandbox command cannot be empty"),
        ({"command": [1], "docker": {"image": "x"}}, r"command\[0\]: must be text"),
        ({"command": ["x"]}, "missing required key 'docker'"),
        ({"command": ["x"], "docker": {}}, "exactly one of image or build_context"),
        (
            {"command": ["x"], "docker": {"image": "x", "build": "."}},
            "exactly one of image or build_context",
        ),
        (
            {"command": ["x"], "docker": {"image": "x", "dockerfile": "Dockerfile"}},
            "dockerfile requires a build context",
        ),
        ({"command": ["x"], "docker": {"image": "x"}, "backend": "nsjail"}, "unsupported sandbox backend"),
        ({"command": ["x"], "docker": {"image": "x"}, "stdio": "terminal"}, "unsupported sandbox stdio"),
        ({"command": ["x"], "docker": {"image": "x"}, "env": []}, "env: must be a TOML table"),
        ({"command": ["x"], "docker": {"image": "x"}, "pause-at-exec": 1}, "must be true or false"),
        ({"command": ["x"], "docker": {"image": "x"}, "host-aslr": 1}, "must be true or false"),
        ({"command": ["x"], "docker": {"image": "x"}, "qemu": True}, "qemu: must be a TOML table"),
        (
            {"command": ["x"], "docker": {"image": "x"}, "qemu": {}},
            "missing required key 'architecture'",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "arm", "source": "container"},
            },
            "QEMU source must be auto, host, or image",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "bad architecture"},
            },
            "QEMU architecture",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "arm", "source": "image", "binary": "qemu-arm"},
            },
            "absolute container path",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "arm", "binary": ""},
            },
            "QEMU binary cannot be empty",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "arm", "binary": 1},
            },
            "QEMU binary must be text",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "arm", "sysroot": ""},
            },
            "QEMU sysroot cannot be empty",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "arm", "sysroot": 1},
            },
            "QEMU sysroot must be text",
        ),
        (
            {
                "command": ["x"],
                "docker": {"image": "x"},
                "qemu": {"architecture": "arm", "guest-aslr": 0},
            },
            "guest-aslr: must be true or false",
        ),
    ],
)
def test_invalid_profile_values_have_field_context(profile, match, tmp_path):
    with pytest.raises(SandboxConfigError, match=match):
        parse_project_config({"sandbox": {"default": profile}}, tmp_path / "pwnc.toml")


def test_duplicate_port_names_and_mount_targets_are_rejected(tmp_path):
    base = {"command": ["x"], "docker": {"image": "x"}}
    duplicate_ports = dict(
        base,
        ports=[
            {"name": "pwn", "internal": 1},
            {"name": "pwn", "internal": 2},
        ],
    )
    with pytest.raises(SandboxConfigError, match="port names must be unique"):
        parse_project_config({"sandbox": {"default": duplicate_ports}}, tmp_path / "pwnc.toml")

    duplicate_mounts = dict(
        base,
        mounts=[
            {"source": "one", "target": "/data"},
            {"source": "two", "target": "/data"},
        ],
    )
    with pytest.raises(SandboxConfigError, match="mount targets must be unique"):
        parse_project_config({"sandbox": {"default": duplicate_mounts}}, tmp_path / "pwnc.toml")


def test_invalid_toml_is_reported_as_sandbox_config_error(tmp_path):
    path = _write(tmp_path / "pwnc.toml", "[sandbox\n")
    with pytest.raises(SandboxConfigError, match="could not read project config"):
        load_project_config(path)


def test_config_path_must_be_existing_pwnc_file(tmp_path):
    wrong = _write(tmp_path / "other.toml", _minimal())
    with pytest.raises(SandboxConfigError, match="must be named pwnc.toml"):
        resolve_project_config(wrong)
    with pytest.raises(SandboxConfigError, match="does not exist"):
        resolve_project_config(tmp_path / "pwnc.toml")
    with pytest.raises(TypeError, match="path-like"):
        resolve_project_config(True)


def test_tilde_paths_expand_before_config_relative_resolution(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", os.fspath(fake_home))
    data = {
        "sandbox": {
            "default": {
                "command": ["x"],
                "docker": {"build": "~/build", "dockerfile": "~/Dockerfile"},
                "mounts": [{"source": "~/flag", "target": "/flag"}],
            }
        }
    }
    spec = parse_project_config(data, tmp_path / "project" / "pwnc.toml").profile()
    assert spec.docker.build_context == fake_home / "build"
    assert spec.docker.dockerfile == fake_home / "Dockerfile"
    assert spec.mounts[0].source == fake_home / "flag"


@pytest.mark.parametrize("source", ["auto", "host", "image"])
@pytest.mark.parametrize("guest_aslr", [None, True, False])
@pytest.mark.parametrize("host_aslr", [None, True, False])
def test_qemu_source_and_aslr_tri_states_parse_exhaustively(source, guest_aslr, host_aslr, tmp_path):
    profile = {
        "command": ["/guest"],
        "docker": {"image": "challenge"},
        "qemu": {"architecture": "mipsel", "source": source},
    }
    if source == "image":
        profile["qemu"]["binary"] = "/usr/bin/qemu-mipsel"
    else:
        profile["qemu"]["binary"] = "qemu-mipsel-static"
    if guest_aslr is not None:
        profile["qemu"]["guest-aslr"] = guest_aslr
    if host_aslr is not None:
        profile["host-aslr"] = host_aslr

    spec = parse_project_config({"sandbox": {"default": profile}}, tmp_path / "pwnc.toml").profile()

    assert spec.qemu is not None
    assert spec.qemu.source == source
    assert spec.qemu.architecture == "mipsel"
    assert spec.qemu.guest_aslr is guest_aslr
    assert spec.host_aslr is host_aslr


def test_qemu_table_presence_enables_auto_mode_and_preserves_backend_resolved_strings(tmp_path):
    profile = {
        "command": ["/guest"],
        "docker": {"image": "challenge"},
        "qemu": {
            "architecture": "riscv64",
            "binary": "tools/qemu-riscv64-static",
            "sysroot": "sysroots/riscv64",
        },
    }

    spec = parse_project_config({"sandbox": {"default": profile}}, tmp_path / "pwnc.toml").profile()

    assert spec.qemu == QemuSpec(
        architecture="riscv64",
        source="auto",
        binary="tools/qemu-riscv64-static",
        sysroot="sysroots/riscv64",
    )


@pytest.mark.parametrize("source", ["auto", "host", "image"])
def test_qemu_binary_and_sysroot_can_be_omitted_for_every_source(source, tmp_path):
    profile = {
        "command": ["/guest"],
        "docker": {"image": "challenge"},
        "qemu": {"architecture": "arm", "source": source},
    }

    spec = parse_project_config({"sandbox": {"default": profile}}, tmp_path / "pwnc.toml").profile()

    assert spec.qemu == QemuSpec(architecture="arm", source=source)
