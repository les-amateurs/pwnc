from __future__ import annotations

import builtins
import json
import signal
import sys
from dataclasses import dataclass, field
from types import ModuleType, SimpleNamespace

import pytest

import pwnc.commands.sandbox as sandbox_cli
from pwnc.pwncli import get_main_parser, main


@dataclass
class _Binding:
    name: str = "pwn"
    protocol: str = "tcp"
    host: str = "127.0.0.1"
    host_port: int = 41001


@dataclass
class _Snapshot:
    id: str = "s-test"
    state: object = field(default_factory=lambda: SimpleNamespace(value="paused"))
    profile: str = "default"
    host_pid: int | None = 1234
    container_id: str | None = "0123456789abcdef"
    stdio: object = field(default_factory=lambda: SimpleNamespace(value="pty"))
    stdio_socket: str | None = "/tmp/stdio.sock"
    ports: tuple = field(default_factory=lambda: (_Binding(),))
    exit_code: int | None = None
    error: str | None = None

    def to_wire(self):
        return {
            "id": self.id,
            "profile": self.profile,
            "state": self.state.value,
            "host_pid": self.host_pid,
        }


class _Tube:
    def __init__(self):
        self.interactive_calls = 0
        self.closed = False

    def interactive(self):
        self.interactive_calls += 1

    def close(self):
        self.closed = True


class _Remote:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.id = snapshot.id
        self.calls = []
        self.network_tube = _Tube()
        self.stdio_tube = _Tube()

    def connect(self, port, *, timeout):
        self.calls.append(("connect", port, timeout))
        return self.network_tube

    def stdio(self, *, timeout):
        self.calls.append(("stdio", timeout))
        return self.stdio_tube

    def attach(self):
        self.calls.append(("attach",))
        return {"generation": 7, "pid": self.snapshot.host_pid}

    def resume(self):
        self.calls.append(("resume",))
        return self.snapshot

    def signal(self, signum):
        self.calls.append(("signal", signum))
        return self.snapshot

    def kill(self):
        self.calls.append(("kill",))
        return self.snapshot

    def wait(self, timeout):
        self.calls.append(("wait", timeout))
        return self.snapshot


class _Client:
    def __init__(self):
        self.snapshot = _Snapshot()
        self.remote = _Remote(self.snapshot)
        self.calls = []

    def start(self, profile, **overrides):
        self.calls.append(("start", profile, overrides))
        return self.remote

    def list(self):
        self.calls.append(("list",))
        return (self.snapshot,)

    def get(self, sandbox_id):
        self.calls.append(("get", sandbox_id))
        return self.remote

    def close_sandbox(self, sandbox_id):
        self.calls.append(("close", sandbox_id))
        return self.snapshot

    def shutdown(self):
        self.calls.append(("shutdown",))

    def ping(self):
        self.calls.append(("ping",))
        return {"backend": "docker", "version": 1}


def _args(*values):
    return get_main_parser().parse_args(["sandbox", *values])


def test_sandbox_parser_is_lazy_and_preserves_start_target_argv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    imported = []
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.startswith("pwnc.sandbox"):
            imported.append(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    parser = get_main_parser()
    positional = parser.parse_args(
        [
            "sandbox",
            "start",
            "--timeout",
            "45.5",
            "--paused",
            "--pty",
            "--env",
            "TOKEN=a=b",
            "debug",
            "--",
            "/challenge",
            "--mode",
            "hard",
        ]
    )
    named = parser.parse_args(["sandbox", "start", "--profile", "default", "--", "/challenge", "--flag"])

    assert imported == []
    assert not (tmp_path / "pwnc.toml").exists()
    assert positional.profile == "debug"
    assert positional.profile_override is None
    assert positional.paused is True
    assert positional.stdio == "pty"
    assert positional.timeout == 45.5
    assert positional.target_command == ["/challenge", "--mode", "hard"]
    assert named.profile is None
    assert named.profile_override == "default"
    assert named.timeout is None
    assert named.target_command == ["/challenge", "--flag"]


@pytest.mark.parametrize(
    "arguments",
    [
        ("manager", "--gdb-pol-size", "4"),
        ("list", "--jsno"),
        ("connect", "s-test", "pwn", "--timout", "1"),
    ],
)
def test_main_rejects_unconsumed_sandbox_arguments(arguments, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["pwnc", "sandbox", *arguments])

    with pytest.raises(SystemExit) as raised:
        main()

    assert raised.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_main_preserves_start_target_argv_and_shellc_extra_flags(tmp_path, monkeypatch):
    sandbox_calls = []

    def sandbox_command(args):
        sandbox_calls.append(args)
        return 23

    monkeypatch.setattr(sandbox_cli, "command", sandbox_command)
    monkeypatch.setattr(
        sys,
        "argv",
        ["pwnc", "sandbox", "start", "--pty", "debug", "--", "/challenge", "--hard"],
    )

    assert main() == 23
    assert sandbox_calls[0].target_command == ["/challenge", "--hard"]

    import pwnc.commands.shellc

    shellc_calls = []
    monkeypatch.setattr(
        pwnc.commands.shellc,
        "command",
        lambda args, extra: shellc_calls.append((args, extra)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["pwnc", "shellc", "zig", "input.c", "-o", str(tmp_path / "shellcode"), "-DVALUE=7"],
    )

    assert main() is None
    assert shellc_calls[0][0].files == ["input.c"]
    assert shellc_calls[0][1] == ["-DVALUE=7"]


def test_manager_parser_and_dispatch_use_exact_public_startup_contract(tmp_path, monkeypatch):
    calls = []
    manager_module = ModuleType("pwnc.sandbox.manager")

    def run_manager(**kwargs):
        calls.append(kwargs)
        return 19

    manager_module.run_manager = run_manager
    monkeypatch.setitem(sys.modules, "pwnc.sandbox.manager", manager_module)
    args = _args(
        "manager",
        "--socket",
        str(tmp_path / "manager.sock"),
        "--config",
        str(tmp_path / "pwnc.toml"),
        "--name",
        "local",
        "--gdb-pool-size",
        "4",
        "--gdb-name",
        "reserve",
        "--gdb-path",
        "/opt/gdb/bin/gdb",
        "--gdb-execute",
        "source /opt/gef.py",
        "--gdb-execute",
        "set pagination off",
        "--no-gdb-init",
    )

    assert sandbox_cli.command(args) == 19
    assert len(calls) == 1
    options = calls[0]
    setup = options.pop("gdb_setup")
    assert options == {
        "name": "local",
        "socket_path": tmp_path / "manager.sock",
        "config_path": tmp_path / "pwnc.toml",
        "gdb_pool_size": 4,
        "gdb_name": "reserve",
        "gdb_init": False,
        "gdb_path": "/opt/gdb/bin/gdb",
    }
    configured = []
    setup(SimpleNamespace(execute=configured.append))
    assert configured == ["source /opt/gef.py", "set pagination off"]


def test_manager_rejects_setup_commands_without_a_pool(monkeypatch):
    manager_module = ModuleType("pwnc.sandbox.manager")
    manager_module.run_manager = lambda **_kwargs: None
    monkeypatch.setitem(sys.modules, "pwnc.sandbox.manager", manager_module)

    with pytest.raises(RuntimeError, match="requires a nonzero"):
        sandbox_cli.command(_args("manager", "--gdb-execute", "show version"))


def test_start_forwards_only_explicit_overrides_and_emits_json(monkeypatch, capsys):
    client = _Client()
    monkeypatch.setattr(sandbox_cli, "_client", lambda _args: client)
    args = _args(
        "start",
        "--json",
        "--running",
        "--pipe",
        "--env",
        "A=first",
        "--env",
        "A=last",
        "--env",
        "EMPTY=",
        "debug",
        "--",
        "/challenge",
        "--verbose",
    )

    assert sandbox_cli.command(args) == 0
    assert client.calls == [
        (
            "start",
            "debug",
            {
                "command": ["/challenge", "--verbose"],
                "env": {"A": "last", "EMPTY": ""},
                "stdio": "pipe",
                "paused": False,
                "timeout": None,
            },
        )
    ]
    assert json.loads(capsys.readouterr().out) == client.snapshot.to_wire()


def test_start_forwards_explicit_timeout(monkeypatch):
    client = _Client()
    monkeypatch.setattr(sandbox_cli, "_client", lambda _args: client)

    assert sandbox_cli.command(_args("start", "--timeout", "300", "default")) == 0

    assert client.calls == [
        (
            "start",
            "default",
            {
                "command": None,
                "env": None,
                "stdio": None,
                "paused": None,
                "timeout": 300.0,
            },
        )
    ]


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (("start", "--profile", "one", "two"), "either positionally"),
        (("start", "default", "/challenge"), "must follow --"),
        (("start", "--"), "cannot be empty"),
        (("start", "--env", "INVALID"), "KEY=VALUE"),
        (("start", "--timeout", "-1"), "timeout cannot be negative"),
    ],
)
def test_start_rejects_ambiguous_or_invalid_overrides(values, message, monkeypatch):
    monkeypatch.setattr(sandbox_cli, "_client", lambda _args: _Client())
    args = get_main_parser().parse_known_args(["sandbox", *values])[0]

    with pytest.raises(RuntimeError, match=message):
        sandbox_cli.command(args)


def test_noninteractive_lifecycle_commands_use_remote_handle(monkeypatch, capsys):
    client = _Client()
    monkeypatch.setattr(sandbox_cli, "_client", lambda _args: client)

    for values in (
        ("list", "--json"),
        ("show", "s-test", "--json"),
        ("attach", "s-test", "--json"),
        ("resume", "s-test", "--json"),
        ("signal", "s-test", "TERM", "--json"),
        ("kill", "s-test", "--json"),
        ("wait", "s-test", "--timeout", "2.5", "--json"),
        ("close", "s-test", "--json"),
        ("check", "--json"),
        ("shutdown", "--json"),
    ):
        assert sandbox_cli.command(_args(*values)) == 0

    assert ("list",) in client.calls
    assert client.calls.count(("get", "s-test")) == 6
    assert ("close", "s-test") in client.calls
    assert ("ping",) in client.calls
    assert ("shutdown",) in client.calls
    assert ("attach",) in client.remote.calls
    assert ("resume",) in client.remote.calls
    assert ("signal", int(signal.SIGTERM)) in client.remote.calls
    assert ("kill",) in client.remote.calls
    assert ("wait", 2.5) in client.remote.calls
    lines = capsys.readouterr().out.splitlines()
    assert json.loads(lines[-2]) == {"backend": "docker", "version": 1}
    assert json.loads(lines[-1]) == {"ok": True}


def test_connect_and_stdio_interact_once_then_close_tubes(monkeypatch):
    client = _Client()
    monkeypatch.setattr(sandbox_cli, "_client", lambda _args: client)

    assert sandbox_cli.command(_args("connect", "s-test", "pwn", "--timeout", "3")) == 0
    assert sandbox_cli.command(_args("stdio", "s-test", "--timeout", "4")) == 0

    assert client.remote.calls == [("connect", "pwn", 3.0), ("stdio", 4.0)]
    assert client.remote.network_tube.interactive_calls == 1
    assert client.remote.network_tube.closed
    assert client.remote.stdio_tube.interactive_calls == 1
    assert client.remote.stdio_tube.closed


def test_human_snapshot_brackets_ipv6_port_hosts():
    snapshot = _Snapshot(ports=(_Binding(host="::1"),))

    assert "pwn=tcp://[::1]:41001" in sandbox_cli._snapshot_line(snapshot)


def test_client_discovery_options_and_main_dispatch_are_lazy(tmp_path, monkeypatch):
    calls = []

    class Client:
        @staticmethod
        def discover(**kwargs):
            calls.append(kwargs)
            return _Client()

    import pwnc.sandbox.client

    monkeypatch.setattr(pwnc.sandbox.client, "SandboxClient", Client)
    command_calls = []
    real_command = sandbox_cli.command

    def wrapped(args):
        command_calls.append(getattr(args, "subcommand.sandbox"))
        return real_command(args)

    monkeypatch.setattr(sandbox_cli, "command", wrapped)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "pwnc",
            "sandbox",
            "check",
            "--socket",
            str(tmp_path / "manager.sock"),
            "--config",
            str(tmp_path / "pwnc.toml"),
            "--name",
            "project",
            "--json",
        ],
    )

    assert main() == 0
    assert command_calls == ["check"]
    assert calls == [
        {
            "name": "project",
            "socket_path": tmp_path / "manager.sock",
            "config_path": tmp_path / "pwnc.toml",
        }
    ]
