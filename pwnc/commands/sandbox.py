"""Command-line interface for the persistent local sandbox manager."""

from __future__ import annotations

import json
import signal
from collections.abc import Mapping


def _manager(args):
    # Manager startup pulls in Docker, the ptrace shim, and optionally GDB.  It
    # must stay out of parser construction and unrelated pwnc commands.
    from pwnc.sandbox.manager import run_manager

    setup_commands = tuple(args.gdb_execute or ())
    for setup_command in setup_commands:
        if not setup_command or "\0" in setup_command:
            raise ValueError("GDB setup commands must be nonempty text without NUL")
    if setup_commands and not args.gdb_pool_size:
        raise ValueError("--gdb-execute requires a nonzero --gdb-pool-size")

    def configure(gdb):
        for setup_command in setup_commands:
            gdb.execute(setup_command)

    return run_manager(
        name=args.name,
        socket_path=args.socket_path,
        config_path=args.config_path,
        gdb_pool_size=args.gdb_pool_size,
        gdb_name=args.gdb_name,
        gdb_init=args.gdb_init,
        gdb_setup=configure if setup_commands else None,
        gdb_path=args.gdb_path,
    )


def _client(args):
    from pwnc.sandbox.client import SandboxClient

    return SandboxClient.discover(
        name=args.name,
        socket_path=args.socket_path,
        config_path=args.config_path,
    )


def _json(value) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _snapshot_line(snapshot) -> str:
    parts = [snapshot.id, snapshot.state.value, f"profile={snapshot.profile}"]
    if snapshot.host_pid is not None:
        parts.append(f"pid={snapshot.host_pid}")
    if snapshot.container_id is not None:
        parts.append(f"container={snapshot.container_id[:12]}")
    if snapshot.stdio_socket is not None:
        parts.append(f"stdio={snapshot.stdio.value}:{snapshot.stdio_socket}")
    elif snapshot.stdio.value != "none":
        parts.append(f"stdio={snapshot.stdio.value}")
    for binding in snapshot.ports:
        host = f"[{binding.host}]" if ":" in binding.host else binding.host
        parts.append(f"{binding.name}={binding.protocol}://{host}:{binding.host_port}")
    debug = getattr(snapshot, "debug", None)
    if debug is not None:
        host = f"[{debug.host}]" if ":" in debug.host else debug.host
        parts.append(f"debug={debug.transport}://{host}:{debug.port}({debug.architecture})")
    if snapshot.exit_code is not None:
        parts.append(f"exit={snapshot.exit_code}")
    if snapshot.error is not None:
        parts.append(f"error={snapshot.error!r}")
    return " ".join(parts)


def _emit_snapshot(snapshot, *, as_json: bool) -> None:
    if as_json:
        _json(snapshot.to_wire())
    else:
        print(_snapshot_line(snapshot))


def _emit_snapshots(snapshots, *, as_json: bool) -> None:
    if as_json:
        _json([snapshot.to_wire() for snapshot in snapshots])
    else:
        for snapshot in snapshots:
            print(_snapshot_line(snapshot))


def _emit_mapping(value: Mapping, *, as_json: bool, prefix: str) -> None:
    if as_json:
        _json(dict(value))
        return
    details = " ".join(f"{key}={item}" for key, item in sorted(value.items()))
    print(prefix if not details else f"{prefix} {details}")


def _environment(values) -> dict[str, str] | None:
    if values is None:
        return None
    result = {}
    for assignment in values:
        key, separator, value = assignment.partition("=")
        if not separator or not key:
            raise ValueError(f"environment override must be KEY=VALUE: {assignment!r}")
        if "\0" in key or "\0" in value:
            raise ValueError("environment override cannot contain NUL")
        result[key] = value
    return result


def _start_arguments(args):
    if args.profile_override is not None and args.profile is not None:
        raise ValueError("specify the sandbox profile either positionally or with --profile, not both")
    if args.sandbox_unparsed:
        rendered = " ".join(args.sandbox_unparsed)
        raise ValueError(f"target command must follow -- (unparsed: {rendered})")
    command = args.target_command
    if command == []:
        raise ValueError("target command after -- cannot be empty")
    profile = args.profile_override if args.profile_override is not None else args.profile
    return profile, command, _environment(args.env)


def _signal_number(value: str) -> int:
    try:
        number = int(value, 0)
    except ValueError:
        name = value.upper()
        if not name.startswith("SIG"):
            name = f"SIG{name}"
        try:
            number = int(getattr(signal, name))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError(f"unknown signal: {value!r}") from error
    if number <= 0:
        raise ValueError("signal number must be positive")
    return number


def _timeout(value):
    if value is not None and value < 0:
        raise ValueError("timeout cannot be negative")
    return value


def _interactive(tube) -> None:
    try:
        tube.interactive()
    finally:
        tube.close()


def _dispatch(args):
    operation = getattr(args, "subcommand.sandbox")
    if operation == "manager":
        return _manager(args)

    client = _client(args)
    if operation == "start":
        profile, target_command, environment = _start_arguments(args)
        sandbox = client.start(
            profile,
            command=target_command,
            env=environment,
            stdio=args.stdio,
            paused=args.paused,
            timeout=_timeout(args.timeout),
        )
        _emit_snapshot(sandbox.snapshot, as_json=args.json)
    elif operation == "list":
        _emit_snapshots(client.list(), as_json=args.json)
    elif operation == "show":
        sandbox = client.get(args.sandbox_id)
        _emit_snapshot(sandbox.snapshot, as_json=args.json)
    elif operation == "connect":
        sandbox = client.get(args.sandbox_id)
        _interactive(sandbox.connect(args.port, timeout=_timeout(args.timeout)))
    elif operation == "stdio":
        sandbox = client.get(args.sandbox_id)
        _interactive(sandbox.stdio(timeout=_timeout(args.timeout)))
    elif operation == "attach":
        sandbox = client.get(args.sandbox_id)
        result = sandbox.attach()
        _emit_mapping(result, as_json=args.json, prefix=f"{sandbox.id}: GDB attached")
    elif operation == "resume":
        sandbox = client.get(args.sandbox_id)
        _emit_snapshot(sandbox.resume(), as_json=args.json)
    elif operation == "signal":
        sandbox = client.get(args.sandbox_id)
        _emit_snapshot(sandbox.signal(_signal_number(args.signal)), as_json=args.json)
    elif operation == "kill":
        sandbox = client.get(args.sandbox_id)
        _emit_snapshot(sandbox.kill(), as_json=args.json)
    elif operation in {"stop", "close"}:
        snapshot = client.close_sandbox(args.sandbox_id)
        _emit_snapshot(snapshot, as_json=args.json)
    elif operation == "wait":
        sandbox = client.get(args.sandbox_id)
        _emit_snapshot(sandbox.wait(_timeout(args.timeout)), as_json=args.json)
    elif operation == "shutdown":
        client.shutdown()
        if args.json:
            _json({"ok": True})
        else:
            print("sandbox manager stopped")
    elif operation == "check":
        result = client.ping()
        _emit_mapping(result, as_json=args.json, prefix="sandbox manager available")
    else:  # pragma: no cover - argparse owns the operation vocabulary.
        raise RuntimeError(f"unsupported sandbox command: {operation}")
    return 0


def command(args):
    operation = getattr(args, "subcommand.sandbox", "command")
    try:
        return _dispatch(args)
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        raise RuntimeError(f"sandbox {operation}: {error}") from error


__all__ = ["command"]
