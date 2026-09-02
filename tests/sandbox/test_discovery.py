from __future__ import annotations

import os
import socket
import stat
import threading
from pathlib import Path

import pytest
import toml

from pwnc import config as project_config
from pwnc.sandbox.discovery import (
    DISCOVERY_NAMESPACE,
    MAX_UNIX_SOCKET_PATH_BYTES,
    SandboxManagerAddress,
    acquire_manager_socket,
    discover_client,
    discover_manager,
)
from pwnc.sandbox.errors import SandboxAlreadyRunningError, SandboxDiscoveryError


def _write(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _seeded(path: Path, seed: str = "01" * 16, extra: str = "") -> Path:
    return _write(path, f'[pwnc]\nseed = "{seed}"\n{extra}')


def test_explicit_socket_is_a_complete_override_and_never_creates_config(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)

    manager = discover_manager(socket_path="state/manager.sock")
    client = discover_client(socket_path="state/manager.sock")
    expected = project / "state" / "manager.sock"
    assert manager == client == SandboxManagerAddress(expected, "explicit")
    assert manager.socket_path == expected
    assert manager.config_path is None
    assert not (project / "pwnc.toml").exists()


def test_manager_lazily_creates_seed_and_client_derives_identical_address(tmp_path):
    project = tmp_path / "project"
    runtime = tmp_path / "runtime"
    project.mkdir()

    manager = discover_manager(start=project, runtime_dir=runtime)
    config_path = project / "pwnc.toml"
    assert config_path.is_file()
    data = toml.load(config_path)
    seed = data["pwnc"]["seed"]
    assert len(seed) == 32
    assert bytes.fromhex(seed)
    assert manager.source == "derived"
    assert manager.config_path == config_path.resolve()
    assert manager.project_root == project.resolve()
    assert manager.seed == seed
    assert manager.runtime_dir == runtime.absolute()
    assert manager.path.parent == runtime.absolute()
    assert manager.path.name.startswith("s-")
    assert manager.path.suffix == ".sock"
    assert DISCOVERY_NAMESPACE == "pwnc.sandbox.manager"
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700

    before = config_path.read_bytes()
    client = discover_client(start=project, runtime_dir=runtime)
    assert client == manager
    assert config_path.read_bytes() == before


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            b'# project comment\n[sandbox]\n# keep this spacing\nsocket = "run/manager.sock"\n',
            (
                b'# project comment\n[sandbox]\n# keep this spacing\nsocket = "run/manager.sock"\n\n'
                b'[pwnc]\nseed = "abababababababababababababababab"\n'
            ),
        ),
        (
            b'# project comment\r\n[pwnc] # rendezvous\r\n# keep this here\r\nname = "demo"\r\n',
            (
                b"# project comment\r\n[pwnc] # rendezvous\r\n"
                b'seed = "abababababababababababababababab"\r\n# keep this here\r\nname = "demo"\r\n'
            ),
        ),
    ],
)
def test_manager_seed_insertion_preserves_existing_toml_text(source, expected, tmp_path, monkeypatch):
    path = tmp_path / "project" / "pwnc.toml"
    path.parent.mkdir()
    path.write_bytes(source)
    monkeypatch.setattr(project_config.secrets, "token_hex", lambda _size: "ab" * 16)

    discover_manager(config_path=path, runtime_dir=tmp_path / "runtime")

    assert path.read_bytes() == expected


def test_client_lookup_never_creates_a_project_or_seed(tmp_path):
    missing = tmp_path / "missing"
    missing.mkdir()
    with pytest.raises(SandboxDiscoveryError, match="could not find pwnc.toml"):
        discover_client(start=missing, runtime_dir=tmp_path / "runtime")
    assert not (missing / "pwnc.toml").exists()

    path = _write(tmp_path / "existing" / "pwnc.toml", "[sandbox]\n")
    before = path.read_bytes()
    with pytest.raises(SandboxDiscoveryError, match=r"no \[pwnc\]\.seed"):
        discover_client(config_path=path, runtime_dir=tmp_path / "runtime")
    assert path.read_bytes() == before


def test_configured_socket_is_relative_to_project_and_client_does_not_need_seed(tmp_path):
    path = _write(
        tmp_path / "project" / "pwnc.toml",
        '[sandbox]\nsocket = "run/sandbox.sock"\n',
    )
    before = path.read_bytes()
    client = discover_client(config_path=path)
    assert client.path == (path.parent / "run" / "sandbox.sock").resolve()
    assert client.source == "config"
    assert client.seed is None
    assert path.read_bytes() == before

    manager = discover_manager(config_path=path)
    assert manager.path == client.path
    assert manager.source == "config"
    assert "seed" in toml.load(path)["pwnc"]


def test_derived_name_depends_on_seed_and_canonical_config_path(tmp_path):
    runtime = tmp_path / "runtime"
    first = _seeded(tmp_path / "one" / "pwnc.toml", "11" * 16)
    second = _seeded(tmp_path / "two" / "pwnc.toml", "11" * 16)
    third = _seeded(tmp_path / "three" / "pwnc.toml", "22" * 16)

    one = discover_client(config_path=first, runtime_dir=runtime)
    two = discover_client(config_path=second, runtime_dir=runtime)
    three = discover_client(config_path=third, runtime_dir=runtime)
    assert one.path != two.path
    assert one.path != three.path
    assert two.path != three.path
    assert discover_client(config_path=first, runtime_dir=runtime) == one


def test_logical_manager_name_is_validated_and_part_of_derivation(tmp_path):
    path = _seeded(tmp_path / "project" / "pwnc.toml")
    runtime = tmp_path / "runtime"
    first = discover_client("first", config_path=path, runtime_dir=runtime)
    second = discover_client("second", config_path=path, runtime_dir=runtime)
    assert first.name == "first"
    assert second.name == "second"
    assert first.path != second.path
    with pytest.raises(ValueError, match="cannot be empty"):
        discover_client("", config_path=path)
    with pytest.raises(TypeError, match="manager name must be text"):
        discover_client(True, config_path=path)


def test_nearest_project_lookup_is_stable_from_nested_directory(tmp_path):
    outer = _seeded(tmp_path / "outer" / "pwnc.toml", "10" * 16)
    inner = _seeded(tmp_path / "outer" / "inner" / "pwnc.toml", "20" * 16)
    nested = inner.parent / "a" / "b"
    nested.mkdir(parents=True)

    found = discover_client(start=nested, runtime_dir=tmp_path / "runtime")
    explicit = discover_client(config_path=inner, runtime_dir=tmp_path / "runtime")
    outer_address = discover_client(config_path=outer, runtime_dir=tmp_path / "runtime")
    assert found == explicit
    assert found != outer_address


def test_invalid_seed_and_socket_configuration_are_helpful_and_read_only(tmp_path):
    bad_seed = _seeded(tmp_path / "bad-seed" / "pwnc.toml", "not-a-seed")
    seed_before = bad_seed.read_bytes()
    with pytest.raises(SandboxDiscoveryError, match="seed is invalid"):
        discover_client(config_path=bad_seed, runtime_dir=tmp_path / "runtime")
    assert bad_seed.read_bytes() == seed_before

    bad_socket = _write(
        tmp_path / "bad-socket" / "pwnc.toml",
        "[sandbox]\nsocket = 3\n",
    )
    socket_before = bad_socket.read_bytes()
    with pytest.raises(SandboxDiscoveryError, match=r"\[sandbox\]\.socket: must be text"):
        discover_client(config_path=bad_socket)
    assert bad_socket.read_bytes() == socket_before


def test_runtime_directory_must_be_private_and_same_uid(tmp_path):
    path = _seeded(tmp_path / "project" / "pwnc.toml")
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o755)

    with pytest.raises(SandboxDiscoveryError, match="mode 0700"):
        discover_manager(config_path=path, runtime_dir=runtime)
    with pytest.raises(SandboxDiscoveryError, match="mode 0700"):
        discover_client(config_path=path, runtime_dir=runtime)


def test_socket_path_portable_limit_is_checked_before_binding(tmp_path):
    too_long = tmp_path / ("x" * MAX_UNIX_SOCKET_PATH_BYTES) / "manager.sock"
    with pytest.raises(ValueError, match="portable limit"):
        discover_manager(socket_path=too_long)


def test_lease_binds_private_socket_duplicates_listener_and_cleans_identity(tmp_path):
    directory = tmp_path / "run"
    directory.mkdir(mode=0o700)
    address = SandboxManagerAddress(directory / "manager.sock", "explicit")

    lease = acquire_manager_socket(address, backlog=3)
    duplicate = lease.duplicate_socket()
    try:
        assert lease.socket.getsockname() == os.fspath(address.path)
        assert duplicate.getsockname() == os.fspath(address.path)
        assert not lease.socket.get_inheritable()
        assert not duplicate.get_inheritable()
        info = address.path.lstat()
        assert stat.S_ISSOCK(info.st_mode)
        assert info.st_uid == os.getuid()
        assert stat.S_IMODE(info.st_mode) == 0o600
        lock = address.lock_path.lstat()
        assert stat.S_ISREG(lock.st_mode)
        assert lock.st_uid == os.getuid()
        assert stat.S_IMODE(lock.st_mode) == 0o600
    finally:
        duplicate.close()
        lease.close()

    assert lease.closed
    assert not address.path.exists()
    assert address.lock_path.is_file()
    lease.close()
    with pytest.raises(SandboxDiscoveryError, match="lease is closed"):
        _ = lease.socket
    with pytest.raises(SandboxDiscoveryError, match="lease is closed"):
        lease.duplicate_socket()


def test_lease_is_exclusive_then_reacquirable_after_close(tmp_path):
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    first = acquire_manager_socket(address)
    try:
        with pytest.raises(SandboxAlreadyRunningError, match="already owns"):
            acquire_manager_socket(address)
    finally:
        first.close()

    with acquire_manager_socket(address) as second:
        assert second.socket.fileno() >= 0
    assert not address.path.exists()


def test_concurrent_acquire_has_exactly_one_winner(tmp_path):
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    leases = []
    errors = []

    def acquire():
        barrier.wait()
        try:
            result = acquire_manager_socket(address)
        except BaseException as error:  # noqa: BLE001 - collect thread result
            with lock:
                errors.append(error)
        else:
            with lock:
                leases.append(result)

    threads = [threading.Thread(target=acquire) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    try:
        assert all(not thread.is_alive() for thread in threads)
        assert len(leases) == 1
        assert len(errors) == 7
        assert all(isinstance(error, SandboxAlreadyRunningError) for error in errors)
    finally:
        for lease in leases:
            lease.close()


def test_concurrent_manager_discovery_creates_one_stable_seed(tmp_path):
    project = tmp_path / "project"
    runtime = tmp_path / "runtime"
    project.mkdir()
    barrier = threading.Barrier(12)
    lock = threading.Lock()
    addresses = []
    errors = []

    def discover():
        barrier.wait()
        try:
            result = discover_manager(start=project, runtime_dir=runtime)
        except BaseException as error:  # noqa: BLE001 - collect thread result
            with lock:
                errors.append(error)
        else:
            with lock:
                addresses.append(result)

    threads = [threading.Thread(target=discover) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert all(not thread.is_alive() for thread in threads)
    assert not errors
    assert len(addresses) == 12
    assert len(set(addresses)) == 1
    seed = toml.load(project / "pwnc.toml")["pwnc"]["seed"]
    assert seed == addresses[0].seed


def test_stale_owned_socket_is_replaced_but_regular_file_is_preserved(tmp_path):
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(os.fspath(address.path))
    stale.close()
    with acquire_manager_socket(address) as lease:
        assert stat.S_ISSOCK(address.path.lstat().st_mode)
        assert lease.socket.fileno() >= 0

    address.path.write_text("do not remove")
    with pytest.raises(SandboxDiscoveryError, match="refusing to replace"):
        acquire_manager_socket(address)
    assert address.path.read_text() == "do not remove"


def test_close_does_not_unlink_a_replacement_socket(tmp_path):
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    lease = acquire_manager_socket(address)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        address.path.unlink()
        replacement.bind(os.fspath(address.path))
        replacement_identity = address.path.lstat().st_ino
        lease.close()
        assert address.path.is_socket()
        assert address.path.lstat().st_ino == replacement_identity
    finally:
        replacement.close()
        try:
            address.path.unlink()
        except FileNotFoundError:
            pass


def test_insecure_lock_file_and_missing_parent_fail_closed(tmp_path):
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    address.lock_path.write_text("lock")
    address.lock_path.chmod(0o644)
    with pytest.raises(SandboxDiscoveryError, match="private regular file"):
        acquire_manager_socket(address)
    assert not address.path.exists()

    missing = SandboxManagerAddress(tmp_path / "missing" / "manager.sock", "explicit")
    with pytest.raises(SandboxDiscoveryError, match="parent directory does not exist"):
        acquire_manager_socket(missing)


@pytest.mark.parametrize("backlog", [True, False, 0, -1, 1.5, "2"])
def test_backlog_validation(backlog, tmp_path):
    address = SandboxManagerAddress(tmp_path / "manager.sock", "explicit")
    with pytest.raises((TypeError, ValueError), match="backlog"):
        acquire_manager_socket(address, backlog=backlog)


def test_address_type_and_explicit_path_validation(tmp_path):
    with pytest.raises(TypeError, match="SandboxManagerAddress"):
        acquire_manager_socket(tmp_path / "manager.sock")
    with pytest.raises(TypeError, match="manager name must be text"):
        discover_client(True)
    with pytest.raises(ValueError, match="project config must be named"):
        discover_client(config_path=tmp_path / "other.toml")
