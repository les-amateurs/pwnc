"""Deterministic tests for project-scoped GDB-pool rendezvous discovery."""

from __future__ import annotations

import multiprocessing
import errno
import os
import socket
import stat
from pathlib import Path

import pytest
import toml

from pwnc import config
from pwnc.gdb.dap import discovery as discovery_module
from pwnc.gdb.dap.discovery import (
    MAX_UNIX_SOCKET_PATH_BYTES,
    PoolAlreadyRunningError,
    PoolDiscoveryError,
    acquire_pool_socket,
    discover_manager,
    discover_viewer,
)


PROCESS_TIMEOUT = 10.0


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _reset_local_config(monkeypatch):
    monkeypatch.setattr(config, "_local_config_", None)
    monkeypatch.setattr(config, "_local_config_path_", None)
    monkeypatch.setattr(config, "_old_serialized_config_", None)


def _seed_racer(project, runtime, barrier, results):
    try:
        barrier.wait(PROCESS_TIMEOUT)
        address = discover_manager(start=project, runtime_dir=runtime)
        results.put(("ok", address.seed, os.fspath(address.path)))
    except BaseException as error:
        results.put(("error", type(error).__name__, str(error)))


def _cross_environment_seed_racer(project, xdg_runtime, barrier, results):
    try:
        if xdg_runtime is None:
            os.environ.pop("XDG_RUNTIME_DIR", None)
        else:
            os.environ["XDG_RUNTIME_DIR"] = os.fspath(xdg_runtime)
        barrier.wait(PROCESS_TIMEOUT)
        address = discover_manager(start=project)
        results.put(("ok", address.seed, os.fspath(address.path)))
    except BaseException as error:
        results.put(("error", type(error).__name__, str(error)))


def _stale_legacy_config_writer(project, loaded, release, results):
    try:
        os.chdir(project)
        cached = config.load_config(False)
        if cached is None:
            raise AssertionError("expected the existing project config")
        loaded.set()
        if not release.wait(PROCESS_TIMEOUT):
            raise TimeoutError("parent did not release stale config writer")
        cached.setdefault("legacy", {})["pending"] = "preserved"
        config.save_config()
        results.put(("ok",))
    except BaseException as error:
        results.put(("error", type(error).__name__, str(error)))


def _lease_racer(address, barrier, release, results):
    lease = None
    try:
        barrier.wait(PROCESS_TIMEOUT)
        lease = acquire_pool_socket(address)
        results.put(("won", os.getpid()))
        if not release.wait(PROCESS_TIMEOUT):
            raise TimeoutError("parent did not release lease winner")
    except PoolAlreadyRunningError:
        results.put(("busy", os.getpid()))
    except BaseException as error:
        results.put(("error", type(error).__name__, str(error)))
    finally:
        if lease is not None:
            lease.close()


def test_explicit_socket_is_a_complete_override_and_never_creates_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    relative = Path("manual.sock")

    manager = discover_manager(socket_path=relative)
    viewer = discover_viewer(socket_path=relative)

    assert manager == viewer
    assert manager.source == "explicit"
    assert manager.path == tmp_path / relative
    assert manager.config_path is None
    assert not (tmp_path / config.CONFIG_FILE).exists()


def test_legacy_load_config_false_remains_read_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _reset_local_config(monkeypatch)

    assert config.load_config(False) is None
    assert config.find_config() is None
    assert not (tmp_path / config.CONFIG_FILE).exists()


def test_legacy_load_config_true_immediately_creates_and_caches_seed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _reset_local_config(monkeypatch)

    loaded = config.load_config(True)
    local = tmp_path / config.CONFIG_FILE

    assert local.is_file()
    assert len(bytes.fromhex(loaded["pwnc"]["seed"])) == 16
    assert toml.load(local) == loaded
    assert config._local_config_path_ == local.resolve()
    assert config._old_serialized_config_ == local.read_text()
    assert not (tmp_path / f".{config.CONFIG_FILE}.lock").exists()


def test_legacy_true_seeds_config_previously_cached_by_read_only_load(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _reset_local_config(monkeypatch)
    local = tmp_path / config.CONFIG_FILE
    local.write_text("[gdb]\nindex-cache = true\n")

    loaded = config.load_config(False)
    assert "pwnc" not in loaded
    before = local.read_bytes()
    assert config.load_config(True) is loaded

    assert local.read_bytes() != before
    assert len(bytes.fromhex(loaded["pwnc"]["seed"])) == 16
    assert toml.load(local) == loaded


def test_find_or_init_and_pending_save_preserve_seed_at_atexit_write(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _reset_local_config(monkeypatch)

    returned = config.find_or_init_config()
    local = tmp_path / config.CONFIG_FILE
    initial_seed = toml.load(local)["pwnc"]["seed"]
    config.save(config.Key("test") / "pending", "survives")

    # Exercise the registered atexit callback body deterministically rather
    # than relying on interpreter shutdown ordering inside the test runner.
    config.save_config()
    persisted = toml.load(local)
    assert returned.absolute() == local
    assert persisted["pwnc"]["seed"] == initial_seed
    assert persisted["test"]["pending"] == "survives"


def test_find_or_init_immediately_seeds_an_existing_local_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _reset_local_config(monkeypatch)
    local = tmp_path / config.CONFIG_FILE
    local.write_text("[gdb]\nindex-cache = true\n")

    returned = config.find_or_init_config()

    assert returned == local
    assert len(bytes.fromhex(toml.load(local)["pwnc"]["seed"])) == 16


def test_manager_creates_seed_immediately_and_viewer_is_read_only(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    runtime = _private_directory(tmp_path / "runtime")

    with pytest.raises(PoolDiscoveryError, match="could not find"):
        discover_viewer(start=project, runtime_dir=runtime)
    assert not (project / config.CONFIG_FILE).exists()

    manager = discover_manager(start=project, runtime_dir=runtime)
    config_path = project / config.CONFIG_FILE
    assert config_path.is_file()
    assert not (project / f".{config.CONFIG_FILE}.lock").exists()
    on_disk = toml.load(config_path)
    assert len(bytes.fromhex(on_disk["pwnc"]["seed"])) == 16
    assert manager.seed == on_disk["pwnc"]["seed"]

    before = config_path.read_bytes()
    viewer = discover_viewer(start=project, runtime_dir=runtime)
    assert viewer == manager
    assert config_path.read_bytes() == before


def test_existing_seed_and_unchanged_legacy_cache_preserve_config_bytes(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    local = project / config.CONFIG_FILE
    contents = b'# keep this formatting\n[pwnc]\nseed = "ABCDEF0123456789ABCDEF0123456789"\n'
    local.write_bytes(contents)

    address = discover_manager(start=project, runtime_dir=_private_directory(tmp_path / "runtime"))
    assert address.seed == "abcdef0123456789abcdef0123456789"
    assert local.read_bytes() == contents

    monkeypatch.chdir(project)
    _reset_local_config(monkeypatch)
    assert config.load_config(False)["pwnc"]["seed"].startswith("ABCDEF")
    config.save_config()
    assert local.read_bytes() == contents


def test_nearest_config_and_config_relative_socket_override(tmp_path):
    project = tmp_path / "project"
    nested = project / "one" / "two"
    nested.mkdir(parents=True)
    configured = project / "run" / "manager.sock"
    (project / config.CONFIG_FILE).write_text('[gdb.pool]\nsocket = "run/manager.sock"\n')

    manager = discover_manager(start=nested, runtime_dir=_private_directory(tmp_path / "runtime"))
    assert manager.source == "config"
    assert manager.config_path == (project / config.CONFIG_FILE).resolve()
    assert manager.project_root == project.resolve()
    assert manager.path == configured
    assert len(bytes.fromhex(toml.load(project / config.CONFIG_FILE)["pwnc"]["seed"])) == 16

    # A viewer can use a configured manual socket without a seed and must not
    # mutate the config while doing so.
    seedless = tmp_path / "seedless"
    seedless.mkdir()
    seedless_config = seedless / config.CONFIG_FILE
    seedless_config.write_text('[gdb.pool]\nsocket = "viewer.sock"\n')
    before = seedless_config.read_bytes()
    viewer = discover_viewer(start=seedless)
    assert viewer.path == seedless / "viewer.sock"
    assert seedless_config.read_bytes() == before


def test_global_seed_is_never_used_for_project_discovery(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    local = project / config.CONFIG_FILE
    local.write_text("[gdb]\nindex-cache = true\n")
    monkeypatch.setattr(config, "_global_config_", {"pwnc": {"seed": "11" * 16}})

    before = local.read_bytes()
    with pytest.raises(PoolDiscoveryError, match=r"no \[pwnc\]\.seed"):
        discover_viewer(start=project, runtime_dir=tmp_path / "unused")
    assert local.read_bytes() == before


def test_seed_derivation_uses_config_identity_and_logical_pool_name(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    runtime = _private_directory(tmp_path / "runtime")
    seed = "0123456789abcdef" * 2
    contents = f'[pwnc]\nseed = "{seed}"\n'
    (first / config.CONFIG_FILE).write_text(contents)
    (second / config.CONFIG_FILE).write_text(contents)

    default = discover_viewer(start=first, runtime_dir=runtime)
    again = discover_viewer(config_path=first / config.CONFIG_FILE, runtime_dir=runtime)
    named = discover_viewer("secondary", start=first, runtime_dir=runtime)
    copied = discover_viewer(start=second, runtime_dir=runtime)

    assert default.path == again.path
    assert len({default.path, named.path, copied.path}) == 3
    assert default.path.parent == runtime


def test_cached_local_config_is_synchronized_before_atexit_save(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    local = project / config.CONFIG_FILE
    local.write_text("[gdb]\nindex-cache = true\n")
    monkeypatch.chdir(project)
    monkeypatch.setattr(config, "_local_config_", None)
    monkeypatch.setattr(config, "_local_config_path_", None)
    monkeypatch.setattr(config, "_old_serialized_config_", None)

    loaded = config.load_config(False)
    config.save(config.Key("test") / "pending", "kept")
    address = discover_manager(runtime_dir=_private_directory(tmp_path / "runtime"))

    assert loaded["pwnc"]["seed"] == address.seed
    assert config._local_config_path_ == local.resolve()
    config.save_config()
    persisted = toml.load(local)
    assert persisted["pwnc"]["seed"] == address.seed
    assert persisted["test"]["pending"] == "kept"


def test_seed_creation_applies_only_dirty_cached_keys(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    local = project / config.CONFIG_FILE
    local.write_text('[gdb]\nmode = "cached"\n')
    monkeypatch.chdir(project)
    _reset_local_config(monkeypatch)

    cached = config.load_config(False)
    cached["pending"] = {"value": "local"}
    # This edit happened after the legacy cache was loaded and must not be
    # reverted merely because manager discovery adds its seed.
    local.write_text('[gdb]\nmode = "external"\n[concurrent]\nvalue = "disk"\n')

    address = discover_manager(runtime_dir=_private_directory(tmp_path / "runtime"))
    persisted = toml.load(local)
    assert persisted["pwnc"]["seed"] == address.seed
    assert persisted["gdb"]["mode"] == "external"
    assert persisted["concurrent"]["value"] == "disk"
    assert persisted["pending"]["value"] == "local"
    assert cached == persisted


def test_stale_legacy_writer_cannot_erase_seed_or_concurrent_edits(tmp_path):
    project = tmp_path / "stale-writer-project"
    project.mkdir()
    local = project / config.CONFIG_FILE
    local.write_text('[gdb]\nmode = "cached"\n')
    context = multiprocessing.get_context("spawn")
    loaded = context.Event()
    release = context.Event()
    results = context.Queue()
    process = context.Process(
        target=_stale_legacy_config_writer,
        args=(project, loaded, release, results),
    )
    process.start()
    try:
        assert loaded.wait(PROCESS_TIMEOUT)
        local.write_text('[gdb]\nmode = "external"\n[concurrent]\nvalue = "disk"\n')
        address = discover_manager(start=project)
        release.set()
        assert results.get(timeout=PROCESS_TIMEOUT) == ("ok",)
        process.join(PROCESS_TIMEOUT)
        assert process.exitcode == 0
    finally:
        release.set()
        process.join(PROCESS_TIMEOUT)
        if process.is_alive():
            process.terminate()
            process.join(PROCESS_TIMEOUT)

    persisted = toml.load(local)
    assert persisted["pwnc"]["seed"] == address.seed
    assert persisted["gdb"]["mode"] == "external"
    assert persisted["concurrent"]["value"] == "disk"
    assert persisted["legacy"]["pending"] == "preserved"


@pytest.mark.parametrize("name", ["", True, 4, "x" * 257])
def test_pool_name_validation_precedes_config_mutation(tmp_path, name):
    with pytest.raises((TypeError, ValueError)):
        discover_manager(name, start=tmp_path, runtime_dir=tmp_path / "runtime")
    assert not (tmp_path / config.CONFIG_FILE).exists()


@pytest.mark.parametrize("seed", [1, "", "00", "z" * 32, "00" * 17])
def test_invalid_local_seed_is_rejected_without_rewrite(tmp_path, seed):
    project = tmp_path / "project"
    project.mkdir()
    local = project / config.CONFIG_FILE
    local.write_text(toml.dumps({"pwnc": {"seed": seed}}))
    before = local.read_bytes()

    with pytest.raises(PoolDiscoveryError, match="seed is invalid"):
        discover_viewer(start=project, runtime_dir=tmp_path / "runtime")
    assert local.read_bytes() == before


def test_viewer_discovery_wraps_os_failures_with_lookup_context(tmp_path, monkeypatch):
    failure = PermissionError(errno.EACCES, "Permission denied", os.fspath(tmp_path))

    def fail_find_config(_start=None):
        raise failure

    monkeypatch.setattr(config, "find_config", fail_find_config)
    with pytest.raises(
        PoolDiscoveryError,
        match=r"could not discover GDB pool 'default'.*permission was denied",
    ) as caught:
        discover_viewer(start=tmp_path)

    assert caught.value.__cause__ is failure
    assert "[Errno" not in str(caught.value)


def test_unix_socket_path_length_is_checked_on_encoded_bytes(tmp_path):
    oversized = tmp_path / ("s" * (MAX_UNIX_SOCKET_PATH_BYTES + 1))
    with pytest.raises(ValueError, match="portable limit"):
        discover_manager(socket_path=oversized)
    assert not (tmp_path / config.CONFIG_FILE).exists()

    project = tmp_path / "project"
    project.mkdir()
    (project / config.CONFIG_FILE).write_text(f'[pwnc]\nseed = "{"01" * 16}"\n')
    long_runtime = tmp_path / ("r" * 80)
    long_runtime.mkdir()
    long_runtime.chmod(0o700)
    with pytest.raises(ValueError, match="portable limit"):
        discover_viewer(start=project, runtime_dir=long_runtime)


def test_default_runtime_is_independent_of_xdg_environment(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / config.CONFIG_FILE).write_text(f'[pwnc]\nseed = "{"ab" * 16}"\n')
    xdg = _private_directory(tmp_path / "xdg")
    monkeypatch.setenv("XDG_RUNTIME_DIR", os.fspath(xdg))

    manager = discover_manager(start=project)
    expected = Path("/tmp") / f"pwnc-{os.getuid()}"
    assert manager.runtime_dir == expected
    assert stat.S_IMODE(expected.stat().st_mode) == 0o700

    # A separately launched viewer may have no XDG environment at all and must
    # still derive the exact same path.
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    viewer = discover_viewer(start=project)
    assert viewer == manager


def test_seed_creation_is_atomic_across_processes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    runtime = _private_directory(tmp_path / "runtime")
    context = multiprocessing.get_context("spawn")
    count = 8
    barrier = context.Barrier(count)
    results = context.Queue()
    processes = [
        context.Process(target=_seed_racer, args=(project, runtime, barrier, results))
        for _ in range(count)
    ]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=PROCESS_TIMEOUT) for _ in processes]
    for process in processes:
        process.join(PROCESS_TIMEOUT)
        assert process.exitcode == 0

    assert {outcome[0] for outcome in outcomes} == {"ok"}
    assert len({outcome[1] for outcome in outcomes}) == 1
    assert len({outcome[2] for outcome in outcomes}) == 1
    parsed = toml.load(project / config.CONFIG_FILE)
    assert parsed["pwnc"]["seed"] == outcomes[0][1]


def test_seed_and_socket_converge_across_different_process_environments(tmp_path):
    project = tmp_path / "cross-environment-project"
    project.mkdir()
    xdg_first = _private_directory(tmp_path / "xdg-first")
    xdg_second = _private_directory(tmp_path / "xdg-second")
    environments = [xdg_first, xdg_second, None, tmp_path / "missing-xdg"] * 2
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(len(environments))
    results = context.Queue()
    processes = [
        context.Process(
            target=_cross_environment_seed_racer,
            args=(project, environment, barrier, results),
        )
        for environment in environments
    ]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=PROCESS_TIMEOUT) for _ in processes]
    for process in processes:
        process.join(PROCESS_TIMEOUT)
        assert process.exitcode == 0

    assert {outcome[0] for outcome in outcomes} == {"ok"}
    assert len({outcome[1] for outcome in outcomes}) == 1
    assert len({outcome[2] for outcome in outcomes}) == 1
    socket_path = Path(outcomes[0][2])
    assert socket_path.parent == Path("/tmp") / f"pwnc-{os.getuid()}"
    assert toml.load(project / config.CONFIG_FILE)["pwnc"]["seed"] == outcomes[0][1]


def test_socket_lease_binds_listens_duplicates_and_cleans_up(tmp_path):
    address = discover_manager(socket_path=tmp_path / "pool.sock")
    lease = acquire_pool_socket(address, backlog=2)
    duplicate = lease.duplicate_socket()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    accepted = None
    try:
        assert lease.path.exists()
        assert stat.S_IMODE(lease.path.stat().st_mode) == 0o600
        assert lease.socket.getsockname() == os.fspath(lease.path)
        client.connect(os.fspath(lease.path))
        accepted, _peer = duplicate.accept()
        client.sendall(b"x")
        assert accepted.recv(1) == b"x"
        with pytest.raises(PoolAlreadyRunningError):
            acquire_pool_socket(address)
    finally:
        if accepted is not None:
            accepted.close()
        client.close()
        duplicate.close()
        lease.close()
    assert lease.closed
    assert not lease.path.exists()


def test_socket_lease_replaces_only_owned_stale_socket_nodes(tmp_path):
    address = discover_manager(socket_path=tmp_path / "pool.sock")
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(os.fspath(address.path))
    stale.close()

    lease = acquire_pool_socket(address)
    try:
        assert stat.S_ISSOCK(address.path.stat().st_mode)
        assert lease.socket.getsockname() == os.fspath(address.path)
    finally:
        lease.close()

    address.path.write_text("not a socket")
    with pytest.raises(PoolDiscoveryError, match="refusing to replace"):
        acquire_pool_socket(address)
    assert address.path.read_text() == "not a socket"


def test_lease_close_does_not_unlink_a_replacement_inode(tmp_path):
    address = discover_manager(socket_path=tmp_path / "pool.sock")
    lease = acquire_pool_socket(address)
    address.path.unlink()
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement.bind(os.fspath(address.path))
    try:
        lease.close()
        assert address.path.exists()
    finally:
        replacement.close()
        address.path.unlink(missing_ok=True)


def test_post_bind_failure_does_not_unlink_a_replacement_inode(tmp_path, monkeypatch):
    address = discover_manager(socket_path=tmp_path / "pool.sock")
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    real_chmod = discovery_module.os.chmod

    def replace_then_fail(path, _mode):
        Path(path).unlink()
        replacement.bind(os.fspath(path))
        replacement.listen(1)
        raise OSError("injected post-bind failure")

    monkeypatch.setattr(discovery_module.os, "chmod", replace_then_fail)
    with pytest.raises(
        PoolDiscoveryError,
        match=r"restrict Unix listener permissions.*injected post-bind failure",
    ) as caught:
        acquire_pool_socket(address)
    assert isinstance(caught.value.__cause__, OSError)
    assert address.path.is_socket()

    monkeypatch.setattr(discovery_module.os, "chmod", real_chmod)
    replacement.close()
    address.path.unlink()
    with acquire_pool_socket(address) as lease:
        assert lease.socket.getsockname() == os.fspath(address.path)


def test_only_one_concurrent_manager_can_claim_a_pool_socket(tmp_path):
    address = discover_manager(socket_path=tmp_path / "pool.sock")
    context = multiprocessing.get_context("spawn")
    count = 8
    barrier = context.Barrier(count)
    release = context.Event()
    results = context.Queue()
    processes = [
        context.Process(target=_lease_racer, args=(address, barrier, release, results))
        for _ in range(count)
    ]
    for process in processes:
        process.start()
    outcomes = [results.get(timeout=PROCESS_TIMEOUT) for _ in processes]
    release.set()
    for process in processes:
        process.join(PROCESS_TIMEOUT)
        assert process.exitcode == 0

    assert sum(outcome[0] == "won" for outcome in outcomes) == 1
    assert sum(outcome[0] == "busy" for outcome in outcomes) == count - 1
    assert not address.path.exists()
