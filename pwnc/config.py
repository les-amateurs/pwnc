import atexit
import copy
import hashlib
import os
import platform
import re
import secrets
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

import toml

CONFIG_FILE = "pwnc.toml"
DEFAULT_GLOBAL_CONFIG = """
[gdb]
index-cache = true
# index-cache-path =
"""


def locate_global_config_directory():
    home = Path.home()

    if platform.system() == "Windows":
        config_root = Path(os.getenv("APPDATA", home / "AppData" / "Roaming"))
    else:
        config_root = Path(os.getenv("XDG_CONFIG_HOME", home / ".config"))

    return config_root / "pwnc"


def load_global_config():
    config_path = locate_global_config_directory() / CONFIG_FILE
    if not config_path.exists():
        config_path.parent.mkdir(exist_ok=True, parents=True)
        with open(config_path, "w+") as fp:
            fp.write(DEFAULT_GLOBAL_CONFIG)
            # toml.dump(DEFAULT_GLOBAL_CONFIG, fp)

    with open(config_path, "r") as fp:
        return toml.load(fp)


def find_config(start=None):
    """Find the nearest local config, preserving the historical no-arg API.

    ``start`` is intentionally optional so feature-specific users can resolve a
    project before changing their process working directory.  Existing callers
    still begin at ``Path(".").absolute()`` and receive the same return shape.
    """
    cwd = Path(".").absolute() if start is None else Path(start).absolute()
    if cwd.is_file():
        cwd = cwd.parent
    while not (cwd / CONFIG_FILE).exists():
        if cwd == cwd.parent:
            return None

        cwd = cwd.parent

    return cwd / CONFIG_FILE


def find_or_init_config():
    p = find_config()
    if p is None:
        load_config(True)
        return Path(".") / CONFIG_FILE
    ensure_project_seed(p)
    return p


_global_config_ = load_global_config()
_local_config_ = None
_local_config_path_ = None
_old_serialized_config_ = None
_project_seed_lock_ = threading.Lock()


def save_config():
    global _old_serialized_config_
    if _local_config_path_ is not None:
        local = copy.deepcopy(_local_config_)
        baseline = toml.loads(_old_serialized_config_ or "")
        if local == baseline:
            return

        path = Path(_local_config_path_).resolve(strict=False)
        with _locked_project_config(path):
            try:
                on_disk_serialized = path.read_text()
            except FileNotFoundError:
                on_disk_serialized = ""
            on_disk = toml.loads(on_disk_serialized)
            _apply_config_delta(on_disk, baseline, local)
            serialized = _atomic_write_config(path, on_disk)

        # Keep the legacy mutable object identity stable for callers holding a
        # reference while advancing its baseline to the merged disk state.
        _local_config_.clear()
        _local_config_.update(copy.deepcopy(on_disk))
        _old_serialized_config_ = serialized


atexit.register(save_config)


def load_config(init: bool):
    global _local_config_, _local_config_path_, _old_serialized_config_
    if _local_config_ is not None:
        if init:
            pwnc_table = _local_config_.get("pwnc")
            if not isinstance(pwnc_table, dict) or "seed" not in pwnc_table:
                ensure_project_seed(_local_config_path_)
            else:
                validate_project_seed(pwnc_table["seed"])
        return _local_config_

    if _local_config_ is None:
        config_path = find_config()
        if config_path is None:
            if not init:
                return None
            config_path = (Path(".").absolute() / CONFIG_FILE).resolve(strict=False)
        else:
            config_path = config_path.resolve(strict=True)

        if init:
            # ``ensure_project_seed`` is defined later in this module but is
            # resolved only when an explicit initialization request executes.
            # It does not call load_config(), so this introduces no recursion.
            ensure_project_seed(config_path)
        with open(config_path, "r") as fp:
            _old_serialized_config_ = fp.read()
        _local_config_ = toml.loads(_old_serialized_config_)
        _local_config_path_ = config_path

    return _local_config_


class Key:
    def __init__(self, key: str):
        self.parts = [key]

    def name(self):
        return self.parts[-1]

    def path(self):
        return self.parts[:-1]

    def __truediv__(self, other: str):
        new = Key("")
        new.parts = [part for part in self.parts] + [other]
        return new

    def __str__(self):
        return " -> ".join(self.parts)

    def __repr__(self):
        return f"{self}"


def traverse(config: dict, key: Key, create: bool):
    keys = iter(key.path())
    while True:
        try:
            next_key = next(keys)
        except StopIteration:
            break

        if next_key not in config:
            if create:
                subconfig = {}
                config[next_key] = subconfig
            else:
                raise KeyError(next_key)

        config = config[next_key]

    return config


def save(key: Key, info):
    config = load_config(True)
    traverse(config, key, True)[key.name()] = info


def load(key: Key):
    config = load_config(False)
    if config is not None:
        try:
            return traverse(config, key, False)[key.name()]
        except KeyError:
            pass

    try:
        return traverse(_global_config_, key, False)[key.name()]
    except KeyError:
        raise KeyError(key)


def maybe(key: Key):
    try:
        return load(key)
    except KeyError:
        return None


def exists(key: Key):
    config = load_config(False)
    if config is not None:
        try:
            traverse(config, key, False)[key.name()]
            return True
        except KeyError:
            pass

    try:
        traverse(_global_config_, key, False)[key.name()]
        return True
    except KeyError:
        pass
    return False


def load_project_config(config_path):
    """Read exactly one local ``pwnc.toml`` without global fallback or caching.

    Pool rendezvous uses this narrow helper so a global ``[pwnc].seed`` can
    never accidentally identify an unrelated project.  It deliberately does
    not alter the legacy module-level config cache.
    """
    path = Path(config_path).resolve(strict=True)
    if not path.is_file():
        raise FileNotFoundError(path)
    with open(path, "r") as fp:
        return toml.load(fp)


def validate_project_seed(seed):
    """Return a canonical 128-bit project seed or raise ``ValueError``."""
    if not isinstance(seed, str):
        raise TypeError("[pwnc].seed must be a 32-character hexadecimal string")
    if len(seed) != 32:
        raise ValueError("[pwnc].seed must encode exactly 128 bits as 32 hexadecimal characters")
    try:
        raw = bytes.fromhex(seed)
    except ValueError as error:
        raise ValueError("[pwnc].seed must be hexadecimal") from error
    if len(raw) != 16:
        raise ValueError("[pwnc].seed must encode exactly 128 bits")
    return raw.hex()


_MISSING = object()


def _apply_config_delta(target, baseline, local):
    """Apply only ``baseline -> local`` changes onto current disk *target*.

    Unchanged cached values never overwrite edits made by another process.
    Conflicts at the same changed key use the local value, matching the legacy
    writer's last-writer-wins behavior, while independent nested keys merge.
    """
    keys = list(baseline)
    keys.extend(key for key in local if key not in baseline)
    for key in keys:
        before = baseline.get(key, _MISSING)
        after = local.get(key, _MISSING)
        if after is _MISSING:
            target.pop(key, None)
            continue
        if before is _MISSING:
            target[key] = copy.deepcopy(after)
            continue
        if isinstance(before, dict) and isinstance(after, dict):
            if before == after:
                continue
            current = target.get(key, _MISSING)
            if not isinstance(current, dict):
                target[key] = copy.deepcopy(after)
            else:
                _apply_config_delta(current, before, after)
            continue
        if before != after:
            target[key] = copy.deepcopy(after)


def _atomic_write_serialized(path: Path, serialized: str) -> str:
    """Atomically replace one config with already-validated UTF-8 TOML."""

    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        mode = 0o600

    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as fp:
            descriptor = -1
            fp.write(serialized.encode("utf-8"))
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temporary, path)
        try:
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            directory = -1
        if directory >= 0:
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return serialized


def _atomic_write_config(path: Path, data: dict) -> str:
    return _atomic_write_serialized(path, toml.dumps(data))


_PWNC_TABLE_HEADER = re.compile(
    r"^[ \t]*\[[ \t]*(?:pwnc|\"pwnc\"|'pwnc')[ \t]*\][ \t]*(?:\#[^\r\n]*)?(?P<newline>\r?\n|$)",
    re.MULTILINE,
)


def _insert_project_seed(source: str, seed: str, *, pwnc_existed: bool, data: dict) -> str | None:
    """Insert a seed without reformatting unrelated project TOML.

    Exotic but valid declarations (for example an inline ``pwnc`` table) fall
    back to the normal serializer.  The parsed equality check makes this a
    conservative text edit rather than a second TOML parser.
    """

    newline = "\r\n" if "\r\n" in source else "\n"
    if pwnc_existed:
        match = _PWNC_TABLE_HEADER.search(source)
        if match is None:
            return None
        insertion = f'seed = "{seed}"{newline}'
        if not match.group("newline"):
            insertion = newline + insertion
        candidate = source[: match.end()] + insertion + source[match.end() :]
    else:
        if not source:
            candidate = f'[pwnc]{newline}seed = "{seed}"{newline}'
        else:
            separator = newline if source.endswith(("\n", "\r")) else newline * 2
            candidate = source + separator + f'[pwnc]{newline}seed = "{seed}"{newline}'
    try:
        parsed = toml.loads(candidate)
    except (TypeError, ValueError):
        return None
    return candidate if parsed == data else None


def _private_runtime_directory(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700


def _ensure_private_runtime_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if not _private_runtime_directory(path):
        raise PermissionError(f"pwnc runtime directory must be owned by this uid with mode 0700: {path}")
    return path


def _project_seed_lock_path(config_path: Path) -> Path:
    """Return a stable per-UID lock outside the project working tree.

    This namespace intentionally does not depend on ``XDG_RUNTIME_DIR`` or any
    other ambient setting: separate manager processes resolving the same config
    must take the same lock even when they were launched by different services
    or terminal environments.
    """
    directory = _ensure_private_runtime_directory(Path("/tmp") / f"pwnc-{os.getuid()}")
    digest = hashlib.sha256(os.fsencode(config_path)).hexdigest()[:32]
    return directory / f"config-{digest}.lock"


@contextmanager
def _locked_project_config(config_path: Path):
    """Serialize cooperative readers/writers of one local project config."""
    if os.name != "posix":
        # Pool discovery itself is Unix-socket based.  Preserve the historical
        # cross-platform config writer with in-process serialization where
        # flock and the per-UID Unix runtime namespace do not exist.
        with _project_seed_lock_:
            yield
        return

    # Keep the legacy config module importable on Windows; only Unix pool
    # discovery and its compatible writer use this feature-scoped primitive.
    import fcntl

    lock_path = _project_seed_lock_path(config_path)
    with _project_seed_lock_:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(lock_path, flags, 0o600)
        try:
            lock_info = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != os.getuid()
                or stat.S_IMODE(lock_info.st_mode) & 0o077
            ):
                raise PermissionError("project config lock must be a private regular file owned by this uid")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def ensure_project_seed(config_path):
    """Create and persist a local 128-bit ``[pwnc].seed`` exactly once.

    This is an explicit, feature-scoped mutation used by manager-side pool
    discovery.  A sidecar flock serializes independent processes, the config is
    re-read after locking, and replacement is atomic.  If the legacy local
    config cache already refers to this file it is synchronized immediately so
    its atexit writer cannot later erase the new seed.
    """
    global _local_config_path_, _old_serialized_config_
    path = Path(config_path).resolve(strict=False)
    if path.name != CONFIG_FILE:
        raise ValueError(f"project config must be named {CONFIG_FILE}")
    if not path.parent.is_dir():
        raise FileNotFoundError(path.parent)
    with _locked_project_config(path):
        try:
            on_disk_serialized = path.read_bytes().decode("utf-8")
        except FileNotFoundError:
            on_disk_serialized = ""
        data = toml.loads(on_disk_serialized)

        cache_matches = False
        if _local_config_ is not None and _local_config_path_ is not None:
            try:
                cache_matches = Path(_local_config_path_).resolve(strict=False) == path
            except OSError:
                cache_matches = False
        if cache_matches:
            baseline = toml.loads(_old_serialized_config_ or "")
            before_cache_delta = copy.deepcopy(data)
            _apply_config_delta(data, baseline, _local_config_)
            cache_changed = data != before_cache_delta
        else:
            cache_changed = False

        pwnc_table = data.get("pwnc")
        pwnc_existed = pwnc_table is not None
        if pwnc_table is None:
            pwnc_table = {}
            data["pwnc"] = pwnc_table
        elif not isinstance(pwnc_table, dict):
            raise TypeError("[pwnc] must be a TOML table")

        seed = pwnc_table.get("seed")
        seed_inserted = seed is None
        if seed is None:
            seed = secrets.token_hex(16)
            pwnc_table["seed"] = seed
        seed = validate_project_seed(seed)

        if cache_changed or seed_inserted or not on_disk_serialized:
            serialized = None
            if seed_inserted and not cache_changed:
                serialized = _insert_project_seed(
                    on_disk_serialized,
                    seed,
                    pwnc_existed=pwnc_existed,
                    data=data,
                )
            if serialized is None:
                serialized = toml.dumps(data)
            serialized = _atomic_write_serialized(path, serialized)
        else:
            serialized = on_disk_serialized

        if cache_matches:
            _local_config_.clear()
            _local_config_.update(copy.deepcopy(data))
            _local_config_path_ = path
            _old_serialized_config_ = serialized
        return seed
