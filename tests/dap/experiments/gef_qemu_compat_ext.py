# ruff: noqa

"""Atomic, runtime-only compatibility guards for bata24 GEF under qemu-user.

The preferred use is to source this extension instead of sourcing GEF in a
separate DAP request.  If GEF is not present yet, the extension verifies and
sources the exact fixture named by ``PWNC_BATA24_GEF_PATH``, then installs the
guards before the outer ``source`` request can return and run GEF's prompt
hook.  An already-loaded GEF is supported as well.  GEF's source is never
modified.
"""

import hashlib as _pwnc_gef_qemu_hashlib
import os as _pwnc_gef_qemu_os
import threading as _pwnc_gef_qemu_threading

import gdb as _pwnc_gef_qemu_gdb
from gdb.dap.server import request as _pwnc_gef_qemu_request


_PWNC_GEF_QEMU_EXPECTED_SHA256 = (
    "f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01"
)
_PWNC_GEF_QEMU_IMPOSSIBLE_PID = 2_147_483_647
_pwnc_gef_qemu_intended = (
    _pwnc_gef_qemu_os.environ.get("PWNC_BATA24_GEF_QEMU") == "1"
)


def _pwnc_gef_qemu_digest(path):
    digest = _pwnc_gef_qemu_hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _pwnc_gef_qemu_present():
    namespace = globals()
    return all(
        name in namespace
        for name in ("Gef", "Pid", "is_qemu_user", "is_qiling")
    )


_pwnc_gef_qemu_source_path = _pwnc_gef_qemu_os.path.realpath(
    _pwnc_gef_qemu_os.path.expanduser(
        _pwnc_gef_qemu_os.environ.get(
            "PWNC_BATA24_GEF_PATH",
            "/home/ctf/bata24-gef/gef.py",
        )
    )
)
_pwnc_gef_qemu_loaded_before = _pwnc_gef_qemu_present()
_pwnc_gef_qemu_loaded_by_compat = False
_pwnc_gef_qemu_source_sha256 = None
_pwnc_gef_qemu_source_verified = False
_pwnc_gef_qemu_source_output = ""

if _pwnc_gef_qemu_os.path.isfile(_pwnc_gef_qemu_source_path):
    _pwnc_gef_qemu_source_sha256 = _pwnc_gef_qemu_digest(
        _pwnc_gef_qemu_source_path
    )
    _pwnc_gef_qemu_source_verified = (
        _pwnc_gef_qemu_source_sha256 == _PWNC_GEF_QEMU_EXPECTED_SHA256
    )

if not _pwnc_gef_qemu_loaded_before:
    if _pwnc_gef_qemu_source_sha256 is None:
        raise RuntimeError(
            "bata24 GEF fixture does not exist: {}".format(
                _pwnc_gef_qemu_source_path
            )
        )
    if not _pwnc_gef_qemu_source_verified:
        raise RuntimeError(
            "unexpected bata24 GEF source hash: expected {}, got {}".format(
                _PWNC_GEF_QEMU_EXPECTED_SHA256,
                _pwnc_gef_qemu_source_sha256,
            )
        )
    if any(character.isspace() for character in _pwnc_gef_qemu_source_path):
        raise RuntimeError(
            "bata24 GEF source path cannot contain whitespace: {!r}".format(
                _pwnc_gef_qemu_source_path
            )
        )
    if "\n" in _pwnc_gef_qemu_source_path or "\r" in _pwnc_gef_qemu_source_path:
        raise RuntimeError("bata24 GEF source path contains a newline")
    _pwnc_gef_qemu_source_output = _pwnc_gef_qemu_gdb.execute(
        "source {}".format(_pwnc_gef_qemu_source_path),
        from_tty=False,
        to_string=True,
    )
    if not _pwnc_gef_qemu_present():
        raise RuntimeError("sourcing bata24 GEF did not install its runtime")
    _pwnc_gef_qemu_loaded_by_compat = True


def _pwnc_gef_qemu_error(error):
    try:
        message = str(error)
    except BaseException:
        message = "<exception stringification failed>"
    return {
        "type": type(error).__name__,
        "message": message,
    }


def _pwnc_gef_qemu_make_pid_guard(original, state, lock):
    def guarded(pid):
        try:
            return original(pid)
        except (
            FileNotFoundError,
            PermissionError,
            ProcessLookupError,
        ) as error:
            error_type = type(error).__name__
            error_number = getattr(error, "errno", None)
            summary = {
                "pid": pid,
                "type": error_type,
                "errno": error_number,
                "message": str(error),
            }
            with lock:
                state["suppressed_count"] += 1
                by_type = state["by_type"]
                by_type[error_type] = by_type.get(error_type, 0) + 1
                errno_key = str(error_number)
                by_errno = state["by_errno"]
                by_errno[errno_key] = by_errno.get(errno_key, 0) + 1
                pid_key = str(pid)
                by_pid = state["by_pid"]
                by_pid[pid_key] = by_pid.get(pid_key, 0) + 1
                state["last"] = summary
                state["recent"].append(summary)
                del state["recent"][:-8]
            return []

    guarded._pwnc_gef_qemu_pid_guard = True
    guarded._pwnc_gef_qemu_original = original
    guarded._pwnc_gef_qemu_state = state
    guarded._pwnc_gef_qemu_lock = lock
    return guarded


_pwnc_gef_qemu_pid_class = globals()["Pid"]
_pwnc_gef_qemu_current_pid_getter = _pwnc_gef_qemu_pid_class.get_tcp_sess
if getattr(
    _pwnc_gef_qemu_current_pid_getter,
    "_pwnc_gef_qemu_pid_guard",
    False,
):
    _pwnc_gef_qemu_pid_guard = _pwnc_gef_qemu_current_pid_getter
    _pwnc_gef_qemu_original_pid_getter = getattr(
        _pwnc_gef_qemu_pid_guard,
        "_pwnc_gef_qemu_original",
    )
    _pwnc_gef_qemu_pid_state = getattr(
        _pwnc_gef_qemu_pid_guard,
        "_pwnc_gef_qemu_state",
    )
    _pwnc_gef_qemu_pid_lock = getattr(
        _pwnc_gef_qemu_pid_guard,
        "_pwnc_gef_qemu_lock",
    )
else:
    _pwnc_gef_qemu_original_pid_getter = _pwnc_gef_qemu_current_pid_getter
    _pwnc_gef_qemu_pid_state = {
        "suppressed_count": 0,
        "by_type": {},
        "by_errno": {},
        "by_pid": {},
        "last": None,
        "recent": [],
    }
    _pwnc_gef_qemu_pid_lock = _pwnc_gef_qemu_threading.RLock()
    _pwnc_gef_qemu_pid_guard = _pwnc_gef_qemu_make_pid_guard(
        _pwnc_gef_qemu_original_pid_getter,
        _pwnc_gef_qemu_pid_state,
        _pwnc_gef_qemu_pid_lock,
    )
    _pwnc_gef_qemu_pid_class.get_tcp_sess = staticmethod(
        _pwnc_gef_qemu_pid_guard
    )


_pwnc_gef_qemu_initialization_errors = {}
try:
    _pwnc_gef_qemu_user_confirmed = bool(globals()["is_qemu_user"]())
except BaseException as _pwnc_gef_qemu_user_error:
    _pwnc_gef_qemu_user_confirmed = False
    _pwnc_gef_qemu_initialization_errors["is_qemu_user"] = (
        _pwnc_gef_qemu_error(_pwnc_gef_qemu_user_error)
    )

_pwnc_gef_qemu_current_is_qiling = globals()["is_qiling"]
if getattr(
    _pwnc_gef_qemu_current_is_qiling,
    "_pwnc_gef_qemu_qiling_guard",
    False,
):
    _pwnc_gef_qemu_qiling_guard = _pwnc_gef_qemu_current_is_qiling
    _pwnc_gef_original_is_qiling = getattr(
        _pwnc_gef_qemu_qiling_guard,
        "_pwnc_gef_qemu_original",
    )
elif _pwnc_gef_qemu_user_confirmed or _pwnc_gef_qemu_intended:
    _pwnc_gef_original_is_qiling = _pwnc_gef_qemu_current_is_qiling

    def _pwnc_gef_qemu_qiling_guard():
        return False

    _pwnc_gef_qemu_qiling_guard._pwnc_gef_qemu_qiling_guard = True
    _pwnc_gef_qemu_qiling_guard._pwnc_gef_qemu_original = (
        _pwnc_gef_original_is_qiling
    )
    globals()["is_qiling"] = _pwnc_gef_qemu_qiling_guard
else:
    _pwnc_gef_original_is_qiling = _pwnc_gef_qemu_current_is_qiling
    _pwnc_gef_qemu_qiling_guard = None


# bata24's live checksec probes execute code by writing through
# /proc/<qemu-pid>/mem.  That cannot work in the remote deployment model and
# must not become a prerequisite for this integration.  File-level mitigation
# parsing remains fully active; only the live CET/PAC/MTE status probes are
# reported as unavailable while qemu-user is intended.
_pwnc_gef_qemu_checksec_methods = (
    "get_cet_status_old_interface",
    "get_cet_status_new_interface",
    "get_cet_status_via_procfs",
    "get_mte_status",
    "get_pac_status",
)
_pwnc_gef_qemu_checksec_originals = {}
_pwnc_gef_qemu_checksec_skipped = dict(
    (name, 0) for name in _pwnc_gef_qemu_checksec_methods
)


def _pwnc_gef_qemu_make_unavailable_probe(name, original):
    def unavailable():
        _pwnc_gef_qemu_checksec_skipped[name] += 1
        return None

    unavailable._pwnc_gef_qemu_checksec_guard = True
    unavailable._pwnc_gef_qemu_original = original
    return unavailable


if _pwnc_gef_qemu_intended:
    _pwnc_gef_qemu_checksec_class = globals()["Checksec"]
    for _pwnc_gef_qemu_checksec_name in _pwnc_gef_qemu_checksec_methods:
        _pwnc_gef_qemu_checksec_current = getattr(
            _pwnc_gef_qemu_checksec_class,
            _pwnc_gef_qemu_checksec_name,
        )
        if getattr(
            _pwnc_gef_qemu_checksec_current,
            "_pwnc_gef_qemu_checksec_guard",
            False,
        ):
            _pwnc_gef_qemu_checksec_originals[
                _pwnc_gef_qemu_checksec_name
            ] = _pwnc_gef_qemu_checksec_current._pwnc_gef_qemu_original
        else:
            _pwnc_gef_qemu_checksec_originals[
                _pwnc_gef_qemu_checksec_name
            ] = _pwnc_gef_qemu_checksec_current
            setattr(
                _pwnc_gef_qemu_checksec_class,
                _pwnc_gef_qemu_checksec_name,
                staticmethod(
                    _pwnc_gef_qemu_make_unavailable_probe(
                        _pwnc_gef_qemu_checksec_name,
                        _pwnc_gef_qemu_checksec_current,
                    )
                ),
            )
else:
    _pwnc_gef_qemu_checksec_class = globals()["Checksec"]


def _pwnc_gef_qemu_pid_snapshot():
    with _pwnc_gef_qemu_pid_lock:
        return {
            "installed": (
                _pwnc_gef_qemu_pid_class.get_tcp_sess
                is _pwnc_gef_qemu_pid_guard
            ),
            "suppressed_count": _pwnc_gef_qemu_pid_state[
                "suppressed_count"
            ],
            "by_type": dict(_pwnc_gef_qemu_pid_state["by_type"]),
            "by_errno": dict(_pwnc_gef_qemu_pid_state["by_errno"]),
            "by_pid": dict(_pwnc_gef_qemu_pid_state["by_pid"]),
            "last": _pwnc_gef_qemu_pid_state["last"],
            "recent": list(_pwnc_gef_qemu_pid_state["recent"]),
        }


def _pwnc_gef_qemu_compat_snapshot_body():
    try:
        qemu_user_confirmed = bool(globals()["is_qemu_user"]())
    except BaseException as error:
        qemu_user_confirmed = False
        _pwnc_gef_qemu_initialization_errors["is_qemu_user_snapshot"] = (
            _pwnc_gef_qemu_error(error)
        )
    qiling_installed = (
        _pwnc_gef_qemu_qiling_guard is not None
        and globals().get("is_qiling") is _pwnc_gef_qemu_qiling_guard
    )
    missing_commands = {}
    for name, error in globals()["Gef"].missing_commands.items():
        missing_commands[str(name)] = _pwnc_gef_qemu_error(error)
    checksec_installed = {}
    for name in _pwnc_gef_qemu_checksec_methods:
        current = getattr(_pwnc_gef_qemu_checksec_class, name)
        checksec_installed[name] = bool(
            getattr(current, "_pwnc_gef_qemu_checksec_guard", False)
        )
    return {
        "source": {
            "path": _pwnc_gef_qemu_source_path,
            "sha256": _pwnc_gef_qemu_source_sha256,
            "expected_sha256": _PWNC_GEF_QEMU_EXPECTED_SHA256,
            "verified": _pwnc_gef_qemu_source_verified,
            "gef_present_before": _pwnc_gef_qemu_loaded_before,
            "loaded_by_compat": _pwnc_gef_qemu_loaded_by_compat,
            "output": _pwnc_gef_qemu_source_output,
        },
        "missing_commands": missing_commands,
        "pid_guard": _pwnc_gef_qemu_pid_snapshot(),
        "qemu_user_intended": _pwnc_gef_qemu_intended,
        "qemu_user_confirmed": qemu_user_confirmed,
        "qiling_guard": {
            "installed": qiling_installed,
            "original_preserved": callable(
                _pwnc_gef_original_is_qiling
            ),
        },
        "checksec_guard": {
            "installed": checksec_installed,
            "originals_preserved": all(
                callable(original)
                for original in _pwnc_gef_qemu_checksec_originals.values()
            ),
            "skipped": dict(_pwnc_gef_qemu_checksec_skipped),
        },
        "initialization_errors": dict(
            _pwnc_gef_qemu_initialization_errors
        ),
    }


if not globals().get("_pwnc_gef_qemu_compat_requests_registered", False):

    @_pwnc_gef_qemu_request(
        "pwncGefQemuCompatSnapshot",
        on_dap_thread=True,
        expect_stopped=False,
    )
    def _pwnc_gef_qemu_compat_snapshot(**_extra):
        return _pwnc_gef_qemu_compat_snapshot_body()

    @_pwnc_gef_qemu_request(
        "pwncGefQemuCompatProbe",
        on_dap_thread=True,
        expect_stopped=False,
    )
    def _pwnc_gef_qemu_compat_probe(**_extra):
        before = _pwnc_gef_qemu_pid_snapshot()["suppressed_count"]
        sessions = _pwnc_gef_qemu_pid_class.get_tcp_sess(
            _PWNC_GEF_QEMU_IMPOSSIBLE_PID
        )
        after = _pwnc_gef_qemu_pid_snapshot()["suppressed_count"]
        return {
            "pid": _PWNC_GEF_QEMU_IMPOSSIBLE_PID,
            "sessions": sessions,
            "suppressed_before": before,
            "suppressed_after": after,
            "suppressed_delta": after - before,
            "pid_guard_installed": (
                _pwnc_gef_qemu_pid_class.get_tcp_sess
                is _pwnc_gef_qemu_pid_guard
            ),
        }

    _pwnc_gef_qemu_compat_requests_registered = True
