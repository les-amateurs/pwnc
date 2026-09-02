#!/usr/bin/python3
"""Private exec wrapper used to launch a gdbserver inferior losslessly.

``gdbserver --no-startup-with-shell`` rejects arguments containing whitespace
on otherwise supported GNU gdbserver releases.  The host writes the desired
``execve`` inputs to a mode-0600 file and passes only its name in the wrapper's
environment.  Consequently, gdbserver never parses or re-serializes the real
argument vector.

This file intentionally depends only on the Python standard library: it is
executed as a standalone program by gdbserver, potentially with a very small
target environment.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn

CONFIG_ENVIRONMENT_KEY = b"_PWNC_DAP_INFERIOR_CONFIG"
CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 64 * 1024 * 1024


def _decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _bytes(value: object, *, label: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        result = bytes(value)
    elif isinstance(value, str):
        result = os.fsencode(value)
    elif isinstance(value, os.PathLike):
        result = os.fsencode(os.fspath(value))
    else:
        result = os.fsencode(str(value))
    if b"\0" in result:
        raise ValueError(f"NUL byte in {label}")
    return result


def _target_environment(environment: Mapping | None) -> dict[bytes, bytes]:
    if environment is None:
        environb = getattr(os, "environb", None)
        if environb is not None:
            return dict(environb)
        environment = os.environ

    result = {}
    for key, value in environment.items():
        key_bytes = _bytes(key, label="environment name")
        value_bytes = _bytes(value, label=f"environment value for {key!r}")
        if not key_bytes or b"=" in key_bytes:
            raise ValueError(f"invalid environment name: {key!r}")
        result[key_bytes] = value_bytes
    return result


def prepare_launch(
    program: str | bytes | os.PathLike,
    arguments: Sequence[object],
    environment: Mapping | None,
) -> tuple[str, dict[bytes, bytes], str]:
    """Return the launcher path, its environment, and config path.

    The returned config path must be passed to :func:`discard_config` once the
    target has executed or launch has failed.
    """

    executable = _bytes(program, label="executable")
    argv = [executable]
    argv.extend(_bytes(argument, label="argument") for argument in arguments)
    target_environment = _target_environment(environment)
    payload = {
        "version": CONFIG_VERSION,
        "executable": _encode(executable),
        "argv": [_encode(argument) for argument in argv],
        "environment": [[_encode(key), _encode(value)] for key, value in target_environment.items()],
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("ascii")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ValueError("inferior launch configuration is too large")

    descriptor, path = tempfile.mkstemp(prefix="pwnc-dap-inferior-", suffix=".json")
    try:
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
    except BaseException:
        os.close(descriptor)
        discard_config(path)
        raise
    else:
        os.close(descriptor)

    # Do not expose target-only variables (notably LD_PRELOAD and loader/debug
    # knobs) to gdbserver or to this Python helper.  The real environment is
    # installed atomically by execvpe below.
    launcher_environment = {CONFIG_ENVIRONMENT_KEY: os.fsencode(path)}
    helper = str(Path(__file__).resolve())
    return helper, launcher_environment, path


def discard_config(path: str | None) -> None:
    if path is None:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _fail(message: str) -> NoReturn:
    try:
        os.write(2, ("pwnc inferior launcher: " + message + "\n").encode())
    finally:
        raise SystemExit(127)


def _read_config(path: bytes) -> dict:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _fail("configuration is not a regular file")
        if metadata.st_uid != os.geteuid():
            _fail("configuration has the wrong owner")
        if metadata.st_size > MAX_CONFIG_BYTES:
            _fail("configuration is too large")
        chunks = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and os.read(descriptor, 1):
            _fail("configuration is too large")
        return json.loads(b"".join(chunks))
    finally:
        os.close(descriptor)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def main() -> None:
    environ = getattr(os, "environb", None)
    if environ is None:
        config_path = os.environ.get(CONFIG_ENVIRONMENT_KEY.decode())
        if config_path is None:
            _fail("configuration environment variable is missing")
        config_path = os.fsencode(config_path)
    else:
        config_path = environ.get(CONFIG_ENVIRONMENT_KEY)
        if config_path is None:
            _fail("configuration environment variable is missing")

    try:
        config = _read_config(config_path)
        if config.get("version") != CONFIG_VERSION:
            _fail("unsupported configuration version")
        executable = _decode(config["executable"])
        argv = [_decode(value) for value in config["argv"]]
        environment = {_decode(key): _decode(value) for key, value in config["environment"]}
        if not argv:
            _fail("empty argument vector")
        if b"\0" in executable or any(b"\0" in value for value in argv):
            _fail("NUL byte in executable or argument")
        if any(b"\0" in key or b"=" in key or b"\0" in value for key, value in environment.items()):
            _fail("invalid environment entry")
        os.execvpe(executable, argv, environment)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - emit a diagnostic before standalone exit
        _fail(f"cannot exec target: {type(error).__name__}: {error}")


if __name__ == "__main__":
    main()
