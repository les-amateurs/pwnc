"""Docker CLI backend for locally isolated challenge processes.

The backend deliberately uses the Docker CLI as an argv-only subprocess API.
It never discovers or mutates containers by name, label query, or a global
``prune`` operation: every lifecycle command is issued against an exact ID
returned by Docker during this backend session.
"""

from __future__ import annotations

import errno
import fcntl
import ipaddress
import json
import os
import pty
import queue
import re
import selectors
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import tty
import uuid
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO, Protocol, Self

from pwnc.qemu_user import (
    QemuNotFoundError,
    QemuUserError,
    guest_layout_args,
    qemu_binary_names_for_arch,
    resolve_qemu,
)

from ._qemu_bridge import QemuGdbBridge
from .errors import SandboxBackendError, SandboxCapabilityError, SandboxConfigError
from .model import SandboxDebug, SandboxPort, SandboxPortBinding, SandboxSpec, SandboxStdio

_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PRIVATE_DIR = "/run/pwnc"
_CONTAINER_SHIM = f"{_PRIVATE_DIR}/shim"
_CONTAINER_CONTROL_DIR = f"{_PRIVATE_DIR}/control"
_CONTAINER_QEMU = f"{_PRIVATE_DIR}/qemu-user"
_CONTAINER_DEBUG_DIR = f"{_PRIVATE_DIR}/debug"
_CONTAINER_GDB_SOCKET = f"{_CONTAINER_DEBUG_DIR}/gdb.sock"
_HOST_NO_ASLR_SECCOMP = Path(__file__).with_name("moby-seccomp-host-no-aslr.json")
_START_EVENT_TIMEOUT = 30.0

_MANAGED_LABEL = "io.pwnc.sandbox.managed"
_SESSION_LABEL = "io.pwnc.sandbox.session"
_PROFILE_LABEL = "io.pwnc.sandbox.profile"
_INSTANCE_LABEL = "io.pwnc.sandbox.instance"

# ``DockerSpec.extra_args`` is intentionally useful for resource controls, but
# it must not be able to replace isolation, ownership, or lifecycle arguments
# supplied by this backend.  Both ``--option=value`` and attached short forms
# are rejected.
_FORBIDDEN_LONG_OPTIONS = frozenset(
    {
        "--add-host",
        "--annotation",
        "--attach",
        "--cap-add",
        "--cap-drop",
        "--cgroup-parent",
        "--cgroupns",
        "--device",
        "--device-cgroup-rule",
        "--dns",
        "--dns-option",
        "--dns-search",
        "--entrypoint",
        "--env",
        "--env-file",
        "--expose",
        "--gpus",
        "--group-add",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-start-interval",
        "--health-start-period",
        "--health-timeout",
        "--ipc",
        "--interactive",
        "--ip",
        "--ip6",
        "--label",
        "--label-file",
        "--link",
        "--link-local-ip",
        "--mac-address",
        "--mount",
        "--name",
        "--network",
        "--network-alias",
        "--no-healthcheck",
        "--pid",
        "--platform",
        "--privileged",
        "--publish",
        "--publish-all",
        "--pull",
        "--read-only",
        "--restart",
        "--rm",
        "--runtime",
        "--security-opt",
        "--storage-opt",
        "--tmpfs",
        "--tty",
        "--use-api-socket",
        "--user",
        "--userns",
        "--uts",
        "--volume",
        "--volume-driver",
        "--volumes-from",
        "--workdir",
    }
)
_FORBIDDEN_SHORT_OPTIONS = frozenset({"-a", "-e", "-i", "-l", "-p", "-P", "-t", "-u", "-v", "-w"})
_SHORT_OPTIONS_WITH_ATTACHED_VALUES = frozenset({"-a", "-e", "-i", "-l", "-p", "-t", "-u", "-v", "-w"})


class CommandRunner(Protocol):
    """Injectable, argv-only command runner used by focused backend tests."""

    def __call__(
        self,
        argv: tuple[str, ...],
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[bytes]: ...


class PopenFactory(Protocol):
    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.Popen[bytes]: ...


_PIDFD_UNAVAILABLE = object()


@dataclass(slots=True)
class _ThreadWait:
    done: threading.Event = field(default_factory=threading.Event)
    result: int | None = None
    error: BaseException | None = None


_thread_waits: weakref.WeakKeyDictionary[Any, _ThreadWait] = weakref.WeakKeyDictionary()
_thread_waits_lock = threading.Lock()


def _timeout_error(process: Any, timeout: float | None) -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(getattr(process, "args", getattr(process, "pid", "child process")), timeout)


def _wait_pidfd(process: Any, timeout: float | None) -> object | int:
    pidfd_open = getattr(os, "pidfd_open", None)
    if pidfd_open is None:
        return _PIDFD_UNAVAILABLE
    try:
        pid = int(process.pid)
        if pid <= 0:
            return _PIDFD_UNAVAILABLE
        pidfd = pidfd_open(pid, 0)
    except (AttributeError, OSError, TypeError, ValueError):
        return _PIDFD_UNAVAILABLE

    selector = selectors.DefaultSelector()
    try:
        selector.register(pidfd, selectors.EVENT_READ)
        ready = selector.select(timeout)
    except (OSError, ValueError):
        return _PIDFD_UNAVAILABLE
    finally:
        selector.close()
        os.close(pidfd)

    if not ready:
        status = process.poll()
        if status is None:
            raise _timeout_error(process, timeout)
        return status
    return process.wait()


def _thread_wait_state(process: Any) -> _ThreadWait:
    def make_waiter() -> tuple[_ThreadWait, threading.Thread]:
        state = _ThreadWait()

        def reap() -> None:
            try:
                state.result = process.wait()
            except BaseException as error:  # noqa: BLE001 - replay in caller
                state.error = error
            finally:
                state.done.set()

        thread = threading.Thread(
            target=reap,
            name=f"pwnc-docker-wait-{getattr(process, 'pid', 'unknown')}",
            daemon=True,
        )
        return state, thread

    try:
        weakref.ref(process)
        hash(process)
    except TypeError:
        state, thread = make_waiter()
        thread.start()
        return state

    with _thread_waits_lock:
        state = _thread_waits.get(process)
        if state is not None:
            return state
        state, thread = make_waiter()
        _thread_waits[process] = state
        try:
            thread.start()
        except BaseException:
            del _thread_waits[process]
            raise
        return state


def _wait_process(process: Any, timeout: float | None = None) -> int:
    """Wait for one subprocess exit event without a sleep/status loop."""
    if timeout is not None:
        timeout = max(0.0, float(timeout))
    status = _wait_pidfd(process, timeout)
    if status is not _PIDFD_UNAVAILABLE:
        return int(status)

    state = _thread_wait_state(process)
    if not state.done.wait(timeout):
        raise _timeout_error(process, timeout)
    if state.error is not None:
        raise state.error
    assert state.result is not None
    return state.result


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        _wait_process(process)
        return
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    try:
        _wait_process(process, 2.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        process.kill()
    except ProcessLookupError:
        pass
    _wait_process(process)


def _run_subprocess(argv: tuple[str, ...], timeout: float | None = None) -> subprocess.CompletedProcess[bytes]:
    """Capture a Docker CLI command without pipe backpressure or busy waits."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
            )
        except OSError as error:
            raise SandboxBackendError(f"could not execute Docker CLI {argv[0]!r}: {error}") from error
        try:
            returncode = _wait_process(process, timeout)
        except subprocess.TimeoutExpired as error:
            _terminate_process(process)
            stdout.seek(0)
            stderr.seek(0)
            raise subprocess.TimeoutExpired(argv, timeout, output=stdout.read(), stderr=stderr.read()) from error
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(argv, returncode, stdout.read(), stderr.read())


def _decode_error(data: bytes) -> str:
    message = data.decode("utf-8", "replace").strip()
    if not message:
        return "Docker CLI returned no diagnostic"
    if len(message) > 2_000:
        return message[:2_000] + "..."
    return message


def _checked(result: subprocess.CompletedProcess[bytes], action: str) -> bytes:
    if result.returncode != 0:
        raise SandboxBackendError(
            f"Docker {action} failed with exit {result.returncode}: {_decode_error(result.stderr)}"
        )
    return result.stdout


def _validate_extra_args(arguments: Sequence[str]) -> tuple[str, ...]:
    result = tuple(arguments)
    for argument in result:
        if not argument or "\0" in argument:
            raise SandboxConfigError("Docker extra_args cannot contain empty or NUL arguments")
        if argument == "-" or not argument.startswith("-"):
            raise SandboxConfigError(
                "Docker extra_args cannot contain positional arguments; attach option values to their option"
            )
        option = argument.split("=", 1)[0]
        if option in _FORBIDDEN_LONG_OPTIONS or option in _FORBIDDEN_SHORT_OPTIONS:
            raise SandboxConfigError(f"Docker option {option!r} is owned by the sandbox backend")
        if any(argument.startswith(short) and argument != short for short in _SHORT_OPTIONS_WITH_ATTACHED_VALUES):
            raise SandboxConfigError(f"Docker option {argument!r} is owned by the sandbox backend")
        if argument == "--":
            raise SandboxConfigError("Docker extra_args cannot terminate the backend option list")
    return result


def _mount_argument(source: Path, target: str, *, read_only: bool) -> str:
    source_text = os.fspath(source)
    if "," in source_text or "," in target:
        raise SandboxConfigError("Docker bind mount paths cannot contain commas")
    options = f"type=bind,source={source_text},target={target}"
    return options + (",readonly" if read_only else "")


def _publish_argument(port: SandboxPort) -> str:
    if port.bind_host not in {"127.0.0.1", "::1"}:
        raise SandboxConfigError(f"Docker ports may only bind to loopback, not {port.bind_host!r}")
    host = f"[{port.bind_host}]" if ":" in port.bind_host else port.bind_host
    published = "" if port.host_port is None else str(port.host_port)
    return f"{host}:{published}:{port.internal_port}/{port.protocol}"


def _parse_identifier(output: bytes, pattern: re.Pattern[str], kind: str) -> str:
    try:
        lines = [line.strip() for line in output.decode("ascii", "strict").splitlines() if line.strip()]
    except UnicodeDecodeError as error:
        raise SandboxBackendError(f"Docker returned a non-ASCII {kind} identifier") from error
    if len(lines) != 1 or pattern.fullmatch(lines[0]) is None:
        raise SandboxBackendError(f"Docker returned an invalid {kind} identifier")
    return lines[0]


def _parse_inspect(
    output: bytes,
    container_id: str,
    requested_ports: Sequence[SandboxPort],
    *,
    network_id: str | None = None,
) -> tuple[int, tuple[SandboxPortBinding, ...], str | None]:
    try:
        decoded = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SandboxBackendError("Docker inspect returned invalid JSON") from error
    if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], Mapping):
        raise SandboxBackendError("Docker inspect did not return exactly one container")
    record = decoded[0]
    if record.get("Id") != container_id:
        raise SandboxBackendError("Docker inspect returned a different container ID")

    state = record.get("State")
    try:
        host_pid = state["Pid"] if isinstance(state, Mapping) else None
    except (KeyError, TypeError):
        host_pid = None
    if isinstance(host_pid, bool) or not isinstance(host_pid, int) or host_pid <= 0:
        raise SandboxBackendError("Docker container exited before its host PID could be recorded")

    network_settings = record.get("NetworkSettings")
    raw_ports = network_settings.get("Ports") if isinstance(network_settings, Mapping) else None
    if not isinstance(raw_ports, Mapping):
        raise SandboxBackendError("Docker inspect omitted container port bindings")

    bindings: list[SandboxPortBinding] = []
    expected_keys = {f"{port.internal_port}/{port.protocol}" for port in requested_ports}
    for raw_key, raw_values in raw_ports.items():
        if raw_key not in expected_keys and raw_values:
            raise SandboxBackendError(f"Docker published unexpected container port {raw_key!r}")

    for port in requested_ports:
        key = f"{port.internal_port}/{port.protocol}"
        candidates = raw_ports.get(key)
        if not isinstance(candidates, list):
            raise SandboxBackendError(f"Docker did not publish requested port {key}")
        matches = []
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            host = candidate.get("HostIp")
            raw_host_port = candidate.get("HostPort")
            try:
                host_port = int(raw_host_port)
            except (TypeError, ValueError):
                continue
            if host != port.bind_host or not 1 <= host_port <= 65535:
                continue
            if port.host_port is not None and host_port != port.host_port:
                continue
            matches.append((host, host_port))
        if len(matches) != 1:
            raise SandboxBackendError(f"Docker returned {len(matches)} matching bindings for requested port {key}")
        host, host_port = matches[0]
        bindings.append(
            SandboxPortBinding(
                name=port.name,
                internal_port=port.internal_port,
                host=host,
                host_port=host_port,
                protocol=port.protocol,
            )
        )
    container_address = None
    if network_id is not None:
        raw_networks = network_settings.get("Networks") if isinstance(network_settings, Mapping) else None
        if not isinstance(raw_networks, Mapping):
            raise SandboxBackendError("Docker inspect omitted container network addresses")
        matching_networks = [
            network
            for network in raw_networks.values()
            if isinstance(network, Mapping) and network.get("NetworkID") == network_id
        ]
        if len(matching_networks) != 1:
            raise SandboxBackendError("Docker inspect did not identify the exact internal session network")
        raw_address = matching_networks[0].get("IPAddress")
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as error:
            raise SandboxBackendError("Docker inspect returned an invalid internal container address") from error
        if not address.is_private:
            raise SandboxBackendError("Docker assigned a non-private address to its internal session network")
        container_address = str(address)

    return host_pid, tuple(bindings), container_address


class DockerTCPProxy:
    """A bounded, fixed-destination TCP bridge for an internal Docker network.

    The listening socket is bound before the container starts, so both an
    explicit host port and the kernel's port-zero allocation are atomic.  Each
    direction copies at most one 64 KiB block at a time and blocks in
    ``sendall`` when its peer applies backpressure; no unbounded userspace
    queue or status-poll loop is involved.
    """

    BUFFER_SIZE = 64 * 1024
    MAX_CONNECTIONS = 128

    def __init__(self, port: SandboxPort):
        if port.protocol != "tcp":
            raise SandboxCapabilityError("deny-egress Docker sandboxes currently support published TCP ports only")
        family = socket.AF_INET6 if ":" in port.bind_host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((port.bind_host, port.host_port or 0))
            listener.listen(self.MAX_CONNECTIONS)
        except OSError as error:
            listener.close()
            requested = "automatic" if port.host_port is None else str(port.host_port)
            raise SandboxBackendError(
                f"cannot reserve loopback TCP port {requested} for sandbox service {port.name!r}: {error}"
            ) from error
        except BaseException:
            listener.close()
            raise

        host_port = int(listener.getsockname()[1])
        self.binding = SandboxPortBinding(
            name=port.name,
            internal_port=port.internal_port,
            host=port.bind_host,
            host_port=host_port,
            protocol=port.protocol,
        )
        self._listener = listener
        try:
            self._wake_r, self._wake_w = socket.socketpair()
        except BaseException:
            listener.close()
            raise
        self._destination: tuple[str, int] | None = None
        self._condition = threading.Condition(threading.RLock())
        self._close_lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._workers: set[threading.Thread] = set()
        self._closing_workers: tuple[threading.Thread, ...] = ()
        self._accept_thread: threading.Thread | None = None
        self._accept_done = False
        self._closing = False
        self._closed = False
        self._error: BaseException | None = None

    @property
    def error(self) -> BaseException | None:
        with self._condition:
            return self._error

    def start(self, destination_host: str) -> None:
        try:
            destination = ipaddress.ip_address(destination_host)
        except ValueError as error:
            raise SandboxBackendError(f"invalid Docker proxy destination {destination_host!r}") from error
        with self._condition:
            if self._closing or self._closed:
                raise SandboxBackendError("Docker TCP proxy is closed")
            if self._accept_thread is not None:
                raise SandboxBackendError("Docker TCP proxy is already started")
            self._destination = (str(destination), self.binding.internal_port)
            thread = threading.Thread(
                target=self._accept_loop,
                name=f"pwnc-docker-proxy-{self.binding.name}-{self.binding.host_port}",
                daemon=True,
            )
            self._accept_thread = thread
            try:
                thread.start()
            except BaseException:
                self._accept_thread = None
                raise

    @staticmethod
    def _shutdown(sock: socket.socket, how: int = socket.SHUT_RDWR) -> None:
        try:
            sock.shutdown(how)
        except OSError:
            pass

    @staticmethod
    def _close_socket(sock: socket.socket, *, checked: bool = False) -> bool:
        DockerTCPProxy._shutdown(sock)
        try:
            sock.close()
        except OSError:
            if checked:
                raise
            return False
        return True

    def _drop_socket(self, sock: socket.socket) -> None:
        with self._condition:
            self._connections.discard(sock)

    def _pump(self, source: socket.socket, destination: socket.socket, done: threading.Event) -> None:
        try:
            while True:
                data = source.recv(self.BUFFER_SIZE)
                if not data:
                    self._shutdown(destination, socket.SHUT_WR)
                    return
                destination.sendall(data)
        except OSError:
            # A transport error cannot preserve useful half-close semantics;
            # wake the opposite pump immediately.
            self._shutdown(source)
            self._shutdown(destination)
        finally:
            done.set()

    def _connect_upstream(self) -> socket.socket | None:
        """Connect without leaving close blocked in a kernel connect timeout."""
        assert self._destination is not None
        family = socket.AF_INET6 if ":" in self._destination[0] else socket.AF_INET
        with self._condition:
            if self._closing:
                return None
            upstream = socket.socket(family, socket.SOCK_STREAM)
            self._connections.add(upstream)
        try:
            upstream.setblocking(False)
            result = upstream.connect_ex(self._destination)
            if result not in {0, errno.EISCONN}:
                if result not in {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR}:
                    raise OSError(result, os.strerror(result))
                selector = selectors.DefaultSelector()
                try:
                    selector.register(upstream, selectors.EVENT_WRITE, "upstream")
                    selector.register(self._wake_r, selectors.EVENT_READ, "close")
                    ready = selector.select(3.0)
                finally:
                    selector.close()
                if not ready:
                    raise TimeoutError("timed out connecting to Docker proxy destination")
                with self._condition:
                    closing = self._closing
                if closing or any(key.data == "close" for key, _events in ready):
                    if self._close_socket(upstream):
                        self._drop_socket(upstream)
                    return None
                socket_error = upstream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if socket_error:
                    raise OSError(socket_error, os.strerror(socket_error))
            upstream.setblocking(True)
            return upstream
        except BaseException:
            if self._close_socket(upstream):
                self._drop_socket(upstream)
            raise

    def _serve(self, client: socket.socket) -> None:
        worker = threading.current_thread()
        upstream: socket.socket | None = None
        started_pumps: list[threading.Thread] = []
        try:
            upstream = self._connect_upstream()
            if upstream is None:
                return
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_to_upstream = threading.Event()
            upstream_to_client = threading.Event()
            pumps = (
                threading.Thread(
                    target=self._pump,
                    args=(client, upstream, client_to_upstream),
                    name=f"{worker.name}-upload",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._pump,
                    args=(upstream, client, upstream_to_client),
                    name=f"{worker.name}-download",
                    daemon=True,
                ),
            )
            for pump in pumps:
                pump.start()
                started_pumps.append(pump)
            client_to_upstream.wait()
            upstream_to_client.wait()
        except OSError:
            # A refused target is local to this one inbound connection.  The
            # listener stays available for a challenge that is still starting.
            pass
        except BaseException as error:  # noqa: BLE001 - publish worker lifecycle failure
            with self._condition:
                if not self._closing:
                    self._error = error
        finally:
            client_closed = self._close_socket(client)
            upstream_closed = upstream is not None and self._close_socket(upstream)
            for pump in started_pumps:
                pump.join()
            if client_closed:
                self._drop_socket(client)
            if upstream is not None and upstream_closed:
                self._drop_socket(upstream)
            with self._condition:
                self._workers.discard(worker)
                self._condition.notify_all()

    def _accept_loop(self) -> None:
        try:
            while True:
                try:
                    client, _address = self._listener.accept()
                except OSError:
                    with self._condition:
                        if self._closing:
                            return
                    raise
                with self._condition:
                    if self._closing:
                        self._connections.add(client)
                        if self._close_socket(client):
                            self._connections.discard(client)
                        return
                    if len(self._workers) >= self.MAX_CONNECTIONS:
                        self._connections.add(client)
                        if self._close_socket(client):
                            self._connections.discard(client)
                        continue
                    self._connections.add(client)
                    worker = threading.Thread(
                        target=self._serve,
                        args=(client,),
                        name=f"pwnc-docker-proxy-connection-{self.binding.name}",
                        daemon=True,
                    )
                    self._workers.add(worker)
                try:
                    worker.start()
                except BaseException:
                    with self._condition:
                        self._workers.discard(worker)
                        if self._close_socket(client):
                            self._connections.discard(client)
                    raise
        except BaseException as error:  # noqa: BLE001 - publish proxy failure for its owner
            with self._condition:
                if not self._closing:
                    self._error = error
        finally:
            with self._condition:
                self._accept_done = True
                self._condition.notify_all()

    def close(self) -> None:
        with self._close_lock:
            with self._condition:
                if self._closed:
                    return
                self._closing = True
                connections = tuple(self._connections)
                started = self._accept_thread is not None
                if not self._closing_workers:
                    self._closing_workers = tuple(self._workers)
            # EOF on this socket is level-triggered, so it wakes every concurrent
            # nonblocking-connect selector without polling or one-token races.
            self._shutdown(self._wake_w)
            failures: list[BaseException] = []
            try:
                self._close_socket(self._listener, checked=True)
            except BaseException as error:  # noqa: BLE001 - retain and retry the exact listener
                failures.append(error)
            for connection in connections:
                try:
                    self._close_socket(connection, checked=True)
                except BaseException as error:  # noqa: BLE001 - wake every connection before reporting
                    failures.append(error)
                else:
                    self._drop_socket(connection)
            if failures:
                self._raise_close_failures(failures)

            with self._condition:
                if not started:
                    self._accept_done = True
                # Closing the listener and every registered connection wakes all
                # blocking accept/recv/send calls.  Retain ownership and wait for
                # those exact threads instead of abandoning them after a timer.
                self._condition.wait_for(lambda: self._accept_done and not self._workers)
                accept_thread = self._accept_thread
                workers = self._closing_workers

            if accept_thread is not None:
                try:
                    accept_thread.join()
                except BaseException as error:  # noqa: BLE001 - retain exact thread for retry
                    failures.append(error)
                else:
                    with self._condition:
                        if self._accept_thread is accept_thread:
                            self._accept_thread = None
            for worker in workers:
                try:
                    worker.join()
                except BaseException as error:  # noqa: BLE001 - retain exact thread for retry
                    failures.append(error)
            if not failures:
                with self._condition:
                    self._closing_workers = ()

            with self._condition:
                remaining_connections = tuple(self._connections)
            for connection in remaining_connections:
                try:
                    self._close_socket(connection, checked=True)
                except BaseException as error:  # noqa: BLE001 - retain late exact connections for retry
                    failures.append(error)
                else:
                    self._drop_socket(connection)

            for wake_socket in (self._wake_r, self._wake_w):
                try:
                    self._close_socket(wake_socket, checked=True)
                except BaseException as error:  # noqa: BLE001 - retain exact wake endpoints for retry
                    failures.append(error)
            if failures:
                self._raise_close_failures(failures)
            with self._condition:
                self._closed = True
                self._condition.notify_all()

    def _raise_close_failures(self, failures: list[BaseException]) -> None:
        error = SandboxBackendError(f"Docker TCP proxy {self.binding.name!r} cleanup failed ({len(failures)} error(s))")
        for failure in failures:
            error.add_note(str(failure))
        raise error from failures[0]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


@dataclass(slots=True)
class DockerAttach:
    """One explicit Docker CLI attach process and its host-side handles."""

    process: subprocess.Popen[bytes]
    mode: SandboxStdio
    stdin: BinaryIO | None = None
    stdout: BinaryIO | None = None
    stderr: BinaryIO | None = None
    master_fd: int | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _process_closed: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def fileno(self) -> int:
        if self.master_fd is not None:
            return self.master_fd
        if self.stdout is not None:
            return self.stdout.fileno()
        raise OSError("Docker attach has no readable file descriptor")

    def resize(self, rows: int, columns: int) -> None:
        if self.mode is not SandboxStdio.PTY or self.master_fd is None:
            raise SandboxCapabilityError("terminal resize requires PTY stdio")
        if isinstance(rows, bool) or not isinstance(rows, int) or rows <= 0:
            raise ValueError("rows must be a positive integer")
        if isinstance(columns, bool) or not isinstance(columns, int) or columns <= 0:
            raise ValueError("columns must be a positive integer")
        with self._lock:
            if self._closed:
                raise SandboxBackendError("Docker attach is closed")
            fcntl.ioctl(self.master_fd, termios_tiocswinsz(), struct.pack("HHHH", rows, columns, 0, 0))
            try:
                os.kill(self.process.pid, signal.SIGWINCH)
            except ProcessLookupError:
                pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            failures: list[BaseException] = []
            handles = (self.stdin, self.stdout, self.stderr)
            seen: set[int] = set()
            for handle in handles:
                if handle is None or id(handle) in seen:
                    continue
                seen.add(id(handle))
                try:
                    handle.close()
                except BaseException as error:  # noqa: BLE001 - retain failed handles for retry
                    failures.append(error)
                else:
                    if self.stdin is handle:
                        self.stdin = None
                    if self.stdout is handle:
                        self.stdout = None
                    if self.stderr is handle:
                        self.stderr = None

            if self.master_fd is not None:
                master_fd = self.master_fd
                try:
                    os.close(master_fd)
                except OSError as error:
                    if error.errno == errno.EBADF:
                        self.master_fd = None
                    else:
                        failures.append(error)
                else:
                    self.master_fd = None

            if not self._process_closed:
                try:
                    _terminate_process(self.process)
                except BaseException as error:  # noqa: BLE001 - retain the exact process for retry
                    failures.append(error)
                else:
                    self._process_closed = True

            cleanup_complete = (
                self.stdin is None
                and self.stdout is None
                and self.stderr is None
                and self.master_fd is None
                and self._process_closed
            )
            self._closed = cleanup_complete
            if failures:
                error = SandboxBackendError(f"Docker attach cleanup failed ({len(failures)} error(s))")
                for failure in failures:
                    error.add_note(str(failure))
                raise error from failures[0]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


@dataclass(slots=True)
class _DockerEventStream:
    """A bounded, exact-container Docker event subscription."""

    process: subprocess.Popen[bytes]
    stdout: BinaryIO | None
    _process_closed: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def closed(self) -> bool:
        return self._closed

    def expect(self, action: str) -> None:
        """Wait for one event line without polling the daemon or child process."""

        if self._closed or self.stdout is None:
            raise SandboxBackendError("Docker event stream is closed")
        stdout = self.stdout
        completed: queue.Queue[tuple[bytes | None, BaseException | None]] = queue.Queue(maxsize=1)

        def read_event() -> None:
            try:
                completed.put((stdout.readline(128), None))
            except BaseException as error:  # noqa: BLE001 - replay in the lifecycle thread
                completed.put((None, error))

        reader = threading.Thread(
            target=read_event,
            name=f"pwnc-docker-events-{self.process.pid}",
            daemon=True,
        )
        reader.start()
        try:
            raw, read_error = completed.get(timeout=_START_EVENT_TIMEOUT)
        except queue.Empty as error:
            raise SandboxBackendError(f"timed out waiting for Docker container {action!r} event") from error
        if read_error is not None:
            raise SandboxBackendError(f"could not read Docker container {action!r} event: {read_error}") from read_error
        assert raw is not None
        if not raw:
            status = _wait_process(self.process)
            raise SandboxBackendError(
                f"Docker event stream exited with status {status} before container {action!r} event"
            )
        if not raw.endswith(b"\n"):
            raise SandboxBackendError(
                f"Docker event stream returned an oversized container event while waiting for {action!r}"
            )
        observed = raw.decode("utf-8", "replace").strip()
        if observed != action:
            raise SandboxBackendError(
                f"Docker event stream returned {observed!r} while waiting for container {action!r} event"
            )

    def close(self) -> None:
        if self._closed:
            return
        failures: list[BaseException] = []
        if not self._process_closed:
            try:
                _terminate_process(self.process)
            except BaseException as error:  # noqa: BLE001 - retain the exact process for retry
                failures.append(error)
            else:
                self._process_closed = True
        if self.stdout is not None:
            stdout = self.stdout
            try:
                stdout.close()
            except BaseException as error:  # noqa: BLE001 - retain the exact handle for retry
                failures.append(error)
            else:
                if self.stdout is stdout:
                    self.stdout = None
        self._closed = self._process_closed and self.stdout is None
        if failures:
            error = SandboxBackendError(f"Docker event stream cleanup failed ({len(failures)} error(s))")
            for failure in failures:
                error.add_note(str(failure))
            raise error from failures[0]


def termios_tiocswinsz() -> int:
    # Keeping the platform lookup behind a function makes the PTY-only feature
    # explicit and avoids importing a non-portable constant at module import.
    import termios

    return termios.TIOCSWINSZ


@dataclass(slots=True)
class _DockerPendingCleanup:
    """Exact resources acquired by a spawn that did not publish an instance."""

    container_id: str | None
    attach: DockerAttach | None
    proxies: tuple[DockerTCPProxy, ...]
    qemu_bridge: QemuGdbBridge | None = None
    events: _DockerEventStream | None = None

    @property
    def complete(self) -> bool:
        return (
            self.container_id is None
            and self.attach is None
            and not self.proxies
            and self.qemu_bridge is None
            and self.events is None
        )


@dataclass(frozen=True, slots=True)
class _DockerQemuRuntime:
    """Resolved source, argv, mount, and debugger resources for one spawn."""

    command: tuple[str, ...]
    mounts: tuple[str, ...]
    fallback_executable: str | None
    bridge: QemuGdbBridge | None
    debug: SandboxDebug | None


@dataclass(slots=True)
class DockerInstance:
    """A single exact-ID container owned by :class:`DockerBackend`."""

    container_id: str
    host_pid: int
    ports: tuple[SandboxPortBinding, ...]
    stdio: SandboxStdio
    image: str
    attach: DockerAttach | None
    proxies: tuple[DockerTCPProxy, ...]
    qemu_bridge: QemuGdbBridge | None
    debug: SandboxDebug | None
    paused: bool
    shim_control_socket: Path | None
    _backend: DockerBackend = field(repr=False)
    target_host_pid: int | None = None
    _exit_code: int | None = field(default=None, init=False, repr=False)
    _container_removed: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    @property
    def bindings(self) -> Mapping[str, SandboxPortBinding]:
        return MappingProxyType({binding.name: binding for binding in self.ports})

    @property
    def exit_code(self) -> int | None:
        with self._lock:
            return self._exit_code

    def authorize_debugger(self, target_host_pid: int) -> None:
        """Bind the private QEMU stub to the exact retained target pidfd."""

        bridge = self.qemu_bridge
        if bridge is None:
            return
        bridge.authorize(target_host_pid)

    def wait_debugger_ready(self, timeout: float | None, *, cancelled=None) -> None:
        bridge = self.qemu_bridge
        if bridge is not None:
            bridge.wait_ready(timeout, cancelled=cancelled)

    def wake_debugger_waiters(self) -> None:
        bridge = self.qemu_bridge
        if bridge is not None:
            bridge.wake_waiters()

    def wait(self, timeout: float | None = None) -> int:
        with self._lock:
            if self._closed:
                if self._exit_code is None:
                    raise SandboxBackendError("Docker instance is closed")
                return self._exit_code
            if self._exit_code is not None:
                return self._exit_code
        output = _checked(
            self._backend._run((self._backend.docker_executable, "wait", self.container_id), timeout),
            f"wait for container {self.container_id}",
        )
        try:
            lines = [line.strip() for line in output.decode("ascii", "strict").splitlines() if line.strip()]
            if len(lines) != 1:
                raise ValueError
            exit_code = int(lines[0], 10)
        except (UnicodeDecodeError, ValueError) as error:
            raise SandboxBackendError("Docker wait returned an invalid exit code") from error
        with self._lock:
            self._exit_code = exit_code
        return exit_code

    def kill(self) -> None:
        with self._lock:
            if self._closed:
                return
            container_id = self.container_id
        _checked(
            self._backend._run((self._backend.docker_executable, "kill", container_id), None),
            f"kill container {container_id}",
        )

    def resize(self, rows: int, columns: int) -> None:
        if self.attach is None:
            raise SandboxCapabilityError("terminal resize requires attached PTY stdio")
        self.attach.resize(rows, columns)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            failures: list[BaseException] = []
            if self.attach is not None:
                attach = self.attach
                try:
                    attach.close()
                except BaseException as error:  # noqa: BLE001 - continue exact container cleanup
                    failures.append(error)
                else:
                    if self.attach is attach:
                        self.attach = None

            remaining_proxies: list[DockerTCPProxy] = []
            for proxy in self.proxies:
                try:
                    proxy.close()
                except BaseException as error:  # noqa: BLE001 - retain only the exact failed proxy
                    failures.append(error)
                    remaining_proxies.append(proxy)
            self.proxies = tuple(remaining_proxies)

            if not self._container_removed:
                kill_failure: BaseException | None = None
                if self._exit_code is None:
                    try:
                        self._backend._run((self._backend.docker_executable, "kill", self.container_id), None)
                    except BaseException as error:  # noqa: BLE001 - forced removal remains authoritative
                        kill_failure = error
                try:
                    removed = self._backend._run(
                        (self._backend.docker_executable, "rm", "--force", "--volumes", self.container_id),
                        None,
                    )
                    _checked(removed, f"remove container {self.container_id}")
                except BaseException as error:  # noqa: BLE001 - retain the exact ID for retry
                    if kill_failure is not None:
                        error.add_note(f"Docker kill also failed: {kill_failure}")
                    failures.append(error)
                else:
                    self._container_removed = True

            if self.qemu_bridge is not None:
                bridge = self.qemu_bridge
                try:
                    bridge.close()
                except BaseException as error:  # noqa: BLE001 - exact bridge remains retryable
                    failures.append(error)
                else:
                    if self.qemu_bridge is bridge:
                        self.qemu_bridge = None

            cleanup_complete = (
                self.attach is None and not self.proxies and self.qemu_bridge is None and self._container_removed
            )
            if cleanup_complete:
                try:
                    self._backend._release(self)
                except BaseException as error:  # noqa: BLE001 - retry backend ownership release
                    failures.append(error)
                else:
                    self._closed = True

            if failures:
                error = SandboxBackendError(f"Docker instance cleanup failed ({len(failures)} error(s))")
                for failure in failures:
                    error.add_note(str(failure))
                raise error from failures[0]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


class DockerBackend:
    """Own a Docker session network and exact-ID challenge containers."""

    def __init__(
        self,
        *,
        session_id: str | None = None,
        docker_executable: str = "docker",
        shim_path: os.PathLike[str] | str | None = None,
        control_socket: os.PathLike[str] | str | None = None,
        runner: CommandRunner | None = None,
        popen: PopenFactory | None = None,
    ):
        session_id = session_id or uuid.uuid4().hex
        if not isinstance(session_id, str) or _SESSION_ID.fullmatch(session_id) is None:
            raise SandboxConfigError("Docker session_id contains unsupported characters")
        if not isinstance(docker_executable, str) or not docker_executable or "\0" in docker_executable:
            raise SandboxConfigError("docker_executable must be nonempty text without NUL")
        if (shim_path is None) != (control_socket is None):
            raise SandboxConfigError("shim_path and control_socket must be configured together")

        uid, gid = os.getuid(), os.getgid()
        if uid == 0 or os.geteuid() == 0:
            raise SandboxCapabilityError(
                "Docker sandboxes cannot run as root; invoke pwnc as an unprivileged host user"
            )

        self.session_id = session_id
        self.docker_executable = docker_executable
        self.uid = uid
        self.gid = gid
        self.shim_path = Path(shim_path).expanduser().absolute() if shim_path is not None else None
        self.control_socket = Path(control_socket).expanduser().absolute() if control_socket is not None else None
        self._runner = runner or _run_subprocess
        self._popen = popen or subprocess.Popen
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._instances: dict[str, DockerInstance] = {}
        self._pending_cleanup: list[_DockerPendingCleanup] = []
        self._built_images: dict[object, str] = {}
        self._internal_network_id: str | None = None
        self._close_started = False
        self._closing = False
        self._closed = False

    @property
    def internal_network_id(self) -> str | None:
        with self._lock:
            return self._internal_network_id

    @property
    def built_image_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(dict.fromkeys(self._built_images.values()))

    def _run(self, argv: tuple[str, ...], timeout: float | None) -> subprocess.CompletedProcess[bytes]:
        return self._runner(argv, timeout)

    def _command(self, arguments: Sequence[str], action: str) -> bytes:
        argv = (self.docker_executable, *arguments)
        return _checked(self._run(argv, None), action)

    def _network_name(self) -> str:
        suffix = uuid.uuid5(uuid.NAMESPACE_URL, f"pwnc-docker:{self.session_id}").hex[:12]
        return f"pwnc-{self.session_id[:24]}-{suffix}"

    def _ensure_network(self) -> tuple[str, bool]:
        if self._internal_network_id is not None:
            return self._internal_network_id, False
        output = self._command(
            (
                "network",
                "create",
                "--driver",
                "bridge",
                "--internal",
                "--label",
                f"{_MANAGED_LABEL}=true",
                "--label",
                f"{_SESSION_LABEL}={self.session_id}",
                self._network_name(),
            ),
            "create isolated session network",
        )
        network_id = _parse_identifier(output, _CONTAINER_ID, "network")
        self._internal_network_id = network_id
        return network_id, True

    def _remove_network(self, network_id: str, *, checked: bool) -> None:
        result = self._run((self.docker_executable, "network", "rm", network_id), None)
        if checked or result.returncode != 0:
            _checked(result, f"remove session network {network_id}")
        if self._internal_network_id == network_id:
            self._internal_network_id = None

    def _resolve_image(self, spec: SandboxSpec) -> str:
        docker = spec.docker
        if docker.image is not None:
            return docker.image
        cached = self._built_images.get(docker)
        if cached is not None:
            return cached
        assert docker.build_context is not None
        if not docker.build_context.is_dir():
            raise SandboxConfigError(f"Docker build context is not a directory: {docker.build_context}")
        if docker.dockerfile is not None and not docker.dockerfile.is_file():
            raise SandboxConfigError(f"Dockerfile is not a file: {docker.dockerfile}")
        arguments = [
            "build",
            "--quiet",
            "--label",
            f"{_MANAGED_LABEL}=true",
            "--label",
            f"{_SESSION_LABEL}={self.session_id}",
        ]
        if docker.pull == "always":
            arguments.append("--pull")
        elif docker.pull == "never":
            arguments.append("--pull=false")
        if docker.platform is not None:
            arguments.extend(("--platform", docker.platform))
        if docker.dockerfile is not None:
            arguments.extend(("--file", os.fspath(docker.dockerfile)))
        arguments.append(os.fspath(docker.build_context))
        output = self._command(arguments, "build challenge image")
        image = _parse_identifier(output, _IMAGE_ID, "image")
        self._built_images[docker] = image
        return image

    @staticmethod
    def _image_qemu_executable(spec: SandboxSpec) -> str:
        assert spec.qemu is not None
        if spec.qemu.binary is not None:
            return spec.qemu.binary
        try:
            name = qemu_binary_names_for_arch(spec.qemu.architecture, static=False)[0]
        except (QemuUserError, TypeError, ValueError) as error:
            raise SandboxConfigError(str(error)) from error
        return name

    def _qemu_runtime(self, spec: SandboxSpec) -> _DockerQemuRuntime | None:
        qemu = spec.qemu
        if qemu is None:
            return None
        if not spec.command[0].startswith("/"):
            raise SandboxConfigError("QEMU sandbox commands must use an absolute container executable path")
        if self.control_socket is None:
            raise SandboxConfigError("QEMU sandboxes require DockerBackend shim_path and control_socket")

        image_executable = self._image_qemu_executable(spec)
        command_executable = image_executable
        fallback_executable: str | None = None
        mounts: list[str] = []
        displayed_emulator = image_executable

        if qemu.source in {"host", "auto"}:
            explicit = qemu.binary if qemu.source == "host" else None
            try:
                resolved = resolve_qemu(qemu.architecture, executable=explicit, static=True)
            except QemuNotFoundError as error:
                if qemu.source == "host":
                    raise SandboxCapabilityError(str(error)) from error
            else:
                host_path = Path(os.fsdecode(resolved.path)).resolve(strict=True)
                mounts.append(_mount_argument(host_path, _CONTAINER_QEMU, read_only=True))
                if qemu.source == "host":
                    command_executable = _CONTAINER_QEMU
                    displayed_emulator = os.fspath(host_path)
                else:
                    fallback_executable = _CONTAINER_QEMU
                    displayed_emulator = f"{image_executable} (host fallback {host_path})"

        try:
            layout_arguments = guest_layout_args(qemu.architecture, qemu.guest_aslr)
        except (QemuUserError, TypeError, ValueError) as error:
            raise SandboxCapabilityError(str(error)) from error

        bridge = None
        debug = None
        command = [command_executable]
        if spec.pause_at_exec:
            # QEMU 7.1+ accepts a raw Unix pathname and blocks before the first
            # guest instruction.  ``suspend=n`` did not exist before QEMU 10,
            # so running profiles omit -g instead of silently suspending.
            bridge = QemuGdbBridge(self.control_socket.parent / f"debug-{uuid.uuid4().hex}")
            mounts.append(_mount_argument(bridge.directory, _CONTAINER_DEBUG_DIR, read_only=False))
            command.extend(("-g", _CONTAINER_GDB_SOCKET))
            debug = SandboxDebug(
                transport="tcp",
                architecture=qemu.architecture,
                emulator=displayed_emulator,
                host=bridge.host,
                port=bridge.host_port,
            )
        command.extend(layout_arguments)
        if qemu.sysroot is not None:
            command.extend(("-L", qemu.sysroot))
        command.extend(spec.command)
        return _DockerQemuRuntime(
            command=tuple(command),
            mounts=tuple(mounts),
            fallback_executable=fallback_executable,
            bridge=bridge,
            debug=debug,
        )

    @staticmethod
    def _validate_host_aslr(spec: SandboxSpec) -> None:
        if spec.host_aslr is not True:
            return
        setting = Path("/proc/sys/kernel/randomize_va_space")
        try:
            enabled = int(setting.read_text(encoding="ascii").strip())
        except (OSError, ValueError) as error:
            raise SandboxCapabilityError(f"cannot verify host ASLR policy from {setting}: {error}") from error
        if enabled <= 0:
            raise SandboxCapabilityError(
                "host_aslr=true cannot override kernel.randomize_va_space=0; enable host ASLR first"
            )

    def _shim_arguments(
        self,
        spec: SandboxSpec,
        qemu_runtime: _DockerQemuRuntime | None = None,
    ) -> tuple[list[str], list[str], Path | None]:
        if self.shim_path is None or self.control_socket is None:
            if spec.pause_at_exec:
                raise SandboxConfigError("pause_at_exec requires DockerBackend shim_path and control_socket")
            if spec.host_aslr is not None:
                raise SandboxConfigError("host_aslr requires DockerBackend shim_path and control_socket")
            return [], list(spec.command), None
        if not self.shim_path.is_file() or not os.access(self.shim_path, os.X_OK):
            raise SandboxConfigError(f"Docker shim is not an executable file: {self.shim_path}")
        control_directory = self.control_socket.parent
        if not control_directory.is_dir():
            raise SandboxConfigError(f"Docker shim control directory does not exist: {control_directory}")
        control_target = f"{_CONTAINER_CONTROL_DIR}/{self.control_socket.name}"
        mounts = [
            _mount_argument(self.shim_path, _CONTAINER_SHIM, read_only=True),
            # The shim only needs to connect to this one socket.  Mounting the
            # containing host runtime directory would let the target unlink
            # manager endpoints or fill the host filesystem through it.
            _mount_argument(self.control_socket, control_target, read_only=True),
        ]
        command = [_CONTAINER_SHIM, "--control", control_target]
        native_pause = spec.pause_at_exec and qemu_runtime is None
        command.append("--pause" if native_pause else "--no-pause")
        if spec.host_aslr is not None:
            command.extend(("--host-aslr", "on" if spec.host_aslr else "off"))
        target_command = spec.command if qemu_runtime is None else qemu_runtime.command
        if qemu_runtime is not None and qemu_runtime.fallback_executable is not None:
            command.extend(("--fallback-executable", qemu_runtime.fallback_executable))
        command.extend(("--", *target_command))
        return mounts, command, self.control_socket

    def _create_arguments(
        self,
        spec: SandboxSpec,
        *,
        image: str,
        network: str,
        instance_token: str,
        qemu_runtime: _DockerQemuRuntime | None = None,
    ) -> list[str]:
        extra_args = _validate_extra_args(spec.docker.extra_args)
        endpoints = [(port.internal_port, port.protocol) for port in spec.ports]
        if len(endpoints) != len(set(endpoints)):
            raise SandboxConfigError("Docker cannot unambiguously name duplicate internal port/protocol bindings")

        shim_mounts, command, _control_socket = self._shim_arguments(spec, qemu_runtime)
        if qemu_runtime is not None:
            shim_mounts.extend(qemu_runtime.mounts)
        if shim_mounts:
            for mount in spec.mounts:
                if mount.target == _PRIVATE_DIR or mount.target.startswith(_PRIVATE_DIR + "/"):
                    raise SandboxConfigError(f"sandbox mount target overlaps Docker shim directory: {mount.target}")
                if _PRIVATE_DIR.startswith(mount.target.rstrip("/") + "/"):
                    raise SandboxConfigError(f"sandbox mount target contains Docker shim directory: {mount.target}")

        arguments = [
            "create",
            "--pull",
            "never" if spec.docker.build_context is not None else spec.docker.pull,
            "--user",
            f"{self.uid}:{self.gid}",
            "--cap-drop",
            "ALL",
        ]
        if spec.pause_at_exec and qemu_runtime is None:
            arguments.extend(("--cap-add", "SYS_PTRACE"))
        entrypoint, *command_arguments = command
        arguments.extend(
            (
                # Image metadata is untrusted challenge input.  In particular,
                # an image ENTRYPOINT or HEALTHCHECK must not execute outside
                # the capability-clearing, post-exec shim handoff.
                "--entrypoint",
                entrypoint,
                "--no-healthcheck",
                "--security-opt",
                "no-new-privileges=true",
                "--network",
                network,
                "--label",
                f"{_MANAGED_LABEL}=true",
                "--label",
                f"{_SESSION_LABEL}={self.session_id}",
                "--label",
                f"{_PROFILE_LABEL}={spec.profile}",
                "--label",
                f"{_INSTANCE_LABEL}={instance_token}",
            )
        )
        if spec.host_aslr is False:
            if not _HOST_NO_ASLR_SECCOMP.is_file():
                raise SandboxConfigError(f"host ASLR seccomp profile is missing: {_HOST_NO_ASLR_SECCOMP}")
            arguments.extend(("--security-opt", f"seccomp={_HOST_NO_ASLR_SECCOMP}"))
        if spec.stdio in {SandboxStdio.PIPE, SandboxStdio.PTY}:
            arguments.append("--interactive")
        if spec.stdio is SandboxStdio.PTY:
            arguments.append("--tty")
        if spec.read_only_root:
            arguments.append("--read-only")
        if spec.docker.platform is not None:
            arguments.extend(("--platform", spec.docker.platform))
        if spec.cwd is not None:
            arguments.extend(("--workdir", spec.cwd))
        for key, value in sorted(spec.env.items()):
            arguments.extend(("--env", f"{key}={value}"))
        for mount in spec.mounts:
            if not mount.source.exists():
                raise SandboxConfigError(f"Docker bind mount source does not exist: {mount.source}")
            arguments.extend(("--mount", _mount_argument(mount.source, mount.target, read_only=mount.read_only)))
        for mount in shim_mounts:
            arguments.extend(("--mount", mount))
        if spec.allow_egress:
            for port in spec.ports:
                arguments.extend(("--publish", _publish_argument(port)))
        arguments.extend(extra_args)
        # Keep even a malformed or attacker-supplied image reference in the
        # positional image slot.  Without the explicit terminator, a value
        # such as ``--privileged`` would be parsed by the Docker CLI as one of
        # its own options instead of failing as an invalid image reference.
        arguments.extend(("--", image, *command_arguments))
        return arguments

    def _start_attached(self, container_id: str, mode: SandboxStdio) -> DockerAttach:
        if mode is SandboxStdio.NONE:
            raise AssertionError("NONE stdio must use detached Docker start")
        # ``docker start --attach`` asks the daemon to attach the streams before
        # starting PID 1.  A later ``docker attach`` cannot recover output that
        # a fast challenge wrote between the two independent commands.
        argv = (self.docker_executable, "start", "--attach", "--interactive", container_id)
        if mode is SandboxStdio.PIPE:
            try:
                process = self._popen(
                    argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                    close_fds=True,
                    start_new_session=True,
                )
            except OSError as error:
                raise SandboxBackendError(
                    f"could not start and attach to Docker container {container_id}: {error}"
                ) from error
            return DockerAttach(
                process=process,
                mode=mode,
                stdin=process.stdin,
                stdout=process.stdout,
                stderr=None,
            )

        master_fd, slave_fd = pty.openpty()
        try:
            tty.setraw(slave_fd)
            process = self._popen(
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                start_new_session=True,
            )
        except BaseException:
            os.close(master_fd)
            os.close(slave_fd)
            raise
        os.close(slave_fd)
        return DockerAttach(process=process, mode=mode, master_fd=master_fd)

    def _start_events(self, container_id: str) -> _DockerEventStream:
        argv = (
            self.docker_executable,
            "events",
            "--since",
            "0",
            "--filter",
            f"container={container_id}",
            "--filter",
            "event=create",
            "--filter",
            "event=start",
            "--format",
            "{{.Action}}",
        )
        try:
            process = self._popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as error:
            raise SandboxBackendError(
                f"could not subscribe to Docker events for container {container_id}: {error}"
            ) from error
        assert process.stdout is not None
        return _DockerEventStream(process=process, stdout=process.stdout)

    def _cleanup_pending(self, cleanup: _DockerPendingCleanup) -> list[BaseException]:
        failures: list[BaseException] = []
        if cleanup.events is not None:
            events = cleanup.events
            try:
                events.close()
            except BaseException as error:  # noqa: BLE001 - every cleanup stage must run
                failures.append(error)
            else:
                if cleanup.events is events:
                    cleanup.events = None
        if cleanup.attach is not None:
            attach = cleanup.attach
            try:
                attach.close()
            except BaseException as error:  # noqa: BLE001 - every cleanup stage must run
                failures.append(error)
            else:
                if cleanup.attach is attach:
                    cleanup.attach = None

        remaining_proxies: list[DockerTCPProxy] = []
        for proxy in cleanup.proxies:
            try:
                proxy.close()
            except BaseException as error:  # noqa: BLE001 - retain exact failed proxies
                failures.append(error)
                remaining_proxies.append(proxy)
        cleanup.proxies = tuple(remaining_proxies)

        if cleanup.container_id is not None:
            container_id = cleanup.container_id
            kill_failure: BaseException | None = None
            try:
                self._run((self.docker_executable, "kill", container_id), None)
            except BaseException as error:  # noqa: BLE001 - removal must still run
                kill_failure = error
            try:
                removed = self._run((self.docker_executable, "rm", "--force", "--volumes", container_id), None)
                _checked(removed, f"remove failed container {container_id}")
            except BaseException as error:  # noqa: BLE001 - retain exact ID for a later close
                if kill_failure is not None:
                    error.add_note(f"Docker kill also failed: {kill_failure}")
                failures.append(error)
            else:
                cleanup.container_id = None

        if cleanup.qemu_bridge is not None:
            bridge = cleanup.qemu_bridge
            try:
                bridge.close()
            except BaseException as error:  # noqa: BLE001 - retain exact failed bridge
                failures.append(error)
            else:
                if cleanup.qemu_bridge is bridge:
                    cleanup.qemu_bridge = None
        return failures

    def _reserve_proxies(self, spec: SandboxSpec) -> tuple[DockerTCPProxy, ...]:
        if spec.allow_egress:
            return ()
        proxies: list[DockerTCPProxy] = []
        try:
            for port in spec.ports:
                proxies.append(DockerTCPProxy(port))
        except BaseException as error:
            cleanup = _DockerPendingCleanup(container_id=None, attach=None, proxies=tuple(proxies))
            cleanup_failures = self._cleanup_pending(cleanup)
            if not cleanup.complete:
                self._pending_cleanup.append(cleanup)
            for cleanup_error in cleanup_failures:
                error.add_note(f"also failed to close reserved Docker TCP proxy: {cleanup_error}")
            raise
        return tuple(proxies)

    def spawn(self, spec: SandboxSpec) -> DockerInstance:
        if not isinstance(spec, SandboxSpec):
            raise TypeError("spec must be a SandboxSpec")
        with self._lock:
            if self._close_started or self._closed:
                raise SandboxBackendError("Docker backend is closed")
            _validate_extra_args(spec.docker.extra_args)
            self._validate_host_aslr(spec)
            image = self._resolve_image(spec)
            network_created = False
            container_id: str | None = None
            attach: DockerAttach | None = None
            events: _DockerEventStream | None = None
            proxies: tuple[DockerTCPProxy, ...] = ()
            qemu_runtime: _DockerQemuRuntime | None = None
            try:
                qemu_runtime = self._qemu_runtime(spec)
                proxies = self._reserve_proxies(spec)
                if spec.allow_egress:
                    network = "bridge"
                else:
                    network, network_created = self._ensure_network()
                instance_token = uuid.uuid4().hex
                create_arguments = self._create_arguments(
                    spec,
                    image=image,
                    network=network,
                    instance_token=instance_token,
                    qemu_runtime=qemu_runtime,
                )
                output = self._command(create_arguments, "create challenge container")
                container_id = _parse_identifier(output, _CONTAINER_ID, "container")
                if spec.stdio is SandboxStdio.NONE:
                    self._command(("start", container_id), f"start container {container_id}")
                else:
                    # The historical create event is a protocol-level readiness
                    # barrier: once observed, this exact-ID subscription is live
                    # before the atomic attached start is issued.
                    events = self._start_events(container_id)
                    events.expect("create")
                    attach = self._start_attached(container_id, spec.stdio)
                    events.expect("start")
                    events.close()
                    events = None
                inspect = self._command(("inspect", container_id), f"inspect container {container_id}")
                if spec.allow_egress:
                    host_pid, bindings, _container_address = _parse_inspect(inspect, container_id, spec.ports)
                else:
                    host_pid, _docker_bindings, container_address = _parse_inspect(
                        inspect,
                        container_id,
                        (),
                        network_id=network if proxies else None,
                    )
                    bindings = tuple(proxy.binding for proxy in proxies)
                    if proxies:
                        assert container_address is not None
                        for proxy in proxies:
                            proxy.start(container_address)
                instance = DockerInstance(
                    container_id=container_id,
                    host_pid=host_pid,
                    ports=bindings,
                    stdio=spec.stdio,
                    image=image,
                    attach=attach,
                    proxies=proxies,
                    qemu_bridge=None if qemu_runtime is None else qemu_runtime.bridge,
                    debug=None if qemu_runtime is None else qemu_runtime.debug,
                    paused=spec.pause_at_exec,
                    shim_control_socket=self.control_socket if self.shim_path is not None else None,
                    _backend=self,
                )
                self._instances[container_id] = instance
                # Ownership moved into the published instance.
                qemu_runtime = None
                return instance
            except BaseException as error:
                cleanup = _DockerPendingCleanup(
                    container_id=container_id,
                    attach=attach,
                    proxies=proxies,
                    qemu_bridge=None if qemu_runtime is None else qemu_runtime.bridge,
                    events=events,
                )
                cleanup_failures = self._cleanup_pending(cleanup)
                if not cleanup.complete:
                    self._pending_cleanup.append(cleanup)
                for cleanup_error in cleanup_failures:
                    error.add_note(f"also failed to clean Docker spawn resource: {cleanup_error}")
                if (
                    network_created
                    and not self._instances
                    and not self._pending_cleanup
                    and self._internal_network_id is not None
                ):
                    try:
                        self._remove_network(self._internal_network_id, checked=False)
                    except BaseException as cleanup_error:  # noqa: BLE001 - preserve original lifecycle error
                        error.add_note(f"also failed to remove Docker session network: {cleanup_error}")
                raise

    def _release(self, instance: DockerInstance) -> None:
        with self._lock:
            if self._instances.get(instance.container_id) is instance:
                del self._instances[instance.container_id]

    def close(self) -> None:
        with self._condition:
            self._close_started = True
            while self._closing:
                self._condition.wait()
                if self._closed:
                    return
            if self._closed:
                return
            self._closing = True
            instances = tuple(self._instances.values())
            pending_cleanup = tuple(self._pending_cleanup)

        failures: list[BaseException] = []
        completed_pending: set[int] = set()
        try:
            for instance in instances:
                try:
                    instance.close()
                except BaseException as error:  # noqa: BLE001 - finish exact-ID cleanup
                    failures.append(error)
            for cleanup in pending_cleanup:
                failures.extend(self._cleanup_pending(cleanup))
                if cleanup.complete:
                    completed_pending.add(id(cleanup))

            with self._condition:
                if completed_pending:
                    self._pending_cleanup = [
                        cleanup for cleanup in self._pending_cleanup if id(cleanup) not in completed_pending
                    ]
                resources_remain = bool(self._instances or self._pending_cleanup)
                network_id = self._internal_network_id
                if network_id is not None and not resources_remain:
                    try:
                        self._remove_network(network_id, checked=True)
                    except BaseException as error:  # noqa: BLE001 - retain exact network ID
                        failures.append(error)
                image_ids = tuple(dict.fromkeys(self._built_images.values())) if not resources_remain else ()
                removed_images: set[str] = set()
                for image_id in image_ids:
                    try:
                        removed = self._run((self.docker_executable, "image", "rm", image_id), None)
                        _checked(removed, f"remove session image {image_id}")
                    except BaseException as error:  # noqa: BLE001 - retain exact image ID
                        failures.append(error)
                    else:
                        removed_images.add(image_id)
                if removed_images:
                    self._built_images = {
                        key: image_id for key, image_id in self._built_images.items() if image_id not in removed_images
                    }
                if (
                    not self._instances
                    and not self._pending_cleanup
                    and self._internal_network_id is None
                    and not self._built_images
                ):
                    self._closed = True
        finally:
            with self._condition:
                self._closing = False
                self._condition.notify_all()
        if failures:
            error = SandboxBackendError(f"Docker backend cleanup failed ({len(failures)} error(s))")
            for failure in failures:
                error.add_note(str(failure))
            raise error from failures[0]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


__all__ = [
    "CommandRunner",
    "DockerAttach",
    "DockerBackend",
    "DockerInstance",
    "DockerTCPProxy",
    "PopenFactory",
]
