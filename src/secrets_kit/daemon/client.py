"""
secrets_kit.daemon.client

Client and lifecycle helpers for the minimal seckitd UDS daemon.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from secrets_kit.daemon.control import (
    control_message_bytes,
    route_frame_bytes,
    route_wait_message_bytes,
    runtime_access_message_bytes,
)

METADATA_FILENAME = "seckitd.json"
SOCKET_FILENAME = "seckitd.sock"
START_LOCK_FILENAME = "seckitd.start.lock"
DEFAULT_TCP_PORT = 19777
TCP_HOST = "127.0.0.1"
DAEMON_STARTUP_TIMEOUT_SECONDS = 30.0


class DaemonError(RuntimeError):
    """Raised when a daemon lifecycle operation fails."""


def runtime_dir() -> Path:
    raw = os.environ.get("SECKIT_DAEMON_RUNTIME_DIR") or os.environ.get("SECKIT_RUNTIME_DIR")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".local" / "share" / "seckit" / "runtime"


def metadata_path() -> Path:
    return runtime_dir() / METADATA_FILENAME


def uds_path() -> Path:
    return runtime_dir() / SOCKET_FILENAME


def start_lock_path() -> Path:
    return runtime_dir() / START_LOCK_FILENAME


def default_tcp_port(*, default: int = DEFAULT_TCP_PORT) -> int:
    """Return the configured daemon port, allowing libp2p to request port zero."""
    raw = os.environ.get("SECKIT_DAEMON_TCP_PORT")
    if raw is None:
        try:
            from secrets_kit.cli.config_defaults import load_config_defaults

            configured = load_config_defaults().get("daemon_tcp_port")
        except Exception:
            configured = None
        raw = str(configured) if configured is not None else str(default)
    try:
        port = int(raw)
    except ValueError as exc:
        raise DaemonError("daemon tcp port must be an integer") from exc
    if port < 0 or port > 65535:
        raise DaemonError("daemon tcp port must be between 0 and 65535")
    return port


def daemon_tcp_host(*, default: str = TCP_HOST) -> str:
    """Return the daemon bind host, preserving localhost as the default."""
    raw = os.environ.get("SECKIT_DAEMON_TCP_HOST")
    if raw is None:
        try:
            from secrets_kit.cli.config_defaults import load_config_defaults

            configured = load_config_defaults().get("daemon_tcp_host")
        except Exception:
            configured = None
        raw = str(configured) if configured is not None else default
    host = raw.strip()
    if not host:
        raise DaemonError("daemon tcp host must not be empty")
    return host


@contextmanager
def _start_lock() -> Iterator[None]:
    runtime_dir().mkdir(parents=True, exist_ok=True)
    with start_lock_path().open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_metadata() -> dict[str, Any]:
    path = metadata_path()
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def request_daemon(*, command: str, timeout: float = 1.0) -> dict[str, Any]:
    payload = control_message_bytes(operation=command)
    return _request_socket(
        payload=payload, timeout=timeout, sock_factory=lambda: socket.socket(socket.AF_UNIX)
    )


def wait_daemon_route(*, peer_id: str, timeout_seconds: int = 30) -> None:
    """Wait for one authenticated route event over the owner-only UDS."""
    response = _request_socket(
        payload=route_wait_message_bytes(
            peer_id=peer_id, timeout_seconds=timeout_seconds
        ),
        timeout=timeout_seconds + 5,
        sock_factory=lambda: socket.socket(socket.AF_UNIX),
    )
    if response.get("status") != "ok" or response.get("response") != "route_connected":
        raise DaemonError(str(response.get("error") or "authorized route unavailable"))


def request_daemon_status(*, timeout: float = 2.0) -> dict[str, Any]:
    """Request the authoritative structured status from the local daemon."""
    response = request_daemon(command="status", timeout=timeout)
    if response.get("status") != "ok":
        raise DaemonError(str(response.get("details") or response.get("error") or "status request failed"))
    payload = response.get("data")
    if not isinstance(payload, dict):
        raise DaemonError("daemon returned no structured status")
    return payload


def request_secret_metadata(
    *,
    backend: str,
    service: str | None = None,
    account: str | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """List authorized non-secret metadata through the local runtime authority."""
    arguments: dict[str, Any] = {"backend": backend}
    if service is not None:
        arguments["service"] = service
    if account is not None:
        arguments["account"] = account
    response = _request_runtime_access(
        operation="list_metadata", arguments=arguments, timeout=timeout
    )
    entries = response.get("entries")
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise DaemonError("runtime returned invalid metadata")
    allowed = {
        "entry_id",
        "name",
        "service",
        "account",
        "type",
        "kind",
        "tags",
        "updated_at",
    }
    projected: list[dict[str, Any]] = []
    for item in entries:
        if not set(item).issubset(allowed):
            raise DaemonError("runtime returned unsafe metadata")
        projected.append({key: item[key] for key in allowed if key in item})
    return projected


def request_secret_value(
    *,
    backend: str,
    service: str,
    account: str,
    name: str,
    timeout: float = 5.0,
) -> str:
    """Explicitly materialize one authorized value through the local runtime authority."""
    response = _request_runtime_access(
        operation="resolve_secret",
        arguments={
            "backend": backend,
            "service": service,
            "account": account,
            "name": name,
        },
        timeout=timeout,
    )
    value = response.get("value")
    if not isinstance(value, str):
        raise DaemonError("runtime returned invalid secret material")
    return value


def _request_runtime_access(
    *, operation: str, arguments: dict[str, Any], timeout: float
) -> dict[str, Any]:
    """Send one local-only runtime authority request and validate its safe envelope."""
    response = _request_socket(
        payload=runtime_access_message_bytes(operation=operation, arguments=arguments),
        timeout=timeout,
        sock_factory=lambda: socket.socket(socket.AF_UNIX),
    )
    if response.get("status") != "ok":
        error = response.get("error")
        raise DaemonError(str(error) if isinstance(error, str) else "runtime access failed")
    data = response.get("data")
    if not isinstance(data, dict):
        raise DaemonError("runtime returned invalid response")
    return data


def request_opaque_route(
    *,
    peer_id: str,
    payload: bytes,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Submit opaque bytes and a peer identity to the local daemon."""
    return _request_socket(
        payload=route_frame_bytes(peer_id=peer_id, payload=payload),
        timeout=timeout,
        sock_factory=lambda: socket.socket(socket.AF_UNIX),
    )


def request_daemon_tcp(*, command: str, port: int | None = None, timeout: float = 1.0) -> dict[str, Any]:
    payload = control_message_bytes(operation=command)

    def make_socket() -> socket.socket:
        return socket.create_connection((daemon_tcp_host(), port or active_tcp_port()), timeout=timeout)

    return _request_socket(payload=payload, timeout=timeout, sock_factory=make_socket)


def send_opaque_tcp(
    *,
    payload: bytes,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 1.0,
) -> dict[str, Any]:
    def make_socket() -> socket.socket:
        return socket.create_connection((host or daemon_tcp_host(), port or active_tcp_port()), timeout=timeout)

    return _request_socket(payload=payload, timeout=timeout, sock_factory=make_socket)


def _request_socket(
    *,
    payload: bytes,
    timeout: float = 1.0,
    sock_factory: Any,
) -> dict[str, Any]:
    chunks: list[bytes] = []
    with sock_factory() as sock:
        sock.settimeout(timeout)
        if sock.family == socket.AF_UNIX:
            sock.connect(str(uds_path()))
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise DaemonError("invalid daemon response") from exc
    if not isinstance(response, dict):
        raise DaemonError("invalid daemon response")
    return response


def ping_daemon(*, timeout: float = 1.0) -> bool:
    try:
        response = request_daemon(command="ping", timeout=timeout)
    except (DaemonError, OSError):
        return False
    return response.get("status") == "ok" and response.get("response") == "pong"


def wait_until_running(*, timeout: float = DAEMON_STARTUP_TIMEOUT_SECONDS) -> bool:
    """
    Wait a bounded interval for the local daemon to answer a ping.

    ``timeout`` is the maximum startup interval in seconds. The helper returns
    whether the daemon became reachable and performs no unbounded retries.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ping_daemon(timeout=0.2):
            return True
        time.sleep(0.05)
    return ping_daemon(timeout=0.2)


def start_daemon(*, timeout: float = DAEMON_STARTUP_TIMEOUT_SECONDS) -> bool:
    """
    Start the daemon and wait for bounded runtime initialization.

    ``timeout`` is passed to :func:`wait_until_running`. The function returns
    ``True`` when it starts a new daemon and ``False`` when one is already
    reachable. It creates the protected runtime directory, removes a stale
    socket, and launches a detached same-user process. A daemon that cannot
    answer within the bound raises :class:`DaemonError`.
    """
    if ping_daemon(timeout=0.2):
        return False
    with _start_lock():
        if ping_daemon(timeout=0.2):
            return False
        rdir = runtime_dir()
        rdir.mkdir(parents=True, exist_ok=True)
        path = uds_path()
        if path.exists():
            path.unlink()
        env = dict(os.environ)
        env["SECKIT_DAEMON_RUNTIME_DIR"] = str(rdir)
        process = subprocess.Popen(
            [sys.executable, "-m", "secrets_kit.daemon.server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env=env,
            start_new_session=True,
        )
        if not wait_until_running(timeout=timeout):
            # Own only the child we launched, never a PID recovered from state.
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
            raise DaemonError("daemon did not become reachable")
        # Keep the handle alive and reap on exit in long-lived CLI consumers.
        # A daemon thread does not prevent the launching CLI from exiting.
        threading.Thread(target=process.wait, name="seckit-daemon-reaper", daemon=True).start()
        return True


def stop_daemon(*, timeout: float = 5.0) -> bool:
    if not ping_daemon(timeout=0.2):
        return False
    try:
        request_daemon(command="shutdown", timeout=1.0)
    except (DaemonError, OSError) as exc:
        raise DaemonError("failed to request daemon shutdown") from exc
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not ping_daemon(timeout=0.2):
            return True
        time.sleep(0.05)
    raise DaemonError("daemon did not stop")


def daemon_status() -> dict[str, Any]:
    metadata = read_metadata()
    return {
        "running": ping_daemon(timeout=0.2),
        "pid": metadata.get("pid"),
        "uds_path": metadata.get("uds_path") or str(uds_path()),
        "tcp_port": metadata.get("tcp_port"),
        "transport": metadata.get("transport"),
        "transport_requested": metadata.get("transport_requested"),
        "transport_endpoint": metadata.get("endpoint"),
        "startup_timestamp": metadata.get("startup_timestamp"),
    }


def active_tcp_port() -> int:
    port = daemon_status().get("tcp_port")
    if isinstance(port, int):
        return port
    raise DaemonError("daemon tcp port is not available")


__all__ = [
    "DEFAULT_TCP_PORT",
    "DaemonError",
    "TCP_HOST",
    "daemon_tcp_host",
    "active_tcp_port",
    "daemon_status",
    "default_tcp_port",
    "metadata_path",
    "ping_daemon",
    "read_metadata",
    "request_daemon",
    "request_daemon_status",
    "request_daemon_tcp",
    "request_secret_metadata",
    "request_secret_value",
    "request_opaque_route",
    "runtime_dir",
    "start_lock_path",
    "start_daemon",
    "stop_daemon",
    "uds_path",
    "wait_until_running",
    "send_opaque_tcp",
]
