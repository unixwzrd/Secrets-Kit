"""
secrets_kit.seckitd.server

Unix domain socket listener for ``seckitd``.
"""

from __future__ import annotations

import os
import signal
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from secrets_kit.runtime.identity import default_agent_id
from secrets_kit.runtime.paths import RuntimeLayout, ensure_runtime_dir as ensure_runtime_namespace_dir, runtime_layout
from secrets_kit.runtime.registry import EndpointRecord, register_endpoint, unregister_endpoint
from secrets_kit.transport.framing import (
    FramingError,
    frame_json,
    parse_json_object,
    read_frame,
)
from secrets_kit.seckitd.loopback_transport import LoopbackTransport
from secrets_kit.seckitd.peer_cred import PeerCredentialError, verify_unix_peer_euid
from secrets_kit.seckitd.protocol import DaemonState, handle_request
from secrets_kit.transport.unix import configure_unix_ipc_socket, probe_unix_socket


def runtime_loopback_enabled() -> bool:
    v = os.environ.get("SECKITD_RUNTIME_LOOPBACK", "").strip().lower()
    return v in ("1", "true", "yes")


def ensure_runtime_dir(path: Path) -> None:
    """Create runtime directory with owner-only permissions."""
    ensure_runtime_namespace_dir(path)


def bind_unix_socket(path: Path) -> socket.socket:
    """Bind a new Unix stream socket at ``path`` after stale-socket probing."""
    ensure_runtime_dir(path.parent)
    if path.exists():
        if probe_unix_socket(path, timeout_s=0.1):
            raise OSError(f"Unix socket already active: {path}")
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    configure_unix_ipc_socket(sock)
    sock.bind(str(path))
    os.chmod(path, 0o600)
    return sock


def serve_forever(
    *,
    socket_path: Optional[Path] = None,
    instance: Optional[str] = None,
    agent_id: Optional[str] = None,
    seckit_argv: Optional[List[str]] = None,
    child_env: Optional[Dict[str, str]] = None,
    stop_flag: Optional[Any] = None,
) -> None:
    """Accept connections until ``stop_flag`` is set or SIGINT/SIGTERM.

    ``stop_flag`` may be a threading.Event-like object with ``is_set()`` → bool.
    """
    agent = default_agent_id(agent_id)
    layout: Optional[RuntimeLayout] = None
    endpoint_id = "local"
    if socket_path is None:
        layout = runtime_layout(instance=instance)
        socket_path = layout.agent_socket_path(agent)
    sock = bind_unix_socket(socket_path)
    sock.listen(8)
    state = DaemonState(agent_id=agent, instance_id=layout.instance if layout else (instance or "manual"))
    if layout is not None:
        pid_path = layout.agent_pid_path(agent)
        lock_path = layout.agent_lock_path(agent)
        pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
        os.chmod(pid_path, 0o600)
        lock_path.write_text(f"{uuid.uuid4()}\n", encoding="utf-8")
        os.chmod(lock_path, 0o600)
        register_endpoint(
            layout,
            EndpointRecord(
                instance_id=layout.instance,
                agent_id=agent,
                endpoint_id=endpoint_id,
                socket_path=str(socket_path),
                pid=os.getpid(),
                uid=os.geteuid(),
                protocol_version=1,
                capabilities=["ping", "status", "sync_status", "peer_outbound", "peer_inbound_import"],
            ),
        )
    _stop = False
    ticker_stop: Optional[threading.Event] = None
    ticker_thread: Optional[threading.Thread] = None
    if runtime_loopback_enabled():
        state.loopback = LoopbackTransport()
        ticker_stop = threading.Event()

        def _tick_loop() -> None:
            """Daemon thread that periodically ticks the runtime session."""
            while not ticker_stop.is_set():
                if stop_flag is not None and stop_flag.is_set():
                    break
                if _stop:
                    break
                try:
                    assert state.loopback is not None
                    state.runtime.tick(state.loopback)
                except Exception:
                    pass
                time.sleep(0.05)

        ticker_thread = threading.Thread(target=_tick_loop, daemon=True)
        ticker_thread.start()

    def _handle_signal(signum: int, frame: Any) -> None:
        nonlocal _stop
        _stop = True

    main_thread = threading.current_thread() is threading.main_thread()
    old_int: Any = None
    old_term: Any = None
    if main_thread:
        old_int = signal.signal(signal.SIGINT, _handle_signal)
        old_term = signal.signal(signal.SIGTERM, _handle_signal)
    try:
        sock.settimeout(1.0)
        while not _stop and (stop_flag is None or not stop_flag.is_set()):
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if _stop:
                    break
                raise
            _handle_connection(
                conn=conn,
                state=state,
                seckit_argv=seckit_argv,
                child_env=child_env,
            )
    finally:
        if ticker_stop is not None:
            ticker_stop.set()
        if ticker_thread is not None:
            ticker_thread.join(timeout=2.0)
        if main_thread and old_int is not None and old_term is not None:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)
        try:
            sock.close()
        except OSError:
            pass
        if socket_path.exists():
            try:
                socket_path.unlink()
            except OSError:
                pass
        if layout is not None:
            unregister_endpoint(layout, instance_id=layout.instance, agent_id=agent, endpoint_id=endpoint_id)
            for artifact in (layout.agent_pid_path(agent), layout.agent_lock_path(agent)):
                try:
                    artifact.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass


def _handle_connection(
    *,
    conn: socket.socket,
    state: DaemonState,
    seckit_argv: Optional[List[str]],
    child_env: Optional[Dict[str, str]],
) -> None:
    """Read one framed JSON-RPC request, dispatch it, and send the response."""
    try:
        verify_unix_peer_euid(conn)
    except PeerCredentialError as exc:
        try:
            conn.sendall(frame_json({"ok": False, "error": str(exc)}))
        except OSError:
            pass
        return
    try:
        body = read_frame(conn)
        request = parse_json_object(body)
        response = handle_request(
            state=state,
            request=request,
            seckit_argv=seckit_argv,
            child_env=child_env,
        )
        conn.sendall(frame_json(response))
    except FramingError as exc:
        try:
            conn.sendall(frame_json({"ok": False, "error": str(exc)}))
        except OSError:
            pass
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
