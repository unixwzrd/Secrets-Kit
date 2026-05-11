"""Unix domain socket listener for ``seckitd``."""

from __future__ import annotations

import os
import signal
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from secrets_kit.seckitd.framing import FramingError, frame_json, parse_json_object, read_frame
from secrets_kit.seckitd.loopback_transport import LoopbackTransport
from secrets_kit.seckitd.peer_cred import PeerCredentialError, verify_unix_peer_euid
from secrets_kit.seckitd.protocol import DaemonState, handle_request


def runtime_loopback_enabled() -> bool:
    v = os.environ.get("SECKITD_RUNTIME_LOOPBACK", "").strip().lower()
    return v in ("1", "true", "yes")


def ensure_runtime_dir(path: Path) -> None:
    """Create runtime directory with owner-only permissions."""
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        if path.stat().st_mode & 0o077 != 0:
            path.chmod(0o700)
    except OSError:
        pass


def bind_unix_socket(path: Path) -> socket.socket:
    """Bind a new Unix stream socket at ``path`` (unlinks stale file first)."""
    ensure_runtime_dir(path.parent)
    if path.exists():
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, 0o600)
    return sock


def serve_forever(
    *,
    socket_path: Path,
    seckit_argv: Optional[List[str]] = None,
    child_env: Optional[Dict[str, str]] = None,
    stop_flag: Optional[Any] = None,
) -> None:
    """Accept connections until ``stop_flag`` is set or SIGINT/SIGTERM.

    ``stop_flag`` may be a threading.Event-like object with ``is_set()`` → bool.
    """
    sock = bind_unix_socket(socket_path)
    sock.listen(8)
    state = DaemonState()
    _stop = False
    ticker_stop: Optional[threading.Event] = None
    ticker_thread: Optional[threading.Thread] = None
    if runtime_loopback_enabled():
        state.loopback = LoopbackTransport()
        ticker_stop = threading.Event()

        def _tick_loop() -> None:
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


def _handle_connection(
    *,
    conn: socket.socket,
    state: DaemonState,
    seckit_argv: Optional[List[str]],
    child_env: Optional[Dict[str, str]],
) -> None:
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
