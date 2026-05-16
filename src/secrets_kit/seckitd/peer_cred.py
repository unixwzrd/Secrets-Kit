"""
secrets_kit.seckitd.peer_cred

Unix stream socket peer UID checks (same-user ``seckitd`` boundary).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import struct
import sys
from typing import Callable


class PeerCredentialError(Exception):
    """Peer socket credential check failed (wrong user or unavailable)."""


# Linux `SOL_SOCKET` + `SO_PEERCRED` returns `struct ucred` (pid, uid, gid as u32).
_LINUX_UCRED_SIZE = struct.calcsize("=III")
_LINUX_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)


def _linux_peer_uid(conn: socket.socket) -> int:
    """Read the peer UID from a Linux socket using SO_PEERCRED."""
    cred = conn.getsockopt(socket.SOL_SOCKET, _LINUX_SO_PEERCRED, _LINUX_UCRED_SIZE)
    _pid, uid, _gid = struct.unpack("=III", cred)
    return int(uid)


def _getpeereid_uid(conn: socket.socket) -> int:
    """Read peer euid via libc ``getpeereid`` (macOS, *BSD, etc.)."""
    libname = ctypes.util.find_library("c")
    if not libname:
        raise OSError("libc not found for getpeereid")
    libc = ctypes.CDLL(libname)
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    rc = libc.getpeereid(conn.fileno(), ctypes.byref(uid), ctypes.byref(gid))
    if rc != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, "getpeereid failed")
    return int(uid.value)


def get_unix_peer_uid(conn: socket.socket) -> int:
    """Return the peer's effective uid for a connected Unix stream socket.

    Raises:
        OSError: Platform error or unsupported socket.
    """
    if sys.platform == "linux":
        return _linux_peer_uid(conn)
    return _getpeereid_uid(conn)


def insecure_skip_peer_cred_checks() -> bool:
    """Unsafe opt-out for containers / exotic UDS setups (documented only)."""
    return os.environ.get("SECKITD_INSECURE_SKIP_PEER_CRED", "").strip() == "1"


def verify_unix_peer_euid(
    conn: socket.socket,
    *,
    expected_euid: int | None = None,
    _peer_uid_fn: Callable[[socket.socket], int] | None = None,
) -> None:
    """Ensure peer uid matches daemon effective uid.

    When ``SECKITD_INSECURE_SKIP_PEER_CRED=1``, skips checks entirely (**unsafe**).

    Args:
        conn: Accepted Unix stream socket.
        expected_euid: Defaults to ``os.geteuid()`` for production; inject in tests.
        _peer_uid_fn: Override peer uid lookup (tests only).
    """
    if insecure_skip_peer_cred_checks():
        return
    exp = os.geteuid() if expected_euid is None else int(expected_euid)
    peer_fn = _peer_uid_fn or get_unix_peer_uid
    try:
        peer_uid = int(peer_fn(conn))
    except OSError as exc:
        raise PeerCredentialError(f"cannot read Unix socket peer credentials: {exc}") from exc
    if peer_uid != exp:
        raise PeerCredentialError(f"peer uid {peer_uid} != daemon euid {exp}")
