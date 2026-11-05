"""secrets_kit.backends.sqlite.peer_delivery_lock

Serialize local outbound delivery and revocation for one peer across processes.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager

from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.gate import sqlite_path
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier


@contextmanager
def peer_delivery_lock(*, node_id: str, timeout_seconds: float | None = None) -> Iterator[None]:
    """Hold an owner-only sidecar lock until the peer send or revoke completes."""
    try:
        validate_identifier(value=node_id, expected_type="node", field="node_id")
    except IdentifierValidationError as exc:
        raise SQLiteBackendError(str(exc)) from exc
    digest = hashlib.sha256(node_id.encode("utf-8")).hexdigest()
    path = sqlite_path().with_name(f".seckit-peer-delivery-{digest}.lock")
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError as exc:
        raise SQLiteBackendError(f"peer delivery lock is unavailable: {exc.strerror}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SQLiteBackendError("peer delivery lock has unsafe ownership or permissions")
        if timeout_seconds is None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise SQLiteBackendError(
                            "peer delivery is still active; revocation was not applied"
                        ) from exc
                    time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


__all__ = ["peer_delivery_lock"]
