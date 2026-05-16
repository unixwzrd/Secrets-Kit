"""
secrets_kit.cli.support.args

Argparse-derived backend path and access helpers.
"""

from __future__ import annotations

import argparse
import os

from secrets_kit.backends.registry import BACKEND_SECURE, is_secure_backend, is_sqlite_backend
from secrets_kit.backends.sqlite import default_sqlite_db_path


def _keychain_arg(args: argparse.Namespace) -> str | None:
    """Return the ``--keychain`` override, or ``None`` for default."""
    return getattr(args, "keychain", None)


def _backend_arg(args: argparse.Namespace) -> str:
    """Return the effective backend identifier (defaults to ``secure``)."""
    return getattr(args, "backend", BACKEND_SECURE)


def _store_path(args: argparse.Namespace) -> str | None:
    """Backend store path: keychain file (secure) or SQLite database path (sqlite).

    Resolution order for SQLite:
    1. ``--db`` flag
    2. ``SECKIT_SQLITE_DB`` environment variable
    3. ``default_sqlite_db_path()``
    """
    backend = _backend_arg(args)
    if is_sqlite_backend(backend):
        db = getattr(args, "db", None)
        if db:
            return os.path.expanduser(str(db))
        env_db = os.environ.get("SECKIT_SQLITE_DB", "").strip()
        if env_db:
            return os.path.expanduser(env_db)
        return default_sqlite_db_path()
    return _keychain_arg(args)


def _kek_keychain_arg(args: argparse.Namespace) -> str | None:
    """Return the keychain path that holds the SQLite KEK, or ``None``.

    Only meaningful when ``backend`` is ``sqlite``; otherwise ``None``.
    """
    if not is_sqlite_backend(_backend_arg(args)):
        return None
    k = _keychain_arg(args)
    return os.path.expanduser(str(k)) if k else None


def _backend_access_kwargs(args: argparse.Namespace) -> dict[str, object]:
    """Build the ``**kwargs`` dict used by backend convenience functions.

    Keys: ``path``, ``backend``, ``kek_keychain_path``.
    """
    return {
        "path": _store_path(args),
        "backend": _backend_arg(args),
        "kek_keychain_path": _kek_keychain_arg(args),
    }


def _doctor_skip_missing_secret_scan(args: argparse.Namespace) -> bool:
    """Return ``True`` when doctor should skip the missing-secret scan.

    Skips when the operator has explicitly customised the store path
    (``--keychain`` for secure or ``--db`` for sqlite) because the
    default-path heuristics no longer apply.
    """
    backend = _backend_arg(args)
    if is_secure_backend(backend) and _keychain_arg(args) is not None:
        return True
    if is_sqlite_backend(backend) and getattr(args, "db", None):
        return True
    return False
