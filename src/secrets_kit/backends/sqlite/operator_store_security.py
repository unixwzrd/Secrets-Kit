"""
secrets_kit.backends.sqlite.operator_store_security

Permission validation for the local SQLite operator store.
"""

from __future__ import annotations

import getpass
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.node_identity import sqlite_node_identity_key_path
from secrets_kit.crypto.storage.sqlite import sqlite_storage_key_path


@dataclass(frozen=True)
class OperatorStorePathPolicy:
    """Expected ownership and mode for one operator-store path."""

    path: Path
    expected_mode: int
    kind: str


def is_operator_store_path(*, path: Path, home: Path | None = None) -> bool:
    """
    Return whether ``path`` is the canonical SQLite operator database path.

    Args:
        path:
            SQLite database path.
        home:
            Optional operator home override.

    Returns:
        True when the path is ``<home>/.config/seckit/seckit.sqlite``.

    Side Effects:
        None.
    """
    expected = registry_dir(home=home) / "seckit.sqlite"
    return path.expanduser() == expected.expanduser()


def registry_dir(*, home: Path | None = None) -> Path:
    """Return local Seckit config directory path without importing registry."""
    base = home or Path.home()
    return base / ".config" / "seckit"


def defaults_path(*, home: Path | None = None) -> Path:
    """Return operator defaults path without importing registry."""
    return registry_dir(home=home) / "defaults.json"


def registry_path(*, home: Path | None = None) -> Path:
    """Return operator registry path without importing registry."""
    return registry_dir(home=home) / "registry.json"


def validate_sqlite_operator_store(
    *,
    home: Path | None = None,
    sqlite_db_path: Path | None = None,
    current_uid: int | None = None,
    require_storage_key: bool = True,
) -> None:
    """
    Validate SQLite operator-store ownership and permissions.

    Args:
        home:
            Optional operator home override.
        sqlite_db_path:
            Optional explicit SQLite database path.
        current_uid:
            Optional current uid override for tests.
        require_storage_key:
            Whether ``sqlite-storage.key`` is required. Encrypted datastores
            require it; plaintext datastores do not create or use it.

    Returns:
        None.

    Raises:
        SQLiteBackendError:
            Any required path is missing, owned by another uid, or has an
            unsafe mode.

    Side Effects:
        Reads filesystem metadata only.
    """
    db_path = sqlite_db_path or (registry_dir(home=home) / "seckit.sqlite")
    policies = [
        OperatorStorePathPolicy(
            path=registry_dir(home=home),
            expected_mode=0o700,
            kind="directory",
        ),
        OperatorStorePathPolicy(
            path=defaults_path(home=home),
            expected_mode=0o600,
            kind="file",
        ),
        OperatorStorePathPolicy(
            path=registry_path(home=home),
            expected_mode=0o600,
            kind="file",
        ),
        OperatorStorePathPolicy(
            path=db_path,
            expected_mode=0o600,
            kind="file",
        ),
        OperatorStorePathPolicy(
            path=sqlite_node_identity_key_path(home=home),
            expected_mode=0o600,
            kind="file",
        ),
    ]
    if require_storage_key:
        policies.append(
            OperatorStorePathPolicy(
                path=sqlite_storage_key_path(home=home),
                expected_mode=0o600,
                kind="file",
            )
        )
    uid = os.getuid() if current_uid is None else current_uid
    for policy in policies:
        _validate_path(policy=policy, current_uid=uid)


def _validate_path(*, policy: OperatorStorePathPolicy, current_uid: int) -> None:
    path = policy.path
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise _permission_error(
            path=path,
            expected_mode=policy.expected_mode,
            actual="missing",
            reason="required operator-store path is missing",
        ) from exc
    actual_mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode):
        raise _permission_error(
            path=path,
            expected_mode=policy.expected_mode,
            actual=f"{_mode_text(actual_mode)} symbolic-link",
            reason="operator-store path must not be a symbolic link",
        )
    if policy.kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
        raise _permission_error(
            path=path,
            expected_mode=policy.expected_mode,
            actual=f"{_mode_text(actual_mode)} {_file_type(metadata.st_mode)}",
            reason="operator-store path is not a directory",
        )
    if policy.kind == "file" and not stat.S_ISREG(metadata.st_mode):
        raise _permission_error(
            path=path,
            expected_mode=policy.expected_mode,
            actual=f"{_mode_text(actual_mode)} {_file_type(metadata.st_mode)}",
            reason="operator-store path is not a regular file",
        )
    if metadata.st_uid != current_uid:
        raise _permission_error(
            path=path,
            expected_mode=policy.expected_mode,
            actual=f"uid {metadata.st_uid}, mode {_mode_text(actual_mode)}",
            reason=f"expected owner uid {current_uid}",
        )
    if actual_mode != policy.expected_mode:
        raise _permission_error(
            path=path,
            expected_mode=policy.expected_mode,
            actual=_mode_text(actual_mode),
            reason="unsafe operator-store permissions",
        )


def _permission_error(
    *,
    path: Path,
    expected_mode: int,
    actual: str,
    reason: str,
) -> SQLiteBackendError:
    expected = _mode_text(expected_mode)
    user = getpass.getuser()
    return SQLiteBackendError(
        "SQLite operator store permission validation failed: "
        f"{reason}; path={path}; expected={expected}; actual={actual}; "
        f"suggested_fix='chmod {expected[-3:]} {path} && chown {user} {path}'"
    )


def _mode_text(mode: int) -> str:
    return f"0{mode:o}"


def _file_type(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular-file"
    if stat.S_ISLNK(mode):
        return "symbolic-link"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISCHR(mode):
        return "character-device"
    return "unknown"


__all__ = [
    "is_operator_store_path",
    "validate_sqlite_operator_store",
]
