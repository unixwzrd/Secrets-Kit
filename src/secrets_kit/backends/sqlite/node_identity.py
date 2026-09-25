"""
secrets_kit.backends.sqlite.node_identity

Standalone SQLite local-node identity lifecycle.

This module provisions and validates one local node identity for the SQLite
backend. Private key material is stored in a local operator-store file. SQLite
stores only public keys in ``nodes`` and private-key references in
``node_private``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.local_node import (
    LocalNodeProjection,
    load_local_node_projection,
    save_local_node_projection,
)
from secrets_kit.crypto.models import NodeIdentity, generate_node_identity
from secrets_kit.crypto.persistence import (
    RECORD_TYPE_ENCRYPTION_KEYPAIR,
    RECORD_TYPE_SIGNING_KEYPAIR,
    encryption_keypair_from_record,
    encryption_keypair_to_record,
    signing_keypair_from_record,
    signing_keypair_to_record,
)
from secrets_kit.crypto.storage.sqlite import SQLITE_PATH_ENV
from secrets_kit.identifiers import random_identifier, validate_identifier

SQLITE_NODE_IDENTITY_KEY_ENV: Final = "SECKIT_SQLITE_NODE_IDENTITY_KEY_PATH"
SQLITE_NODE_IDENTITY_RECORD_VERSION: Final = 1
SQLITE_NODE_IDENTITY_RECORD_TYPE: Final = "sqlite_node_identity"
SQLITE_NODE_IDENTITY_FILENAME: Final = "node-identity.key"


@dataclass(frozen=True)
class SQLiteNodeIdentitySummary:
    """Public local-node identity inspection fields."""

    node_id: str
    signing_algorithm: str
    signing_public_key_fingerprint: str
    encryption_algorithm: str
    encryption_public_key_fingerprint: str
    created_at: str
    state: str


def sqlite_node_identity_key_path(*, home: Path | None = None) -> Path:
    """
    Return the local SQLite node-identity material path.

    The default operator path is ``~/.config/seckit/node-identity.key``. The
    environment override and SQLite-path-relative fallback exist for isolated
    tests and scripted sandboxes.
    """
    configured = os.getenv(SQLITE_NODE_IDENTITY_KEY_ENV)
    if configured:
        return Path(configured).expanduser()
    sqlite_path = os.getenv(SQLITE_PATH_ENV)
    if sqlite_path:
        return Path(sqlite_path).expanduser().parent / SQLITE_NODE_IDENTITY_FILENAME
    operator_home = home or Path.home()
    return operator_home / ".config" / "seckit" / SQLITE_NODE_IDENTITY_FILENAME


def ensure_sqlite_node_identity(
    *,
    conn: sqlite3.Connection,
    home: Path | None = None,
    replace: bool = False,
) -> SQLiteNodeIdentitySummary:
    """
    Create or load the local SQLite node identity and persist its projection.

    This is an explicit provisioning operation for ``seckit init`` paths. Normal
    runtime validation must call ``validate_sqlite_node_identity`` instead.
    """
    path = sqlite_node_identity_key_path(home=home)
    if path.is_symlink():
        raise SQLiteBackendError(f"SQLite node identity material must not be a symbolic link: {path}")
    if replace and path.exists():
        path.unlink()
    if path.exists():
        _validate_identity_file_permissions(path=path)
        identity = _load_identity_file(path=path)
    else:
        identity = _create_identity_file(path=path)
    save_local_node_projection(
        conn=conn,
        identity=identity,
        signing_private_key_reference=_private_key_reference(
            path=path,
            key_type="signing",
            key_id=identity.signing.metadata.key_id,
        ),
        encryption_private_key_reference=_private_key_reference(
            path=path,
            key_type="encryption",
            key_id=identity.encryption.metadata.key_id,
        ),
    )
    conn.commit()
    validate_sqlite_node_identity(conn=conn, home=home)
    return _summary_from_identity(identity=identity, projection=_require_projection(conn=conn))


def validate_sqlite_node_identity(*, conn: sqlite3.Connection, home: Path | None = None) -> None:
    """
    Validate local SQLite node identity file and SQLite projection state.

    Raises ``SQLiteBackendError`` when identity material is missing, malformed,
    insecure, or mismatched with ``nodes``/``node_private``.
    """
    path = sqlite_node_identity_key_path(home=home)
    _validate_identity_file_permissions(path=path)
    identity = _load_identity_file(path=path)
    projection = _require_projection(conn=conn)
    _validate_projection_matches_identity(path=path, projection=projection, identity=identity)


def load_sqlite_node_identity_summary(
    *,
    conn: sqlite3.Connection,
    home: Path | None = None,
) -> SQLiteNodeIdentitySummary | None:
    """
    Return public identity inspection fields, or ``None`` when uninitialized.

    This helper validates identity state when both the material file and
    projection exist. It never returns or prints private key material.
    """
    path = sqlite_node_identity_key_path(home=home)
    projection = load_local_node_projection(conn=conn)
    if projection is None and not path.exists():
        return None
    validate_sqlite_node_identity(conn=conn, home=home)
    identity = _load_identity_file(path=path)
    return _summary_from_identity(identity=identity, projection=_require_projection(conn=conn))


def load_sqlite_node_identity_material(
    *,
    conn: sqlite3.Connection,
    home: Path | None = None,
) -> NodeIdentity:
    """
    Load local node identity material for local signing operations.

    This returns private key material to in-process admission/signing code only.
    Callers must never serialize, log, print, or place the returned private
    material in transactions or envelopes.
    """
    validate_sqlite_node_identity(conn=conn, home=home)
    return _load_identity_file(path=sqlite_node_identity_key_path(home=home))


def _create_identity_file(*, path: Path) -> NodeIdentity:
    # Open architecture decision before peer admission:
    # Option A: keep a random UUID node identifier.
    # Option B: derive the node identifier deterministically from the public
    # signing identity. Do not make peer-trust assumptions from this temporary
    # local standalone identifier.
    identity = generate_node_identity(node_id=random_identifier(identifier_type="node"))
    _write_identity_file(path=path, identity=identity)
    return identity


def _write_identity_file(*, path: Path, identity: NodeIdentity) -> None:
    _validate_distinct_keypairs(identity=identity)
    _ensure_new_parent_directory(path=path)
    payload = {
        "encryption": encryption_keypair_to_record(keypair=identity.encryption),
        "node_id": identity.node_id,
        "record_type": SQLITE_NODE_IDENTITY_RECORD_TYPE,
        "signing": signing_keypair_to_record(keypair=identity.signing),
        "version": SQLITE_NODE_IDENTITY_RECORD_VERSION,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        indent=2,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.write(b"\n")
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _load_identity_file(*, path: Path) -> NodeIdentity:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SQLiteBackendError(f"invalid SQLite node identity material: {path}") from exc
    if not isinstance(payload, dict):
        raise SQLiteBackendError("SQLite node identity material must be a JSON object")
    try:
        identity = _identity_from_payload(payload=payload)
    except (TypeError, ValueError) as exc:
        raise SQLiteBackendError(f"invalid SQLite node identity material: {exc}") from exc
    _validate_distinct_keypairs(identity=identity)
    return identity


def _identity_from_payload(*, payload: dict[str, Any]) -> NodeIdentity:
    if payload.get("version") != SQLITE_NODE_IDENTITY_RECORD_VERSION:
        raise ValueError("unsupported SQLite node identity version")
    if payload.get("record_type") != SQLITE_NODE_IDENTITY_RECORD_TYPE:
        raise ValueError(f"record_type must be {SQLITE_NODE_IDENTITY_RECORD_TYPE}")
    node_id = payload.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("node_id is required")
    validate_identifier(value=node_id, expected_type="node", field="node_id")
    signing_record = payload.get("signing")
    encryption_record = payload.get("encryption")
    if not isinstance(signing_record, dict):
        raise ValueError("signing keypair record is required")
    if not isinstance(encryption_record, dict):
        raise ValueError("encryption keypair record is required")
    if signing_record.get("record_type") != RECORD_TYPE_SIGNING_KEYPAIR:
        raise ValueError("signing record_type is invalid")
    if encryption_record.get("record_type") != RECORD_TYPE_ENCRYPTION_KEYPAIR:
        raise ValueError("encryption record_type is invalid")
    return NodeIdentity(
        node_id=node_id,
        signing=signing_keypair_from_record(record=signing_record),
        encryption=encryption_keypair_from_record(record=encryption_record),
    )


def _validate_identity_file_permissions(*, path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise SQLiteBackendError(f"SQLite node identity material is missing: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise SQLiteBackendError(f"SQLite node identity material must not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SQLiteBackendError(
            f"SQLite node identity material is not a regular file: {path}"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != os.getuid():
        raise SQLiteBackendError(
            "SQLite node identity permission validation failed: "
            f"path={path}; expected_owner_uid={os.getuid()}; actual_owner_uid={metadata.st_uid}"
        )
    if mode != 0o600:
        raise SQLiteBackendError(
            "SQLite node identity permission validation failed: "
            f"path={path}; expected=0600; actual=0{mode:o}; "
            f"suggested_fix='chmod 600 {path}'"
        )


def _ensure_new_parent_directory(*, path: Path) -> None:
    parent = path.parent
    if parent.exists():
        metadata = parent.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SQLiteBackendError(
                f"SQLite node identity directory must not be a symbolic link: {parent}"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise SQLiteBackendError(f"SQLite node identity parent is not a directory: {parent}")
        return
    parent.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(parent, 0o700)


def _require_projection(*, conn: sqlite3.Connection) -> LocalNodeProjection:
    row_count = conn.execute("SELECT count(*) FROM node_private").fetchone()[0]
    if row_count != 1:
        raise SQLiteBackendError(
            f"SQLite node identity projection must contain exactly one local node; found {row_count}"
        )
    projection = load_local_node_projection(conn=conn)
    if projection is None:
        raise SQLiteBackendError("SQLite node identity projection is missing")
    return projection


def _validate_projection_matches_identity(
    *,
    path: Path,
    projection: LocalNodeProjection,
    identity: NodeIdentity,
) -> None:
    expected_signing_reference = _private_key_reference(
        path=path,
        key_type="signing",
        key_id=identity.signing.metadata.key_id,
    )
    expected_encryption_reference = _private_key_reference(
        path=path,
        key_type="encryption",
        key_id=identity.encryption.metadata.key_id,
    )
    mismatches: list[str] = []
    if projection.node_id != identity.node_id:
        mismatches.append("node_id")
    if projection.signing_public_key != identity.signing.public_key:
        mismatches.append("signing_public_key")
    if projection.signing_private_key_reference != expected_signing_reference:
        mismatches.append("signing_private_key_reference")
    if projection.encryption_public_key != identity.encryption.public_key:
        mismatches.append("encryption_public_key")
    if projection.encryption_private_key_reference != expected_encryption_reference:
        mismatches.append("encryption_private_key_reference")
    if projection.state != "active":
        mismatches.append("state")
    if mismatches:
        raise SQLiteBackendError(
            "SQLite node identity projection does not match local identity material: "
            + ", ".join(mismatches)
        )


def _validate_distinct_keypairs(*, identity: NodeIdentity) -> None:
    if identity.signing.public_key == identity.encryption.public_key:
        raise SQLiteBackendError("SQLite node identity signing and encryption public keys match")
    if identity.signing.private_key == identity.encryption.private_key:
        raise SQLiteBackendError("SQLite node identity signing and encryption private keys match")


def _private_key_reference(*, path: Path, key_type: str, key_id: str) -> str:
    return f"file:{path}#{key_type}:{key_id}"


def _summary_from_identity(
    *,
    identity: NodeIdentity,
    projection: LocalNodeProjection,
) -> SQLiteNodeIdentitySummary:
    return SQLiteNodeIdentitySummary(
        node_id=identity.node_id,
        signing_algorithm=identity.signing.metadata.algorithm,
        signing_public_key_fingerprint=identity.signing.metadata.key_id,
        encryption_algorithm=identity.encryption.metadata.algorithm,
        encryption_public_key_fingerprint=identity.encryption.metadata.key_id,
        created_at=projection.created_at,
        state=projection.state,
    )


__all__ = [
    "SQLITE_NODE_IDENTITY_KEY_ENV",
    "SQLiteNodeIdentitySummary",
    "ensure_sqlite_node_identity",
    "load_sqlite_node_identity_material",
    "load_sqlite_node_identity_summary",
    "sqlite_node_identity_key_path",
    "validate_sqlite_node_identity",
]
