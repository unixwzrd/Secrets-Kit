"""secrets_kit.host_context: public, administrator-owned host identity hints.

The host document never grants peer admission or RSS billing authority. It
contains only stable local organization/client identifiers and display labels;
each Unix account retains its own store, keys and RSS credential.
"""

from __future__ import annotations

import json
import os
import pwd
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from secrets_kit.identifiers import random_identifier, validate_identifier
from secrets_kit.models import now_utc_iso

HOST_CONTEXT_VERSION = 1
HOST_CONTEXT_RELATIVE_PATH = Path("config/host.json")
HOST_ENVIRONMENTS = frozenset({"dev", "qa", "production"})
HOST_MEMBERSHIP_KEY = "host_context_v1"


@dataclass(frozen=True)
class HostContext:
    """Identifiers shared as metadata, not as credentials or authorization."""

    installation_id: str
    environment: str
    organization_id: str
    organization_name: str
    client_id: str
    client_name: str

    def as_dict(self) -> dict[str, object]:
        return {"version": HOST_CONTEXT_VERSION, **self.__dict__}


def host_context_path(prefix: Path) -> Path:
    """Return the stable config path outside runtime generations."""
    if not prefix.is_absolute() or prefix == Path("/"):
        raise ValueError("host installation prefix must be an absolute, non-root path")
    return prefix / HOST_CONTEXT_RELATIVE_PATH


def _check_prefix_ancestry(prefix: Path) -> None:
    current = Path("/")
    for part in prefix.parts[1:]:
        current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError(f"unsafe shared-host path component: {current}")


def load_host_context(prefix: Path) -> HostContext:
    """Read an administrator-owned, non-writable host hint document."""
    path = host_context_path(prefix)
    _check_prefix_ancestry(prefix)
    for directory in (prefix, path.parent):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("host prefix and config directory must be root-owned, non-writable directories")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError("host configuration must be a root-owned, non-writable regular file")
    raw = json.loads(path.read_text(encoding="utf-8"))
    required = {"version", "installation_id", "environment", "organization_id", "organization_name", "client_id", "client_name"}
    if not isinstance(raw, dict) or set(raw) != required or raw["version"] != HOST_CONTEXT_VERSION:
        raise ValueError("unsupported host configuration format")
    if raw["environment"] not in HOST_ENVIRONMENTS:
        raise ValueError("invalid host environment")
    if not isinstance(raw["installation_id"], str):
        raise ValueError("invalid installation_id")
    uuid.UUID(raw["installation_id"])
    validate_identifier(value=raw["organization_id"], expected_type="organization", field="organization_id")
    validate_identifier(value=raw["client_id"], expected_type="client", field="client_id")
    for field in ("organization_name", "client_name"):
        if not isinstance(raw[field], str) or not raw[field].strip() or len(raw[field]) > 128:
            raise ValueError(f"invalid {field}")
    return HostContext(**{key: raw[key] for key in required - {"version"}})


def create_host_context(
    *, prefix: Path, environment: str, organization_name: str, client_name: str,
    organization_id: str | None = None, client_id: str | None = None,
) -> HostContext:
    """Create one immutable host hint file; caller must be a system administrator."""
    if os.geteuid() != 0:
        raise PermissionError("administrator privileges are required for host configuration")
    path = host_context_path(prefix)
    _check_prefix_ancestry(prefix)
    parent = path.parent
    for directory in (prefix, parent):
        info = directory.lstat() if directory.exists() or directory.is_symlink() else None
        if info is not None and (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise PermissionError("host prefix and config directory must be root-owned, non-writable directories")
    if not prefix.is_dir():
        raise ValueError("administrator must create the installation prefix first")
    if prefix.stat().st_mode & 0o055 != 0o055:
        raise PermissionError("host prefix must be readable and searchable by participating users")
    parent.mkdir(mode=0o755, exist_ok=True)
    if environment not in HOST_ENVIRONMENTS:
        raise ValueError("invalid host environment")
    if (
        not organization_name.strip() or not client_name.strip()
        or len(organization_name) > 128 or len(client_name) > 128
    ):
        raise ValueError("organization and client names are required and must be at most 128 characters")
    if organization_id is not None:
        validate_identifier(value=organization_id, expected_type="organization", field="organization_id")
    if client_id is not None:
        validate_identifier(value=client_id, expected_type="client", field="client_id")
    parent.chmod(0o755)
    context = HostContext(
        installation_id=str(uuid.uuid4()),
        environment=environment,
        organization_id=organization_id or random_identifier(identifier_type="organization"),
        organization_name=organization_name.strip(),
        client_id=client_id or random_identifier(identifier_type="client"),
        client_name=client_name.strip(),
    )
    payload = json.dumps(context.as_dict(), sort_keys=True, indent=2).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fchmod(target.fileno(), 0o644)
            os.fsync(target.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return context


def join_host_context(*, prefix: Path, environment: str, home: Path | None = None) -> dict[str, object]:
    """Opt one existing user store into a host scope without rewriting history.

    The caller remains the datastore owner. Host IDs are metadata only; this
    operation does not issue an RSS credential or authorize a peer.
    """
    if os.geteuid() == 0:
        raise PermissionError("run host join as the Secrets Kit user, never root")
    from secrets_kit.backends.sqlite.connection import transaction
    from secrets_kit.backends.sqlite.gate import open_sqlite_backend, sqlite_path
    from secrets_kit.backends.sqlite.local_hierarchy import LOCAL_CLIENT_ID

    context = load_host_context(prefix)
    if context.environment != environment:
        raise ValueError("host environment does not match the selected user environment")
    database = sqlite_path(home=home)
    if not database.is_file() or database.is_symlink():
        raise ValueError("initialize the user's own SQLite store before joining a host")
    conn = open_sqlite_backend(home=home)
    try:
        username = pwd.getpwuid(os.geteuid()).pw_name
        existing = conn.execute(
            "SELECT metadata_value FROM datastore_metadata WHERE metadata_key=?",
            (HOST_MEMBERSHIP_KEY,),
        ).fetchone()
        if existing is not None:
            prior = json.loads(existing["metadata_value"])
            if (
                prior.get("installation_id") != context.installation_id
                or prior.get("organization_id") != context.organization_id
                or prior.get("client_id") != context.client_id
                or prior.get("unix_username") != username
            ):
                raise PermissionError("store is already bound to another host context or Unix user")
            return prior
        foreign = conn.execute(
            "SELECT 1 FROM owners WHERE client_id IS NOT NULL AND client_id != ? LIMIT 1",
            (LOCAL_CLIENT_ID,),
        ).fetchone()
        if foreign is not None:
            raise PermissionError("store contains a non-standalone client scope; automatic host joining is unsafe")
        legacy_owner_ids = [
            row["owner_id"] for row in conn.execute("SELECT owner_id FROM owners ORDER BY owner_id")
        ]
        principal_owner_id = random_identifier(identifier_type="owner")
        membership: dict[str, object] = {
            "version": 1,
            "installation_id": context.installation_id,
            "environment": context.environment,
            "organization_id": context.organization_id,
            "client_id": context.client_id,
            "principal_owner_id": principal_owner_id,
            "legacy_owner_ids": legacy_owner_ids,
            "unix_username": username,
        }
        with transaction(conn=conn):
            conn.execute(
                "INSERT OR IGNORE INTO business_organizations (organization_id, name) VALUES (?, ?)",
                (context.organization_id, context.organization_name),
            )
            conn.execute(
                "INSERT OR IGNORE INTO business_clients (client_id, organization_id, name) VALUES (?, ?, ?)",
                (context.client_id, context.organization_id, context.client_name),
            )
            conn.execute(
                "INSERT INTO owners (owner_id, client_id, name, operator_comment) VALUES (?, ?, ?, ?)",
                (principal_owner_id, context.client_id, username, "local Unix principal"),
            )
            conn.execute(
                "UPDATE owners SET client_id=? WHERE client_id=?",
                (context.client_id, LOCAL_CLIENT_ID),
            )
            conn.execute(
                "INSERT INTO datastore_metadata (metadata_key, metadata_value, created_at) VALUES (?, ?, ?)",
                (HOST_MEMBERSHIP_KEY, json.dumps(membership, sort_keys=True), now_utc_iso()),
            )
        return membership
    finally:
        conn.close()


def local_host_scope(*, conn: sqlite3.Connection) -> tuple[str | None, str | None, str | None]:
    """Return explicit organization/client/principal scope for new local records only."""
    row = conn.execute(
        "SELECT metadata_value FROM datastore_metadata WHERE metadata_key=?",
        (HOST_MEMBERSHIP_KEY,),
    ).fetchone()
    if row is None:
        return None, None, None
    membership = json.loads(row["metadata_value"])
    return (
        str(membership["organization_id"]),
        str(membership["client_id"]),
        str(membership["principal_owner_id"]),
    )


def joined_host_membership(*, prefix: Path, home: Path | None = None) -> dict[str, object]:
    """Read and verify this Unix user's shared-host membership without changing its store."""
    context = load_host_context(prefix)
    database = (home or Path.home()) / ".config/seckit/seckit.sqlite"
    info = database.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PermissionError("unsafe per-user Secrets Kit database")
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT metadata_value FROM datastore_metadata WHERE metadata_key=?",
            (HOST_MEMBERSHIP_KEY,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ValueError("this user has not joined the shared host")
    membership = json.loads(row[0])
    if (
        not isinstance(membership, dict)
        or membership.get("installation_id") != context.installation_id
        or membership.get("environment") != context.environment
        or membership.get("organization_id") != context.organization_id
        or membership.get("client_id") != context.client_id
        or membership.get("unix_username") != pwd.getpwuid(os.geteuid()).pw_name
        or not isinstance(membership.get("principal_owner_id"), str)
    ):
        raise PermissionError("user membership does not match the shared host")
    return membership


__all__ = ["HostContext", "create_host_context", "host_context_path", "join_host_context", "joined_host_membership", "load_host_context", "local_host_scope"]
