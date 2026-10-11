"""secrets_kit.runtime.peer_invitation_state

Owner-private, bounded invitation recovery state, separate from signed history.
Capabilities and staged frames remain local; this store grants no admission.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

from secrets_kit.backends.sqlite.node_identity import sqlite_node_identity_key_path
from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.identifiers import validate_identifier
from secrets_kit.protocol.peer_invitation import InvitationError

MAX_STATE_BYTES = 256 * 1024


class InvitationStateStore:
    """Private revisioned records; callers must verify signed frames separately.

    Record identity, role and original deadline are immutable. A successful
    write commits before return; stale/concurrent revisions fail closed.
    """

    def __init__(self, *, path: Path | None = None, max_records: int = 64) -> None:
        if type(max_records) is not int or max_records <= 0:
            raise InvitationError("invitation state limit is invalid")
        self.path = path or sqlite_node_identity_key_path().with_name("peer-invitations.sqlite")
        self.max_records = max_records
        parent = self.path.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise InvitationError("invitation state directory is unsafe")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise InvitationError("invitation state file is unsafe")
        finally:
            os.close(fd)
        self._db = sqlite3.connect(self.path, timeout=2)
        self._db.execute("CREATE TABLE IF NOT EXISTS invitation_state (session_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, expires_at INTEGER NOT NULL, record BLOB NOT NULL)")
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    @staticmethod
    def _id(session_id: str) -> None:
        try:
            if not isinstance(session_id, str) or len(session_id) != 43:
                raise ValueError
            raw = decode_b64url(session_id)
            if len(raw) != 32 or encode_b64url(raw) != session_id:
                raise ValueError
        except (TypeError, ValueError):
            raise InvitationError("invitation identifier is invalid") from None

    @staticmethod
    def _validate(session_id: str, record: dict[str, Any]) -> bytes:
        if (not isinstance(record, dict) or type(record.get("version")) is not int or record.get("version") != 1
                or record.get("session_id") != session_id or record.get("role") not in ("source", "target")
                or type(record.get("expires_at")) is not int):
            raise InvitationError("invitation state is invalid")
        if any(not isinstance(record.get(key), str) or not record[key].strip()
               or len(record[key]) > 512 or "\0" in record[key] for key in ("service", "account")):
            raise InvitationError("invitation scope is invalid")
        try:
            validate_identifier(value=record.get("local_node_id"), expected_type="node", field="invitation node")
            payload = canonical_json_bytes(record)
        except (TypeError, ValueError):
            raise InvitationError("invitation state is invalid") from None
        if len(payload) > MAX_STATE_BYTES:
            raise InvitationError("invitation state is too large")
        return payload

    def read(self, *, session_id: str, local_node_id: str) -> tuple[int, dict[str, Any]]:
        self._id(session_id)
        row = self._db.execute("SELECT revision,record FROM invitation_state WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise InvitationError("invitation state is unavailable")
        try:
            record = json.loads(row[1])
            self._validate(session_id, record)
            if record["local_node_id"] != local_node_id:
                raise InvitationError("invitation belongs to another local node")
        except (TypeError, ValueError):
            raise InvitationError("invitation state is invalid") from None
        return int(row[0]), record

    def save(self, *, session_id: str, record: dict[str, Any], expected_revision: int | None,
             now: int | None = None) -> int:
        self._id(session_id)
        payload = self._validate(session_id, record)
        timestamp = int(time.time()) if now is None else now
        if not timestamp < record["expires_at"] <= timestamp + 900:
            raise InvitationError("invitation state expired or deadline is invalid")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("DELETE FROM invitation_state WHERE expires_at<=?", (timestamp,))
            row = self._db.execute("SELECT revision,record FROM invitation_state WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                if expected_revision is not None or self._db.execute("SELECT COUNT(*) FROM invitation_state").fetchone()[0] >= self.max_records:
                    raise InvitationError("invitation state cannot be created")
                revision = 1
                self._db.execute("INSERT INTO invitation_state VALUES(?,?,?,?)", (session_id, revision, record["expires_at"], payload))
            else:
                if type(expected_revision) is not int or row[0] != expected_revision:
                    raise InvitationError("invitation state changed; resume again")
                prior = json.loads(row[1])
                if any(record[key] != prior[key] for key in ("version", "session_id", "role", "local_node_id", "expires_at", "service", "account")):
                    raise InvitationError("invitation identity or deadline changed")
                protected = ("code", "source_cap", "claim_cap", "operator_url",
                             "remote_node_id", "remote_signing_key", "remote_encryption_key", "include_rss", "rss_identity", "remote_candidate")
                if any(key in prior and record.get(key) != prior[key] for key in protected):
                    raise InvitationError("invitation binding changed")
                frames = prior.get("frames", {})
                replacement = record.get("frames", {})
                if not isinstance(frames, dict) or not isinstance(replacement, dict) or any(
                    replacement.get(key) != value for key, value in frames.items()
                ):
                    raise InvitationError("staged invitation frame changed")
                revision = expected_revision + 1
                self._db.execute("UPDATE invitation_state SET revision=?,record=? WHERE session_id=?", (revision, payload, session_id))
            self._db.commit()
            return revision
        except Exception:
            self._db.rollback()
            raise
