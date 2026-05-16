"""SQLite-local recovery/export helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional


@dataclass(frozen=True)
class SqliteRecoveryCandidate:
    """One decrypted SQLite row projected for backend-local recovery tooling."""

    account: str
    service: str
    name: str
    metadata_comment: str


def iter_sqlite_recovery_candidates(
    *,
    db_path: str,
    service_filter: Optional[str] = None,
) -> Iterator[SqliteRecoveryCandidate]:
    """Yield decrypted SQLite recovery candidates from a SQLite store."""
    from pathlib import Path

    from secrets_kit.backends.sqlite.store import SqliteSecretStore

    store = SqliteSecretStore(db_path=str(Path(db_path).expanduser()))
    yield from store.iter_recovery_candidates(service_filter=service_filter)

