"""Enumerate secret-store rows for ``seckit recover`` (registry rebuild).

Supports **secure** (Keychain dump) and **sqlite** (plaintext index columns only).
"""

from __future__ import annotations

from typing import Iterator, Optional

from secrets_kit.keychain_backend import BackendError, is_secure_backend, is_sqlite_backend, keychain_path
from secrets_kit.keychain_inventory import GenpCandidate, dump_keychain_text, iter_seckit_genp_candidates
from secrets_kit.sqlite_backend import iter_secrets_plaintext_index


def iter_recover_candidates(
    *,
    backend: str,
    service_filter: Optional[str],
    keychain_file: Optional[str],
    sqlite_db: Optional[str],
) -> Iterator[GenpCandidate]:
    """Yield candidates in store order; same shape for Keychain and SQLite."""
    want = service_filter.strip() if service_filter else None
    if is_secure_backend(backend):
        kc = keychain_path(path=keychain_file)
        dump = dump_keychain_text(path=kc)
        yield from iter_seckit_genp_candidates(dump, service_filter=want)
        return
    if is_sqlite_backend(backend):
        if not sqlite_db or not str(sqlite_db).strip():
            raise BackendError("SQLite recover requires a database path (--db or defaults / SECKIT_SQLITE_DB)")
        yield from iter_secrets_plaintext_index(db_path=str(sqlite_db).strip(), service_filter=want)
        return
    raise BackendError(f"recover does not support backend {backend!r} (use secure or sqlite)")
