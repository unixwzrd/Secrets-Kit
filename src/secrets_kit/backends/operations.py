"""Backend convenience operations used by CLI and integration code.

These helpers are thin dispatch wrappers over ``BackendStore``. They are not a
compatibility store interface and do not preserve backend-specific runtime branches.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, Optional

from secrets_kit.backends.base import BackendStore
from secrets_kit.backends.errors import BackendError
from secrets_kit.backends.registry import resolve_backend_store
from secrets_kit.models.core import EntryMetadata, ensure_entry_id, now_utc_iso


def _access_backend_store(
    *,
    backend: str,
    path: Optional[str],
    kek_keychain_path: Optional[str],
) -> BackendStore:
    """Resolve the concrete ``BackendStore`` for the given backend identifier."""
    return resolve_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)


def _entry_metadata_for_secret_set(*, service: str, account: str, name: str, comment: str) -> EntryMetadata:
    """Build current ``EntryMetadata`` when writing through convenience helpers."""
    if comment.strip():
        parsed = EntryMetadata.from_keychain_comment(comment)
        if parsed is not None:
            meta = ensure_entry_id(parsed)
            return replace(meta, name=name, service=service, account=account)
    ts = now_utc_iso()
    return ensure_entry_id(
        EntryMetadata(name=name, service=service, account=account, created_at=ts, updated_at=ts, source="manual")
    )


def set_secret(
    *,
    service: str,
    account: str,
    name: str,
    value: str,
    comment: str = "",
    label: Optional[str] = None,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> None:
    """Create or update a secret entry in the configured backend."""
    del label
    store = _access_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    meta = _entry_metadata_for_secret_set(service=service, account=account, name=name, comment=comment)
    store.set_entry(service=service, account=account, name=name, secret=value, metadata=meta)


def get_secret(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> str:
    """Read secret value from backend."""
    store = _access_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    return store.get_secret(service=service, account=account, name=name)


def get_secret_metadata(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Read store-backed metadata attributes for one secret."""
    store = _access_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    return store.metadata(service=service, account=account, name=name)


def secret_exists(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> bool:
    """Return whether an entry exists for one logical secret."""
    store = _access_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    return store.exists(service=service, account=account, name=name)


def delete_secret(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> None:
    """Delete secret from backend."""
    store = _access_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    store.delete_entry(service=service, account=account, name=name)


def doctor_roundtrip(
    *,
    service: str = "seckit-doctor",
    account: str = "doctor",
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> None:
    """Run a backend write/read/delete smoke test."""
    test_name = "DOCTOR_TEST_KEY"
    value = "doctor_ok"
    set_secret(
        service=service,
        account=account,
        name=test_name,
        value=value,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
    )
    fetched = get_secret(
        service=service,
        account=account,
        name=test_name,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
    )
    if fetched != value:
        raise BackendError("doctor roundtrip mismatch")
    delete_secret(
        service=service,
        account=account,
        name=test_name,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
    )
