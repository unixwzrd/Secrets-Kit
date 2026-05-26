"""
secrets_kit.backends.dispatch

Backend-neutral secret operations for CLI and future transport layers.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from secrets_kit.backends.common import BackendError, normalize_backend
from secrets_kit.backends.keychain import (
    delete_secret as keychain_delete_secret,
)
from secrets_kit.backends.keychain import (
    get_secret as keychain_get_secret,
)
from secrets_kit.backends.keychain import (
    get_secret_metadata,
)
from secrets_kit.backends.keychain import (
    secret_exists as keychain_secret_exists,
)
from secrets_kit.backends.keychain import (
    set_secret as keychain_set_secret,
)
from secrets_kit.backends.keychain.comment_codec import (
    format_keychain_comment,
    parse_keychain_comment,
)
from secrets_kit.backends.sqlite import (
    SqliteSecretStore,
    delete_sqlite_secret,
    get_sqlite_metadata,
    get_sqlite_secret,
    get_sqlite_secret_entry,
    is_sqlite_backend,
    list_active_sqlite_metadata,
    set_sqlite_secret,
    sqlite_secret_exists,
)
from secrets_kit.models import EntryMetadata
from secrets_kit.system_objects import is_operator_locator, is_operator_metadata


def read_secret_value(
    *,
    service: str,
    account: str,
    name: str,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> str:
    """Read secret value only."""
    if is_sqlite_backend(backend=backend):
        return get_sqlite_secret(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=sqlite_dev_mode,
        )
    return keychain_get_secret(
        service=service,
        account=account,
        name=name,
        path=keychain_path,
        backend=backend,
    )


def read_secret_entry(
    *,
    service: str,
    account: str,
    name: str,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> Tuple[str, EntryMetadata]:
    """Read secret value and metadata."""
    if is_sqlite_backend(backend=backend):
        value, metadata = get_sqlite_secret_entry(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        return value, metadata
    value = keychain_get_secret(
        service=service,
        account=account,
        name=name,
        path=keychain_path,
        backend=backend,
    )
    fields = get_secret_metadata(
        service=service, account=account, name=name, path=keychain_path, backend=backend
    )
    parsed = parse_keychain_comment(comment=str(fields.get("comment", "")))
    if parsed is not None:
        return value, parsed
    return value, EntryMetadata(
        name=name, service=service, account=account, source="keychain-minimal"
    )


def write_secret(
    *,
    service: str,
    account: str,
    name: str,
    value: str,
    metadata: EntryMetadata,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
    label: Optional[str] = None,
) -> None:
    """Store secret value and metadata."""
    if is_sqlite_backend(backend=backend):
        set_sqlite_secret(
            service=service,
            account=account,
            name=name,
            value=value,
            metadata=metadata,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        return
    keychain_set_secret(
        service=service,
        account=account,
        name=name,
        value=value,
        label=label or name,
        comment=format_keychain_comment(metadata=metadata),
        path=keychain_path,
        backend=backend,
    )


def delete_secret_entry(
    *,
    service: str,
    account: str,
    name: str,
    metadata: EntryMetadata,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> None:
    """Delete secret from backend."""
    if is_sqlite_backend(backend=backend):
        delete_sqlite_secret(
            service=service,
            account=account,
            name=name,
            metadata=metadata,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        return
    keychain_delete_secret(
        service=service, account=account, name=name, path=keychain_path, backend=backend
    )


def secret_exists_for_backend(
    *,
    service: str,
    account: str,
    name: str,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> bool:
    """Return whether the secret exists in the selected backend."""
    if is_sqlite_backend(backend=backend):
        return sqlite_secret_exists(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=sqlite_dev_mode,
        )
    return keychain_secret_exists(
        service=service, account=account, name=name, path=keychain_path, backend=backend
    )


def list_secret_metadata(
    *,
    backend: str,
    service: Optional[str] = None,
    account: Optional[str] = None,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> List[EntryMetadata]:
    """List operator secret metadata from the active backend (excludes system objects)."""
    if is_sqlite_backend(backend=backend):
        entries = list_active_sqlite_metadata(
            service=service,
            account=account,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        return [meta for meta in entries if is_operator_metadata(metadata=meta)]

    from secrets_kit.registry import load_registry
    from secrets_kit.registry.resolve import read_metadata

    registry = load_registry()
    keys = sorted(registry.keys())
    results: List[EntryMetadata] = []
    for key in keys:
        parts = key.split("::")
        if len(parts) != 3:
            continue
        svc, acct, entry_name = parts
        if service and svc != service:
            continue
        if account and acct != account:
            continue
        if not is_operator_locator(service=svc, account=acct, name=entry_name):
            continue
        resolved = read_metadata(
            service=svc,
            account=acct,
            name=entry_name,
            registry=registry,
            path=keychain_path,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        if resolved and isinstance(resolved.get("metadata"), EntryMetadata):
            results.append(resolved["metadata"])
    return sorted(results, key=lambda item: (item.service, item.account, item.name))


def read_metadata_for_backend(
    *,
    service: str,
    account: str,
    name: str,
    backend: str,
    sqlite_dev_mode: bool = False,
) -> Optional[EntryMetadata]:
    """Read metadata only from backend (no registry fallback)."""
    if is_sqlite_backend(backend=backend):
        if not sqlite_secret_exists(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=sqlite_dev_mode,
        ):
            return None
        return get_sqlite_metadata(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=sqlite_dev_mode,
        )
    if not keychain_secret_exists(service=service, account=account, name=name, backend=backend):
        return None
    fields = get_secret_metadata(service=service, account=account, name=name, backend=backend)
    return parse_keychain_comment(comment=str(fields.get("comment", "")))


def build_env_map(
    *,
    entries: List[EntryMetadata],
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> Dict[str, str]:
    """Build name -> value map for run/export."""
    env_map: Dict[str, str] = {}
    for meta in entries:
        try:
            env_map[meta.name] = read_secret_value(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
        except BackendError as exc:
            raise BackendError(
                f"failed to read secret for run: service={meta.service} account={meta.account} "
                f"name={meta.name}. Use --names/--tag to narrow the injected set if this command "
                f"does not need every entry in the scope. Underlying error: {exc}"
            ) from exc
    return env_map


def sqlite_store(*, sqlite_dev_mode: bool = False) -> SqliteSecretStore:
    """Return SQLite store for doctor roundtrip."""
    return SqliteSecretStore(sqlite_dev_mode=sqlite_dev_mode)


def normalized_backend(backend: str) -> str:
    """Normalize backend id for dispatch callers."""
    return normalize_backend(backend)


__all__ = [
    "build_env_map",
    "delete_secret_entry",
    "list_secret_metadata",
    "normalized_backend",
    "read_metadata_for_backend",
    "read_secret_entry",
    "read_secret_value",
    "secret_exists_for_backend",
    "sqlite_store",
    "write_secret",
]
