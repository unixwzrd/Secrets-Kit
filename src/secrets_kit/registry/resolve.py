"""
secrets_kit.registry.resolve

Registry and backend metadata resolution (shared by CLI and sync).
"""

from __future__ import annotations

from typing import Dict, Optional

from secrets_kit.backends.security import (
    BackendError,
    get_secret_metadata,
    is_secure_backend,
    is_sqlite_backend,
    secret_exists,
)
from secrets_kit.models.core import EntryMetadata
from secrets_kit.registry.core import load_registry


def _read_metadata(
    *,
    service: str,
    account: str,
    name: str,
    registry: Optional[Dict[str, EntryMetadata]] = None,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> Optional[Dict[str, object]]:
    key = f"{service}::{account}::{name}"
    registry = registry if registry is not None else load_registry()
    registry_meta = registry.get(key)
    if secret_exists(
        service=service,
        account=account,
        name=name,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
    ):
        res_store = None
        try:
            from secrets_kit.backends.base import resolve_backend_store

            store = resolve_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
            resolved = store.resolve_by_locator(service=service, account=account, name=name)
            if resolved is not None:
                res_store = resolved
        except (BackendError, OSError, ValueError, TypeError):
            res_store = None
        if res_store is not None:
            keychain_fields: Dict[str, object] = {}
            try:
                keychain_fields = get_secret_metadata(
                    service=service,
                    account=account,
                    name=name,
                    path=path,
                    backend=backend,
                    kek_keychain_path=kek_keychain_path,
                )
            except BackendError:
                pass
            return {
                "metadata": res_store.metadata,
                "metadata_source": "sqlite" if is_sqlite_backend(backend) else "keychain",
                "keychain_fields": keychain_fields,
                "registry_fallback_used": False,
            }
        keychain_fields = {}
        try:
            keychain_fields = get_secret_metadata(
                service=service,
                account=account,
                name=name,
                path=path,
                backend=backend,
                kek_keychain_path=kek_keychain_path,
            )
        except BackendError:
            if registry_meta:
                return {
                    "metadata": registry_meta,
                    "metadata_source": "registry-fallback",
                    "keychain_fields": {},
                    "registry_fallback_used": True,
                }
            minimal = EntryMetadata(
                name=name,
                service=service,
                account=account,
                comment="",
                source="keychain-unmanaged",
            )
            return {
                "metadata": minimal,
                "metadata_source": "sqlite-minimal" if is_sqlite_backend(backend) else "keychain-minimal",
                "keychain_fields": {},
                "registry_fallback_used": False,
            }
        keychain_meta = EntryMetadata.from_keychain_comment(str(keychain_fields.get("comment", "")))
        if keychain_meta:
            return {
                "metadata": keychain_meta,
                "metadata_source": "sqlite" if is_sqlite_backend(backend) else "keychain",
                "keychain_fields": keychain_fields,
                "registry_fallback_used": False,
            }
        if registry_meta:
            return {
                "metadata": registry_meta,
                "metadata_source": "registry-fallback",
                "keychain_fields": keychain_fields,
                "registry_fallback_used": True,
            }
        minimal = EntryMetadata(
            name=name,
            service=service,
            account=account,
            comment="",
            source="keychain-unmanaged",
        )
        return {
            "metadata": minimal,
            "metadata_source": "sqlite-minimal" if is_sqlite_backend(backend) else "keychain-minimal",
            "keychain_fields": keychain_fields,
            "registry_fallback_used": False,
        }
    if registry_meta and path is None and is_secure_backend(backend):
        return {
            "metadata": registry_meta,
            "metadata_source": "registry-only",
            "keychain_fields": {},
            "registry_fallback_used": True,
        }
    if registry_meta and is_sqlite_backend(backend):
        return {
            "metadata": registry_meta,
            "metadata_source": "registry-only",
            "keychain_fields": {},
            "registry_fallback_used": True,
        }
    return None
