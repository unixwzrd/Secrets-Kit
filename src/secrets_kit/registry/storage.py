"""
secrets_kit.registry.storage

Local catalog storage for registry.json and operator defaults.

registry.json is a schema/catalog document. It must not contain per-secret
inventory rows, secret values, or metadata instances.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from secrets_kit.models import EntryMetadata

if TYPE_CHECKING:
    from secrets_kit.schemas.registry_doc import SchemaRegistryDocument


class RegistryError(RuntimeError):
    """Registry operation failed."""


REGISTRY_VERSION = 2
REGISTRY_SCHEMA = "https://unixwzrd.ai/schemas/seckit/registry-catalog-v2.json"
CATALOG_BACKUP_SUFFIX = ".pre-catalog-cleanup.bak"


def registry_dir(*, home: Path | None = None) -> Path:
    """Return local Seckit config directory path."""
    base = home or Path.home()
    return base / ".config" / "seckit"


def registry_path(*, home: Path | None = None) -> Path:
    """Return local schema/catalog registry file path."""
    return registry_dir(home=home) / "registry.json"


def defaults_path(*, home: Path | None = None) -> Path:
    """Return operator defaults file path."""
    return registry_dir(home=home) / "defaults.json"


def registry_backup_path(*, home: Path | None = None) -> Path:
    """Return backup path used before removing old inventory rows."""
    return registry_path(home=home).with_name(f"registry.json{CATALOG_BACKUP_SUFFIX}")


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _check_secure_perms(*, path: Path, max_mode: int) -> None:
    if not path.exists():
        return
    mode = _mode(path)
    if mode > max_mode:
        raise RegistryError(
            f"unsafe permissions on {path}: {oct(mode)} (expected <= {oct(max_mode)})"
        )


def _atomic_write_json(*, path: Path, payload: Mapping[str, object]) -> None:
    """Write JSON atomically with secure file mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="registry-", suffix=".json", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            _ = handle.write("\n")
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _catalog_document_from_seeds() -> "SchemaRegistryDocument":
    """Build the default catalog from bundled and user seed descriptors."""
    from secrets_kit.schemas.merge import merge_seed_into_registry
    from secrets_kit.schemas.registry_doc import SchemaRegistryDocument
    from secrets_kit.schemas.seed import load_seed_descriptors

    merged = merge_seed_into_registry(
        registry=SchemaRegistryDocument.empty(),
        seeds=load_seed_descriptors(),
        allow_replace=False,
    )
    return merged.document


def _catalog_payload(*, document: "SchemaRegistryDocument") -> dict[str, object]:
    payload = document.to_dict()
    return {
        "version": REGISTRY_VERSION,
        "$schema": REGISTRY_SCHEMA,
        "registry_version": payload["registry_version"],
        "schemas": payload["schemas"],
        "deprecated": payload["deprecated"],
    }


def _document_from_catalog_payload(*, payload: Mapping[str, object]) -> "SchemaRegistryDocument":
    from secrets_kit.schemas.registry_doc import SchemaRegistryDocument

    document_payload = {
        "registry_version": payload.get("registry_version", 1),
        "schemas": payload.get("schemas", {}),
        "deprecated": payload.get("deprecated", {}),
    }
    return SchemaRegistryDocument.from_dict(document_payload)


def _payload_contains_inventory(*, payload: Mapping[str, object]) -> bool:
    entries = payload.get("entries")
    return isinstance(entries, list) and bool(entries)


def _backup_inventory_registry(*, home: Path | None = None) -> None:
    rpath = registry_path(home=home)
    backup = registry_backup_path(home=home)
    if backup.exists():
        return
    shutil.copy2(rpath, backup)
    os.chmod(backup, 0o600)


def _write_catalog(*, document: "SchemaRegistryDocument", home: Path | None = None) -> None:
    rpath = registry_path(home=home)
    _atomic_write_json(path=rpath, payload=_catalog_payload(document=document))
    os.chmod(rpath, 0o600)


def ensure_registry_storage(*, home: Path | None = None) -> Path:
    """Create local schema/catalog registry storage with secure permissions."""
    rdir = registry_dir(home=home)
    rdir.mkdir(parents=True, exist_ok=True)
    os.chmod(rdir, 0o700)
    _check_secure_perms(path=rdir, max_mode=0o700)

    rpath = registry_path(home=home)
    if not rpath.exists():
        _write_catalog(document=_catalog_document_from_seeds(), home=home)
    os.chmod(rpath, 0o600)
    _check_secure_perms(path=rpath, max_mode=0o600)
    return rpath


def ensure_defaults_storage(*, home: Path | None = None) -> Path:
    """Create defaults file with secure permissions."""
    rdir = registry_dir(home=home)
    rdir.mkdir(parents=True, exist_ok=True)
    os.chmod(rdir, 0o700)
    _check_secure_perms(path=rdir, max_mode=0o700)

    dpath = defaults_path(home=home)
    if not dpath.exists():
        _atomic_write_json(path=dpath, payload={})
    os.chmod(dpath, 0o600)
    _check_secure_perms(path=dpath, max_mode=0o600)
    return dpath


def load_catalog(*, home: Path | None = None) -> "SchemaRegistryDocument":
    """Load registry.json, creating or repairing explicit catalog storage."""
    rpath = ensure_registry_storage(home=home)
    _check_secure_perms(path=rpath, max_mode=0o600)
    raw_payload = cast(object, json.loads(rpath.read_text(encoding="utf-8")))
    if not isinstance(raw_payload, dict):
        raise RegistryError(f"invalid registry json: {rpath} (top-level must be object)")
    payload = cast(dict[str, object], raw_payload)

    if _payload_contains_inventory(payload=payload):
        _backup_inventory_registry(home=home)
        document = _catalog_document_from_seeds()
        _write_catalog(document=document, home=home)
        return document

    try:
        return _document_from_catalog_payload(payload=payload)
    except Exception as exc:
        raise RegistryError(f"invalid registry catalog: {rpath}: {exc}") from exc


def read_catalog(*, home: Path | None = None) -> "SchemaRegistryDocument":
    """Read registry.json without creating, repairing, or rewriting it."""
    rpath = registry_path(home=home)
    if not rpath.is_file():
        raise RegistryError(f"schema registry not found: {rpath}; run seckit init")
    _check_secure_perms(path=rpath, max_mode=0o600)
    try:
        raw_payload = cast(object, json.loads(rpath.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"invalid registry json: {rpath}: {exc}") from exc
    if not isinstance(raw_payload, dict):
        raise RegistryError(f"invalid registry json: {rpath} (top-level must be object)")
    payload = cast(dict[str, object], raw_payload)
    if _payload_contains_inventory(payload=payload):
        raise RegistryError(
            f"invalid registry catalog: {rpath}: legacy inventory content requires explicit init"
        )
    try:
        return _document_from_catalog_payload(payload=payload)
    except Exception as exc:
        raise RegistryError(f"invalid registry catalog: {rpath}: {exc}") from exc


def save_catalog(*, document: "SchemaRegistryDocument", home: Path | None = None) -> None:
    """Persist registry.json as a schema/catalog document."""
    _ = ensure_registry_storage(home=home)
    _write_catalog(document=document, home=home)


def load_defaults(*, home: Path | None = None) -> dict[str, object]:
    """Load operator defaults from defaults.json."""
    dpath = ensure_defaults_storage(home=home)
    _check_secure_perms(path=dpath, max_mode=0o600)
    raw_payload = cast(object, json.loads(dpath.read_text(encoding="utf-8")))
    if not isinstance(raw_payload, dict):
        raise RegistryError(f"invalid defaults json: {dpath} (top-level must be object)")
    return cast(dict[str, object], raw_payload)


def read_defaults(*, home: Path | None = None) -> dict[str, object]:
    """Read operator defaults without creating, repairing, or rewriting them."""
    dpath = defaults_path(home=home)
    if not dpath.is_file():
        raise RegistryError(f"operator defaults not found: {dpath}; run seckit init")
    _check_secure_perms(path=dpath, max_mode=0o600)
    try:
        raw_payload = cast(object, json.loads(dpath.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"invalid defaults json: {dpath}: {exc}") from exc
    if not isinstance(raw_payload, dict):
        raise RegistryError(f"invalid defaults json: {dpath} (top-level must be object)")
    return cast(dict[str, object], raw_payload)


def save_defaults(*, payload: dict[str, object], home: Path | None = None) -> None:
    """Persist operator defaults."""
    dpath = ensure_defaults_storage(home=home)
    _check_secure_perms(path=dpath, max_mode=0o600)
    _atomic_write_json(path=dpath, payload=payload)
    os.chmod(dpath, 0o600)


def load_registry(*, home: Path | None = None) -> dict[str, EntryMetadata]:
    """Compatibility wrapper for removed inventory registry reads."""
    _ = load_catalog(home=home)
    raise RegistryError("registry inventory is no longer supported; use load_catalog()")


def save_registry(*, entries: dict[str, EntryMetadata], home: Path | None = None) -> None:
    """Compatibility wrapper for removed inventory registry writes."""
    _ = entries, home
    raise RegistryError("registry inventory is no longer supported; use save_catalog()")


def upsert_metadata(*, metadata: EntryMetadata, home: Path | None = None) -> None:
    """Reject per-secret metadata writes to registry.json."""
    _ = metadata, home
    raise RegistryError("registry.json is a catalog only and cannot store metadata instances")


def delete_metadata(*, service: str, account: str, name: str, home: Path | None = None) -> bool:
    """Reject per-secret metadata deletes from registry.json."""
    _ = service, account, name, home
    raise RegistryError("registry.json is a catalog only and has no metadata inventory")
