"""Registry handling for non-secret metadata."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from secrets_kit.models.core import EntryMetadata, ensure_entry_id, normalize_custom, now_utc_iso

_VALIDATE_REGISTRY_METADATA = os.environ.get("SECKIT_VALIDATE_REGISTRY_METADATA") == "1"

# On-disk registry.json top-level ``version`` (v2 = slim index only).
REGISTRY_FILE_VERSION = 2
LEGACY_REGISTRY_FILE_VERSION = 1

# JSON Schema id for tooling / documentation (not a JSON Schema file on disk).
REGISTRY_JSON_SCHEMA_ID = "https://unixwzrd.ai/schemas/seckit/registry-slim-v2.json"

# Keys allowed in each registry entry object on disk (v2). No tags, source, kind, domains, etc.
# ``sync_origin_host`` holds only the peer-sync vector host id (same semantics as
# ``custom["seckit_sync_origin_host"]`` in full metadata); kept so merge can compare registry vs store.
_REGISTRY_PEER_SYNC_KEY = "seckit_sync_origin_host"
_REGISTRY_ENTRY_ALLOWED_KEYS = frozenset(
    {"name", "service", "account", "entry_id", "created_at", "updated_at", "sync_origin_host"}
)


class RegistryError(RuntimeError):
    """Registry operation failed."""


def registry_dir(*, home: Optional[Path] = None) -> Path:
    """Return metadata directory path."""
    base = home or Path.home()
    return base / ".config" / "seckit"


def registry_path(*, home: Optional[Path] = None) -> Path:
    """Return metadata file path."""
    return registry_dir(home=home) / "registry.json"


def defaults_path(*, home: Optional[Path] = None) -> Path:
    """Return operator defaults file path."""
    return registry_dir(home=home) / "defaults.json"


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _check_secure_perms(*, path: Path, max_mode: int) -> None:
    if not path.exists():
        return
    mode = _mode(path)
    if mode > max_mode:
        raise RegistryError(f"unsafe permissions on {path}: {oct(mode)} (expected <= {oct(max_mode)})")


def ensure_registry_storage(*, home: Optional[Path] = None) -> Path:
    """Create registry directory/file with secure permissions."""
    rdir = registry_dir(home=home)
    rdir.mkdir(parents=True, exist_ok=True)
    os.chmod(rdir, 0o700)
    _check_secure_perms(path=rdir, max_mode=0o700)

    rpath = registry_path(home=home)
    if not rpath.exists():
        payload = _empty_registry_payload()
        _atomic_write_json(path=rpath, payload=payload)
    os.chmod(rpath, 0o600)
    _check_secure_perms(path=rpath, max_mode=0o600)
    return rpath


def ensure_defaults_storage(*, home: Optional[Path] = None) -> Path:
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


def _atomic_write_json(*, path: Path, payload: Dict) -> None:
    """Write JSON atomically with secure file mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="registry-", suffix=".json", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _empty_registry_payload() -> Dict[str, object]:
    return {
        "version": REGISTRY_FILE_VERSION,
        "$schema": REGISTRY_JSON_SCHEMA_ID,
        "entries": [],
    }


def _peer_origin_from_metadata(meta: EntryMetadata) -> str:
    """Host id used for peer merge vector (must match ``sync_merge.SYNC_ORIGIN_CUSTOM_KEY``)."""
    if not meta.custom:
        return ""
    return str(meta.custom.get(_REGISTRY_PEER_SYNC_KEY, "")).strip()


def entry_to_slim_registry_dict(metadata: EntryMetadata) -> Dict[str, Any]:
    """Serialize one entry for ``registry.json`` (non-leaking index only)."""
    meta = ensure_entry_id(metadata)
    row: Dict[str, Any] = {
        "name": meta.name,
        "service": meta.service,
        "account": meta.account,
        "entry_id": meta.entry_id,
        "created_at": meta.created_at,
        "updated_at": meta.updated_at,
    }
    sync_origin = _peer_origin_from_metadata(meta)
    if sync_origin:
        row["sync_origin_host"] = sync_origin
    return row


def slim_registry_entry_to_metadata(payload: Dict[str, Any]) -> EntryMetadata:
    """Build in-memory :class:`EntryMetadata` from a v2 registry row (defaults for unstored fields)."""
    sync_origin = str(payload.get("sync_origin_host", "") or "").strip()
    custom = normalize_custom({_REGISTRY_PEER_SYNC_KEY: sync_origin} if sync_origin else {})
    return EntryMetadata(
        name=str(payload["name"]),
        service=str(payload["service"]),
        account=str(payload["account"]),
        entry_id=str(payload.get("entry_id", "")),
        created_at=str(payload.get("created_at", now_utc_iso())),
        updated_at=str(payload.get("updated_at", now_utc_iso())),
        custom=custom,
    )


def _merged_peer_sync_custom(*, incoming: EntryMetadata, existing: Optional[EntryMetadata]) -> Dict[str, Any]:
    sync = _peer_origin_from_metadata(incoming) or (
        _peer_origin_from_metadata(existing) if existing is not None else ""
    )
    return normalize_custom({_REGISTRY_PEER_SYNC_KEY: sync} if sync else {})


def merge_into_slim_registry_entry(*, incoming: EntryMetadata, existing: Optional[EntryMetadata]) -> EntryMetadata:
    """Strip ``incoming`` to index fields; preserve ``created_at`` / ``entry_id`` from *existing* when needed."""
    ts = now_utc_iso()
    inc = ensure_entry_id(incoming)
    peer_custom = _merged_peer_sync_custom(incoming=inc, existing=existing)
    if existing:
        ex = ensure_entry_id(existing)
        eid = (inc.entry_id or ex.entry_id).strip() or ex.entry_id
        return EntryMetadata(
            name=inc.name,
            service=inc.service,
            account=inc.account,
            entry_id=eid,
            created_at=ex.created_at,
            updated_at=ts,
            custom=peer_custom,
        )
    return EntryMetadata(
        name=inc.name,
        service=inc.service,
        account=inc.account,
        entry_id=inc.entry_id,
        created_at=inc.created_at or ts,
        updated_at=inc.updated_at or ts,
        custom=peer_custom,
    )


def load_registry(*, home: Optional[Path] = None) -> Dict[str, EntryMetadata]:
    """Load metadata registry into keyed mapping.

    **v2 (current):** each file entry is a slim index (locator + ``entry_id`` + timestamps).
    Authoritative tags, source, kind, domains, etc. live in the backend store only.

    **v1 (legacy):** full :class:`EntryMetadata` blobs are read once, rewritten as v2 on load.

    When the environment variable ``SECKIT_VALIDATE_REGISTRY_METADATA=1`` is set at process
    start, each row is additionally checked against :mod:`secrets_kit.schemas.metadata`
    mirrors after load-time parsing (see ``docs/METADATA_REGISTRY.md`` and ``docs/BACKEND_STORE_CONTRACT.md``).
    Default is off (no extra validation).
    """
    rpath = ensure_registry_storage(home=home)
    _check_secure_perms(path=rpath, max_mode=0o600)
    payload = json.loads(rpath.read_text(encoding="utf-8"))
    file_ver = int(payload.get("version", LEGACY_REGISTRY_FILE_VERSION))
    entries = payload.get("entries", [])
    mapping: Dict[str, EntryMetadata] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        if file_ver <= LEGACY_REGISTRY_FILE_VERSION:
            if _VALIDATE_REGISTRY_METADATA:
                from secrets_kit.schemas.metadata import parse_full_registry_metadata_with_schema_check

                full = parse_full_registry_metadata_with_schema_check(item)
            else:
                full = EntryMetadata.from_dict(item)
            sync = _peer_origin_from_metadata(full)
            slim = EntryMetadata(
                name=full.name,
                service=full.service,
                account=full.account,
                entry_id=ensure_entry_id(full).entry_id,
                created_at=full.created_at,
                updated_at=full.updated_at,
                custom=normalize_custom({_REGISTRY_PEER_SYNC_KEY: sync} if sync else {}),
            )
            mapping[slim.key()] = slim
        else:
            if _VALIDATE_REGISTRY_METADATA:
                from secrets_kit.schemas.metadata import validate_slim_registry_entry

                validate_slim_registry_entry(item)
            keys = set(item.keys())
            if not keys <= _REGISTRY_ENTRY_ALLOWED_KEYS:
                raise RegistryError(
                    f"registry entry has unexpected keys (expected slim index only): {sorted(keys - _REGISTRY_ENTRY_ALLOWED_KEYS)!r}"
                )
            if "name" not in item or "service" not in item or "account" not in item:
                raise RegistryError("registry entry missing required locator fields (name, service, account)")
            meta = ensure_entry_id(slim_registry_entry_to_metadata(item))
            mapping[meta.key()] = meta
    if file_ver <= LEGACY_REGISTRY_FILE_VERSION:
        save_registry(entries=mapping, home=home)
    return mapping


def save_registry(*, entries: Dict[str, EntryMetadata], home: Optional[Path] = None) -> None:
    """Persist metadata registry mapping (always v2 slim index)."""
    rpath = ensure_registry_storage(home=home)
    _check_secure_perms(path=rpath, max_mode=0o600)
    serialized = [
        entry_to_slim_registry_dict(m)
        for m in sorted(entries.values(), key=lambda item: (item.service, item.account, item.name))
    ]
    body: Dict[str, object] = {
        "version": REGISTRY_FILE_VERSION,
        "$schema": REGISTRY_JSON_SCHEMA_ID,
        "entries": serialized,
    }
    _atomic_write_json(path=rpath, payload=body)
    os.chmod(rpath, 0o600)


def load_defaults(*, home: Optional[Path] = None) -> Dict[str, object]:
    """Load operator defaults from defaults.json."""
    dpath = ensure_defaults_storage(home=home)
    _check_secure_perms(path=dpath, max_mode=0o600)
    payload = json.loads(dpath.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RegistryError(f"invalid defaults json: {dpath} (top-level must be object)")
    return payload


def save_defaults(*, payload: Dict[str, object], home: Optional[Path] = None) -> None:
    """Persist operator defaults."""
    dpath = ensure_defaults_storage(home=home)
    _check_secure_perms(path=dpath, max_mode=0o600)
    _atomic_write_json(path=dpath, payload=payload)
    os.chmod(dpath, 0o600)


def upsert_metadata(*, metadata: EntryMetadata, home: Optional[Path] = None) -> None:
    """Insert or update one registry index row (slim); does not duplicate store metadata."""
    entries = load_registry(home=home)
    key = metadata.key()
    existing = entries.get(key)
    entries[key] = merge_into_slim_registry_entry(incoming=metadata, existing=existing)
    save_registry(entries=entries, home=home)


def delete_metadata(*, service: str, account: str, name: str, home: Optional[Path] = None) -> bool:
    """Delete one metadata record. Return True when removed."""
    entries = load_registry(home=home)
    key = f"{service}::{account}::{name}"
    existed = key in entries
    if existed:
        del entries[key]
        save_registry(entries=entries, home=home)
    return existed
