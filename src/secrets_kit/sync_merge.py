"""Deterministic merge rules for peer sync import."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Literal, Optional, Set

from secrets_kit.importers import ImportCandidate
from secrets_kit.keychain_backend import BackendError, get_secret, secret_exists, set_secret
from secrets_kit.models import EntryMetadata, normalize_custom, normalize_domains
from secrets_kit.registry import load_registry, upsert_metadata

SYNC_ORIGIN_CUSTOM_KEY = "seckit_sync_origin_host"


def effective_origin_host(*, meta: EntryMetadata, default_host_id: str) -> str:
    """Host id that last wrote this metadata (for vector-clock style merge)."""
    raw = meta.custom.get(SYNC_ORIGIN_CUSTOM_KEY) if meta.custom else None
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return default_host_id


MergeAction = Literal["import", "skip", "unchanged", "conflict"]


def merge_decision(
    *,
    local_meta: Optional[EntryMetadata],
    local_value: Optional[str],
    incoming_meta: EntryMetadata,
    incoming_value: str,
    incoming_origin_host: str,
    local_host_id: str,
) -> MergeAction:
    """Compare ``updated_at`` then ``origin_host``; equal timestamps + differing values → conflict."""
    if local_meta is None or local_value is None:
        return "import"

    loc_origin = effective_origin_host(meta=local_meta, default_host_id=local_host_id)
    inc_origin = incoming_origin_host.strip() or effective_origin_host(
        meta=incoming_meta, default_host_id=""
    )

    tup_loc = (local_meta.updated_at, loc_origin)
    tup_inc = (incoming_meta.updated_at, inc_origin)

    if tup_inc > tup_loc:
        return "import"
    if tup_inc < tup_loc:
        return "skip"
    if local_value == incoming_value:
        return "unchanged"
    return "conflict"


def stronger_metadata_for_sync(
    *,
    a: Optional[EntryMetadata],
    b: Optional[EntryMetadata],
    local_host_id: str,
) -> Optional[EntryMetadata]:
    """When both registry and store carry metadata, use the lexicographically larger merge vector."""
    if a is None:
        return b
    if b is None:
        return a
    ta = (a.updated_at, effective_origin_host(meta=a, default_host_id=local_host_id))
    tb = (b.updated_at, effective_origin_host(meta=b, default_host_id=local_host_id))
    return a if ta >= tb else b


def import_candidate_from_sync_row(row: Dict[str, object], *, default_origin: str) -> ImportCandidate:
    """Build candidate from inner bundle ``entries[]`` row."""
    if not isinstance(row, dict):
        raise ValueError("sync entry must be an object")
    meta_raw = row.get("metadata")
    if not isinstance(meta_raw, dict):
        raise ValueError("sync entry missing metadata object")
    meta = EntryMetadata.from_dict(meta_raw)
    value = str(row.get("value", ""))
    origin = str(row.get("origin_host", "") or "").strip() or default_origin
    custom = dict(meta.custom)
    custom[SYNC_ORIGIN_CUSTOM_KEY] = origin
    meta.custom = normalize_custom(custom)
    return ImportCandidate(metadata=meta, value=value)


def apply_peer_sync_import(
    *,
    inner_entries: List[Dict[str, object]],
    local_host_id: str,
    dry_run: bool,
    path: Optional[str],
    backend: str,
    kek_keychain_path: Optional[str],
    domain_filter: Optional[List[str]] = None,
    home: Optional[Path] = None,
) -> Dict[str, int]:
    """Apply deterministic merge for decrypted bundle entries.

    ``home`` selects the metadata registry tree (``HOME/.config/seckit`` when
    omitted, same as other CLI helpers). Use an explicit path in tests or
    tooling so imports do not depend on mutating ``HOME``.
    """
    from secrets_kit.cli import _read_metadata

    stats = {"conflicts": 0, "created": 0, "skipped": 0, "unchanged": 0, "updated": 0}
    registry = load_registry(home=home)

    filter_set: Optional[Set[str]] = None
    if domain_filter:
        filter_set = set(normalize_domains(domain_filter))

    for raw in inner_entries:
        if not isinstance(raw, dict):
            stats["skipped"] += 1
            continue
        cand = import_candidate_from_sync_row(raw, default_origin=local_host_id)
        if filter_set:
            entry_domains = set(normalize_domains(cand.metadata.domains))
            if not (filter_set & entry_domains):
                stats["skipped"] += 1
                continue

        res = _read_metadata(
            service=cand.metadata.service,
            account=cand.metadata.account,
            name=cand.metadata.name,
            registry=registry,
            path=path,
            backend=backend,
            kek_keychain_path=kek_keychain_path,
        )
        store_meta = res["metadata"] if res and isinstance(res.get("metadata"), EntryMetadata) else None
        reg_key = cand.metadata.key()
        registry_entry = registry.get(reg_key)
        local_meta = stronger_metadata_for_sync(
            a=registry_entry,
            b=store_meta,
            local_host_id=local_host_id,
        )
        local_val: Optional[str] = None
        if local_meta and secret_exists(
            service=cand.metadata.service,
            account=cand.metadata.account,
            name=cand.metadata.name,
            path=path,
            backend=backend,
            kek_keychain_path=kek_keychain_path,
        ):
            try:
                local_val = get_secret(
                    service=cand.metadata.service,
                    account=cand.metadata.account,
                    name=cand.metadata.name,
                    path=path,
                    backend=backend,
                    kek_keychain_path=kek_keychain_path,
                )
            except BackendError:
                local_val = None

        incoming_origin = str(raw.get("origin_host", "") or "").strip()
        if not incoming_origin:
            incoming_origin = effective_origin_host(meta=cand.metadata, default_host_id="")

        decision = merge_decision(
            local_meta=local_meta,
            local_value=local_val,
            incoming_meta=cand.metadata,
            incoming_value=cand.value,
            incoming_origin_host=incoming_origin,
            local_host_id=local_host_id,
        )

        if decision == "skip":
            stats["skipped"] += 1
            continue
        if decision == "unchanged":
            stats["unchanged"] += 1
            continue
        if decision == "conflict":
            stats["conflicts"] += 1
            continue

        exists = local_val is not None
        if dry_run:
            stats["updated" if exists else "created"] += 1
            continue

        set_secret(
            service=cand.metadata.service,
            account=cand.metadata.account,
            name=cand.metadata.name,
            value=cand.value,
            label=cand.metadata.name,
            comment=cand.metadata.to_keychain_comment(),
            path=path,
            backend=backend,
            kek_keychain_path=kek_keychain_path,
        )
        upsert_metadata(metadata=cand.metadata, home=home)
        registry[cand.metadata.key()] = cand.metadata
        stats["updated" if exists else "created"] += 1

    return stats
