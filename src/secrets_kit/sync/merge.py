"""
secrets_kit.sync.merge

Deterministic merge rules for peer sync import.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

from secrets_kit.backends.base import normalize_store_locator
from secrets_kit.backends.errors import BackendError
from secrets_kit.backends.operations import delete_secret, get_secret, secret_exists, set_secret
from secrets_kit.backends.registry import BACKEND_SQLITE, is_sqlite_backend, normalize_backend
from secrets_kit.importers import ImportCandidate
from secrets_kit.models.core import (
    EntryMetadata,
    ensure_entry_id,
    make_registry_key,
    normalize_custom,
    normalize_domains,
)
from secrets_kit.models.lineage import LineageSnapshot
from secrets_kit.registry.core import delete_metadata, load_registry, upsert_metadata
from secrets_kit.registry.resolve import _read_metadata
from secrets_kit.sync.canonical_record import (
    computed_peer_row_content_hash,
    verify_incoming_row_content_hash,
)
from secrets_kit.sync.reconcile_reasons import (
    MergeAction,
    MergeExplain,
    ReconcileReason,
    hash_preview,
)

SYNC_ORIGIN_CUSTOM_KEY = "seckit_sync_origin_host"


def effective_origin_host(*, meta: EntryMetadata, default_host_id: str) -> str:
    """Host id that last wrote this metadata (legacy merge tie-break)."""
    raw = meta.custom.get(SYNC_ORIGIN_CUSTOM_KEY) if meta.custom else None
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return default_host_id


def sync_lineage_eligible(cand: ImportCandidate) -> bool:
    """True when incoming row carries Phase 6A lineage fields (SQLite ladder)."""
    if cand.disposition == "tombstone":
        return cand.tombstone_generation is not None
    return cand.generation is not None


def _entry_id_conflict(*, local_meta: Optional[EntryMetadata], incoming: ImportCandidate) -> bool:
    """Return True when local and incoming entry IDs differ and both are non-empty."""
    if local_meta is None:
        return False
    a = (local_meta.entry_id or "").strip()
    b = (incoming.metadata.entry_id or "").strip()
    if not a or not b:
        return False
    return a != b


def merge_decision(
    *,
    local_meta: Optional[EntryMetadata],
    local_value: Optional[str],
    incoming_meta: EntryMetadata,
    incoming_value: str,
    incoming_origin_host: str,
    local_host_id: str,
) -> Literal["import", "skip", "unchanged", "conflict"]:
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


def merge_explanation_v2(
    *,
    local_meta: Optional[EntryMetadata],
    local_value: Optional[str],
    local_lineage: Optional[LineageSnapshot],
    incoming: ImportCandidate,
    incoming_origin_host: str,
    local_host_id: str,
    sqlite_lineage_merge: bool,
) -> MergeExplain:
    """Pure classification with stable ``reason`` (no I/O)."""
    use_ladder = sqlite_lineage_merge and sync_lineage_eligible(incoming)
    inc_disp: Literal["active", "tombstone"] = incoming.disposition
    ldel = local_lineage.deleted if local_lineage is not None else None
    lg = int(local_lineage.generation) if local_lineage is not None else None
    ltg = int(local_lineage.tombstone_generation) if local_lineage is not None else None
    ig = incoming.generation
    itg = incoming.tombstone_generation

    if use_ladder and _entry_id_conflict(local_meta=local_meta, incoming=incoming):
        return MergeExplain(
            decision="conflict",
            reason=ReconcileReason.ENTRY_ID_MISMATCH,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=ldel,
            local_generation=lg,
            local_tombstone_generation=ltg,
            incoming_generation=ig,
            incoming_tombstone_generation=itg,
            use_lineage_ladder=True,
        )

    if not use_ladder:
        raw = merge_decision(
            local_meta=local_meta,
            local_value=local_value,
            incoming_meta=incoming.metadata,
            incoming_value=incoming.value if incoming.disposition == "active" else "",
            incoming_origin_host=incoming_origin_host,
            local_host_id=local_host_id,
        )
        reason_map = {
            "import": ReconcileReason.LEGACY_IMPORT,
            "skip": ReconcileReason.LEGACY_SKIP,
            "unchanged": ReconcileReason.LEGACY_UNCHANGED,
            "conflict": ReconcileReason.LEGACY_CONFLICT,
        }
        return MergeExplain(
            decision=raw,  # type: ignore[arg-type]
            reason=reason_map[raw],
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            use_lineage_ladder=False,
        )

    if incoming.disposition == "tombstone":
        inc_t = int(incoming.tombstone_generation or 0)
        if local_lineage is None:
            return MergeExplain(
                decision="unchanged",
                reason=ReconcileReason.TOMBSTONE_NO_LOCAL_ROW,
                sqlite_lineage_merge=sqlite_lineage_merge,
                incoming_disposition=inc_disp,
                incoming_tombstone_generation=inc_t,
                use_lineage_ladder=True,
            )
        if local_lineage.deleted:
            loc_t = int(local_lineage.tombstone_generation)
            if inc_t < loc_t:
                return MergeExplain(
                    decision="skip",
                    reason=ReconcileReason.TOMBSTONE_SKIP_STALE_VS_TOMBSTONE,
                    sqlite_lineage_merge=sqlite_lineage_merge,
                    incoming_disposition=inc_disp,
                    local_deleted=True,
                    local_generation=int(local_lineage.generation),
                    local_tombstone_generation=loc_t,
                    incoming_tombstone_generation=inc_t,
                    use_lineage_ladder=True,
                )
            if inc_t == loc_t:
                return MergeExplain(
                    decision="unchanged",
                    reason=ReconcileReason.TOMBSTONE_UNCHANGED_EQUAL,
                    sqlite_lineage_merge=sqlite_lineage_merge,
                    incoming_disposition=inc_disp,
                    local_deleted=True,
                    local_generation=int(local_lineage.generation),
                    local_tombstone_generation=loc_t,
                    incoming_tombstone_generation=inc_t,
                    use_lineage_ladder=True,
                )
            return MergeExplain(
                decision="import",
                reason=ReconcileReason.TOMBSTONE_BUMP_NEWER,
                sqlite_lineage_merge=sqlite_lineage_merge,
                incoming_disposition=inc_disp,
                local_deleted=True,
                local_generation=int(local_lineage.generation),
                local_tombstone_generation=loc_t,
                incoming_tombstone_generation=inc_t,
                use_lineage_ladder=True,
            )
        loc_g = int(local_lineage.generation)
        if inc_t >= loc_g:
            return MergeExplain(
                decision="import",
                reason=ReconcileReason.TOMBSTONE_WINS_ACTIVE,
                sqlite_lineage_merge=sqlite_lineage_merge,
                incoming_disposition=inc_disp,
                local_deleted=False,
                local_generation=loc_g,
                incoming_tombstone_generation=inc_t,
                use_lineage_ladder=True,
            )
        return MergeExplain(
            decision="skip",
            reason=ReconcileReason.TOMBSTONE_SKIP_STALE_VS_ACTIVE,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=False,
            local_generation=loc_g,
            incoming_tombstone_generation=inc_t,
            use_lineage_ladder=True,
        )

    if incoming.generation is None:
        return MergeExplain(
            decision="skip",
            reason=ReconcileReason.ACTIVE_SKIP_MISSING_GENERATION,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=ldel,
            local_generation=lg,
            local_tombstone_generation=ltg,
            use_lineage_ladder=True,
        )
    inc_g = int(incoming.generation)
    if local_lineage is None:
        return MergeExplain(
            decision="import",
            reason=ReconcileReason.ACTIVE_IMPORT_NO_LOCAL_LINEAGE,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            incoming_generation=inc_g,
            use_lineage_ladder=True,
        )
    if local_lineage.deleted:
        return MergeExplain(
            decision="replay_suppressed",
            reason=ReconcileReason.LOCAL_DELETED_REPLAY_SUPPRESSED,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=True,
            local_generation=int(local_lineage.generation),
            local_tombstone_generation=int(local_lineage.tombstone_generation),
            incoming_generation=inc_g,
            use_lineage_ladder=True,
        )

    loc_g = int(local_lineage.generation)
    loc_h = ""
    if local_meta is not None:
        loc_h = (local_meta.content_hash or "").strip().lower()
    inc_h = (incoming.content_hash or incoming.metadata.content_hash or "").strip().lower()
    if inc_g > loc_g:
        return MergeExplain(
            decision="import",
            reason=ReconcileReason.NEWER_GENERATION_IMPORT,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=False,
            local_generation=loc_g,
            incoming_generation=inc_g,
            local_content_hash_preview=hash_preview(loc_h),
            incoming_content_hash_preview=hash_preview(inc_h),
            use_lineage_ladder=True,
        )
    if inc_g < loc_g:
        return MergeExplain(
            decision="skip",
            reason=ReconcileReason.STALE_GENERATION,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=False,
            local_generation=loc_g,
            incoming_generation=inc_g,
            use_lineage_ladder=True,
        )
    if loc_h and inc_h and loc_h != inc_h:
        return MergeExplain(
            decision="conflict",
            reason=ReconcileReason.CONTENT_HASH_MISMATCH_EQUAL_GEN,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=False,
            local_generation=loc_g,
            incoming_generation=inc_g,
            local_content_hash_preview=hash_preview(loc_h),
            incoming_content_hash_preview=hash_preview(inc_h),
            use_lineage_ladder=True,
        )
    lv = local_value if local_value is not None else ""
    if lv == incoming.value:
        return MergeExplain(
            decision="unchanged",
            reason=ReconcileReason.EQUAL_GEN_SAME_VALUE,
            sqlite_lineage_merge=sqlite_lineage_merge,
            incoming_disposition=inc_disp,
            local_deleted=False,
            local_generation=loc_g,
            incoming_generation=inc_g,
            use_lineage_ladder=True,
        )
    return MergeExplain(
        decision="conflict",
        reason=ReconcileReason.EQUAL_GEN_VALUE_CONFLICT,
        sqlite_lineage_merge=sqlite_lineage_merge,
        incoming_disposition=inc_disp,
        local_deleted=False,
        local_generation=loc_g,
        incoming_generation=inc_g,
        use_lineage_ladder=True,
    )


def merge_decision_v2(
    *,
    local_meta: Optional[EntryMetadata],
    local_value: Optional[str],
    local_lineage: Optional[LineageSnapshot],
    incoming: ImportCandidate,
    incoming_origin_host: str,
    local_host_id: str,
    sqlite_lineage_merge: bool,
) -> MergeAction:
    """Phase 6A merge action; see ``merge_explanation_v2`` for stable reason codes."""
    return merge_explanation_v2(
        local_meta=local_meta,
        local_value=local_value,
        local_lineage=local_lineage,
        incoming=incoming,
        incoming_origin_host=incoming_origin_host,
        local_host_id=local_host_id,
        sqlite_lineage_merge=sqlite_lineage_merge,
    ).decision


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

    disp_raw = row.get("disposition", "active")
    disp = str(disp_raw).strip().lower()
    if disp not in ("active", "tombstone"):
        disp = "active"

    def _opt_int(key: str) -> Optional[int]:
        """Safely coerce a dict value to int or None."""
        if key not in row:
            return None
        v = row[key]
        if v is None or v == "":
            return None
        try:
            return int(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    def _opt_str_hash(key: str) -> Optional[str]:
        """Safely extract a string hash value or None."""
        if key not in row:
            return None
        v = row[key]
        if v is None:
            return None
        s = str(v).strip().lower()
        return s or None

    row_hash = _opt_str_hash("content_hash")
    meta_hash = (meta.content_hash or "").strip().lower() or None
    eff_hash = row_hash or meta_hash

    return ImportCandidate(
        metadata=meta,
        value=value,
        disposition="tombstone" if disp == "tombstone" else "active",
        generation=_opt_int("generation"),
        tombstone_generation=_opt_int("tombstone_generation"),
        content_hash=eff_hash,
    )


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
    trace_out: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Apply deterministic merge for decrypted bundle entries.

    Returns counters plus optional ``hash_conflict_details`` (list of diagnostic dicts; no secret values).

    When ``trace_out`` is a list, appends one secret-safe dict per classified row (decision, reason, lineage fields).

    ``home`` selects the metadata registry tree (``HOME/.config/seckit`` when
    omitted, same as other CLI helpers). Use an explicit path in tests or
    tooling so imports do not depend on mutating ``HOME``.
    """
    stats = {
        "conflicts": 0,
        "created": 0,
        "skipped": 0,
        "unchanged": 0,
        "updated": 0,
        "replay_suppressed": 0,
        "tombstone_applied": 0,
        "hash_conflicts": 0,
        "hash_conflict_details": [],
    }
    registry = load_registry(home=home)
    nb = normalize_backend(backend)
    sqlite_store = None
    if nb == BACKEND_SQLITE and path:
        from secrets_kit.backends.sqlite import SqliteSecretStore

        sqlite_store = SqliteSecretStore(db_path=path, kek_keychain_path=kek_keychain_path)

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

        if cand.disposition == "active":
            declared = str(raw.get("content_hash", "") or "").strip()
            if declared and not verify_incoming_row_content_hash(
                secret=cand.value,
                metadata=cand.metadata,
                row_content_hash=declared,
            ):
                stats["hash_conflicts"] += 1
                stats["conflicts"] += 1
                computed = computed_peer_row_content_hash(secret=cand.value, metadata=cand.metadata)
                details = stats["hash_conflict_details"]
                if isinstance(details, list):
                    details.append(
                        {
                            "reason": ReconcileReason.CONTENT_HASH_MISMATCH,
                            "declared_content_hash": declared.lower(),
                            "computed_content_hash": computed.lower(),
                            "entry_id": (cand.metadata.entry_id or "").strip(),
                            "service": cand.metadata.service,
                            "account": cand.metadata.account,
                            "name": cand.metadata.name,
                            "generation": cand.generation,
                            "tombstone_generation": cand.tombstone_generation,
                        }
                    )
                if trace_out is not None:
                    trace_out.append(
                        {
                            "entry_id": (cand.metadata.entry_id or "").strip(),
                            "service": cand.metadata.service,
                            "account": cand.metadata.account,
                            "name": cand.metadata.name,
                            "decision": "conflict",
                            "reason": ReconcileReason.CONTENT_HASH_MISMATCH,
                            "sqlite_lineage_merge": bool(is_sqlite_backend(backend) and sqlite_store is not None),
                            "incoming_disposition": "active",
                            "incoming_generation": cand.generation,
                            "incoming_tombstone_generation": cand.tombstone_generation,
                            "local_content_hash": hash_preview(computed),
                            "incoming_content_hash": hash_preview(declared),
                        }
                    )
                continue

        eid = (cand.metadata.entry_id or "").strip()
        sqlite_merge = is_sqlite_backend(backend) and sqlite_store is not None

        resolved_by_eid = None
        if sqlite_merge and eid:
            assert sqlite_store is not None
            resolved_by_eid = sqlite_store.resolve_by_entry_id(entry_id=eid)

        if resolved_by_eid is not None:
            store_meta = resolved_by_eid.metadata
            local_val: Optional[str] = resolved_by_eid.secret
            reg_key_cand = cand.metadata.key()
            reg_key_store = store_meta.key()
        else:
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
            reg_key_cand = cand.metadata.key()
            reg_key_store = store_meta.key() if store_meta is not None else reg_key_cand
            local_val = None
            if store_meta and secret_exists(
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

        registry_entry = registry.get(reg_key_cand) or (
            registry.get(reg_key_store) if reg_key_store != reg_key_cand else None
        )
        local_meta = stronger_metadata_for_sync(
            a=registry_entry,
            b=store_meta,
            local_host_id=local_host_id,
        )

        incoming_origin = str(raw.get("origin_host", "") or "").strip()
        if not incoming_origin:
            incoming_origin = effective_origin_host(meta=cand.metadata, default_host_id="")

        local_lineage: Optional[LineageSnapshot] = None
        if sqlite_merge and (sync_lineage_eligible(cand) or cand.disposition == "tombstone"):
            assert sqlite_store is not None
            local_lineage = sqlite_store.read_lineage_snapshot(
                entry_id=eid if eid else None,
                service=cand.metadata.service,
                account=cand.metadata.account,
                name=cand.metadata.name,
            )

        explain = merge_explanation_v2(
            local_meta=local_meta,
            local_value=local_val,
            local_lineage=local_lineage,
            incoming=cand,
            incoming_origin_host=incoming_origin,
            local_host_id=local_host_id,
            sqlite_lineage_merge=sqlite_merge,
        )
        decision = explain.decision
        if trace_out is not None:
            trace_out.append(
                explain.to_trace_dict(
                    entry_id=eid,
                    service=cand.metadata.service,
                    account=cand.metadata.account,
                    name=cand.metadata.name,
                )
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
        if decision == "replay_suppressed":
            stats["replay_suppressed"] += 1
            continue

        if cand.disposition == "tombstone":
            if dry_run:
                stats["tombstone_applied"] += 1
                continue
            if sqlite_store is not None and local_lineage is not None and local_lineage.deleted:
                bump = cand.tombstone_generation

                def _bump_only(conn: object) -> None:
                    """Update tombstone generation for an already-deleted entry."""
                    assert sqlite_store is not None
                    if bump is not None:
                        sqlite_store._bump_tombstone_lineage_conn(  # type: ignore[attr-defined]
                            conn,
                            entry_id=local_lineage.entry_id,
                            tombstone_generation=bump,
                        )

                sqlite_store.run_reconcile_transaction(_bump_only)
                stats["tombstone_applied"] += 1
                continue
            del_svc, del_acct, del_nm = cand.metadata.service, cand.metadata.account, cand.metadata.name
            if local_lineage is not None:
                del_svc, del_acct, del_nm = local_lineage.service, local_lineage.account, local_lineage.name
            elif sqlite_store is not None and (cand.metadata.entry_id or "").strip():
                snap = sqlite_store.read_lineage_snapshot(entry_id=(cand.metadata.entry_id or "").strip())
                if snap is not None:
                    del_svc, del_acct, del_nm = snap.service, snap.account, snap.name
            reg_del_key = make_registry_key(service=del_svc, account=del_acct, name=del_nm)

            if sqlite_store is not None:

                def _del_row(conn: object) -> None:
                    """Delete an entry by locator inside a reconcile transaction."""
                    assert sqlite_store is not None
                    sqlite_store._delete_entry_locator_conn(  # type: ignore[attr-defined]
                        conn,
                        service=del_svc,
                        account=del_acct,
                        name=del_nm,
                    )

                sqlite_store.run_reconcile_transaction(_del_row)
            else:
                delete_secret(
                    service=del_svc,
                    account=del_acct,
                    name=del_nm,
                    path=path,
                    backend=backend,
                    kek_keychain_path=kek_keychain_path,
                )
            delete_metadata(service=del_svc, account=del_acct, name=del_nm, home=home)
            registry.pop(reg_del_key, None)
            stats["tombstone_applied"] += 1
            continue

        exists = local_val is not None
        if dry_run:
            stats["updated" if exists else "created"] += 1
            continue

        loc = normalize_store_locator(
            service=cand.metadata.service,
            account=cand.metadata.account,
            name=cand.metadata.name,
        )
        meta_persist = ensure_entry_id(cand.metadata)
        meta_persist = replace(meta_persist, name=loc.name, service=loc.service, account=loc.account)

        if sqlite_store is not None:
            need_rename = False
            if eid and local_lineage is not None and not local_lineage.deleted:
                need_rename = (
                    local_lineage.service != loc.service
                    or local_lineage.account != loc.account
                    or local_lineage.name != loc.name
                )

            def _apply_active(conn: object) -> None:
                """Rename if needed and upsert an active entry inside a reconcile transaction."""
                assert sqlite_store is not None
                if need_rename:
                    sqlite_store._rename_entry_conn(  # type: ignore[attr-defined]
                        conn,
                        entry_id=eid,
                        new_service=loc.service,
                        new_account=loc.account,
                        new_name=loc.name,
                    )
                sqlite_store._set_entry_conn(conn, loc=loc, secret=cand.value, meta=meta_persist)  # type: ignore[attr-defined]

            sqlite_store.run_reconcile_transaction(_apply_active)
        else:
            set_secret(
                service=cand.metadata.service,
                account=cand.metadata.account,
                name=cand.metadata.name,
                value=cand.value,
                label=cand.metadata.name,
                comment=meta_persist.to_keychain_comment(),
                path=path,
                backend=backend,
                kek_keychain_path=kek_keychain_path,
            )

        if resolved_by_eid is not None:
            old_key = resolved_by_eid.metadata.key()
            if old_key != meta_persist.key():
                registry.pop(old_key, None)

        upsert_metadata(metadata=meta_persist, home=home)
        registry[meta_persist.key()] = meta_persist
        stats["updated" if exists else "created"] += 1

    return stats


def explain_incoming_sync_row(
    *,
    raw_row: Dict[str, object],
    local_host_id: str,
    path: Optional[str],
    backend: str,
    kek_keychain_path: Optional[str],
    home: Optional[Path] = None,
) -> Tuple[MergeExplain, Dict[str, Any]]:
    """Read-only: classify one bundle row against current local state (no mutations)."""
    cand = import_candidate_from_sync_row(raw_row, default_origin=local_host_id)
    if cand.disposition == "active":
        declared = str(raw_row.get("content_hash", "") or "").strip()
        if declared and not verify_incoming_row_content_hash(
            secret=cand.value,
            metadata=cand.metadata,
            row_content_hash=declared,
        ):
            computed = computed_peer_row_content_hash(secret=cand.value, metadata=cand.metadata)
            explain = MergeExplain(
                decision="conflict",
                reason=ReconcileReason.CONTENT_HASH_MISMATCH,
                sqlite_lineage_merge=is_sqlite_backend(backend) and bool(path),
                incoming_disposition="active",
                incoming_generation=cand.generation,
                incoming_tombstone_generation=cand.tombstone_generation,
                local_content_hash_preview=hash_preview(computed),
                incoming_content_hash_preview=hash_preview(declared),
                use_lineage_ladder=False,
            )
            ctx = {
                "local_host_id": local_host_id,
                "hash_verify_failed": True,
                "incoming": {
                    "disposition": cand.disposition,
                    "generation": cand.generation,
                    "tombstone_generation": cand.tombstone_generation,
                    "content_hash_preview": hash_preview(declared),
                    "locator": {
                        "service": cand.metadata.service,
                        "account": cand.metadata.account,
                        "name": cand.metadata.name,
                    },
                },
            }
            return explain, ctx
    registry = load_registry(home=home)
    nb = normalize_backend(backend)
    sqlite_store = None
    if nb == BACKEND_SQLITE and path:
        from secrets_kit.backends.sqlite import SqliteSecretStore

        sqlite_store = SqliteSecretStore(db_path=path, kek_keychain_path=kek_keychain_path)

    eid = (cand.metadata.entry_id or "").strip()
    sqlite_merge = is_sqlite_backend(backend) and sqlite_store is not None

    resolved_by_eid = None
    if sqlite_merge and eid:
        assert sqlite_store is not None
        resolved_by_eid = sqlite_store.resolve_by_entry_id(entry_id=eid)

    if resolved_by_eid is not None:
        store_meta = resolved_by_eid.metadata
        local_val: Optional[str] = resolved_by_eid.secret
        reg_key_cand = cand.metadata.key()
        reg_key_store = store_meta.key()
    else:
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
        reg_key_cand = cand.metadata.key()
        reg_key_store = store_meta.key() if store_meta is not None else reg_key_cand
        local_val = None
        if store_meta and secret_exists(
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

    registry_entry = registry.get(reg_key_cand) or (
        registry.get(reg_key_store) if reg_key_store != reg_key_cand else None
    )
    local_meta = stronger_metadata_for_sync(
        a=registry_entry,
        b=store_meta,
        local_host_id=local_host_id,
    )

    incoming_origin = str(raw_row.get("origin_host", "") or "").strip()
    if not incoming_origin:
        incoming_origin = effective_origin_host(meta=cand.metadata, default_host_id="")

    local_lineage: Optional[LineageSnapshot] = None
    if sqlite_merge and (sync_lineage_eligible(cand) or cand.disposition == "tombstone"):
        assert sqlite_store is not None
        local_lineage = sqlite_store.read_lineage_snapshot(
            entry_id=eid if eid else None,
            service=cand.metadata.service,
            account=cand.metadata.account,
            name=cand.metadata.name,
        )

    explain = merge_explanation_v2(
        local_meta=local_meta,
        local_value=local_val,
        local_lineage=local_lineage,
        incoming=cand,
        incoming_origin_host=incoming_origin,
        local_host_id=local_host_id,
        sqlite_lineage_merge=sqlite_merge,
    )

    lineage_dict: Optional[Dict[str, Any]] = None
    if local_lineage is not None:
        lineage_dict = {
            "entry_id": local_lineage.entry_id,
            "service": local_lineage.service,
            "account": local_lineage.account,
            "name": local_lineage.name,
            "generation": local_lineage.generation,
            "tombstone_generation": local_lineage.tombstone_generation,
            "deleted": local_lineage.deleted,
        }

    ctx: Dict[str, Any] = {
        "local_host_id": local_host_id,
        "incoming_origin_host": incoming_origin,
        "resolved_by_entry_id": resolved_by_eid is not None,
        "registry_key_candidate": reg_key_cand,
        "registry_key_store": reg_key_store,
        "local_secret_present": local_val is not None,
        "local_metadata_present": local_meta is not None,
        "sqlite_lineage_merge_flag": sqlite_merge,
        "local_lineage_snapshot": lineage_dict,
        "incoming": {
            "disposition": cand.disposition,
            "generation": cand.generation,
            "tombstone_generation": cand.tombstone_generation,
            "content_hash_preview": hash_preview(
                (cand.content_hash or cand.metadata.content_hash or "")
            ),
            "locator": {
                "service": cand.metadata.service,
                "account": cand.metadata.account,
                "name": cand.metadata.name,
            },
        },
    }
    return explain, ctx
