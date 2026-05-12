"""Semi-stable reconciliation reason identifiers (operational compatibility surface).

Human-readable descriptions may change; these string values should remain stable
across releases unless explicitly deprecated. Document additions in PHASE6A_RECONCILIATION.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional


class ReconcileReason:
    """Stable reason code constants (use string values in JSON traces)."""

    # Identity / hash verification (pre-merge or equal-gen)
    ENTRY_ID_MISMATCH = "entry_id_mismatch"
    CONTENT_HASH_MISMATCH = "content_hash_mismatch"
    CONTENT_HASH_MISMATCH_EQUAL_GEN = "content_hash_mismatch_equal_gen"

    # Legacy timestamp ladder (no lineage on incoming row)
    LEGACY_IMPORT = "legacy_import"
    LEGACY_SKIP = "legacy_skip"
    LEGACY_UNCHANGED = "legacy_unchanged"
    LEGACY_CONFLICT = "legacy_conflict"

    # Tombstone incoming
    TOMBSTONE_NO_LOCAL_ROW = "tombstone_no_local_row"
    TOMBSTONE_SKIP_STALE_VS_TOMBSTONE = "tombstone_skip_stale_vs_tombstone"
    TOMBSTONE_UNCHANGED_EQUAL = "tombstone_unchanged_equal"
    TOMBSTONE_BUMP_NEWER = "tombstone_bump_newer"
    TOMBSTONE_WINS_ACTIVE = "tombstone_wins"
    TOMBSTONE_SKIP_STALE_VS_ACTIVE = "tombstone_skip_stale_vs_active"

    # Active incoming (lineage mode)
    ACTIVE_SKIP_MISSING_GENERATION = "active_skip_missing_generation"
    ACTIVE_IMPORT_NO_LOCAL_LINEAGE = "active_import_no_local_lineage"
    LOCAL_DELETED_REPLAY_SUPPRESSED = "local_deleted_replay_suppressed"
    STALE_GENERATION = "stale_generation"
    NEWER_GENERATION_IMPORT = "newer_generation_import"
    EQUAL_GEN_SAME_VALUE = "equal_generation_same_value"
    EQUAL_GEN_VALUE_CONFLICT = "equal_generation_value_conflict"


MergeAction = Literal["import", "skip", "unchanged", "conflict", "replay_suppressed"]


@dataclass
class MergeExplain:
    """Pure classification result: decision + stable reason + lineage fields (no secrets)."""

    decision: MergeAction
    reason: str
    sqlite_lineage_merge: bool
    incoming_disposition: Literal["active", "tombstone"]
    local_deleted: Optional[bool] = None
    local_generation: Optional[int] = None
    local_tombstone_generation: Optional[int] = None
    incoming_generation: Optional[int] = None
    incoming_tombstone_generation: Optional[int] = None
    local_content_hash_preview: Optional[str] = None
    incoming_content_hash_preview: Optional[str] = None
    use_lineage_ladder: bool = False

    def to_trace_dict(
        self,
        *,
        entry_id: str,
        service: str,
        account: str,
        name: str,
    ) -> Dict[str, Any]:
        """Secret-safe trace row for CLI / tests."""
        d: Dict[str, Any] = {
            "entry_id": entry_id,
            "service": service,
            "account": account,
            "name": name,
            "decision": self.decision,
            "reason": self.reason,
            "sqlite_lineage_merge": self.sqlite_lineage_merge,
            "use_lineage_ladder": self.use_lineage_ladder,
            "incoming_disposition": self.incoming_disposition,
        }
        if self.local_deleted is not None:
            d["local_deleted"] = self.local_deleted
        if self.local_generation is not None:
            d["local_generation"] = self.local_generation
        if self.local_tombstone_generation is not None:
            d["local_tombstone_generation"] = self.local_tombstone_generation
        if self.incoming_generation is not None:
            d["incoming_generation"] = self.incoming_generation
        if self.incoming_tombstone_generation is not None:
            d["incoming_tombstone_generation"] = self.incoming_tombstone_generation
        if self.local_content_hash_preview:
            d["local_content_hash"] = self.local_content_hash_preview
        if self.incoming_content_hash_preview:
            d["incoming_content_hash"] = self.incoming_content_hash_preview
        return d


def hash_preview(h: str) -> Optional[str]:
    """Short non-secret prefix for trace (full hash may be long)."""
    s = (h or "").strip().lower()
    if not s:
        return None
    return s[:16] + "…" if len(s) > 16 else s
