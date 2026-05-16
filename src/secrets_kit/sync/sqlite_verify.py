"""
secrets_kit.sync.sqlite_verify

Read-only SQLite reconcile invariant checks (report-only; no repair).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any


def sqlite_reconcile_verify(
    *,
    db_path: str,
    strict_content_hash: bool = False,
) -> dict[str, Any]:
    """Run PRAGMA checks and lineage-shaped row invariants. Does not mutate the database.

    Args:
        db_path: Path to the SQLite database.
        strict_content_hash: When ``True``, report non-deleted rows with empty ``content_hash`` (informational).

    Returns:
        Dictionary with ``ok`` (bool), ``issues`` (list of dicts with stable ``code`` keys),
        and ``pragma`` summaries.
    """
    issues: list[dict[str, Any]] = []
    pragma: dict[str, Any] = {}
    expanded = os.path.expanduser(db_path)
    ro_path = Path(expanded).resolve()
    if not ro_path.is_file():
        return {
            "ok": False,
            "issues": [{"code": "missing_db_file", "detail": str(ro_path)}],
            "pragma": {},
        }
    uri = ro_path.as_uri()
    if uri.startswith("file:///"):
        # sqlite3.connect(uri=...) expects file: path form
        pass
    try:
        conn = sqlite3.connect(f"{uri}?mode=ro", uri=True, timeout=30.0)
    except sqlite3.Error as exc:
        return {"ok": False, "issues": [{"code": "open_failed", "detail": str(exc)}], "pragma": {}}
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        ic = str(row[0]) if row else ""
        pragma["integrity_check"] = ic
        if ic.lower() != "ok":
            issues.append({"code": "integrity_check_failed", "detail": ic})

        fk_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
        pragma["foreign_key_check_count"] = len(fk_rows)
        if fk_rows:
            issues.append(
                {
                    "code": "foreign_key_violation",
                    "detail": "foreign_key_check returned rows",
                    "count": len(fk_rows),
                }
            )

        cur = conn.execute(
            """
            SELECT entry_id, service, account, name, deleted, generation, tombstone_generation, content_hash
            FROM secrets
            """
        )
        for r in cur.fetchall():
            eid = str(r[0])
            deleted = int(r[4])
            gen = int(r[5])
            tgen = int(r[6])
            ch_raw = r[7]
            ch = str(ch_raw).strip() if ch_raw is not None else ""
            if gen < 1:
                issues.append(
                    {
                        "code": "lineage_generation_invalid",
                        "entry_id": eid,
                        "generation": gen,
                    }
                )
            if tgen < 0:
                issues.append(
                    {
                        "code": "lineage_tombstone_generation_invalid",
                        "entry_id": eid,
                        "tombstone_generation": tgen,
                    }
                )
            if deleted and tgen < 1:
                issues.append(
                    {
                        "code": "lineage_deleted_without_tombstone_generation",
                        "entry_id": eid,
                        "tombstone_generation": tgen,
                    }
                )
            if strict_content_hash and not deleted and not ch:
                issues.append(
                    {
                        "code": "content_hash_empty_on_active",
                        "entry_id": eid,
                        "service": str(r[1]),
                        "account": str(r[2]),
                        "name": str(r[3]),
                    }
                )

        dup_rows = conn.execute(
            """
            SELECT service, account, name, COUNT(*) AS n
            FROM secrets
            GROUP BY service, account, name
            HAVING COUNT(*) > 1
            """
        ).fetchall()
        for row in dup_rows:
            issues.append(
                {
                    "code": "secrets_row_locator_collision",
                    "service": str(row[0]),
                    "account": str(row[1]),
                    "name": str(row[2]),
                    "count": int(row[3]),
                }
            )
    finally:
        conn.close()

    return {"ok": len(issues) == 0, "issues": issues, "pragma": pragma}
