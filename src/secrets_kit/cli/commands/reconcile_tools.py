"""
secrets_kit.cli.commands.reconcile_tools

Read-only reconciliation diagnostics (inspect / explain / verify).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from secrets_kit.backends.security import BACKEND_SQLITE, is_sqlite_backend
from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.args import _backend_access_kwargs
from secrets_kit.cli.support.interaction import _fatal
from secrets_kit.models.core import EntryMetadata
from secrets_kit.sync.merge import explain_incoming_sync_row
from secrets_kit.sync.sqlite_verify import sqlite_reconcile_verify

if TYPE_CHECKING:
    from secrets_kit.backends.sqlite import SqliteSecretStore


def _open_sqlite_store_for_reconcile(args: argparse.Namespace) -> "SqliteSecretStore" | int:
    from secrets_kit.backends.sqlite import SqliteSecretStore

    kwargs = _backend_access_kwargs(args)
    if not is_sqlite_backend(kwargs["backend"]):
        return _fatal(message="reconcile commands require --backend sqlite", code=EXIT_CODES["EINVAL"])
    p = kwargs["path"]
    if not p:
        return _fatal(message="reconcile requires SQLite db path (--db or SECKIT_SQLITE_DB)", code=EXIT_CODES["EINVAL"])
    return SqliteSecretStore(db_path=str(p), kek_keychain_path=kwargs["kek_keychain_path"])


def cmd_reconcile_inspect(*, args: argparse.Namespace) -> int:
    st = _open_sqlite_store_for_reconcile(args)
    if isinstance(st, int):
        return st
    row = st.fetch_entry_reconcile_index(entry_id=args.entry_id)
    caps = st.capabilities()
    out: dict[str, object] = {
        "backend": BACKEND_SQLITE,
        "capabilities": {
            "supports_peer_lineage_merge": caps.supports_peer_lineage_merge,
            "supports_reconcile_transaction": caps.supports_reconcile_transaction,
        },
        "sqlite_index_row": row,
        "notes": [
            "Keychain and non-SQLite backends do not carry durable Phase 6A lineage columns; "
            "peer merge authority for generation/tombstone ordering is SQLite-first.",
        ],
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_reconcile_lineage(*, args: argparse.Namespace) -> int:
    st = _open_sqlite_store_for_reconcile(args)
    if isinstance(st, int):
        return st
    row = st.fetch_entry_reconcile_index(entry_id=args.entry_id)
    if row is None:
        print(json.dumps({"entry_id": args.entry_id, "lineage": None}, indent=2, sort_keys=True))
        return EXIT_CODES["ENOENT"]
    lineage = {
        "entry_id": row["entry_id"],
        "service": row["service"],
        "account": row["account"],
        "name": row["name"],
        "generation": row["generation"],
        "tombstone_generation": row["tombstone_generation"],
        "deleted": row["deleted"],
        "deleted_at": row["deleted_at"],
        "updated_at": row["updated_at"],
        "origin_host": row["origin_host"],
        "content_hash": row["content_hash"],
        "corrupt": row["corrupt"],
        "corrupt_reason": row["corrupt_reason"],
    }
    print(json.dumps({"entry_id": args.entry_id, "lineage": lineage}, indent=2, sort_keys=True))
    return 0


def cmd_reconcile_explain(*, args: argparse.Namespace) -> int:
    src = getattr(args, "bundle_row", None)
    if src in (None, "-"):
        text = sys.stdin.read()
    else:
        text = Path(str(src)).expanduser().read_text(encoding="utf-8")
    raw = json.loads(text)
    if not isinstance(raw, dict):
        return _fatal(message="bundle row must be a JSON object", code=EXIT_CODES["EINVAL"])
    kwargs = _backend_access_kwargs(args)
    if not is_sqlite_backend(kwargs["backend"]):
        return _fatal(
            message="reconcile explain requires --backend sqlite for lineage-aware classification",
            code=EXIT_CODES["EINVAL"],
        )
    explain, ctx = explain_incoming_sync_row(
        raw_row=raw,
        local_host_id=args.local_host_id,
        path=kwargs["path"],
        backend=kwargs["backend"],
        kek_keychain_path=kwargs["kek_keychain_path"],
        home=None,
    )
    meta_raw = raw.get("metadata")
    if isinstance(meta_raw, dict):
        meta = EntryMetadata.from_dict(meta_raw)
        eid = (meta.entry_id or "").strip()
        svc, acct, nm = meta.service, meta.account, meta.name
    else:
        eid, svc, acct, nm = "", "", "", ""
    trace = explain.to_trace_dict(entry_id=eid, service=svc, account=acct, name=nm)
    out = {"classification": trace, "context": ctx}
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_reconcile_verify(*, args: argparse.Namespace) -> int:
    kwargs = _backend_access_kwargs(args)
    if not is_sqlite_backend(kwargs["backend"]):
        return _fatal(message="reconcile verify requires --backend sqlite", code=EXIT_CODES["EINVAL"])
    p = kwargs["path"]
    if not p:
        return _fatal(message="reconcile verify requires SQLite db path", code=EXIT_CODES["EINVAL"])
    report = sqlite_reconcile_verify(
        db_path=str(p),
        strict_content_hash=bool(getattr(args, "strict_content_hash", False)),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else EXIT_CODES["EIO"]
