#!/usr/bin/env python3
"""Offline replay helper: apply bundle entries via ``apply_peer_sync_import`` only.

Usage (from repo root)::

    PYTHONPATH=src ./scripts/replay_import_sequence.py \\
      --db /path/v.db --home /path/h \\
      --entries-json /path/entries.json \\
      --local-host replay-local --backend sqlite

``entries.json`` may be either:

- A JSON object with ``inner_entries`` (list of dicts) and optional ``local_host_id``,
  ``dry_run``, ``domain_filter``; or
- A JSON array (treated as ``inner_entries``).

``SECKIT_SQLITE_PASSPHRASE`` must be set when using the sqlite backend.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", required=True, help="SQLite vault path")
    p.add_argument("--home", required=True, help="Seckit home (registry tree)")
    p.add_argument("--entries-json", required=True, help="JSON file: object with inner_entries or array of rows")
    p.add_argument("--local-host", default=None, help="Local host id (overrides file if set)")
    p.add_argument("--backend", default="sqlite", help="Backend name (default sqlite)")
    p.add_argument("--dry-run", action="store_true", help="Pass dry_run=True into apply")
    p.add_argument("--repeat", type=int, default=1, help="Apply the same batch N times (default 1)")
    p.add_argument("--print-trace", action="store_true", help="Print secret-safe trace JSON to stdout")
    return p.parse_args()


def _load_batch(path: Path) -> Tuple[List[Dict[str, object]], Optional[str], bool, Optional[List[str]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        inner = cast(List[Dict[str, object]], raw)
        return inner, None, False, None
    if isinstance(raw, dict):
        obj = cast(Dict[str, Any], raw)
        inn = obj.get("inner_entries")
        if not isinstance(inn, list):
            raise SystemExit("entries JSON object must contain inner_entries array")
        inner = cast(List[Dict[str, object]], inn)
        local = obj.get("local_host_id")
        lh = str(local) if isinstance(local, str) and local.strip() else None
        dry = bool(obj.get("dry_run", False))
        df = obj.get("domain_filter")
        domain: Optional[List[str]] = None
        if isinstance(df, list) and all(isinstance(x, str) for x in df):
            domain = cast(List[str], df)
        return inner, lh, dry, domain
    raise SystemExit("entries JSON must be an array or object")


def main() -> None:
    args = _parse_args()
    home = Path(args.home).expanduser().resolve()
    db = str(Path(args.db).expanduser().resolve())
    inner, file_lh, file_dry, domain = _load_batch(Path(args.entries_json).expanduser().resolve())
    local_host = args.local_host if args.local_host else file_lh
    if not local_host or not str(local_host).strip():
        raise SystemExit("local host id required (--local-host or local_host_id in JSON)")
    dry_run = bool(args.dry_run or file_dry)
    repo_root = Path(__file__).resolve().parent.parent
    src = repo_root / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))

    from secrets_kit.sync.merge import apply_peer_sync_import

    repeat = max(1, int(args.repeat))
    for i in range(repeat):
        trace: List[Dict[str, Any]] = []
        stats = apply_peer_sync_import(
            inner_entries=inner,
            local_host_id=str(local_host).strip(),
            dry_run=dry_run,
            path=db,
            backend=str(args.backend),
            kek_keychain_path=None,
            domain_filter=domain,
            home=home,
            trace_out=trace,
        )
        out: Dict[str, Any] = {"pass": i + 1, "stats": stats}
        if args.print_trace:
            out["trace"] = trace
        print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
