"""Optional append-only operator log adjacent to ``registry.json``.

The journal is **operational convenience only** and **must never be treated as authoritative state**
(authority lives in :class:`~secrets_kit.backends.base.BackendStore`; ``registry.json`` is a slim index).

Events are JSON lines written to ``registry_events.jsonl``. Sync and merge stay on the
:class:`~secrets_kit.backends.base.BackendStore` protocol; this file is for audit and future
registry v2 journaling without changing secret storage layouts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from secrets_kit.registry.core import registry_dir


def journal_path(*, home: Optional[Path] = None) -> Path:
    """Path to the JSONL journal file."""
    return registry_dir(home=home) / "registry_events.jsonl"


def append_journal_event(*, home: Optional[Path] = None, event: Dict[str, Any]) -> Path:
    """Append one JSON object as a line; create parent dir with 0700. Returns the file path."""
    path = journal_path(home=home)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    line = json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
    return path
