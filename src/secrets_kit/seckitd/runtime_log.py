"""
secrets_kit.seckitd.runtime_log

Structured stderr logs for seckitd (redaction-safe: never pass payload or secrets).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping

_FORBIDDEN_KEYS = frozenset(
    {
        "payload_b64",
        "payload_text",
        "secret",
        "password",
        "stdout_tail",
        "stderr_tail",
    }
)


def runtime_log(*, category: str, event: str, **fields: Any) -> None:
    """Emit one JSON line to stderr. Callers must not pass sensitive keys."""
    for k in fields:
        if k in _FORBIDDEN_KEYS:
            raise ValueError(f"refusing to log forbidden key: {k!r}")
    line = json.dumps(
        {"category": category, "event": event, **fields},
        sort_keys=True,
        default=str,
    )
    print(line, file=sys.stderr, flush=True)


def runtime_log_mapping(*, category: str, event: str, fields: Mapping[str, Any]) -> None:
    runtime_log(category=category, event=event, **dict(fields))
