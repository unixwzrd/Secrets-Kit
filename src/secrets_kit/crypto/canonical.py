"""
secrets_kit.crypto.canonical

Deterministic JSON serialization helpers for future signing and hashing boundaries.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json_text(obj: Any) -> str:
    """Return deterministic canonical JSON text for ``obj``."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_json_bytes(obj: Any) -> bytes:
    """Return deterministic UTF-8 canonical JSON bytes for ``obj``."""
    return canonical_json_text(obj).encode("utf-8")


__all__ = ["canonical_json_bytes", "canonical_json_text"]
