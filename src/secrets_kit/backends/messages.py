"""Operator-facing backend messages (no imports from ``cli``)."""

from __future__ import annotations

BACKEND_NORMALIZE_HINT = (
    "Supported values: --backend secure or local (macOS Keychain via /usr/bin/security), "
    "or --backend sqlite. Fix ~/.config/seckit/defaults.json and unset SECKIT_DEFAULT_BACKEND "
    "if it still holds an invalid value."
)
