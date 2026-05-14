"""
secrets_kit.backends.keychain

macOS Keychain (``security`` CLI) backend and inventory helpers for recover flows.
"""

from __future__ import annotations

from secrets_kit.backends.keychain.backend import KeychainBackendStore
from secrets_kit.backends.keychain.inventory import (
    GenpCandidate,
    dump_keychain_text,
    iter_seckit_genp_candidates,
)

__all__ = [
    "GenpCandidate",
    "KeychainBackendStore",
    "dump_keychain_text",
    "iter_seckit_genp_candidates",
]
