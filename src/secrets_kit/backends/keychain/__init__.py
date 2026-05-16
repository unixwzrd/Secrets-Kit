"""
secrets_kit.backends.keychain

macOS Keychain (``security`` CLI) backend and inventory helpers for recover flows.
"""

from __future__ import annotations

from secrets_kit.backends.keychain.security_cli import (
    check_security_cli,
    create_keychain,
    delete_keychain,
    harden_keychain,
    keychain_accessible,
    keychain_info,
    keychain_path,
    keychain_policy,
    lock_keychain,
    make_temp_keychain,
    unlock_keychain,
    unlock_keychain_with_password,
)
from secrets_kit.backends.keychain.store import KeychainBackendStore
from secrets_kit.backends.keychain.inventory import (
    GenpCandidate,
    dump_keychain_text,
    iter_seckit_genp_candidates,
)

__all__ = [
    "GenpCandidate",
    "KeychainBackendStore",
    "check_security_cli",
    "create_keychain",
    "delete_keychain",
    "dump_keychain_text",
    "harden_keychain",
    "iter_seckit_genp_candidates",
    "keychain_accessible",
    "keychain_info",
    "keychain_path",
    "keychain_policy",
    "lock_keychain",
    "make_temp_keychain",
    "unlock_keychain",
    "unlock_keychain_with_password",
]
