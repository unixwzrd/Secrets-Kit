"""
secrets_kit.backends.keychain

Public exports for the macOS Keychain backend.
"""

from __future__ import annotations

from secrets_kit.backends.base import SecretStore
from secrets_kit.backends.common import BackendError
from secrets_kit.backends.keychain.security_cli import (
    DEFAULT_KEYCHAIN_PATH,
    SecurityCliStore,
    backend_service_name,
    check_security_cli,
    create_keychain,
    delete_keychain,
    delete_secret,
    doctor_roundtrip,
    get_secret,
    get_secret_metadata,
    harden_keychain,
    keychain_accessible,
    keychain_info,
    keychain_path,
    keychain_policy,
    lock_keychain,
    make_temp_keychain,
    resolve_secret_store,
    secret_exists,
    set_secret,
    unlock_keychain,
    unlock_keychain_with_password,
)

__all__ = [
    "BackendError",
    "DEFAULT_KEYCHAIN_PATH",
    "SecretStore",
    "SecurityCliStore",
    "backend_service_name",
    "check_security_cli",
    "create_keychain",
    "delete_keychain",
    "delete_secret",
    "doctor_roundtrip",
    "get_secret",
    "get_secret_metadata",
    "harden_keychain",
    "keychain_accessible",
    "keychain_info",
    "keychain_path",
    "keychain_policy",
    "lock_keychain",
    "make_temp_keychain",
    "resolve_secret_store",
    "secret_exists",
    "set_secret",
    "unlock_keychain",
    "unlock_keychain_with_password",
]
