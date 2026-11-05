"""
secrets_kit.crypto.cli.export_json

Password-protected encrypted JSON for cross-host backup export/import.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict

from secrets_kit.crypto.errors import CryptoUnavailable

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
DEFAULT_MAX_ENCRYPTED_BACKUP_BYTES = 128 * 1024 * 1024


@dataclass
class EncryptedPayload:
    """Structured encrypted export backup container."""

    format: str
    version: int
    kdf: Dict[str, Any]
    cipher: str
    data: str


def _require_crypto() -> None:
    try:
        from cryptography.fernet import Fernet  # noqa: F401
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: F401
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional extra
        raise CryptoUnavailable(
            "cryptography is required for encrypted export/import. "
            "Install with: pip install seckit[crypto]"
        ) from exc


def ensure_crypto_available() -> None:
    """Verify optional cryptography dependencies are importable."""
    _require_crypto()


def _derive_key(*, password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    _require_crypto()
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(*, payload: Dict[str, Any], password: str) -> EncryptedPayload:
    """Encrypt a JSON export payload using a password-derived key."""
    _require_crypto()
    from cryptography.fernet import Fernet

    salt = os.urandom(SCRYPT_SALT_BYTES)
    kdf_params = {
        "name": "scrypt",
        "salt": base64.b64encode(salt).decode("utf-8"),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }
    key = _derive_key(
        password=password, salt=salt, n=kdf_params["n"], r=kdf_params["r"], p=kdf_params["p"]
    )
    token = Fernet(base64.urlsafe_b64encode(key)).encrypt(json.dumps(payload).encode("utf-8"))
    return EncryptedPayload(
        format="seckit.encrypted_json",
        version=1,
        kdf=kdf_params,
        cipher="fernet",
        data=token.decode("utf-8"),
    )


def decrypt_payload(*, payload: Dict[str, Any], password: str) -> Dict[str, Any]:
    """Decrypt a JSON export backup using a password-derived key."""
    if not isinstance(payload, dict):
        raise ValueError("encrypted backup must be a JSON object")
    if payload.get("format") != "seckit.encrypted_json":
        raise ValueError("unsupported encrypted payload format")
    if type(payload.get("version")) is not int or payload["version"] != 1:
        raise ValueError("unsupported encrypted backup version")
    if payload.get("cipher") != "fernet":
        raise ValueError("unsupported encrypted backup cipher")
    kdf = payload.get("kdf")
    if not isinstance(kdf, dict):
        raise ValueError("encrypted backup kdf must be an object")
    if kdf.get("name") != "scrypt":
        raise ValueError("unsupported kdf")
    salt_b64 = kdf.get("salt")
    if not isinstance(salt_b64, str):
        raise ValueError("invalid kdf salt")
    try:
        salt = base64.b64decode(salt_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid kdf salt") from exc
    if len(salt) != SCRYPT_SALT_BYTES:
        raise ValueError("invalid kdf salt length")
    if any(
        type(kdf.get(name)) is not int or kdf[name] != expected
        for name, expected in (("n", SCRYPT_N), ("r", SCRYPT_R), ("p", SCRYPT_P))
    ):
        raise ValueError("unsupported scrypt work factors")
    token = payload.get("data")
    if not isinstance(token, str) or not token:
        raise ValueError("invalid encrypted backup data")
    try:
        token_bytes = token.encode("ascii")
        decoded_token = base64.b64decode(token_bytes, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise ValueError("invalid encrypted backup data") from exc
    if len(decoded_token) < 73 or decoded_token[0] != 0x80:
        raise ValueError("invalid encrypted backup data")
    _require_crypto()
    from cryptography.fernet import Fernet

    key = _derive_key(
        password=password,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    plaintext = Fernet(base64.urlsafe_b64encode(key)).decrypt(token_bytes)
    try:
        decoded = json.loads(plaintext.decode("utf-8"))
    except RecursionError:
        raise ValueError("decrypted backup nesting is too deep") from None
    if not isinstance(decoded, dict):
        raise ValueError("decrypted backup must be a JSON object")
    return decoded


def build_plain_export(*, entries: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the plaintext JSON envelope encrypted by :func:`encrypt_payload`."""
    return {
        "format": "seckit.export",
        "version": 1,
        "created_at": datetime.now(tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "entries": entries,
    }


__all__ = [
    "EncryptedPayload",
    "build_plain_export",
    "decrypt_payload",
    "encrypt_payload",
    "ensure_crypto_available",
]
