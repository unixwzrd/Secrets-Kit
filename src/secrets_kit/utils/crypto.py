"""
secrets_kit.utils.crypto

Encrypted export/import helpers.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict


class CryptoUnavailable(RuntimeError):
    """Raised when cryptography dependencies are missing."""


@dataclass
class EncryptedPayload:
    """Structured encrypted payload container."""

    format: str
    version: int
    kdf: Dict[str, Any]
    cipher: str
    data: str


def _require_crypto():
    """Import cryptography modules; raise ``CryptoUnavailable`` when missing."""
    try:
        from cryptography.fernet import Fernet  # noqa: F401
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: F401
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional extra
        raise CryptoUnavailable(
            "cryptography is required for encrypted export/import. "
            "Install with: pip install seckit[crypto]"
        ) from exc


def ensure_crypto_available() -> None:
    """Public guard for optional crypto support."""
    _require_crypto()


def _derive_key(*, password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Derive a 32-byte key from password + salt using Scrypt KDF."""
    _require_crypto()
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(*, payload: Dict[str, Any], password: str) -> EncryptedPayload:
    """Encrypt a JSON payload using password-derived key."""
    _require_crypto()
    from cryptography.fernet import Fernet

    salt = os.urandom(16)
    kdf_params = {"name": "scrypt", "salt": base64.b64encode(salt).decode("utf-8"), "n": 2**14, "r": 8, "p": 1}
    key = _derive_key(password=password, salt=salt, n=kdf_params["n"], r=kdf_params["r"], p=kdf_params["p"])
    token = Fernet(base64.urlsafe_b64encode(key)).encrypt(json.dumps(payload).encode("utf-8"))
    return EncryptedPayload(
        format="seckit.encrypted_json",
        version=1,
        kdf=kdf_params,
        cipher="fernet",
        data=token.decode("utf-8"),
    )


def decrypt_payload(*, payload: Dict[str, Any], password: str) -> Dict[str, Any]:
    """Decrypt a JSON payload using password-derived key."""
    _require_crypto()
    from cryptography.fernet import Fernet

    if payload.get("format") != "seckit.encrypted_json":
        raise ValueError("unsupported encrypted payload format")
    kdf = payload.get("kdf", {})
    if kdf.get("name") != "scrypt":
        raise ValueError("unsupported kdf")
    salt_b64 = kdf.get("salt")
    if not salt_b64:
        raise ValueError("missing kdf salt")
    salt = base64.b64decode(salt_b64)
    key = _derive_key(password=password, salt=salt, n=int(kdf.get("n", 2**14)), r=int(kdf.get("r", 8)), p=int(kdf.get("p", 1)))
    token = payload.get("data", "")
    plaintext = Fernet(base64.urlsafe_b64encode(key)).decrypt(token.encode("utf-8"))
    return json.loads(plaintext.decode("utf-8"))


def build_plain_export(*, entries: list[dict[str, str]], version: str = "1") -> dict[str, Any]:
    """Build plain JSON payload for encryption."""
    return {
        "format": "seckit.export",
        "version": 1,
        "created_at": datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
