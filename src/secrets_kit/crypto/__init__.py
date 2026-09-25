"""Public crypto helper exports."""

from __future__ import annotations

from secrets_kit.crypto.codecs import (
    CryptoHeader,
    EncryptedBlob,
    decode_b64url,
    decode_encrypted_blob,
    encode_b64url,
    encode_encrypted_blob,
)
from secrets_kit.crypto.encryption import decrypt_aead, encrypt_aead
from secrets_kit.crypto.errors import CryptoUnavailable
from secrets_kit.crypto.hashing import hmac_sha256, sha256_bytes, sha256_hex
from secrets_kit.crypto.indexes import blind_index, blind_index_hex
from secrets_kit.crypto.keyring import InMemoryKeyring
from secrets_kit.crypto.keys import (
    derive_hkdf_sha256,
    derive_x25519_shared_key,
    generate_symmetric_key,
    generate_x25519_keypair,
)
from secrets_kit.crypto.keystore import InMemoryKeyStore, KeyStore
from secrets_kit.crypto.models import (
    EncryptionKeypair,
    KeyMetadata,
    NodeIdentity,
    SigningKeypair,
)
from secrets_kit.crypto.random import random_bytes
from secrets_kit.crypto.records import (
    CiphertextRecord,
    SignatureRecord,
    WrappedKeyRecord,
)
from secrets_kit.crypto.signatures import (
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
)
from secrets_kit.crypto.transaction_signing import (
    TransactionSignature,
    sign_payload,
    sign_payload_with_keyring,
    verify_payload,
)

__all__ = [
    "CiphertextRecord",
    "CryptoHeader",
    "CryptoUnavailable",
    "EncryptionKeypair",
    "EncryptedBlob",
    "InMemoryKeyStore",
    "InMemoryKeyring",
    "KeyMetadata",
    "KeyStore",
    "NodeIdentity",
    "SignatureRecord",
    "SigningKeypair",
    "TransactionSignature",
    "WrappedKeyRecord",
    "blind_index",
    "blind_index_hex",
    "decode_b64url",
    "decode_encrypted_blob",
    "decrypt_aead",
    "derive_hkdf_sha256",
    "derive_x25519_shared_key",
    "encode_b64url",
    "encode_encrypted_blob",
    "encrypt_aead",
    "generate_ed25519_keypair",
    "generate_symmetric_key",
    "generate_x25519_keypair",
    "hmac_sha256",
    "random_bytes",
    "sha256_bytes",
    "sha256_hex",
    "sign_payload",
    "sign_payload_with_keyring",
    "sign_ed25519",
    "verify_ed25519",
    "verify_payload",
]
