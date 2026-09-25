"""
tests.security.test_envelope_payload_encryption

Security regressions for encrypted envelope payloads.
"""

from __future__ import annotations

import base64
import json
import os
import unittest
from unittest import mock

from tests.canonical_id_helpers import tid

from secrets_kit.backends.sqlite.transactions import create_transaction
from secrets_kit.crypto.codecs import encode_b64url
from secrets_kit.crypto.keys import generate_x25519_keypair
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV
from secrets_kit.protocol.envelope import build_transaction_envelope, canonical_envelope_dict
from secrets_kit.protocol.payload_codec import (
    EnvelopePayloadCodecError,
    EnvelopePayloadContext,
    encoded_payload_bytes,
    encrypted_envelope_payload_codec,
)

SOURCE_NODE_ID = tid("node", "security-envelope-source")
DESTINATION_NODE_ID = tid("node", "security-envelope-destination")
TRANSACTION_ID = tid("transaction", "security-envelope-transaction")
RECIPIENT_PRIVATE_KEY, RECIPIENT_PUBLIC_KEY = generate_x25519_keypair()
OTHER_PRIVATE_KEY, OTHER_PUBLIC_KEY = generate_x25519_keypair()


def _context() -> EnvelopePayloadContext:
    return EnvelopePayloadContext(
        envelope_id=tid("envelope", "security-envelope"),
        source_node_id=SOURCE_NODE_ID,
        destination_node_id=DESTINATION_NODE_ID,
        transaction_id=TRANSACTION_ID,
        envelope_version=1,
        protocol_version=1,
    )


def _transaction():
    return create_transaction(
        transaction_id=TRANSACTION_ID,
        transaction_type="vocabulary.tag.upsert",
        origin_node_id=SOURCE_NODE_ID,
        created_at="2026-07-13T00:00:00Z",
        payload={
            "tag_id": "security-envelope-tag",
            "name": "private-envelope-marker",
        },
    )


class EnvelopePayloadEncryptionSecurityTest(unittest.TestCase):
    def test_private_key_material_is_not_serialized_in_encrypted_envelope(self) -> None:
        envelope = build_transaction_envelope(
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            payload_codec=encrypted_envelope_payload_codec(
                recipient_node_id=DESTINATION_NODE_ID,
                recipient_public_key=RECIPIENT_PUBLIC_KEY,
            ),
        )
        serialized = json.dumps(canonical_envelope_dict(envelope=envelope), sort_keys=True)
        private_fragments = [
            RECIPIENT_PRIVATE_KEY.hex(),
            OTHER_PRIVATE_KEY.hex(),
            encode_b64url(RECIPIENT_PRIVATE_KEY),
            encode_b64url(OTHER_PRIVATE_KEY),
        ]
        for fragment in private_fragments:
            self.assertNotIn(fragment, serialized)

    def test_wrong_recipient_cannot_decrypt_payload(self) -> None:
        context = _context()
        record = encrypted_envelope_payload_codec(
            context=context,
            recipient_node_id=DESTINATION_NODE_ID,
            recipient_public_key=RECIPIENT_PUBLIC_KEY,
        ).encode(canonical_payload_bytes=b'{"secret":true}')

        with self.assertRaisesRegex(EnvelopePayloadCodecError, "recipient key fingerprint mismatch"):
            encrypted_envelope_payload_codec(
                context=context,
                local_private_key=OTHER_PRIVATE_KEY,
                local_public_key=OTHER_PUBLIC_KEY,
                encryption_metadata=record.encryption_metadata,
            ).decode(payload=record.payload)

    def test_tampered_ciphertext_is_rejected(self) -> None:
        context = _context()
        record = encrypted_envelope_payload_codec(
            context=context,
            recipient_node_id=DESTINATION_NODE_ID,
            recipient_public_key=RECIPIENT_PUBLIC_KEY,
        ).encode(canonical_payload_bytes=b'{"secret":true}')
        ciphertext = bytearray(encoded_payload_bytes(payload=record.payload))
        ciphertext[-1] ^= 1
        tampered_payload = dict(record.payload)
        tampered_payload["data_b64"] = (
            base64.urlsafe_b64encode(bytes(ciphertext)).decode("ascii").rstrip("=")
        )

        with self.assertRaisesRegex(EnvelopePayloadCodecError, "authentication failed"):
            encrypted_envelope_payload_codec(
                context=context,
                local_private_key=RECIPIENT_PRIVATE_KEY,
                local_public_key=RECIPIENT_PUBLIC_KEY,
                encryption_metadata=record.encryption_metadata,
            ).decode(payload=tampered_payload)

    def test_sqlite_storage_key_is_not_used_as_envelope_key(self) -> None:
        context = _context()
        with mock.patch.dict(os.environ, {SQLITE_STORAGE_KEY_ENV: "/missing/key"}, clear=False):
            record = encrypted_envelope_payload_codec(
                context=context,
                recipient_node_id=DESTINATION_NODE_ID,
                recipient_public_key=RECIPIENT_PUBLIC_KEY,
            ).encode(canonical_payload_bytes=b'{"secret":true}')
            decoded = encrypted_envelope_payload_codec(
                context=context,
                local_private_key=RECIPIENT_PRIVATE_KEY,
                local_public_key=RECIPIENT_PUBLIC_KEY,
                encryption_metadata=record.encryption_metadata,
            ).decode(payload=record.payload)

        self.assertEqual(decoded, b'{"secret":true}')


if __name__ == "__main__":
    unittest.main()
