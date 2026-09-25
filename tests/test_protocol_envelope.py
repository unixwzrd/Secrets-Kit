from __future__ import annotations

import base64
import json
import os
import unittest
from unittest import mock

from secrets_kit.backends.sqlite.transactions import create_transaction
from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.keys import generate_x25519_keypair
from secrets_kit.crypto.signatures import generate_ed25519_keypair
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV
from secrets_kit.protocol.envelope import (
    CANONICAL_ENVELOPE_VERSION,
    EnvelopeValidationError,
    build_transaction_envelope,
    canonical_envelope_bytes,
    canonical_envelope_dict,
    parse_envelope_bytes,
    parse_envelope_mapping,
    payload_commitment,
)
from secrets_kit.protocol.envelope_signing import (
    EnvelopeSignatureError,
    envelope_signing_bytes,
    sign_envelope,
    verify_envelope_signature,
)
from secrets_kit.protocol.payload_codec import (
    ENCRYPTED_CODEC_ALGORITHM,
    ENCRYPTED_CODEC_MODE,
    EnvelopePayloadCodecError,
    EnvelopePayloadContext,
    decode_envelope_payload,
    encoded_payload_bytes,
    encrypted_envelope_payload_codec,
    plaintext_envelope_payload_codec,
    validate_payload_codec_metadata,
)
from tests.canonical_id_helpers import tid

SOURCE_NODE_ID = tid("node", "protocol-envelope-source")
DESTINATION_NODE_ID = tid("node", "protocol-envelope-destination")
TRANSACTION_ID = tid("transaction", "protocol-envelope-transaction")
SIGNING_PRIVATE_KEY, SIGNING_PUBLIC_KEY = generate_ed25519_keypair()
OTHER_SIGNING_PRIVATE_KEY, OTHER_SIGNING_PUBLIC_KEY = generate_ed25519_keypair()
RECIPIENT_PRIVATE_KEY, RECIPIENT_PUBLIC_KEY = generate_x25519_keypair()
OTHER_RECIPIENT_PRIVATE_KEY, OTHER_RECIPIENT_PUBLIC_KEY = generate_x25519_keypair()


def _transaction():
    return create_transaction(
        transaction_id=TRANSACTION_ID,
        transaction_type="vocabulary.tag.upsert",
        origin_node_id=SOURCE_NODE_ID,
        created_at="2026-07-12T00:00:00Z",
        payload={
            "tag_id": "protocol-tag",
            "name": "protocol",
            "operator_comment": "canonical envelope test",
        },
    )


def _envelope_dict() -> dict[str, object]:
    return canonical_envelope_dict(
        envelope=build_transaction_envelope(
            payload_codec=plaintext_envelope_payload_codec(),
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            created_at="2026-07-12T00:01:00Z",
        )
    )


def _signed_envelope():
    return sign_envelope(
        envelope=build_transaction_envelope(
            payload_codec=plaintext_envelope_payload_codec(),
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            created_at="2026-07-12T00:01:00Z",
        ),
        signer_node_id=SOURCE_NODE_ID,
        signing_private_key=SIGNING_PRIVATE_KEY,
        signing_public_key=SIGNING_PUBLIC_KEY,
    )


class CanonicalProtocolEnvelopeTest(unittest.TestCase):
    def test_builder_requires_explicit_codec(self) -> None:
        with self.assertRaises(TypeError):
            build_transaction_envelope(transaction=_transaction(), destination_node_id=DESTINATION_NODE_ID)

    def test_canonical_envelope_fields_are_explicit(self) -> None:
        payload = _envelope_dict()
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["envelope_version"], CANONICAL_ENVELOPE_VERSION)
        self.assertEqual(payload["message_type"], "transaction")
        self.assertEqual(payload["message_id"], payload["envelope_id"])
        self.assertEqual(payload["source_node_id"], SOURCE_NODE_ID)
        self.assertEqual(payload["destination_node_id"], DESTINATION_NODE_ID)
        self.assertEqual(payload["transaction_id"], TRANSACTION_ID)
        self.assertEqual(payload["routing"], {})
        self.assertIsNone(payload["expires_at"])
        self.assertIsNone(payload["signature_metadata"])
        self.assertIsNone(payload["encryption_metadata"])
        envelope_payload = payload["payload"]
        assert isinstance(envelope_payload, dict)
        self.assertEqual(
            envelope_payload["codec"],
            {"version": 1, "mode": "plaintext", "algorithm": "identity"},
        )
        self.assertEqual(envelope_payload["encoding"], "base64url")

    def test_identical_envelopes_serialize_identically(self) -> None:
        first = build_transaction_envelope(
            payload_codec=plaintext_envelope_payload_codec(),
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            created_at="2026-07-12T00:01:00Z",
        )
        second = build_transaction_envelope(
            payload_codec=plaintext_envelope_payload_codec(),
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            created_at="2026-07-12T00:01:00Z",
        )
        self.assertEqual(
            canonical_envelope_bytes(envelope=first),
            canonical_envelope_bytes(envelope=second),
        )

    def test_plaintext_codec_is_identity_transform(self) -> None:
        payload_bytes = b'{"a":1}'
        record = plaintext_envelope_payload_codec().encode(
            canonical_payload_bytes=payload_bytes,
        )
        self.assertEqual(record.encoded_payload_bytes, payload_bytes)
        self.assertEqual(decode_envelope_payload(payload=record.payload), payload_bytes)
        self.assertEqual(encoded_payload_bytes(payload=record.payload), payload_bytes)
        self.assertEqual(
            validate_payload_codec_metadata(metadata=record.metadata),
            {"version": 1, "mode": "plaintext", "algorithm": "identity"},
        )

    def test_plaintext_codec_requires_no_sqlite_storage_key(self) -> None:
        env = dict(os.environ)
        env.pop(SQLITE_STORAGE_KEY_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            record = plaintext_envelope_payload_codec().encode(
                canonical_payload_bytes=b'{"visible":true}',
            )
            self.assertEqual(decode_envelope_payload(payload=record.payload), b'{"visible":true}')

    def test_encrypted_codec_round_trip(self) -> None:
        context = EnvelopePayloadContext(
            envelope_id=tid("envelope", "encrypted-codec"),
            source_node_id=SOURCE_NODE_ID,
            destination_node_id=DESTINATION_NODE_ID,
            transaction_id=TRANSACTION_ID,
            envelope_version=1,
            protocol_version=1,
        )
        record = encrypted_envelope_payload_codec(
            context=context,
            recipient_node_id=DESTINATION_NODE_ID,
            recipient_public_key=RECIPIENT_PUBLIC_KEY,
        ).encode(canonical_payload_bytes=b'{"secret":true}')
        self.assertEqual(
            record.metadata,
            {"version": 1, "mode": "encrypted", "algorithm": ENCRYPTED_CODEC_ALGORITHM},
        )
        self.assertNotEqual(record.encoded_payload_bytes, b'{"secret":true}')
        self.assertIsNotNone(record.encryption_metadata)
        decoded = encrypted_envelope_payload_codec(
            context=context,
            local_private_key=RECIPIENT_PRIVATE_KEY,
            local_public_key=RECIPIENT_PUBLIC_KEY,
            encryption_metadata=record.encryption_metadata,
        ).decode(payload=record.payload)
        self.assertEqual(decoded, b'{"secret":true}')

    def test_encrypted_codec_does_not_use_sqlite_storage_key(self) -> None:
        context = EnvelopePayloadContext(
            envelope_id=tid("envelope", "encrypted-no-sqlite-key"),
            source_node_id=SOURCE_NODE_ID,
            destination_node_id=DESTINATION_NODE_ID,
            transaction_id=TRANSACTION_ID,
            envelope_version=1,
            protocol_version=1,
        )
        with mock.patch.dict(os.environ, {SQLITE_STORAGE_KEY_ENV: "/does/not/exist"}, clear=False):
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

    def test_encrypted_codec_rejects_tampered_ciphertext(self) -> None:
        context = EnvelopePayloadContext(
            envelope_id=tid("envelope", "encrypted-tamper"),
            source_node_id=SOURCE_NODE_ID,
            destination_node_id=DESTINATION_NODE_ID,
            transaction_id=TRANSACTION_ID,
            envelope_version=1,
            protocol_version=1,
        )
        record = encrypted_envelope_payload_codec(
            context=context,
            recipient_node_id=DESTINATION_NODE_ID,
            recipient_public_key=RECIPIENT_PUBLIC_KEY,
        ).encode(canonical_payload_bytes=b'{"secret":true}')
        ciphertext = bytearray(encoded_payload_bytes(payload=record.payload))
        ciphertext[0] ^= 1
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

    def test_encrypted_codec_binds_aad_to_destination_and_transaction(self) -> None:
        context = EnvelopePayloadContext(
            envelope_id=tid("envelope", "encrypted-aad"),
            source_node_id=SOURCE_NODE_ID,
            destination_node_id=DESTINATION_NODE_ID,
            transaction_id=TRANSACTION_ID,
            envelope_version=1,
            protocol_version=1,
        )
        record = encrypted_envelope_payload_codec(
            context=context,
            recipient_node_id=DESTINATION_NODE_ID,
            recipient_public_key=RECIPIENT_PUBLIC_KEY,
        ).encode(canonical_payload_bytes=b'{"secret":true}')
        wrong_context = EnvelopePayloadContext(
            envelope_id=context.envelope_id,
            source_node_id=context.source_node_id,
            destination_node_id=context.destination_node_id,
            transaction_id=tid("transaction", "wrong-aad-transaction"),
            envelope_version=context.envelope_version,
            protocol_version=context.protocol_version,
        )
        with self.assertRaisesRegex(EnvelopePayloadCodecError, "authentication failed"):
            encrypted_envelope_payload_codec(
                context=wrong_context,
                local_private_key=RECIPIENT_PRIVATE_KEY,
                local_public_key=RECIPIENT_PUBLIC_KEY,
                encryption_metadata=record.encryption_metadata,
            ).decode(payload=record.payload)

    def test_encrypted_envelope_payload_hash_commits_to_ciphertext(self) -> None:
        envelope = build_transaction_envelope(
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            created_at="2026-07-12T00:01:00Z",
            payload_codec=encrypted_envelope_payload_codec(
                recipient_node_id=DESTINATION_NODE_ID,
                recipient_public_key=RECIPIENT_PUBLIC_KEY,
            ),
        )
        payload = envelope.payload
        assert isinstance(payload, dict)
        codec = payload["codec"]
        assert isinstance(codec, dict)
        self.assertEqual(codec["mode"], ENCRYPTED_CODEC_MODE)
        self.assertEqual(
            envelope.payload_hash,
            payload_commitment(encoded_payload_bytes=encoded_payload_bytes(payload=payload)),
        )
        self.assertNotIn(
            b"canonical envelope test",
            encoded_payload_bytes(payload=payload),
        )
        with self.assertRaises(EnvelopePayloadCodecError):
            decode_envelope_payload(payload=payload)

    def test_wrong_recipient_cannot_decrypt_encrypted_codec(self) -> None:
        context = EnvelopePayloadContext(
            envelope_id=tid("envelope", "encrypted-wrong-recipient"),
            source_node_id=SOURCE_NODE_ID,
            destination_node_id=DESTINATION_NODE_ID,
            transaction_id=TRANSACTION_ID,
            envelope_version=1,
            protocol_version=1,
        )
        record = encrypted_envelope_payload_codec(
            context=context,
            recipient_node_id=DESTINATION_NODE_ID,
            recipient_public_key=RECIPIENT_PUBLIC_KEY,
        ).encode(canonical_payload_bytes=b'{"secret":true}')
        with self.assertRaisesRegex(EnvelopePayloadCodecError, "recipient key fingerprint mismatch"):
            encrypted_envelope_payload_codec(
                context=context,
                local_private_key=OTHER_RECIPIENT_PRIVATE_KEY,
                local_public_key=OTHER_RECIPIENT_PUBLIC_KEY,
                encryption_metadata=record.encryption_metadata,
            ).decode(payload=record.payload)

    def test_round_trip_reconstructs_identical_canonical_bytes(self) -> None:
        envelope = build_transaction_envelope(
            payload_codec=plaintext_envelope_payload_codec(),
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            created_at="2026-07-12T00:01:00Z",
        )
        serialized = canonical_envelope_bytes(envelope=envelope)
        reconstructed = parse_envelope_bytes(data=serialized)
        self.assertEqual(canonical_envelope_bytes(envelope=reconstructed), serialized)

    def test_local_transport_metadata_is_not_protocol_state(self) -> None:
        envelope = build_transaction_envelope(
            payload_codec=plaintext_envelope_payload_codec(),
            transaction=_transaction(),
            destination_node_id=DESTINATION_NODE_ID,
            created_at="2026-07-12T00:01:00Z",
        )
        before = canonical_envelope_bytes(envelope=envelope)
        local_metadata = {
            "attempt_count": 9,
            "claimed_at": "2026-07-12T00:02:00Z",
            "last_error": "connection refused",
        }
        self.assertNotIn("attempt_count", canonical_envelope_dict(envelope=envelope))
        self.assertEqual(before, canonical_envelope_bytes(envelope=envelope))
        self.assertEqual(local_metadata["attempt_count"], 9)

    def test_mapping_parser_rejects_missing_required_field(self) -> None:
        payload = _envelope_dict()
        payload.pop("source_node_id")
        with self.assertRaisesRegex(EnvelopeValidationError, "missing required field: source_node_id"):
            parse_envelope_mapping(payload=payload)

    def test_mapping_parser_rejects_malformed_identifier(self) -> None:
        payload = _envelope_dict()
        payload["destination_node_id"] = "not-a-node-id"
        with self.assertRaisesRegex(EnvelopeValidationError, "destination_node_id"):
            parse_envelope_mapping(payload=payload)

    def test_mapping_parser_rejects_unsupported_version(self) -> None:
        payload = _envelope_dict()
        payload["envelope_version"] = 999
        with self.assertRaisesRegex(EnvelopeValidationError, "envelope_version is unsupported"):
            parse_envelope_mapping(payload=payload)

    def test_mapping_parser_rejects_invalid_routing(self) -> None:
        payload = _envelope_dict()
        payload["routing"] = ["not", "object"]
        with self.assertRaisesRegex(EnvelopeValidationError, "routing must be an object"):
            parse_envelope_mapping(payload=payload)

    def test_mapping_parser_rejects_payload_commitment_mismatch(self) -> None:
        payload = _envelope_dict()
        payload["payload_hash"] = "0" * 64
        with self.assertRaisesRegex(EnvelopeValidationError, "payload_hash does not match payload"):
            parse_envelope_mapping(payload=payload)

    def test_byte_parser_rejects_duplicate_fields(self) -> None:
        payload = _envelope_dict()
        text = json.dumps(payload, sort_keys=True)
        duplicate = text.replace('"version": 1', '"version": 1, "version": 1', 1)
        with self.assertRaisesRegex(EnvelopeValidationError, "duplicate envelope field: version"):
            parse_envelope_bytes(data=duplicate.encode("utf-8"))

    def test_signed_envelope_verifies_against_canonical_bytes(self) -> None:
        envelope = _signed_envelope()
        verify_envelope_signature(
            envelope=envelope,
            expected_signer_node_id=SOURCE_NODE_ID,
            signing_public_key=SIGNING_PUBLIC_KEY,
        )
        self.assertIn(b'"signature":null', envelope_signing_bytes(envelope=envelope))

    def test_signed_envelope_survives_persistence_round_trip(self) -> None:
        envelope = _signed_envelope()
        serialized = canonical_envelope_bytes(envelope=envelope)
        reconstructed = parse_envelope_bytes(data=serialized)
        self.assertEqual(canonical_envelope_bytes(envelope=reconstructed), serialized)
        verify_envelope_signature(
            envelope=reconstructed,
            expected_signer_node_id=SOURCE_NODE_ID,
            signing_public_key=SIGNING_PUBLIC_KEY,
        )

    def test_signing_same_envelope_is_deterministic(self) -> None:
        first = _signed_envelope()
        second = _signed_envelope()
        self.assertEqual(
            canonical_envelope_bytes(envelope=first),
            canonical_envelope_bytes(envelope=second),
        )

    def test_payload_modification_invalidates_signature(self) -> None:
        payload = canonical_envelope_dict(envelope=_signed_envelope())
        payload_record = plaintext_envelope_payload_codec().encode(
            canonical_payload_bytes=canonical_json_bytes({"tampered": True})
        )
        payload["payload"] = payload_record.payload
        payload["payload_hash"] = payload_commitment(
            encoded_payload_bytes=payload_record.encoded_payload_bytes
        )
        envelope = parse_envelope_mapping(payload=payload)
        with self.assertRaisesRegex(EnvelopeSignatureError, "signature is invalid"):
            verify_envelope_signature(
                envelope=envelope,
                expected_signer_node_id=SOURCE_NODE_ID,
                signing_public_key=SIGNING_PUBLIC_KEY,
            )

    def test_routing_modification_invalidates_signature(self) -> None:
        payload = canonical_envelope_dict(envelope=_signed_envelope())
        payload["routing"] = {"via": "changed"}
        envelope = parse_envelope_mapping(payload=payload)
        with self.assertRaisesRegex(EnvelopeSignatureError, "signature is invalid"):
            verify_envelope_signature(
                envelope=envelope,
                expected_signer_node_id=SOURCE_NODE_ID,
                signing_public_key=SIGNING_PUBLIC_KEY,
            )

    def test_identifier_modification_invalidates_signature(self) -> None:
        payload = canonical_envelope_dict(envelope=_signed_envelope())
        payload["destination_node_id"] = tid("node", "protocol-envelope-other-destination")
        envelope = parse_envelope_mapping(payload=payload)
        with self.assertRaisesRegex(EnvelopeSignatureError, "signature is invalid"):
            verify_envelope_signature(
                envelope=envelope,
                expected_signer_node_id=SOURCE_NODE_ID,
                signing_public_key=SIGNING_PUBLIC_KEY,
            )

    def test_timestamp_modification_invalidates_signature(self) -> None:
        payload = canonical_envelope_dict(envelope=_signed_envelope())
        payload["created_at"] = "2026-07-12T99:99:99Z"
        envelope = parse_envelope_mapping(payload=payload)
        with self.assertRaisesRegex(EnvelopeSignatureError, "signature is invalid"):
            verify_envelope_signature(
                envelope=envelope,
                expected_signer_node_id=SOURCE_NODE_ID,
                signing_public_key=SIGNING_PUBLIC_KEY,
            )

    def test_signature_corruption_is_rejected(self) -> None:
        payload = canonical_envelope_dict(envelope=_signed_envelope())
        metadata = payload["signature_metadata"]
        assert isinstance(metadata, dict)
        metadata["signature"] = "AAAA"
        envelope = parse_envelope_mapping(payload=payload)
        with self.assertRaisesRegex(EnvelopeSignatureError, "signature must be 64 raw bytes"):
            verify_envelope_signature(
                envelope=envelope,
                expected_signer_node_id=SOURCE_NODE_ID,
                signing_public_key=SIGNING_PUBLIC_KEY,
            )

    def test_wrong_public_key_is_rejected(self) -> None:
        envelope = _signed_envelope()
        with self.assertRaisesRegex(EnvelopeSignatureError, "key fingerprint"):
            verify_envelope_signature(
                envelope=envelope,
                expected_signer_node_id=SOURCE_NODE_ID,
                signing_public_key=OTHER_SIGNING_PUBLIC_KEY,
            )


if __name__ == "__main__":
    unittest.main()
