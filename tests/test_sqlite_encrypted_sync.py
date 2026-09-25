"""Encrypted SQLite peer synchronization boundary tests."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.provisioning import provision_sqlite_datastore
from secrets_kit.backends.sqlite.sync_storage import (
    STORAGE_REWRAP_PROTOCOL,
    localize_inbound_storage_payload,
    prepare_outbound_storage_payload,
)
from secrets_kit.backends.sqlite.transactions import create_transaction, insert_transaction
from secrets_kit.crypto.storage.sqlite import decrypt_payload, encrypt_payload
from secrets_kit.protocol.payload_codec import (
    ENVELOPE_PAYLOAD_CODEC_ENV,
    EnvelopePayloadCodecError,
    configured_envelope_payload_codec_mode,
)


def _transaction(transaction_type: str = "secret.set", *, include_value: bool = True) -> Transaction:
    payload = {
        "secret_id": "secret:11111111-1111-4111-8111-111111111111",
        "encrypted_name_b64": base64.b64encode(
            encrypt_payload(plaintext=b"TOKEN", field_name="encrypted_name")
        ).decode("ascii"),
        "encrypted_payload_b64": base64.b64encode(
            encrypt_payload(plaintext=b"value", field_name="encrypted_payload")
        ).decode("ascii"),
    }
    if not include_value:
        payload.pop("encrypted_payload_b64")
    return create_transaction(
        transaction_id="txn:11111111-1111-4111-8111-111111111111",
        transaction_type=transaction_type,
        origin_node_id="node:11111111-1111-4111-8111-111111111111",
        payload=payload,
        created_at="2026-08-09T00:00:00Z",
    )


class EncryptedSQLiteSyncTest(unittest.TestCase):
    def test_custom_path_and_plaintext_environment_cannot_initialize_store(self) -> None:
        from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
        from secrets_kit.backends.sqlite.gate import open_sqlite_backend

        with tempfile.TemporaryDirectory() as home:
            database = Path(home) / "custom.sqlite"
            with mock.patch.dict("os.environ", {"HOME": home, "SECKIT_SQLITE_PATH": str(database), "SECKIT_SQLITE_STORAGE_MODE": "plaintext"}, clear=True):
                with self.assertRaisesRegex(SQLiteBackendError, "run seckit init"):
                    open_sqlite_backend()
                self.assertFalse(database.exists())

    def test_live_plaintext_is_rejected_before_decode_even_with_unsafe_fixture_override(self) -> None:
        from secrets_kit.protocol.envelope import canonical_envelope_dict
        from secrets_kit.runtime.inbound_envelopes import apply_inbound_transaction_envelope
        from tests.test_protocol_envelope import _signed_envelope

        payload = canonical_envelope_dict(envelope=_signed_envelope())
        with mock.patch.dict("os.environ", {"SECKIT_UNSAFE_PLAINTEXT_ENVELOPES": "1"}), mock.patch("secrets_kit.runtime.inbound_envelopes.open_sqlite_backend"), mock.patch("secrets_kit.runtime.inbound_envelopes._decode_inbound_envelope_payload") as decode, mock.patch("secrets_kit.runtime.inbound_envelopes.apply_inbound_transaction") as apply:
            with self.assertRaisesRegex(SQLiteValidationError, "live synchronization requires encrypted envelopes"):
                apply_inbound_transaction_envelope(envelope=payload)
            decode.assert_not_called()
            apply.assert_not_called()

    def test_lan_without_rss_defaults_envelope_payloads_to_encrypted(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict("os.environ", {"HOME": home}, clear=True):
                self.assertFalse((Path(home) / ".config/seckit/rss-client.json").exists())
                self.assertEqual(configured_envelope_payload_codec_mode(), "encrypted")

    def test_invalid_envelope_override_fails_closed(self) -> None:
        with mock.patch.dict("os.environ", {ENVELOPE_PAYLOAD_CODEC_ENV: "invalid"}):
            with self.assertRaises(EnvelopePayloadCodecError):
                configured_envelope_payload_codec_mode()

    def test_plaintext_envelopes_require_separate_unsafe_acknowledgement(self) -> None:
        with mock.patch.dict("os.environ", {ENVELOPE_PAYLOAD_CODEC_ENV: "plaintext"}, clear=True):
            with self.assertRaisesRegex(EnvelopePayloadCodecError, "UNSAFE"):
                configured_envelope_payload_codec_mode()
            with mock.patch.dict("os.environ", {"SECKIT_UNSAFE_PLAINTEXT_ENVELOPES": "1"}):
                self.assertEqual(configured_envelope_payload_codec_mode(), "plaintext")

    def test_unsafe_acknowledgement_alone_does_not_disable_encryption(self) -> None:
        with mock.patch.dict("os.environ", {"SECKIT_UNSAFE_PLAINTEXT_ENVELOPES": "1"}, clear=True):
            self.assertEqual(configured_envelope_payload_codec_mode(), "encrypted")

    def test_encrypted_storage_is_rewrapped_for_an_independent_peer(self) -> None:
        self._assert_rewrapped(transaction_type="secret.set", include_value=True)

    def test_delete_name_is_rewrapped_for_an_independent_peer(self) -> None:
        self._assert_rewrapped(transaction_type="secret.delete", include_value=False)

    def test_delete_with_optional_value_is_rewrapped(self) -> None:
        self._assert_rewrapped(transaction_type="secret.delete", include_value=True)

    def _assert_rewrapped(self, *, transaction_type: str, include_value: bool) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_key = root / "source.key"
            target_key = root / "target.key"
            source = provision_sqlite_datastore(
                path=root / "source.sqlite", storage_mode="encrypted"
            )
            target = provision_sqlite_datastore(
                path=root / "target.sqlite", storage_mode="encrypted"
            )
            try:
                with mock.patch.dict(
                    "os.environ", {"SECKIT_SQLITE_STORAGE_KEY_PATH": str(source_key)}
                ):
                    transaction = _transaction(transaction_type, include_value=include_value)
                    with self.assertRaisesRegex(SQLiteValidationError, "requires encrypted envelopes"):
                        prepare_outbound_storage_payload(conn=source, transaction=transaction, envelope_encrypted=False)
                    wire = prepare_outbound_storage_payload(
                        conn=source, transaction=transaction, envelope_encrypted=True
                    )
                self.assertEqual(
                    wire.payload["storage_rewrap"], STORAGE_REWRAP_PROTOCOL
                )
                self.assertNotIn("encrypted_payload_b64", wire.payload)

                with mock.patch.dict(
                    "os.environ", {"SECKIT_SQLITE_STORAGE_KEY_PATH": str(target_key)}
                ):
                    localized = localize_inbound_storage_payload(
                        conn=target,
                        transaction_id=wire.transaction_id,
                        transaction_type=wire.transaction_type,
                        payload=wire.payload,
                    )
                    self.assertEqual(
                        decrypt_payload(
                            stored=base64.b64decode(
                                str(localized["encrypted_name_b64"]).encode("ascii"),
                                validate=True,
                            ),
                            field_name="encrypted_name",
                        ),
                        b"TOKEN",
                    )
                    if include_value:
                        self.assertEqual(
                            decrypt_payload(
                                stored=base64.b64decode(str(localized["encrypted_payload_b64"]), validate=True),
                                field_name="encrypted_payload",
                            ),
                            b"value",
                        )
                    else:
                        self.assertNotIn("encrypted_payload_b64", localized)
                        self.assertNotIn("payload_b64", wire.payload)
                    # Reject malformed or ambiguous wire fields before retaining state.
                    invalid_payloads = [
                        {**wire.payload, "name_b64": None},
                        {**wire.payload, "payload_b64": None},
                        {**wire.payload, "encrypted_name_b64": "ambiguous"},
                        {**wire.payload, "storage_rewrap": "unknown"},
                        {key: value for key, value in wire.payload.items() if key != "name_b64"},
                    ]
                    if transaction_type == "secret.set":
                        invalid_payloads.append({key: value for key, value in wire.payload.items() if key != "payload_b64"})
                    for invalid in invalid_payloads:
                        with self.assertRaises(SQLiteValidationError):
                            localize_inbound_storage_payload(conn=target, transaction_id=wire.transaction_id,
                                transaction_type=wire.transaction_type, payload=invalid)
                    retained = create_transaction(
                        transaction_id=wire.transaction_id,
                        transaction_type=wire.transaction_type,
                        origin_node_id=str(wire.origin_node_id),
                        payload=localized,
                        created_at=str(wire.created_at),
                    )
                    target.execute("PRAGMA foreign_keys = OFF")
                    insert_transaction(conn=target, transaction=retained)
                    target.commit()
                    target.execute("PRAGMA foreign_keys = ON")
                    replay = localize_inbound_storage_payload(
                        conn=target,
                        transaction_id=wire.transaction_id,
                        transaction_type=wire.transaction_type,
                        payload=wire.payload,
                    )
                    with self.assertRaisesRegex(SQLiteValidationError, "duplicate transaction payload"):
                        localize_inbound_storage_payload(conn=target, transaction_id=wire.transaction_id,
                            transaction_type=wire.transaction_type, payload={**wire.payload, "name_b64": "VEFNUEVSRUQ="})
                    with self.assertRaisesRegex(SQLiteValidationError, "duplicate transaction type"):
                        localize_inbound_storage_payload(conn=target, transaction_id=wire.transaction_id,
                            transaction_type="secret.delete" if transaction_type == "secret.set" else "secret.set",
                            payload=wire.payload)
                self.assertEqual(replay, localized)
                self.assertNotEqual(source_key.read_bytes(), target_key.read_bytes())
            finally:
                source.close()
                target.close()

    def test_encrypted_storage_refuses_plaintext_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            conn = provision_sqlite_datastore(
                path=root / "source.sqlite", storage_mode="encrypted"
            )
            try:
                with mock.patch.dict(
                    "os.environ",
                    {"SECKIT_SQLITE_STORAGE_KEY_PATH": str(root / "source.key")},
                ):
                    transaction = _transaction()
                    with self.assertRaisesRegex(
                        SQLiteValidationError, "requires encrypted envelopes"
                    ):
                        prepare_outbound_storage_payload(
                            conn=conn,
                            transaction=transaction,
                            envelope_encrypted=False,
                        )
            finally:
                conn.close()

    def test_rss_profile_defaults_envelope_payloads_to_encrypted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            profile = root / ".config" / "seckit" / "rss-client.json"
            profile.parent.mkdir(parents=True)
            profile.write_text("{}", encoding="utf-8")
            with mock.patch.dict("os.environ", {"HOME": str(root)}, clear=True):
                self.assertEqual(configured_envelope_payload_codec_mode(), "encrypted")
