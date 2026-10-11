"""Customer Checkout receipt and deterministic enrollment tests."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.rss import _installed_operator_url, cmd_rss_local_status
from secrets_kit.crypto.models import generate_signing_keypair
from secrets_kit.crypto.persistence import signing_keypair_from_record, signing_keypair_to_record
from secrets_kit.protocol.rss_auth import RSSAuthenticationError
from secrets_kit.protocol.rss_provisioning import (
    _valid_peer,
    complete_rss_enrollment,
    configure_rss_provisioning_bundle,
    prepare_rss_device_identity,
    rss_identity_prepared_path,
    start_rss_checkout,
)


class Response:
    def __init__(self, value: dict[str, object]) -> None:
        self._stream = io.BytesIO(json.dumps(value).encode("utf-8"))

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self._stream.read(limit)


class RSSProvisioningTest(unittest.TestCase):
    @staticmethod
    def token(*, expires_at: int) -> str:
        claims = {"protocol": "rss_enrollment_token/v1", "expires_at": expires_at}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        return f"ret1.{payload}.signature"

    def pending_profile(self, *, expires_at: int) -> tuple[Path, Path, dict[str, object]]:
        self.profile.parent.mkdir(mode=0o700, parents=True)
        token_path = self.profile.with_name("rss-enrollment-token")
        token_path.write_text(self.token(expires_at=expires_at), encoding="ascii")
        token_path.chmod(0o600)
        key_path = self.profile.with_name("rss-auth-key.json")
        key_path.write_text("synthetic-key", encoding="ascii")
        key_path.chmod(0o600)
        profile: dict[str, object] = {
            "version": 1, "entitlement_id": "ent_test", "connection_id": "connection-preserved",
            "key_file": str(key_path.resolve()), "enrollment_token_file": str(token_path.resolve()),
            "relay_peers": ["/dns4/east.example.test/tcp/14001/p2p/east",
                            "/dns4/west.example.test/tcp/14001/p2p/west"],
            "enrollment_primary": "/dns4/east.example.test/tcp/14001/p2p/east",
            "enrollment_url": "https://qa.example.test",
        }
        self.profile.write_text(json.dumps(profile), encoding="utf-8")
        self.profile.chmod(0o600)
        return token_path, key_path, profile

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.profile = self.root / "config" / "rss-client.json"
        self.paths = (
            mock.patch(
                "secrets_kit.protocol.rss_provisioning.rss_client_profile_path",
                return_value=self.profile,
            ),
            mock.patch(
                "secrets_kit.protocol.rss_auth.rss_client_profile_path",
                return_value=self.profile,
            ),
        )
        for patcher in self.paths:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.paths):
            patcher.stop()
        self.temp.cleanup()

    def _bundle(self, *, token: str = "ret1.one-use-token", entitlement: str = "ent_test") -> dict[str, object]:
        return {
            "protocol": "rss_provisioning_bundle/v1", "entitlement_id": entitlement,
            "rss_enrollment_token": token, "enrollment_url": "https://qa.example.test",
            "relay_peers": [
                "/dns4/east.example.test/tcp/14001/p2p/east",
                "/dns4/west.example.test/tcp/14001/p2p/west",
            ],
        }

    def test_prepared_identity_is_idempotent_and_owner_private(self) -> None:
        first = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        second = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        self.assertEqual(first, second)
        prep = rss_identity_prepared_path()
        key = self.profile.with_name("rss-auth-key.json")
        self.assertEqual(prep.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("private", prep.read_text())

    def test_missing_token_after_state_write_resumes_exact_authority(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        key = self.profile.with_name("rss-auth-key.json")
        original_key = key.read_bytes()
        bundle = self._bundle()
        state_path = self.profile.with_name("rss-provisioning.json")
        token_path = self.profile.with_name("rss-enrollment-token")
        with mock.patch("secrets_kit.protocol.rss_provisioning.store_rss_enrollment_token_file", side_effect=OSError("interrupted token write")):
            with self.assertRaises(OSError):
                configure_rss_provisioning_bundle(bundle=bundle, expected_operator_url="https://qa.example.test")
        self.assertTrue(state_path.exists())
        self.assertFalse(token_path.exists())
        retained = state_path.read_bytes()
        with self.assertRaisesRegex(RSSAuthenticationError, "pending RSS authority differs"):
            configure_rss_provisioning_bundle(bundle={**bundle, "entitlement_id": "ent_other"}, expected_operator_url="https://qa.example.test")
        self.assertEqual(state_path.read_bytes(), retained)
        self.assertFalse(token_path.exists())
        with self.assertRaisesRegex(RSSAuthenticationError, "response is invalid"):
            configure_rss_provisioning_bundle(bundle={**bundle, "extra": "invalid"}, expected_operator_url="https://qa.example.test")
        self.assertFalse(token_path.exists())
        configure_rss_provisioning_bundle(bundle=bundle, expected_operator_url="https://qa.example.test")
        self.assertEqual(json.loads(self.profile.read_text())["connection_id"], identity["connection_id"])
        self.assertEqual(key.read_bytes(), original_key)
        self.assertFalse(state_path.exists())
        self.assertFalse(rss_identity_prepared_path().exists())

    def test_bundle_preserves_prepared_key_and_connection_id(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        key = self.profile.with_name("rss-auth-key.json")
        original_key = key.read_bytes()
        configured = configure_rss_provisioning_bundle(
            bundle=self._bundle(), expected_operator_url="https://qa.example.test"
        )
        self.assertEqual(configured, self.profile)
        profile = json.loads(self.profile.read_text())
        self.assertEqual(profile["connection_id"], identity["connection_id"])
        self.assertEqual(key.read_bytes(), original_key)
        self.assertFalse(rss_identity_prepared_path().exists())

    def test_prepared_identity_authority_and_key_collisions_are_untouched(self) -> None:
        prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        prep = rss_identity_prepared_path()
        original_prep = prep.read_bytes()
        with self.assertRaisesRegex(RSSAuthenticationError, "authority differs"):
            prepare_rss_device_identity(expected_operator_url="https://other.example.test")
        self.assertEqual(prep.read_bytes(), original_prep)
        key = self.profile.with_name("rss-auth-key.json")
        key.write_bytes(b"not-a-key")
        key.chmod(0o600)
        with self.assertRaises(RSSAuthenticationError):
            configure_rss_provisioning_bundle(
                bundle=self._bundle(), expected_operator_url="https://qa.example.test"
            )
        self.assertEqual(prep.read_bytes(), original_prep)
        self.assertFalse(self.profile.exists())
        self.assertFalse(self.profile.with_name("rss-enrollment-token").exists())

    def test_prepared_identity_rejects_insecure_or_symlinked_record(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        prep = rss_identity_prepared_path()
        prep.chmod(0o640)
        with self.assertRaises(RSSAuthenticationError):
            prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        prep.unlink()
        prep.symlink_to(self.profile.with_name("target"))
        with self.assertRaises(RSSAuthenticationError):
            prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        prep.unlink()
        self.assertTrue(identity["connection_id"])

    def test_interrupted_bundle_retains_prepared_identity_and_resumes(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        prep = rss_identity_prepared_path()
        key = self.profile.with_name("rss-auth-key.json")
        original_key = key.read_bytes()
        with mock.patch(
            "secrets_kit.protocol.rss_provisioning.configure_rss_client",
            side_effect=RSSAuthenticationError("interrupted"),
        ):
            with self.assertRaisesRegex(RSSAuthenticationError, "interrupted"):
                configure_rss_provisioning_bundle(
                    bundle=self._bundle(token=self.token(expires_at=4102444800)), expected_operator_url="https://qa.example.test"
                )
        self.assertTrue(prep.exists())
        self.assertEqual(key.read_bytes(), original_key)
        self.assertTrue(self.profile.with_name("rss-enrollment-token").exists())
        configure_rss_provisioning_bundle(
            bundle=self._bundle(token=self.token(expires_at=4102444800)), expected_operator_url="https://qa.example.test"
        )
        self.assertEqual(json.loads(self.profile.read_text())["connection_id"], identity["connection_id"])
        self.assertFalse(prep.exists())

    def test_preparation_rejects_already_configured_profile(self) -> None:
        self.pending_profile(expires_at=9999999999)
        with self.assertRaisesRegex(RSSAuthenticationError, "already configured"):
            prepare_rss_device_identity(expected_operator_url="https://qa.example.test")

    def test_pending_recovery_returns_existing_identity_without_writing(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        key = self.profile.with_name("rss-auth-key.json")
        key_bytes = key.read_bytes()
        token = self.profile.with_name("rss-enrollment-token")
        token.write_text(self.token(expires_at=100), encoding="ascii")
        token.chmod(0o600)
        self.profile.write_text(json.dumps({
            "version": 1, "entitlement_id": "ent_test", "connection_id": identity["connection_id"],
            "key_file": str(key.resolve()), "enrollment_token_file": str(token.resolve()),
            "relay_peers": ["/dns4/east.example.test/tcp/14001/p2p/east", "/dns4/west.example.test/tcp/14001/p2p/west"],
            "enrollment_primary": "/dns4/east.example.test/tcp/14001/p2p/east",
            "enrollment_url": "https://qa.example.test",
        }), encoding="utf-8")
        self.profile.chmod(0o600)
        prep = rss_identity_prepared_path()
        prep_bytes = prep.read_bytes()
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            recovered = prepare_rss_device_identity(
                expected_operator_url="https://qa.example.test", allow_pending_recovery=True
            )
        self.assertEqual(recovered, identity)
        self.assertEqual(key.read_bytes(), key_bytes)
        self.assertEqual(prep.read_bytes(), prep_bytes)

    def test_pending_recovery_default_healthy_and_wrong_origin_fail(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        key = self.profile.with_name("rss-auth-key.json")
        token = self.profile.with_name("rss-enrollment-token")
        token.write_text(self.token(expires_at=300), encoding="ascii")
        token.chmod(0o600)
        self.profile.write_text(json.dumps({
            "version": 1, "entitlement_id": "ent_test", "connection_id": identity["connection_id"],
            "key_file": str(key.resolve()), "enrollment_token_file": str(token.resolve()),
            "relay_peers": ["/dns4/east.example.test/tcp/14001/p2p/east", "/dns4/west.example.test/tcp/14001/p2p/west"],
            "enrollment_primary": "/dns4/east.example.test/tcp/14001/p2p/east",
            "enrollment_url": "https://qa.example.test",
        }), encoding="utf-8")
        self.profile.chmod(0o600)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            with self.assertRaises(RSSAuthenticationError):
                prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
            with self.assertRaises(RSSAuthenticationError):
                prepare_rss_device_identity(expected_operator_url="https://other.example.test", allow_pending_recovery=True)

    def test_configured_profile_path_canonicalizes_and_pending_recovery_renews(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=50):
            configure_rss_provisioning_bundle(
                bundle=self._bundle(token=self.token(expires_at=100)),
                expected_operator_url="https://qa.example.test",
            )
        profile_before = json.loads(self.profile.read_text())
        key_before = self.profile.with_name("rss-auth-key.json").read_bytes()
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            recovered = prepare_rss_device_identity(
                expected_operator_url="https://qa.example.test", allow_pending_recovery=True
            )
            self.assertEqual(recovered, identity)
            configure_rss_provisioning_bundle(
                bundle=self._bundle(token=self.token(expires_at=300)),
                expected_operator_url="https://qa.example.test",
            )
        profile_after = json.loads(self.profile.read_text())
        self.assertEqual(profile_after["connection_id"], profile_before["connection_id"])
        self.assertEqual(Path(profile_after["key_file"]).resolve(), self.profile.with_name("rss-auth-key.json").resolve())
        self.assertEqual(self.profile.with_name("rss-auth-key.json").read_bytes(), key_before)

    def test_crash_after_state_and_token_replaces_only_expired_ret(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        token_a = self.token(expires_at=100)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=50), mock.patch(
            "secrets_kit.protocol.rss_provisioning.configure_rss_client",
            side_effect=RSSAuthenticationError("crash after token"),
        ):
            with self.assertRaisesRegex(RSSAuthenticationError, "crash after token"):
                configure_rss_provisioning_bundle(
                    bundle=self._bundle(token=token_a), expected_operator_url="https://qa.example.test"
                )
        token_path = self.profile.with_name("rss-enrollment-token")
        self.assertEqual(token_path.read_text(), token_a)
        token_b = self.token(expires_at=300)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            configure_rss_provisioning_bundle(
                bundle=self._bundle(token=token_b), expected_operator_url="https://qa.example.test"
            )
        profile = json.loads(self.profile.read_text())
        self.assertEqual(profile["connection_id"], identity["connection_id"])
        self.assertEqual(token_path.read_text(), token_b)

    def test_crash_recovery_rejects_nonexpired_replacement_and_expired_same_token(self) -> None:
        prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        token_a = self.token(expires_at=300)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=50), mock.patch(
            "secrets_kit.protocol.rss_provisioning.configure_rss_client", side_effect=RSSAuthenticationError("crash")
        ):
            with self.assertRaises(RSSAuthenticationError):
                configure_rss_provisioning_bundle(bundle=self._bundle(token=token_a), expected_operator_url="https://qa.example.test")
        state_before = self.profile.with_name("rss-provisioning.json").read_bytes()
        token_before = self.profile.with_name("rss-enrollment-token").read_bytes()
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=100):
            with self.assertRaises(RSSAuthenticationError):
                configure_rss_provisioning_bundle(bundle=self._bundle(token=self.token(expires_at=400)), expected_operator_url="https://qa.example.test")
        self.assertEqual(self.profile.with_name("rss-provisioning.json").read_bytes(), state_before)
        self.assertEqual(self.profile.with_name("rss-enrollment-token").read_bytes(), token_before)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=400):
            with self.assertRaises(RSSAuthenticationError):
                configure_rss_provisioning_bundle(bundle=self._bundle(token=token_a), expected_operator_url="https://qa.example.test")
        self.assertEqual(self.profile.with_name("rss-provisioning.json").read_bytes(), state_before)
        self.assertEqual(self.profile.with_name("rss-enrollment-token").read_bytes(), token_before)

    def test_crash_recovery_rejects_different_public_state_untouched(self) -> None:
        prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        token_a = self.token(expires_at=100)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=50), mock.patch(
            "secrets_kit.protocol.rss_provisioning.configure_rss_client", side_effect=RSSAuthenticationError("crash")
        ):
            with self.assertRaises(RSSAuthenticationError):
                configure_rss_provisioning_bundle(bundle=self._bundle(token=token_a), expected_operator_url="https://qa.example.test")
        state_path = self.profile.with_name("rss-provisioning.json")
        token_path = self.profile.with_name("rss-enrollment-token")
        state_before, token_before = state_path.read_bytes(), token_path.read_bytes()
        altered = self._bundle(token=self.token(expires_at=300), entitlement="ent_other")
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            with self.assertRaisesRegex(RSSAuthenticationError, "authority differs"):
                configure_rss_provisioning_bundle(bundle=altered, expected_operator_url="https://qa.example.test")
        self.assertEqual(state_path.read_bytes(), state_before)
        self.assertEqual(token_path.read_bytes(), token_before)

    def test_crash_recovery_replaces_malformed_partial_ret_with_matching_state(self) -> None:
        identity = prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        token_a = self.token(expires_at=100)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=50), mock.patch(
            "secrets_kit.protocol.rss_provisioning.configure_rss_client", side_effect=RSSAuthenticationError("crash")
        ):
            with self.assertRaises(RSSAuthenticationError):
                configure_rss_provisioning_bundle(bundle=self._bundle(token=token_a), expected_operator_url="https://qa.example.test")
        token_path = self.profile.with_name("rss-enrollment-token")
        token_path.write_text("ret1.partial", encoding="ascii")
        token_path.chmod(0o600)
        token_b = self.token(expires_at=300)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            configure_rss_provisioning_bundle(bundle=self._bundle(token=token_b), expected_operator_url="https://qa.example.test")
        self.assertEqual(json.loads(self.profile.read_text())["connection_id"], identity["connection_id"])
        self.assertEqual(token_path.read_text(), token_b)

    def test_crash_recovery_unsafe_ret_file_is_denied(self) -> None:
        prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=50), mock.patch(
            "secrets_kit.protocol.rss_provisioning.configure_rss_client", side_effect=RSSAuthenticationError("crash")
        ):
            with self.assertRaises(RSSAuthenticationError):
                configure_rss_provisioning_bundle(bundle=self._bundle(token=self.token(expires_at=100)), expected_operator_url="https://qa.example.test")
        token_path = self.profile.with_name("rss-enrollment-token")
        token_path.chmod(0o640)
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            with self.assertRaisesRegex(RSSAuthenticationError, "permissions"):
                configure_rss_provisioning_bundle(bundle=self._bundle(token=self.token(expires_at=300)), expected_operator_url="https://qa.example.test")

    def test_preparation_rejects_writable_parent_and_boolean_version(self) -> None:
        self.profile.parent.mkdir(mode=0o777)
        self.profile.parent.chmod(0o777)
        with self.assertRaises(RSSAuthenticationError):
            prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        self.assertFalse(self.profile.with_name("rss-auth-key.json").exists())
        self.profile.parent.chmod(0o700)
        prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        prep = rss_identity_prepared_path()
        record = json.loads(prep.read_text())
        record["version"] = True
        prep.write_text(json.dumps(record))
        with self.assertRaises(RSSAuthenticationError):
            prepare_rss_device_identity(expected_operator_url="https://qa.example.test")

    def test_prepared_key_must_have_matching_private_and_public_halves(self) -> None:
        prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        key_path = self.profile.with_name("rss-auth-key.json")
        keypair = signing_keypair_from_record(record=json.loads(key_path.read_text()))
        inconsistent = type(keypair)(metadata=keypair.metadata, public_key=keypair.public_key,
                                    private_key=generate_signing_keypair().private_key)
        key_path.write_text(json.dumps(signing_keypair_to_record(keypair=inconsistent)))
        with self.assertRaises(RSSAuthenticationError):
            prepare_rss_device_identity(expected_operator_url="https://qa.example.test")
        self.assertFalse(self.profile.exists())

    def test_ssh_bundle_configures_distinct_device_without_checkout_receipt(self) -> None:
        bundle = {
            "protocol": "rss_provisioning_bundle/v1", "entitlement_id": "ent_test",
            "rss_enrollment_token": "ret1.one-use-token",
            "enrollment_url": "https://qa.example.test",
            "relay_peers": [
                "/dns4/east.example.test/tcp/14001/p2p/east",
                "/dns4/west.example.test/tcp/14001/p2p/west",
            ],
        }
        with mock.patch(
            "secrets_kit.protocol.rss_provisioning.configure_rss_client",
            return_value=self.profile,
        ) as configure:
            result = configure_rss_provisioning_bundle(
                bundle=bundle, expected_operator_url="https://qa.example.test"
            )
        self.assertEqual(result, self.profile)
        self.assertFalse(self.profile.with_name("rss-provisioning.json").exists())
        self.assertFalse(self.profile.with_name("rss-checkout.json").exists())
        self.assertEqual(configure.call_args.kwargs["entitlement_id"], "ent_test")
        self.assertEqual(
            self.profile.with_name("rss-enrollment-token").read_text(), "ret1.one-use-token"
        )

    def test_ssh_bundle_rejects_cross_environment_origin(self) -> None:
        with self.assertRaises(RSSAuthenticationError):
            configure_rss_provisioning_bundle(
                bundle={
                    "protocol": "rss_provisioning_bundle/v1", "entitlement_id": "ent_test",
                    "rss_enrollment_token": "ret1.one-use-token",
                    "enrollment_url": "https://dev.example.test",
                    "relay_peers": [
                        "/dns4/east.example.test/tcp/14001/p2p/east",
                        "/dns4/west.example.test/tcp/14001/p2p/west",
                    ],
                },
                expected_operator_url="https://qa.example.test",
            )
        self.assertFalse(self.profile.with_name("rss-enrollment-token").exists())

    def test_expired_pending_bundle_renews_token_without_replacing_identity(self) -> None:
        token_path, key_path, original = self.pending_profile(expires_at=100)
        bundle = {
            "protocol": "rss_provisioning_bundle/v1", "entitlement_id": "ent_test",
            "rss_enrollment_token": self.token(expires_at=300),
            "enrollment_url": "https://qa.example.test", "relay_peers": original["relay_peers"],
        }
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            self.assertEqual(
                configure_rss_provisioning_bundle(
                    bundle=bundle, expected_operator_url="https://qa.example.test"
                ), self.profile
            )
        self.assertEqual(json.loads(self.profile.read_text()), original)
        self.assertEqual(key_path.read_text(), "synthetic-key")
        self.assertEqual(token_path.read_text(), bundle["rss_enrollment_token"])
        self.assertEqual(token_path.stat().st_mode & 0o777, 0o600)

    def test_pending_bundle_rejects_changed_authority_without_touching_identity(self) -> None:
        token_path, _, original = self.pending_profile(expires_at=100)
        old_token = token_path.read_text()
        bundle = {
            "protocol": "rss_provisioning_bundle/v1", "entitlement_id": "ent_other",
            "rss_enrollment_token": self.token(expires_at=300),
            "enrollment_url": "https://qa.example.test", "relay_peers": original["relay_peers"],
        }
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            with self.assertRaisesRegex(RSSAuthenticationError, "authority differs"):
                configure_rss_provisioning_bundle(
                    bundle=bundle, expected_operator_url="https://qa.example.test"
                )
        self.assertEqual(token_path.read_text(), old_token)
        self.assertEqual(json.loads(self.profile.read_text()), original)

    def test_paid_receipt_renews_only_expired_pending_token(self) -> None:
        token_path, _, original = self.pending_profile(expires_at=100)
        receipt = self.profile.with_name("rss-checkout.json")
        receipt.write_text(json.dumps({
            "protocol": "rss_checkout_receipt/v1", "operator_url": "https://qa.example.test",
            "account_id": "ska_test", "checkout_session_id": "cs_test_123",
        }), encoding="utf-8")
        receipt.chmod(0o600)
        bundle = {
            "protocol": "rss_provisioning_bundle/v1", "entitlement_id": "ent_test",
            "rss_enrollment_token": self.token(expires_at=300),
            "enrollment_url": "https://qa.example.test", "relay_peers": original["relay_peers"],
        }
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=50):
            with mock.patch("secrets_kit.protocol.rss_provisioning._post_json") as request:
                self.assertEqual(complete_rss_enrollment(), self.profile)
            request.assert_not_called()
        with mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            with mock.patch("secrets_kit.protocol.rss_provisioning._post_json", return_value=bundle) as request:
                self.assertEqual(complete_rss_enrollment(), self.profile)
            request.assert_called_once()
        self.assertEqual(token_path.read_text(), bundle["rss_enrollment_token"])
        self.assertEqual(json.loads(self.profile.read_text()), original)

    def test_local_status_reports_pending_expiry_without_leaking_ret(self) -> None:
        token = self.token(expires_at=100)
        output = io.StringIO()
        with mock.patch(
            "secrets_kit.cli.commands.rss.load_rss_relay_credentials_from_environment",
            return_value=mock.Mock(
                entitlement_id="ent_test", connection_id="connection-preserved",
                enrollment_token=token,
            ),
        ), mock.patch("secrets_kit.protocol.rss_provisioning.time.time", return_value=200):
            with contextlib.redirect_stdout(output):
                self.assertEqual(cmd_rss_local_status(args=mock.Mock()), 0)
        self.assertTrue(json.loads(output.getvalue())["enrollment_token_expired"])
        self.assertNotIn(token, output.getvalue())

    def test_shared_qa_runtime_uses_embedded_operator_origin(self) -> None:
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "seckit-environment").write_text("qa\n", encoding="utf-8")
        origin = runtime / "seckit-rss-operator-url"
        origin.write_text("https://qa.example.test\n", encoding="utf-8")
        with mock.patch("secrets_kit.cli.commands.rss.sys.prefix", str(runtime)), mock.patch(
            "secrets_kit.cli.commands.rss._safe_install_state",
            return_value={"rss_operator_url": "https://previous-qa.example.test"},
        ):
            self.assertEqual(_installed_operator_url(), "https://qa.example.test")
            origin.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "origin is missing"):
                _installed_operator_url()
            origin.write_text("http://qa.example.test\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid installed RSS operator origin"):
                _installed_operator_url()

    def test_relay_peer_accepts_supported_hosts_and_tcp_ports(self) -> None:
        for host_protocol in ("dns4", "dns6", "ip4", "ip6"):
            for port in (1, 4001, 14001, 24001, 65535):
                with self.subTest(host_protocol=host_protocol, port=port):
                    self.assertTrue(
                        _valid_peer(
                            value=f"/{host_protocol}/relay.example.test/tcp/{port}/p2p/relay"
                        )
                    )

    def test_relay_peer_rejects_malformed_addresses(self) -> None:
        malformed = (
            None,
            "",
            "dns4/relay.example.test/tcp/4001/p2p/relay",
            "/dns/relay.example.test/tcp/4001/p2p/relay",
            "/dns4//tcp/4001/p2p/relay",
            "/dns4/relay.example.test/udp/4001/p2p/relay",
            "/dns4/relay.example.test/tcp//p2p/relay",
            "/dns4/relay.example.test/tcp/0/p2p/relay",
            "/dns4/relay.example.test/tcp/65536/p2p/relay",
            "/dns4/relay.example.test/tcp/-1/p2p/relay",
            "/dns4/relay.example.test/tcp/+1/p2p/relay",
            "/dns4/relay.example.test/tcp/1.0/p2p/relay",
            "/dns4/relay.example.test/tcp/١٤٠٠١/p2p/relay",
            "/dns4/relay.example.test/tcp/4001/ipfs/relay",
            "/dns4/relay.example.test/tcp/4001/p2p/",
            "/dns4/relay.example.test/tcp/4001/p2p/relay/extra",
            f"/dns4/{'h' * 2048}/tcp/4001/p2p/relay",
        )
        for value in malformed:
            with self.subTest(value=value):
                self.assertFalse(_valid_peer(value=value))

    def test_checkout_retains_private_receipt_without_ret(self) -> None:
        response = Response(
            {
                "account_id": "ska_test",
                "checkout_session_id": "cs_test_123",
                "checkout_url": "https://checkout.stripe.com/c/pay/cs_test_123",
            }
        )
        with mock.patch(
            "secrets_kit.protocol.rss_provisioning.urllib.request.urlopen",
            return_value=response,
        ):
            checkout_url, receipt = start_rss_checkout(connection_units=2)
        self.assertTrue(checkout_url.startswith("https://checkout.stripe.com/"))
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("ret1.", receipt.read_text(encoding="utf-8"))
        with self.assertRaises(FileExistsError):
            with mock.patch(
                "secrets_kit.protocol.rss_provisioning.urllib.request.urlopen",
                return_value=response,
            ):
                start_rss_checkout(connection_units=2)

    def test_checkout_sends_invite_only_to_operator_not_receipt(self) -> None:
        code = "ski_synthetic_test_invitation"
        response = Response(
            {
                "account_id": "ska_invited",
                "checkout_session_id": "cs_test_invited",
                "checkout_url": "https://checkout.stripe.com/c/pay/cs_test_invited",
            }
        )
        with mock.patch(
            "secrets_kit.protocol.rss_provisioning.urllib.request.urlopen",
            return_value=response,
        ) as request:
            _, receipt = start_rss_checkout(connection_units=2, invite_code=code)
        self.assertEqual(
            json.loads(request.call_args.args[0].data),
            {"connection_units": 2, "invite_code": code},
        )
        self.assertNotIn(code, receipt.read_text(encoding="utf-8"))

    def test_checkout_rejects_non_origin_operator_url_before_network(self) -> None:
        with mock.patch(
            "secrets_kit.protocol.rss_provisioning.urllib.request.urlopen"
        ) as request:
            with self.assertRaisesRegex(RSSAuthenticationError, "URL is invalid"):
                start_rss_checkout(
                    connection_units=2,
                    operator_url="https://seckit-ops.example.test/path",
                )
        request.assert_not_called()

    def test_paid_receipt_configures_complete_ordered_bundle_without_printing_ret(self) -> None:
        self.profile.parent.mkdir(mode=0o700, parents=True)
        receipt = self.profile.with_name("rss-checkout.json")
        receipt.write_text(
            json.dumps(
                {
                    "protocol": "rss_checkout_receipt/v1",
                    "operator_url": "https://seckit-ops.unixwzrd.net",
                    "account_id": "ska_test",
                    "checkout_session_id": "cs_test_123",
                }
            ),
            encoding="utf-8",
        )
        receipt.chmod(0o600)
        response = Response(
            {
                "protocol": "rss_provisioning_bundle/v1",
                "entitlement_id": "ent_test",
                "rss_enrollment_token": "ret1.opaque.signature",
                "enrollment_url": "https://seckit-ops.unixwzrd.net",
                "relay_peers": [
                    "/dns4/east.example.test/tcp/24001/p2p/east",
                    "/dns4/west.example.test/tcp/24001/p2p/west",
                ],
            }
        )
        with mock.patch(
            "secrets_kit.protocol.rss_provisioning.urllib.request.urlopen",
            return_value=response,
        ):
            configured = complete_rss_enrollment()
        self.assertEqual(configured, self.profile)
        value = json.loads(self.profile.read_text(encoding="utf-8"))
        self.assertEqual(value["entitlement_id"], "ent_test")
        self.assertEqual(value["relay_peers"][0].split("/")[2], "east.example.test")
        token = self.profile.with_name("rss-enrollment-token")
        self.assertEqual(token.stat().st_mode & 0o777, 0o600)

    def test_provisioning_rejects_unknown_fields_before_writing_token(self) -> None:
        self.profile.parent.mkdir(mode=0o700, parents=True)
        receipt = self.profile.with_name("rss-checkout.json")
        receipt.write_text(
            json.dumps(
                {
                    "protocol": "rss_checkout_receipt/v1",
                    "operator_url": "https://seckit-ops.unixwzrd.net",
                    "account_id": "ska_test",
                    "checkout_session_id": "cs_test_123",
                }
            ),
            encoding="utf-8",
        )
        receipt.chmod(0o600)
        with mock.patch(
            "secrets_kit.protocol.rss_provisioning.urllib.request.urlopen",
            return_value=Response({"unexpected": True}),
        ):
            with self.assertRaisesRegex(RSSAuthenticationError, "response is invalid"):
                complete_rss_enrollment()
        self.assertFalse(self.profile.with_name("rss-enrollment-token").exists())

    def test_interrupted_configuration_reuses_ret_without_second_operator_call(self) -> None:
        self.profile.parent.mkdir(mode=0o700, parents=True)
        receipt = self.profile.with_name("rss-checkout.json")
        receipt.write_text(
            json.dumps(
                {
                    "protocol": "rss_checkout_receipt/v1",
                    "operator_url": "https://seckit-ops.unixwzrd.net",
                    "account_id": "ska_test",
                    "checkout_session_id": "cs_test_123",
                }
            ),
            encoding="utf-8",
        )
        receipt.chmod(0o600)
        response = Response(
            {
                "protocol": "rss_provisioning_bundle/v1",
                "entitlement_id": "ent_test",
                "rss_enrollment_token": "ret1.opaque.signature",
                "enrollment_url": "https://seckit-ops.unixwzrd.net",
                "relay_peers": [
                    "/dns4/east.example.test/tcp/14001/p2p/east",
                    "/dns4/west.example.test/tcp/14001/p2p/west",
                ],
            }
        )
        with (
            mock.patch(
                "secrets_kit.protocol.rss_provisioning.urllib.request.urlopen",
                return_value=response,
            ),
            mock.patch(
                "secrets_kit.protocol.rss_provisioning.configure_rss_client",
                side_effect=RSSAuthenticationError("interrupted"),
            ),
            self.assertRaisesRegex(RSSAuthenticationError, "interrupted"),
        ):
            complete_rss_enrollment()
        state = self.profile.with_name("rss-provisioning.json")
        token = self.profile.with_name("rss-enrollment-token")
        self.assertTrue(state.exists())
        self.assertTrue(token.exists())
        with mock.patch("secrets_kit.protocol.rss_provisioning.urllib.request.urlopen") as request:
            complete_rss_enrollment()
        request.assert_not_called()
        self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
