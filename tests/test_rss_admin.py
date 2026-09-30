"""Owner-key lifecycle stays private and distinct from an RSS device key."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from secrets_kit.crypto.signatures import generate_ed25519_keypair
from secrets_kit.protocol.rss_admin import (
    admin_action,
    claim_customer_admin,
    finish_customer_admin_claim,
    pending_customer_admin_codes,
)
from secrets_kit.protocol.rss_auth import RSSAuthenticationError


class RSSAdminTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.profile = Path(self.temp.name) / "rss-client.json"
        self.addCleanup(mock.patch.stopall)
        mock.patch(
            "secrets_kit.protocol.rss_admin.rss_client_profile_path",
            return_value=self.profile,
        ).start()
        mock.patch(
            "secrets_kit.protocol.rss_admin.rss_checkout_receipt_path",
            return_value=self.profile.with_name("rss-checkout.json"),
        ).start()
        receipt = {
            "protocol": "rss_checkout_receipt/v1", "operator_url": "https://qa.example.test",
            "account_id": "ska_test", "checkout_session_id": "cs_test_paid",
        }
        path = self.profile.with_name("rss-checkout.json")
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o600)
        device_private, _ = generate_ed25519_keypair()
        mock.patch(
            "secrets_kit.protocol.rss_admin.load_rss_relay_credentials_from_environment",
            return_value=SimpleNamespace(
                enrollment_token=None, connection_id="connection-original",
                customer_private_key=device_private,
            ),
        ).start()

    def test_claim_persists_separate_key_and_one_time_codes(self) -> None:
        with mock.patch(
            "secrets_kit.protocol.rss_admin._post",
            return_value=(200, {"status": "claimed"}),
        ) as post:
            codes = claim_customer_admin()
        self.assertEqual(len(codes), 4)
        self.assertTrue(all(code.startswith("skr_") for code in codes))
        payload = post.call_args.kwargs["body"]["payload"]
        self.assertEqual(payload["connection_id"], "connection-original")
        self.assertNotIn("recovery_codes", payload)
        self.assertEqual(pending_customer_admin_codes(), codes)
        owner = json.loads(self.profile.with_name("rss-admin-key.json").read_text())
        self.assertNotIn("recovery_codes", owner)
        self.assertEqual(self.profile.with_name("rss-admin-key.json").stat().st_mode & 0o077, 0)
        finish_customer_admin_claim()
        self.assertIsNone(pending_customer_admin_codes())
        with mock.patch(
            "secrets_kit.protocol.rss_admin._post",
            return_value=(200, {"devices": [], "capacity": {}}),
        ) as action_post:
            status, _ = admin_action(action="devices.list", parameters={})
        self.assertEqual(status, 200)
        self.assertEqual(action_post.call_args.kwargs["body"]["payload"]["account_id"], "ska_test")

    def test_lost_claim_reply_reuses_protected_pending_key_and_codes(self) -> None:
        with mock.patch(
            "secrets_kit.protocol.rss_admin._post",
            side_effect=RSSAuthenticationError("reply lost"),
        ):
            with self.assertRaises(RSSAuthenticationError):
                claim_customer_admin()
        pending = self.profile.with_name("rss-admin-pending.json")
        original = json.loads(pending.read_text())
        with mock.patch(
            "secrets_kit.protocol.rss_admin._post",
            return_value=(200, {"status": "claimed"}),
        ):
            codes = claim_customer_admin()
        self.assertEqual(codes, tuple(original["recovery_codes"]))
        self.assertEqual(
            json.loads(pending.read_text())["public_key"], original["public_key"]
        )


if __name__ == "__main__":
    unittest.main()
