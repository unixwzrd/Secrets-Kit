"""Customer Checkout receipt and deterministic enrollment tests."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.protocol.rss_auth import RSSAuthenticationError
from secrets_kit.protocol.rss_provisioning import (
    _valid_peer,
    complete_rss_enrollment,
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
