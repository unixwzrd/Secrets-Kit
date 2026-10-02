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
from secrets_kit.protocol.rss_auth import RSSAuthenticationError
from secrets_kit.protocol.rss_provisioning import (
    _valid_peer,
    complete_rss_enrollment,
    configure_rss_provisioning_bundle,
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
            "key_file": str(key_path), "enrollment_token_file": str(token_path),
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
