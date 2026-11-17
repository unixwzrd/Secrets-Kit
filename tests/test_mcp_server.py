"""
tests.test_mcp_server

Verify the Secrets Kit MCP surface and model-visible redaction boundaries.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.daemon.client import DaemonError
from secrets_kit.mcp_server import McpPolicy, McpPolicyError, handle_message, load_policy, main

SECRET = "never-visible-except-explicit-get"
POLICY = McpPolicy(
    backend="sqlite",
    service="hermes",
    account="beta",
    metadata_names=frozenset({"API_TOKEN"}),
    retrieval_names=frozenset({"API_TOKEN"}),
)
WRITE_POLICY = McpPolicy(
    backend="sqlite",
    service="hermes",
    account="beta",
    metadata_names=frozenset({"API_TOKEN", "CREATE_TOKEN"}),
    retrieval_names=frozenset(),
    policy_version=2,
    create_names=frozenset({"CREATE_TOKEN"}),
    update_names=frozenset({"API_TOKEN"}),
    delete_names=frozenset({"API_TOKEN"}),
)
REVISION = "rev1:" + "a" * 64


def _request(*, request_id: int, method: str, params: object | None = None) -> dict[str, object]:
    value: dict[str, object] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        value["params"] = params
    return value


class McpServerTest(unittest.TestCase):
    """Exercise discovery, listing, explicit retrieval, and safe errors."""

    def test_initialize_and_tools_are_read_only(self) -> None:
        initialized = handle_message(_request(request_id=1, method="initialize", params={}))
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "secrets-kit")
        response = handle_message(_request(request_id=2, method="tools/list"))
        tools = response["result"]["tools"]
        self.assertEqual(
            [tool["name"] for tool in tools],
            ["seckit_status", "seckit_list_secrets", "seckit_get_secret"],
        )
        self.assertTrue(all(tool["annotations"]["readOnlyHint"] for tool in tools))
        self.assertEqual(tools[1]["inputSchema"]["properties"], {})
        self.assertEqual(set(tools[2]["inputSchema"]["properties"]), {"name"})
        self.assertNotIn(SECRET, json.dumps(response))

    def test_listing_returns_metadata_without_value(self) -> None:
        entries = [
            {"name": "API_TOKEN", "service": "hermes", "account": "beta"},
            {"name": "OTHER_TOKEN", "service": "hermes", "account": "beta"},
        ]
        with mock.patch(
            "secrets_kit.mcp_server.request_secret_metadata", return_value=entries
        ) as list_mock:
            response = handle_message(
                _request(
                    request_id=3,
                    method="tools/call",
                    params={"name": "seckit_list_secrets", "arguments": {}},
                ),
                policy=POLICY,
            )
        self.assertEqual(response["result"]["structuredContent"], {"entries": entries[:1]})
        self.assertNotIn("value", response["result"]["structuredContent"])
        list_mock.assert_called_once_with(
            backend="sqlite", service="hermes", account="beta", revision_names=[]
        )

    def test_v2_tools_are_opt_in_and_exactly_granted(self) -> None:
        tools = handle_message(
            _request(request_id=30, method="tools/list"), policy=WRITE_POLICY
        )["result"]["tools"]
        self.assertEqual(
            [tool["name"] for tool in tools],
            [
                "seckit_status",
                "seckit_list_secrets",
                "seckit_get_secret",
                "seckit_create_secret",
                "seckit_update_secret",
                "seckit_delete_secret",
            ],
        )
        self.assertEqual(
            tools[3]["inputSchema"]["properties"]["name"]["enum"], ["CREATE_TOKEN"]
        )
        self.assertEqual(
            tools[4]["inputSchema"]["properties"]["name"]["enum"], ["API_TOKEN"]
        )
        self.assertFalse(tools[3]["annotations"]["readOnlyHint"])

    def test_v2_create_and_update_use_fixed_scope_without_reflecting_value(self) -> None:
        with mock.patch(
            "secrets_kit.mcp_server.request_secret_create", return_value=REVISION
        ) as create, mock.patch(
            "secrets_kit.mcp_server.request_secret_update", return_value=REVISION
        ) as update:
            created = handle_message(
                _request(
                    request_id=31,
                    method="tools/call",
                    params={
                        "name": "seckit_create_secret",
                        "arguments": {"name": "CREATE_TOKEN", "value": SECRET},
                    },
                ),
                policy=WRITE_POLICY,
            )
            changed = handle_message(
                _request(
                    request_id=32,
                    method="tools/call",
                    params={
                        "name": "seckit_update_secret",
                        "arguments": {
                            "name": "API_TOKEN",
                            "value": SECRET,
                            "revision": REVISION,
                        },
                    },
                ),
                policy=WRITE_POLICY,
            )
        self.assertNotIn(SECRET, json.dumps(created))
        self.assertNotIn(SECRET, json.dumps(changed))
        self.assertEqual(
            created["result"]["structuredContent"],
            {"created": True, "revision": REVISION},
        )
        self.assertEqual(
            changed["result"]["structuredContent"],
            {"updated": True, "revision": REVISION},
        )
        create.assert_called_once_with(
            service="hermes", account="beta", name="CREATE_TOKEN", value=SECRET
        )
        update.assert_called_once_with(
            service="hermes",
            account="beta",
            name="API_TOKEN",
            value=SECRET,
            revision=REVISION,
        )

    def test_v2_denies_ungranted_name_scope_override_and_v1_writes(self) -> None:
        with mock.patch("secrets_kit.mcp_server.request_secret_create") as create:
            ungranted = handle_message(
                _request(
                    request_id=33,
                    method="tools/call",
                    params={
                        "name": "seckit_create_secret",
                        "arguments": {"name": "API_TOKEN", "value": SECRET},
                    },
                ),
                policy=WRITE_POLICY,
            )
            scope_override = handle_message(
                _request(
                    request_id=34,
                    method="tools/call",
                    params={
                        "name": "seckit_create_secret",
                        "arguments": {
                            "name": "CREATE_TOKEN",
                            "value": SECRET,
                            "service": "other",
                        },
                    },
                ),
                policy=WRITE_POLICY,
            )
            v1 = handle_message(
                _request(
                    request_id=35,
                    method="tools/call",
                    params={
                        "name": "seckit_create_secret",
                        "arguments": {"name": "CREATE_TOKEN", "value": SECRET},
                    },
                ),
                policy=POLICY,
            )
        self.assertTrue(ungranted["result"]["isError"])
        self.assertTrue(scope_override["result"]["isError"])
        self.assertTrue(v1["result"]["isError"])
        create.assert_not_called()

    def test_v2_delete_uses_revision_and_never_returns_secret(self) -> None:
        with mock.patch("secrets_kit.mcp_server.request_secret_delete") as delete:
            response = handle_message(
                _request(
                    request_id=36,
                    method="tools/call",
                    params={
                        "name": "seckit_delete_secret",
                        "arguments": {"name": "API_TOKEN", "revision": REVISION},
                    },
                ),
                policy=WRITE_POLICY,
            )
        delete.assert_called_once_with(
            service="hermes", account="beta", name="API_TOKEN", revision=REVISION
        )
        self.assertEqual(response["result"]["structuredContent"], {"deleted": True})

    def test_v2_metadata_requests_revisions_only_for_update_and_delete_grants(self) -> None:
        entries = [
            {"name": "API_TOKEN", "service": "hermes", "account": "beta", "revision": REVISION},
            {"name": "CREATE_TOKEN", "service": "hermes", "account": "beta", "revision": REVISION},
        ]
        with mock.patch(
            "secrets_kit.mcp_server.request_secret_metadata", return_value=entries
        ) as listing:
            response = handle_message(
                _request(
                    request_id=37,
                    method="tools/call",
                    params={"name": "seckit_list_secrets", "arguments": {}},
                ),
                policy=WRITE_POLICY,
            )
        listing.assert_called_once_with(
            backend="sqlite",
            service="hermes",
            account="beta",
            revision_names=["API_TOKEN"],
        )
        output = response["result"]["structuredContent"]["entries"]
        self.assertIn("revision", output[0])
        self.assertNotIn("revision", output[1])

    def test_status_separates_daemon_health_from_peer_discovery(self) -> None:
        status = {
            "overall": "WAITING FOR PEERS",
            "daemon_health": "healthy",
            "peer_discovery": "waiting",
            "backend": "sqlite",
            "daemon": {"running": True},
        }
        with mock.patch("secrets_kit.mcp_server.request_daemon_status", return_value=status) as status_mock:
            response = handle_message(
                _request(
                    request_id=6,
                    method="tools/call",
                    params={"name": "seckit_status", "arguments": {}},
                ),
                policy=POLICY,
            )
        content = response["result"]["structuredContent"]
        status_mock.assert_called_once_with(timeout=5.0)
        self.assertEqual(content["overall"], "WAITING FOR PEERS")
        self.assertEqual(content["daemon_health"], "healthy")
        self.assertEqual(content["peer_discovery"], "waiting")

    def test_explicit_get_returns_requested_value(self) -> None:
        with mock.patch(
            "secrets_kit.mcp_server.request_secret_value", return_value=SECRET
        ) as get_mock:
            response = handle_message(
                _request(
                    request_id=4,
                    method="tools/call",
                    params={
                        "name": "seckit_get_secret",
                        "arguments": {"name": "API_TOKEN"},
                    },
                ),
                policy=POLICY,
            )
        self.assertEqual(response["result"]["structuredContent"]["value"], SECRET)
        get_mock.assert_called_once_with(
            backend="sqlite", service="hermes", account="beta", name="API_TOKEN"
        )

    def test_daemon_error_does_not_reflect_sensitive_details(self) -> None:
        with mock.patch(
            "secrets_kit.mcp_server.request_secret_value",
            side_effect=DaemonError(f"failure included {SECRET}"),
        ):
            response = handle_message(
                _request(
                    request_id=5,
                    method="tools/call",
                    params={
                        "name": "seckit_get_secret",
                        "arguments": {"name": "API_TOKEN"},
                    },
                ),
                policy=POLICY,
            )
        self.assertTrue(response["result"]["isError"])
        self.assertNotIn(SECRET, json.dumps(response))

    def test_missing_policy_and_unapproved_retrieval_fail_closed(self) -> None:
        request = _request(
            request_id=7,
            method="tools/call",
            params={"name": "seckit_get_secret", "arguments": {"name": "API_TOKEN"}},
        )
        without_policy = handle_message(request)
        self.assertTrue(without_policy["result"]["isError"])
        metadata_only = McpPolicy(
            backend="sqlite",
            service="hermes",
            account="beta",
            metadata_names=frozenset({"API_TOKEN"}),
            retrieval_names=frozenset(),
        )
        with mock.patch("secrets_kit.mcp_server.request_secret_value") as get_mock:
            denied = handle_message(request, policy=metadata_only)
        self.assertTrue(denied["result"]["isError"])
        get_mock.assert_not_called()

    def test_policy_loader_requires_owner_only_file_and_fixed_subset(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "mcp-policy.json"
            payload = {
                "version": 1,
                "backend": "sqlite",
                "service": "hermes",
                "account": "beta",
                "metadata_names": ["API_TOKEN", "OTHER_TOKEN"],
                "retrieval_names": ["API_TOKEN"],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            policy = load_policy(path)
            self.assertEqual(policy.metadata_names, frozenset({"API_TOKEN", "OTHER_TOKEN"}))
            self.assertEqual(policy.retrieval_names, frozenset({"API_TOKEN"}))

            payload["backend"] = "keychain"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(McpPolicyError, "migrate credentials"):
                load_policy(path)
            payload["backend"] = "sqlite"
            path.write_text(json.dumps(payload), encoding="utf-8")

            path.chmod(0o644)
            with self.assertRaises(McpPolicyError):
                load_policy(path)
            path.chmod(0o600)
            payload["retrieval_names"] = ["NOT_IN_METADATA"]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(McpPolicyError):
                load_policy(path)

    def test_policy_loader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            link = root / "mcp-policy.json"
            os.symlink(target, link)
            with self.assertRaises(McpPolicyError):
                load_policy(link)

    def test_policy_loader_accepts_v2_exact_write_names_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "mcp-policy.json"
            payload = {
                "version": 2,
                "backend": "sqlite",
                "service": "hermes",
                "account": "beta",
                "metadata_names": ["API_TOKEN"],
                "retrieval_names": [],
                "create_names": [],
                "update_names": ["API_TOKEN"],
                "delete_names": [],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            policy = load_policy(path)
            self.assertEqual(policy.policy_version, 2)
            self.assertEqual(policy.update_names, frozenset({"API_TOKEN"}))
            payload["update_names"] = ["UNLISTED"]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(McpPolicyError):
                load_policy(path)

    def test_stdio_server_requires_policy_before_processing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            missing = Path(raw) / "missing.json"
            err = io.StringIO()
            with mock.patch("sys.argv", ["seckit-mcp", "--policy", str(missing)]), redirect_stderr(err):
                code = main()
        self.assertEqual(code, 78)
        self.assertEqual(err.getvalue(), "Secrets Kit MCP policy is unavailable or invalid\n")

    def test_stdio_server_initializes_with_valid_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "mcp-policy.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "backend": "sqlite",
                        "service": "hermes",
                        "account": "beta",
                        "metadata_names": ["API_TOKEN"],
                        "retrieval_names": [],
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
            request = json.dumps(_request(request_id=9, method="initialize")) + "\n"
            out = io.StringIO()
            with (
                mock.patch("sys.argv", ["seckit-mcp", "--policy", str(path)]),
                mock.patch("sys.stdin", io.StringIO(request)),
                redirect_stdout(out),
            ):
                code = main()
        self.assertEqual(code, 0)
        response = json.loads(out.getvalue())
        self.assertEqual(response["result"]["serverInfo"]["name"], "secrets-kit")


if __name__ == "__main__":
    unittest.main()
