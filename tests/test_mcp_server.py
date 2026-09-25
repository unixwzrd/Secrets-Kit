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
        list_mock.assert_called_once_with(backend="sqlite", service="hermes", account="beta")

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
