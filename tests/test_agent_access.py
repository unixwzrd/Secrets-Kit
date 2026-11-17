"""
tests.test_agent_access

Verify the read-only runtime access boundary and secret redaction behavior.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite.node_identity import ensure_sqlite_node_identity
from secrets_kit.backends.sqlite.provisioning import provision_sqlite_datastore
from secrets_kit.crypto.storage.sqlite import ensure_sqlite_storage_key
from secrets_kit.daemon.client import DaemonError, request_secret_metadata, request_secret_value
from secrets_kit.daemon.control import runtime_access_message_bytes
from secrets_kit.daemon.server import _handle_request
from secrets_kit.models import EntryMetadata
from secrets_kit.runtime.agent_access import handle_runtime_access_request

SECRET = "do-not-log-or-echo-this-value"


class RuntimeAgentAccessTest(unittest.TestCase):
    """Exercise metadata and explicit materialization at runtime authority."""

    def test_metadata_projection_excludes_value_and_sensitive_freeform_fields(self) -> None:
        metadata = EntryMetadata(
            entry_id="entry:00000000-0000-0000-0000-000000000001",
            name="API_TOKEN",
            service="hermes",
            account="beta",
            comment=SECRET,
            source_url=f"https://{SECRET}.invalid",
            custom={"private_note": SECRET},
        )
        request = runtime_access_message_bytes(
            operation="list_metadata", arguments={"backend": "sqlite"}
        )
        with mock.patch(
            "secrets_kit.runtime.agent_access.list_secret_metadata", return_value=[metadata]
        ):
            response = handle_runtime_access_request(data=request)
        self.assertNotIn(SECRET.encode(), response)
        payload = json.loads(response)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["data"]["entries"][0]["name"], "API_TOKEN")
        self.assertNotIn("comment", payload["data"]["entries"][0])
        self.assertNotIn("custom", payload["data"]["entries"][0])

    def test_resolve_materializes_only_for_explicit_operation(self) -> None:
        request = runtime_access_message_bytes(
            operation="resolve_secret",
            arguments={
                "backend": "sqlite",
                "service": "hermes",
                "account": "beta",
                "name": "API_TOKEN",
            },
        )
        with mock.patch(
            "secrets_kit.runtime.agent_access.read_secret_value", return_value=SECRET
        ) as read, mock.patch(
            "secrets_kit.runtime.agent_access.read_metadata_for_backend",
            return_value=EntryMetadata(name="API_TOKEN", service="hermes", account="beta"),
        ):
            payload = json.loads(handle_runtime_access_request(data=request))
        self.assertEqual(payload["data"]["value"], SECRET)
        read.assert_called_once_with(
            backend="sqlite", service="hermes", account="beta", name="API_TOKEN"
        )

    def test_backend_failure_is_redacted(self) -> None:
        request = runtime_access_message_bytes(
            operation="resolve_secret",
            arguments={
                "backend": "sqlite",
                "service": "hermes",
                "account": "beta",
                "name": "API_TOKEN",
            },
        )
        with mock.patch(
            "secrets_kit.runtime.agent_access.read_secret_value",
            side_effect=RuntimeError(f"backend failed near {SECRET}"),
        ), mock.patch(
            "secrets_kit.runtime.agent_access.read_metadata_for_backend",
            return_value=EntryMetadata(name="API_TOKEN", service="hermes", account="beta"),
        ):
            response = handle_runtime_access_request(data=request)
        self.assertNotIn(SECRET.encode(), response)
        self.assertEqual(json.loads(response)["error"], "access_denied_or_unavailable")

    def test_missing_secret_has_clear_safe_error(self) -> None:
        request = runtime_access_message_bytes(
            operation="resolve_secret",
            arguments={
                "backend": "sqlite",
                "service": "hermes",
                "account": "beta",
                "name": "MISSING_TOKEN",
            },
        )
        with mock.patch(
            "secrets_kit.runtime.agent_access.read_metadata_for_backend", return_value=None
        ), mock.patch("secrets_kit.runtime.agent_access.read_secret_value") as read:
            response = handle_runtime_access_request(data=request)
        self.assertEqual(json.loads(response)["error"], "not_found")
        read.assert_not_called()

    def test_sqlite_writes_use_atomic_revisions_and_never_echo_values(self) -> None:
        for storage_mode in ("plaintext", "encrypted"):
            with self.subTest(storage_mode=storage_mode), tempfile.TemporaryDirectory() as raw:
                home = Path(raw)
                database = home / "seckit.sqlite"
                env = {
                    "HOME": str(home),
                    "SECKIT_SQLITE_PATH": str(database),
                    "SECKIT_SQLITE_STORAGE_MODE": storage_mode,
                }
                if storage_mode == "encrypted":
                    env["SECKIT_SQLITE_STORAGE_KEY_PATH"] = str(home / "sqlite-storage.key")
                with mock.patch.dict(os.environ, env, clear=True):
                    if storage_mode == "encrypted":
                        ensure_sqlite_storage_key(home=home)
                    conn = provision_sqlite_datastore(path=database, storage_mode=storage_mode)
                    ensure_sqlite_node_identity(conn=conn, home=home)
                    conn.close()

                    def request(operation: str, **arguments: object) -> dict[str, object]:
                        encoded = runtime_access_message_bytes(
                            operation=operation,
                            arguments={
                                "backend": "sqlite",
                                "service": "hermes",
                                "account": "qa",
                                "name": "API_TOKEN",
                                **arguments,
                            },
                        )
                        response = handle_runtime_access_request(data=encoded)
                        self.assertNotIn(SECRET.encode(), response)
                        return json.loads(response)

                    created = request("create_secret", value=SECRET)
                    self.assertEqual(created["status"], "ok")
                    first_revision = created["data"]["revision"]
                    self.assertRegex(first_revision, r"^rev1:[0-9a-f]{64}$")
                    duplicate = request("create_secret", value=SECRET)
                    self.assertEqual(duplicate["error"], "secret_already_exists")
                    oversized = request("create_secret", value="x" * 262_145)
                    self.assertEqual(oversized["error"], "invalid_value")

                    listed = json.loads(
                        handle_runtime_access_request(
                            data=runtime_access_message_bytes(
                                operation="list_metadata",
                                arguments={
                                    "backend": "sqlite",
                                    "service": "hermes",
                                    "account": "qa",
                                    "revision_names": ["API_TOKEN"],
                                },
                            )
                        )
                    )
                    self.assertEqual(
                        listed["data"]["entries"][0]["revision"], first_revision
                    )

                    updated = request("update_secret", value=SECRET, revision=first_revision)
                    second_revision = updated["data"]["revision"]
                    self.assertNotEqual(first_revision, second_revision)
                    stale = request("delete_secret", revision=first_revision)
                    self.assertEqual(stale["error"], "secret_revision_conflict")

                    deleted = request("delete_secret", revision=second_revision)
                    self.assertEqual(deleted["data"], {"deleted": True})
                    missing = request("resolve_secret")
                    self.assertEqual(missing["error"], "not_found")


class DaemonAgentAccessBoundaryTest(unittest.TestCase):
    """Prove the daemon forwards local frames and rejects remote access."""

    def test_uds_access_request_is_forwarded_opaque(self) -> None:
        request = runtime_access_message_bytes(
            operation="resolve_secret",
            arguments={
                "backend": "sqlite",
                "service": "hermes",
                "account": "beta",
                "name": "API_TOKEN",
            },
        )
        response = b'{"version":1,"status":"ok","data":{"value":"returned"}}'
        with mock.patch(
            "secrets_kit.daemon.server._invoke_runtime_access", return_value=response
        ) as invoke:
            actual, should_stop = _handle_request(request, transport="uds")
        self.assertFalse(should_stop)
        self.assertEqual(actual, response)
        invoke.assert_called_once_with(data=request)

    def test_tcp_access_request_is_forbidden_without_runtime_invocation(self) -> None:
        request = runtime_access_message_bytes(
            operation="list_metadata", arguments={"backend": "sqlite"}
        )
        with mock.patch("secrets_kit.daemon.server._invoke_runtime_access") as invoke:
            response, should_stop = _handle_request(request, transport="tcp")
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["error"], "runtime_access_forbidden")
        invoke.assert_not_called()


class DaemonAgentClientTest(unittest.TestCase):
    """Validate stable client contracts without exposing daemon details."""

    def test_client_lists_metadata(self) -> None:
        with mock.patch(
            "secrets_kit.daemon.client._request_socket",
            return_value={"status": "ok", "data": {"entries": [{"name": "API_TOKEN"}]}},
        ):
            self.assertEqual(
                request_secret_metadata(backend="sqlite"), [{"name": "API_TOKEN"}]
            )

    def test_client_rejects_unexpected_metadata_fields(self) -> None:
        with mock.patch(
            "secrets_kit.daemon.client._request_socket",
            return_value={
                "status": "ok",
                "data": {"entries": [{"name": "API_TOKEN", "value": SECRET}]},
            },
        ):
            with self.assertRaisesRegex(DaemonError, "unsafe metadata"):
                request_secret_metadata(backend="sqlite")

    def test_client_rejects_failed_materialization_without_details(self) -> None:
        with mock.patch(
            "secrets_kit.daemon.client._request_socket",
            return_value={"status": "error", "error": "access_denied_or_unavailable"},
        ):
            with self.assertRaisesRegex(DaemonError, "access_denied_or_unavailable"):
                request_secret_value(
                    backend="sqlite", service="hermes", account="beta", name="API_TOKEN"
                )


if __name__ == "__main__":
    unittest.main()
