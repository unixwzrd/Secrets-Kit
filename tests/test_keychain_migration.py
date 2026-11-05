"""Synthetic, isolated Keychain-to-SQLite migration security regressions."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secrets_kit.backends.common import BackendError, normalize_backend
from secrets_kit.backends.keychain.security_cli import SecurityCliStore
from secrets_kit.backends.sqlite import get_sqlite_secret_entry, secrets_api
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.secrets_api import (
    authorize_existing_sqlite_secret_for_sync,
    delete_sqlite_secret,
    import_sqlite_secret_local,
)
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.cli.commands.migrate import cmd_migrate_keychain
from secrets_kit.cli.keychain_migration import MigrationError, inventory_keychain, read_legacy_value
from secrets_kit.cli.main import _daemon_events_after_success
from secrets_kit.cli.parser import build_parser
from secrets_kit.identifiers import deterministic_identifier
from secrets_kit.models import EntryMetadata


class KeychainMigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "home"
        self.source = Path(self.temp.name) / "synthetic.keychain-db"
        self.source.write_bytes(b"original synthetic Keychain fixture")
        self.home_patch = mock.patch("pathlib.Path.home", return_value=self.home)
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.env_patch = mock.patch.dict(os.environ, {}, clear=False)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        for key in (
            "SECKIT_SQLITE_PATH",
            "SECKIT_SQLITE_STORAGE_KEY",
            "SECKIT_SQLITE_NODE_IDENTITY_KEY",
        ):
            os.environ.pop(key, None)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(
                cmd_init_operator(
                    args=argparse.Namespace(
                        yes=True, home=str(self.home), init_target=None, backend="sqlite"
                    )
                ),
                0,
            )

    def _dump(self, *items: tuple[str, str | None]) -> bytes:
        blocks = []
        for name, comment in items:
            lines = [
                f'keychain: "{self.source}"',
                'class: "genp"',
                "attributes:",
                '    "acct"<blob>="acct"',
                f'    "svce"<blob>="svc:{name}"',
            ]
            if comment is not None:
                lines.append(f'    "icmt"<blob>={json.dumps(comment)}')
            else:
                lines.append('    "icmt"<blob>=<NULL>')
            blocks.append("\n".join(lines))
        return ("\n".join(blocks) + "\n").encode()

    def _run(self, *items: tuple[str, str | None], values: dict[str, str] | None = None):
        values = values or {}
        calls: list[list[str]] = []

        def fake_run(kind, *, target=None, inventory=None, item=None):
            if kind == "dump":
                calls.append(["security", "dump-keychain", str(target)])
                return self._dump(*items), b""
            assert item is not None
            calls.append(["Security.framework", item.metadata.account, item.metadata.name])
            if item.metadata.name not in values:
                raise MigrationError("Keychain value read failed")
            return values[item.metadata.name]

        return calls, fake_run

    @contextmanager
    def _mock_legacy(self, fake):
        with (
            mock.patch(
                "secrets_kit.cli.keychain_migration._bounded_inventory_output",
                side_effect=lambda *, target: fake("dump", target=target),
            ),
            mock.patch(
                "secrets_kit.cli.commands.migrate.read_legacy_value",
                side_effect=lambda *, inventory, item: fake(
                    "read", inventory=inventory, item=item
                ),
            ),
        ):
            yield

    def _command(
        self, *, apply: bool = False, authorize_sync: bool = False
    ) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = cmd_migrate_keychain(
                args=argparse.Namespace(
                    keychain=str(self.source),
                    service="svc",
                    account="acct",
                    apply=apply,
                    authorize_sync=authorize_sync,
                )
            )
        return result, stdout.getvalue(), stderr.getvalue()

    def test_inventory_reads_no_values_and_never_changes_source(self) -> None:
        original = self.source.read_bytes()
        calls, fake = self._run(("ALPHA", None), values={"ALPHA": "private synthetic value"})
        with self._mock_legacy(fake):
            code, output, error = self._command()
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], "dump-keychain")
        self.assertEqual(json.loads(output)["items"], [{"name": "ALPHA", "target": "absent"}])
        self.assertNotIn("private synthetic value", output)
        self.assertEqual(self.source.read_bytes(), original)

    def test_apply_preserves_metadata_is_idempotent_and_queues_no_envelopes(self) -> None:
        metadata = EntryMetadata(
            name="ALPHA", service="svc", account="acct", source="legacy", comment="note"
        )
        secret = " leading and trailing synthetic value "
        calls, fake = self._run(("ALPHA", json.dumps(metadata.to_dict())), values={"ALPHA": secret})
        with (
            self._mock_legacy(fake),
            mock.patch(
                "secrets_kit.backends.sqlite.transaction_engine.persist_outbound_envelopes_for_configured_peers"
            ) as outbound,
        ):
            first = self._command(apply=True)
            second = self._command(apply=True)
        self.assertEqual(first[0], 0, first)
        self.assertEqual(second[0], 0, second)
        self.assertEqual(json.loads(first[1])["copied"], 1)
        self.assertEqual(json.loads(second[1])["skipped"], 1)
        outbound.assert_not_called()
        self.assertEqual(
            get_sqlite_secret_entry(service="svc", account="acct", name="ALPHA")[0], secret
        )
        conn = open_sqlite_backend()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0], 0)
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM transactions WHERE transaction_type = 'secret.set'"
                ).fetchone()[0],
                1,
            )
        finally:
            conn.close()
        self.assertTrue(all(secret not in " ".join(argv) for argv in calls))
        self.assertTrue(
            all(secret not in stream for result in (first, second) for stream in result[1:])
        )
        self.assertEqual(self.source.read_bytes(), b"original synthetic Keychain fixture")

    def test_conflict_stops_before_any_copy(self) -> None:
        metadata = EntryMetadata(
            name="ALPHA", service="svc", account="acct", source="keychain-migration"
        )
        import_sqlite_secret_local(
            service="svc", account="acct", name="ALPHA", value="existing", metadata=metadata
        )
        calls, fake = self._run(
            ("ALPHA", None), ("BETA", None), values={"ALPHA": "different", "BETA": "new"}
        )
        with self._mock_legacy(fake):
            code, output, error = self._command(apply=True)
        self.assertEqual(code, 1)
        self.assertIn("conflicts", error)
        self.assertFalse(any("BETA" in " ".join(argv) for argv in calls))
        conn = open_sqlite_backend()
        try:
            self.assertIsNone(conn.execute("SELECT 1 FROM secrets WHERE name = 'BETA'").fetchone())
        finally:
            conn.close()
        self.assertEqual(output, "")

    def test_deleted_sqlite_identity_is_never_recreated_by_migration(self) -> None:
        metadata = EntryMetadata(
            name="ALPHA", service="svc", account="acct", source="keychain-migration"
        )
        import_sqlite_secret_local(
            service="svc", account="acct", name="ALPHA", value="old", metadata=metadata
        )
        delete_sqlite_secret(service="svc", account="acct", name="ALPHA", metadata=metadata)
        calls, fake = self._run(("ALPHA", None), values={"ALPHA": "new"})
        with self._mock_legacy(fake):
            result = self._command(apply=True)
        self.assertEqual(result[0], 1)
        self.assertIn("deleted or unsupported identity", result[2])
        self.assertEqual(len(calls), 1)

    def test_retained_history_blocks_a_missing_projection(self) -> None:
        metadata = EntryMetadata(
            name="ALPHA", service="svc", account="acct", source="keychain-migration"
        )
        import_sqlite_secret_local(
            service="svc", account="acct", name="ALPHA", value="old", metadata=metadata
        )
        conn = open_sqlite_backend()
        try:
            conn.execute("DELETE FROM secrets WHERE name = 'ALPHA'")
        finally:
            conn.close()
        calls, fake = self._run(("ALPHA", None), values={"ALPHA": "new"})
        with self._mock_legacy(fake):
            result = self._command(apply=True)
        self.assertEqual(result[0], 1)
        self.assertIn("originals remain", result[2])
        self.assertTrue(any(argv[0] == "Security.framework" for argv in calls))
        conn = open_sqlite_backend()
        try:
            self.assertIsNone(conn.execute("SELECT 1 FROM secrets WHERE name = 'ALPHA'").fetchone())
        finally:
            conn.close()

    def test_duplicate_keychain_identity_stops_without_value_read(self) -> None:
        calls, fake = self._run(("ALPHA", None), ("ALPHA", None), values={"ALPHA": "new"})
        with self._mock_legacy(fake):
            result = self._command(apply=True)
        self.assertEqual(result[0], 1)
        self.assertEqual(len(calls), 1)

    def test_partial_failure_reports_counts_and_reruns_safely(self) -> None:
        calls, fake = self._run(("ALPHA", None), ("BETA", None), values={"ALPHA": "alpha"})
        with self._mock_legacy(fake):
            first = self._command(apply=True)
        self.assertEqual(first[0], 1)
        self.assertEqual(json.loads(first[1])["copied"], 1)
        self.assertIn("originals remain", first[2])
        calls, fake = self._run(
            ("ALPHA", None), ("BETA", None), values={"ALPHA": "alpha", "BETA": "beta"}
        )
        with self._mock_legacy(fake):
            second = self._command(apply=True)
        self.assertEqual(second[0], 0, second)
        self.assertEqual(json.loads(second[1])["skipped"], 1)
        self.assertEqual(json.loads(second[1])["copied"], 1)

    def test_partial_sync_authorization_waits_for_complete_verified_copy(self) -> None:
        calls, fake = self._run(("ALPHA", None), ("BETA", None), values={"ALPHA": "alpha"})
        with self._mock_legacy(fake), mock.patch(
            "secrets_kit.backends.sqlite.secrets_api.persist_outbound_envelopes_for_configured_peers"
        ) as outbound:
            first = self._command(apply=True, authorize_sync=True)
        self.assertEqual(first[0], 1)
        self.assertEqual(json.loads(first[1])["copied"], 1)
        outbound.assert_not_called()
        calls, fake = self._run(
            ("ALPHA", None), ("BETA", None), values={"ALPHA": "alpha", "BETA": "beta"}
        )
        with self._mock_legacy(fake), mock.patch(
            "secrets_kit.backends.sqlite.secrets_api.persist_outbound_envelopes_for_configured_peers"
        ) as outbound:
            second = self._command(apply=True, authorize_sync=True)
        self.assertEqual(second[0], 0, second)
        self.assertEqual(json.loads(second[1])["skipped"], 1)
        self.assertGreaterEqual(outbound.call_count, 6)

    def test_dry_run_inventory_before_sqlite_initialization(self) -> None:
        _, fake = self._run(("ALPHA", None))
        with self._mock_legacy(fake), mock.patch(
            "secrets_kit.cli.commands.migrate.require_encrypted_sqlite_target",
            side_effect=MigrationError("target unavailable"),
        ):
            code, output, error = self._command()
        self.assertEqual((code, error), (0, ""))
        self.assertFalse(json.loads(output)["target_ready"])
        self.assertEqual(json.loads(output)["items"][0]["target"], "unavailable")

    def test_ambiguous_comment_fails_closed_without_value_read(self) -> None:
        calls, fake = self._run(
            ("ALPHA", '{"name":"ALPHA","service":"svc","account":"acct","unknown":1}'),
            values={"ALPHA": "secret"},
        )
        with self._mock_legacy(fake):
            code, output, _ = self._command(apply=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(output, "")

    def test_sync_authorization_is_explicit_and_can_queue_retained_history(self) -> None:
        calls, fake = self._run(("ALPHA", None), values={"ALPHA": "synthetic"})
        with self._mock_legacy(fake):
            denied = self._command(authorize_sync=True)
            with (
                mock.patch(
                    "secrets_kit.backends.sqlite.secrets_api.persist_outbound_envelopes_for_configured_peers"
                ) as outbound,
            ):
                accepted = self._command(apply=True, authorize_sync=True)
            before = self._secret_storage_snapshot()
            repeated = self._command(apply=True, authorize_sync=True)
        self.assertEqual(denied[0], 1)
        self.assertEqual(accepted[0], 0, accepted)
        self.assertGreaterEqual(outbound.call_count, 3)
        self.assertEqual(repeated[0], 0, repeated)
        self.assertEqual(self._secret_storage_snapshot(), before)

    def test_sync_authorization_uses_retained_history_across_interleaved_writes(self) -> None:
        for service, name in (("svc", "ALPHA"), ("other", "INTERLEAVED"), ("svc", "BETA")):
            import_sqlite_secret_local(
                service=service, account="acct", name=name, value="synthetic",
                metadata=EntryMetadata(name=name, service=service, account="acct"),
            )
        queued: list[tuple[str, str]] = []
        with mock.patch(
            "secrets_kit.backends.sqlite.secrets_api.persist_outbound_envelopes_for_configured_peers",
            side_effect=lambda *, conn, transaction: queued.append(
                (transaction.transaction_type, transaction.transaction_id)
            ),
        ):
            for name in ("ALPHA", "BETA"):
                authorize_existing_sqlite_secret_for_sync(
                    service="svc", account="acct", name=name
                )
        self.assertEqual(
            [kind for kind, _ in queued],
            ["vocabulary.entry_type.upsert", "vocabulary.entry_kind.upsert", "secret.set"] * 2,
        )
        self.assertEqual(len({transaction_id for _, transaction_id in queued}), 6)

    def test_partial_sync_authorization_retry_preserves_delivery_states(self) -> None:
        eligible = deterministic_identifier(
            identifier_type="node", namespace="test", name="migration-eligible-peer"
        )
        ineligible = deterministic_identifier(
            identifier_type="node", namespace="test", name="migration-ineligible-peer"
        )
        conn = open_sqlite_backend()
        try:
            group_id = conn.execute("SELECT peer_group_id FROM peer_groups LIMIT 1").fetchone()[0]
            for node_id, state in ((eligible, "active"), (ineligible, "rejected")):
                public_key = X25519PrivateKey.generate().public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
                conn.execute(
                    """INSERT INTO nodes (
                        node_id, peer_group_id, signing_public_key, signing_algorithm,
                        encryption_public_key, encryption_algorithm, state, authorization_mode
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        node_id, group_id, bytes(32), "ed25519", public_key, "x25519",
                        state, "all",
                    ),
                )
        finally:
            conn.close()

        for name in ("ALPHA", "BETA"):
            import_sqlite_secret_local(
                service="svc", account="acct", name=name, value="synthetic",
                metadata=EntryMetadata(name=name, service="svc", account="acct"),
            )
        authorize_existing_sqlite_secret_for_sync(service="svc", account="acct", name="ALPHA")
        original = secrets_api.persist_outbound_envelopes_for_configured_peers

        def fail_on_secret(*, conn, transaction):
            if transaction.transaction_type == "secret.set":
                raise RuntimeError("synthetic authorization interruption")
            return original(conn=conn, transaction=transaction)

        with mock.patch.object(
            secrets_api, "persist_outbound_envelopes_for_configured_peers",
            side_effect=fail_on_secret,
        ), self.assertRaisesRegex(RuntimeError, "synthetic authorization interruption"):
            authorize_existing_sqlite_secret_for_sync(service="svc", account="acct", name="BETA")
        conn = open_sqlite_backend()
        try:
            before = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
            rows = conn.execute("SELECT envelope_id FROM envelopes ORDER BY envelope_id").fetchall()
            self.assertEqual(len(rows), 3)
            conn.execute("UPDATE envelopes SET state = 'sent' WHERE envelope_id = ?", (rows[0][0],))
            conn.execute(
                "UPDATE envelopes SET state = 'acknowledged' WHERE envelope_id = ?",
                (rows[1][0],),
            )
        finally:
            conn.close()
        for name in ("ALPHA", "BETA"):
            authorize_existing_sqlite_secret_for_sync(service="svc", account="acct", name=name)
        conn = open_sqlite_backend()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0], before)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0], 6)
            self.assertEqual(
                dict(conn.execute("SELECT state, COUNT(*) FROM envelopes GROUP BY state")),
                {"acknowledged": 1, "pending": 4, "sent": 1},
            )
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ?", (ineligible,)
                ).fetchone()[0], 0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM envelopes"
                ).fetchone()[0],
                conn.execute(
                    "SELECT COUNT(DISTINCT transaction_id || destination_node_id) FROM envelopes"
                ).fetchone()[0],
            )
        finally:
            conn.close()

    def test_sync_authorization_does_not_send_secret_to_unscoped_peer(self) -> None:
        peer_id = deterministic_identifier(
            identifier_type="node", namespace="test", name="migration-unscoped-peer"
        )
        conn = open_sqlite_backend()
        try:
            group_id = conn.execute("SELECT peer_group_id FROM peer_groups LIMIT 1").fetchone()[0]
            public_key = X25519PrivateKey.generate().public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            conn.execute(
                """INSERT INTO nodes (
                    node_id, peer_group_id, signing_public_key, signing_algorithm,
                    encryption_public_key, encryption_algorithm, state, authorization_mode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (peer_id, group_id, bytes(32), "ed25519", public_key, "x25519", "active", "none"),
            )
        finally:
            conn.close()
        import_sqlite_secret_local(
            service="svc", account="acct", name="ALPHA", value="synthetic",
            metadata=EntryMetadata(name="ALPHA", service="svc", account="acct"),
        )
        authorize_existing_sqlite_secret_for_sync(service="svc", account="acct", name="ALPHA")
        conn = open_sqlite_backend()
        try:
            rows = conn.execute(
                """SELECT t.transaction_type FROM envelopes e
                   JOIN transactions t USING (transaction_id)
                   WHERE e.destination_node_id = ? ORDER BY t.rowid""",
                (peer_id,),
            ).fetchall()
            self.assertEqual(
                [row[0] for row in rows],
                ["vocabulary.entry_type.upsert", "vocabulary.entry_kind.upsert"],
            )
        finally:
            conn.close()

    def _secret_storage_snapshot(self):
        conn = open_sqlite_backend()
        try:
            row = conn.execute(
                "SELECT encrypted_payload FROM secrets WHERE name = 'ALPHA'"
            ).fetchone()
            count = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
            return (None if row is None else bytes(row[0]), count)
        finally:
            conn.close()

    def test_value_read_failure_has_no_provider_output_or_argv_secret(self) -> None:
        calls, fake = self._run(("ALPHA", None))
        with self._mock_legacy(fake):
            result = self._command(apply=True)
        self.assertEqual(result[0], 1)
        self.assertNotIn("synthetic missing", result[2])
        self.assertEqual(calls[-1][0], "Security.framework")

    def test_legacy_write_and_backend_selection_are_retired(self) -> None:
        with mock.patch("subprocess.run") as invoked:
            with self.assertRaisesRegex(BackendError, "retired"):
                normalize_backend("keychain")
            with self.assertRaisesRegex(BackendError, "writes are retired"):
                SecurityCliStore(path=str(self.source)).set(
                    service="svc", account="acct", name="ALPHA", value="synthetic"
                )
            invoked.assert_not_called()

    def test_parser_defaults_to_inventory_and_does_not_wake_delivery(self) -> None:
        parser = build_parser()
        base = [
            "migrate",
            "keychain",
            "--keychain",
            str(self.source),
            "--service",
            "svc",
            "--account",
            "acct",
        ]
        dry_run = parser.parse_args(base)
        local_apply = parser.parse_args([*base, "--apply"])
        sync_apply = parser.parse_args([*base, "--apply", "--authorize-sync"])
        self.assertFalse(dry_run.apply)
        self.assertEqual(_daemon_events_after_success(args=dry_run), ())
        self.assertEqual(_daemon_events_after_success(args=local_apply), ())
        self.assertEqual(_daemon_events_after_success(args=sync_apply), ("delivery-wake",))


@unittest.skipUnless(sys.platform == "darwin", "disposable Keychain requires macOS")
class KeychainMigrationMacIntegrationTest(unittest.TestCase):
    def test_disposable_keychain_exact_utf8_values(self) -> None:
        values = {
            "EMPTY": "",
            "UNICODE": "αβ雪🔐",
            "EMBEDDED": "line one\nline two",
            "TRAILING": "value\n",
        }
        security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        security.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        security.SecKeychainOpen.restype = ctypes.c_int32
        security.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
        ]
        security.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        core_foundation = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
        with tempfile.TemporaryDirectory(prefix="seckit-migration-") as directory:
            path = Path(directory).resolve() / "fixture.keychain-db"
            created = subprocess.run(
                ["security", "create-keychain", "-p", "synthetic-fixture", str(path)],
                capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(created.returncode, 0, "disposable Keychain creation failed")
            try:
                unlocked = subprocess.run(
                    ["security", "unlock-keychain", "-p", "synthetic-fixture", str(path)],
                    capture_output=True, timeout=10, check=False,
                )
                self.assertEqual(unlocked.returncode, 0, "disposable Keychain unlock failed")
                keychain = ctypes.c_void_p()
                self.assertEqual(
                    security.SecKeychainOpen(os.fsencode(path), ctypes.byref(keychain)), 0
                )
                try:
                    for name, value in values.items():
                        service = f"svc:{name}".encode()
                        account = b"acct"
                        raw = value.encode("utf-8")
                        buffer = ctypes.create_string_buffer(raw or b"\0")
                        self.assertEqual(
                            security.SecKeychainAddGenericPassword(
                                keychain, len(service), service, len(account), account,
                                len(raw), buffer, None,
                            ),
                            0,
                        )
                    inventory = inventory_keychain(path=str(path), service="svc", account="acct")
                    self.assertEqual(inventory.unsupported, ())
                    self.assertEqual({item.metadata.name for item in inventory.items}, set(values))
                    with mock.patch(
                        "secrets_kit.cli.keychain_migration.MAX_INVENTORY_BYTES", 1
                    ), self.assertRaisesRegex(MigrationError, "maximum size"):
                        inventory_keychain(path=str(path), service="svc", account="acct")
                    for item in inventory.items:
                        actual = read_legacy_value(inventory=inventory, item=item)
                        self.assertEqual(actual.encode("utf-8"), values[item.metadata.name].encode("utf-8"))
                    home = Path(directory) / "sqlite-home"
                    sqlite_path = Path(directory) / "sqlite" / "seckit.sqlite"
                    with (
                        mock.patch("pathlib.Path.home", return_value=home),
                        mock.patch.dict(
                            os.environ,
                            {"HOME": str(home), "SECKIT_SQLITE_PATH": str(sqlite_path)},
                        ),
                        redirect_stdout(StringIO()),
                        redirect_stderr(StringIO()),
                    ):
                        self.assertEqual(
                            cmd_init_operator(
                                args=argparse.Namespace(
                                    yes=True, home=str(home), init_target=None, backend="sqlite"
                                )
                            ),
                            0,
                        )
                        migrate_args = argparse.Namespace(
                            keychain=str(path), service="svc", account="acct",
                            apply=True, authorize_sync=False,
                        )
                        self.assertEqual(cmd_migrate_keychain(args=migrate_args), 0)
                        for name, value in values.items():
                            stored, _ = get_sqlite_secret_entry(
                                service="svc", account="acct", name=name
                            )
                            self.assertEqual(stored.encode("utf-8"), value.encode("utf-8"))
                        conn = open_sqlite_backend()
                        try:
                            self.assertEqual(conn.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0], 0)
                        finally:
                            conn.close()
                        self.assertEqual(cmd_migrate_keychain(args=migrate_args), 0)
                    preserved = inventory_keychain(path=str(path), service="svc", account="acct")
                    self.assertEqual({item.metadata.name for item in preserved.items}, set(values))
                    for item in preserved.items:
                        self.assertEqual(
                            read_legacy_value(inventory=preserved, item=item),
                            values[item.metadata.name],
                        )
                finally:
                    core_foundation.CFRelease(keychain)
            finally:
                subprocess.run(
                    ["security", "delete-keychain", str(path)],
                    capture_output=True, timeout=10, check=False,
                )


if __name__ == "__main__":
    unittest.main()
