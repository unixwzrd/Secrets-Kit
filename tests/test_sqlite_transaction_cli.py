"""
tests.test_sqlite_transaction_cli

Public CLI coverage for read-only SQLite transaction inspection.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from secrets_kit.backends.sqlite import bootstrap_schema, create_transaction, insert_transaction
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "org-1")
CLIENT_ID = tid("client", "client-1")
OWNER_ID = tid("owner", "owner-1")
PEER_GROUP_ID = tid("peer_group", "peer-group-1")
NODE_ID = tid("node", "node-1")
SECRET_ID = tid("secret", "secret-1")
TXN_SHOW_ID = tid("transaction", "txn-show-1")
TXN_MISSING_ID = tid("transaction", "txn-missing")


class SQLiteTransactionCliTest(unittest.TestCase):
    """Exercise transaction inspection through the public CLI entry point."""

    def test_transaction_show_prints_canonical_metadata_and_payload(self) -> None:
        with TemporaryDirectory() as tmp:
            home = Path(tmp)
            self._seed_transaction(home=home)

            completed = self._run_cli(home=home, transaction_id=TXN_SHOW_ID)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertIn(f"transaction_id: {TXN_SHOW_ID}", completed.stdout)
            self.assertIn(f"organization_id: {ORG_ID}", completed.stdout)
            self.assertIn("transaction_type: secret.set", completed.stdout)
            self.assertIn(f'  "secret_id": "{SECRET_ID}"', completed.stdout)
            self.assertNotIn("payload_encoding:", completed.stdout)

    def test_transaction_show_missing_id_is_normal_cli_error(self) -> None:
        with TemporaryDirectory() as tmp:
            home = Path(tmp)
            self._seed_transaction(home=home)

            completed = self._run_cli(home=home, transaction_id=TXN_MISSING_ID)

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(
                completed.stderr,
                f"ERROR: transaction not found: {TXN_MISSING_ID}\n",
            )
            self.assertNotIn("Traceback", completed.stderr)

    @staticmethod
    def _run_cli(*, home: Path, transaction_id: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["PYTHONPATH"] = "src"
        env.pop("SECKIT_SQLITE_PATH", None)
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "secrets_kit.cli",
                "transaction",
                "show",
                transaction_id,
            ],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def _seed_transaction(*, home: Path) -> None:
        path = home / ".config" / "seckit" / "seckit.sqlite"
        path.parent.mkdir(parents=True)
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            bootstrap_schema(conn=conn)
            conn.execute(
                "INSERT INTO business_organizations (organization_id) VALUES (?)",
                (ORG_ID,),
            )
            conn.execute(
                "INSERT INTO business_clients (client_id, organization_id) VALUES (?, ?)",
                (CLIENT_ID, ORG_ID),
            )
            conn.execute(
                "INSERT INTO owners (owner_id, client_id) VALUES (?, ?)",
                (OWNER_ID, CLIENT_ID),
            )
            conn.execute(
                "INSERT INTO peer_groups (peer_group_id, owner_id) VALUES (?, ?)",
                (PEER_GROUP_ID, OWNER_ID),
            )
            conn.execute(
                """
                INSERT INTO nodes (
                    node_id,
                    peer_group_id,
                    signing_public_key,
                    signing_algorithm,
                    encryption_public_key,
                    encryption_algorithm
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    NODE_ID,
                    PEER_GROUP_ID,
                    b"s" * 32,
                    "ed25519",
                    b"e" * 32,
                    "x25519",
                ),
            )
            transaction = create_transaction(
                transaction_id=TXN_SHOW_ID,
                transaction_type="secret.set",
                organization_id=ORG_ID,
                client_id=CLIENT_ID,
                owner_id=OWNER_ID,
                origin_node_id=NODE_ID,
                payload={"secret_id": SECRET_ID},
                created_at="2026-06-30T00:00:00Z",
            )
            insert_transaction(conn=conn, transaction=transaction)


if __name__ == "__main__":
    unittest.main()
