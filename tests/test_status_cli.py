from __future__ import annotations

import ast
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class StatusCliTest(unittest.TestCase):
    def test_public_status_command_has_no_sqlite_imports(self) -> None:
        source_path = Path(__file__).parents[1] / "src" / "secrets_kit" / "cli" / "commands" / "status.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        ]
        imports.extend(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertFalse(any(name.startswith("sqlite3") or "backends.sqlite" in name for name in imports))

    def test_status_reports_clean_plaintext_sqlite_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env, sqlite_path = self._init_plaintext_env(root=Path(tmp))
            payload = self._status_json(env=env)

            self.assertEqual(payload["overall"], "WAITING FOR PEERS")
            self.assertEqual(payload["daemon_health"], "healthy")
            self.assertEqual(payload["peer_discovery"], "waiting")
            self.assertEqual(payload["backend"], "sqlite")
            self.assertTrue(payload["daemon"]["running"])
            self.assertEqual(payload["database"]["storage_mode"], "plaintext")
            self.assertEqual(payload["database"]["path"], str(sqlite_path))
            self.assertGreaterEqual(payload["transactions"]["total"], 1)
            self.assertEqual(payload["transactions"]["pending"], 0)
            self.assertEqual(payload["transactions"]["failed"], 0)
            self.assertEqual(payload["envelopes"]["total"], 0)
            self.assertEqual(payload["peers"], [])

    def test_status_counts_successful_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env, sqlite_path = self._init_plaintext_env(root=Path(tmp))
            self._run_cli(
                [
                    "set",
                    "--backend",
                    "sqlite",
                    "--service",
                    "status-service",
                    "--account",
                    "local",
                    "--name",
                    "STATUS_SECRET",
                    "--value",
                    "status-value",
                    "--accept-normalized",
                ],
                env=env,
            )
            payload = self._status_json(env=env)

            self.assertEqual(payload["overall"], "WAITING FOR PEERS")
            self.assertEqual(payload["transactions"]["pending"], 0)
            self.assertEqual(payload["transactions"]["failed"], 0)
            self.assertGreaterEqual(payload["transactions"]["applied"], 1)
            self.assertEqual(payload["transactions"]["total"], self._table_count(path=sqlite_path, table="transactions"))
            self.assertIsNotNone(payload["transactions"]["latest_success"])

    def test_rollback_probe_leaves_status_without_incomplete_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env, sqlite_path = self._init_plaintext_env(root=Path(tmp))
            self._run_cli(
                [
                    "set",
                    "--backend",
                    "sqlite",
                    "--service",
                    "status-service",
                    "--account",
                    "local",
                    "--name",
                    "STATUS_COMMITTED",
                    "--value",
                    "committed",
                    "--accept-normalized",
                ],
                env=env,
            )
            before = self._status_json(env=env)
            self._run_rollback_probe(env=env)
            after = self._status_json(env=env)

            self.assertGreaterEqual(after["transactions"]["total"], before["transactions"]["total"])
            self.assertEqual(after["transactions"]["pending"], 0)
            self.assertEqual(after["transactions"]["failed"], 0)
            self.assertEqual(self._secret_count(path=sqlite_path, name="STATUS_ROLLBACK"), 0)

    def _init_plaintext_env(self, *, root: Path) -> tuple[dict[str, str], Path]:
        home = root / "home"
        sqlite_path = root / "seckit.sqlite"
        env = dict(os.environ)
        env.update(
            {
                "HOME": str(home),
                "PYTHONPATH": self._pythonpath(),
                "SECKIT_SQLITE_PATH": str(sqlite_path),
                "SECKIT_SQLITE_STORAGE_MODE": "plaintext",
                "SECKIT_DAEMON_RUNTIME_DIR": str(root / "runtime"),
            }
        )
        env.pop("SECKIT_SQLITE_STORAGE_KEY_PATH", None)
        self._run_cli(
            [
                "init",
                "--backend",
                "sqlite",
                "--storage-mode",
                "plaintext",
                "--home",
                str(home),
                "--yes",
            ],
            env=env,
        )
        return env, sqlite_path

    def _status_json(self, *, env: dict[str, str]) -> dict[str, object]:
        self._run_cli(["daemon", "start"], env=env)
        try:
            result = self._run_cli(["status", "--backend", "sqlite", "--json"], env=env)
            payload = json.loads(result.stdout)
            self.assertIsInstance(payload, dict)
            return payload
        finally:
            self._run_cli(["daemon", "stop"], env=env)

    def _run_cli(
        self,
        args: list[str],
        *,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", "secrets_kit.cli", *args],
            check=False,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            self.fail(
                f"seckit {' '.join(args)} failed: "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        return result

    def _run_rollback_probe(self, *, env: dict[str, str]) -> None:
        old_env = os.environ.copy()
        os.environ.clear()
        os.environ.update(env)
        try:
            from secrets_kit.backends.sqlite.connection import transaction as sqlite_transaction
            from secrets_kit.backends.sqlite.gate import open_sqlite_backend
            from secrets_kit.backends.sqlite.secrets_api import (
                _ensure_local_projection_parents,
                _local_origin_node_id,
                _set_payload,
            )
            from secrets_kit.backends.sqlite.storage_mode import read_sqlite_storage_mode
            from secrets_kit.backends.sqlite.transaction_engine import (
                LOCAL_TRANSACTION_POLICY,
                submit_transaction,
            )
            from secrets_kit.backends.sqlite.transactions import create_transaction
            from secrets_kit.identifiers import random_identifier
            from secrets_kit.models import EntryMetadata, now_utc_iso

            conn = open_sqlite_backend()
            try:
                with self.assertRaisesRegex(RuntimeError, "intentional rollback"):
                    with sqlite_transaction(conn=conn):
                        metadata = EntryMetadata(
                            name="STATUS_ROLLBACK",
                            service="status-service",
                            account="local",
                            entry_kind="api_key",
                        )
                        _ensure_local_projection_parents(
                            conn=conn,
                            account="local",
                            service="status-service",
                        )
                        transaction = create_transaction(
                            transaction_id=random_identifier(identifier_type="transaction"),
                            transaction_type="secret.set",
                            origin_node_id=_local_origin_node_id(conn=conn),
                            created_at=now_utc_iso(),
                            payload=_set_payload(
                                service="status-service",
                                account="local",
                                name="STATUS_ROLLBACK",
                                value="rollback",
                                metadata=metadata,
                                storage_mode=read_sqlite_storage_mode(conn=conn),
                            ),
                        )
                        submit_transaction(
                            conn=conn,
                            transaction=transaction,
                            policy=LOCAL_TRANSACTION_POLICY,
                        )
                        raise RuntimeError("intentional rollback")
            finally:
                conn.close()
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def _table_count(self, *, path: Path, table: str) -> int:
        conn = sqlite3.connect(path)
        try:
            return int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
        finally:
            conn.close()

    def _secret_count(self, *, path: Path, name: str) -> int:
        conn = sqlite3.connect(path)
        try:
            return int(
                conn.execute("SELECT COUNT(*) FROM secrets WHERE name = ?", (name,)).fetchone()[0]
            )
        finally:
            conn.close()

    def _pythonpath(self) -> str:
        src = str(Path(__file__).resolve().parents[1] / "src")
        existing = os.environ.get("PYTHONPATH")
        return os.pathsep.join([src, existing]) if existing else src


if __name__ == "__main__":
    unittest.main()
