from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.connection import transaction as sqlite3_transaction
from secrets_kit.backends.sqlite.gate import SQLITE_PATH_ENV, open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import (
    SQLITE_NODE_IDENTITY_KEY_ENV,
)
from secrets_kit.backends.sqlite.peer_admission import (
    accept_peer_admission,
    create_signed_peer_admission_request,
    local_peer_public_identity,
)
from secrets_kit.backends.sqlite.transaction_engine import (
    REMOTE_TRANSACTION_POLICY,
    submit_transaction,
)
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.daemon.client import (
    TCP_HOST,
    request_daemon_tcp,
    send_opaque_tcp,
)
from secrets_kit.identifiers import deterministic_identifier
from secrets_kit.protocol.payload_codec import (
    ENCRYPTED_CODEC_MODE,
    ENVELOPE_PAYLOAD_CODEC_ENV,
)
from secrets_kit.runtime.outbound_delivery import process_pending_outbound_envelopes
from tests.canonical_id_helpers import tid

NODE_A_ID = tid("node", "sync-node-a")
NODE_B_ID = tid("node", "sync-node-b")
NODE_C_ID = tid("node", "sync-node-c")
SYNC_SERVICE_GROUP_ID = deterministic_identifier(
    identifier_type="service_group",
    namespace="sqlite.service_group",
    name="local\x00sync-service",
)


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((TCP_HOST, 0))
        return int(sock.getsockname()[1])


def _deliver_envelope_tcp(
    *, envelope: dict[str, object], host: str, port: int
) -> dict[str, object]:
    return send_opaque_tcp(
        payload=json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        host=host,
        port=port,
    )


def _pythonpath_env() -> str:
    repo_src = str(Path(__file__).resolve().parents[1] / "src")
    existing = os.environ.get("PYTHONPATH")
    if existing:
        return os.pathsep.join([repo_src, existing])
    return repo_src


def _node_env(
    *,
    home_path: Path,
    sqlite_path: Path,
    identity_key_path: Path,
    runtime_dir: Path,
    port: int,
) -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(home_path)
    env["PYTHONPATH"] = _pythonpath_env()
    env[SQLITE_PATH_ENV] = str(sqlite_path)
    env[SQLITE_NODE_IDENTITY_KEY_ENV] = str(identity_key_path)
    env["SECKIT_DAEMON_RUNTIME_DIR"] = str(runtime_dir)
    env["SECKIT_DAEMON_TCP_PORT"] = str(port)
    env["SECKIT_DAEMON_TRANSPORT"] = "direct_tcp"
    env["SECKIT_UNSAFE_TEST_DIRECT_TCP"] = "1"
    return env


def _source_env(
    *,
    home_path: Path,
    sqlite_path: Path,
    identity_key_path: Path,
    runtime_dir: Path,
    port: int,
    target_port: int,
) -> dict[str, str]:
    env = _node_env(
        home_path=home_path,
        sqlite_path=sqlite_path,
        identity_key_path=identity_key_path,
        runtime_dir=runtime_dir,
        port=port,
    )
    env["SECKIT_DAEMON_PEERS"] = f"{NODE_B_ID}@{TCP_HOST}:{target_port}"
    return env


def _bidirectional_node_env(
    *,
    home_path: Path,
    sqlite_path: Path,
    identity_key_path: Path,
    runtime_dir: Path,
    port: int,
    peer_node_id: str,
    peer_port: int,
) -> dict[str, str]:
    env = _node_env(
        home_path=home_path,
        sqlite_path=sqlite_path,
        identity_key_path=identity_key_path,
        runtime_dir=runtime_dir,
        port=port,
    )
    env["SECKIT_DAEMON_PEERS"] = f"{peer_node_id}@{TCP_HOST}:{peer_port}"
    return env


def _multi_peer_node_env(
    *,
    home_path: Path,
    sqlite_path: Path,
    identity_key_path: Path,
    runtime_dir: Path,
    port: int,
    peers: list[tuple[str, int]],
) -> dict[str, str]:
    env = _node_env(
        home_path=home_path,
        sqlite_path=sqlite_path,
        identity_key_path=identity_key_path,
        runtime_dir=runtime_dir,
        port=port,
    )
    env["SECKIT_DAEMON_PEERS"] = ",".join(
        f"{node_id}@{TCP_HOST}:{peer_port}" for node_id, peer_port in peers
    )
    return env


def _start_daemon(*, env: dict[str, str], port: int) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        [sys.executable, "-m", "secrets_kit.daemon.server"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=env,
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            response = request_daemon_tcp(command="ping", port=port)
        except Exception:
            if proc.poll() is not None:
                raise AssertionError(
                    f"daemon exited early with code {proc.returncode}"
                ) from None
            time.sleep(0.05)
            continue
        if response.get("status") == "ok" and response.get("response") == "pong":
            return proc
    raise AssertionError(f"daemon did not become reachable on port {port}")


def _stop_daemon(*, proc: subprocess.Popen[bytes], port: int) -> None:
    try:
        request_daemon_tcp(command="shutdown", port=port)
    except Exception:
        pass
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)


def _run_cli(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "secrets_kit.cli", *args],
        check=False,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _create_source_secret(*, env: dict[str, str], name: str, value: str) -> None:
    result = _run_cli(
        "set",
        "--backend",
        "sqlite",
        "--service",
        "sync-service",
        "--account",
        "local",
        "--name",
        name,
        "--value",
        value,
        env=env,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)


def _provision_node_identity(*, env: dict[str, str]) -> None:
    old_env = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(env)
        os.environ.pop("SECKIT_SQLITE_STORAGE_KEY_PATH", None)
        args = argparse.Namespace(
            yes=True,
            home=env["HOME"],
            init_target=None,
            backend="sqlite",
            unsafe_plaintext_storage=True,
        )
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            if cmd_init_operator(args=args) != 0:
                raise AssertionError("failed to provision local sync node")
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _with_env(env: dict[str, str]):
    class _EnvContext:
        def __enter__(self) -> None:
            self._old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update(env)

        def __exit__(self, _exc_type, _exc, _tb) -> None:
            os.environ.clear()
            os.environ.update(self._old_env)

    return _EnvContext()


def _local_node_id(*, env: dict[str, str]) -> str:
    with _with_env(env):
        return local_peer_public_identity().node_id


def _configure_daemon_peers(
    *,
    env: dict[str, str],
    peers: list[tuple[str, int]],
) -> None:
    env["SECKIT_DAEMON_PEERS"] = ",".join(
        f"{node_id}@{TCP_HOST}:{peer_port}" for node_id, peer_port in peers
    )


def _inject_remote_transaction(*, env: dict[str, str], transaction) -> None:
    with _with_env(env):
        conn = open_sqlite_backend()
        try:
            with sqlite3_transaction(conn=conn):
                submit_transaction(
                    conn=conn,
                    transaction=transaction,
                    policy=REMOTE_TRANSACTION_POLICY,
                )
        finally:
            conn.close()


def _admit_peer_pair(*, left_env: dict[str, str], right_env: dict[str, str]) -> None:
    with _with_env(left_env):
        left_request = create_signed_peer_admission_request()
    _inject_remote_transaction(env=right_env, transaction=left_request)
    with _with_env(right_env):
        accept_peer_admission(
            node_id=str(left_request.payload["node_id"]),
            service_group_ids=(SYNC_SERVICE_GROUP_ID,),
        )

    with _with_env(right_env):
        right_request = create_signed_peer_admission_request()
    _inject_remote_transaction(env=left_env, transaction=right_request)
    with _with_env(left_env):
        accept_peer_admission(
            node_id=str(right_request.payload["node_id"]),
            service_group_ids=(SYNC_SERVICE_GROUP_ID,),
        )


def _delete_secret(*, env: dict[str, str], name: str) -> None:
    result = _run_cli(
        "delete",
        "--backend",
        "sqlite",
        "--service",
        "sync-service",
        "--account",
        "local",
        "--name",
        name,
        "--yes",
        env=env,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)


def _deliver_outbound(*, env: dict[str, str], peer_port: int, peer_node_id: str) -> int:
    return _deliver_outbound_to_peers(env=env, peers=[(peer_node_id, peer_port)])


def _deliver_outbound_to_peers(*, env: dict[str, str], peers: list[tuple[str, int]]) -> int:
    old_env = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(env)
        conn = open_sqlite_backend()
        try:
            # These tests explicitly request a deterministic retry after changing
            # peer availability; do not wait for the production backoff clock.
            with sqlite3_transaction(conn=conn):
                conn.execute(
                    """
                    UPDATE envelopes
                    SET next_attempt_at = '2000-01-01T00:00:00Z'
                    WHERE state = 'retry_pending'
                    """
                )
            return process_pending_outbound_envelopes(
                conn=conn,
                peer_ids=[node_id for node_id, _ in peers],
            )
        finally:
            conn.close()
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _deliver_source_outbound(*, env: dict[str, str], target_port: int) -> int:
    return _deliver_outbound(env=env, peer_port=target_port, peer_node_id=NODE_B_ID)


def _raw_target_get(*, env: dict[str, str], name: str) -> str:
    deadline = time.monotonic() + 3.0
    last_error = ""
    while time.monotonic() < deadline:
        result = _run_cli(
            "get",
            "--backend",
            "sqlite",
            "--service",
            "sync-service",
            "--account",
            "local",
            "--name",
            name,
            "--raw",
            env=env,
        )
        if result.returncode == 0:
            return result.stdout
        last_error = result.stderr
        time.sleep(0.05)
    raise AssertionError(last_error)


def _raw_get_optional(*, env: dict[str, str], name: str) -> str | None:
    result = _run_cli(
        "get",
        "--backend",
        "sqlite",
        "--service",
        "sync-service",
        "--account",
        "local",
        "--name",
        name,
        "--raw",
        env=env,
    )
    if result.returncode == 0:
        return result.stdout
    return None


def _transaction_count(*, sqlite_path: Path) -> int:
    conn = connect_sqlite(path=sqlite_path)
    try:
        row = conn.execute("SELECT COUNT(*) AS count FROM transactions").fetchone()
        return int(row["count"])
    finally:
        conn.close()


def _applied_transaction_counts(
    *, sqlite_path: Path, transaction_ids: list[str]
) -> dict[str, int]:
    conn = connect_sqlite(path=sqlite_path)
    try:
        return {
            transaction_id: int(
                conn.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM transactions
                    WHERE transaction_id = ? AND state = 'applied'
                    """,
                    (transaction_id,),
                ).fetchone()["count"]
            )
            for transaction_id in transaction_ids
        }
    finally:
        conn.close()


def _wait_for_applied_transaction_ids(
    *, sqlite_path: Path, transaction_ids: list[str], timeout: float = 5.0
) -> None:
    deadline = time.monotonic() + timeout
    counts: dict[str, int] = {}
    while time.monotonic() < deadline:
        counts = _applied_transaction_counts(
            sqlite_path=sqlite_path,
            transaction_ids=transaction_ids,
        )
        if counts and all(count == 1 for count in counts.values()):
            return
        time.sleep(0.05)
    raise AssertionError(
        f"transactions did not apply exactly once before timeout: {counts}"
    )


def _transaction_ids_for_type(
    *, sqlite_path: Path, transaction_type: str
) -> list[str]:
    conn = connect_sqlite(path=sqlite_path)
    try:
        rows = conn.execute(
            """
            SELECT transaction_id
            FROM transactions
            WHERE transaction_type = ?
            ORDER BY rowid
            """,
            (transaction_type,),
        ).fetchall()
        return [str(row["transaction_id"]) for row in rows]
    finally:
        conn.close()


def _outbound_transaction_ids(*, sqlite_path: Path) -> list[str]:
    conn = connect_sqlite(path=sqlite_path)
    try:
        rows = conn.execute(
            """
            SELECT DISTINCT transaction_id
            FROM envelopes
            ORDER BY transaction_id
            """
        ).fetchall()
        return [str(row["transaction_id"]) for row in rows]
    finally:
        conn.close()


def _wait_for_no_pending_envelopes(
    *, sqlite_path: Path, timeout: float = 5.0
) -> None:
    deadline = time.monotonic() + timeout
    count = -1
    while time.monotonic() < deadline:
        conn = connect_sqlite(path=sqlite_path)
        try:
            count = int(conn.execute(
                "SELECT COUNT(*) FROM envelopes WHERE state IN ('pending', 'retry_pending', 'claimed', 'sending')"
            ).fetchone()[0])
        finally:
            conn.close()
        if count == 0:
            return
        time.sleep(0.05)
    raise AssertionError(f"outbound envelopes did not drain before timeout: {count}")


def _secret_set_transaction_count(*, sqlite_path: Path) -> int:
    conn = connect_sqlite(path=sqlite_path)
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM transactions
            WHERE transaction_type = 'secret.set' AND state = 'applied'
            """
        ).fetchone()
        return int(row["count"])
    finally:
        conn.close()


def _secret_projection_summary(*, sqlite_path: Path) -> list[tuple[str, str, str, str, str]]:
    conn = connect_sqlite(path=sqlite_path)
    try:
        rows = conn.execute(
            """
            SELECT secret_id, service, account, name, state
            FROM secrets
            ORDER BY secret_id
            """
        ).fetchall()
        return [
            (
                str(row["secret_id"]),
                str(row["service"]),
                str(row["account"]),
                str(row["name"]),
                str(row["state"]),
            )
            for row in rows
        ]
    finally:
        conn.close()


def _transaction_summary(*, sqlite_path: Path) -> list[tuple[str, str, str]]:
    conn = connect_sqlite(path=sqlite_path)
    try:
        rows = conn.execute(
            """
            SELECT transaction_id, transaction_type, state
            FROM transactions
            ORDER BY transaction_id
            """
        ).fetchall()
        return [
            (
                str(row["transaction_id"]),
                str(row["transaction_type"]),
                str(row["state"]),
            )
            for row in rows
        ]
    finally:
        conn.close()


def _pending_envelope_count(*, sqlite_path: Path) -> int:
    conn = connect_sqlite(path=sqlite_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM envelopes WHERE state IN ('pending', 'retry_pending')"
        ).fetchone()
        return int(row["count"])
    finally:
        conn.close()


def _sent_envelope_count(*, sqlite_path: Path) -> int:
    conn = connect_sqlite(path=sqlite_path)
    try:
        row = conn.execute("SELECT COUNT(*) AS count FROM envelopes WHERE state = 'sent'").fetchone()
        return int(row["count"])
    finally:
        conn.close()


def _ordered_source_envelopes(*, sqlite_path: Path) -> list[dict[str, object]]:
    conn = connect_sqlite(path=sqlite_path)
    try:
        rows = conn.execute(
            """
            SELECT e.encrypted_payload
            FROM envelopes e
            JOIN transactions t ON t.transaction_id = e.transaction_id
            ORDER BY t.rowid ASC, e.envelope_id ASC
            """
        ).fetchall()
        return [json.loads(bytes(row["encrypted_payload"]).decode("utf-8")) for row in rows]
    finally:
        conn.close()


def _ordered_envelopes_for_transaction_type(
    *,
    sqlite_path: Path,
    transaction_type: str,
) -> list[tuple[bytes, dict[str, object]]]:
    conn = connect_sqlite(path=sqlite_path)
    try:
        rows = conn.execute(
            """
            SELECT e.encrypted_payload
            FROM envelopes e
            JOIN transactions t ON t.transaction_id = e.transaction_id
            WHERE t.transaction_type = ?
            ORDER BY t.rowid ASC, e.envelope_id ASC
            """,
            (transaction_type,),
        ).fetchall()
        return [
            (
                bytes(row["encrypted_payload"]),
                json.loads(bytes(row["encrypted_payload"]).decode("utf-8")),
            )
            for row in rows
        ]
    finally:
        conn.close()


class DaemonTwoNodeSyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.source_home = root / "node-a-home"
        self.target_home = root / "node-b-home"
        self.source_db = root / "node-a" / "seckit.sqlite"
        self.target_db = root / "node-b" / "seckit.sqlite"
        # ST-01 uses explicit plaintext SQLite storage mode for unauthenticated
        # local sync tests. Each node owns its own HOME, database, runtime
        # directory, port, and identity. No active synchronization test shares a
        # SQLite storage key.
        self.source_identity_key = root / "node-a" / "node-identity.key"
        self.target_identity_key = root / "node-b" / "node-identity.key"
        self.source_runtime = root / "node-a-runtime"
        self.target_runtime = root / "node-b-runtime"
        self.source_port = _free_tcp_port()
        self.target_port = _free_tcp_port()
        self.target_env = _node_env(
            home_path=self.target_home,
            sqlite_path=self.target_db,
            identity_key_path=self.target_identity_key,
            runtime_dir=self.target_runtime,
            port=self.target_port,
        )
        self.source_env = _node_env(
            home_path=self.source_home,
            sqlite_path=self.source_db,
            identity_key_path=self.source_identity_key,
            runtime_dir=self.source_runtime,
            port=self.source_port,
        )
        _provision_node_identity(env=self.source_env)
        _provision_node_identity(env=self.target_env)
        self.source_node_id = _local_node_id(env=self.source_env)
        self.target_node_id = _local_node_id(env=self.target_env)
        _admit_peer_pair(left_env=self.source_env, right_env=self.target_env)
        _configure_daemon_peers(
            env=self.source_env,
            peers=[(self.target_node_id, self.target_port)],
        )
        _configure_daemon_peers(
            env=self.target_env,
            peers=[(self.source_node_id, self.source_port)],
        )
        self.assertFalse((self.source_db.parent / "sqlite-storage.key").exists())
        self.assertFalse((self.target_db.parent / "sqlite-storage.key").exists())
        self.source_proc: subprocess.Popen[bytes] | None = None
        self.target_proc: subprocess.Popen[bytes] | None = None

    def tearDown(self) -> None:
        if self.source_proc is not None:
            _stop_daemon(proc=self.source_proc, port=self.source_port)
        if self.target_proc is not None:
            _stop_daemon(proc=self.target_proc, port=self.target_port)
        self.tmp.cleanup()

    def _start_source_daemon(self) -> None:
        self.source_proc = _start_daemon(env=self.source_env, port=self.source_port)

    def _start_target_daemon(self) -> None:
        self.target_proc = _start_daemon(env=self.target_env, port=self.target_port)

    def _start_both_daemons(self) -> None:
        self._start_source_daemon()
        self._start_target_daemon()

    def _restart_source_daemon(self) -> None:
        if self.source_proc is not None:
            _stop_daemon(proc=self.source_proc, port=self.source_port)
            self.source_proc = None
        self._start_source_daemon()

    def _restart_target_daemon(self) -> None:
        if self.target_proc is not None:
            _stop_daemon(proc=self.target_proc, port=self.target_port)
            self.target_proc = None
        self._start_target_daemon()

    def _deliver_a_to_b(self) -> int:
        return _deliver_outbound(
            env=self.source_env, peer_port=self.target_port, peer_node_id=self.target_node_id
        )

    def _deliver_b_to_a(self) -> int:
        return _deliver_outbound(
            env=self.target_env, peer_port=self.source_port, peer_node_id=self.source_node_id
        )

    def test_successful_one_way_synchronization_without_manual_delivery(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM02_SECRET", value="sm02-value")
        transaction_ids = _transaction_ids_for_type(
            sqlite_path=self.source_db,
            transaction_type="secret.set",
        )
        self.assertEqual(len(transaction_ids), 1)

        _wait_for_applied_transaction_ids(
            sqlite_path=self.target_db,
            transaction_ids=transaction_ids,
        )
        self.assertEqual(
            _raw_target_get(env=self.target_env, name="SM02_SECRET"),
            "sm02-value\n",
        )
        _wait_for_no_pending_envelopes(sqlite_path=self.source_db)
        self.assertEqual(_pending_envelope_count(sqlite_path=self.source_db), 0)
        self.assertGreater(_sent_envelope_count(sqlite_path=self.source_db), 0)

    def test_encrypted_envelope_payload_synchronizes_two_nodes(self) -> None:
        for env in (self.source_env, self.target_env):
            env.pop(ENVELOPE_PAYLOAD_CODEC_ENV, None)
            self.assertFalse((Path(env["HOME"]) / ".config/seckit/rss-client.json").exists())
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="EL03_SECRET", value="el03-value")

        secret_envelopes = _ordered_envelopes_for_transaction_type(
            sqlite_path=self.source_db,
            transaction_type="secret.set",
        )
        self.assertGreater(len(secret_envelopes), 0)
        for stored_bytes, envelope in secret_envelopes:
            with self.subTest(envelope=envelope["envelope_id"]):
                payload = envelope["payload"]
                assert isinstance(payload, dict)
                codec = payload["codec"]
                assert isinstance(codec, dict)
                self.assertEqual(codec["mode"], ENCRYPTED_CODEC_MODE)
                self.assertIsNotNone(envelope["encryption_metadata"])
                self.assertNotIn(b"el03-value", stored_bytes)

        self.assertGreater(self._deliver_a_to_b(), 0)
        self.assertEqual(
            _raw_target_get(env=self.target_env, name="EL03_SECRET"),
            "el03-value\n",
        )

    def test_bidirectional_synchronization(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_A", value="a-value")
        _create_source_secret(env=self.target_env, name="SM03_B", value="b-value")

        self.assertGreaterEqual(self._deliver_a_to_b(), 0)
        self.assertGreaterEqual(self._deliver_b_to_a(), 0)

        self.assertEqual(_raw_target_get(env=self.target_env, name="SM03_A"), "a-value\n")
        self.assertEqual(_raw_target_get(env=self.source_env, name="SM03_B"), "b-value\n")
        self.assertEqual(
            _secret_projection_summary(sqlite_path=self.source_db),
            _secret_projection_summary(sqlite_path=self.target_db),
        )

    def test_concurrent_independent_writes_converge(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_CONCURRENT_A", value="a1")
        _create_source_secret(env=self.target_env, name="SM03_CONCURRENT_B", value="b1")

        self.assertGreater(self._deliver_b_to_a(), 0)
        self.assertGreater(self._deliver_a_to_b(), 0)

        self.assertEqual(_raw_target_get(env=self.source_env, name="SM03_CONCURRENT_B"), "b1\n")
        self.assertEqual(_raw_target_get(env=self.target_env, name="SM03_CONCURRENT_A"), "a1\n")
        self.assertEqual(
            _secret_projection_summary(sqlite_path=self.source_db),
            _secret_projection_summary(sqlite_path=self.target_db),
        )

    def test_update_propagates_in_both_directions(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_UPDATE_A", value="a1")
        _create_source_secret(env=self.target_env, name="SM03_UPDATE_B", value="b1")
        self.assertGreater(self._deliver_a_to_b(), 0)
        self.assertGreater(self._deliver_b_to_a(), 0)

        _create_source_secret(env=self.source_env, name="SM03_UPDATE_A", value="a2")
        _create_source_secret(env=self.target_env, name="SM03_UPDATE_B", value="b2")
        self._deliver_a_to_b()
        self._deliver_b_to_a()

        self.assertEqual(_raw_target_get(env=self.target_env, name="SM03_UPDATE_A"), "a2\n")
        self.assertEqual(_raw_target_get(env=self.source_env, name="SM03_UPDATE_B"), "b2\n")
        self.assertEqual(
            _secret_projection_summary(sqlite_path=self.source_db),
            _secret_projection_summary(sqlite_path=self.target_db),
        )

    def test_delete_tombstones_propagate(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_DELETE_A", value="a-delete")
        _create_source_secret(env=self.target_env, name="SM03_DELETE_B", value="b-delete")
        self.assertGreater(self._deliver_a_to_b(), 0)
        self.assertGreater(self._deliver_b_to_a(), 0)

        _delete_secret(env=self.source_env, name="SM03_DELETE_A")
        _delete_secret(env=self.target_env, name="SM03_DELETE_B")
        self._deliver_a_to_b()
        self._deliver_b_to_a()

        self.assertIsNone(_raw_get_optional(env=self.target_env, name="SM03_DELETE_A"))
        self.assertIsNone(_raw_get_optional(env=self.source_env, name="SM03_DELETE_B"))
        self.assertEqual(
            _secret_projection_summary(sqlite_path=self.source_db),
            _secret_projection_summary(sqlite_path=self.target_db),
        )

    def test_duplicate_transaction_is_idempotent(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM02_DUP", value="dup-value")
        transaction_ids = _outbound_transaction_ids(sqlite_path=self.source_db)
        self.assertGreater(len(transaction_ids), 0)
        _wait_for_applied_transaction_ids(
            sqlite_path=self.target_db,
            transaction_ids=transaction_ids,
        )
        _wait_for_no_pending_envelopes(sqlite_path=self.source_db)
        before = _applied_transaction_counts(
            sqlite_path=self.target_db,
            transaction_ids=transaction_ids,
        )

        for envelope in _ordered_source_envelopes(sqlite_path=self.source_db):
            response = _deliver_envelope_tcp(
                envelope=envelope,
                host=TCP_HOST,
                port=self.target_port,
            )
            self.assertEqual(response, {"version": 1, "status": "ok", "response": "delivered"})

        self.assertEqual(
            _applied_transaction_counts(
                sqlite_path=self.target_db,
                transaction_ids=transaction_ids,
            ),
            before,
        )
        self.assertTrue(all(count == 1 for count in before.values()))
        self.assertEqual(_raw_target_get(env=self.target_env, name="SM02_DUP"), "dup-value\n")

    def test_bidirectional_duplicate_delivery_is_idempotent(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_DUP_A", value="a-dup")
        _create_source_secret(env=self.target_env, name="SM03_DUP_B", value="b-dup")
        source_transaction_ids = _outbound_transaction_ids(sqlite_path=self.source_db)
        target_transaction_ids = _outbound_transaction_ids(sqlite_path=self.target_db)
        self.assertGreater(len(source_transaction_ids), 0)
        self.assertGreater(len(target_transaction_ids), 0)
        # The automatic worker may finish before the manual assist; the exact
        # application/queue checks below establish completion in either case.
        self.assertGreaterEqual(self._deliver_a_to_b(), 0)
        self.assertGreaterEqual(self._deliver_b_to_a(), 0)
        _wait_for_applied_transaction_ids(
            sqlite_path=self.target_db,
            transaction_ids=source_transaction_ids,
        )
        _wait_for_applied_transaction_ids(
            sqlite_path=self.source_db,
            transaction_ids=target_transaction_ids,
        )
        _wait_for_no_pending_envelopes(sqlite_path=self.source_db)
        _wait_for_no_pending_envelopes(sqlite_path=self.target_db)
        source_total_before = _transaction_count(sqlite_path=self.source_db)
        target_total_before = _transaction_count(sqlite_path=self.target_db)
        source_before = _applied_transaction_counts(
            sqlite_path=self.source_db,
            transaction_ids=target_transaction_ids,
        )
        target_before = _applied_transaction_counts(
            sqlite_path=self.target_db,
            transaction_ids=source_transaction_ids,
        )

        for envelope in _ordered_source_envelopes(sqlite_path=self.source_db):
            response = _deliver_envelope_tcp(
                envelope=envelope,
                host=TCP_HOST,
                port=self.target_port,
            )
            self.assertEqual(response, {"version": 1, "status": "ok", "response": "delivered"})
        for envelope in _ordered_source_envelopes(sqlite_path=self.target_db):
            response = _deliver_envelope_tcp(
                envelope=envelope,
                host=TCP_HOST,
                port=self.source_port,
            )
            self.assertEqual(response, {"version": 1, "status": "ok", "response": "delivered"})

        self.assertEqual(
            _applied_transaction_counts(
                sqlite_path=self.source_db,
                transaction_ids=target_transaction_ids,
            ),
            source_before,
        )
        self.assertEqual(
            _applied_transaction_counts(
                sqlite_path=self.target_db,
                transaction_ids=source_transaction_ids,
            ),
            target_before,
        )
        self.assertTrue(all(count == 1 for count in source_before.values()))
        self.assertTrue(all(count == 1 for count in target_before.values()))
        self.assertEqual(_transaction_count(sqlite_path=self.source_db), source_total_before)
        self.assertEqual(_transaction_count(sqlite_path=self.target_db), target_total_before)
        self.assertEqual(
            _secret_projection_summary(sqlite_path=self.source_db),
            _secret_projection_summary(sqlite_path=self.target_db),
        )

    def test_synchronization_does_not_loop_between_peers(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_LOOP_A", value="a-loop")
        _create_source_secret(env=self.target_env, name="SM03_LOOP_B", value="b-loop")

        self.assertGreater(self._deliver_a_to_b(), 0)
        self.assertGreater(self._deliver_b_to_a(), 0)
        drained = 0
        for _ in range(3):
            drained += self._deliver_a_to_b()
            drained += self._deliver_b_to_a()
        self.assertEqual(drained, 0)
        source_transactions = _transaction_count(sqlite_path=self.source_db)
        target_transactions = _transaction_count(sqlite_path=self.target_db)
        source_envelopes = _sent_envelope_count(sqlite_path=self.source_db)
        target_envelopes = _sent_envelope_count(sqlite_path=self.target_db)

        self.assertEqual(self._deliver_a_to_b(), 0)
        self.assertEqual(self._deliver_b_to_a(), 0)
        self.assertEqual(_transaction_count(sqlite_path=self.source_db), source_transactions)
        self.assertEqual(_transaction_count(sqlite_path=self.target_db), target_transactions)
        self.assertEqual(_sent_envelope_count(sqlite_path=self.source_db), source_envelopes)
        self.assertEqual(_sent_envelope_count(sqlite_path=self.target_db), target_envelopes)
        self.assertEqual(_pending_envelope_count(sqlite_path=self.source_db), 0)
        self.assertEqual(_pending_envelope_count(sqlite_path=self.target_db), 0)

    def test_daemon_restart_before_apply_still_synchronizes(self) -> None:
        self._start_both_daemons()
        assert self.target_proc is not None
        _stop_daemon(proc=self.target_proc, port=self.target_port)
        self.target_proc = None
        _create_source_secret(env=self.source_env, name="SM02_RESTART", value="restart-value")
        transaction_ids = _transaction_ids_for_type(
            sqlite_path=self.source_db,
            transaction_type="secret.set",
        )
        self.assertEqual(len(transaction_ids), 1)
        self.assertEqual(
            _applied_transaction_counts(
                sqlite_path=self.target_db,
                transaction_ids=transaction_ids,
            ),
            {transaction_ids[0]: 0},
        )
        self._restart_target_daemon()

        _wait_for_applied_transaction_ids(
            sqlite_path=self.target_db,
            transaction_ids=transaction_ids,
            timeout=8.0,
        )
        self.assertEqual(
            _raw_target_get(env=self.target_env, name="SM02_RESTART"),
            "restart-value\n",
        )

    def test_daemon_restart_on_either_node_resumes_synchronization(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_RESTART_A", value="a-restart")
        _create_source_secret(env=self.target_env, name="SM03_RESTART_B", value="b-restart")
        self._restart_source_daemon()
        self._restart_target_daemon()

        self.assertGreaterEqual(self._deliver_a_to_b(), 0)
        self.assertGreaterEqual(self._deliver_b_to_a(), 0)

        self.assertEqual(_raw_target_get(env=self.target_env, name="SM03_RESTART_A"), "a-restart\n")
        self.assertEqual(_raw_target_get(env=self.source_env, name="SM03_RESTART_B"), "b-restart\n")
        self.assertEqual(
            _secret_projection_summary(sqlite_path=self.source_db),
            _secret_projection_summary(sqlite_path=self.target_db),
        )

    def test_pending_outbound_replays_after_reconnect(self) -> None:
        self._start_source_daemon()
        _create_source_secret(env=self.source_env, name="SM02_RECONNECT", value="reconnect-value")

        self.assertEqual(self._deliver_a_to_b(), 0)
        self.assertGreater(_pending_envelope_count(sqlite_path=self.source_db), 0)

        self._start_target_daemon()
        self.assertGreater(self._deliver_a_to_b(), 0)

        self.assertEqual(
            _raw_target_get(env=self.target_env, name="SM02_RECONNECT"),
            "reconnect-value\n",
        )
        self.assertEqual(_pending_envelope_count(sqlite_path=self.source_db), 0)

    def test_bidirectional_reconnect_converges(self) -> None:
        _create_source_secret(env=self.source_env, name="SM03_RECONNECT_A", value="a-reconnect")
        _create_source_secret(env=self.target_env, name="SM03_RECONNECT_B", value="b-reconnect")

        self.assertEqual(self._deliver_a_to_b(), 0)
        self.assertEqual(self._deliver_b_to_a(), 0)
        self.assertGreater(_pending_envelope_count(sqlite_path=self.source_db), 0)
        self.assertGreater(_pending_envelope_count(sqlite_path=self.target_db), 0)

        self._start_both_daemons()
        self.assertGreater(self._deliver_a_to_b(), 0)
        self.assertGreater(self._deliver_b_to_a(), 0)

        self.assertEqual(_raw_target_get(env=self.target_env, name="SM03_RECONNECT_A"), "a-reconnect\n")
        self.assertEqual(_raw_target_get(env=self.source_env, name="SM03_RECONNECT_B"), "b-reconnect\n")
        self.assertEqual(
            _secret_projection_summary(sqlite_path=self.source_db),
            _secret_projection_summary(sqlite_path=self.target_db),
        )
        # Peer Registry admission histories are local authorization records and
        # need not be byte-for-byte identical across nodes. Transaction-driven
        # secret projections must converge deterministically.
        self.assertEqual(_secret_set_transaction_count(sqlite_path=self.source_db), 2)
        self.assertEqual(_secret_set_transaction_count(sqlite_path=self.target_db), 2)
        final_round = -1
        for _ in range(3):
            final_round = self._deliver_a_to_b() + self._deliver_b_to_a()
        self.assertEqual(final_round, 0)
        self.assertEqual(_pending_envelope_count(sqlite_path=self.source_db), 0)
        self.assertEqual(_pending_envelope_count(sqlite_path=self.target_db), 0)

    def test_repeated_replay_is_deterministic(self) -> None:
        self._start_both_daemons()
        _create_source_secret(env=self.source_env, name="SM03_DETERMINISTIC_A", value="a1")
        _create_source_secret(env=self.target_env, name="SM03_DETERMINISTIC_B", value="b1")
        source_transaction_ids = _outbound_transaction_ids(sqlite_path=self.source_db)
        target_transaction_ids = _outbound_transaction_ids(sqlite_path=self.target_db)
        self.assertGreater(len(source_transaction_ids), 0)
        self.assertGreater(len(target_transaction_ids), 0)
        # The automatic worker may finish before the manual assist; the exact
        # application/queue checks below establish completion in either case.
        self.assertGreaterEqual(self._deliver_a_to_b(), 0)
        self.assertGreaterEqual(self._deliver_b_to_a(), 0)
        _wait_for_applied_transaction_ids(
            sqlite_path=self.target_db,
            transaction_ids=source_transaction_ids,
        )
        _wait_for_applied_transaction_ids(
            sqlite_path=self.source_db,
            transaction_ids=target_transaction_ids,
        )
        _wait_for_no_pending_envelopes(sqlite_path=self.source_db)
        _wait_for_no_pending_envelopes(sqlite_path=self.target_db)
        first_source_projection = _secret_projection_summary(sqlite_path=self.source_db)
        first_target_projection = _secret_projection_summary(sqlite_path=self.target_db)
        first_source_transactions = _transaction_summary(sqlite_path=self.source_db)
        first_target_transactions = _transaction_summary(sqlite_path=self.target_db)

        for _ in range(3):
            for envelope in _ordered_source_envelopes(sqlite_path=self.source_db):
                response = _deliver_envelope_tcp(
                    envelope=envelope,
                    host=TCP_HOST,
                    port=self.target_port,
                )
                self.assertEqual(response, {"version": 1, "status": "ok", "response": "delivered"})
            for envelope in _ordered_source_envelopes(sqlite_path=self.target_db):
                response = _deliver_envelope_tcp(
                    envelope=envelope,
                    host=TCP_HOST,
                    port=self.source_port,
                )
                self.assertEqual(response, {"version": 1, "status": "ok", "response": "delivered"})

        self.assertEqual(_secret_projection_summary(sqlite_path=self.source_db), first_source_projection)
        self.assertEqual(_secret_projection_summary(sqlite_path=self.target_db), first_target_projection)
        self.assertEqual(_transaction_summary(sqlite_path=self.source_db), first_source_transactions)
        self.assertEqual(_transaction_summary(sqlite_path=self.target_db), first_target_transactions)


class DaemonThreeNodeSyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.homes = {
            name: self.root / f"{name}-home" for name in ("a", "b", "c")
        }
        # ST-01 uses explicit plaintext SQLite storage mode for unauthenticated
        # local sync tests. Each node owns its own HOME, database, runtime
        # directory, port, and identity. No active synchronization test shares a
        # SQLite storage key.
        self.node_ids: dict[str, str] = {}
        self.dbs = {
            name: self.root / name / "seckit.sqlite" for name in ("a", "b", "c")
        }
        self.identity_keys = {
            name: self.root / name / "node-identity.key" for name in ("a", "b", "c")
        }
        self.runtimes = {
            name: self.root / f"{name}-runtime" for name in ("a", "b", "c")
        }
        self.ports = {name: _free_tcp_port() for name in ("a", "b", "c")}
        self.procs: dict[str, subprocess.Popen[bytes]] = {}

    def tearDown(self) -> None:
        for name, proc in list(self.procs.items()):
            _stop_daemon(proc=proc, port=self.ports[name])
        self.tmp.cleanup()

    def _env(self, name: str, peer_names: list[str]) -> dict[str, str]:
        env = _node_env(
            home_path=self.homes[name],
            sqlite_path=self.dbs[name],
            identity_key_path=self.identity_keys[name],
            runtime_dir=self.runtimes[name],
            port=self.ports[name],
        )
        _provision_node_identity(env=env)
        self.node_ids[name] = _local_node_id(env=env)
        self.assertFalse((self.dbs[name].parent / "sqlite-storage.key").exists())
        return env

    def _full_mesh_envs(self) -> dict[str, dict[str, str]]:
        envs = {name: self._env(name, []) for name in ("a", "b", "c")}
        self._admit_all_peers(envs=envs)
        self._configure_topology(
            envs=envs,
            topology={name: [peer for peer in envs if peer != name] for name in envs},
        )
        return envs

    def _configure_topology(
        self,
        *,
        envs: dict[str, dict[str, str]],
        topology: dict[str, list[str]],
    ) -> None:
        for name, peer_names in topology.items():
            _configure_daemon_peers(
                env=envs[name],
                peers=[
                    (self.node_ids[peer_name], self.ports[peer_name])
                    for peer_name in peer_names
                ],
            )

    def _admit_all_peers(self, *, envs: dict[str, dict[str, str]]) -> None:
        names = sorted(envs)
        for index, left in enumerate(names):
            for right in names[index + 1 :]:
                _admit_peer_pair(left_env=envs[left], right_env=envs[right])

    def _start(self, name: str, env: dict[str, str]) -> None:
        self.procs[name] = _start_daemon(env=env, port=self.ports[name])

    def _start_many(self, envs: dict[str, dict[str, str]], names: list[str]) -> None:
        for name in names:
            self._start(name, envs[name])

    def _restart(self, name: str, env: dict[str, str]) -> None:
        proc = self.procs.pop(name, None)
        if proc is not None:
            _stop_daemon(proc=proc, port=self.ports[name])
        self._start(name, env)

    def _deliver(self, name: str, envs: dict[str, dict[str, str]], peer_names: list[str]) -> int:
        return _deliver_outbound_to_peers(
            env=envs[name],
            peers=[
                (self.node_ids[peer_name], self.ports[peer_name])
                for peer_name in peer_names
            ],
        )

    def _deliver_full_mesh_once(self, envs: dict[str, dict[str, str]]) -> int:
        return sum(
            self._deliver(
                name,
                envs,
                [peer for peer in self.node_ids if peer != name],
            )
            for name in self.node_ids
        )

    def _assert_value_on_nodes(
        self,
        *,
        envs: dict[str, dict[str, str]],
        names: list[str],
        secret_name: str,
        value: str,
    ) -> None:
        for name in names:
            with self.subTest(node=name, secret=secret_name):
                self.assertEqual(
                    _raw_target_get(env=envs[name], name=secret_name),
                    f"{value}\n",
                )

    def _assert_deleted_on_nodes(
        self,
        *,
        envs: dict[str, dict[str, str]],
        names: list[str],
        secret_name: str,
    ) -> None:
        for name in names:
            with self.subTest(node=name, secret=secret_name):
                self.assertIsNone(_raw_get_optional(env=envs[name], name=secret_name))

    def test_signed_destination_envelopes_do_not_retarget_through_intermediates(self) -> None:
        envs = {
            "a": self._env("a", ["b"]),
            "b": self._env("b", ["c"]),
            "c": self._env("c", []),
        }
        self._admit_all_peers(envs=envs)
        self._configure_topology(envs=envs, topology={"a": ["b"], "b": ["c"], "c": []})
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["a"], name="SM04_CHAIN_A", value="a-chain")

        self.assertGreater(self._deliver("a", envs, ["b"]), 0)
        self.assertEqual(_raw_target_get(env=envs["b"], name="SM04_CHAIN_A"), "a-chain\n")
        # Peer-admission transactions may legitimately be queued from B to C;
        # delivery count is not the application-retargeting invariant here.
        self._deliver("b", envs, ["c"])
        self._assert_value_on_nodes(
            envs=envs,
            names=["a", "b"],
            secret_name="SM04_CHAIN_A",
            value="a-chain",
        )
        self.assertIsNone(_raw_get_optional(env=envs["c"], name="SM04_CHAIN_A"))

    def test_a_to_c_direct_converges_when_configured(self) -> None:
        envs = {
            "a": self._env("a", ["b", "c"]),
            "b": self._env("b", []),
            "c": self._env("c", []),
        }
        self._admit_all_peers(envs=envs)
        self._configure_topology(envs=envs, topology={"a": ["b", "c"], "b": [], "c": []})
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["a"], name="SM04_DIRECT_A", value="a-direct")

        self.assertGreater(self._deliver("a", envs, ["b", "c"]), 0)

        self._assert_value_on_nodes(
            envs=envs,
            names=["a", "b", "c"],
            secret_name="SM04_DIRECT_A",
            value="a-direct",
        )

    def test_encrypted_destination_envelopes_converge_across_three_peers(self) -> None:
        envs = self._full_mesh_envs()
        for env in envs.values():
            env[ENVELOPE_PAYLOAD_CODEC_ENV] = ENCRYPTED_CODEC_MODE
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["a"], name="EL03_THREE_NODE", value="three-node-secret")

        secret_envelopes = _ordered_envelopes_for_transaction_type(
            sqlite_path=self.dbs["a"],
            transaction_type="secret.set",
        )
        self.assertGreaterEqual(len(secret_envelopes), 2)
        for stored_bytes, envelope in secret_envelopes:
            with self.subTest(envelope=envelope["envelope_id"]):
                payload = envelope["payload"]
                assert isinstance(payload, dict)
                codec = payload["codec"]
                assert isinstance(codec, dict)
                self.assertEqual(codec["mode"], ENCRYPTED_CODEC_MODE)
                self.assertIsNotNone(envelope["encryption_metadata"])
                self.assertNotIn(b"three-node-secret", stored_bytes)

        self.assertGreater(self._deliver_full_mesh_once(envs), 0)
        self.assertGreaterEqual(self._deliver_full_mesh_once(envs), 0)
        self._assert_value_on_nodes(
            envs=envs,
            names=["a", "b", "c"],
            secret_name="EL03_THREE_NODE",
            value="three-node-secret",
        )

    def test_each_peer_can_originate_and_all_converge(self) -> None:
        envs = self._full_mesh_envs()
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["a"], name="SM04_FROM_A", value="from-a")
        _create_source_secret(env=envs["b"], name="SM04_FROM_B", value="from-b")
        _create_source_secret(env=envs["c"], name="SM04_FROM_C", value="from-c")

        self.assertGreater(self._deliver_full_mesh_once(envs), 0)
        self.assertGreaterEqual(self._deliver_full_mesh_once(envs), 0)

        self._assert_value_on_nodes(
            envs=envs, names=["a", "b", "c"], secret_name="SM04_FROM_A", value="from-a"
        )
        self._assert_value_on_nodes(
            envs=envs, names=["a", "b", "c"], secret_name="SM04_FROM_B", value="from-b"
        )
        self._assert_value_on_nodes(
            envs=envs, names=["a", "b", "c"], secret_name="SM04_FROM_C", value="from-c"
        )

    def test_tombstone_propagates_across_three_peers(self) -> None:
        envs = self._full_mesh_envs()
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["c"], name="SM04_DELETE_C", value="delete-c")
        self.assertGreater(self._deliver_full_mesh_once(envs), 0)
        self.assertGreaterEqual(self._deliver_full_mesh_once(envs), 0)
        self._assert_value_on_nodes(
            envs=envs,
            names=["a", "b", "c"],
            secret_name="SM04_DELETE_C",
            value="delete-c",
        )

        _delete_secret(env=envs["c"], name="SM04_DELETE_C")
        self.assertGreater(self._deliver_full_mesh_once(envs), 0)
        self.assertGreaterEqual(self._deliver_full_mesh_once(envs), 0)

        self._assert_deleted_on_nodes(
            envs=envs,
            names=["a", "b", "c"],
            secret_name="SM04_DELETE_C",
        )

    def test_c_offline_then_reconnect_converges_all_peers(self) -> None:
        envs = self._full_mesh_envs()
        self._start_many(envs, ["a", "b"])
        _create_source_secret(env=envs["a"], name="SM04_OFFLINE_C", value="offline-c")

        self.assertGreater(self._deliver("a", envs, ["b", "c"]), 0)
        self.assertEqual(_raw_target_get(env=envs["b"], name="SM04_OFFLINE_C"), "offline-c\n")
        self.assertIsNone(_raw_get_optional(env=envs["c"], name="SM04_OFFLINE_C"))
        self.assertGreater(_pending_envelope_count(sqlite_path=self.dbs["a"]), 0)

        self._start("c", envs["c"])
        self.assertGreater(self._deliver_full_mesh_once(envs), 0)
        self.assertGreaterEqual(self._deliver_full_mesh_once(envs), 0)

        self._assert_value_on_nodes(
            envs=envs,
            names=["a", "b", "c"],
            secret_name="SM04_OFFLINE_C",
            value="offline-c",
        )
        self.assertEqual(_pending_envelope_count(sqlite_path=self.dbs["a"]), 0)
        self.assertEqual(_pending_envelope_count(sqlite_path=self.dbs["b"]), 0)
        self.assertEqual(_pending_envelope_count(sqlite_path=self.dbs["c"]), 0)

    def test_duplicate_delivery_is_idempotent_across_three_peers(self) -> None:
        envs = self._full_mesh_envs()
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["a"], name="SM04_DUP", value="dup")
        self.assertGreater(self._deliver_full_mesh_once(envs), 0)
        self.assertGreaterEqual(self._deliver_full_mesh_once(envs), 0)
        deadline = time.monotonic() + 5.0
        before = {name: _transaction_count(sqlite_path=self.dbs[name]) for name in self.node_ids}
        while len(set(before.values())) != 1 and time.monotonic() < deadline:
            time.sleep(0.1)
            before = {
                name: _transaction_count(sqlite_path=self.dbs[name]) for name in self.node_ids
            }

        for envelope in _ordered_source_envelopes(sqlite_path=self.dbs["a"]):
            for target in ["b", "c"]:
                response = _deliver_envelope_tcp(
                    envelope=envelope,
                    host=TCP_HOST,
                    port=self.ports[target],
                )
                if envelope["destination_node_id"] == self.node_ids[target]:
                    self.assertEqual(response, {"version": 1, "status": "ok", "response": "delivered"})
                else:
                    self.assertEqual(response, {"version": 1, "status": "error", "error": "runtime_handoff_failed"})

        after = {name: _transaction_count(sqlite_path=self.dbs[name]) for name in self.node_ids}
        self.assertEqual(after, before)
        self._assert_value_on_nodes(
            envs=envs,
            names=["a", "b", "c"],
            secret_name="SM04_DUP",
            value="dup",
        )

    def test_daemon_restart_recovery_across_three_peers(self) -> None:
        envs = self._full_mesh_envs()
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["b"], name="SM04_RESTART_B", value="restart-b")
        self._restart("c", envs["c"])

        self.assertGreater(self._deliver_full_mesh_once(envs), 0)
        self.assertGreaterEqual(self._deliver_full_mesh_once(envs), 0)

        self._assert_value_on_nodes(
            envs=envs,
            names=["a", "b", "c"],
            secret_name="SM04_RESTART_B",
            value="restart-b",
        )

    def test_no_sync_loops_across_three_peers(self) -> None:
        envs = self._full_mesh_envs()
        self._start_many(envs, ["a", "b", "c"])
        _create_source_secret(env=envs["a"], name="SM04_LOOP", value="loop")

        first_round = self._deliver_full_mesh_once(envs)
        second_round = self._deliver_full_mesh_once(envs)
        self.assertGreater(first_round, 0)
        self.assertGreaterEqual(second_round, 0)
        counts = {name: _transaction_count(sqlite_path=self.dbs[name]) for name in self.node_ids}
        sent = {name: _sent_envelope_count(sqlite_path=self.dbs[name]) for name in self.node_ids}

        for _ in range(3):
            self.assertEqual(self._deliver_full_mesh_once(envs), 0)

        self.assertEqual(
            {name: _transaction_count(sqlite_path=self.dbs[name]) for name in self.node_ids},
            counts,
        )
        self.assertEqual(
            {name: _sent_envelope_count(sqlite_path=self.dbs[name]) for name in self.node_ids},
            sent,
        )
        self.assertEqual(
            {name: _pending_envelope_count(sqlite_path=self.dbs[name]) for name in self.node_ids},
            {"a": 0, "b": 0, "c": 0},
        )


if __name__ == "__main__":
    unittest.main()
