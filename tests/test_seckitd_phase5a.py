"""Phase 5A: local ``seckitd`` Unix socket daemon and IPC client tests."""

from __future__ import annotations

import importlib.util
import json
import os
import site
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from secrets_kit.identity.core import export_public_identity, init_identity, load_identity
from secrets_kit.identity.peers import add_peer_from_file, get_peer
from secrets_kit.models.core import EntryMetadata
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.seckitd.client import ipc_call
from secrets_kit.seckitd.framing import MAX_FRAME_BYTES, FramingError, frame_json, parse_json_object, read_frame
from secrets_kit.seckitd.paths import default_runtime_dir, default_socket_path
from secrets_kit.seckitd.server import bind_unix_socket, ensure_runtime_dir, serve_forever
from secrets_kit.sync.bundle import build_bundle, parse_bundle_file
from secrets_kit.sync.envelope import build_transport_message

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.operations import get_secret, set_secret
    from secrets_kit.backends.registry import BACKEND_SQLITE
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    class SqliteSecretStore:  # pragma: no cover
        pass

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


@unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "requires Unix domain sockets")
class SeckitdPhase5ATests(unittest.TestCase):
    def test_default_paths_are_absolute(self) -> None:
        d = default_runtime_dir()
        self.assertTrue(d.is_absolute())
        s = default_socket_path()
        self.assertTrue(s.name.endswith(".sock"))

    def test_ensure_runtime_dir_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "nested" / "run"
            ensure_runtime_dir(p)
            self.assertTrue(p.is_dir())
            mode = p.stat().st_mode & 0o777
            self.assertEqual(mode, 0o700)

    def test_frame_roundtrip(self) -> None:
        raw = frame_json({"op": "ping"})
        self.assertEqual(len(raw) >= 8, True)
        body = raw[4:]
        obj = parse_json_object(body)
        self.assertEqual(obj["op"], "ping")

    def test_parse_json_rejects_array(self) -> None:
        with self.assertRaises(FramingError):
            parse_json_object(b"[1]")

    def test_read_frame_rejects_length_over_max(self) -> None:
        class _HdrConn:
            def recv(self, n: int) -> bytes:  # noqa: ARG002
                return (MAX_FRAME_BYTES + 1).to_bytes(4, "big")

        with self.assertRaises(FramingError) as ctx:
            read_frame(_HdrConn())
        self.assertIn("large", str(ctx.exception).lower())

    def test_server_ping_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sock = Path(td) / "t.sock"
            stop = threading.Event()

            def _run() -> None:
                serve_forever(socket_path=sock, stop_flag=stop)

            th = threading.Thread(target=_run, daemon=True)
            th.start()
            try:
                deadline = time.time() + 5.0
                while time.time() < deadline:
                    if sock.exists():
                        break
                    time.sleep(0.05)
                self.assertTrue(sock.exists())
                ping = ipc_call(socket_path=sock, request={"op": "ping"}, timeout_s=5.0)
                self.assertTrue(ping.get("ok"))
                self.assertTrue(ping["data"]["pong"])
                st = ipc_call(socket_path=sock, request={"op": "status"}, timeout_s=5.0)
                self.assertTrue(st.get("ok"))
                self.assertIn("uptime_seconds", st["data"])
            finally:
                stop.set()
                th.join(timeout=10.0)

    def test_peer_outbound_local_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sock = Path(td) / "t.sock"
            stop = threading.Event()
            th = threading.Thread(target=lambda: serve_forever(socket_path=sock, stop_flag=stop), daemon=True)
            th.start()
            try:
                for _ in range(100):
                    if sock.exists():
                        break
                    time.sleep(0.05)
                r = ipc_call(
                    socket_path=sock,
                    request={
                        "op": "peer_outbound",
                        "payload_b64": "BQ==",
                        "payload_type": "test",
                        "client_ref": "unit",
                    },
                    timeout_s=5.0,
                )
                self.assertTrue(r.get("ok"))
                self.assertTrue(r["data"]["local_receipt"])
                st = ipc_call(socket_path=sock, request={"op": "status"}, timeout_s=5.0)
                self.assertEqual(st["data"]["outbound_artifacts_logged"], 1)
            finally:
                stop.set()
                th.join(timeout=10.0)

    def test_peer_inbound_import_rejects_bad_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sock = Path(td) / "t.sock"
            stop = threading.Event()
            th = threading.Thread(target=lambda: serve_forever(socket_path=sock, stop_flag=stop), daemon=True)
            th.start()
            try:
                for _ in range(100):
                    if sock.exists():
                        break
                    time.sleep(0.05)
                r = ipc_call(
                    socket_path=sock,
                    request={
                        "op": "peer_inbound_import",
                        "signer": "a",
                        "payload_text": "{}",
                        "wrapper": {"destination_peer": uuid.uuid4().hex},
                    },
                    timeout_s=5.0,
                )
                self.assertFalse(r.get("ok"))
            finally:
                stop.set()
                th.join(timeout=10.0)


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
@unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "requires Unix domain sockets")
class SeckitdRelayInboundSqliteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.home_a = self.td / "home_a"
        self.home_b = self.td / "home_b"
        self.shared = self.td / "shared"
        for p in (self.home_a, self.home_b, self.shared):
            p.mkdir(parents=True, exist_ok=True)
        self.db_a = self.home_a / "vault.db"
        self.db_b = self.home_b / "vault.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "seckitd-phase5a-passphrase-test!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def test_peer_inbound_import_invokes_sync_import(self) -> None:
        init_identity(home=self.home_a)
        init_identity(home=self.home_b)
        pub_a = self.shared / "a.pub.json"
        pub_b = self.shared / "b.pub.json"
        export_public_identity(out=pub_a, home=self.home_a)
        export_public_identity(out=pub_b, home=self.home_b)
        add_peer_from_file(alias="b", path=pub_b, home=self.home_a)
        add_peer_from_file(alias="a", path=pub_a, home=self.home_b)

        ensure_registry_storage(home=self.home_a)
        set_secret(
            service="svc5",
            account="dev",
            name="K",
            value="v1",
            path=str(self.db_a),
            backend=BACKEND_SQLITE,
        )
        meta = EntryMetadata(
            name="K",
            service="svc5",
            account="dev",
            entry_type="secret",
            entry_kind="generic",
        )
        upsert_metadata(metadata=meta, home=self.home_a)

        id_a = load_identity(home=self.home_a)
        id_b = load_identity(home=self.home_b)
        peer_b = get_peer(alias="b", home=self.home_a)
        st_a = SqliteSecretStore(db_path=str(self.db_a), kek_keychain_path=None)
        res_a = st_a.resolve_by_locator(service="svc5", account="dev", name="K")
        self.assertIsNotNone(res_a)
        val_a = get_secret(
            service="svc5",
            account="dev",
            name="K",
            path=str(self.db_a),
            backend=BACKEND_SQLITE,
        )
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(peer_b.fingerprint, peer_b.box_public())],
            entries=[
                {
                    "metadata": res_a.metadata.to_dict(),
                    "origin_host": id_a.host_id,
                    "value": val_a,
                }
            ],
        )
        bundle_text = json.dumps(bundle)
        parse_bundle_file(bundle_text)

        sock = self.td / "ipc.sock"
        stop = threading.Event()
        repo_src = str(Path(__file__).resolve().parents[1] / "src")
        user_site = site.getusersitepackages()
        prev_pp = os.environ.get("PYTHONPATH", "")
        parts = [repo_src, user_site]
        if prev_pp:
            parts.append(prev_pp)
        py_path = os.pathsep.join(parts)
        child_env = {
            **os.environ,
            "HOME": str(self.home_b),
            "SECKIT_SQLITE_PASSPHRASE": os.environ["SECKIT_SQLITE_PASSPHRASE"],
            "SECKIT_DEFAULT_BACKEND": "sqlite",
            "SECKIT_SQLITE_DB": str(self.db_b),
            "PYTHONPATH": py_path,
        }
        ensure_registry_storage(home=self.home_b)

        def _run() -> None:
            serve_forever(
                socket_path=sock,
                stop_flag=stop,
                child_env=child_env,
            )

        th = threading.Thread(target=_run, daemon=True)
        th.start()
        try:
            for _ in range(200):
                if sock.exists():
                    break
                time.sleep(0.05)
            wrap = build_transport_message(
                source_peer=id_a.host_id,
                destination_peer=id_b.host_id,
                timestamp="2026-05-05T12:00:00Z",
                payload_type="peer_bundle",
                payload="opaque-not-used-for-validation",
            )
            r = ipc_call(
                socket_path=sock,
                request={
                    "op": "peer_inbound_import",
                    "signer": "a",
                    "wrapper": wrap,
                    "payload_text": bundle_text,
                },
                timeout_s=120.0,
            )
            self.assertTrue(r.get("ok"), msg=r)
            self.assertTrue(r["data"].get("seckit_ok"), msg=r)
            self.assertEqual(r["data"].get("stdout_tail"), "")
            self.assertEqual(r["data"].get("stderr_tail"), "")
            r2 = ipc_call(
                socket_path=sock,
                request={
                    "op": "peer_inbound_import",
                    "signer": "a",
                    "wrapper": wrap,
                    "payload_text": bundle_text,
                },
                timeout_s=120.0,
            )
            self.assertTrue(r2.get("ok"), msg=r2)
            self.assertTrue(r2["data"].get("seckit_ok"), msg=r2)
            val_b = get_secret(
                service="svc5",
                account="dev",
                name="K",
                path=str(self.db_b),
                backend=BACKEND_SQLITE,
            )
            self.assertEqual(val_b, "v1")
        finally:
            stop.set()
            th.join(timeout=120.0)


@unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "requires Unix domain sockets")
class SeckitdBindTests(unittest.TestCase):
    def test_bind_unix_socket_chmod_socket(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "s.sock"
            sk = bind_unix_socket(p)
            try:
                mode = p.stat().st_mode & 0o777
                self.assertEqual(mode, 0o600)
            finally:
                sk.close()
                if p.exists():
                    p.unlink()


class SeckitdImportLayerTest(unittest.TestCase):
    def test_seckitd_sources_do_not_import_cli_package(self) -> None:
        import ast

        root = Path(__file__).resolve().parents[1] / "src" / "secrets_kit" / "seckitd"
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.name.split(".")[0:2]
                        if len(name) >= 2 and name[0] == "secrets_kit" and name[1] == "cli":
                            self.fail(f"{path}: imports secrets_kit.cli")
                if isinstance(node, ast.ImportFrom) and node.module:
                    parts = node.module.split(".")
                    if len(parts) >= 2 and parts[0] == "secrets_kit" and parts[1] == "cli":
                        self.fail(f"{path}: imports from secrets_kit.cli")


if __name__ == "__main__":
    unittest.main()
