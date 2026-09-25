from __future__ import annotations

import argparse
import base64
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.gate import SQLITE_PATH_ENV, open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.storage_mode import initialize_sqlite_storage_mode
from secrets_kit.backends.sqlite.transactions import create_transaction
from secrets_kit.cli.commands.daemon import (
    cmd_daemon_ping,
    cmd_daemon_start,
    cmd_daemon_status,
    cmd_daemon_stop,
)
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.cli.commands.internal import cmd_internal_apply_envelope
from secrets_kit.cli.main import main
from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.keys import generate_x25519_keypair
from secrets_kit.crypto.signatures import generate_ed25519_keypair
from secrets_kit.daemon.client import (
    DAEMON_STARTUP_TIMEOUT_SECONDS,
    TCP_HOST,
    DaemonError,
    daemon_status,
    metadata_path,
    ping_daemon,
    read_metadata,
    request_daemon,
    request_daemon_tcp,
    request_opaque_route,
    send_opaque_tcp,
    start_daemon,
    stop_daemon,
    wait_until_running,
)
from secrets_kit.daemon.server import (
    _handle_connection,
    _handle_request,
    _OutboundRuntimeScheduler,
)
from secrets_kit.models import EntryMetadata
from secrets_kit.protocol.envelope import (
    EnvelopeValidationError,
    build_transaction_envelope,
    canonical_envelope_bytes,
    canonical_envelope_dict,
    parse_envelope_mapping,
    payload_commitment,
)
from secrets_kit.protocol.envelope_signing import sign_envelope
from secrets_kit.protocol.payload_codec import (
    EnvelopePayloadContext,
    encoded_payload_bytes,
    encrypted_envelope_payload_codec,
)
from secrets_kit.runtime.inbound_envelopes import _decode_inbound_envelope_payload
from tests.canonical_id_helpers import tid

PEER_GROUP_ID = tid("peer_group", "daemon-peer-group")
NODE_ID = tid("node", "daemon-node")
REMOTE_NODE_ID = tid("node", "daemon-remote-node")
SECRET_ID = tid("secret", "daemon-secret")
OWNER_ID = tid("owner", "daemon-owner")
SERVICE_GROUP_ID = tid("service_group", "daemon-service-group")
TRANSACTION_ID = tid("transaction", "daemon-transaction")
SECRET_SET_TRANSACTION_ID = tid("transaction", "secret-set-transaction")
BAD_SECRET_SET_TXN_ID = tid("transaction", "daemon-bad-secret-set")
NODE_SIGNING_PRIVATE_KEY, NODE_SIGNING_PUBLIC_KEY = generate_ed25519_keypair()
REMOTE_SIGNING_PRIVATE_KEY, REMOTE_SIGNING_PUBLIC_KEY = generate_ed25519_keypair()


def _send_envelope_tcp(*, envelope: dict[str, object], port: int | None = None) -> dict[str, object]:
    return send_opaque_tcp(
        payload=canonical_envelope_bytes(envelope=parse_envelope_mapping(payload=envelope)),
        port=port,
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _transaction_envelope(
    *,
    transaction_id: str = TRANSACTION_ID,
    transaction_type: str = "vocabulary.tag.upsert",
    origin_node_id: str = NODE_ID,
    source_node_id: str | None = None,
    destination_node_id: str | None = None,
    recipient_sqlite_path: Path | None = None,
    payload: dict[str, object] | None = None,
    **overrides: object,
) -> dict[str, object]:
    conn = connect_sqlite(path=recipient_sqlite_path) if recipient_sqlite_path else open_sqlite_backend()
    try:
        if recipient_sqlite_path:
            with mock.patch.dict(os.environ, {"SECKIT_SQLITE_NODE_IDENTITY_KEY_PATH": str(recipient_sqlite_path.with_suffix(".identity"))}):
                identity = load_sqlite_node_identity_material(conn=conn)
        else:
            identity = load_sqlite_node_identity_material(conn=conn)
    finally:
        conn.close()
    destination_node_id = destination_node_id or identity.node_id
    transaction = create_transaction(
        transaction_id=transaction_id,
        transaction_type=transaction_type,
        origin_node_id=origin_node_id,
        created_at="2026-06-05T00:00:00+00:00",
        payload=payload
        if payload is not None
        else {
            "tag_id": "tag-1",
            "name": "prod",
            "operator_comment": "inbound daemon test",
        },
    )
    envelope = canonical_envelope_dict(
        envelope=_signed_envelope(
            envelope=build_transaction_envelope(
                payload_codec=encrypted_envelope_payload_codec(recipient_node_id=destination_node_id, recipient_public_key=identity.encryption.public_key),
                transaction=transaction,
                destination_node_id=destination_node_id,
                created_at="2026-06-05T00:00:00+00:00",
            ),
            signer_node_id=origin_node_id,
        )
    )
    if source_node_id is not None:
        envelope["source_node_id"] = source_node_id
    if overrides:
        envelope.update(overrides)
    if source_node_id is not None or overrides:
        payload_obj = envelope["payload"]
        if isinstance(payload_obj, dict):
            envelope["payload_hash"] = payload_commitment(
                encoded_payload_bytes=encoded_payload_bytes(payload=payload_obj)
            )
        try:
            _resign_envelope(envelope=envelope)
        except EnvelopeValidationError:
            pass
    return envelope


def _envelope(**overrides: object) -> dict[str, object]:
    return _transaction_envelope(**overrides)


def _decoded_transaction_payload(envelope: dict[str, object]) -> dict[str, object]:
    payload = json.loads(_decode_inbound_envelope_payload(envelope=parse_envelope_mapping(payload=envelope)).decode("utf-8"))
    assert isinstance(payload, dict)
    return payload


def _replace_decoded_transaction_payload(
    envelope: dict[str, object],
    payload: dict[str, object],
) -> None:
    conn = open_sqlite_backend()
    try:
        identity = load_sqlite_node_identity_material(conn=conn)
    finally:
        conn.close()
    canonical = parse_envelope_mapping(payload=envelope)
    record = encrypted_envelope_payload_codec(
        recipient_node_id=canonical.destination_node_id,
        recipient_public_key=identity.encryption.public_key,
        context=EnvelopePayloadContext(envelope_id=canonical.envelope_id, source_node_id=canonical.source_node_id, destination_node_id=canonical.destination_node_id, transaction_id=canonical.transaction_id, envelope_version=canonical.envelope_version, protocol_version=canonical.protocol_version),
    ).encode(
        canonical_payload_bytes=canonical_json_bytes(payload)
    )
    envelope["payload"] = record.payload
    envelope["encryption_metadata"] = record.encryption_metadata
    envelope["payload_hash"] = payload_commitment(encoded_payload_bytes=record.encoded_payload_bytes)
    _resign_envelope(envelope=envelope)


def _signed_envelope(*, envelope: object, signer_node_id: str) -> object:
    private_key, public_key = _signing_keypair_for_node(node_id=signer_node_id)
    return sign_envelope(
        envelope=envelope,
        signer_node_id=signer_node_id,
        signing_private_key=private_key,
        signing_public_key=public_key,
    )


def _resign_envelope(*, envelope: dict[str, object]) -> None:
    envelope["signature_metadata"] = None
    canonical = parse_envelope_mapping(payload=envelope)
    signed = _signed_envelope(envelope=canonical, signer_node_id=canonical.source_node_id)
    envelope.clear()
    envelope.update(canonical_envelope_dict(envelope=signed))


def _signing_keypair_for_node(*, node_id: str) -> tuple[bytes, bytes]:
    if node_id == REMOTE_NODE_ID:
        return REMOTE_SIGNING_PRIVATE_KEY, REMOTE_SIGNING_PUBLIC_KEY
    return NODE_SIGNING_PRIVATE_KEY, NODE_SIGNING_PUBLIC_KEY


def _secret_set_transaction_envelope(
    *, transaction_id: str = SECRET_SET_TRANSACTION_ID
) -> dict[str, object]:
    return _transaction_envelope(
        transaction_id=transaction_id,
        transaction_type="secret.set",
        payload={
            "secret_id": SECRET_ID,
            "owner_id": OWNER_ID,
            "service_group_id": SERVICE_GROUP_ID,
            "entry_type": "secret",
            "entry_kind": "api_key",
            "name": "NAME_1",
            "service": "svc-1",
            "account": "acct-1",
            "locator_hash_b64": _b64(b"locator-1"),
            "encrypted_name_b64": _b64(b"name-1"),
            "encrypted_payload_b64": _b64(b"payload-1"),
            "content_hash_b64": _b64(b"content-1"),
        },
    )


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((TCP_HOST, 0))
        return int(sock.getsockname()[1])


def _seed_known_origin_node(*, sqlite_path: Path) -> None:
    conn = connect_sqlite(path=sqlite_path)
    try:
        bootstrap_schema(conn=conn)
        initialize_sqlite_storage_mode(conn=conn, mode="plaintext")
        conn.execute(
            "INSERT OR IGNORE INTO peer_groups (peer_group_id) VALUES (?)",
            (PEER_GROUP_ID,),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO nodes (
                node_id,
                peer_group_id,
                signing_public_key,
                signing_algorithm,
                encryption_public_key,
                encryption_algorithm,
                authorization_mode,
                state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                NODE_ID,
                PEER_GROUP_ID,
                NODE_SIGNING_PUBLIC_KEY,
                "ed25519",
                generate_x25519_keypair()[1],
                "x25519",
                "all",
                "active",
            ),
        )
    finally:
        conn.close()


def _start_daemon_process(
    *,
    runtime_dir: Path,
    tcp_port: int,
    peers: str = "",
    sqlite_path: Path | None = None,
) -> subprocess.Popen[bytes]:
    runtime_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["SECKIT_DAEMON_RUNTIME_DIR"] = str(runtime_dir)
    env["SECKIT_DAEMON_TCP_PORT"] = str(tcp_port)
    env["SECKIT_DAEMON_PEERS"] = peers
    if sqlite_path is not None:
        env[SQLITE_PATH_ENV] = str(sqlite_path)
        env["SECKIT_SQLITE_NODE_IDENTITY_KEY_PATH"] = str(sqlite_path.with_suffix(".identity"))
        with mock.patch.dict(os.environ, env), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            if cmd_init_operator(args=argparse.Namespace(home=str(runtime_dir), yes=True, unsafe_plaintext_storage=True)) != 0:
                raise AssertionError("test peer initialization failed")
            _seed_known_origin_node(sqlite_path=sqlite_path)
    return subprocess.Popen(
        [sys.executable, "-m", "secrets_kit.daemon.server"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=env,
    )


def _wait_for_tcp_ping(*, port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if request_daemon_tcp(command="ping", port=port).get("response") == "pong":
                return
        except Exception:
            pass
        time.sleep(0.05)
    raise AssertionError(f"daemon did not become reachable on tcp port {port}")


def _stop_daemon_process(*, proc: subprocess.Popen[bytes], port: int) -> None:
    try:
        request_daemon_tcp(command="shutdown", port=port)
    except Exception:
        pass
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)


def _cleanup_daemon_runtime(*, runtime_path: Path) -> None:
    metadata = _read_daemon_metadata(runtime_path=runtime_path)
    pid = metadata.get("pid")
    try:
        stop_daemon(timeout=2.0)
    except Exception:
        pass
    if not isinstance(pid, int) or pid <= 0 or pid == os.getpid():
        return
    if _wait_for_pid_exit(pid=pid, timeout=2.0):
        return
    if not _pid_is_running(pid=pid):
        return
    if not _pid_looks_like_test_daemon(pid=pid):
        return
    os.kill(pid, signal.SIGTERM)
    if _wait_for_pid_exit(pid=pid, timeout=2.0):
        return
    os.kill(pid, signal.SIGKILL)
    _wait_for_pid_exit(pid=pid, timeout=2.0)


def _read_daemon_metadata(*, runtime_path: Path) -> dict[str, object]:
    path = runtime_path / "seckitd.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def _pid_is_running(*, pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return not _pid_is_zombie(pid=pid)


def _pid_is_zombie(*, pid: int) -> bool:
    try:
        completed = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat="],
            capture_output=True,
            check=False,
            text=True,
            timeout=2.0,
        )
    except Exception:
        return False
    if completed.returncode != 0:
        return False
    return completed.stdout.strip().startswith("Z")


def _pid_looks_like_test_daemon(*, pid: int) -> bool:
    try:
        completed = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            check=False,
            text=True,
            timeout=2.0,
        )
    except Exception:
        return False
    if completed.returncode != 0:
        return False
    return "secrets_kit.daemon.server" in completed.stdout


def _wait_for_pid_exit(*, pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_running(pid=pid):
            return True
        time.sleep(0.05)
    return not _pid_is_running(pid=pid)


class DaemonTest(unittest.TestCase):
    def test_delivery_scheduler_coalesces_recovery_events_and_cancels_shutdown(self) -> None:
        first = mock.Mock()
        first.poll.return_value = None
        second = mock.Mock()
        second.poll.return_value = None
        scheduler = _OutboundRuntimeScheduler(startup_grace_seconds=60.0)
        node_id = tid("node", "scheduler-recovered-peer")
        with mock.patch(
            "secrets_kit.daemon.server._start_outbound_runtime_worker",
            side_effect=[first, second],
        ) as start:
            scheduler.observe({"event": "route_installed", "node_id": node_id})
            scheduler.observe({"event": "route_installed", "node_id": node_id})
            scheduler.poll()
            start.assert_called_once_with(recovered_peer_ids=(node_id,))
            scheduler.wake()
            self.assertEqual(scheduler.timeout(maximum=0.125), 0.125)
            scheduler.poll()
            self.assertEqual(start.call_count, 1)
            first.poll.return_value = 0
            first.returncode = 0
            first.communicate.return_value = (
                b'{"version":1,"sent_count":0,"next_attempt_at":null}',
                b"",
            )
            scheduler.poll()
            self.assertEqual(start.call_count, 2)
            start.assert_called_with(recovered_peer_ids=())
            scheduler.stop()
        second.terminate.assert_called_once()
        second.wait.assert_called_once_with(timeout=2.0)

    def test_local_delivery_wake_control_is_coalescible_callback(self) -> None:
        wake = mock.Mock()
        response, should_stop = _handle_request(
            b'{"kind":"control","operation":"delivery-wake","version":1}',
            transport="uds",
            delivery_wake=wake,
        )
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["response"], "delivery_woken")
        wake.assert_called_once_with()

    def test_local_admission_change_wakes_binding_reconsideration_only(self) -> None:
        admission_wake = mock.Mock()
        delivery_wake = mock.Mock()
        response, should_stop = _handle_request(
            b'{"kind":"control","operation":"admission-changed","version":1}',
            transport="uds",
            delivery_wake=delivery_wake,
            admission_wake=admission_wake,
        )
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["response"], "admission_reconsidered")
        admission_wake.assert_called_once_with()
        delivery_wake.assert_not_called()

    def test_remote_admission_change_control_is_rejected(self) -> None:
        admission_wake = mock.Mock()
        response, should_stop = _handle_request(
            b'{"kind":"control","operation":"admission-changed","version":1}',
            transport="libp2p",
            admission_wake=admission_wake,
        )
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["error"], "control_forbidden")
        admission_wake.assert_not_called()

    def test_read_only_peer_commands_emit_no_daemon_event(self) -> None:
        request = mock.Mock()
        parser = mock.Mock()
        with (
            mock.patch("secrets_kit.cli.main.build_parser", return_value=parser),
            mock.patch("secrets_kit.daemon.client.request_daemon", request),
        ):
            for peer_command in ("list", "show", "export-identity"):
                with self.subTest(peer_command=peer_command):
                    command = mock.Mock(return_value=0)
                    parser.parse_args.return_value = argparse.Namespace(
                        command="peer",
                        peer_command=peer_command,
                        func=command,
                    )
                    self.assertEqual(main(), 0)
        request.assert_not_called()

    def test_successful_peer_admission_mutations_emit_daemon_events(self) -> None:
        parser = mock.Mock()
        for peer_command in ("accept", "import-acceptance"):
            with self.subTest(peer_command=peer_command):
                parser.parse_args.return_value = argparse.Namespace(
                    command="peer",
                    peer_command=peer_command,
                    func=mock.Mock(return_value=0),
                )
                with (
                    mock.patch(
                        "secrets_kit.cli.main.build_parser",
                        return_value=parser,
                    ),
                    mock.patch(
                        "secrets_kit.daemon.client.request_daemon"
                    ) as request,
                ):
                    self.assertEqual(main(), 0)
                self.assertEqual(
                    request.call_args_list,
                    [
                        mock.call(command="admission-changed", timeout=0.2),
                        mock.call(command="delivery-wake", timeout=0.2),
                    ],
                )

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(
            "os.environ",
            {
                "HOME": self.tmp.name,
                "SECKIT_DAEMON_RUNTIME_DIR": self.tmp.name,
                "SECKIT_DAEMON_TRANSPORT": "direct_tcp",
                "SECKIT_UNSAFE_TEST_DIRECT_TCP": "1",
                SQLITE_PATH_ENV: str(Path(self.tmp.name) / "seckit.sqlite"),
            },
            clear=False,
        )
        self.env.start()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                cmd_init_operator(
                    args=argparse.Namespace(
                        yes=True,
                        home=self.tmp.name,
                        init_target=None,
                        backend="sqlite",
                        unsafe_plaintext_storage=True,
                    )
                ),
                0,
            )
        _seed_known_origin_node(sqlite_path=Path(self.tmp.name) / "seckit.sqlite")

    def tearDown(self) -> None:
        runtime_path = Path(self.tmp.name)
        try:
            _cleanup_daemon_runtime(runtime_path=runtime_path)
        finally:
            self.env.stop()
            self.tmp.cleanup()

    def test_start_creates_reachable_daemon_and_metadata(self) -> None:
        self.assertTrue(start_daemon())
        self.assertTrue(ping_daemon())
        metadata = read_metadata()
        self.assertIsInstance(metadata.get("pid"), int)
        self.assertEqual(metadata.get("uds_path"), str(Path(self.tmp.name) / "seckitd.sock"))
        self.assertIsInstance(metadata.get("startup_timestamp"), str)

    def test_cleanup_helper_stops_started_daemon(self) -> None:
        self.assertTrue(start_daemon())
        pid = read_metadata().get("pid")
        self.assertIsInstance(pid, int)
        _cleanup_daemon_runtime(runtime_path=Path(self.tmp.name))
        self.assertFalse(ping_daemon())
        self.assertFalse(_pid_is_running(pid=pid))

    def test_ping_command_round_trips_pong(self) -> None:
        start_daemon()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_daemon_ping(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue().strip(), "pong")

    def test_status_verifies_socket_reachability(self) -> None:
        start_daemon()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_daemon_status(args=argparse.Namespace())
        self.assertEqual(code, 0)
        text = stdout.getvalue()
        self.assertIn("running: true", text)
        self.assertIn("pid:", text)
        self.assertIn("uds path:", text)
        self.assertIn("tcp port:", text)
        self.assertIn("startup timestamp:", text)

    def test_stop_shuts_down_daemon(self) -> None:
        start_daemon()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_daemon_stop(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue().strip(), "stopped")
        self.assertFalse(ping_daemon())

    def test_unknown_control_is_rejected(self) -> None:
        start_daemon()
        response = request_daemon(command="unknown")
        self.assertEqual(response.get("status"), "error")
        self.assertEqual(response.get("error"), "unsupported_control")

    def test_tcp_ping_returns_pong(self) -> None:
        start_daemon()
        response = request_daemon_tcp(command="ping")
        self.assertEqual(response, {"version": 1, "status": "ok", "response": "pong"})

    def test_tcp_unknown_control_is_rejected(self) -> None:
        start_daemon()
        response = request_daemon_tcp(command="unknown")
        self.assertEqual(response.get("status"), "error")
        self.assertEqual(response.get("error"), "unsupported_control")

    def test_uds_application_bytes_require_route_frame(self) -> None:
        response, should_stop = _handle_request(b"opaque application bytes", transport="uds")
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response), {"version": 1, "status": "error", "error": "route_frame_required"})

    def test_tcp_opaque_bytes_are_handed_to_runtime(self) -> None:
        raw = b"opaque application bytes"
        with mock.patch("secrets_kit.daemon.server._invoke_runtime", return_value=True) as invoke:
            response, should_stop = _handle_request(raw, transport="tcp")
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response), {"version": 1, "status": "ok", "response": "delivered"})
        invoke.assert_called_once_with(data=raw)

    def test_oversized_request_is_rejected(self) -> None:
        server_sock, client_sock = socket.socketpair()
        try:
            client_sock.sendall(b'{"version":1,"kind":"control","operation":"ping"}')
            client_sock.shutdown(socket.SHUT_WR)
            with mock.patch("secrets_kit.daemon.server.MAX_REQUEST_BYTES", 8):
                should_stop = _handle_connection(server_sock, transport="uds")
            self.assertFalse(should_stop)
            payload = json.loads(client_sock.recv(4096).decode("utf-8"))
            self.assertEqual(payload.get("status"), "error")
            self.assertEqual(payload.get("error"), "bad_request")
            self.assertEqual(payload.get("details"), "request_too_large")
        finally:
            client_sock.close()

    def test_incomplete_request_times_out(self) -> None:
        server_sock, client_sock = socket.socketpair()
        try:
            client_sock.sendall(b'{"version": 1')
            with mock.patch("secrets_kit.daemon.server.REQUEST_READ_TIMEOUT_SECONDS", 0.01):
                should_stop = _handle_connection(server_sock, transport="uds")
            self.assertFalse(should_stop)
            payload = json.loads(client_sock.recv(4096).decode("utf-8"))
            self.assertEqual(payload.get("status"), "error")
            self.assertEqual(payload.get("error"), "bad_request")
            self.assertEqual(payload.get("details"), "request_timeout")
        finally:
            client_sock.close()

    def test_opaque_route_uses_bounded_default_timeout(self) -> None:
        response = {"version": 1, "status": "ok", "response": "delivered"}
        with mock.patch(
            "secrets_kit.daemon.client._request_socket", return_value=response
        ) as request:
            self.assertEqual(
                request_opaque_route(peer_id=NODE_ID, payload=b"opaque"),
                response,
            )
        self.assertEqual(request.call_args.kwargs["timeout"], 15.0)
        self.assertIn(b"payload_b64", request.call_args.kwargs["payload"])

    def test_one_peer_receives_transaction_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            peer_port = _free_tcp_port()
            forwarder_port = _free_tcp_port()
            peer = _start_daemon_process(
                runtime_dir=root / "peer",
                tcp_port=peer_port,
                sqlite_path=root / "peer.sqlite",
            )
            forwarder = _start_daemon_process(
                runtime_dir=root / "forwarder",
                tcp_port=forwarder_port,
                peers=f"{NODE_ID}@{TCP_HOST}:{peer_port}",
                sqlite_path=root / "forwarder.sqlite",
            )
            try:
                _wait_for_tcp_ping(port=peer_port)
                _wait_for_tcp_ping(port=forwarder_port)
                with mock.patch.dict(
                    "os.environ",
                    {"SECKIT_DAEMON_RUNTIME_DIR": str(root / "forwarder")},
                    clear=False,
                ):
                    response = request_opaque_route(
                        peer_id=NODE_ID,
                        payload=canonical_envelope_bytes(
                            envelope=parse_envelope_mapping(payload=_transaction_envelope(recipient_sqlite_path=root / "peer.sqlite"))
                        ),
                    )
                self.assertEqual(
                    response,
                    {"version": 1, "status": "ok", "response": "delivered"},
                )
            finally:
                _stop_daemon_process(proc=forwarder, port=forwarder_port)
                _stop_daemon_process(proc=peer, port=peer_port)

    def test_multiple_peers_receive_transaction_envelope_with_explicit_extended_timeout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            peer_a_port = _free_tcp_port()
            peer_b_port = _free_tcp_port()
            forwarder_port = _free_tcp_port()
            peer_a = _start_daemon_process(
                runtime_dir=root / "peer-a",
                tcp_port=peer_a_port,
                sqlite_path=root / "peer-a.sqlite",
            )
            peer_b = _start_daemon_process(
                runtime_dir=root / "peer-b",
                tcp_port=peer_b_port,
                sqlite_path=root / "peer-b.sqlite",
            )
            forwarder = _start_daemon_process(
                runtime_dir=root / "forwarder",
                tcp_port=forwarder_port,
                peers=f"{NODE_ID}@{TCP_HOST}:{peer_a_port},{REMOTE_NODE_ID}@{TCP_HOST}:{peer_b_port}",
                sqlite_path=root / "forwarder.sqlite",
            )
            try:
                _wait_for_tcp_ping(port=peer_a_port)
                _wait_for_tcp_ping(port=peer_b_port)
                _wait_for_tcp_ping(port=forwarder_port)
                with mock.patch.dict(
                    "os.environ",
                    {"SECKIT_DAEMON_RUNTIME_DIR": str(root / "forwarder")},
                    clear=False,
                ):
                    payload = canonical_envelope_bytes(
                        envelope=parse_envelope_mapping(payload=_transaction_envelope(recipient_sqlite_path=root / "peer-a.sqlite"))
                    )
                    first = request_opaque_route(
                        peer_id=NODE_ID, payload=payload, timeout=5.0
                    )
                    second = request_opaque_route(
                        peer_id=REMOTE_NODE_ID,
                        payload=canonical_envelope_bytes(envelope=parse_envelope_mapping(payload=_transaction_envelope(recipient_sqlite_path=root / "peer-b.sqlite"))),
                        timeout=5.0,
                    )
                self.assertEqual(first.get("response"), "delivered")
                self.assertEqual(second.get("response"), "delivered")
            finally:
                _stop_daemon_process(proc=forwarder, port=forwarder_port)
                _stop_daemon_process(proc=peer_b, port=peer_b_port)
                _stop_daemon_process(proc=peer_a, port=peer_a_port)

    def test_peer_acknowledgement_failure_propagates_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_peer_port = _free_tcp_port()
            forwarder_port = _free_tcp_port()
            forwarder = _start_daemon_process(
                runtime_dir=root / "forwarder",
                tcp_port=forwarder_port,
                peers=f"{NODE_ID}@{TCP_HOST}:{missing_peer_port}",
                sqlite_path=root / "forwarder.sqlite",
            )
            try:
                _wait_for_tcp_ping(port=forwarder_port)
                with mock.patch.dict(
                    "os.environ",
                    {"SECKIT_DAEMON_RUNTIME_DIR": str(root / "forwarder")},
                    clear=False,
                ):
                    response = request_opaque_route(
                        peer_id=NODE_ID,
                        payload=canonical_envelope_bytes(
                            envelope=parse_envelope_mapping(payload=_transaction_envelope())
                        ),
                    )
                self.assertEqual(response.get("status"), "error")
                self.assertEqual(response.get("error"), "transport_delivery_failed")
            finally:
                _stop_daemon_process(proc=forwarder, port=forwarder_port)

    def test_uds_does_not_validate_application_envelope_fields(self) -> None:
        envelope = _envelope()
        envelope.pop("message_id")
        raw_response, should_stop = _handle_request(
            json.dumps(envelope).encode("utf-8"),
            transport="uds",
        )
        self.assertFalse(should_stop)
        response = json.loads(raw_response.decode("utf-8"))
        self.assertEqual(response.get("version"), 1)
        self.assertEqual(response.get("status"), "error")
        self.assertEqual(response.get("error"), "route_frame_required")

    def test_uds_does_not_validate_application_envelope_versions(self) -> None:
        raw_response, should_stop = _handle_request(
            json.dumps(_envelope(version=999)).encode("utf-8"),
            transport="uds",
        )
        self.assertFalse(should_stop)
        response = json.loads(raw_response.decode("utf-8"))
        self.assertEqual(response.get("version"), 1)
        self.assertEqual(response.get("status"), "error")
        self.assertEqual(response.get("error"), "route_frame_required")

    def test_tcp_port_collision_selects_next_available_port(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind((TCP_HOST, 0))
            occupied.listen()
            requested_port = int(occupied.getsockname()[1])
            with mock.patch.dict(
                "os.environ", {"SECKIT_DAEMON_TCP_PORT": str(requested_port)}, clear=False
            ):
                start_daemon()
        tcp_port = read_metadata().get("tcp_port")
        self.assertIsInstance(tcp_port, int)
        self.assertGreater(tcp_port, requested_port)
        self.assertEqual(
            request_daemon_tcp(command="ping", port=int(tcp_port)),
            {"version": 1, "status": "ok", "response": "pong"},
        )

    def test_metadata_reports_active_tcp_port(self) -> None:
        start_daemon()
        metadata = read_metadata()
        self.assertIsInstance(metadata.get("tcp_port"), int)
        self.assertEqual(daemon_status().get("tcp_port"), metadata.get("tcp_port"))

    def test_stale_metadata_without_socket_is_not_running(self) -> None:
        Path(self.tmp.name).mkdir(parents=True, exist_ok=True)
        metadata_path().write_text(
            json.dumps(
                {
                    "pid": 999999,
                    "uds_path": str(Path(self.tmp.name) / "seckitd.sock"),
                    "startup_timestamp": "2026-06-05T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        status = daemon_status()
        self.assertFalse(status["running"])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_daemon_status(args=argparse.Namespace())
        self.assertEqual(code, 1)
        self.assertIn("running: false", stdout.getvalue())

    def test_start_when_already_running_does_not_spawn_second_daemon(self) -> None:
        self.assertTrue(start_daemon())
        first_pid = read_metadata().get("pid")
        self.assertFalse(start_daemon())
        self.assertEqual(read_metadata().get("pid"), first_pid)

    def test_start_uses_bounded_runtime_startup_timeout(self) -> None:
        with (
            mock.patch("secrets_kit.daemon.client.ping_daemon", side_effect=[False, False]),
            mock.patch("secrets_kit.daemon.client.subprocess.Popen"),
            mock.patch(
                "secrets_kit.daemon.client.wait_until_running", return_value=True
            ) as wait,
        ):
            self.assertTrue(start_daemon())
        wait.assert_called_once_with(timeout=DAEMON_STARTUP_TIMEOUT_SECONDS)
        self.assertEqual(DAEMON_STARTUP_TIMEOUT_SECONDS, 30.0)

    def test_start_reports_true_bounded_startup_failure(self) -> None:
        with (
            mock.patch("secrets_kit.daemon.client.ping_daemon", side_effect=[False, False]),
            mock.patch("secrets_kit.daemon.client.subprocess.Popen") as spawn,
            mock.patch("secrets_kit.daemon.client.wait_until_running", return_value=False),
            self.assertRaisesRegex(DaemonError, "daemon did not become reachable"),
        ):
            start_daemon()
        spawn.return_value.terminate.assert_called_once_with()
        spawn.return_value.wait.assert_called_once_with(timeout=2.0)

    def test_start_kills_and_reaps_child_when_termination_times_out(self) -> None:
        with (
            mock.patch("secrets_kit.daemon.client.ping_daemon", side_effect=[False, False]),
            mock.patch("secrets_kit.daemon.client.subprocess.Popen") as spawn,
            mock.patch("secrets_kit.daemon.client.wait_until_running", return_value=False),
        ):
            spawn.return_value.wait.side_effect = [subprocess.TimeoutExpired("daemon", 2), 0]
            with self.assertRaisesRegex(DaemonError, "daemon did not become reachable"):
                start_daemon()
        spawn.return_value.kill.assert_called_once_with()
        self.assertEqual(spawn.return_value.wait.call_count, 2)

    def test_successful_start_retains_child_for_background_reaping(self) -> None:
        with (
            mock.patch("secrets_kit.daemon.client.ping_daemon", side_effect=[False, False]),
            mock.patch("secrets_kit.daemon.client.subprocess.Popen") as spawn,
            mock.patch("secrets_kit.daemon.client.wait_until_running", return_value=True),
            mock.patch("secrets_kit.daemon.client.threading.Thread") as thread,
        ):
            self.assertTrue(start_daemon())
        thread.assert_called_once_with(target=spawn.return_value.wait, name="seckit-daemon-reaper", daemon=True)
        thread.return_value.start.assert_called_once_with()
        spawn.return_value.terminate.assert_not_called()

    def test_wait_until_running_honors_explicit_zero_timeout(self) -> None:
        with mock.patch("secrets_kit.daemon.client.ping_daemon", return_value=False) as ping:
            self.assertFalse(wait_until_running(timeout=0.0))
        ping.assert_called_once_with(timeout=0.2)

    def test_start_command_reports_status(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_daemon_start(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertIn("running: true", stdout.getvalue())

    def test_ping_command_reports_unreachable_daemon(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = cmd_daemon_ping(args=argparse.Namespace())
        self.assertEqual(code, 1)
        self.assertIn("daemon is not reachable", stderr.getvalue())

    def test_normal_cli_command_does_not_contact_absent_daemon(self) -> None:
        self.assertFalse(ping_daemon())
        stdout = io.StringIO()
        with (
            mock.patch("sys.argv", ["seckit", "config", "path"]),
            mock.patch("secrets_kit.daemon.client.ping_daemon") as ping,
            mock.patch("secrets_kit.daemon.client.start_daemon") as start,
            redirect_stdout(stdout),
        ):
            code = main()
        self.assertEqual(code, 0)
        ping.assert_not_called()
        start.assert_not_called()
        self.assertFalse(ping_daemon())
        self.assertIn(".config/seckit/defaults.json", stdout.getvalue())

    def test_daemon_status_command_does_not_start_daemon(self) -> None:
        with (
            mock.patch("sys.argv", ["seckit", "daemon", "status"]),
            mock.patch("secrets_kit.cli.commands.daemon.start_daemon") as start,
            redirect_stdout(io.StringIO()),
        ):
            code = main()
        self.assertEqual(code, 1)
        start.assert_not_called()

    def test_envelope_inspection_command_does_not_auto_start(self) -> None:
        with (
            mock.patch("sys.argv", ["seckit", "envelope", "list"]),
            mock.patch("secrets_kit.daemon.client.start_daemon") as start,
            redirect_stdout(io.StringIO()),
        ):
            code = main()
        self.assertEqual(code, 0)
        start.assert_not_called()

    def test_transaction_inspection_command_does_not_auto_start(self) -> None:
        with (
            mock.patch("sys.argv", ["seckit", "transaction", "list"]),
            mock.patch("secrets_kit.daemon.client.start_daemon") as start,
            redirect_stdout(io.StringIO()),
        ):
            code = main()
        self.assertEqual(code, 0)
        start.assert_not_called()

    def test_sqlite_crud_succeeds_without_running_daemon(self) -> None:
        commands = (
            [
                "seckit",
                "set",
                "--backend",
                "sqlite",
                "--service",
                "svc",
                "--account",
                "acct",
                "--name",
                "RB06_KEY",
                "--value",
                "secret",
            ],
            [
                "seckit",
                "get",
                "--backend",
                "sqlite",
                "--service",
                "svc",
                "--account",
                "acct",
                "--name",
                "RB06_KEY",
                "--raw",
            ],
            [
                "seckit",
                "list",
                "--backend",
                "sqlite",
                "--service",
                "svc",
                "--account",
                "acct",
            ],
            [
                "seckit",
                "delete",
                "--backend",
                "sqlite",
                "--service",
                "svc",
                "--account",
                "acct",
                "--name",
                "RB06_KEY",
                "--yes",
            ],
        )
        with (
            mock.patch("secrets_kit.daemon.client.ping_daemon") as ping,
            mock.patch(
                "secrets_kit.daemon.client.start_daemon",
                side_effect=DaemonError("daemon did not become reachable"),
            ) as start,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            for argv in commands:
                with self.subTest(command=argv[1]), mock.patch("sys.argv", argv):
                    self.assertEqual(main(), 0)
        ping.assert_not_called()
        start.assert_not_called()

    def test_daemon_startup_failure_does_not_break_keychain_crud(self) -> None:
        metadata = EntryMetadata(name="RB06_KEY", service="svc", account="acct")
        commands = (
            [
                "seckit",
                "set",
                "--backend",
                "keychain",
                "--service",
                "svc",
                "--account",
                "acct",
                "--name",
                "RB06_KEY",
                "--value",
                "secret",
            ],
            [
                "seckit",
                "get",
                "--backend",
                "keychain",
                "--service",
                "svc",
                "--account",
                "acct",
                "--name",
                "RB06_KEY",
            ],
            [
                "seckit",
                "list",
                "--backend",
                "keychain",
                "--service",
                "svc",
                "--account",
                "acct",
            ],
            [
                "seckit",
                "delete",
                "--backend",
                "keychain",
                "--service",
                "svc",
                "--account",
                "acct",
                "--name",
                "RB06_KEY",
                "--yes",
            ],
        )
        with (
            mock.patch("secrets_kit.cli.commands.set.write_secret"),
            mock.patch(
                "secrets_kit.cli.commands.get.read_secret_entry",
                return_value=("secret", metadata),
            ),
            mock.patch(
                "secrets_kit.cli.commands.list.list_secret_metadata",
                return_value=[metadata],
            ),
            mock.patch("secrets_kit.cli.commands.delete.delete_secret_entry"),
            mock.patch("secrets_kit.daemon.client.ping_daemon") as ping,
            mock.patch(
                "secrets_kit.daemon.client.start_daemon",
                side_effect=DaemonError("daemon did not become reachable"),
            ) as start,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            for argv in commands:
                with self.subTest(command=argv[1]), mock.patch("sys.argv", argv):
                    self.assertEqual(main(), 0)
        ping.assert_not_called()
        start.assert_not_called()

    def test_valid_stdin_envelope_command_succeeds(self) -> None:
        stdin = io.StringIO(json.dumps(_transaction_envelope()))
        with mock.patch("sys.stdin", stdin):
            code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
        self.assertEqual(code, 0)

    def test_invalid_stdin_envelope_command_fails(self) -> None:
        stdin = io.StringIO(json.dumps(_transaction_envelope()))
        payload = json.loads(stdin.getvalue())
        payload["version"] = 999
        stdin = io.StringIO(json.dumps(payload))
        stderr = io.StringIO()
        with mock.patch("sys.stdin", stdin), redirect_stderr(stderr):
            code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
        self.assertEqual(code, 1)
        self.assertIn("invalid envelope", stderr.getvalue())

    def test_inbound_transaction_rejects_unknown_origin_node(self) -> None:
        envelope = _transaction_envelope(origin_node_id=REMOTE_NODE_ID, source_node_id=REMOTE_NODE_ID)
        stderr = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(envelope))):
            with redirect_stderr(stderr):
                code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
        self.assertEqual(code, 1)
        self.assertIn("unknown peer", stderr.getvalue())
        conn = open_sqlite_backend()
        try:
            node_row = conn.execute(
                "SELECT node_id FROM nodes WHERE node_id = ?",
                (REMOTE_NODE_ID,),
            ).fetchone()
            self.assertIsNone(node_row)
        finally:
            conn.close()

    def test_tcp_payload_is_handed_to_runtime_without_daemon_parsing(self) -> None:
        raw = json.dumps(_transaction_envelope()).encode("utf-8")
        with mock.patch("secrets_kit.daemon.server._invoke_runtime", return_value=True) as invoke:
            response, should_stop = _handle_request(raw, transport="tcp")
        self.assertFalse(should_stop)
        self.assertEqual(
            json.loads(response.decode("utf-8")),
            {"version": 1, "status": "ok", "response": "delivered"},
        )
        invoke.assert_called_once_with(data=raw)

    def test_daemon_returns_transport_error_when_runtime_handoff_fails(self) -> None:
        raw = json.dumps(_transaction_envelope()).encode("utf-8")
        with mock.patch("secrets_kit.daemon.server._invoke_runtime", return_value=False):
            response, should_stop = _handle_request(raw, transport="tcp")
        self.assertFalse(should_stop)
        payload = json.loads(response.decode("utf-8"))
        self.assertEqual(payload.get("status"), "error")
        self.assertEqual(payload.get("error"), "runtime_handoff_failed")

    def test_tcp_transaction_returns_transport_receipt_when_runtime_succeeds(self) -> None:
        start_daemon()
        response = _send_envelope_tcp(envelope=_transaction_envelope())
        self.assertEqual(response, {"version": 1, "status": "ok", "response": "delivered"})

    def test_valid_inbound_transaction_envelope_inserts_and_applies_projection(self) -> None:
        stdin = io.StringIO(json.dumps(_transaction_envelope()))
        with mock.patch("sys.stdin", stdin):
            code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
        self.assertEqual(code, 0)
        conn = open_sqlite_backend()
        try:
            transaction_row = conn.execute(
                """
                SELECT transaction_id, state, applied_at
                FROM transactions
                WHERE transaction_id = ?
                """,
                (TRANSACTION_ID,),
            ).fetchone()
            self.assertIsNotNone(transaction_row)
            self.assertEqual(transaction_row["state"], "applied")
            self.assertIsNotNone(transaction_row["applied_at"])
            tag_row = conn.execute(
                "SELECT name FROM secret_tags WHERE tag_id = ?",
                ("tag-1",),
            ).fetchone()
            self.assertIsNotNone(tag_row)
            self.assertEqual(tag_row["name"], "prod")
        finally:
            conn.close()

    def test_inbound_transaction_envelope_invokes_payload_codec(self) -> None:
        stdin = io.StringIO(json.dumps(_transaction_envelope()))
        with mock.patch(
            "secrets_kit.runtime.inbound_envelopes._decode_inbound_envelope_payload",
            wraps=_decode_inbound_envelope_payload,
        ) as decode:
            with mock.patch("sys.stdin", stdin):
                code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
        self.assertEqual(code, 0)
        self.assertGreaterEqual(decode.call_count, 1)

    def test_duplicate_inbound_transaction_returns_success_noop(self) -> None:
        envelope = _transaction_envelope()
        for _ in range(2):
            with mock.patch("sys.stdin", io.StringIO(json.dumps(envelope))):
                code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
            self.assertEqual(code, 0)
        conn = open_sqlite_backend()
        try:
            count = conn.execute(
                "SELECT COUNT(*) AS count FROM transactions WHERE transaction_id = ?",
                (TRANSACTION_ID,),
            ).fetchone()["count"]
            self.assertEqual(count, 1)
        finally:
            conn.close()

    def test_invalid_transaction_payload_fails(self) -> None:
        envelope = _transaction_envelope()
        transaction = _decoded_transaction_payload(envelope)
        transaction.pop("transaction_id")
        _replace_decoded_transaction_payload(envelope, transaction)
        stderr = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(envelope))), redirect_stderr(stderr):
            code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
        self.assertEqual(code, 1)
        self.assertIn("transaction.transaction_id is required", stderr.getvalue())

    def test_unsupported_transaction_type_fails_through_apply_validation(self) -> None:
        envelope = _transaction_envelope(transaction_type="unsupported.transaction")
        stderr = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(envelope))), redirect_stderr(stderr):
            code = cmd_internal_apply_envelope(args=argparse.Namespace(stdin=True))
        self.assertEqual(code, 1)
        self.assertIn("transaction scope is unknown", stderr.getvalue())
        conn = open_sqlite_backend()
        try:
            count = conn.execute(
                "SELECT COUNT(*) AS count FROM transactions WHERE transaction_id = ?",
                (TRANSACTION_ID,),
            ).fetchone()["count"]
            self.assertEqual(count, 0)
        finally:
            conn.close()

    def test_daemon_tcp_returns_runtime_handoff_error_when_apply_fails(self) -> None:
        start_daemon()
        envelope = _secret_set_transaction_envelope(transaction_id=BAD_SECRET_SET_TXN_ID)
        transaction = _decoded_transaction_payload(envelope)
        payload = transaction["payload"]
        assert isinstance(payload, dict)
        payload.pop("encrypted_payload_b64")
        _replace_decoded_transaction_payload(envelope, transaction)
        response = _send_envelope_tcp(envelope=envelope)
        self.assertEqual(response.get("status"), "error")
        self.assertEqual(response.get("error"), "runtime_handoff_failed")


if __name__ == "__main__":
    unittest.main()
