from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from secrets_kit.backends.sqlite.connection import transaction as sqlite_transaction
from secrets_kit.backends.sqlite.gate import SQLITE_PATH_ENV, open_sqlite_backend
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.node_identity import (
    SQLITE_NODE_IDENTITY_KEY_ENV,
    load_sqlite_node_identity_material,
)
from secrets_kit.backends.sqlite.peer_admission import (
    PEER_ADMISSION_ACCEPT,
    PeerPublicIdentity,
    create_signed_peer_admission_decision,
    create_signed_peer_admission_request,
    local_peer_public_identity,
)
from secrets_kit.backends.sqlite.transaction_engine import (
    REMOTE_TRANSACTION_POLICY,
    submit_transaction,
)
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.crypto.codecs import decode_b64url
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV
from secrets_kit.daemon.client import TCP_HOST, request_daemon
from secrets_kit.identifiers import deterministic_identifier
from secrets_kit.protocol.envelope import build_transaction_envelope, canonical_envelope_dict
from secrets_kit.protocol.envelope_signing import sign_envelope
from secrets_kit.protocol.payload_codec import (
    encrypted_envelope_payload_codec,
    plaintext_envelope_payload_codec,
)


@dataclass(frozen=True)
class LocalPeerNode:
    name: str
    home: Path
    operator_store: Path
    sqlite_path: Path
    identity_key_path: Path
    runtime_dir: Path
    port: int
    env: dict[str, str]


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((TCP_HOST, 0))
        return int(sock.getsockname()[1])


def pythonpath_env() -> str:
    repo_src = str(Path(__file__).resolve().parents[1] / "src")
    existing = os.environ.get("PYTHONPATH")
    if existing:
        return os.pathsep.join([repo_src, existing])
    return repo_src


def make_node(*, root: Path, name: str, port: int | None = None) -> LocalPeerNode:
    node_root = root / name
    home = node_root / "home"
    sqlite_path = node_root / "seckit.sqlite"
    identity_key_path = node_root / "node-identity.key"
    runtime_dir = node_root / "runtime"
    assigned_port = port or free_tcp_port()
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "PYTHONPATH": pythonpath_env(),
            SQLITE_PATH_ENV: str(sqlite_path),
            SQLITE_NODE_IDENTITY_KEY_ENV: str(identity_key_path),
            "SECKIT_DAEMON_RUNTIME_DIR": str(runtime_dir),
            "SECKIT_DAEMON_TCP_PORT": str(assigned_port),
            "SECKIT_SQLITE_STORAGE_MODE": "plaintext",
        }
    )
    env.pop(SQLITE_STORAGE_KEY_ENV, None)
    return LocalPeerNode(
        name=name,
        home=home,
        operator_store=home / ".config" / "seckit",
        sqlite_path=sqlite_path,
        identity_key_path=identity_key_path,
        runtime_dir=runtime_dir,
        port=assigned_port,
        env=env,
    )


def provision_node(*, node: LocalPeerNode) -> None:
    old_env = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(node.env)
        args = argparse.Namespace(
            yes=True,
            home=str(node.home),
            init_target=None,
            backend="sqlite",
            unsafe_plaintext_storage=True,
        )
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            if cmd_init_operator(args=args) != 0:
                raise AssertionError(f"failed to provision {node.name}: {debug_summary(node=node)}")
    finally:
        os.environ.clear()
        os.environ.update(old_env)


@contextmanager
def node_environment(*, node: LocalPeerNode) -> Iterator[None]:
    old_env = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(node.env)
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def public_identity(*, node: LocalPeerNode) -> PeerPublicIdentity:
    with node_environment(node=node):
        return local_peer_public_identity()


def peer_request_transaction(*, source: LocalPeerNode) -> Transaction:
    with node_environment(node=source):
        return create_signed_peer_admission_request()


def peer_acceptance_response_transactions(
    *, source: LocalPeerNode
) -> tuple[Transaction, Transaction]:
    with node_environment(node=source):
        request = create_signed_peer_admission_request()
        request_id = str(request.payload["request_id"])
        accept = create_signed_peer_admission_decision(
            proof_type=PEER_ADMISSION_ACCEPT,
            node_id=str(request.payload["node_id"]),
            request_id=request_id,
        )
        return request, accept


def inject_transaction(*, node: LocalPeerNode, transaction: Transaction) -> None:
    with node_environment(node=node):
        conn = open_sqlite_backend()
        try:
            with sqlite_transaction(conn=conn):
                submit_transaction(
                    conn=conn,
                    transaction=transaction,
                    policy=REMOTE_TRANSACTION_POLICY,
                )
        finally:
            conn.close()


def transaction_envelope(
    *,
    transaction: Transaction,
    destination_node_id: str | None = None,
    signer_node: LocalPeerNode | None = None,
    recipient_node: LocalPeerNode | None = None,
) -> dict[str, object]:
    destination = destination_node_id or deterministic_identifier(
        identifier_type="node",
        namespace="local_peer_lab.destination",
        name=transaction.transaction_id,
    )
    # Plaintext is explicit only for artifact-inspection fixtures, never live traffic.
    codec = plaintext_envelope_payload_codec()
    if recipient_node is not None:
        recipient = public_identity(node=recipient_node)
        destination = recipient.node_id
        codec = encrypted_envelope_payload_codec(recipient_node_id=destination, recipient_public_key=decode_b64url(recipient.encryption_public_key))
    envelope = build_transaction_envelope(
        payload_codec=codec,
        transaction=transaction,
        destination_node_id=destination,
    )
    if signer_node is not None:
        with node_environment(node=signer_node):
            conn = open_sqlite_backend()
            try:
                identity = load_sqlite_node_identity_material(conn=conn)
            finally:
                conn.close()
        envelope = sign_envelope(
            envelope=envelope,
            signer_node_id=identity.node_id,
            signing_private_key=identity.signing.private_key,
            signing_public_key=identity.signing.public_key,
        )
    return canonical_envelope_dict(envelope=envelope)


def start_daemon(*, node: LocalPeerNode) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        [sys.executable, "-m", "secrets_kit.daemon.server"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=node.env,
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with node_environment(node=node):
                response = request_daemon(command="ping", timeout=0.2)
            if response.get("status") == "ok" and response.get("response") == "pong":
                return proc
        except OSError:
            pass
        if proc.poll() is not None:
            raise AssertionError(
                f"daemon exited for {node.name}: {proc.returncode}; {debug_summary(node=node)}"
            ) from None
        time.sleep(0.05)
    raise AssertionError(f"daemon did not start for {node.name}: {debug_summary(node=node)}")


def stop_daemon(*, proc: subprocess.Popen[bytes], node: LocalPeerNode) -> None:
    try:
        with node_environment(node=node):
            request_daemon(command="shutdown")
    except Exception:
        pass
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)


def run_cli(*, node: LocalPeerNode, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "secrets_kit.cli", *args],
        check=False,
        env=node.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_cli_json(*, node: LocalPeerNode, args: list[str]) -> object:
    result = run_cli(node=node, args=args)
    if result.returncode != 0:
        raise AssertionError(f"CLI failed for {node.name}: {result.stderr}")
    return json.loads(result.stdout)


def peer_state(*, node: LocalPeerNode, peer_node_id: str) -> str:
    with node_environment(node=node):
        conn = open_sqlite_backend()
        try:
            row = conn.execute(
                "SELECT state FROM nodes WHERE node_id = ?",
                (peer_node_id,),
            ).fetchone()
            if row is None:
                return ""
            return str(row["state"] or "")
        finally:
            conn.close()


def transaction_count(*, node: LocalPeerNode) -> int:
    with node_environment(node=node):
        conn = open_sqlite_backend()
        try:
            return int(conn.execute("SELECT count(*) FROM transactions").fetchone()[0])
        finally:
            conn.close()


def debug_summary(*, node: LocalPeerNode) -> str:
    return (
        f"name={node.name} home={node.home} sqlite={node.sqlite_path} "
        f"identity={node.identity_key_path} runtime={node.runtime_dir} port={node.port}"
    )
