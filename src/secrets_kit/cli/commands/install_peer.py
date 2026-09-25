"""secrets_kit.cli.commands.install_peer

Interactive SSH peer bootstrap after a remote install. Existing signed peer
admission commands own identity validation and authorization; this module
only transports their public proofs through the operator's SSH connection.
Private keys and datastore secrets never cross SSH.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

from secrets_kit.crypto.codecs import decode_b64url


def _peer_command(
    *, host: str | None, parts: list[str], payload: dict[str, Any] | None = None
) -> dict[str, Any] | list[dict[str, Any]]:
    """Run one bounded peer CLI operation and parse JSON output when present."""
    if host is None:
        launcher = Path.home() / ".local/bin/seckit"
        executable = str(launcher) if launcher.is_file() else shutil.which("seckit")
        if not executable:
            raise ValueError("local Secrets Kit command is unavailable")
        argv = [executable, "peer", *parts]
    else:
        remote = '"$HOME/.local/bin/seckit" peer ' + " ".join(shlex.quote(part) for part in parts)
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, remote]
    completed = subprocess.run(
        argv,
        input=json.dumps(payload) if payload is not None else None,
        text=True,
        capture_output=True,
        check=False,
        timeout=90,
    )
    if completed.returncode:
        side = host or "this machine"
        raise ValueError(f"peer setup failed on {side}: {completed.stderr.strip()[:400]}")
    if "--json" not in parts:
        return {}
    value = json.loads(completed.stdout)
    if not isinstance(value, dict) and not (
        parts[0] == "list" and isinstance(value, list) and all(isinstance(row, dict) for row in value)
    ):
        raise ValueError("peer setup returned invalid JSON")
    return value


def _existing_admission(*, host: str | None, node_id: str) -> dict[str, Any] | None:
    """Read admission without changing it; missing is distinct from failed lookup."""
    rows = _peer_command(host=host, parts=["list", "--backend", "sqlite", "--json"])
    if not isinstance(rows, list):
        raise ValueError("peer list returned an invalid JSON array")
    return next((row for row in rows if row.get("node_id") == node_id), None)


def _identity_summary(value: dict[str, Any]) -> tuple[str, str, str]:
    """Return node ID, signing fingerprint, and encryption fingerprint."""
    node_id = value.get("node_id")
    signing = value.get("signing_public_key")
    encryption = value.get("encryption_public_key")
    if not all(isinstance(part, str) and part for part in (node_id, signing, encryption)):
        raise ValueError("peer identity is missing public-key fields")
    return (
        node_id,
        hashlib.sha256(decode_b64url(signing)).hexdigest(),
        hashlib.sha256(decode_b64url(encryption)).hexdigest(),
    )


def _confirm_scope(*, host: str, local: tuple[str, str, str], remote: tuple[str, str, str]) -> tuple[str, str]:
    print(f"Local node:  {local[0]}  signing fingerprint: {local[1]}")
    print(f"Remote node: {remote[0]}  signing fingerprint: {remote[1]}")
    print(f"Remote encryption fingerprint: {remote[2]}")
    print(f"SSH destination: {host}")
    service = input("Service to share: ").strip()
    account = input("Account to share: ").strip()
    if not service or not account:
        raise ValueError("service and account are required for peer authorization")
    answer = input(
        f"Authorize these two nodes for {service}/{account} over this SSH connection? [y/N] "
    ).strip().lower()
    if answer not in {"y", "yes"}:
        raise ValueError("peer authorization declined; no admission requests were created")
    return service, account


def pair_installed_peer(*, host: str) -> None:
    """Exchange existing signed proofs over SSH and verify mutual scoped admission.

    Installation has already completed. A failure after requests are created
    may leave pending or one-sided admission; the operator must inspect both
    peers before retrying.
    """
    local_identity = _peer_command(host=None, parts=["export-identity", "--backend", "sqlite", "--json"])
    remote_identity = _peer_command(host=host, parts=["export-identity", "--backend", "sqlite", "--json"])
    local_summary = _identity_summary(local_identity)
    remote_summary = _identity_summary(remote_identity)
    if local_summary[0] == remote_summary[0]:
        raise ValueError("local and remote nodes have the same identity")
    local_existing = _existing_admission(host=None, node_id=remote_summary[0])
    remote_existing = _existing_admission(host=host, node_id=local_summary[0])
    if local_existing is not None or remote_existing is not None:
        if local_existing is None or remote_existing is None:
            raise ValueError("one-sided peer admission; preserve both stores and report this state")
        expected = set(local_existing.get("service_group_ids", []))
        if not expected or expected != set(remote_existing.get("service_group_ids", [])):
            raise ValueError("existing peer scopes differ; preserve both stores and report this state")
        for row, summary in ((local_existing, remote_summary), (remote_existing, local_summary)):
            if row.get("state") != "active" or not row.get("synchronization_eligible"):
                raise ValueError("existing peer admission is not active; no re-pair attempted")
            if row.get("signing_fingerprint") != summary[1] or row.get("encryption_fingerprint") != summary[2]:
                raise ValueError("existing peer identity differs from SSH endpoint; no re-pair attempted")
        print("Existing mutual peer authorization preserved; no re-pair attempted.")
        return
    service, account = _confirm_scope(host=host, local=local_summary, remote=remote_summary)

    request_args = ["request", "--backend", "sqlite", "--json"]
    local_request = _peer_command(host=None, parts=request_args)
    remote_request = _peer_command(host=host, parts=request_args)
    if _identity_summary(local_request) != local_summary or _identity_summary(remote_request) != remote_summary:
        raise ValueError("a node identity changed during SSH peer setup; no peer was authorized")

    _peer_command(host=None, parts=["import-request", "--backend", "sqlite"], payload=remote_request)
    _peer_command(host=host, parts=["import-request", "--backend", "sqlite"], payload=local_request)
    accept_args = ["--backend", "sqlite", "--service", service, "--account", account, "--json"]
    local_acceptance = _peer_command(host=None, parts=["accept", remote_summary[0], *accept_args])
    remote_acceptance = _peer_command(host=host, parts=["accept", local_summary[0], *accept_args])
    _peer_command(host=None, parts=["import-acceptance", "--backend", "sqlite"], payload=remote_acceptance)
    _peer_command(host=host, parts=["import-acceptance", "--backend", "sqlite"], payload=local_acceptance)

    expected = set(local_acceptance.get("service_group_ids", []))
    if not expected or expected != set(remote_acceptance.get("service_group_ids", [])):
        raise ValueError("peer authorization scopes differ; inspect both nodes")
    for side, node_id in ((None, remote_summary[0]), (host, local_summary[0])):
        row = _peer_command(host=side, parts=["show", "--backend", "sqlite", "--json", node_id])
        if row.get("state") != "active" or not row.get("synchronization_eligible"):
            raise ValueError("peer authorization did not become active on both nodes")
        if set(row.get("service_group_ids", [])) != expected:
            raise ValueError("peer authorization scope mismatch")
    print(f"Peer admission complete for {service}/{account} on both nodes.")


def _status_command(*, host: str | None) -> dict[str, Any]:
    """Read one bounded daemon snapshot without modifying peer or route state."""
    if host is None:
        launcher = Path.home() / ".local/bin/seckit"
        executable = str(launcher) if launcher.is_file() else shutil.which("seckit")
        if not executable:
            raise ValueError("local Secrets Kit command is unavailable")
        argv = [executable, "status", "--json"]
    else:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
                '"$HOME/.local/bin/seckit" status --json']
    completed = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=30)
    if completed.returncode:
        raise ValueError(f"daemon status failed on {host or 'this machine'}: {completed.stderr.strip()[:400]}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("daemon status returned an invalid JSON object")
    return value


def _wait_route_command(*, host: str | None, peer_id: str) -> None:
    """Wait for the daemon's authenticated route event, never poll status."""
    if host is None:
        launcher = Path.home() / ".local/bin/seckit"
        executable = str(launcher) if launcher.is_file() else shutil.which("seckit")
        if not executable:
            raise ValueError("local Secrets Kit command is unavailable")
        argv = [executable, "internal", "wait-route", peer_id]
    else:
        argv = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
            f'"$HOME/.local/bin/seckit" internal wait-route {shlex.quote(peer_id)}',
        ]
    completed = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=45)
    if completed.returncode:
        raise ValueError(
            f"authorized route not connected on {host or 'this machine'}; no repair attempted"
        )


def verify_authorized_route(*, host: str) -> None:
    """Fail closed unless each live daemon reports the authenticated peer route."""
    local = _peer_command(host=None, parts=["export-identity", "--backend", "sqlite", "--json"])
    remote = _peer_command(host=host, parts=["export-identity", "--backend", "sqlite", "--json"])
    if not isinstance(local, dict) or not isinstance(remote, dict):
        raise ValueError("peer identity response was invalid")
    local_id = _identity_summary(local)[0]
    remote_id = _identity_summary(remote)[0]
    for side, other_id in ((None, remote_id), (host, local_id)):
        _wait_route_command(host=side, peer_id=other_id)
        status = _status_command(host=side)
        daemon = status.get("daemon")
        routing = status.get("routing")
        routes = routing.get("routes") if isinstance(routing, dict) else None
        if not isinstance(daemon, dict) or daemon.get("running") is not True or not isinstance(routes, list):
            raise ValueError(f"daemon or route status unavailable on {side or 'this machine'}")
        if not any(
            isinstance(route, dict) and route.get("peer_id") == other_id
            and route.get("connected") is True and route.get("reachable") is True
            for route in routes
        ):
            raise ValueError(f"authorized route not connected on {side or 'this machine'}; no repair attempted")
    print("Authorized routes are connected on both nodes.")
