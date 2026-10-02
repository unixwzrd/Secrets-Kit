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
import sys
from pathlib import Path
from typing import Any

from secrets_kit.crypto.codecs import decode_b64url
from secrets_kit.crypto.models import key_id_for_public_key
from secrets_kit.protocol.rss_admin import admin_action
from secrets_kit.protocol.rss_auth import (
    RSSAuthenticationError,
    load_rss_relay_credentials_from_environment,
)


def _local_seckit_command(*, shared_launcher: Path | None) -> str:
    """Use the invoked client for local peer work, even beside an older per-user install."""
    if shared_launcher is not None:
        return str(shared_launcher)
    invoked = Path(sys.argv[0])
    if invoked.name == "seckit":
        if invoked.is_file():
            return str(invoked)
        resolved = shutil.which("seckit")
        if resolved:
            return resolved
    launcher = Path.home() / ".local/bin/seckit"
    executable = str(launcher) if launcher.is_file() else shutil.which("seckit")
    if not executable:
        raise ValueError("local Secrets Kit command is unavailable")
    return executable


def _peer_command(
    *, host: str | None, parts: list[str], payload: dict[str, Any] | None = None,
    shared_launcher: Path | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """Run one bounded peer CLI operation and parse JSON output when present."""
    if host is None:
        argv = [_local_seckit_command(shared_launcher=shared_launcher), "peer", *parts]
    else:
        remote_launcher = shlex.quote(str(shared_launcher)) if shared_launcher else '"$HOME/.local/bin/seckit"'
        remote = remote_launcher + " peer " + " ".join(shlex.quote(part) for part in parts)
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


def _call_peer(
    *, host: str | None, parts: list[str], payload: dict[str, Any] | None = None,
    shared_launcher: Path | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """Keep the per-user command unchanged unless a shared launcher was verified."""
    if shared_launcher is None:
        return _peer_command(host=host, parts=parts, payload=payload)
    return _peer_command(host=host, parts=parts, payload=payload, shared_launcher=shared_launcher)


def _existing_admission(*, host: str | None, node_id: str, shared_launcher: Path | None = None) -> dict[str, Any] | None:
    """Read admission without changing it; missing is distinct from failed lookup."""
    rows = _call_peer(host=host, parts=["list", "--backend", "sqlite", "--json"], shared_launcher=shared_launcher)
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


def _confirm_scope(
    *, host: str, local: tuple[str, str, str], remote: tuple[str, str, str],
    local_identity: dict[str, Any], remote_identity: dict[str, Any],
) -> tuple[str, str]:
    """Display the same public-key fingerprints as ``seckit info`` before consent."""
    local_signing = key_id_for_public_key(
        algorithm="ed25519", public_key=decode_b64url(local_identity["signing_public_key"]),
    )
    remote_signing = key_id_for_public_key(
        algorithm="ed25519", public_key=decode_b64url(remote_identity["signing_public_key"]),
    )
    remote_encryption = key_id_for_public_key(
        algorithm="x25519", public_key=decode_b64url(remote_identity["encryption_public_key"]),
    )
    print(f"Local node:  {local[0]}  signing fingerprint: {local_signing}")
    print(f"Remote node: {remote[0]}  signing fingerprint: {remote_signing}")
    print(f"Remote encryption fingerprint: {remote_encryption}")
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


def pair_installed_peer(*, host: str, shared_launcher: Path | None = None) -> None:
    """Exchange existing signed proofs over SSH and verify mutual scoped admission.

    Installation has already completed. A failure after requests are created
    may leave pending or one-sided admission; the operator must inspect both
    peers before retrying.
    """
    local_identity = _call_peer(host=None, parts=["export-identity", "--backend", "sqlite", "--json"], shared_launcher=shared_launcher)
    remote_identity = _call_peer(host=host, parts=["export-identity", "--backend", "sqlite", "--json"], shared_launcher=shared_launcher)
    local_summary = _identity_summary(local_identity)
    remote_summary = _identity_summary(remote_identity)
    if local_summary[0] == remote_summary[0]:
        raise ValueError("local and remote nodes have the same identity")
    local_existing = _existing_admission(host=None, node_id=remote_summary[0], shared_launcher=shared_launcher)
    remote_existing = _existing_admission(host=host, node_id=local_summary[0], shared_launcher=shared_launcher)
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
    service, account = _confirm_scope(
        host=host, local=local_summary, remote=remote_summary,
        local_identity=local_identity, remote_identity=remote_identity,
    )

    request_args = ["request", "--backend", "sqlite", "--json"]
    local_request = _call_peer(host=None, parts=request_args, shared_launcher=shared_launcher)
    remote_request = _call_peer(host=host, parts=request_args, shared_launcher=shared_launcher)
    if _identity_summary(local_request) != local_summary or _identity_summary(remote_request) != remote_summary:
        raise ValueError("a node identity changed during SSH peer setup; no peer was authorized")

    _call_peer(host=None, parts=["import-request", "--backend", "sqlite"], payload=remote_request, shared_launcher=shared_launcher)
    _call_peer(host=host, parts=["import-request", "--backend", "sqlite"], payload=local_request, shared_launcher=shared_launcher)
    accept_args = ["--backend", "sqlite", "--service", service, "--account", account, "--json"]
    local_acceptance = _call_peer(host=None, parts=["accept", remote_summary[0], *accept_args], shared_launcher=shared_launcher)
    remote_acceptance = _call_peer(host=host, parts=["accept", local_summary[0], *accept_args], shared_launcher=shared_launcher)
    _call_peer(host=None, parts=["import-acceptance", "--backend", "sqlite"], payload=remote_acceptance, shared_launcher=shared_launcher)
    _call_peer(host=host, parts=["import-acceptance", "--backend", "sqlite"], payload=local_acceptance, shared_launcher=shared_launcher)

    expected = set(local_acceptance.get("service_group_ids", []))
    if not expected or expected != set(remote_acceptance.get("service_group_ids", [])):
        raise ValueError("peer authorization scopes differ; inspect both nodes")
    for side, node_id in ((None, remote_summary[0]), (host, local_summary[0])):
        row = _call_peer(host=side, parts=["show", "--backend", "sqlite", "--json", node_id], shared_launcher=shared_launcher)
        if row.get("state") != "active" or not row.get("synchronization_eligible"):
            raise ValueError("peer authorization did not become active on both nodes")
        if set(row.get("service_group_ids", [])) != expected:
            raise ValueError("peer authorization scope mismatch")
    print(f"Peer admission complete for {service}/{account} on both nodes.")


def _status_command(*, host: str | None, shared_launcher: Path | None = None) -> dict[str, Any]:
    """Read one bounded daemon snapshot without modifying peer or route state."""
    if host is None:
        argv = [_local_seckit_command(shared_launcher=shared_launcher), "status", "--json"]
    else:
        remote_launcher = shlex.quote(str(shared_launcher)) if shared_launcher else '"$HOME/.local/bin/seckit"'
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
                f"{remote_launcher} status --json"]
    completed = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=30)
    if completed.returncode:
        raise ValueError(f"daemon status failed on {host or 'this machine'}: {completed.stderr.strip()[:400]}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("daemon status returned an invalid JSON object")
    return value


def enroll_installed_rss_peer(*, host: str, shared_launcher: Path | None = None) -> None:
    """Give one new SSH-installed peer its own RSS key and one-use enrollment token.

    Existing remote RSS identity is preserved. The token travels only through
    the authenticated SSH stdin channel, never a command argument or log.
    """
    local = load_rss_relay_credentials_from_environment()
    if local is None:
        return
    if local.enrollment_token is not None:
        raise ValueError("enroll this RSS device before adding another")
    launcher = shlex.quote(str(shared_launcher)) if shared_launcher else '"$HOME/.local/bin/seckit"'
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
        f"{launcher} rss local-status",
    ]
    observed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    if observed.returncode:
        raise ValueError("remote RSS status is unavailable; no token issued")
    try:
        state = json.loads(observed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("remote RSS status is invalid; no token issued") from exc
    if not isinstance(state, dict) or type(state.get("configured")) is not bool:
        raise ValueError("remote RSS status is invalid; no token issued")
    if state["configured"]:
        if state.get("entitlement_id") != local.entitlement_id:
            raise ValueError("remote RSS identity belongs to another entitlement; preserved")
        if state.get("enrolled") is not True:
            if state.get("enrollment_token_expired") is not True:
                resumed = subprocess.run(
                    command[:-1] + [f"{launcher} rss enroll"],
                    capture_output=True, text=True, check=False, timeout=90,
                )
                if resumed.returncode:
                    raise ValueError("remote RSS enrollment remains pending; rerun after checking payment and connectivity")
                print("Pending remote RSS enrollment resumed without replacing its identity.")
                return
        if state.get("enrolled") is True:
            print("Existing remote RSS device preserved; no new enrollment token issued.")
            return
    try:
        status, bundle = admin_action(action="device.ret", parameters={})
        if status == 409 and bundle.get("reason") == "device_capacity_exhausted":
            portal_status, portal = admin_action(action="billing.portal", parameters={})
            link = portal.get("portal_url") if portal_status == 200 else None
            capacity = bundle.get("capacity")
            raise ValueError(
                f"RSS device capacity is full ({capacity}); increase paid units at {link or 'the billing portal'} "
                "and rerun the same seckit install command"
            )
        if status != 200 or bundle.get("protocol") != "rss_provisioning_bundle/v1":
            raise ValueError("RSS device enrollment authorization was not confirmed")
    except RSSAuthenticationError as exc:
        raise ValueError(f"RSS billing-owner authorization failed: {exc}") from exc
    enrolled = subprocess.run(
        command[:-1] + [f"{launcher} rss enroll --bundle-stdin"],
        input=json.dumps(bundle, sort_keys=True), text=True,
        capture_output=True, check=False, timeout=90,
    )
    if enrolled.returncode:
        raise ValueError("remote RSS enrollment did not complete; inspect the remote user's state")
    print("Remote RSS device enrolled with a distinct key and connection ID.")


def _wait_route_command(*, host: str | None, peer_id: str, shared_launcher: Path | None = None) -> None:
    """Wait for the daemon's authenticated route event, never poll status."""
    if host is None:
        argv = [_local_seckit_command(shared_launcher=shared_launcher), "internal", "wait-route", peer_id]
    else:
        remote_launcher = shlex.quote(str(shared_launcher)) if shared_launcher else '"$HOME/.local/bin/seckit"'
        argv = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
            f"{remote_launcher} internal wait-route {shlex.quote(peer_id)}",
        ]
    completed = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=45)
    if completed.returncode:
        raise ValueError(
            f"authorized route not connected on {host or 'this machine'}; no repair attempted"
        )


def verify_authorized_route(*, host: str, shared_launcher: Path | None = None) -> None:
    """Fail closed unless each live daemon reports the authenticated peer route."""
    local = _call_peer(host=None, parts=["export-identity", "--backend", "sqlite", "--json"], shared_launcher=shared_launcher)
    remote = _call_peer(host=host, parts=["export-identity", "--backend", "sqlite", "--json"], shared_launcher=shared_launcher)
    if not isinstance(local, dict) or not isinstance(remote, dict):
        raise ValueError("peer identity response was invalid")
    local_id = _identity_summary(local)[0]
    remote_id = _identity_summary(remote)[0]
    for side, other_id in ((None, remote_id), (host, local_id)):
        _wait_route_command(host=side, peer_id=other_id, shared_launcher=shared_launcher)
        status = _status_command(host=side, shared_launcher=shared_launcher)
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
