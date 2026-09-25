"""The public operational status command."""

from __future__ import annotations

import argparse
import json
from typing import Any

from secrets_kit.cli.io import _fatal
from secrets_kit.cli.update_check import cached_update_available
from secrets_kit.daemon.client import DaemonError, request_daemon_status
from secrets_kit.locale import msg


def cmd_status(*, args: argparse.Namespace) -> int:
    """Ask the local daemon for status and format its response."""
    data = build_status_dict(args=args)
    if getattr(args, "status_json", False):
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        _print_status_text(data=data)
        latest = cached_update_available()
        if latest:
            print(msg("cli.upgrade.status_notice", latest=latest))
    if data.get("error"):
        return _fatal(message=str(data["error"]), code=1)
    return 0 if isinstance(data.get("daemon"), dict) and data["daemon"].get("running") else 1


def build_status_dict(*, args: argparse.Namespace | None = None) -> dict[str, Any]:
    """Return authoritative status, or unknown liveness when IPC fails."""
    _ = args
    try:
        # Use the same bounded status wait as the read-only MCP interface.
        return request_daemon_status(timeout=5.0)
    except (DaemonError, OSError) as exc:
        return {
            "version": 1,
            "overall": "UNKNOWN",
            "ok": False,
            "error": f"daemon status unavailable: {exc}",
            "daemon": {"running": None},
            "identity": None,
            "peers": [],
            "routing": {"count": 0, "routes": [], "missing": []},
            "synchronization": {},
        }


def _print_status_text(*, data: dict[str, Any]) -> None:
    print(str(data.get("overall", "UNKNOWN")))
    identity = data.get("identity")
    if isinstance(identity, dict):
        print("identity:")
        for key in ("peer_name", "peer_id", "version", "runtime_mode", "uptime_seconds"):
            if key in identity:
                print(f"  {key}: {identity[key]}")
    daemon = data.get("daemon")
    if isinstance(daemon, dict):
        print("daemon:")
        for key in (
            "running",
            "pid",
            "startup_time",
            "uptime_seconds",
            "transport",
            "capabilities",
        ):
            if key in daemon:
                print(f"  {key}: {daemon[key]}")
    endpoint = data.get("local_endpoint")
    if isinstance(endpoint, dict):
        print("local endpoint:")
        for key in (
            "host",
            "port",
            "transport",
            "multiaddr",
            "transport_peer_id",
            "bound_addresses",
            "advertised_addresses",
        ):
            if key in endpoint:
                print(f"  {key}: {endpoint[key]}")
    routing = data.get("routing")
    if isinstance(routing, dict):
        print("routing:")
        print(f"  routes: {routing.get('count', 0)}")
        missing = routing.get("missing", [])
        print(f"  missing: {', '.join(str(item) for item in missing) if missing else 'none'}")
        discovery = routing.get("discovery")
        if isinstance(discovery, dict):
            print(
                "  discovery: enabled={enabled} state={state} candidates={candidates} "
                "validated={validated} rejected={rejected}".format(
                    enabled=str(bool(discovery.get("enabled"))).lower(),
                    state=discovery.get("state", "unknown"),
                    candidates=discovery.get("candidate_count", 0),
                    validated=discovery.get("validated_route_count", 0),
                    rejected=discovery.get("rejected_binding_count", 0),
                )
            )
        for route in routing.get("routes", []):
            if not isinstance(route, dict):
                continue
            print(
                "  {peer_id}: source={source} endpoint={endpoint} connected={connected} "
                "reachable={reachable} last_contact={last_contact}".format(
                    peer_id=route.get("peer_id", "unknown"),
                    source=route.get("source", "unknown"),
                    endpoint=route.get("endpoint", "unavailable"),
                    connected=route.get("connected", False),
                    reachable=route.get("reachable", False),
                    last_contact=route.get("last_contact") or "unavailable",
                )
            )
    peers = data.get("peers")
    if isinstance(peers, list):
        print("peers:")
        if not peers:
            print("  none")
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            print(
                "  {name} ({peer_id}) authorized={authorized} connected={connected} "
                "reachable={reachable} endpoint={endpoint} ip={ip} port={port}".format(
                    name=peer.get("name", "unknown"),
                    peer_id=peer.get("peer_id", "unknown"),
                    authorized=str(bool(peer.get("authorized"))).lower(),
                    connected=peer.get("connected", "unknown"),
                    reachable=peer.get("reachable", "unknown"),
                    endpoint=peer.get("known_endpoint") or "unavailable",
                    ip=peer.get("ip") or "unavailable",
                    port=peer.get("port") or "unavailable",
                )
            )
    synchronization = data.get("synchronization")
    if isinstance(synchronization, dict):
        print("synchronization:")
        for key in (
            "applied_transactions",
            "pending_envelopes",
            "retry_queue",
            "currently_sending",
            "last_successful_outbound",
            "last_received_transaction",
        ):
            if key in synchronization:
                print(f"  {key}: {synchronization[key]}")


__all__ = ["build_status_dict", "cmd_status"]
