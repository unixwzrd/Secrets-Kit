"""Public enrollment payloads (dicts only — no private key material).

Canonical identity fields remain ``HostIdentity.export_public_payload``; this module
may add optional **public** enrollment metadata (e.g. where a peer can be reached—
hostnames/URLs only, non-secret).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from secrets_kit.identity.core import HostIdentity

ENROLLMENT_FORMAT = "seckit.enrollment_public"
ENROLLMENT_VERSION = 1


def build_public_enrollment_payload(
    identity: HostIdentity,
    *,
    peer_endpoints: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Return a public enrollment dict: identity export plus optional peer reach hints.

    ``peer_endpoints`` are **non-secret** labels (hostnames, URLs) for where this
    peer may be contacted; dumb forwarders may use them for delivery but must
    not treat them as authority.
    """
    out: Dict[str, Any] = {
        "format": ENROLLMENT_FORMAT,
        "enrollment_version": ENROLLMENT_VERSION,
        "identity": identity.export_public_payload(),
    }
    if peer_endpoints is not None:
        out["relay_endpoints"] = _normalize_peer_endpoints(peer_endpoints)
    return out


def _normalize_peer_endpoints(endpoints: Sequence[str]) -> List[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in endpoints:
        item = str(raw).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
