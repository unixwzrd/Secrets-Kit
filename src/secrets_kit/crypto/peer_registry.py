"""
secrets_kit.crypto.peer_registry

In-memory registry boundary for crypto-layer peer identities.

This module stores existing ``PeerIdentity`` models only. It does not perform
networking, discovery, trust decisions, persistence, daemon integration, or
runtime coordination.
"""

from __future__ import annotations

from secrets_kit.crypto.peer_models import PeerIdentity
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier


class PeerRegistry:
    """
    Store remote peer identities in memory by authoritative ``node_id``.

    Callers pass ``PeerIdentity`` instances from ``crypto.peer_models``. The
    registry returns stored identities directly and preserves insertion order
    through Python's ordered dictionary behavior.
    """

    def __init__(self) -> None:
        """Create an empty in-memory peer registry."""
        self._peers: dict[str, PeerIdentity] = {}

    def add_peer(self, *, peer: PeerIdentity) -> None:
        """
        Add a peer identity by authoritative ``node_id``.

        Raises ``ValueError`` if a peer with the same ``node_id`` already
        exists. This method has no side effects beyond in-memory state.
        """
        _validate_peer(peer=peer)
        if peer.node_id in self._peers:
            raise ValueError(f"peer already exists: {peer.node_id}")
        self._peers[peer.node_id] = peer

    def update_peer(self, *, peer: PeerIdentity) -> None:
        """
        Replace an existing peer identity with the same authoritative ``node_id``.

        Raises ``KeyError`` if the peer is not already present. The ``node_id``
        on the supplied model is the only registry key.
        """
        _validate_peer(peer=peer)
        if peer.node_id not in self._peers:
            raise KeyError(peer.node_id)
        self._peers[peer.node_id] = peer

    def remove_peer(self, *, node_id: str) -> None:
        """
        Remove an existing peer by ``node_id``.

        Raises ``KeyError`` when the ``node_id`` is not present. This is an
        in-memory registry mutation only.
        """
        _validate_node_id(node_id=node_id)
        if node_id not in self._peers:
            raise KeyError(node_id)
        del self._peers[node_id]

    def get_peer(self, *, node_id: str) -> PeerIdentity | None:
        """
        Return a peer identity by ``node_id`` or ``None`` when absent.

        The lookup is local in-memory state only and does not discover or load
        peers from any external system.
        """
        _validate_node_id(node_id=node_id)
        return self._peers.get(node_id)

    def list_peers(self) -> tuple[PeerIdentity, ...]:
        """
        Return all peer identities in insertion order.

        The return value is an immutable tuple snapshot of the current registry.
        """
        return tuple(self._peers.values())

    def list_peers_by_group(self, *, group_name: str) -> tuple[PeerIdentity, ...]:
        """
        Return peers with a matching peer group membership.

        ``group_name`` is matched against ``PeerGroupMembership.group_id`` on
        stored peer models. No trust or discovery semantics are implied.
        """
        _validate_group_name(group_name=group_name)
        return tuple(
            peer
            for peer in self._peers.values()
            if any(membership.group_id == group_name for membership in peer.group_memberships)
        )


def _validate_peer(*, peer: PeerIdentity) -> None:
    """Validate registry input is an existing peer model."""
    if not isinstance(peer, PeerIdentity):
        raise TypeError("peer must be a PeerIdentity")


def _validate_node_id(*, node_id: str) -> None:
    """Validate a canonical peer node identifier."""
    try:
        validate_identifier(value=node_id, expected_type="node", field="node_id")
    except IdentifierValidationError as exc:
        raise ValueError(str(exc)) from exc


def _validate_group_name(*, group_name: str) -> None:
    """Validate a canonical peer group identifier for registry filtering."""
    try:
        validate_identifier(value=group_name, expected_type="peer_group", field="group_name")
    except IdentifierValidationError as exc:
        raise ValueError(str(exc)) from exc


__all__ = ["PeerRegistry"]
