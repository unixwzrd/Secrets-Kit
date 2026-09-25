"""
secrets_kit.backends.sqlite.local_hierarchy

Canonical local SQLite hierarchy identifiers and generated display metadata.
"""

from __future__ import annotations

from secrets_kit.identifiers import deterministic_identifier, validate_identifier

LOCAL_ORGANIZATION_ID = deterministic_identifier(
    identifier_type="organization",
    namespace="sqlite.bootstrap",
    name="local-standalone",
)
LOCAL_CLIENT_ID = deterministic_identifier(
    identifier_type="client",
    namespace="sqlite.bootstrap",
    name="local-standalone-client",
)
LOCAL_FALLBACK_NODE_ID = deterministic_identifier(
    identifier_type="node",
    namespace="sqlite.bootstrap",
    name="local-standalone-cli",
)


def local_peer_group_id_for_node(*, node_id: str) -> str:
    """
    Return the canonical local peer-group id for a local node identity.

    The node id is the stable protocol identity for the node. The peer-group id
    is derived only to make local provisioning deterministic and distinct per
    initialized node; display names never determine identity.
    """
    validate_identifier(value=node_id, expected_type="node", field="node_id")
    return deterministic_identifier(
        identifier_type="peer_group",
        namespace="sqlite.local_peer_group",
        name=node_id,
    )


def local_peer_group_display_name(*, peer_group_id: str) -> str:
    """
    Return a generated human-facing peer-group display name.

    The value is convenience metadata only. It is not globally unique and must
    not be used for routing, authorization, admission, replay, or billing.
    """
    validate_identifier(value=peer_group_id, expected_type="peer_group", field="peer_group_id")
    return f"peergroup-{peer_group_id.removeprefix('pg:')[:8]}"


__all__ = [
    "LOCAL_CLIENT_ID",
    "LOCAL_FALLBACK_NODE_ID",
    "LOCAL_ORGANIZATION_ID",
    "local_peer_group_display_name",
    "local_peer_group_id_for_node",
]
