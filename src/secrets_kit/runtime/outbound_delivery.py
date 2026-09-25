"""
secrets_kit.runtime.outbound_delivery

Own durable outbound-envelope delivery state while delegating byte movement.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from secrets_kit.backends.sqlite.connection import transaction as sqlite_transaction
from secrets_kit.backends.sqlite.envelopes import persist_outbound_envelopes
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.peer_registry import is_peer_synchronization_eligible
from secrets_kit.backends.sqlite.transaction_scope import service_group_scope_id
from secrets_kit.backends.sqlite.transactions import get_transaction
from secrets_kit.daemon.client import request_opaque_route
from secrets_kit.models import now_utc_iso

LOGGER = logging.getLogger(__name__)

CLAIM_LEASE_SECONDS = 60
RETRY_BASE_SECONDS = 3
RETRY_MAX_SECONDS = 60
MAX_DELIVERY_ATTEMPTS = 4


@dataclass(frozen=True)
class DeliveryOutcome:
    """Result of one opaque transport-delivery attempt."""

    delivered: bool
    failure_reason: str = ""


def process_configured_pending_outbound_envelopes() -> int:
    """Open runtime state and submit due envelopes by peer identity."""
    conn = open_sqlite_backend()
    try:
        return process_pending_outbound_envelopes(conn=conn)
    finally:
        conn.close()


def process_pending_outbound_envelopes(
    *,
    conn: sqlite3.Connection,
    peer_ids: Iterable[str] | None = None,
    peers: Iterable[str] | None = None,
) -> int:
    """Authorize, submit, and record due durable envelope deliveries."""
    if peer_ids is not None and peers is not None:
        raise ValueError("peer_ids and peers are mutually exclusive")
    selected_peer_ids = None if peer_ids is None and peers is None else set(peer_ids or peers or ())
    _queue_endpoint_prerequisites(conn=conn, selected_peer_ids=selected_peer_ids)
    _recover_stale_inflight_envelopes(conn=conn)
    sent_count = 0
    failed_peers: set[str] = set()
    for pending_row in _deliverable_outbound_envelopes(conn=conn):
        pending_peer_id = str(pending_row["destination_node_id"])
        if pending_peer_id in failed_peers:
            continue
        row = _claim_outbound_envelope(conn=conn, envelope_id=pending_row["envelope_id"])
        if row is None:
            continue
        destination_node_id = row["destination_node_id"]
        if selected_peer_ids is not None and destination_node_id not in selected_peer_ids:
            _mark_envelope_retry_pending(
                conn=conn,
                row=row,
                failure_reason=f"peer delivery was not selected: peer_id={destination_node_id}",
            )
            continue
        if not is_peer_synchronization_eligible(conn=conn, node_id=destination_node_id):
            _mark_envelope_authorization_denied(
                conn=conn,
                row=row,
                failure_reason=f"peer is not synchronization eligible: peer_id={destination_node_id}",
            )
            continue
        try:
            service_group_id = service_group_scope_id(
                transaction=get_transaction(conn=conn, transaction_id=row["transaction_id"])
            )
        except Exception as exc:
            _mark_envelope_authorization_denied(
                conn=conn,
                row=row,
                failure_reason=f"transaction scope is invalid: {exc}",
            )
            continue
        if not is_peer_synchronization_eligible(
            conn=conn,
            node_id=destination_node_id,
            service_group_id=service_group_id,
        ):
            _mark_envelope_authorization_denied(
                conn=conn,
                row=row,
                failure_reason=(
                    "peer is not authorized for service group: "
                    f"peer_id={destination_node_id} service_group_id={service_group_id}"
                ),
            )
            continue
        _mark_envelope_sending(conn=conn, envelope_id=row["envelope_id"])
        outcome = deliver_outbound_envelope(row=row)
        if not outcome.delivered:
            failed_peers.add(destination_node_id)
            _mark_peer_retry_pending(
                conn=conn,
                row=row,
                failure_reason=outcome.failure_reason,
            )
            continue
        if _mark_envelope_sent_if_sending(conn=conn, envelope_id=row["envelope_id"]):
            sent_count += 1
    return sent_count


def _queue_endpoint_prerequisites(
    *, conn: sqlite3.Connection, selected_peer_ids: set[str] | None
) -> None:
    """Queue only retained prerequisites of an already authorized endpoint update.

    Walk the original local endpoint chain backwards, stopping at an envelope
    already accepted by this destination. Never manufacture a transaction or
    alter replay/projection state. Bound each pass and fail closed on missing
    history. Unrelated local-only history is not broadcast to new peers.
    """
    pending = conn.execute(
        """SELECT t.transaction_id, e.destination_node_id FROM envelopes e
           JOIN transactions t ON t.transaction_id = e.transaction_id
           JOIN node_private n ON n.node_id = t.origin_node_id
           WHERE e.state IN ('pending', 'retry_pending') AND t.state = 'applied'
             AND t.transaction_type IN ('peer.endpoint.update', 'peer.endpoint.replace')
           ORDER BY t.rowid LIMIT 64"""
    ).fetchall()
    for item in pending:
        peer = item["destination_node_id"]
        if selected_peer_ids is not None and peer not in selected_peer_ids:
            continue
        if not is_peer_synchronization_eligible(conn=conn, node_id=peer):
            continue
        current = get_transaction(conn=conn, transaction_id=item["transaction_id"])
        chain = []
        complete = False
        for _ in range(128):
            previous = current.payload.get("previous_endpoint")
            if current.transaction_type == "peer.endpoint.register":
                complete = True
                break
            if not isinstance(previous, str):
                break
            candidates = conn.execute(
                """SELECT transaction_id FROM transactions
                   WHERE origin_node_id = ? AND state = 'applied'
                     AND transaction_type IN ('peer.endpoint.register', 'peer.endpoint.update', 'peer.endpoint.replace')
                     AND rowid < (SELECT rowid FROM transactions WHERE transaction_id = ?)
                   ORDER BY rowid DESC LIMIT 128""",
                (current.origin_node_id, current.transaction_id),
            ).fetchall()
            predecessor = next((tx for row in candidates
                                if (tx := get_transaction(conn=conn, transaction_id=row["transaction_id"])).payload.get("endpoint") == previous), None)
            if predecessor is None:
                break
            existing = conn.execute(
                "SELECT state FROM envelopes WHERE transaction_id = ? AND destination_node_id = ?",
                (predecessor.transaction_id, peer),
            ).fetchone()
            if existing is not None and existing["state"] == "sent":
                complete = True
                break
            chain.append(predecessor)
            current = predecessor
        if not complete:
            LOGGER.warning("endpoint prerequisite history unavailable; delivery remains pending")
            continue
        with sqlite_transaction(conn=conn):
            for prerequisite in reversed(chain):
                exists = conn.execute(
                    "SELECT 1 FROM envelopes WHERE transaction_id = ? AND destination_node_id = ?",
                    (prerequisite.transaction_id, peer),
                ).fetchone()
                if exists is None:
                    # Local application timestamps/state do not describe a new
                    # recipient's lifecycle. Keep the retained transaction intact.
                    outbound = replace(
                        prerequisite, state="pending", received_at=None,
                        applied_at=None, acknowledged_at=None, cleared_at=None,
                    )
                    persist_outbound_envelopes(conn=conn, transaction=outbound, peers=[peer])


def deliver_outbound_envelope(
    *, row: Mapping[str, object]
) -> DeliveryOutcome:
    """Submit persisted canonical bytes to the local daemon transport adapter."""
    destination_node_id = str(row["destination_node_id"])
    try:
        response = request_opaque_route(
            peer_id=destination_node_id,
            payload=bytes(row["encrypted_payload"]),
        )
    except Exception as exc:
        reason = str(exc)
        LOGGER.warning(
            "transport delivery failed envelope_id=%s transaction_id=%s peer_id=%s state=sending retry_state=retry_pending failure_reason=%s",
            row["envelope_id"],
            row["transaction_id"],
            destination_node_id,
            reason,
        )
        return DeliveryOutcome(delivered=False, failure_reason=reason)
    if response.get("status") != "ok" or response.get("response") != "delivered":
        reason = f"transport did not deliver opaque payload: {response}"
        LOGGER.warning(
            "transport delivery receipt failed envelope_id=%s transaction_id=%s peer_id=%s state=sending retry_state=retry_pending failure_reason=%s",
            row["envelope_id"],
            row["transaction_id"],
            destination_node_id,
            reason,
        )
        return DeliveryOutcome(delivered=False, failure_reason=reason)
    return DeliveryOutcome(delivered=True)


def _deliverable_outbound_envelopes(*, conn: sqlite3.Connection) -> list[sqlite3.Row]:
    now = _timestamp()
    return conn.execute(
        """
        SELECT e.envelope_id, e.destination_node_id
        FROM envelopes e
        JOIN transactions t ON t.transaction_id = e.transaction_id
        WHERE e.state IN ('pending', 'retry_pending')
          AND (e.next_attempt_at IS NULL OR e.next_attempt_at <= ?)
          AND NOT EXISTS (
              SELECT 1
              FROM envelopes blocked
              WHERE blocked.destination_node_id = e.destination_node_id
                AND blocked.state = 'retry_pending'
                AND (
                    blocked.next_attempt_at IS NULL
                    OR blocked.next_attempt_at > ?
                )
          )
        ORDER BY CASE e.state WHEN 'retry_pending' THEN 0 ELSE 1 END,
                 e.attempt_count DESC,
                 e.next_attempt_at ASC,
                 t.rowid ASC,
                 e.envelope_id ASC
        """,
        (now, now),
    ).fetchall()


def _recover_stale_inflight_envelopes(*, conn: sqlite3.Connection) -> int:
    """Return abandoned claims to a finite retry queue or park exhausted work."""
    now = _timestamp()
    cutoff = (
        datetime.now(tz=timezone.utc) - timedelta(seconds=CLAIM_LEASE_SECONDS)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with sqlite_transaction(conn=conn):
        cursor = conn.execute(
            """
            UPDATE envelopes
            SET state = 'retry_pending', failed_at = ?,
                next_attempt_at = CASE
                    WHEN attempt_count >= ? THEN NULL
                    ELSE ?
                END,
                last_error = 'delivery worker claim expired before completion'
            WHERE state IN ('claimed', 'sending')
              AND claimed_at IS NOT NULL
              AND claimed_at <= ?
            """,
            (now, MAX_DELIVERY_ATTEMPTS, now, cutoff),
        )
    if cursor.rowcount:
        LOGGER.warning("recovered stale outbound delivery claims count=%s", cursor.rowcount)
    return cursor.rowcount


def _claim_outbound_envelope(
    *, conn: sqlite3.Connection, envelope_id: str
) -> sqlite3.Row | None:
    now = _timestamp()
    with sqlite_transaction(conn=conn):
        cursor = conn.execute(
            """
            UPDATE envelopes
            SET state = 'claimed', claimed_at = ?, attempt_count = attempt_count + 1
            WHERE envelope_id = ?
              AND state IN ('pending', 'retry_pending')
              AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
            """,
            (now, envelope_id, now),
        )
    if cursor.rowcount == 0:
        return None
    return conn.execute(
        """
        SELECT envelope_id, transaction_id, destination_node_id,
               encrypted_payload, state, attempt_count
        FROM envelopes
        WHERE envelope_id = ?
        """,
        (envelope_id,),
    ).fetchone()


def _mark_envelope_sending(*, conn: sqlite3.Connection, envelope_id: str) -> bool:
    with sqlite_transaction(conn=conn):
        cursor = conn.execute(
            "UPDATE envelopes SET state = 'sending' WHERE envelope_id = ? AND state = 'claimed'",
            (envelope_id,),
        )
    return cursor.rowcount > 0


def _mark_envelope_sent_if_sending(*, conn: sqlite3.Connection, envelope_id: str) -> bool:
    with sqlite_transaction(conn=conn):
        cursor = conn.execute(
            """
            UPDATE envelopes
            SET state = 'sent', sent_at = ?, next_attempt_at = NULL, last_error = NULL
            WHERE envelope_id = ? AND state = 'sending'
            """,
            (_timestamp(), envelope_id),
        )
    return cursor.rowcount > 0


def _mark_envelope_retry_pending(
    *, conn: sqlite3.Connection, row: sqlite3.Row, failure_reason: str
) -> None:
    now = _timestamp()
    with sqlite_transaction(conn=conn):
        conn.execute(
            """
            UPDATE envelopes
            SET state = 'retry_pending', failed_at = ?, next_attempt_at = ?, last_error = ?
            WHERE envelope_id = ? AND state IN ('claimed', 'sending')
            """,
            (
                now,
                _next_attempt_at(attempt_count=int(row["attempt_count"] or 0)),
                failure_reason[:500],
                row["envelope_id"],
            ),
        )


def _mark_peer_retry_pending(
    *, conn: sqlite3.Connection, row: sqlite3.Row, failure_reason: str
) -> None:
    """Consume one peer retry budget and defer all of that peer's work together."""
    now = _timestamp()
    exhausted = int(row["attempt_count"] or 0) >= MAX_DELIVERY_ATTEMPTS
    next_attempt_at = (
        None
        if exhausted
        else _next_attempt_at(attempt_count=int(row["attempt_count"] or 0))
    )
    with sqlite_transaction(conn=conn):
        conn.execute(
            """
            UPDATE envelopes
            SET state = 'retry_pending', failed_at = ?, next_attempt_at = ?,
                last_error = ?
            WHERE destination_node_id = ?
              AND (
                  state IN ('pending', 'retry_pending')
                  OR (
                      envelope_id = ?
                      AND state IN ('claimed', 'sending')
                  )
              )
            """,
            (
                now,
                next_attempt_at,
                failure_reason[:500],
                row["destination_node_id"],
                row["envelope_id"],
            ),
        )


def resume_peer_delivery(*, conn: sqlite3.Connection, peer_id: str) -> int:
    """Wake parked work with a fresh finite budget for an authenticated route."""
    now = _timestamp()
    with sqlite_transaction(conn=conn):
        cursor = conn.execute(
            """
            UPDATE envelopes
            SET next_attempt_at = ?, attempt_count = 0
            WHERE destination_node_id = ? AND state = 'retry_pending'
              AND next_attempt_at IS NULL
            """,
            (now, peer_id),
        )
    return cursor.rowcount


def next_outbound_attempt_at(*, conn: sqlite3.Connection) -> str | None:
    """Return the next finite retry or claim-expiry deadline."""
    row = conn.execute(
        """
        SELECT MIN(deadline) AS next_attempt_at
        FROM (
            SELECT e.next_attempt_at AS deadline
            FROM envelopes e
            WHERE e.state = 'retry_pending'
              AND e.next_attempt_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM envelopes parked
                  WHERE parked.destination_node_id = e.destination_node_id
                    AND parked.state = 'retry_pending'
                    AND parked.next_attempt_at IS NULL
              )
            UNION ALL
            SELECT strftime(
                       '%Y-%m-%dT%H:%M:%SZ',
                       e.claimed_at,
                       ?
                   ) AS deadline
            FROM envelopes e
            WHERE e.state IN ('claimed', 'sending')
              AND e.claimed_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM envelopes parked
                  WHERE parked.destination_node_id = e.destination_node_id
                    AND parked.state = 'retry_pending'
                    AND parked.next_attempt_at IS NULL
              )
        )
        """,
        (f"+{CLAIM_LEASE_SECONDS} seconds",),
    ).fetchone()
    value = row["next_attempt_at"] if row is not None else None
    return str(value) if value is not None else None


def configured_delivery_schedule(
    *, recovered_peer_ids: Iterable[str] = ()
) -> tuple[int, str | None]:
    """Run one crash-safe pass and return its one-shot retry deadline."""
    conn = open_sqlite_backend()
    try:
        for peer_id in set(recovered_peer_ids):
            resume_peer_delivery(conn=conn, peer_id=peer_id)
        sent_count = process_pending_outbound_envelopes(conn=conn)
        return sent_count, next_outbound_attempt_at(conn=conn)
    finally:
        conn.close()


def _mark_envelope_authorization_denied(
    *, conn: sqlite3.Connection, row: sqlite3.Row, failure_reason: str
) -> None:
    with sqlite_transaction(conn=conn):
        conn.execute(
            """
            UPDATE envelopes
            SET state = 'authorization_denied', failed_at = ?,
                next_attempt_at = NULL, last_error = ?
            WHERE envelope_id = ? AND state IN ('claimed', 'sending')
            """,
            (_timestamp(), failure_reason[:500], row["envelope_id"]),
        )


def _timestamp() -> str:
    return now_utc_iso()


def _next_attempt_at(*, attempt_count: int) -> str:
    exponent = max(0, min(attempt_count - 1, 8))
    delay_seconds = min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * (2**exponent))
    return (
        datetime.now(tz=timezone.utc) + timedelta(seconds=delay_seconds)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "configured_delivery_schedule",
    "DeliveryOutcome",
    "deliver_outbound_envelope",
    "next_outbound_attempt_at",
    "process_configured_pending_outbound_envelopes",
    "process_pending_outbound_envelopes",
    "resume_peer_delivery",
]
