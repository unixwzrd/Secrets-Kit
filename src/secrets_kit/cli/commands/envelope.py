"""
secrets_kit.cli.commands.envelope

Read-only envelope inspection commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.sqlite.envelopes import (
    EnvelopeInspection,
    get_persisted_envelope,
    list_persisted_envelopes,
)
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.tables import _print_table


def cmd_envelope_list(*, args: argparse.Namespace) -> int:
    rows = [
        [
            envelope.envelope_id,
            envelope.transaction_id,
            envelope.destination_node_id,
            envelope.state,
            str(envelope.attempt_count),
            envelope.retry_state,
            envelope.failure_reason,
            envelope.created_at,
            envelope.sent_at,
        ]
        for envelope in list_persisted_envelopes()
    ]
    _print_table(
        headers=[
            "ENVELOPE_ID",
            "TRANSACTION_ID",
            "DESTINATION_NODE_ID",
            "STATE",
            "ATTEMPTS",
            "RETRY_STATE",
            "FAILURE_REASON",
            "CREATED_AT",
            "SENT_AT",
        ],
        rows=rows,
    )
    return 0


def cmd_envelope_show(*, args: argparse.Namespace) -> int:
    envelope = get_persisted_envelope(envelope_id=args.envelope_id)
    if envelope is None:
        return _fatal(message=f"envelope not found: {args.envelope_id}", code=1)
    _print_envelope(envelope=envelope)
    return 0


def _print_envelope(*, envelope: EnvelopeInspection) -> None:
    print(f"envelope_id: {envelope.envelope_id}")
    print(f"transaction_id: {envelope.transaction_id}")
    print(f"destination_node_id: {envelope.destination_node_id}")
    print(f"state: {envelope.state}")
    print(f"attempt_count: {envelope.attempt_count}")
    print(f"retry_state: {envelope.retry_state}")
    print(f"failure_reason: {envelope.failure_reason}")
    print(f"created_at: {envelope.created_at}")
    print(f"sent_at: {envelope.sent_at}")


__all__ = ["cmd_envelope_list", "cmd_envelope_show"]
