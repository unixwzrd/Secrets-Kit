"""
secrets_kit.cli.commands.transaction

Read-only transaction inspection commands.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from secrets_kit.backends.sqlite.exceptions import TransactionNotFoundError
from secrets_kit.backends.sqlite.gate import sqlite_path
from secrets_kit.backends.sqlite.transactions import (
    TransactionInspection,
    get_persisted_transaction,
    list_persisted_transactions,
)
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.tables import _print_table


def cmd_transaction_list(*, args: argparse.Namespace) -> int:
    rows = [
        [
            transaction.transaction_id,
            transaction.transaction_type,
            transaction.state,
            transaction.origin_node_id,
            transaction.created_at,
            transaction.received_at,
            transaction.applied_at,
            transaction.acknowledged_at,
            transaction.cleared_at,
        ]
        for transaction in list_persisted_transactions(path=sqlite_path())
    ]
    _print_table(
        headers=[
            "TRANSACTION_ID",
            "TRANSACTION_TYPE",
            "STATE",
            "ORIGIN_NODE_ID",
            "CREATED_AT",
            "RECEIVED_AT",
            "APPLIED_AT",
            "ACKNOWLEDGED_AT",
            "CLEARED_AT",
        ],
        rows=rows,
    )
    return 0


def cmd_transaction_show(*, args: argparse.Namespace) -> int:
    try:
        transaction = get_persisted_transaction(
            path=sqlite_path(), transaction_id=args.transaction_id
        )
    except TransactionNotFoundError:
        return _fatal(message=f"transaction not found: {args.transaction_id}", code=1)
    _print_transaction(transaction=transaction)
    return 0


def _print_transaction(*, transaction: TransactionInspection) -> None:
    for field_name in (
        "transaction_id",
        "transaction_version",
        "payload_version",
        "protocol_version",
        "organization_id",
        "client_id",
        "owner_id",
        "transaction_type",
        "origin_node_id",
        "previous_transaction_id",
        "payload_hash",
        "signature",
        "state",
        "created_at",
        "received_at",
        "applied_at",
        "acknowledged_at",
        "cleared_at",
    ):
        print(f"{field_name}: {_format_value(getattr(transaction, field_name))}")
    print("payload:")
    print(json.dumps(transaction.payload, indent=2, sort_keys=True))


def _format_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


__all__ = ["cmd_transaction_list", "cmd_transaction_show"]
