from __future__ import annotations

import unittest

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.transaction_scope import (
    TransactionScopeKind,
    service_group_scope_id,
    transaction_scope,
)
from secrets_kit.backends.sqlite.transactions import create_transaction
from tests.canonical_id_helpers import tid

NODE_ID = tid("node", "transaction-scope-node")
SECRET_SET_TXN_ID = tid("transaction", "transaction-scope-secret-set")
SECRET_DELETE_TXN_ID = tid("transaction", "transaction-scope-secret-delete")
CONTROL_TXN_ID = tid("transaction", "transaction-scope-control")
VOCAB_TXN_ID = tid("transaction", "transaction-scope-vocabulary")
UNKNOWN_TXN_ID = tid("transaction", "transaction-scope-unknown")
SERVICE_GROUP_ID = tid("service_group", "transaction-scope-service-group")


class SQLiteTransactionScopeTest(unittest.TestCase):
    def test_secret_mutations_require_canonical_service_group_scope(self) -> None:
        transaction = _transaction(
            transaction_id=SECRET_SET_TXN_ID,
            transaction_type="secret.set",
            payload={"service_group_id": SERVICE_GROUP_ID},
        )
        scope = transaction_scope(transaction=transaction)
        self.assertEqual(scope.kind, TransactionScopeKind.SERVICE_GROUP)
        self.assertEqual(scope.service_group_id, SERVICE_GROUP_ID)
        self.assertEqual(service_group_scope_id(transaction=transaction), SERVICE_GROUP_ID)

    def test_secret_mutations_reject_missing_or_malformed_service_group_scope(self) -> None:
        missing = _transaction(
            transaction_id=SECRET_DELETE_TXN_ID,
            transaction_type="secret.delete",
            payload={},
        )
        with self.assertRaisesRegex(SQLiteValidationError, "service_group_id is required"):
            transaction_scope(transaction=missing)

        malformed = _transaction(
            transaction_id=SECRET_SET_TXN_ID,
            transaction_type="secret.set",
            payload={"service_group_id": "not-a-service-group"},
        )
        with self.assertRaisesRegex(SQLiteValidationError, "service_group_id"):
            transaction_scope(transaction=malformed)

    def test_control_and_local_system_transactions_do_not_inherit_service_scope(self) -> None:
        control = _transaction(
            transaction_id=CONTROL_TXN_ID,
            transaction_type="peer.admission.accept",
            payload={},
        )
        self.assertEqual(transaction_scope(transaction=control).kind, TransactionScopeKind.CONTROL)
        self.assertIsNone(service_group_scope_id(transaction=control))

        vocabulary = _transaction(
            transaction_id=VOCAB_TXN_ID,
            transaction_type="vocabulary.entry_type.upsert",
            payload={},
        )
        self.assertEqual(
            transaction_scope(transaction=vocabulary).kind,
            TransactionScopeKind.LOCAL_SYSTEM,
        )
        self.assertIsNone(service_group_scope_id(transaction=vocabulary))

    def test_unknown_transaction_scope_is_rejected(self) -> None:
        transaction = _transaction(
            transaction_id=UNKNOWN_TXN_ID,
            transaction_type="unknown.transaction",
            payload={},
        )
        with self.assertRaisesRegex(SQLiteValidationError, "transaction scope is unknown"):
            transaction_scope(transaction=transaction)


def _transaction(*, transaction_id: str, transaction_type: str, payload: dict[str, object]):
    return create_transaction(
        transaction_id=transaction_id,
        transaction_type=transaction_type,
        origin_node_id=NODE_ID,
        created_at="2026-07-14T00:00:00Z",
        payload=payload,
    )
