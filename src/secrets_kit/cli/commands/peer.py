"""
secrets_kit.cli.commands.peer

Explicit peer admission commands with scoped authorization.
"""

from __future__ import annotations

import argparse
import json
import sys

from secrets_kit.backends.common import BACKEND_SQLITE
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError, SQLiteValidationError
from secrets_kit.backends.sqlite.peer_admission import (
    AUTHORIZATION_MODE_ALL,
    PeerAdmissionResult,
    accept_peer_admission,
    create_signed_peer_admission_request,
    get_peer_admission,
    import_peer_admission_decision,
    list_peer_admissions,
    local_peer_public_identity,
    reject_peer_admission,
    request_peer_admission,
    retain_local_peer_admission_request,
)
from secrets_kit.cli.io import _fatal
from secrets_kit.locale import msg


def cmd_peer_request(*, args: argparse.Namespace) -> int:
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    try:
        transaction = create_signed_peer_admission_request(
            service_address=args.service_address or "",
            operator_comment=args.comment or "",
        )
        retain_local_peer_admission_request(transaction=transaction)
    except (SQLiteBackendError, SQLiteValidationError) as exc:
        return _fatal(message=str(exc), code=1)
    if getattr(args, "json", False):
        print(json.dumps(transaction.payload, indent=2, sort_keys=True))
        return 0
    print(json.dumps(transaction.payload, sort_keys=True))
    return 0


def cmd_peer_import_request(*, args: argparse.Namespace) -> int:
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    try:
        result = request_peer_admission(signed_request=_read_json_payload(args=args))
    except (SQLiteBackendError, ValueError, json.JSONDecodeError) as exc:
        return _fatal(message=str(exc), code=1)
    _print_result(result=result)
    return 0


def cmd_peer_accept(*, args: argparse.Namespace) -> int:
    """Accept a peer using existing IDs or one explicitly named account/service.

    Named scopes use the datastore's existing deterministic identifier function;
    they do not create groups, grant wildcard access or alter admission semantics.
    """
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    service_group_ids = tuple(getattr(args, "service_group_id", ()) or ())
    all_service_groups = bool(getattr(args, "all_service_groups", False))
    service = getattr(args, "service", None)
    account = getattr(args, "account", None)
    if service is not None or account is not None:
        if (
            not isinstance(service, str) or not service.strip() or "\0" in service
            or not isinstance(account, str) or not account.strip() or "\0" in account
            or service_group_ids or all_service_groups
        ):
            return _fatal(message=msg("cli.peer.scope_invalid"), code=1)
        from secrets_kit.backends.sqlite.secrets_api import _service_group_id

        service_group_ids = (_service_group_id(account=account, service=service),)
    if all_service_groups and service_group_ids:
        return _fatal(
            message="--all-service-groups cannot be combined with --service-group-id",
            code=1,
        )
    try:
        result = accept_peer_admission(
            node_id=args.node_id,
            operator_comment=args.comment or "",
            service_group_ids=service_group_ids,
            authorization_mode=AUTHORIZATION_MODE_ALL if all_service_groups else None,
        )
    except (SQLiteBackendError, SQLiteValidationError) as exc:
        return _fatal(message=str(exc), code=1)
    if getattr(args, "json", False) and result.proof_payload is not None:
        print(json.dumps(result.proof_payload, indent=2, sort_keys=True))
        return 0
    _print_result(result=result)
    return 0


def cmd_peer_import_acceptance(*, args: argparse.Namespace) -> int:
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    try:
        result = import_peer_admission_decision(signed_decision=_read_json_payload(args=args))
    except (SQLiteBackendError, ValueError, json.JSONDecodeError) as exc:
        return _fatal(message=str(exc), code=1)
    _print_result(result=result)
    return 0


def cmd_peer_reject(*, args: argparse.Namespace) -> int:
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    try:
        result = reject_peer_admission(
            node_id=args.node_id,
            operator_comment=args.comment or "",
        )
    except SQLiteBackendError as exc:
        return _fatal(message=str(exc), code=1)
    if getattr(args, "json", False) and result.proof_payload is not None:
        print(json.dumps(result.proof_payload, indent=2, sort_keys=True))
        return 0
    _print_result(result=result)
    return 0


def cmd_peer_export_identity(*, args: argparse.Namespace) -> int:
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    try:
        identity = local_peer_public_identity()
    except SQLiteBackendError as exc:
        return _fatal(message=str(exc), code=1)
    payload = {
        "node_id": identity.node_id,
        "signing_algorithm": identity.signing_algorithm,
        "signing_public_key": identity.signing_public_key,
        "encryption_algorithm": identity.encryption_algorithm,
        "encryption_public_key": identity.encryption_public_key,
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for key in sorted(payload):
            print(f"{key}: {payload[key]}")
    return 0


def cmd_peer_list(*, args: argparse.Namespace) -> int:
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    rows = list_peer_admissions()
    if getattr(args, "json", False):
        print(
            json.dumps(
                [
                    {
                        "node_id": row.node_id,
                        "state": row.state,
                        "authorization_state": row.authorization_state,
                        "authorization_mode": row.authorization_mode,
                        "synchronization_eligible": row.synchronization_eligible,
                        "signing_algorithm": row.signing_algorithm,
                        "signing_public_key": row.signing_public_key,
                        "signing_fingerprint": row.signing_fingerprint,
                        "encryption_algorithm": row.encryption_algorithm,
                        "encryption_public_key": row.encryption_public_key,
                        "encryption_fingerprint": row.encryption_fingerprint,
                        "service_address": row.service_address,
                        "endpoint": row.endpoint,
                        "endpoint_state": row.endpoint_state,
                        "endpoint_expires_at": row.endpoint_expires_at,
                        "operator_description": row.operator_description,
                        "service_group_ids": list(row.service_group_ids),
                        "created_at": row.created_at,
                        "updated_at": row.updated_at,
                    }
                    for row in rows
                ],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    for row in rows:
        print(f"{row.node_id}\t{row.state}")
    return 0


def cmd_peer_show(*, args: argparse.Namespace) -> int:
    if getattr(args, "backend", None) != BACKEND_SQLITE:
        return _fatal(message="peer admission currently requires --backend sqlite", code=1)
    row = get_peer_admission(node_id=args.node_id)
    if row is None:
        return _fatal(message=f"peer not found: {args.node_id}", code=1)
    payload = {
        "node_id": row.node_id,
        "state": row.state,
        "authorization_state": row.authorization_state,
        "authorization_mode": row.authorization_mode,
        "synchronization_eligible": row.synchronization_eligible,
        "signing_algorithm": row.signing_algorithm,
        "signing_public_key": row.signing_public_key,
        "signing_fingerprint": row.signing_fingerprint,
        "encryption_algorithm": row.encryption_algorithm,
        "encryption_public_key": row.encryption_public_key,
        "encryption_fingerprint": row.encryption_fingerprint,
        "service_address": row.service_address,
        "endpoint": row.endpoint,
        "endpoint_state": row.endpoint_state,
        "endpoint_expires_at": row.endpoint_expires_at,
        "operator_description": row.operator_description,
        "service_group_ids": list(row.service_group_ids),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for key in sorted(payload):
            print(f"{key}: {payload[key]}")
    return 0


def _print_result(*, result: PeerAdmissionResult) -> None:
    print(f"transaction_id: {result.transaction_id}")
    print(f"transaction_type: {result.transaction_type}")
    print(f"node_id: {result.node_id}")
    print(f"state: {result.state}")


def _read_json_payload(*, args: argparse.Namespace) -> dict[str, object]:
    path = getattr(args, "file", None)
    if path:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        payload = json.load(sys.stdin)
    if not isinstance(payload, dict):
        raise ValueError("peer admission payload must be a JSON object")
    return payload


__all__ = [
    "cmd_peer_accept",
    "cmd_peer_export_identity",
    "cmd_peer_import_acceptance",
    "cmd_peer_import_request",
    "cmd_peer_list",
    "cmd_peer_reject",
    "cmd_peer_request",
    "cmd_peer_show",
]
