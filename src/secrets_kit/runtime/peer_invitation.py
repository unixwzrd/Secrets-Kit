"""secrets_kit.runtime.peer_invitation

Drive durable, explicitly approved encrypted peer admission for this user.
Private node keys stay inside the runtime. Framing alone grants no authority;
mutual native admission proofs are applied atomically after recorded consent.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import replace
from typing import Any

from secrets_kit.backends.sqlite.connection import transaction as sqlite_transaction
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.backends.sqlite.peer_admission import (
    PEER_ADMISSION_ACCEPT,
    PEER_ADMISSION_INBOUND_DECISION_POLICY,
    PEER_ADMISSION_LOCAL_POLICY,
    PEER_ADMISSION_OUTBOUND_REQUEST_POLICY,
    PEER_ADMISSION_REQUEST,
    create_peer_admission_transaction,
    create_signed_peer_admission_decision,
    create_signed_peer_admission_request,
    local_peer_public_identity,
)
from secrets_kit.backends.sqlite.peer_admission_auth import (
    verify_admission_decision_signature,
    verify_admission_request_payload,
)
from secrets_kit.backends.sqlite.peer_registry import get_peer_registry_entry
from secrets_kit.backends.sqlite.secrets_api import _service_group_id
from secrets_kit.backends.sqlite.transaction_engine import submit_transaction
from secrets_kit.backends.sqlite.transactions import transaction_exists
from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.crypto.keys import generate_symmetric_key
from secrets_kit.daemon.client import (
    DaemonError,
    request_local_direct_candidate,
    submit_direct_candidate,
)
from secrets_kit.daemon.control import validate_direct_candidate
from secrets_kit.protocol.peer_invitation import (
    InvitationError,
    InvitationSecret,
    open_invitation_message,
    seal_invitation_message,
)
from secrets_kit.protocol.peer_invitation_mailbox import InvitationMailboxClient
from secrets_kit.protocol.rss_admin import admin_action
from secrets_kit.protocol.rss_auth import (
    RSSAuthenticationError,
    load_rss_relay_credentials_from_environment,
)
from secrets_kit.protocol.rss_provisioning import (
    configure_rss_provisioning_bundle,
    prepare_rss_device_identity,
    rss_enrollment_token_expired,
)
from secrets_kit.runtime.peer_invitation_state import InvitationStateStore


def sign_local_invitation(
    *, secret: InvitationSecret, stage: str, body: dict[str, Any], expires_at: int,
) -> bytes:
    """Return one signed encrypted frame; no store or authorization is changed."""
    conn = open_sqlite_backend()
    try:
        identity = load_sqlite_node_identity_material(conn=conn)
    finally:
        conn.close()
    return seal_invitation_message(
        secret=secret, stage=stage, body=body, expires_at=expires_at,
        signing_private_key=identity.signing.private_key,
        signing_public_key=identity.signing.public_key,
    )


def _local_candidate(*, node_id: str) -> dict[str, str] | None:
    """Capture a live dial hint, not an identity assertion or route proof."""
    return request_local_direct_candidate(peer_id=node_id)


def _validate_candidate(*, value: object, node_id: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"peer_id", "endpoint"} or value["peer_id"] != node_id:
        raise InvitationError("invitation direct candidate identity does not match")
    try:
        peer, address = validate_direct_candidate(peer_id=value["peer_id"], endpoint=value["endpoint"])
    except ValueError:
        raise InvitationError("invitation direct candidate is invalid") from None
    return {"peer_id": peer, "endpoint": address}


def _handoff_candidate(*, candidate: dict[str, str] | None) -> None:
    if candidate is None:
        return
    try:
        submit_direct_candidate(peer_id=candidate["peer_id"], endpoint=candidate["endpoint"])
    except (DaemonError, OSError):
        pass  # Admission is retained; enrolled RSS may still supply a route.


class InvitationPending(InvitationError):
    """A retained phase needs retry; expose only its non-secret session ID."""

    def __init__(self, *, session_id: str) -> None:
        super().__init__("invitation delivery pending")
        self.session_id = session_id


class InvitationCapacityPending(InvitationError):
    """Approval needs paid capacity; no admission or slot is changed."""

    def __init__(self, *, capacity: dict[str, int]) -> None:
        super().__init__("invitation RSS capacity pending")
        self.capacity = capacity


class PeerInvitationFlow:
    """Explicit invocation drives bounded phases; no polling/background grants.

    Persist phase frames before network writes, and reuse them on resume.
    Creating or publishing an offer/join never changes peer authorization.
    """

    def __init__(self, *, state: InvitationStateStore, mailbox: InvitationMailboxClient) -> None:
        self.state = state
        self.mailbox = mailbox

    def _load(self, session_id: str, role: str) -> tuple[int, dict[str, Any]]:
        revision, record = self.state.read(session_id=session_id, local_node_id=local_peer_public_identity().node_id)
        if (record["role"] != role or record["expires_at"] <= int(time.time())
                or record.get("operator_url") != self.mailbox.origin):
            raise InvitationError("invitation role or deadline is invalid")
        return revision, record

    @staticmethod
    def _request(body: dict[str, Any], signer: bytes) -> dict[str, Any]:
        request = body.get("request")
        if not isinstance(request, dict):
            raise InvitationError("invitation identity request is invalid")
        try:
            verify_admission_request_payload(payload=request)
            if decode_b64url(request["signing_public_key"]) != signer:
                raise ValueError
        except (SQLiteBackendError, ValueError, KeyError):
            raise InvitationError("invitation identity request is invalid") from None
        return request

    def invite(self, *, service: str, account: str, include_rss: bool = False) -> tuple[str, str]:
        """Return ID and private handoff code after durable offer publication."""
        if any(not isinstance(v, str) or not v.strip() or len(v) > 512 or "\0" in v for v in (service, account)):
            raise InvitationError("invitation scope is invalid")
        if type(include_rss) is not bool:
            raise InvitationError("invitation RSS choice is invalid")
        identity = local_peer_public_identity()
        secret = InvitationSecret.create(issuer_public_key=decode_b64url(identity.signing_public_key))
        request = create_signed_peer_admission_request().payload
        expiry = int(time.time()) + 900
        frame = sign_local_invitation(secret=secret, stage="offer", body={"request": request, "service": service,
                                      "account": account, "include_rss": include_rss,
                                      "direct_candidate": _local_candidate(node_id=identity.node_id)}, expires_at=expiry)
        record = {"version": 1, "session_id": secret.session_id, "local_node_id": identity.node_id,
                  "role": "source", "service": service, "account": account, "expires_at": expiry,
                  "code": secret.code(), "source_cap": encode_b64url(generate_symmetric_key()),
                  "operator_url": self.mailbox.origin,
                  "include_rss": include_rss,
                  "local_request": request, "phase": "created", "frames": {"offer": encode_b64url(frame)}}
        self.state.save(session_id=secret.session_id, record=record, expected_revision=None)
        try:
            self.publish_offer(session_id=secret.session_id)
        except InvitationError:
            raise InvitationPending(session_id=secret.session_id) from None
        return secret.session_id, secret.code()

    def publish_offer(self, *, session_id: str) -> None:
        """Resume the staged offer without replacing its proof/code/deadline."""
        revision, record = self._load(session_id, "source")
        self.mailbox.create(secret=InvitationSecret.from_code(record["code"]), source_cap=record["source_cap"],
                            frame=decode_b64url(record["frames"]["offer"]), expires_at=record["expires_at"])
        if record["phase"] == "created":
            self.state.save(session_id=session_id, record={**record, "phase": "offered"}, expected_revision=revision)

    def inspect_offer(self, *, code: str) -> dict[str, Any]:
        """Verified public identity/scope for display; no local side effects."""
        secret = InvitationSecret.from_code(code)
        messages = self.mailbox.read(secret=secret)
        frame = messages["offer"]
        if not isinstance(frame, bytes):
            raise InvitationError("invitation offer is invalid")
        body, signer, expiry = open_invitation_message(secret=secret, stage="offer", data=frame)
        if (set(body) != {"request", "service", "account", "include_rss", "direct_candidate"}
                or type(body["include_rss"]) is not bool or messages["expires_at"] != expiry):
            raise InvitationError("invitation offer is invalid")
        request = self._request(body, signer)
        _validate_candidate(value=body["direct_candidate"], node_id=request["node_id"])
        if request["node_id"] == local_peer_public_identity().node_id:
            raise InvitationError("invitation cannot join this node to itself")
        if any(not isinstance(body[key], str) or not body[key].strip() or len(body[key]) > 512 or "\0" in body[key] for key in ("service", "account")):
            raise InvitationError("invitation scope is invalid")
        return {**body, "expires_at": expiry, "session_id": secret.session_id}

    def join(self, *, code: str, confirmed: bool) -> str:
        """Stage one target claim only after explicit identity/scope consent."""
        if confirmed is not True:
            raise InvitationError("explicit invitation consent is required")
        offer = self.inspect_offer(code=code)
        secret = InvitationSecret.from_code(code)
        identity = local_peer_public_identity()
        if offer["include_rss"]:
            _check_retained_peer(request=offer["request"], service=offer["service"], account=offer["account"])
        rss_identity = prepare_rss_device_identity(expected_operator_url=self.mailbox.origin, allow_pending_recovery=True) if offer["include_rss"] else None
        request = create_signed_peer_admission_request().payload
        decision = create_signed_peer_admission_decision(
            proof_type=PEER_ADMISSION_ACCEPT, node_id=offer["request"]["node_id"], request_id=offer["request"]["request_id"],
            service_group_ids=(_service_group_id(account=offer["account"], service=offer["service"]),),
        ).payload
        frame = sign_local_invitation(secret=secret, stage="join", body={"request": request, "decision": decision,
                                      "service": offer["service"], "account": offer["account"],
                                      "rss_identity": rss_identity, "direct_candidate": _local_candidate(node_id=identity.node_id)}, expires_at=offer["expires_at"])
        record = {"version": 1, "session_id": secret.session_id, "local_node_id": identity.node_id,
                  "role": "target", "service": offer["service"], "account": offer["account"], "expires_at": offer["expires_at"],
                  "code": code, "claim_cap": encode_b64url(generate_symmetric_key()), "phase": "join_staged",
                  "operator_url": self.mailbox.origin,
                  "include_rss": offer["include_rss"], "rss_identity": rss_identity,
                  "remote_candidate": offer["direct_candidate"],
                  "local_request": request, "remote_request": offer["request"], "local_decision": decision,
                  "remote_node_id": offer["request"]["node_id"], "remote_signing_key": offer["request"]["signing_public_key"],
                  "remote_encryption_key": offer["request"]["encryption_public_key"], "frames": {"join": encode_b64url(frame)}}
        self.state.save(session_id=secret.session_id, record=record, expected_revision=None)
        try:
            self.publish_join(session_id=secret.session_id)
        except InvitationError:
            raise InvitationPending(session_id=secret.session_id) from None
        return secret.session_id

    def publish_join(self, *, session_id: str) -> None:
        """Repeat identical target frame/claim, never grant access on join."""
        revision, record = self._load(session_id, "target")
        self.mailbox.put(secret=InvitationSecret.from_code(record["code"]), stage="join",
                         frame=decode_b64url(record["frames"]["join"]), claim_cap=record["claim_cap"])
        if record["phase"] == "join_staged":
            self.state.save(session_id=session_id, record={**record, "phase": "joined"}, expected_revision=revision)

    def inspect_join(self, *, session_id: str) -> dict[str, Any]:
        """Verify the claimed target for fingerprint display before approval."""
        _, record = self._load(session_id, "source")
        secret = InvitationSecret.from_code(record["code"])
        frame = self.mailbox.read(secret=secret)["join"]
        if not isinstance(frame, bytes):
            raise InvitationError("invitation is waiting for the joining device")
        body, signer, _ = open_invitation_message(secret=secret, stage="join", data=frame, expected_expires_at=record["expires_at"])
        if (set(body) != {"request", "decision", "service", "account", "rss_identity", "direct_candidate"}
                or not isinstance(body["decision"], dict)
                or body["service"] != record["service"] or body["account"] != record["account"]):
            raise InvitationError("invitation target scope is invalid")
        request = self._request(body, signer)
        _validate_candidate(value=body["direct_candidate"], node_id=request["node_id"])
        if request["node_id"] == record["local_node_id"]:
            raise InvitationError("invitation cannot admit this node to itself")
        _verify_decision(decision=body["decision"], signer=request, subject=record["local_request"],
                         scope=_service_group_id(account=record["account"], service=record["service"]))
        rss_identity = body["rss_identity"]
        if record["include_rss"]:
            _check_retained_peer(request=request, service=record["service"], account=record["account"])
            if (not isinstance(rss_identity, dict) or set(rss_identity) != {"connection_id", "public_key"}
                    or not isinstance(rss_identity["connection_id"], str) or not 1 <= len(rss_identity["connection_id"]) <= 256
                    or not isinstance(rss_identity["public_key"], str) or len(rss_identity["public_key"]) != 43):
                raise InvitationError("invitation RSS target is invalid")
            try:
                raw_key = decode_b64url(rss_identity["public_key"])
                if len(raw_key) != 32 or encode_b64url(raw_key) != rss_identity["public_key"]:
                    raise ValueError
            except ValueError:
                raise InvitationError("invitation RSS target is invalid") from None
        elif rss_identity is not None:
            raise InvitationError("invitation did not request RSS enrollment")
        return body

    def approve(self, *, session_id: str, confirmed: bool) -> None:
        """Stage explicit source consent, apply exact proofs, publish approval."""
        revision, record = self._load(session_id, "source")
        secret = InvitationSecret.from_code(record["code"])
        target = self.inspect_join(session_id=session_id)
        if "approve" not in record["frames"]:
            if confirmed is not True:
                raise InvitationError("explicit invitation consent is required")
            remote_request = target["request"]
            rss_bundle = self._issue_target_enrollment(target=target) if record["include_rss"] else None
            decision = create_signed_peer_admission_decision(
                proof_type=PEER_ADMISSION_ACCEPT, node_id=remote_request["node_id"], request_id=remote_request["request_id"],
                service_group_ids=(_service_group_id(account=record["account"], service=record["service"]),),
            ).payload
            body = {"decision": decision, "target_node_id": remote_request["node_id"],
                    "target_signing_key": remote_request["signing_public_key"], "target_encryption_key": remote_request["encryption_public_key"],
                    "rss_identity": target["rss_identity"], "rss_bundle": rss_bundle}
            frame = sign_local_invitation(secret=secret, stage="approve", body=body, expires_at=record["expires_at"])
            record = {**record, "phase": "approval_staged", "remote_request": remote_request,
                      "remote_node_id": remote_request["node_id"], "remote_signing_key": remote_request["signing_public_key"],
                      "remote_encryption_key": remote_request["encryption_public_key"], "remote_decision": target["decision"],
                      "rss_identity": target["rss_identity"],
                      "remote_candidate": target["direct_candidate"],
                      "local_decision": decision, "frames": {**record["frames"], "approve": encode_b64url(frame)}}
            revision = self.state.save(session_id=session_id, record=record, expected_revision=revision)
        elif (target["request"] != record["remote_request"] or target["decision"] != record["remote_decision"]
              or target["rss_identity"] != record["rss_identity"] or target["direct_candidate"] != record["remote_candidate"]):
            raise InvitationError("invitation target changed after approval")
        apply_invitation_admission(local_request=record["local_request"], remote_request=record["remote_request"],
                                   local_decision=record["local_decision"], remote_decision=record["remote_decision"],
                                   service=record["service"], account=record["account"], allow_existing_admission=record["include_rss"])
        _handoff_candidate(candidate=record["remote_candidate"])
        self.mailbox.put(secret=secret, stage="approve", source_cap=record["source_cap"], frame=decode_b64url(record["frames"]["approve"]))
        if record["phase"] not in {"approved", "complete"}:
            self.state.save(session_id=session_id, record={**record, "phase": "approved"}, expected_revision=revision)

    def complete(self, *, session_id: str) -> None:
        """Resume a target's recorded consent, apply mutual proofs and confirm."""
        revision, record = self._load(session_id, "target")
        secret = InvitationSecret.from_code(record["code"])
        frame = self.mailbox.read(secret=secret)["approve"]
        if not isinstance(frame, bytes):
            raise InvitationError("invitation is waiting for source approval")
        body, _, _ = open_invitation_message(secret=secret, stage="approve", data=frame,
                                             expected_signer=decode_b64url(record["remote_signing_key"]), expected_expires_at=record["expires_at"])
        expected = {"target_node_id": record["local_node_id"], "target_signing_key": record["local_request"]["signing_public_key"],
                    "target_encryption_key": record["local_request"]["encryption_public_key"], "rss_identity": record["rss_identity"]}
        if set(body) != {*expected, "decision", "rss_bundle"} or any(body[key] != value for key, value in expected.items()) or not isinstance(body["decision"], dict):
            raise InvitationError("invitation approval bound a different target")
        if (record["include_rss"] and not isinstance(body["rss_bundle"], dict)) or (not record["include_rss"] and body["rss_bundle"] is not None):
            raise InvitationError("invitation RSS approval is invalid")
        if record["include_rss"]:
            try:
                credentials = load_rss_relay_credentials_from_environment()
                if credentials is None or credentials.enrollment_token is not None:
                    token = body["rss_bundle"].get("rss_enrollment_token")
                    if not isinstance(token, str) or rss_enrollment_token_expired(token=token):
                        raise RSSAuthenticationError("expired invitation enrollment")
            except (RSSAuthenticationError, OSError):
                raise InvitationError("invitation RSS authorization expired or invalid; request a fresh invitation") from None
        if "complete" not in record["frames"]:
            confirmation = sign_local_invitation(secret=secret, stage="complete",
                                                body={"node_id": record["local_node_id"], "decision_id": body["decision"].get("decision_id")}, expires_at=record["expires_at"])
            record = {**record, "phase": "completion_staged", "remote_decision": body["decision"],
                      "frames": {**record["frames"], "complete": encode_b64url(confirmation)}}
            revision = self.state.save(session_id=session_id, record=record, expected_revision=revision)
        elif record["remote_decision"] != body["decision"]:
            raise InvitationError("invitation approval changed after completion")
        apply_invitation_admission(local_request=record["local_request"], remote_request=record["remote_request"],
                                   local_decision=record["local_decision"], remote_decision=record["remote_decision"],
                                   service=record["service"], account=record["account"], allow_existing_admission=record["include_rss"])
        if record["include_rss"]:
            self._configure_target_enrollment(record=record, bundle=body["rss_bundle"])
        _handoff_candidate(candidate=record["remote_candidate"])
        self.mailbox.put(secret=secret, stage="complete", claim_cap=record["claim_cap"], frame=decode_b64url(record["frames"]["complete"]))
        if record["phase"] != "complete":
            self.state.save(session_id=session_id, record={**record, "phase": "complete"}, expected_revision=revision)

    def _issue_target_enrollment(self, *, target: dict[str, Any]) -> dict[str, Any]:
        """Use only this origin's account administrator, not a peer credential."""
        identity = target["rss_identity"]
        status, bundle = admin_action(action="device.ret", parameters={
            "target_connection_id": identity["connection_id"], "target_public_key": identity["public_key"],
        }, expected_operator_url=self.mailbox.origin)
        if status == 409 and bundle.get("reason") == "device_capacity_exhausted":
            capacity = bundle.get("capacity")
            if (isinstance(capacity, dict) and set(capacity) == {"purchased_units", "provisioned_units", "available_units"}
                    and all(type(value) is int and value >= 0 for value in capacity.values())):
                raise InvitationCapacityPending(capacity=capacity)
        if status != 200 or not isinstance(bundle, dict):
            raise InvitationError("invitation RSS authorization is unavailable")
        return bundle

    def _configure_target_enrollment(self, *, record: dict[str, Any], bundle: dict[str, Any]) -> None:
        """A retry preserves a matching profile; no exported device key is used."""
        try:
            credentials = load_rss_relay_credentials_from_environment()
            if credentials is None or (credentials.enrollment_token is not None
                                       and rss_enrollment_token_expired(token=credentials.enrollment_token)):
                configure_rss_provisioning_bundle(bundle=bundle, expected_operator_url=self.mailbox.origin)
                credentials = load_rss_relay_credentials_from_environment()
            identity = record["rss_identity"]
            if (credentials is None or credentials.enrollment_url != self.mailbox.origin
                    or credentials.connection_id != identity["connection_id"]
                    or encode_b64url(credentials.customer_public_key) != identity["public_key"]
                    or credentials.entitlement_id != bundle.get("entitlement_id")):
                raise InvitationError("invitation RSS local identity does not match")
            if credentials.enrollment_token is not None and rss_enrollment_token_expired(token=credentials.enrollment_token):
                raise InvitationError("invitation RSS configuration remains pending")
        except (RSSAuthenticationError, OSError):
            raise InvitationError("invitation RSS configuration remains pending") from None

    def confirm_completion(self, *, session_id: str) -> bool:
        """Verify the approved target's acknowledgment; never grant admission.

        Return false while delivery is pending. Reject malformed, substituted
        or expired acknowledgments without changing local authorization.
        """
        revision, record = self._load(session_id, "source")
        if record["phase"] not in {"approved", "complete"}:
            raise InvitationError("invitation source approval is not complete")
        secret = InvitationSecret.from_code(record["code"])
        frame = self.mailbox.read(secret=secret)["complete"]
        if frame is None:
            return False
        if not isinstance(frame, bytes):
            raise InvitationError("invitation completion is invalid")
        body, _, _ = open_invitation_message(
            secret=secret, stage="complete", data=frame,
            expected_signer=decode_b64url(record["remote_signing_key"]),
            expected_expires_at=record["expires_at"],
        )
        if body != {"node_id": record["remote_node_id"],
                    "decision_id": record["local_decision"]["decision_id"]}:
            raise InvitationError("invitation completion does not match approval")
        if record["phase"] != "complete":
            self.state.save(session_id=session_id, record={**record, "phase": "complete"}, expected_revision=revision)
        return True


def apply_invitation_admission(
    *, local_request: dict[str, Any], remote_request: dict[str, Any],
    local_decision: dict[str, Any], remote_decision: dict[str, Any],
    service: str, account: str, allow_existing_admission: bool = False,
) -> None:
    """Apply mutually approved proofs atomically; exact retries never regrant.

    The caller must first verify invitation framing, original expiry and
    recorded consent. Native proof signatures/policies remain authoritative.
    This operation creates no RSS credential or billing authority.
    """
    try:
        _apply_invitation_admission(local_request=local_request, remote_request=remote_request,
                                    local_decision=local_decision, remote_decision=remote_decision,
                                    service=service, account=account, allow_existing_admission=allow_existing_admission)
    except (SQLiteBackendError, sqlite3.Error, KeyError, TypeError):
        raise InvitationError("invitation admission failed") from None


def _apply_invitation_admission(
    *, local_request: dict[str, Any], remote_request: dict[str, Any],
    local_decision: dict[str, Any], remote_decision: dict[str, Any],
    service: str, account: str, allow_existing_admission: bool,
) -> None:
    if any(not isinstance(value, str) or not value.strip() or len(value) > 512 or "\0" in value
           for value in (service, account)):
        raise InvitationError("invitation scope is invalid")
    scope = _service_group_id(account=account, service=service)
    verify_admission_request_payload(payload=local_request)
    verify_admission_request_payload(payload=remote_request)
    if local_request["node_id"] == remote_request["node_id"]:
        raise InvitationError("invitation cannot admit this node to itself")
    for decision, signer, subject in ((local_decision, local_request, remote_request),
                                     (remote_decision, remote_request, local_request)):
        _verify_decision(decision=decision, signer=signer, subject=subject, scope=scope)
    conn = open_sqlite_backend()
    try:
        identity = load_sqlite_node_identity_material(conn=conn)
        if (local_request["node_id"] != identity.node_id
                or local_request["signing_public_key"] != encode_b64url(identity.signing.public_key)
                or local_request["encryption_public_key"] != encode_b64url(identity.encryption.public_key)):
            raise InvitationError("invitation belongs to another local identity")
        stages = (
            (local_request, PEER_ADMISSION_REQUEST, "node_id", PEER_ADMISSION_OUTBOUND_REQUEST_POLICY),
            (remote_request, PEER_ADMISSION_REQUEST, "node_id", PEER_ADMISSION_LOCAL_POLICY),
            (local_decision, PEER_ADMISSION_ACCEPT, "signer_node_id", PEER_ADMISSION_LOCAL_POLICY),
            (remote_decision, PEER_ADMISSION_ACCEPT, "signer_node_id", PEER_ADMISSION_INBOUND_DECISION_POLICY),
        )
        with sqlite_transaction(conn=conn):
            prior_peer = get_peer_registry_entry(conn=conn, node_id=remote_request["node_id"])
            if allow_existing_admission and prior_peer is not None:
                _require_retained_peer(peer=prior_peer, request=remote_request, scope=scope)
                # Fresh RSS consent is not a new peer-admission transaction.
                # Preserve existing history, keys and every authorized scope.
                return
            request_tx = create_peer_admission_transaction(transaction_type=PEER_ADMISSION_REQUEST,
                                                           payload=remote_request, origin_node_id=remote_request["node_id"])
            if (prior_peer is not None and prior_peer.admission_state == "active"
                    and not transaction_exists(conn=conn, transaction_id=request_tx.transaction_id)):
                raise InvitationError("peer already has established admission; existing scope retained")
            for payload, proof_type, origin_field, policy in stages:
                tx = create_peer_admission_transaction(transaction_type=proof_type, payload=payload,
                                                       origin_node_id=payload[origin_field])
                submit_transaction(conn=conn, transaction=tx, policy=replace(policy, ignore_duplicate=True))
    finally:
        conn.close()


def _verify_decision(*, decision: dict[str, Any], signer: dict[str, Any], subject: dict[str, Any], scope: str) -> None:
    expected = {
        "proof_type": PEER_ADMISSION_ACCEPT,
        "signer_node_id": signer["node_id"], "node_id": subject["node_id"],
        "request_id": subject["request_id"],
        "signer_signing_public_key": signer["signing_public_key"],
        "signer_encryption_public_key": signer["encryption_public_key"],
        "authorization_mode": "allow_list", "service_group_ids": [scope],
    }
    if any(decision.get(key) != value for key, value in expected.items()):
        raise InvitationError("invitation decision identity or scope does not match")
    try:
        verify_admission_decision_signature(payload=decision)
    except SQLiteBackendError:
        raise InvitationError("invitation decision signature is invalid") from None


def _require_retained_peer(*, peer: Any, request: dict[str, Any], scope: str) -> None:
    if (not peer.synchronization_eligible or peer.admission_state != "active"
            or peer.signing_public_key != request["signing_public_key"]
            or peer.encryption_public_key != request["encryption_public_key"]
            or not (peer.authorization_mode == "all"
                    or (peer.authorization_mode == "allow_list" and scope in peer.service_group_ids))):
        raise InvitationError("RSS repair cannot change retained peer identity or authorization")


def _check_retained_peer(*, request: dict[str, Any], service: str, account: str) -> None:
    conn = open_sqlite_backend()
    try:
        peer = get_peer_registry_entry(conn=conn, node_id=request["node_id"])
        if peer is not None:
            _require_retained_peer(peer=peer, request=request, scope=_service_group_id(service=service, account=account))
    finally:
        conn.close()
