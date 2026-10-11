"""Security contract for encrypted invitation framing, not admission authority."""

from __future__ import annotations

import base64
import json
import ssl
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.peer_admission import (
    PEER_ADMISSION_ACCEPT,
    create_signed_peer_admission_decision,
    create_signed_peer_admission_request,
    get_peer_admission,
    local_peer_public_identity,
)
from secrets_kit.backends.sqlite.secrets_api import _service_group_id
from secrets_kit.crypto.signatures import generate_ed25519_keypair
from secrets_kit.protocol.peer_invitation import (
    InvitationError,
    InvitationSecret,
    open_invitation_message,
    seal_invitation_message,
)
from secrets_kit.protocol.peer_invitation_mailbox import InvitationMailboxClient, _NoRedirect
from secrets_kit.protocol.rss_auth import load_rss_relay_credentials_from_environment
from secrets_kit.runtime.peer_invitation import (
    InvitationCapacityPending,
    InvitationPending,
    PeerInvitationFlow,
    _local_candidate,
    _validate_candidate,
    apply_invitation_admission,
    sign_local_invitation,
)
from secrets_kit.runtime.peer_invitation_state import InvitationStateStore
from tests.local_peer_lab import make_node, node_environment, provision_node


class PeerInvitationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private, self.public = generate_ed25519_keypair()
        self.target_private, self.target_public = generate_ed25519_keypair()
        self.secret = InvitationSecret.create(issuer_public_key=self.public)

    def test_mailbox_client_uses_tls_post_without_code_in_url(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"status":"stored"}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch("secrets_kit.protocol.peer_invitation_mailbox.urllib.request.build_opener", return_value=opener) as build:
            client = InvitationMailboxClient(origin="https://example.invalid")
            client.create(secret=self.secret, source_cap="source-only-capability", frame=b"opaque", expires_at=1300)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.invalid/v1/peer/invitation")
        self.assertEqual(request.get_method(), "POST")
        self.assertNotIn(self.secret.code(), request.data.decode())
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
        self.assertEqual(build.call_args.args[0]._context.minimum_version, ssl.TLSVersion.TLSv1_3)
        with self.assertRaises(InvitationError):
            _NoRedirect().redirect_request(None, None, 307, "redirect", None, "https://other.invalid")

    def test_mailbox_client_bounds_and_validates_entire_reply(self) -> None:
        client = InvitationMailboxClient(origin="https://example.invalid")
        reply = {"offer": base64.urlsafe_b64encode(b"opaque").decode(), "join": None,
                 "approve": None, "complete": None, "expires_at": 1300}
        with mock.patch.object(client, "_post", return_value=reply):
            self.assertEqual(client.read(secret=self.secret)["offer"], b"opaque")
        for bad in ({**reply, "expires_at": True}, {**reply, "offer": ""},
                    {**reply, "offer": "x" * 43701}, {**reply, "callback": "unexpected"}):
            with self.subTest(reply=bad.keys()), mock.patch.object(client, "_post", return_value=bad), self.assertRaises(InvitationError):
                client.read(secret=self.secret)

    def test_mailbox_writes_cannot_infer_source_authority_from_code(self) -> None:
        client = InvitationMailboxClient(origin="https://example.invalid")
        with self.assertRaises(InvitationError):
            client.put(secret=self.secret, stage="approve", frame=b"opaque")
        with self.assertRaises(InvitationError):
            client.put(secret=self.secret, stage="complete", frame=b"opaque")
        with mock.patch.object(client, "_post", return_value={"status": "stored"}) as post:
            client.put(secret=self.secret, stage="join", frame=b"opaque", claim_cap="target-claim")
        self.assertNotIn("source_cap", post.call_args.args[0])
        self.assertEqual(post.call_args.args[0]["claim_cap"], "target-claim")

    def test_mailbox_http_failure_never_echoes_request_or_response(self) -> None:
        client = InvitationMailboxClient(origin="https://example.invalid")
        opener = mock.Mock()
        opener.open.side_effect = OSError("private-capability-must-not-leak")
        with (mock.patch("secrets_kit.protocol.peer_invitation_mailbox.urllib.request.build_opener", return_value=opener),
              self.assertRaises(InvitationError) as caught):
            client._post({"capability": "private-capability-must-not-leak"})
        self.assertNotIn("private-capability", str(caught.exception))

    def test_private_state_resume_and_compare_and_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite"
            store = InvitationStateStore(path=path)
            other = InvitationStateStore(path=path)
            node = "node:8f841fde-3882-4cc6-9980-331d50821f12"
            record = {"version": 1, "session_id": self.secret.session_id, "role": "source",
                      "local_node_id": node, "expires_at": 1300, "code": self.secret.code(), "phase": "offered",
                      "service": "beta-test", "account": "external"}
            try:
                revision = store.save(session_id=self.secret.session_id, record=record, expected_revision=None, now=1000)
                self.assertEqual(revision, 1)
                self.assertEqual(other.read(session_id=self.secret.session_id, local_node_id=node), (1, record))
                updated = {**record, "phase": "approved"}
                self.assertEqual(other.save(session_id=self.secret.session_id, record=updated, expected_revision=1, now=1100), 2)
                with self.assertRaises(InvitationError):
                    store.save(session_id=self.secret.session_id, record=record, expected_revision=1, now=1100)
                self.assertEqual(store.read(session_id=self.secret.session_id, local_node_id=node), (2, updated))
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            finally:
                other.close()
                store.close()

    def test_state_cannot_switch_local_identity_scope_role_or_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = InvitationStateStore(path=Path(directory) / "state.sqlite")
            node = "node:8f841fde-3882-4cc6-9980-331d50821f12"
            wrong = "node:b33834c2-cbaf-462a-863b-7b98df6f0f4b"
            record = {"version": 1, "session_id": self.secret.session_id, "role": "source",
                      "local_node_id": node, "expires_at": 1300, "service": "beta-test", "account": "external",
                      "code": self.secret.code(), "frames": {"offer": "original-staged-frame"}}
            try:
                store.save(session_id=self.secret.session_id, record=record, expected_revision=None, now=1000)
                for key, value in (("local_node_id", wrong), ("role", "target"), ("expires_at", 1400), ("version", True),
                                   ("service", "other-service"), ("account", "other-account")):
                    with self.subTest(key=key), self.assertRaises(InvitationError):
                        store.save(session_id=self.secret.session_id, record={**record, key: value}, expected_revision=1, now=1100)
                for changes in ({"code": "replacement"}, {"frames": {}}, {"frames": {"offer": "replacement"}}):
                    with self.subTest(changes=changes.keys()), self.assertRaises(InvitationError):
                        store.save(session_id=self.secret.session_id, record={**record, **changes}, expected_revision=1, now=1100)
                with self.assertRaises(InvitationError):
                    store.read(session_id=self.secret.session_id, local_node_id=wrong)
                with self.assertRaises(InvitationError):
                    store.save(session_id=self.secret.session_id, record=record, expected_revision=1, now=1300)
            finally:
                store.close()

    def test_state_capacity_reclaimed_only_after_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = InvitationStateStore(path=Path(directory) / "state.sqlite", max_records=1)
            record = {"version": 1, "session_id": self.secret.session_id, "role": "source",
                      "local_node_id": "node:8f841fde-3882-4cc6-9980-331d50821f12", "expires_at": 1300,
                      "service": "beta-test", "account": "external"}
            other = InvitationSecret.create(issuer_public_key=self.public).session_id
            new = {**record, "session_id": other, "expires_at": 1600}
            try:
                store.save(session_id=self.secret.session_id, record=record, expected_revision=None, now=1000)
                with self.assertRaises(InvitationError):
                    store.save(session_id=other, record=new, expected_revision=None, now=1100)
                self.assertEqual(store.save(session_id=other, record=new, expected_revision=None, now=1300), 1)
            finally:
                store.close()

    def test_state_never_follows_symlink_or_changes_insecure_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            unrelated = Path(directory) / "unrelated"
            unrelated.write_text("untouched")
            link = Path(directory) / "state.sqlite"
            link.symlink_to(unrelated)
            with self.assertRaises(OSError):
                InvitationStateStore(path=link)
            self.assertEqual(unrelated.read_text(), "untouched")
            with self.assertRaises(InvitationError):
                InvitationStateStore(path=unrelated)
            self.assertEqual(unrelated.stat().st_mode & 0o777, 0o644)

    def test_runtime_signs_with_existing_key_and_closes_datastore(self) -> None:
        conn = mock.Mock()
        identity = SimpleNamespace(signing=SimpleNamespace(private_key=self.private, public_key=self.public))
        with (mock.patch("secrets_kit.runtime.peer_invitation.open_sqlite_backend", return_value=conn),
              mock.patch("secrets_kit.runtime.peer_invitation.load_sqlite_node_identity_material", return_value=identity),
              mock.patch("secrets_kit.protocol.peer_invitation.time.time", return_value=1000)):
            frame = sign_local_invitation(secret=self.secret, stage="offer", body={"synthetic": True}, expires_at=1300)
        conn.close.assert_called_once_with()
        body, signer, _ = open_invitation_message(secret=self.secret, stage="offer", data=frame, now=1100)
        self.assertEqual(body, {"synthetic": True})
        self.assertEqual(signer, self.public)

    def seal(self, stage: str = "offer", *, target: bool = False, expiry: int = 1300) -> bytes:
        return seal_invitation_message(
            secret=self.secret, stage=stage, body={"synthetic": "invitation-test"},
            signing_private_key=self.target_private if target else self.private,
            signing_public_key=self.target_public if target else self.public,
            now=1000, expires_at=expiry,
        )

    def test_code_roundtrip_key_domains_and_safe_representation(self) -> None:
        restored = InvitationSecret.from_code(self.secret.code())
        self.assertEqual(restored, self.secret)
        self.assertNotIn(self.secret.code(), repr(self.secret))
        self.assertNotIn(repr(self.secret.root_key), repr(self.secret))
        values = [self.secret.derive(purpose) for purpose in
                  ("session", "read", "join", "encrypt:offer", "encrypt:join", "encrypt:approve", "encrypt:complete")]
        self.assertEqual(len(set(values)), len(values))
        with self.assertRaises(InvitationError):
            self.secret.derive("source-write")

    def test_each_stage_roundtrips_with_explicit_signer_and_original_deadline(self) -> None:
        for stage in ("offer", "join", "approve", "complete"):
            with self.subTest(stage=stage):
                target = stage in {"join", "complete"}
                expected = self.target_public if target else self.public
                body, signer, expiry = open_invitation_message(
                    secret=self.secret, stage=stage, data=self.seal(stage, target=target),
                    expected_signer=expected, expected_expires_at=1300, now=1100,
                )
                self.assertEqual(body, {"synthetic": "invitation-test"})
                self.assertEqual(signer, expected)
                self.assertEqual(expiry, 1300)

    def test_ciphertext_uses_fresh_nonce_and_hides_body(self) -> None:
        first, second = self.seal(), self.seal()
        self.assertNotEqual(first, second)
        self.assertNotIn(b"invitation-test", first)
        self.assertNotIn(self.secret.code().encode(), first)

    def test_substituted_issuer_with_code_cannot_sign_offer_or_approval(self) -> None:
        for stage in ("offer", "approve"):
            with self.subTest(stage=stage), self.assertRaises(InvitationError):
                open_invitation_message(
                    secret=self.secret, stage=stage, data=self.seal(stage, target=True),
                    now=1100, expected_expires_at=1300,
                )

    def test_wrong_session_or_stage_cannot_open_ciphertext(self) -> None:
        other = InvitationSecret.create(issuer_public_key=self.public)
        for secret, stage in ((other, "offer"), (self.secret, "join")):
            with self.subTest(stage=stage), self.assertRaises(InvitationError):
                open_invitation_message(secret=secret, stage=stage, data=self.seal(), now=1100)

    def test_expiry_extension_and_missing_original_deadline_are_rejected(self) -> None:
        cases = (
            {"stage": "offer", "data": self.seal(), "now": 1300},
            {"stage": "join", "data": self.seal("join", target=True), "now": 1100},
            {"stage": "approve", "data": self.seal("approve", expiry=1400), "now": 1100, "expected_expires_at": 1300},
        )
        for kwargs in cases:
            with self.subTest(stage=kwargs["stage"]), self.assertRaises(InvitationError):
                open_invitation_message(secret=self.secret, **kwargs)

    def test_completion_requires_approved_target_and_matching_key(self) -> None:
        for key in (None, self.public):
            with self.subTest(key=key), self.assertRaises(InvitationError):
                open_invitation_message(secret=self.secret, stage="complete", data=self.seal("complete", target=True),
                                        now=1100, expected_expires_at=1300, expected_signer=key)

    def test_mismatched_signature_key_and_tampering_fail_closed(self) -> None:
        wrong = seal_invitation_message(
            secret=self.secret, stage="offer", body={}, signing_private_key=self.target_private,
            signing_public_key=self.public, expires_at=1300, now=1000,
        )
        for data in (wrong, self.seal()[:-1] + b"!", b"x" * 32769):
            with self.subTest(size=len(data)), self.assertRaises(InvitationError):
                open_invitation_message(secret=self.secret, stage="offer", data=data, now=1100)

    def test_bad_code_and_lifetime_do_not_expose_input(self) -> None:
        for code in ("private-malformed-code", self.secret.code() + "=", self.secret.code().replace("skp1", "skp2")):
            with self.subTest(size=len(code)), self.assertRaises(InvitationError) as failure:
                InvitationSecret.from_code(code)
            self.assertNotIn(code, str(failure.exception))
        for expiry in (1000, 1901, True):
            with self.subTest(expiry=expiry), self.assertRaises(InvitationError):
                self.seal(expiry=expiry)


class InvitationAdmissionTests(unittest.TestCase):
    """Real stores: exact scoped proofs, atomic failure and non-regranting replay."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.left = make_node(root=Path(self.directory.name), name="left")
        self.right = make_node(root=Path(self.directory.name), name="right")
        provision_node(node=self.left)
        provision_node(node=self.right)
        with node_environment(node=self.left):
            self.left_request = create_signed_peer_admission_request().payload
            self.left_id = local_peer_public_identity().node_id
        with node_environment(node=self.right):
            self.right_request = create_signed_peer_admission_request().payload
            self.right_id = local_peer_public_identity().node_id
        scope = (_service_group_id(service="beta-test", account="external"),)
        with node_environment(node=self.left):
            self.left_decision = create_signed_peer_admission_decision(
                proof_type=PEER_ADMISSION_ACCEPT, node_id=self.right_id,
                request_id=self.right_request["request_id"], service_group_ids=scope,
            ).payload
        with node_environment(node=self.right):
            self.right_decision = create_signed_peer_admission_decision(
                proof_type=PEER_ADMISSION_ACCEPT, node_id=self.left_id,
                request_id=self.left_request["request_id"], service_group_ids=scope,
            ).payload

    def apply_left(self, **changes) -> None:
        values = {"local_request": self.left_request, "remote_request": self.right_request,
                  "local_decision": self.left_decision, "remote_decision": self.right_decision,
                  "service": "beta-test", "account": "external"}
        with node_environment(node=self.left):
            apply_invitation_admission(**{**values, **changes})

    def count_left(self) -> int:
        with node_environment(node=self.left):
            conn = open_sqlite_backend()
            try:
                return conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
            finally:
                conn.close()

    def test_offer_join_and_interrupted_retry_do_not_grant_admission(self) -> None:
        mailbox = mock.Mock(spec=InvitationMailboxClient)
        mailbox.origin = "https://example.invalid"
        messages = {"offer": None, "join": None, "approve": None, "complete": None, "expires_at": None}
        def create(**kwargs):
            messages["offer"] = kwargs["frame"]
            messages["expires_at"] = kwargs["expires_at"]
        mailbox.create.side_effect = create
        mailbox.read.side_effect = lambda **_kwargs: dict(messages)
        with node_environment(node=self.left):
            left_state = InvitationStateStore()
            source = PeerInvitationFlow(state=left_state, mailbox=mailbox)
            session, code = source.invite(service="beta-test", account="external")
            before = messages["offer"]
            source.publish_offer(session_id=session)
            self.assertEqual(messages["offer"], before)
            self.assertIsNone(get_peer_admission(node_id=self.right_id))
            left_state.close()
        with node_environment(node=self.right):
            right_state = InvitationStateStore()
            target = PeerInvitationFlow(state=right_state, mailbox=mailbox)
            inspected = target.inspect_offer(code=code)
            self.assertEqual(inspected["request"]["node_id"], self.left_id)
            self.assertEqual((inspected["service"], inspected["account"]), ("beta-test", "external"))
            with self.assertRaises(InvitationError):
                target.join(code=code, confirmed=False)
            mailbox.put.side_effect = InvitationError("simulated interruption")
            with self.assertRaises(InvitationPending) as pending:
                target.join(code=code, confirmed=True)
            self.assertEqual(pending.exception.session_id, session)
            self.assertNotIn(code, str(pending.exception))
            revision, record = right_state.read(session_id=session, local_node_id=self.right_id)
            staged = record["frames"]["join"]
            self.assertEqual(record["phase"], "join_staged")
            self.assertIsNone(get_peer_admission(node_id=self.left_id))
            right_state.close()
            # Fresh invocation must reuse the persisted ciphertext and claim.
            reopened = InvitationStateStore()
            try:
                mailbox.put.side_effect = None
                target = PeerInvitationFlow(state=reopened, mailbox=mailbox)
                target.publish_join(session_id=session)
                retried = mailbox.put.call_args.kwargs
                self.assertEqual(base64.urlsafe_b64encode(retried["frame"]).decode().rstrip("="), staged)
                self.assertEqual(retried["claim_cap"], record["claim_cap"])
                self.assertGreater(reopened.read(session_id=session, local_node_id=self.right_id)[0], revision)
                self.assertIsNone(get_peer_admission(node_id=self.left_id))
            finally:
                reopened.close()

    def test_complete_flow_requires_both_consents_and_resumes_interrupted_approval(self) -> None:
        def status():
            return {"identity": {"peer_id": local_peer_public_identity().node_id},
                    "local_endpoint": {"multiaddr": "/ip4/10.1.1.2/tcp/41001/p2p/transport-test"}}
        status_patch = mock.patch("secrets_kit.daemon.client.request_daemon_status", side_effect=status)
        status_patch.start()
        self.addCleanup(status_patch.stop)
        def submit(**kwargs):
            self.assertEqual(get_peer_admission(node_id=kwargs["peer_id"]).state, "active")
        candidate_patch = mock.patch("secrets_kit.runtime.peer_invitation.submit_direct_candidate", side_effect=submit)
        handoff = candidate_patch.start()
        self.addCleanup(candidate_patch.stop)
        mailbox = mock.Mock(spec=InvitationMailboxClient)
        mailbox.origin = "https://example.invalid"
        messages = {"offer": None, "join": None, "approve": None, "complete": None, "expires_at": None}
        def create(**kwargs):
            messages["offer"], messages["expires_at"] = kwargs["frame"], kwargs["expires_at"]
        def put(**kwargs):
            stage = kwargs["stage"]
            if messages[stage] is not None and messages[stage] != kwargs["frame"]:
                raise InvitationError("immutable phase changed")
            messages[stage] = kwargs["frame"]
        mailbox.create.side_effect = create
        mailbox.read.side_effect = lambda **_kwargs: dict(messages)
        mailbox.put.side_effect = put
        with node_environment(node=self.left):
            left_state = InvitationStateStore()
            self.addCleanup(left_state.close)
            source = PeerInvitationFlow(state=left_state, mailbox=mailbox)
            session, code = source.invite(service="beta-test", account="external")
        with node_environment(node=self.right):
            right_state = InvitationStateStore()
            self.addCleanup(right_state.close)
            target = PeerInvitationFlow(state=right_state, mailbox=mailbox)
            self.assertEqual(target.join(code=code, confirmed=True), session)
            with self.assertRaises(InvitationError):
                target.complete(session_id=session)
            self.assertIsNone(get_peer_admission(node_id=self.left_id))
        with node_environment(node=self.left):
            self.assertEqual(source.inspect_join(session_id=session)["request"]["node_id"], self.right_id)
            with self.assertRaises(InvitationError):
                source.approve(session_id=session, confirmed=False)
            self.assertIsNone(get_peer_admission(node_id=self.right_id))
            mailbox.put.side_effect = InvitationError("simulated interrupted approval delivery")
            with self.assertRaises(InvitationError):
                source.approve(session_id=session, confirmed=True)
            _, staged = left_state.read(session_id=session, local_node_id=self.left_id)
            self.assertEqual(staged["phase"], "approval_staged")
            mailbox.put.side_effect = put
            source.approve(session_id=session, confirmed=False)  # durable prior consent
            self.assertFalse(source.confirm_completion(session_id=session))
            self.assertEqual(base64.urlsafe_b64encode(messages["approve"]).decode().rstrip("="), staged["frames"]["approve"])
            self.assertEqual(get_peer_admission(node_id=self.right_id).state, "active")
            mailbox.origin = "https://different.invalid"
            with self.assertRaises(InvitationError):
                source.approve(session_id=session, confirmed=False)
            mailbox.origin = "https://example.invalid"
        with node_environment(node=self.right):
            target.complete(session_id=session)
            target.complete(session_id=session)
            self.assertEqual(get_peer_admission(node_id=self.left_id).state, "active")
            _, completed = right_state.read(session_id=session, local_node_id=self.right_id)
            self.assertEqual(completed["phase"], "complete")
            secret = InvitationSecret.from_code(code)
            _, signer, _ = open_invitation_message(secret=secret, stage="complete", data=messages["complete"],
                                                  expected_signer=base64.urlsafe_b64decode(self.right_request["signing_public_key"] + "="),
                                                  expected_expires_at=completed["expires_at"])
            self.assertEqual(signer, base64.urlsafe_b64decode(self.right_request["signing_public_key"] + "="))
            wrong_decision = sign_local_invitation(
                secret=secret, stage="complete", body={"node_id": self.right_id, "decision_id": "wrong"},
                expires_at=completed["expires_at"],
            )
        with node_environment(node=self.left):
            saved = messages["complete"]
            messages["complete"] = wrong_decision
            with self.assertRaises(InvitationError):
                source.confirm_completion(session_id=session)
            self.assertEqual(left_state.read(session_id=session, local_node_id=self.left_id)[1]["phase"], "approved")
            messages["complete"] = sign_local_invitation(
                secret=secret, stage="complete", body={"node_id": self.right_id, "decision_id": "wrong"},
                expires_at=completed["expires_at"],
            )
            with self.assertRaises(InvitationError):
                source.confirm_completion(session_id=session)
            messages["complete"] = saved
            self.assertTrue(source.confirm_completion(session_id=session))
            self.assertTrue(source.confirm_completion(session_id=session))
            source.approve(session_id=session, confirmed=False)
            self.assertEqual(left_state.read(session_id=session, local_node_id=self.left_id)[1]["phase"], "complete")
        self.assertEqual({call.kwargs["peer_id"] for call in handoff.call_args_list}, {self.left_id, self.right_id})

    def test_invitation_dial_candidate_must_name_the_signed_node(self) -> None:
        candidate = {"peer_id": self.right_id, "endpoint": "/ip4/10.1.1.2/tcp/41001/p2p/transport-test"}
        with self.assertRaises(InvitationError):
            _validate_candidate(value=candidate, node_id=self.left_id)
        with self.assertRaises(InvitationError):
            _validate_candidate(value={**candidate, "endpoint": candidate["endpoint"] + "/p2p/duplicate"}, node_id=self.right_id)
        with mock.patch("secrets_kit.daemon.client.request_daemon_status", return_value={
            "identity": {"peer_id": self.right_id}, "local_endpoint": {"multiaddr": candidate["endpoint"]},
        }):
            self.assertIsNone(_local_candidate(node_id=self.left_id))

    def test_local_candidate_daemon_boundary_preserves_fail_closed_validation(self) -> None:
        from secrets_kit.daemon.client import DaemonError

        endpoint = "/ip4/10.1.1.2/tcp/41001/p2p/transport-test"
        for status in ({}, {"identity": []}, {"identity": {"peer_id": self.left_id}, "local_endpoint": []},
                       {"identity": {"peer_id": self.left_id}, "local_endpoint": {"multiaddr": "invalid"}}):
            with self.subTest(status=status), mock.patch("secrets_kit.daemon.client.request_daemon_status", return_value=status):
                self.assertIsNone(_local_candidate(node_id=self.left_id))
        with mock.patch("secrets_kit.daemon.client.request_daemon_status", side_effect=DaemonError("unavailable")):
            self.assertIsNone(_local_candidate(node_id=self.left_id))
        with mock.patch("secrets_kit.daemon.client.request_daemon_status", return_value={
            "identity": {"peer_id": self.left_id}, "local_endpoint": {"multiaddr": endpoint},
        }):
            self.assertEqual(_local_candidate(node_id=self.left_id), {"peer_id": self.left_id, "endpoint": endpoint})

    def test_interrupted_offer_reports_resumable_id_without_private_code(self) -> None:
        mailbox = mock.Mock(spec=InvitationMailboxClient)
        mailbox.origin = "https://example.invalid"
        mailbox.create.side_effect = InvitationError("delivery interrupted")
        with node_environment(node=self.left):
            state = InvitationStateStore()
            self.addCleanup(state.close)
            flow = PeerInvitationFlow(state=state, mailbox=mailbox)
            with self.assertRaises(InvitationPending) as pending:
                flow.invite(service="beta-test", account="external")
            session = pending.exception.session_id
            _, record = state.read(session_id=session, local_node_id=self.left_id)
            self.assertNotIn(record["code"], str(pending.exception))
            self.assertEqual(record["phase"], "created")
            first = mailbox.create.call_args.kwargs
            mailbox.create.side_effect = None
            flow.publish_offer(session_id=session)
            second = mailbox.create.call_args.kwargs
            self.assertEqual(first["frame"], second["frame"])
            self.assertEqual(first["source_cap"], second["source_cap"])
            self.assertEqual(first["expires_at"], second["expires_at"])
            self.assertIsNone(get_peer_admission(node_id=self.right_id))

    def test_mutual_scoped_admission_applies_and_retry_never_duplicates_history(self) -> None:
        self.apply_left()
        count = self.count_left()
        self.apply_left()
        self.assertEqual(self.count_left(), count)
        with node_environment(node=self.left):
            peer = get_peer_admission(node_id=self.right_id)
            self.assertEqual(peer.state, "active")
            self.assertEqual(peer.authorization_mode, "allow_list")
            self.assertEqual(peer.service_group_ids, (_service_group_id(service="beta-test", account="external"),))
        with node_environment(node=self.right):
            apply_invitation_admission(local_request=self.right_request, remote_request=self.left_request,
                                       local_decision=self.right_decision, remote_decision=self.left_decision,
                                       service="beta-test", account="external")
            self.assertEqual(get_peer_admission(node_id=self.left_id).state, "active")

    def test_rss_invitation_binds_prepared_target_and_resumes_after_capacity_denial(self) -> None:
        mailbox = mock.Mock(spec=InvitationMailboxClient)
        mailbox.origin = "https://example.invalid"
        messages = {"offer": None, "join": None, "approve": None, "complete": None, "expires_at": None}
        def create(**kwargs):
            messages["offer"], messages["expires_at"] = kwargs["frame"], kwargs["expires_at"]
        def put(**kwargs):
            messages[kwargs["stage"]] = kwargs["frame"]
        mailbox.create.side_effect = create
        mailbox.put.side_effect = put
        mailbox.read.side_effect = lambda **_kwargs: dict(messages)
        with node_environment(node=self.left):
            left_state = InvitationStateStore()
            self.addCleanup(left_state.close)
            source = PeerInvitationFlow(state=left_state, mailbox=mailbox)
            session, code = source.invite(service="beta-test", account="external", include_rss=True)
        with node_environment(node=self.right):
            right_state = InvitationStateStore()
            self.addCleanup(right_state.close)
            target = PeerInvitationFlow(state=right_state, mailbox=mailbox)
            target.join(code=code, confirmed=True)
            record = right_state.read(session_id=session, local_node_id=self.right_id)[1]
            identity = record["rss_identity"]
            self.assertIsNone(load_rss_relay_credentials_from_environment())
        def token(expires_at):
            claims = {"protocol": "rss_enrollment_token/v1", "expires_at": expires_at}
            return "ret1." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".synthetic-signature"
        started = int(time.time())
        bundle = {"protocol": "rss_provisioning_bundle/v1", "entitlement_id": "ent_test",
                  "rss_enrollment_token": token(started + 900), "enrollment_url": mailbox.origin,
                  "relay_peers": ["/dns4/east.example.test/tcp/14001/p2p/east", "/dns4/west.example.test/tcp/14001/p2p/west"]}
        with node_environment(node=self.left), mock.patch("secrets_kit.runtime.peer_invitation.admin_action") as action:
            with self.assertRaises(InvitationError):
                source.approve(session_id=session, confirmed=False)
            action.assert_not_called()
            action.return_value = (409, {"reason": "device_capacity_exhausted",
                                        "capacity": {"purchased_units": 2, "provisioned_units": 2, "available_units": 0}})
            with self.assertRaises(InvitationCapacityPending):
                source.approve(session_id=session, confirmed=True)
            self.assertIsNone(get_peer_admission(node_id=self.right_id))
            self.assertNotIn("approve", left_state.read(session_id=session, local_node_id=self.left_id)[1]["frames"])
            action.return_value = (200, bundle)
            source.approve(session_id=session, confirmed=True)
            action.assert_called_with(action="device.ret", parameters={"target_connection_id": identity["connection_id"],
                                      "target_public_key": identity["public_key"]}, expected_operator_url=mailbox.origin)
            action.reset_mock()
            source.approve(session_id=session, confirmed=False)
            action.assert_not_called()
            self.assertNotIn(bundle["rss_enrollment_token"].encode(), messages["approve"])
        with node_environment(node=self.right):
            with mock.patch("secrets_kit.runtime.peer_invitation.rss_enrollment_token_expired", return_value=True):
                with self.assertRaisesRegex(InvitationError, "fresh invitation"):
                    target.complete(session_id=session)
            self.assertIsNone(get_peer_admission(node_id=self.left_id))
            target.complete(session_id=session)
            first = load_rss_relay_credentials_from_environment()
            target.complete(session_id=session)
            second = load_rss_relay_credentials_from_environment()
            self.assertEqual(first, second)
            self.assertEqual(first.connection_id, identity["connection_id"])
            self.assertEqual(base64.urlsafe_b64encode(first.customer_public_key).decode().rstrip("="), identity["public_key"])
            self.assertEqual(first.entitlement_id, "ent_test")
            self.assertEqual(get_peer_admission(node_id=self.left_id).state, "active")
        # A fresh, separately approved invitation renews an expired pending RET
        # without extending the old invitation or changing peer authorization.
        count = self.count_left()
        with mock.patch("time.time", return_value=started + 901):
            with node_environment(node=self.left):
                repair_session, repair_code = source.invite(service="beta-test", account="external", include_rss=True)
            with node_environment(node=self.right):
                target.join(code=repair_code, confirmed=True)
                repair = right_state.read(session_id=repair_session, local_node_id=self.right_id)[1]
                self.assertEqual(repair["rss_identity"], identity)
                conn = open_sqlite_backend()
                try:
                    target_count = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
                finally:
                    conn.close()
            with node_environment(node=self.left), mock.patch("secrets_kit.runtime.peer_invitation.admin_action", return_value=(200, {**bundle, "rss_enrollment_token": token(started + 1801)})):
                with self.assertRaises(InvitationError):
                    source.approve(session_id=repair_session, confirmed=False)
                source.approve(session_id=repair_session, confirmed=True)
            self.assertEqual(self.count_left(), count)
            with node_environment(node=self.right):
                target.complete(session_id=repair_session)
                renewed = load_rss_relay_credentials_from_environment()
                self.assertEqual(renewed.connection_id, first.connection_id)
                self.assertEqual(renewed.customer_private_key, first.customer_private_key)
                self.assertNotEqual(renewed.enrollment_token, first.enrollment_token)
                conn = open_sqlite_backend()
                try:
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0], target_count)
                finally:
                    conn.close()
            with node_environment(node=self.left):
                self.assertTrue(source.confirm_completion(session_id=repair_session))

    def test_tampered_signature_rolls_back_all_staged_requests_and_decisions(self) -> None:
        baseline = self.count_left()
        invalid = {**self.right_decision, "signature": "A" * 86}
        with self.assertRaises(ValueError):
            self.apply_left(remote_decision=invalid)
        self.assertEqual(self.count_left(), baseline)
        with node_environment(node=self.left):
            self.assertIsNone(get_peer_admission(node_id=self.right_id))

    def test_scope_and_identity_substitution_never_apply(self) -> None:
        baseline = self.count_left()
        for changes in ({"service": "different"}, {"account": "different"},
                        {"remote_decision": {**self.right_decision, "authorization_mode": "all"}},
                        {"remote_request": self.left_request}):
            with self.subTest(changes=changes.keys()), self.assertRaises(ValueError):
                self.apply_left(**changes)
        self.assertEqual(self.count_left(), baseline)

    def test_new_invitation_cannot_replace_an_existing_active_scope(self) -> None:
        self.apply_left()
        count = self.count_left()
        with node_environment(node=self.right):
            new_request = create_signed_peer_admission_request().payload
        with node_environment(node=self.left):
            new_decision = create_signed_peer_admission_decision(
                proof_type=PEER_ADMISSION_ACCEPT, node_id=self.right_id,
                request_id=new_request["request_id"],
                service_group_ids=(_service_group_id(service="beta-test", account="external"),),
            ).payload
        with self.assertRaises(InvitationError):
            self.apply_left(remote_request=new_request, local_decision=new_decision)
        self.assertEqual(self.count_left(), count)
        with node_environment(node=self.left):
            self.assertEqual(get_peer_admission(node_id=self.right_id).state, "active")

    def test_rss_repair_verifies_fresh_consent_without_reprojecting_history(self) -> None:
        self.apply_left()
        count = self.count_left()
        with node_environment(node=self.right):
            fresh = create_signed_peer_admission_request().payload
        with node_environment(node=self.left):
            decision = create_signed_peer_admission_decision(
                proof_type=PEER_ADMISSION_ACCEPT, node_id=self.right_id,
                request_id=fresh["request_id"],
                service_group_ids=(_service_group_id(service="beta-test", account="external"),),
            ).payload
        self.apply_left(remote_request=fresh, local_decision=decision, allow_existing_admission=True)
        self.assertEqual(self.count_left(), count)
        with self.assertRaises(InvitationError):
            self.apply_left(remote_request=fresh, local_decision={**decision, "signature": "A" * 86}, allow_existing_admission=True)
        with node_environment(node=self.left):
            conn = open_sqlite_backend()
            try:
                with conn:
                    conn.execute("UPDATE nodes SET state='rejected',authorization_mode='none' WHERE node_id=?", (self.right_id,))
            finally:
                conn.close()
        with self.assertRaisesRegex(InvitationError, "retained peer"):
            self.apply_left(remote_request=fresh, local_decision=decision, allow_existing_admission=True)
        self.assertEqual(self.count_left(), count)

    def test_rss_repair_cannot_expand_scope_or_replace_retained_keys(self) -> None:
        self.apply_left()
        count = self.count_left()
        scope = (_service_group_id(service="different", account="external"),)
        with node_environment(node=self.left):
            left_decision = create_signed_peer_admission_decision(
                proof_type=PEER_ADMISSION_ACCEPT, node_id=self.right_id,
                request_id=self.right_request["request_id"], service_group_ids=scope,
            ).payload
        with node_environment(node=self.right):
            right_decision = create_signed_peer_admission_decision(
                proof_type=PEER_ADMISSION_ACCEPT, node_id=self.left_id,
                request_id=self.left_request["request_id"], service_group_ids=scope,
            ).payload
        with self.assertRaisesRegex(InvitationError, "retained peer"):
            self.apply_left(service="different", local_decision=left_decision,
                            remote_decision=right_decision, allow_existing_admission=True)
        with node_environment(node=self.left):
            conn = open_sqlite_backend()
            try:
                with conn:
                    conn.execute("UPDATE nodes SET signing_public_key=? WHERE node_id=?",
                                 (base64.urlsafe_b64decode(self.left_request["signing_public_key"] + "="), self.right_id))
            finally:
                conn.close()
        with self.assertRaisesRegex(InvitationError, "retained peer"):
            self.apply_left(allow_existing_admission=True)
        self.assertEqual(self.count_left(), count)

    def test_retry_does_not_reapply_projection_after_rejected_state_fault_injection(self) -> None:
        self.apply_left()
        with node_environment(node=self.left):
            conn = open_sqlite_backend()
            try:
                # Projection fault injection in disposable stores, not a
                # claim that the pending-request rejection API revokes peers.
                with conn:
                    conn.execute("UPDATE nodes SET state='rejected',authorization_mode='none' WHERE node_id=?", (self.right_id,))
            finally:
                conn.close()
            before = get_peer_admission(node_id=self.right_id).state
        self.assertNotEqual(before, "active")
        self.apply_left()
        with node_environment(node=self.left):
            self.assertEqual(get_peer_admission(node_id=self.right_id).state, before)


if __name__ == "__main__":
    unittest.main()
