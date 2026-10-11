"""CLI-only safety tests for the terminal peer-invitation surface."""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from secrets_kit.cli import build_parser
from secrets_kit.cli.commands.peer_invitation import (
    cmd_peer_approve_invitation,
    cmd_peer_invite,
    cmd_peer_join_invitation,
)
from secrets_kit.protocol.peer_invitation import InvitationError
from secrets_kit.runtime.peer_invitation import InvitationCapacityPending


class _TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class CliPeerInvitationTest(unittest.TestCase):
    def test_parser_has_no_code_argument_or_yes_bypass(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["peer", "invite", "--service", "svc", "--account", "acct"]).func, cmd_peer_invite)
        self.assertEqual(parser.parse_args(["peer", "join", "--resume", "session"]).func, cmd_peer_join_invitation)
        self.assertEqual(parser.parse_args(["peer", "approve", "session"]).func, cmd_peer_approve_invitation)
        resumed = parser.parse_args(["peer", "invite", "--resume", "session"])
        self.assertIsNone(resumed.service)
        self.assertIsNone(resumed.account)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["peer", "join", "skp1-secret"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["peer", "approve", "session", "--yes"])

    def test_new_invite_requires_scope_before_opening_state(self) -> None:
        args = argparse.Namespace(backend="sqlite", service=None, account=None, rss=False, resume=None)
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow") as flow, redirect_stderr(io.StringIO()):
            self.assertEqual(cmd_peer_invite(args=args), 1)
        flow.assert_not_called()

    def test_invalid_origin_does_not_open_state(self) -> None:
        from secrets_kit.cli.commands.peer_invitation import _flow

        with mock.patch("secrets_kit.cli.commands.peer_invitation._installed_operator_url", side_effect=ValueError), mock.patch("secrets_kit.cli.commands.peer_invitation.InvitationStateStore") as state:
            with self.assertRaises(ValueError):
                _flow()
        state.assert_not_called()

    def test_invite_refuses_non_terminal_before_creating_code(self) -> None:
        args = argparse.Namespace(backend="sqlite", service="svc", account="acct", rss=False, resume=None)
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow") as flow, redirect_stderr(io.StringIO()):
            self.assertEqual(cmd_peer_invite(args=args), 1)
        flow.assert_not_called()

    def test_join_refuses_code_from_non_tty_stdin(self) -> None:
        args = argparse.Namespace(backend="sqlite", resume=None)
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow") as flow, redirect_stderr(io.StringIO()):
            self.assertEqual(cmd_peer_join_invitation(args=args), 1)
        flow.assert_not_called()

    def test_join_denial_does_not_call_join(self) -> None:
        args = argparse.Namespace(backend="sqlite", resume=None)
        state = mock.Mock()
        flow = mock.Mock()
        flow.inspect_offer.return_value = {
            "request": {"node_id": "node_x", "signing_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "encryption_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "service": "svc", "account": "acct", "include_rss": False,
        }
        stdin = mock.Mock(isatty=mock.Mock(return_value=True))
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.sys.stdin", stdin), mock.patch("secrets_kit.cli.commands.peer_invitation.getpass.getpass", return_value="skp1-code"), mock.patch("secrets_kit.cli.commands.peer_invitation.input", return_value="n"), redirect_stderr(io.StringIO()):
            self.assertEqual(cmd_peer_join_invitation(args=args), 1)
        flow.join.assert_not_called()
        state.close.assert_called_once()

    def test_approve_partial_delivery_reports_only_session_id(self) -> None:
        args = argparse.Namespace(backend="sqlite", invitation_id="session-safe")
        state = mock.Mock()
        state.read.return_value = (1, {"role": "source", "include_rss": False, "phase": "created"})
        flow = mock.Mock()
        flow.inspect_join.return_value = {
            "request": {"node_id": "node_x", "signing_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "encryption_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "service": "svc", "account": "acct", "rss_identity": None,
        }
        flow.approve.side_effect = InvitationError("private mailbox detail")
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.local_peer_public_identity"), mock.patch("secrets_kit.cli.commands.peer_invitation.input", return_value="y"), redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(cmd_peer_approve_invitation(args=args), 1)
        self.assertIn("session-safe", errors.getvalue())
        self.assertNotIn("private mailbox detail", errors.getvalue())
        self.assertNotIn("skp1", output.getvalue())

    def test_safe_unexpected_invitation_error_never_claims_route_health(self) -> None:
        args = argparse.Namespace(backend="sqlite", resume=None)
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", side_effect=InvitationError("secret transport trace")), redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(cmd_peer_join_invitation(args=args), 1)
        self.assertNotIn("secret transport trace", errors.getvalue())
        self.assertNotIn("route healthy", output.getvalue().lower())

    def test_fresh_invite_prints_code_once_to_tty_after_publish(self) -> None:
        args = argparse.Namespace(backend="sqlite", service="svc", account="acct", rss=False, resume=None)
        state, flow = mock.Mock(), mock.Mock()
        flow.invite.return_value = ("session-new", "skp1-private-handoff")
        output = _TtyBuffer()
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.sys.stdout", output):
            self.assertEqual(cmd_peer_invite(args=args), 0)
        flow.invite.assert_called_once_with(service="svc", account="acct", include_rss=False)
        self.assertEqual(output.getvalue().count("skp1-private-handoff"), 1)
        state.close.assert_called_once()

    def test_target_resume_completes_with_rss_reload(self) -> None:
        args = argparse.Namespace(backend="sqlite", resume="session-target")
        state, flow = mock.Mock(), mock.Mock()
        state.read.return_value = (1, {"role": "target", "include_rss": True})
        output = io.StringIO()
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.local_peer_public_identity"), mock.patch("secrets_kit.cli.commands.peer_invitation.install_service") as install, redirect_stdout(output):
            self.assertEqual(cmd_peer_join_invitation(args=args), 0)
        flow.publish_join.assert_called_once_with(session_id="session-target")
        flow.complete.assert_called_once_with(session_id="session-target")
        install.assert_called_once_with(reload_runtime=True)
        self.assertIn("Scoped peer admission is complete.", output.getvalue())
        self.assertIn("RSS configuration is installed", output.getvalue())
        self.assertIn("have not been verified", output.getvalue())

    def test_target_rss_reload_failure_never_claims_route_health(self) -> None:
        args = argparse.Namespace(backend="sqlite", resume="session-target")
        state, flow = mock.Mock(), mock.Mock()
        state.read.return_value = (1, {"role": "target", "include_rss": True})
        output, errors = io.StringIO(), io.StringIO()
        from secrets_kit.daemon.service import DaemonServiceError

        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.local_peer_public_identity"), mock.patch("secrets_kit.cli.commands.peer_invitation.install_service", side_effect=DaemonServiceError("private failure")), redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(cmd_peer_join_invitation(args=args), 1)
        self.assertIn("Scoped peer admission is complete.", output.getvalue())
        self.assertNotIn("route healthy", output.getvalue().lower())
        self.assertNotIn("private failure", errors.getvalue())

    def test_source_capacity_pending_has_no_success_claim(self) -> None:
        args = argparse.Namespace(backend="sqlite", invitation_id="session-capacity")
        state, flow = mock.Mock(), mock.Mock()
        state.read.return_value = (1, {"role": "source", "include_rss": True, "phase": "created"})
        flow.inspect_join.return_value = {
            "request": {"node_id": "node_x", "signing_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "encryption_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "service": "svc", "account": "acct", "rss_identity": {"connection_id": "rss-target", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        }
        flow.approve.side_effect = InvitationCapacityPending(capacity={"purchased_units": 2, "provisioned_units": 2, "available_units": 0})
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.local_peer_public_identity"), mock.patch("secrets_kit.cli.commands.peer_invitation.input", return_value="y"), redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(cmd_peer_approve_invitation(args=args), 1)
        self.assertIn("purchased=2, provisioned=2, available=0", errors.getvalue())
        self.assertNotIn("Scoped peer admission is complete.", output.getvalue())
        flow.confirm_completion.assert_not_called()

    def test_retained_source_consent_resumes_without_prompt(self) -> None:
        args = argparse.Namespace(backend="sqlite", invitation_id="session-approved")
        state, flow = mock.Mock(), mock.Mock()
        state.read.return_value = (1, {"role": "source", "include_rss": False, "phase": "approval_staged"})
        flow.inspect_join.return_value = {
            "request": {"node_id": "node_x", "signing_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "encryption_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "service": "svc", "account": "acct", "rss_identity": None,
        }
        flow.confirm_completion.return_value = False
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.local_peer_public_identity"), mock.patch("secrets_kit.cli.commands.peer_invitation.input") as prompt, redirect_stdout(io.StringIO()):
            self.assertEqual(cmd_peer_approve_invitation(args=args), 0)
        prompt.assert_not_called()
        flow.approve.assert_called_once_with(session_id="session-approved", confirmed=True)

    def test_target_resume_successfully_completes_without_rss_reload(self) -> None:
        args = argparse.Namespace(backend="sqlite", resume="session-target")
        state, flow = mock.Mock(), mock.Mock()
        state.read.return_value = (1, {"role": "target", "include_rss": False})
        with mock.patch("secrets_kit.cli.commands.peer_invitation._flow", return_value=(state, flow)), mock.patch("secrets_kit.cli.commands.peer_invitation.local_peer_public_identity"), mock.patch("secrets_kit.cli.commands.peer_invitation.install_service") as install, redirect_stdout(io.StringIO()):
            self.assertEqual(cmd_peer_join_invitation(args=args), 0)
        flow.publish_join.assert_called_once_with(session_id="session-target")
        flow.complete.assert_called_once_with(session_id="session-target")
        install.assert_not_called()
