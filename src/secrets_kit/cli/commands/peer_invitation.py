"""Terminal-only customer workflow for resumable encrypted peer invitations.

This module intentionally receives handoff codes only from a protected terminal
prompt and exposes them only once after a source offer is durably published.
It does not diagnose routes or relay authentication: those are separate facts.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import sys
import time
from typing import Any

from secrets_kit.backends.common import BACKEND_SQLITE
from secrets_kit.backends.sqlite.peer_admission import local_peer_public_identity
from secrets_kit.cli.commands.rss import _installed_operator_url
from secrets_kit.cli.io import _fatal
from secrets_kit.crypto.codecs import decode_b64url
from secrets_kit.daemon.service import DaemonServiceError, install_service
from secrets_kit.locale import msg
from secrets_kit.protocol.peer_invitation import InvitationError
from secrets_kit.protocol.peer_invitation_mailbox import InvitationMailboxClient
from secrets_kit.runtime.peer_invitation import (
    InvitationCapacityPending,
    InvitationPending,
    PeerInvitationFlow,
)
from secrets_kit.runtime.peer_invitation_state import InvitationStateStore


def _flow() -> tuple[InvitationStateStore, PeerInvitationFlow]:
    """Open this user's owner-private state at the verified installed origin."""
    mailbox = InvitationMailboxClient(origin=_installed_operator_url())
    state = InvitationStateStore()
    return state, PeerInvitationFlow(
        state=state, mailbox=mailbox
    )


def _fingerprint(value: str) -> str:
    """Render a SHA-256 key fingerprint without printing the key itself."""
    return hashlib.sha256(decode_b64url(value)).hexdigest()


def _display_identity(*, request: dict[str, Any], service: str, account: str, include_rss: bool, label: str) -> None:
    print(msg("cli.peer.invitation_identity", label=label, node_id=request["node_id"]))
    print(msg("cli.peer.invitation_signing", fingerprint=_fingerprint(request["signing_public_key"])))
    print(msg("cli.peer.invitation_encryption", fingerprint=_fingerprint(request["encryption_public_key"])))
    print(msg("cli.peer.invitation_scope", service=service, account=account))
    print(msg("cli.peer.invitation_rss", value=msg("cli.peer.invitation_rss_yes") if include_rss else msg("cli.peer.invitation_rss_no")))


def _confirm() -> bool:
    try:
        return input(msg("cli.peer.invitation_confirm_prompt")).strip().lower() in {"y", "yes"}
    except (EOFError, KeyboardInterrupt):
        return False


def _safe_failure() -> int:
    return _fatal(message=msg("cli.peer.invitation_error"), code=1)


def _pending(*, session_id: str) -> int:
    return _fatal(message=msg("cli.peer.invitation_pending", session_id=session_id), code=1)


def _source_record(*, state: InvitationStateStore, session_id: str, origin: str) -> dict[str, Any]:
    """Read only a locally bound source record before a source retry."""
    _, record = state.read(session_id=session_id, local_node_id=local_peer_public_identity().node_id)
    if record.get("role") != "source" or record.get("operator_url") != origin or record.get("expires_at", 0) <= int(time.time()):
        raise InvitationError("invitation resume is invalid")
    return record


def cmd_peer_invite(*, args: argparse.Namespace) -> int:
    """Create or resume a source offer; print its code only to an interactive terminal."""
    if getattr(args, "backend", BACKEND_SQLITE) != BACKEND_SQLITE:
        return _safe_failure()
    if not getattr(args, "resume", None) and (not getattr(args, "service", None) or not getattr(args, "account", None)):
        return _fatal(message=msg("cli.peer.scope_invalid"), code=1)
    if not sys.stdout.isatty():
        return _fatal(message=msg("cli.peer.invitation_terminal_required"), code=1)
    state: InvitationStateStore | None = None
    try:
        state, flow = _flow()
        session_id = getattr(args, "resume", None)
        if session_id:
            record = _source_record(state=state, session_id=session_id, origin=flow.mailbox.origin)
            flow.publish_offer(session_id=session_id)
            code = record["code"]
        else:
            session_id, code = flow.invite(service=args.service, account=args.account, include_rss=bool(args.rss))
        print(msg("cli.peer.invitation_created", session_id=session_id))
        print(code)
        return 0
    except InvitationPending as exc:
        return _pending(session_id=exc.session_id)
    except (KeyboardInterrupt, EOFError):
        return _fatal(message=msg("cli.peer.invitation_cancelled"), code=1)
    except (InvitationError, OSError, ValueError):
        return _safe_failure()
    finally:
        if state is not None:
            state.close()


def _read_code() -> str:
    if not sys.stdin.isatty():
        raise InvitationError("protected invitation entry requires a terminal")
    try:
        code = getpass.getpass(msg("cli.peer.invitation_code_prompt"))
    except (EOFError, KeyboardInterrupt):
        raise InvitationError("invitation entry cancelled") from None
    if not code.strip():
        raise InvitationError("invitation code is empty")
    return code.strip()


def _completion_report(*, include_rss: bool) -> int:
    print(msg("cli.peer.invitation_admitted"))
    if include_rss:
        try:
            install_service(reload_runtime=True)
        except (DaemonServiceError, OSError):
            return _fatal(message=msg("cli.peer.invitation_rss_reload_pending"), code=1)
        print(msg("cli.peer.invitation_rss_configured"))
    print(msg("cli.peer.invitation_route_unverified"))
    return 0


def cmd_peer_join_invitation(*, args: argparse.Namespace) -> int:
    """Confirm an inviter's identity, then create or finish a target join."""
    if getattr(args, "backend", BACKEND_SQLITE) != BACKEND_SQLITE:
        return _safe_failure()
    if not getattr(args, "resume", None) and not sys.stdin.isatty():
        return _safe_failure()
    state: InvitationStateStore | None = None
    try:
        state, flow = _flow()
        session_id = getattr(args, "resume", None)
        if session_id:
            _, record = state.read(session_id=session_id, local_node_id=local_peer_public_identity().node_id)
            if record.get("role") != "target":
                raise InvitationError("invitation resume is invalid")
            flow.publish_join(session_id=session_id)
            try:
                flow.complete(session_id=session_id)
            except InvitationError:
                return _pending(session_id=session_id)
            return _completion_report(include_rss=bool(record.get("include_rss")))
        code = _read_code()
        offer = flow.inspect_offer(code=code)
        _display_identity(request=offer["request"], service=offer["service"], account=offer["account"], include_rss=offer["include_rss"], label=msg("cli.peer.invitation_inviter"))
        if not _confirm():
            return _fatal(message=msg("cli.peer.invitation_cancelled"), code=1)
        session_id = flow.join(code=code, confirmed=True)
        try:
            flow.complete(session_id=session_id)
        except InvitationError:
            return _pending(session_id=session_id)
        return _completion_report(include_rss=bool(offer["include_rss"]))
    except InvitationPending as exc:
        return _pending(session_id=exc.session_id)
    except (KeyboardInterrupt, EOFError):
        return _fatal(message=msg("cli.peer.invitation_cancelled"), code=1)
    except (InvitationError, OSError, ValueError):
        return _safe_failure()
    finally:
        if state is not None:
            state.close()


def cmd_peer_approve_invitation(*, args: argparse.Namespace) -> int:
    """Display the target and require source consent before scoped approval."""
    if getattr(args, "backend", BACKEND_SQLITE) != BACKEND_SQLITE:
        return _safe_failure()
    state: InvitationStateStore | None = None
    try:
        state, flow = _flow()
        _, record = state.read(session_id=args.invitation_id, local_node_id=local_peer_public_identity().node_id)
        if record.get("role") != "source":
            raise InvitationError("invitation resume is invalid")
        try:
            target = flow.inspect_join(session_id=args.invitation_id)
        except InvitationError:
            return _pending(session_id=args.invitation_id)
        _display_identity(request=target["request"], service=target["service"], account=target["account"], include_rss=bool(record.get("include_rss")), label=msg("cli.peer.invitation_target"))
        identity = target.get("rss_identity")
        if isinstance(identity, dict):
            print(msg("cli.peer.invitation_rss_identity", connection_id=identity["connection_id"], fingerprint=_fingerprint(identity["public_key"])))
        already_consented = record.get("phase") in {"approval_staged", "approved", "complete"}
        if not already_consented and not _confirm():
            return _fatal(message=msg("cli.peer.invitation_cancelled"), code=1)
        try:
            flow.approve(session_id=args.invitation_id, confirmed=True)
        except InvitationCapacityPending as exc:
            capacity = exc.capacity
            return _fatal(message=msg("cli.peer.invitation_capacity", purchased=capacity["purchased_units"], provisioned=capacity["provisioned_units"], available=capacity["available_units"]), code=1)
        except InvitationError:
            return _pending(session_id=args.invitation_id)
        if flow.confirm_completion(session_id=args.invitation_id):
            print(msg("cli.peer.invitation_admitted"))
        else:
            print(msg("cli.peer.invitation_approved_pending", session_id=args.invitation_id))
        return 0
    except (KeyboardInterrupt, EOFError):
        return _fatal(message=msg("cli.peer.invitation_cancelled"), code=1)
    except (InvitationError, OSError, ValueError):
        return _safe_failure()
    finally:
        if state is not None:
            state.close()


__all__ = ["cmd_peer_approve_invitation", "cmd_peer_invite", "cmd_peer_join_invitation"]
