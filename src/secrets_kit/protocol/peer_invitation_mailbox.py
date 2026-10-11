"""secrets_kit.protocol.peer_invitation_mailbox

Bounded TLS-only transport of opaque invitation frames. Capabilities occur only
in POST bodies; redirects are forbidden. Mailbox replies grant no authority.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.codecs import encode_b64url
from secrets_kit.protocol.peer_invitation import (
    MAX_INVITATION_BYTES,
    InvitationError,
    InvitationSecret,
)
from secrets_kit.protocol.rss_provisioning import _https_base


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        raise InvitationError("invitation service redirect rejected")


class InvitationMailboxClient:
    """Exchange phases at a selected HTTPS origin, never plaintext identities."""

    def __init__(self, *, origin: str) -> None:
        try:
            self._origin = _https_base(value=origin)
            self._url = self._origin + "/v1/peer/invitation"
        except ValueError:
            raise InvitationError("invitation service origin is invalid") from None

    @property
    def origin(self) -> str:
        """Non-secret service origin, pinned in local resumable state."""
        return self._origin

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = canonical_json_bytes(payload)
        if len(encoded) > 64 * 1024:
            raise InvitationError("invitation request is too large")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
        request = urllib.request.Request(self._url, data=encoded, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(request, timeout=15) as response:
                data = response.read(192 * 1024 + 1)
            if len(data) > 192 * 1024:
                raise ValueError
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (OSError, urllib.error.URLError, ValueError):
            raise InvitationError("invitation service request failed") from None

    @staticmethod
    def _frame(data: bytes) -> str:
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_INVITATION_BYTES:
            raise InvitationError("invitation frame is invalid")
        return base64.urlsafe_b64encode(data).decode("ascii")

    @staticmethod
    def _stored(value: dict[str, Any]) -> None:
        if value != {"status": "stored"}:
            raise InvitationError("invitation service reply is invalid")

    def create(self, *, secret: InvitationSecret, source_cap: str, frame: bytes, expires_at: int) -> None:
        self._stored(self._post({
            "action": "create", "session_id": secret.session_id, "source_cap": source_cap,
            "read_cap": encode_b64url(secret.derive("read")), "join_cap": encode_b64url(secret.derive("join")),
            "ciphertext": self._frame(frame), "expires_at": expires_at,
        }))

    def read(self, *, secret: InvitationSecret) -> dict[str, bytes | int | None]:
        value = self._post({"action": "read", "session_id": secret.session_id,
                            "read_cap": encode_b64url(secret.derive("read"))})
        if set(value) != {"offer", "join", "approve", "complete", "expires_at"} or type(value["expires_at"]) is not int:
            raise InvitationError("invitation service reply is invalid")
        result: dict[str, bytes | int | None] = {"expires_at": value["expires_at"]}
        try:
            for stage in ("offer", "join", "approve", "complete"):
                encoded = value[stage]
                if encoded is None and stage != "offer":
                    result[stage] = None
                    continue
                if not isinstance(encoded, str) or len(encoded) > 43700:
                    raise ValueError
                data = base64.urlsafe_b64decode(encoded)
                if self._frame(data) != encoded:
                    raise ValueError
                result[stage] = data
        except (TypeError, ValueError):
            raise InvitationError("invitation service reply is invalid") from None
        return result

    def put(self, *, secret: InvitationSecret, stage: str, frame: bytes,
            source_cap: str | None = None, claim_cap: str | None = None) -> None:
        if stage not in {"join", "approve", "complete"} or (stage == "approve" and source_cap is None) or (stage != "approve" and claim_cap is None):
            raise InvitationError("invitation write capability is required")
        self._stored(self._post({"action": "put", "session_id": secret.session_id, "stage": stage,
                                "write_cap": source_cap if stage == "approve" else encode_b64url(secret.derive("join")),
                                "claim_cap": claim_cap, "ciphertext": self._frame(frame)}))
