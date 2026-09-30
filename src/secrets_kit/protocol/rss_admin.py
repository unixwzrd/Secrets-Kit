"""secrets_kit.protocol.rss_admin

Owner-only RSS account administrator credentials and signed customer actions.
The account key is distinct from peer and RSS transport identities; no private
key or recovery code is sent to an RSS relay or stored by the operator.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from secrets_kit.crypto.signatures import generate_ed25519_keypair, sign_ed25519
from secrets_kit.protocol.rss_auth import (
    RSSAuthenticationError,
    _read_restricted_file,
    _write_restricted_new_file,
    load_rss_relay_credentials_from_environment,
    rss_client_profile_path,
)
from secrets_kit.protocol.rss_provisioning import (
    _https_base,
    rss_checkout_receipt_path,
)

CLAIM_PROTOCOL = "rss_customer_admin_claim/v1"
REQUEST_PROTOCOL = "rss_customer_admin_request/v1"
RECOVERY_PROTOCOL = "rss_customer_admin_recovery/v1"
ADMIN_ACTIONS = frozenset({"devices.list", "devices.revoke", "device.ret", "billing.portal"})


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: object, *, size: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise RSSAuthenticationError("RSS administrator credential is invalid")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise RSSAuthenticationError("RSS administrator credential is invalid") from exc
    if len(raw) != size or _encode(raw) != value:
        raise RSSAuthenticationError("RSS administrator credential is invalid")
    return raw


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _admin_path() -> Path:
    return rss_client_profile_path().with_name("rss-admin-key.json")


def _pending_path() -> Path:
    return rss_client_profile_path().with_name("rss-admin-pending.json")


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_restricted_file(path).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RSSAuthenticationError("RSS administrator credential is unavailable") from exc
    if not isinstance(value, dict):
        raise RSSAuthenticationError("RSS administrator credential is invalid")
    return value


def _new_codes() -> tuple[str, ...]:
    return tuple("skr_" + _encode(secrets.token_bytes(32)) for _ in range(4))


def _material(*, account_id: str, operator_url: str) -> dict[str, object]:
    private_key, public_key = generate_ed25519_keypair()
    codes = _new_codes()
    return {
        "version": 1, "account_id": account_id,
        "operator_url": _https_base(value=operator_url),
        "private_key": _encode(private_key), "public_key": _encode(public_key),
        "recovery_codes": list(codes),
    }


def _key_material(value: dict[str, Any]) -> tuple[str, str, bytes, bytes]:
    if value.get("version") != 1 or not isinstance(value.get("account_id"), str):
        raise RSSAuthenticationError("RSS administrator credential version is invalid")
    account_id = value["account_id"]
    if not account_id or len(account_id) > 128:
        raise RSSAuthenticationError("RSS administrator account is invalid")
    origin = _https_base(value=value.get("operator_url", ""))
    private_key = _decode(value.get("private_key"), size=32)
    public_key = _decode(value.get("public_key"), size=32)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    derived = Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if derived != public_key:
        raise RSSAuthenticationError("RSS administrator keypair is invalid")
    return account_id, origin, private_key, public_key


def _post(*, operator_url: str, path: str, body: dict[str, object]) -> tuple[int, dict[str, Any]]:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    request = urllib.request.Request(
        _https_base(value=operator_url) + path, data=_canonical(body),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        response = urllib.request.urlopen(request, context=context, timeout=20)
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            response = exc
        else:
            raise RSSAuthenticationError(f"RSS administrator request denied ({exc.code})") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RSSAuthenticationError("RSS administrator service is unavailable") from exc
    with response:
        payload = response.read(64 * 1024 + 1)
        status = response.status if hasattr(response, "status") else response.code
    if len(payload) > 64 * 1024:
        raise RSSAuthenticationError("RSS administrator response is too large")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RSSAuthenticationError("RSS administrator response is invalid") from exc
    if not isinstance(value, dict):
        raise RSSAuthenticationError("RSS administrator response is invalid")
    return int(status), value


def claim_customer_admin() -> tuple[str, ...]:
    """Claim one paid account from its original device and return offline codes.

    A pending owner-only file retains the same codes across a lost HTTP reply.
    The caller must display them and obtain an explicit saved acknowledgement
    before discarding the pending file.
    """
    if _admin_path().exists():
        raise RSSAuthenticationError("RSS administrator is already claimed on this user")
    receipt = _read_object(rss_checkout_receipt_path())
    if set(receipt) != {
        "protocol", "operator_url", "account_id", "checkout_session_id"
    } or receipt.get("protocol") != "rss_checkout_receipt/v1":
        raise RSSAuthenticationError("paid Checkout receipt is required")
    account_id = receipt.get("account_id")
    checkout_id = receipt.get("checkout_session_id")
    origin = receipt.get("operator_url")
    if (not isinstance(account_id, str) or not account_id
            or not isinstance(checkout_id, str) or not checkout_id
            or not isinstance(origin, str)):
        raise RSSAuthenticationError("paid Checkout receipt is invalid")
    credentials = load_rss_relay_credentials_from_environment()
    if credentials is None or credentials.enrollment_token is not None:
        raise RSSAuthenticationError("first RSS device must be enrolled before claiming")
    pending = _pending_path()
    if pending.exists():
        material = _read_object(pending)
    else:
        material = _material(account_id=account_id, operator_url=origin)
        _write_restricted_new_file(pending, _canonical(material))
    stored_account, operator_url, admin_private, admin_public = _key_material(material)
    if stored_account != account_id or operator_url != _https_base(value=origin):
        raise RSSAuthenticationError("pending RSS administrator belongs to another Checkout")
    codes = material.get("recovery_codes")
    if not isinstance(codes, list) or len(codes) != 4 or any(
        not isinstance(code, str) or not code.startswith("skr_") for code in codes
    ):
        raise RSSAuthenticationError("pending RSS recovery codes are invalid")
    payload: dict[str, object] = {
        "protocol": CLAIM_PROTOCOL, "account_id": account_id,
        "checkout_session_id": checkout_id, "connection_id": credentials.connection_id,
        "admin_public_key": _encode(admin_public),
        "recovery_hashes": [hashlib.sha256(code.encode("ascii")).hexdigest() for code in codes],
        "request_id": secrets.token_hex(16), "issued_at": int(time.time()),
    }
    message = _canonical(payload)
    status, result = _post(operator_url=operator_url, path="/v1/customer/admin/claim", body={
        "payload": payload,
        "device_signature": _encode(sign_ed25519(credentials.customer_private_key, message)),
        "admin_signature": _encode(sign_ed25519(admin_private, message)),
    })
    if status != 200 or result.get("status") != "claimed":
        raise RSSAuthenticationError("RSS administrator claim was not confirmed")
    key_record = {key: value for key, value in material.items() if key != "recovery_codes"}
    _write_restricted_new_file(_admin_path(), _canonical(key_record))
    # Leave pending codes until the CLI confirms that the customer saved them.
    return tuple(codes)


def finish_customer_admin_claim() -> None:
    """Discard the local plaintext recovery-code staging file after acknowledgement."""
    _read_object(_admin_path())
    _read_object(_pending_path())
    _pending_path().unlink()


def pending_customer_admin_codes() -> tuple[str, ...] | None:
    """Return unacknowledged owner-only recovery codes after a confirmed claim."""
    if not _admin_path().exists() or not _pending_path().exists():
        return None
    administrator = _read_object(_admin_path())
    pending = _read_object(_pending_path())
    if _key_material(administrator) != _key_material(pending):
        raise RSSAuthenticationError("pending RSS administrator key does not match")
    codes = pending.get("recovery_codes")
    if not isinstance(codes, list) or len(codes) != 4 or any(
        not isinstance(code, str) or not code.startswith("skr_") for code in codes
    ):
        raise RSSAuthenticationError("pending RSS recovery codes are invalid")
    return tuple(codes)


def customer_admin_account_id() -> str:
    """Return the non-secret account ID to save beside offline recovery codes."""
    account_id, _, _, _ = _key_material(_read_object(_admin_path()))
    return account_id


def admin_action(*, action: str, parameters: dict[str, object]) -> tuple[int, dict[str, Any]]:
    """Sign one bounded customer action without exposing the private account key."""
    if action not in ADMIN_ACTIONS:
        raise RSSAuthenticationError("RSS administrator action is unsupported")
    account_id, operator_url, private_key, _ = _key_material(_read_object(_admin_path()))
    payload: dict[str, object] = {
        "protocol": REQUEST_PROTOCOL, "account_id": account_id, "action": action,
        "request_id": secrets.token_hex(16), "issued_at": int(time.time()),
        "parameters": parameters,
    }
    return _post(operator_url=operator_url, path="/v1/customer/admin/action", body={
        "payload": payload, "signature": _encode(sign_ed25519(private_key, _canonical(payload))),
    })


def recover_customer_admin(*, account_id: str, operator_url: str, code: str) -> tuple[str, ...]:
    """Use one saved recovery code to rotate the owner credential and code set."""
    if _admin_path().exists():
        raise RSSAuthenticationError("existing RSS administrator state must be preserved")
    if _pending_path().exists():
        material = _read_object(_pending_path())
    else:
        material = _material(account_id=account_id, operator_url=operator_url)
        _write_restricted_new_file(_pending_path(), _canonical(material))
    _, origin, private_key, public_key = _key_material(material)
    if material["account_id"] != account_id or origin != _https_base(value=operator_url):
        raise RSSAuthenticationError("pending RSS recovery belongs to another account")
    codes = material["recovery_codes"]
    assert isinstance(codes, list)
    payload: dict[str, object] = {
        "protocol": RECOVERY_PROTOCOL, "account_id": account_id, "recovery_code": code,
        "new_public_key": _encode(public_key),
        "recovery_hashes": [hashlib.sha256(item.encode("ascii")).hexdigest() for item in codes],
        "request_id": secrets.token_hex(16), "issued_at": int(time.time()),
    }
    status, result = _post(operator_url=origin, path="/v1/customer/admin/recover", body={
        "payload": payload, "signature": _encode(sign_ed25519(private_key, _canonical(payload))),
    })
    if status != 200 or result.get("status") != "recovered":
        raise RSSAuthenticationError("RSS administrator recovery was not confirmed")
    _write_restricted_new_file(
        _admin_path(), _canonical({key: value for key, value in material.items() if key != "recovery_codes"})
    )
    return tuple(codes)


__all__ = [
    "claim_customer_admin", "finish_customer_admin_claim", "admin_action",
    "recover_customer_admin", "pending_customer_admin_codes",
    "customer_admin_account_id",
]
