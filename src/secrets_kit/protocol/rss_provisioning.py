"""
secrets_kit.protocol.rss_provisioning

Deterministic customer Checkout and RSS enrollment bootstrap.

Opaque Checkout recovery state and RET material remain in owner-only local
files. Operator requests require TLS 1.3, and normal output never contains RET
values.
"""

from __future__ import annotations

import json
import os
import ssl
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from secrets_kit.protocol.rss_auth import (
    RSSAuthenticationError,
    configure_rss_client,
    rss_client_profile_path,
    store_rss_enrollment_token_file,
)

DEFAULT_RSS_OPERATOR_URL = "https://seckit-ops.unixwzrd.net"
RSS_CHECKOUT_RECEIPT_PROTOCOL = "rss_checkout_receipt/v1"
RSS_PROVISIONING_BUNDLE_PROTOCOL = "rss_provisioning_bundle/v1"


def rss_checkout_receipt_path() -> Path:
    """Return the standard owner-only Checkout receipt path."""
    return rss_client_profile_path().with_name("rss-checkout.json")


def rss_provisioning_state_path() -> Path:
    """Return the restart-safe public provisioning-state path."""
    return rss_client_profile_path().with_name("rss-provisioning.json")


def start_rss_checkout(
    *, connection_units: int, operator_url: str = DEFAULT_RSS_OPERATOR_URL,
    invite_code: str | None = None,
) -> tuple[str, Path]:
    """Start Checkout and retain opaque recovery IDs; send any invite only to Ops."""
    if connection_units < 2:
        raise RSSAuthenticationError("RSS requires at least two connection units")
    base = _https_base(value=operator_url)
    path = rss_checkout_receipt_path()
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(f"RSS Checkout receipt already exists: {path}")
    request: dict[str, object] = {"connection_units": connection_units}
    if invite_code is not None:
        if not invite_code.startswith("ski_") or len(invite_code) > 128:
            raise RSSAuthenticationError("Beta Checkout invitation is invalid")
        request["invite_code"] = invite_code
    result = _post_json(url=f"{base}/v1/checkout", value=request)
    required = {"account_id", "checkout_session_id", "checkout_url"}
    if set(result) != required:
        raise RSSAuthenticationError("RSS Checkout response is invalid")
    account_id = _bounded_string(value=result, key="account_id", limit=128)
    checkout_session_id = _bounded_string(value=result, key="checkout_session_id", limit=256)
    checkout_url = _bounded_string(value=result, key="checkout_url", limit=2048)
    if not checkout_url.startswith("https://checkout.stripe.com/"):
        raise RSSAuthenticationError("RSS Checkout URL is invalid")
    receipt = {
        "protocol": RSS_CHECKOUT_RECEIPT_PROTOCOL,
        "operator_url": base,
        "account_id": account_id,
        "checkout_session_id": checkout_session_id,
    }
    _write_private_new(path=path, payload=_canonical(value=receipt))
    return checkout_url, path


def complete_rss_enrollment() -> Path:
    """Exchange a paid Checkout receipt for an RET and configure this peer."""
    profile_path = rss_client_profile_path()
    if _path_present(path=profile_path):
        profile = _read_object(path=profile_path)
        if profile.get("version") != 1:
            raise RSSAuthenticationError("RSS client profile version is invalid")
        return profile_path
    receipt_path = rss_checkout_receipt_path()
    receipt = _read_object(path=receipt_path)
    if (
        set(receipt)
        != {
            "protocol",
            "operator_url",
            "account_id",
            "checkout_session_id",
        }
        or receipt.get("protocol") != RSS_CHECKOUT_RECEIPT_PROTOCOL
    ):
        raise RSSAuthenticationError("RSS Checkout receipt is invalid")
    operator_url = _https_base(value=_bounded_string(value=receipt, key="operator_url", limit=2048))
    request = {
        "account_id": _bounded_string(value=receipt, key="account_id", limit=128),
        "checkout_session_id": _bounded_string(value=receipt, key="checkout_session_id", limit=256),
    }
    state_path = rss_provisioning_state_path()
    token_path = profile_path.with_name("rss-enrollment-token")
    if _path_present(path=state_path):
        state = _read_object(path=state_path)
        entitlement_id, enrollment_url, relay_peers = _validate_public_state(
            state, expected_operator_url=operator_url
        )
        if not _path_present(path=token_path):
            state_path.unlink()
        else:
            return _configure_from_state(
                token_path=token_path,
                entitlement_id=entitlement_id,
                enrollment_url=enrollment_url,
                relay_peers=relay_peers,
                state_path=state_path,
            )
    if _path_present(path=token_path):
        raise RSSAuthenticationError("orphaned RSS Enrollment Token requires recovery")

    result = _post_json(url=f"{operator_url}/v1/provisioning/ret", value=request)
    required = {
        "protocol",
        "entitlement_id",
        "rss_enrollment_token",
        "enrollment_url",
        "relay_peers",
    }
    if set(result) != required or result.get("protocol") != RSS_PROVISIONING_BUNDLE_PROTOCOL:
        raise RSSAuthenticationError("RSS provisioning response is invalid")
    entitlement_id = _bounded_string(value=result, key="entitlement_id", limit=128)
    token = _bounded_string(value=result, key="rss_enrollment_token", limit=8192)
    if not token.startswith("ret1."):
        raise RSSAuthenticationError("RSS Enrollment Token is invalid")
    enrollment_url = _https_base(
        value=_bounded_string(value=result, key="enrollment_url", limit=2048)
    )
    if enrollment_url != operator_url:
        raise RSSAuthenticationError("RSS enrollment authority is invalid")
    relay_peers = result.get("relay_peers")
    if (
        not isinstance(relay_peers, list)
        or len(relay_peers) != 2
        or any(not _valid_peer(value=value) for value in relay_peers)
    ):
        raise RSSAuthenticationError("RSS relay endpoint set is invalid")

    public_state = {
        "protocol": RSS_PROVISIONING_BUNDLE_PROTOCOL,
        "entitlement_id": entitlement_id,
        "enrollment_url": enrollment_url,
        "relay_peers": relay_peers,
    }
    _write_private_new(path=state_path, payload=_canonical(value=public_state))
    try:
        store_rss_enrollment_token_file(path=token_path, token=token)
        return _configure_from_state(
            token_path=token_path,
            entitlement_id=entitlement_id,
            enrollment_url=enrollment_url,
            relay_peers=list(relay_peers),
            state_path=state_path,
        )
    except Exception:
        raise


def _configure_from_state(
    *,
    token_path: Path,
    entitlement_id: str,
    enrollment_url: str,
    relay_peers: list[str],
    state_path: Path,
) -> Path:
    """Configure one local peer from restart-safe protected provisioning state."""
    profile = configure_rss_client(
        enrollment_token_file=token_path,
        entitlement_id=entitlement_id,
        connection_id=None,
        relay_peers=relay_peers,
        enrollment_url=enrollment_url,
    )
    state_path.unlink()
    return profile


def _validate_public_state(
    value: Mapping[str, object], *, expected_operator_url: str
) -> tuple[str, str, list[str]]:
    """Validate retained non-secret state before reusing the protected RET."""
    if (
        set(value)
        != {
            "protocol",
            "entitlement_id",
            "enrollment_url",
            "relay_peers",
        }
        or value.get("protocol") != RSS_PROVISIONING_BUNDLE_PROTOCOL
    ):
        raise RSSAuthenticationError("RSS provisioning state is invalid")
    entitlement_id = _bounded_string(value=value, key="entitlement_id", limit=128)
    enrollment_url = _https_base(
        value=_bounded_string(value=value, key="enrollment_url", limit=2048)
    )
    if enrollment_url != expected_operator_url:
        raise RSSAuthenticationError("RSS enrollment authority is invalid")
    peers = value.get("relay_peers")
    if (
        not isinstance(peers, list)
        or len(peers) != 2
        or any(not _valid_peer(value=peer) for peer in peers)
    ):
        raise RSSAuthenticationError("RSS relay endpoint set is invalid")
    return entitlement_id, enrollment_url, list(peers)


def _post_json(*, url: str, value: Mapping[str, object]) -> dict[str, Any]:
    """POST bounded JSON over TLS 1.3 and return one JSON object."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    request = urllib.request.Request(
        url,
        data=_canonical(value=value),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            payload = response.read(64 * 1024 + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise RSSAuthenticationError("RSS operator request failed") from exc
    if len(payload) > 64 * 1024:
        raise RSSAuthenticationError("RSS operator response is too large")
    try:
        result = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RSSAuthenticationError("RSS operator response is invalid") from exc
    if not isinstance(result, dict):
        raise RSSAuthenticationError("RSS operator response is invalid")
    return result


def _https_base(*, value: str) -> str:
    """Validate and normalize an HTTPS origin without a path."""
    base = value.rstrip("/")
    try:
        parsed = urlsplit(base)
        _ = parsed.port
    except ValueError as exc:
        raise RSSAuthenticationError("RSS operator URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise RSSAuthenticationError("RSS operator URL is invalid")
    return base


def _bounded_string(*, value: Mapping[str, object], key: str, limit: int) -> str:
    """Read one required bounded string from a protocol object."""
    item = value.get(key)
    if not isinstance(item, str) or not item or len(item) > limit:
        raise RSSAuthenticationError(f"RSS {key} is invalid")
    return item


def _valid_peer(*, value: object) -> bool:
    """Return whether a value is one bounded host/TCP/p2p relay multiaddress."""
    if not isinstance(value, str) or len(value) > 2048:
        return False
    segments = value.split("/")
    if len(segments) != 7:
        return False
    prefix, host_protocol, host, transport, port, peer_protocol, peer_id = segments
    if (
        prefix
        or host_protocol not in {"dns4", "dns6", "ip4", "ip6"}
        or not host
        or transport != "tcp"
        or not port
        or not port.isascii()
        or not port.isdecimal()
        or peer_protocol != "p2p"
        or not peer_id
    ):
        return False
    return 1 <= int(port) <= 65535


def _canonical(*, value: Mapping[str, object]) -> bytes:
    """Serialize one protocol object deterministically."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_private_new(*, path: Path, payload: bytes) -> None:
    """Create and fsync a new owner-only file without overwriting state."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _read_object(*, path: Path) -> dict[str, Any]:
    """Read one owner-only regular JSON file without following links."""
    try:
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise RSSAuthenticationError("RSS Checkout receipt permissions are too broad")
        value = json.loads(path.read_text(encoding="utf-8"))
    except RSSAuthenticationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RSSAuthenticationError("RSS Checkout receipt is unavailable") from exc
    if not isinstance(value, dict):
        raise RSSAuthenticationError("RSS Checkout receipt is invalid")
    return value


def _path_present(*, path: Path) -> bool:
    """Return whether a path entry exists without following links."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


__all__ = [
    "DEFAULT_RSS_OPERATOR_URL",
    "complete_rss_enrollment",
    "rss_checkout_receipt_path",
    "rss_provisioning_state_path",
    "start_rss_checkout",
]
