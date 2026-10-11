"""
secrets_kit.protocol.rss_provisioning

Deterministic customer Checkout and RSS enrollment bootstrap.

Opaque Checkout recovery state and RET material remain in owner-only local
files. Operator requests require TLS 1.3, and normal output never contains RET
values.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import ssl
import stat
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from secrets_kit.crypto.models import generate_signing_keypair
from secrets_kit.crypto.persistence import signing_keypair_from_record, signing_keypair_to_record
from secrets_kit.crypto.signatures import sign_ed25519, verify_ed25519
from secrets_kit.protocol.rss_auth import (
    RSSAuthenticationError,
    _read_restricted_file,
    configure_rss_client,
    rss_client_profile_path,
    store_rss_enrollment_token_file,
)

DEFAULT_RSS_OPERATOR_URL = "https://seckit-ops.unixwzrd.net"
RSS_CHECKOUT_RECEIPT_PROTOCOL = "rss_checkout_receipt/v1"
RSS_PROVISIONING_BUNDLE_PROTOCOL = "rss_provisioning_bundle/v1"
RSS_IDENTITY_PREPARED_PROTOCOL = "rss_identity_prepared/v1"


def rss_checkout_receipt_path() -> Path:
    """Return the standard owner-only Checkout receipt path."""
    return rss_client_profile_path().with_name("rss-checkout.json")


def rss_provisioning_state_path() -> Path:
    """Return the restart-safe public provisioning-state path."""
    return rss_client_profile_path().with_name("rss-provisioning.json")


def rss_identity_prepared_path() -> Path:
    """Return the owner-private pre-RET RSS identity record path."""
    return rss_client_profile_path().with_name("rss-identity-prepared.json")


def prepare_rss_device_identity(
    *, expected_operator_url: str, allow_pending_recovery: bool = False
) -> dict[str, str]:
    """Prepare and retain this device's RSS key and connection ID before an RET.

    Only the public key and opaque connection ID are returned. Repeated calls
    return the same validated identity; conflicting or unsafe local state is
    rejected without overwriting it.
    """
    operator_url = _https_base(value=expected_operator_url)
    profile_path = rss_client_profile_path()
    _validate_prepared_parent(path=profile_path.parent)
    if _path_present(path=profile_path):
        if not allow_pending_recovery:
            raise RSSAuthenticationError("RSS device is already configured; existing identity preserved")
        profile = _read_object(path=profile_path)
        if type(profile.get("version")) is not int or profile.get("version") != 1:
            raise RSSAuthenticationError("RSS client profile version is invalid")
        for field in ("connection_id", "key_file", "enrollment_token_file", "enrollment_url"):
            if not isinstance(profile.get(field), str) or not profile.get(field):
                raise RSSAuthenticationError("RSS pending recovery profile is invalid")
        if profile.get("enrollment_url") != operator_url:
            raise RSSAuthenticationError("RSS pending recovery authority differs; existing state preserved")
        try:
            configured_key = Path(str(profile["key_file"])).expanduser().resolve()
        except (OSError, RuntimeError, TypeError):
            raise RSSAuthenticationError("RSS pending recovery key path is invalid") from None
        if configured_key != profile_path.with_name("rss-auth-key.json").resolve():
            raise RSSAuthenticationError("RSS pending recovery key path is invalid")
        if not _pending_token_expired(profile=profile, profile_path=profile_path):
            raise RSSAuthenticationError("RSS device is already configured; existing identity preserved")
        key_path = profile_path.with_name("rss-auth-key.json")
        public_key = _read_prepared_key(path=key_path)
        connection_id = profile.get("connection_id")
        if not isinstance(connection_id, str) or not 1 <= len(connection_id) <= 256:
            raise RSSAuthenticationError("RSS pending recovery connection_id is invalid")
        return {"connection_id": connection_id, "public_key": public_key}
    prep_path = rss_identity_prepared_path()
    key_path = profile_path.with_name("rss-auth-key.json")
    if _path_present(path=prep_path):
        record = _read_prepared_record(path=prep_path)
        identity = _validate_prepared_identity(record=record, operator_url=operator_url)
        _validate_prepared_key(path=key_path, expected_public_key=identity["public_key"])
        return identity
    if _path_present(path=key_path):
        public_key = _read_prepared_key(path=key_path)
    else:
        key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        record = signing_keypair_to_record(keypair=generate_signing_keypair())
        _write_private_new(path=key_path, payload=_canonical(value=record))
        public_key = _read_prepared_key(path=key_path)
    identity = {"connection_id": f"connection-{secrets.token_hex(16)}", "public_key": public_key}
    _write_private_new(path=prep_path, payload=_canonical(value={
        "protocol": RSS_IDENTITY_PREPARED_PROTOCOL, "version": 1,
        "operator_url": operator_url, **identity,
    }))
    return identity


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
        if not _pending_token_expired(profile=profile, profile_path=profile_path):
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
    if not _path_present(path=profile_path) and _path_present(path=state_path):
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
    if not _path_present(path=profile_path) and _path_present(path=token_path):
        raise RSSAuthenticationError("orphaned RSS Enrollment Token requires recovery")

    result = _post_json(url=f"{operator_url}/v1/provisioning/ret", value=request)
    return configure_rss_provisioning_bundle(bundle=result, expected_operator_url=operator_url)


def configure_rss_provisioning_bundle(
    *, bundle: Mapping[str, object], expected_operator_url: str
) -> Path:
    """Accept a one-use RET on the destination user without copying an RSS key."""
    operator_url = _https_base(value=expected_operator_url)
    profile_path = rss_client_profile_path()
    existing_profile = _read_object(path=profile_path) if _path_present(path=profile_path) else None
    if existing_profile is not None and not _pending_token_expired(
        profile=existing_profile, profile_path=profile_path
    ):
        raise RSSAuthenticationError("RSS device is already configured; existing identity preserved")
    prepared_path = rss_identity_prepared_path()
    if _path_present(path=prepared_path):
        prepared = _validate_prepared_identity(
            record=_read_prepared_record(path=prepared_path), operator_url=operator_url
        )
        _validate_prepared_key(
            path=profile_path.with_name("rss-auth-key.json"),
            expected_public_key=prepared["public_key"],
        )
    state_path = rss_provisioning_state_path()
    token_path = profile_path.with_name("rss-enrollment-token")
    result = bundle
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

    if existing_profile is not None:
        if (
            existing_profile.get("entitlement_id") != entitlement_id
            or existing_profile.get("enrollment_url") != enrollment_url
            or existing_profile.get("relay_peers") != relay_peers
            or existing_profile.get("enrollment_primary") != relay_peers[0]
        ):
            raise RSSAuthenticationError("renewed RSS authority differs; existing identity preserved")
        if _ret_expires_at(token=token) <= int(time.time()):
            raise RSSAuthenticationError("renewed RSS Enrollment Token is expired")
        _replace_expired_token(path=token_path, token=token)
        return profile_path

    public_state = {
        "protocol": RSS_PROVISIONING_BUNDLE_PROTOCOL,
        "entitlement_id": entitlement_id,
        "enrollment_url": enrollment_url,
        "relay_peers": relay_peers,
    }
    if _path_present(path=state_path):
        state = _read_object(path=state_path)
        _validate_public_state(state, expected_operator_url=operator_url)
        if state != public_state:
            raise RSSAuthenticationError("pending RSS authority differs; existing state preserved")
        # A crash after writing public state but before writing its token is
        # recoverable from the validated retained bundle, never from the host
        # context or an unrelated entitlement. Keep the prepared key/ID intact.
        if not _path_present(path=token_path):
            store_rss_enrollment_token_file(path=token_path, token=token)
        else:
            retained = _read_restricted_file(token_path).decode("ascii").strip()
            if rss_enrollment_token_expired(token=token):
                raise RSSAuthenticationError("RSS Enrollment Token is expired")
            if retained == token:
                try:
                    retained_expired = rss_enrollment_token_expired(token=retained)
                except RSSAuthenticationError:
                    raise RSSAuthenticationError("RSS retained Enrollment Token is invalid") from None
                if retained_expired:
                    raise RSSAuthenticationError("RSS Enrollment Token is expired")
            else:
                try:
                    retained_expired = rss_enrollment_token_expired(token=retained)
                except RSSAuthenticationError:
                    retained_expired = None
                if retained_expired is False:
                    raise RSSAuthenticationError("RSS provisioning is incomplete; existing state preserved")
                _replace_expired_token(path=token_path, token=token)
        return _configure_from_state(
            token_path=token_path, entitlement_id=entitlement_id,
            enrollment_url=enrollment_url, relay_peers=list(relay_peers),
            state_path=state_path,
        )
    if _path_present(path=token_path):
        raise RSSAuthenticationError("RSS provisioning is incomplete; existing state preserved")
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
    prep_path = rss_identity_prepared_path()
    connection_id = None
    if _path_present(path=prep_path):
        identity = _validate_prepared_identity(
            record=_read_prepared_record(path=prep_path), operator_url=enrollment_url
        )
        _validate_prepared_key(
            path=rss_client_profile_path().with_name("rss-auth-key.json"),
            expected_public_key=identity["public_key"],
        )
        connection_id = identity["connection_id"]
    profile = configure_rss_client(
        enrollment_token_file=token_path,
        entitlement_id=entitlement_id,
        connection_id=connection_id,
        relay_peers=relay_peers,
        enrollment_url=enrollment_url,
    )
    state_path.unlink()
    if _path_present(path=prep_path):
        prep_path.unlink()
    return profile


def _read_prepared_key(*, path: Path) -> str:
    try:
        record = json.loads(_read_restricted_file(path).decode("utf-8"))
        keypair = signing_keypair_from_record(record=record)
        message = b"seckit/rss-identity-prepared/key-consistency/v1"
        if not verify_ed25519(keypair.public_key, message, sign_ed25519(keypair.private_key, message)):
            raise ValueError("RSS keypair does not match")
    except (RSSAuthenticationError, OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RSSAuthenticationError("RSS prepared identity key is invalid") from exc
    return base64.urlsafe_b64encode(keypair.public_key).rstrip(b"=").decode("ascii")


def _validate_prepared_parent(*, path: Path) -> None:
    """A different local user must not be able to replace prepared identity."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022
            or metadata.st_uid != os.getuid()):
        raise RSSAuthenticationError("RSS prepared identity directory is unsafe")


def _read_prepared_record(*, path: Path) -> dict[str, Any]:
    _validate_prepared_parent(path=path.parent)
    try:
        value = json.loads(_read_restricted_file(path).decode("utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise RSSAuthenticationError("RSS prepared identity record is invalid") from None
    if not isinstance(value, dict):
        raise RSSAuthenticationError("RSS prepared identity record is invalid")
    return value


def _validate_prepared_key(*, path: Path, expected_public_key: str) -> None:
    if _read_prepared_key(path=path) != expected_public_key:
        raise RSSAuthenticationError("RSS prepared identity key differs; existing state preserved")


def _validate_prepared_identity(*, record: Mapping[str, object], operator_url: str) -> dict[str, str]:
    required = {"protocol", "version", "operator_url", "connection_id", "public_key"}
    if (set(record) != required or record.get("protocol") != RSS_IDENTITY_PREPARED_PROTOCOL
            or type(record.get("version")) is not int or record.get("version") != 1):
        raise RSSAuthenticationError("RSS prepared identity is invalid")
    if record.get("operator_url") != _https_base(value=operator_url):
        raise RSSAuthenticationError("RSS prepared identity authority differs; existing state preserved")
    connection_id = record.get("connection_id")
    public_key = record.get("public_key")
    if not isinstance(connection_id, str) or not 1 <= len(connection_id) <= 256:
        raise RSSAuthenticationError("RSS prepared connection_id is invalid")
    if not isinstance(public_key, str) or not public_key:
        raise RSSAuthenticationError("RSS prepared public key is invalid")
    try:
        decoded = base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))
    except (ValueError, binascii.Error) as exc:
        raise RSSAuthenticationError("RSS prepared public key is invalid") from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != public_key:
        raise RSSAuthenticationError("RSS prepared public key is invalid")
    return {"connection_id": connection_id, "public_key": public_key}


def _pending_token_expired(*, profile: Mapping[str, object], profile_path: Path) -> bool:
    """Inspect expiry only; Ops and the relay remain the RET authorities."""
    token_path = profile_path.with_name("rss-enrollment-token")
    configured = profile.get("enrollment_token_file")
    if not configured:
        return False
    try:
        configured_path = Path(configured).expanduser().resolve()
    except (OSError, RuntimeError, TypeError):
        raise RSSAuthenticationError("RSS enrollment token path is invalid") from None
    if configured_path != token_path.resolve():
        raise RSSAuthenticationError("RSS enrollment token path is invalid")
    try:
        token = _read_restricted_file(token_path).decode("ascii")
    except (OSError, UnicodeError) as exc:
        raise RSSAuthenticationError("pending RSS Enrollment Token is unavailable") from exc
    return rss_enrollment_token_expired(token=token)


def rss_enrollment_token_expired(*, token: str) -> bool:
    """Report local RET expiry only; never treat decoded claims as authority."""
    return _ret_expires_at(token=token) <= int(time.time())


def _ret_expires_at(*, token: str) -> int:
    """Read a bounded RET expiry for retry scheduling, never for authorization."""
    parts = token.split(".")
    if len(token) > 8192 or len(parts) != 3 or parts[0] != "ret1":
        raise RSSAuthenticationError("RSS Enrollment Token format is invalid")
    try:
        payload = base64.b64decode(parts[1] + "=" * (-len(parts[1]) % 4), altchars=b"-_", validate=True)
        claims = json.loads(payload)
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise RSSAuthenticationError("RSS Enrollment Token format is invalid") from exc
    if not isinstance(claims, dict):
        raise RSSAuthenticationError("RSS Enrollment Token claims are invalid")
    expiry = claims.get("expires_at")
    if claims.get("protocol") != "rss_enrollment_token/v1" or type(expiry) is not int:
        raise RSSAuthenticationError("RSS Enrollment Token claims are invalid")
    return expiry


def _replace_expired_token(*, path: Path, token: str) -> None:
    """Atomically replace an owner-only pending RET without touching device identity."""
    _read_restricted_file(path)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(token.encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


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
    "configure_rss_provisioning_bundle",
    "prepare_rss_device_identity",
    "rss_identity_prepared_path",
    "rss_checkout_receipt_path",
    "rss_provisioning_state_path",
    "rss_enrollment_token_expired",
    "start_rss_checkout",
]
