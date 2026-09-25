"""
secrets_kit.protocol.rss_auth

Public customer-side proof builders for authenticated RSS relay reservations.

The module treats an RSS Enrollment Token as opaque and never accepts or emits
customer private key material on the wire. It remains transport-neutral.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import ssl
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from secrets_kit.crypto.models import generate_signing_keypair
from secrets_kit.crypto.persistence import (
    signing_keypair_from_record,
    signing_keypair_to_record,
)
from secrets_kit.crypto.signatures import sign_ed25519

RSS_AUTH_STREAM_PROTOCOL = "/seckit/rss-auth/1.0.0"
RSS_AUTH_CONTROL_PROTOCOL = "rss_auth_control/v1"
RSS_ENROLLMENT_PROOF_PROTOCOL = "rss_enrollment_proof/v2"
RSS_SESSION_AUTH_PROTOCOL = "rss_session_auth/v1"
RSS_SESSION_READY_PROTOCOL = "rss_session_ready/v1"
RSS_IDENTITY_TRANSFER_PROTOCOL = "rss_identity_transfer/v1"


class RSSAuthenticationError(ValueError):
    """RSS authentication configuration or protocol input is invalid."""


@dataclass(frozen=True)
class RSSAuthenticationChallenge:
    """One validated server challenge used by an RSS client proof."""

    protocol: str
    challenge_id: str
    challenge: str
    expires_at: int

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, object], *, expected_protocol: str
    ) -> "RSSAuthenticationChallenge":
        """Validate a challenge response without accepting unknown fields."""
        required = {"protocol", "challenge_id", "challenge", "expires_at"}
        if set(value) != required or value.get("protocol") != expected_protocol:
            raise RSSAuthenticationError("RSS authentication challenge is invalid")
        challenge_id = value.get("challenge_id")
        challenge = value.get("challenge")
        expires_at = value.get("expires_at")
        if not isinstance(challenge_id, str) or not challenge_id:
            raise RSSAuthenticationError("RSS challenge_id is invalid")
        if not isinstance(challenge, str) or not challenge:
            raise RSSAuthenticationError("RSS challenge is invalid")
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            raise RSSAuthenticationError("RSS challenge expires_at is invalid")
        return cls(
            protocol=expected_protocol,
            challenge_id=challenge_id,
            challenge=challenge,
            expires_at=expires_at,
        )


@dataclass(frozen=True)
class RSSRelayClientCredentials:
    """Local-only material needed to authenticate one peer to RSS."""

    entitlement_id: str
    connection_id: str
    customer_private_key: bytes
    customer_public_key: bytes
    enrollment_token: str | None = None
    enrollment_token_file: Path | None = None
    enrollment_url: str | None = None

    def __post_init__(self) -> None:
        if not self.entitlement_id or len(self.entitlement_id) > 128:
            raise RSSAuthenticationError("RSS entitlement_id is invalid")
        if not self.connection_id or len(self.connection_id) > 256:
            raise RSSAuthenticationError("RSS connection_id is invalid")
        if len(self.customer_private_key) != 32 or len(self.customer_public_key) != 32:
            raise RSSAuthenticationError("RSS authentication keys must be 32 raw bytes")


def rss_client_profile_path() -> Path:
    """Return the standard customer RSS profile path."""
    return Path.home() / ".config" / "seckit" / "rss-client.json"


def configure_rss_client(
    *,
    enrollment_token_file: str | Path | None,
    entitlement_id: str,
    connection_id: str | None,
    relay_peers: list[str],
    enrollment_url: str,
    profile_path: str | Path | None = None,
) -> Path:
    """Create customer key material and a restricted daemon-readable RSS profile."""
    token_path: Path | None = None
    if enrollment_token_file is not None:
        token_path = Path(enrollment_token_file).expanduser().resolve()
        _read_restricted_file(token_path)
    destination = Path(profile_path) if profile_path is not None else rss_client_profile_path()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_path = destination.with_name("rss-auth-key.json")
    if not key_path.exists():
        if token_path is None:
            raise RSSAuthenticationError(
                "an RSS Enrollment Token is required when creating a new RSS identity"
            )
        create_rss_authentication_key_file(path=key_path)
    else:
        _read_restricted_file(key_path)
    if not relay_peers or any(not isinstance(value, str) or not value for value in relay_peers):
        raise RSSAuthenticationError("at least one RSS relay peer is required")
    if not enrollment_url.startswith("https://"):
        raise RSSAuthenticationError("RSS enrollment URL must use HTTPS")
    resolved_connection_id = connection_id or f"connection-{secrets.token_hex(16)}"
    profile = {
        "version": 1,
        "entitlement_id": entitlement_id,
        "connection_id": resolved_connection_id,
        "key_file": str(key_path),
        "enrollment_token_file": "" if token_path is None else str(token_path),
        "relay_peers": list(relay_peers),
        "enrollment_primary": relay_peers[0],
        "enrollment_url": enrollment_url,
    }
    payload = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
    return destination


def load_rss_relay_peers_from_profile() -> tuple[str, ...]:
    """Return configured RSS peer multiaddrs or an empty tuple when absent."""
    profile = _load_rss_profile()
    if profile is None:
        return ()
    peers = profile.get("relay_peers")
    if not isinstance(peers, list) or any(
        not isinstance(value, str) or not value for value in peers
    ):
        raise RSSAuthenticationError("RSS relay_peers profile field is invalid")
    if not peers or profile.get("enrollment_primary") != peers[0]:
        raise RSSAuthenticationError("RSS enrollment primary profile field is invalid")
    return tuple(peers)


def create_rss_authentication_key_file(*, path: str | Path) -> Path:
    """Create a new customer-held RSS Ed25519 key file atomically as mode 0600."""
    destination = Path(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = signing_keypair_to_record(keypair=generate_signing_keypair())
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    return destination


def export_rss_authentication_identity(*, path: str | Path) -> Path:
    """Export identity and non-secret RSS configuration for a second clean peer."""
    profile = _load_rss_profile()
    if profile is None or profile.get("enrollment_token_file"):
        raise RSSAuthenticationError("RSS enrollment must complete before identity export")
    source = rss_client_profile_path().with_name("rss-auth-key.json")
    key_payload = _read_restricted_file(source)
    _validate_key_payload(key_payload)
    transfer = {
        "protocol": RSS_IDENTITY_TRANSFER_PROTOCOL,
        "identity": json.loads(key_payload.decode("utf-8")),
        "entitlement_id": profile.get("entitlement_id"),
        "enrollment_url": profile.get("enrollment_url"),
        "relay_peers": profile.get("relay_peers"),
    }
    _validate_identity_transfer(value=transfer)
    payload = json.dumps(transfer, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _write_restricted_new_file(Path(path), payload)


def import_rss_authentication_identity(*, path: str | Path) -> Path:
    """Import identity and configure a distinct second-peer connection."""
    payload = _read_restricted_file(Path(path).expanduser())
    try:
        transfer = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RSSAuthenticationError("RSS identity transfer is invalid") from exc
    _validate_identity_transfer(value=transfer)
    profile_path = rss_client_profile_path()
    destination = profile_path.with_name("rss-auth-key.json")
    key_payload = json.dumps(transfer["identity"], sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    _validate_key_payload(key_payload)
    _write_restricted_new_file(destination, key_payload)
    try:
        configure_rss_client(
            enrollment_token_file=None,
            entitlement_id=transfer["entitlement_id"],
            connection_id=None,
            relay_peers=list(transfer["relay_peers"]),
            enrollment_url=transfer["enrollment_url"],
            profile_path=profile_path,
        )
    except BaseException:
        if destination.exists() and not profile_path.exists():
            destination.unlink()
        raise
    return destination


def _validate_identity_transfer(*, value: object) -> None:
    """Validate the versioned same-customer second-peer transfer object."""
    if not isinstance(value, dict) or set(value) != {
        "protocol",
        "identity",
        "entitlement_id",
        "enrollment_url",
        "relay_peers",
    }:
        raise RSSAuthenticationError("RSS identity transfer is invalid")
    if value.get("protocol") != RSS_IDENTITY_TRANSFER_PROTOCOL:
        raise RSSAuthenticationError("RSS identity transfer version is invalid")
    entitlement_id = value.get("entitlement_id")
    enrollment_url = value.get("enrollment_url")
    relay_peers = value.get("relay_peers")
    if not isinstance(entitlement_id, str) or not entitlement_id or len(entitlement_id) > 128:
        raise RSSAuthenticationError("RSS identity transfer entitlement is invalid")
    if not isinstance(enrollment_url, str) or not enrollment_url.startswith("https://"):
        raise RSSAuthenticationError("RSS identity transfer authority is invalid")
    if (
        not isinstance(relay_peers, list)
        or len(relay_peers) != 2
        or any(not isinstance(peer, str) or not peer for peer in relay_peers)
    ):
        raise RSSAuthenticationError("RSS identity transfer relay set is invalid")
    try:
        identity = json.dumps(value.get("identity"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RSSAuthenticationError("RSS identity transfer key is invalid") from exc
    _validate_key_payload(identity)


def store_rss_enrollment_token_file(*, path: str | Path, token: str) -> Path:
    """Store an RET atomically as mode 0600 without overwriting an existing token."""
    if not isinstance(token, str) or not token:
        raise RSSAuthenticationError("RSS Enrollment Token is required")
    destination = Path(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(token.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    return destination


def load_rss_relay_credentials_from_environment() -> RSSRelayClientCredentials | None:
    """Load opt-in RSS credentials from restricted files and non-secret IDs."""
    key_path = os.environ.get("SECKIT_RSS_AUTH_KEY_FILE", "").strip()
    entitlement_id = os.environ.get("SECKIT_RSS_ENTITLEMENT_ID", "").strip()
    connection_id = os.environ.get("SECKIT_RSS_CONNECTION_ID", "").strip()
    token_path = os.environ.get("SECKIT_RSS_ENROLLMENT_TOKEN_FILE", "").strip()
    enrollment_url = os.environ.get("SECKIT_RSS_ENROLLMENT_URL", "").strip()
    configured = any((key_path, entitlement_id, connection_id, token_path))
    if not configured:
        profile = _load_rss_profile()
        if profile is None:
            return None
        key_path = str(profile.get("key_file", ""))
        entitlement_id = str(profile.get("entitlement_id", ""))
        connection_id = str(profile.get("connection_id", ""))
        token_path = str(profile.get("enrollment_token_file", ""))
        enrollment_url = str(profile.get("enrollment_url", ""))
    if not key_path or not entitlement_id or not connection_id:
        raise RSSAuthenticationError("RSS authentication configuration is incomplete")
    try:
        record = json.loads(_read_restricted_file(Path(key_path)).decode("utf-8"))
        keypair = signing_keypair_from_record(record=record)
    except RSSAuthenticationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RSSAuthenticationError("RSS authentication key file is invalid") from exc
    token = None
    if token_path:
        try:
            token = _read_restricted_file(Path(token_path)).decode("utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise RSSAuthenticationError("RSS Enrollment Token file is invalid") from exc
        if not token:
            raise RSSAuthenticationError("RSS Enrollment Token file is empty")
    return RSSRelayClientCredentials(
        entitlement_id=entitlement_id,
        connection_id=connection_id,
        customer_private_key=keypair.private_key,
        customer_public_key=keypair.public_key,
        enrollment_token=token,
        enrollment_token_file=Path(token_path) if token_path else None,
        enrollment_url=enrollment_url or None,
    )


def perform_rss_https_enrollment(
    *,
    credentials: RSSRelayClientCredentials,
    ssl_context: ssl.SSLContext | None = None,
) -> None:
    """Consume an RET only through a server-authenticated TLS 1.3 endpoint."""
    if credentials.enrollment_token is None:
        raise RSSAuthenticationError("RSS Enrollment Token is required")
    if credentials.enrollment_url is None or not credentials.enrollment_url.startswith("https://"):
        raise RSSAuthenticationError("RSS enrollment URL must use HTTPS")
    context = ssl_context or ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    challenge_value = _https_json(
        credentials.enrollment_url.rstrip("/") + "/v1/enrollment/challenge",
        {"token": credentials.enrollment_token},
        context=context,
    )
    raw_challenge = challenge_value.get("challenge")
    if challenge_value.get("status") != "challenge" or not isinstance(raw_challenge, dict):
        raise RSSAuthenticationError("RSS enrollment challenge was rejected")
    challenge = RSSAuthenticationChallenge.from_mapping(
        raw_challenge,
        expected_protocol=RSS_ENROLLMENT_PROOF_PROTOCOL,
    )
    proof = build_rss_enrollment_proof(
        token=credentials.enrollment_token,
        challenge=challenge,
        customer_private_key=credentials.customer_private_key,
        customer_public_key=credentials.customer_public_key,
        connection_id=credentials.connection_id,
    )
    result = _https_json(
        credentials.enrollment_url.rstrip("/") + "/v1/enrollment/complete",
        {"token": credentials.enrollment_token, "proof": proof},
        context=context,
    )
    if (
        result.get("status") != "ok"
        or result.get("connection_id") != credentials.connection_id
        or result.get("entitlement_id") != credentials.entitlement_id
    ):
        raise RSSAuthenticationError("RSS enrollment was rejected")


def _https_json(url: str, value: Mapping[str, Any], *, context: ssl.SSLContext) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=15) as response:
            payload = response.read(64 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        # Never surface arbitrary provider bodies. Only this bounded, known
        # enrollment denial has a customer-safe classification.
        try:
            body = exc.read(1025)
            denied = json.loads(body) if len(body) <= 1024 else None
        except (OSError, UnicodeError, ValueError):
            denied = None
        if exc.code == 409 and denied == {"status": "denied", "reason": "device_capacity_exhausted"}:
            raise RSSAuthenticationError("RSS device capacity is fully provisioned") from exc
        raise RSSAuthenticationError("RSS enrollment request was rejected") from exc
    except OSError as exc:
        raise RSSAuthenticationError("RSS enrollment endpoint is unavailable") from exc
    if len(payload) > 64 * 1024:
        raise RSSAuthenticationError("RSS enrollment response is too large")
    return parse_rss_auth_response(payload)


def rss_auth_control_request(
    *,
    operation: str,
    token: str | None = None,
    entitlement_id: str | None = None,
    connection_id: str | None = None,
) -> dict[str, object]:
    """Build one bounded RSS authentication control request."""
    if operation != "session_challenge":
        raise RSSAuthenticationError("RSS authentication operation is unsupported")
    value: dict[str, object] = {
        "protocol": RSS_AUTH_CONTROL_PROTOCOL,
        "operation": operation,
    }
    if not isinstance(entitlement_id, str) or not entitlement_id:
        raise RSSAuthenticationError("RSS entitlement_id is required")
    value["entitlement_id"] = entitlement_id
    if not isinstance(connection_id, str) or not 1 <= len(connection_id) <= 256:
        raise RSSAuthenticationError("RSS connection_id is required")
    value["connection_id"] = connection_id
    return value


def build_rss_enrollment_proof(
    *,
    token: str,
    challenge: RSSAuthenticationChallenge,
    customer_private_key: bytes,
    customer_public_key: bytes,
    connection_id: str,
) -> dict[str, object]:
    """Bind this device ID and public key to an RET without exporting its private key."""
    if not isinstance(connection_id, str) or not 1 <= len(connection_id) <= 256:
        raise RSSAuthenticationError("RSS connection_id is invalid")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    message = _canonical(
        {
            "protocol": RSS_ENROLLMENT_PROOF_PROTOCOL,
            "challenge_id": challenge.challenge_id,
            "challenge": challenge.challenge,
            "token_hash": token_hash,
            "connection_id": connection_id,
            "customer_public_key": _encode(customer_public_key),
        }
    )
    return {
        "protocol": RSS_ENROLLMENT_PROOF_PROTOCOL,
        "challenge_id": challenge.challenge_id,
        "connection_id": connection_id,
        "customer_public_key": _encode(customer_public_key),
        "signature": _encode(sign_ed25519(customer_private_key, message)),
    }


def build_rss_session_proof(
    *,
    challenge: RSSAuthenticationChallenge,
    credentials: RSSRelayClientCredentials,
    transport_identity: str,
) -> dict[str, object]:
    """Build a session proof bound to the client's authenticated transport identity."""
    message = _canonical(
        {
            "protocol": RSS_SESSION_AUTH_PROTOCOL,
            "challenge_id": challenge.challenge_id,
            "challenge": challenge.challenge,
            "entitlement_id": credentials.entitlement_id,
            "peer_id": transport_identity,
            "connection_id": credentials.connection_id,
            "customer_public_key": _encode(credentials.customer_public_key),
        }
    )
    return {
        "protocol": RSS_SESSION_AUTH_PROTOCOL,
        "challenge_id": challenge.challenge_id,
        "entitlement_id": credentials.entitlement_id,
        "peer_id": transport_identity,
        "connection_id": credentials.connection_id,
        "customer_public_key": _encode(credentials.customer_public_key),
        "signature": _encode(sign_ed25519(credentials.customer_private_key, message)),
    }


def encode_rss_auth_frame(value: Mapping[str, Any]) -> bytes:
    """Encode one canonical length-prefixed RSS authentication JSON frame."""
    payload = _canonical(dict(value))
    if len(payload) > 64 * 1024:
        raise RSSAuthenticationError("RSS authentication frame is too large")
    return len(payload).to_bytes(4, "big") + payload


def parse_rss_auth_response(payload: bytes) -> dict[str, Any]:
    """Parse one RSS authentication response while rejecting duplicate keys."""
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RSSAuthenticationError("RSS authentication response is invalid") from exc
    if not isinstance(value, dict):
        raise RSSAuthenticationError("RSS authentication response must be an object")
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RSSAuthenticationError(f"duplicate RSS authentication field: {key}")
        value[key] = item
    return value


def _read_restricted_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RSSAuthenticationError("RSS credential file permissions are too broad")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise RSSAuthenticationError("RSS credential file owner is invalid")
        if metadata.st_size > 64 * 1024:
            raise RSSAuthenticationError("RSS credential file is too large")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read(64 * 1024 + 1)
    finally:
        os.close(descriptor)


def _validate_key_payload(payload: bytes) -> None:
    try:
        signing_keypair_from_record(record=json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RSSAuthenticationError("RSS authentication key file is invalid") from exc


def _write_restricted_new_file(path: Path, payload: bytes) -> Path:
    destination = path.expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        destination,
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
    return destination


def clear_consumed_rss_enrollment_token(*, token_path: Path) -> None:
    """Remove a consumed RET and atomically clear its path from the local profile."""
    profile_path = rss_client_profile_path()
    profile = _load_rss_profile()
    _read_restricted_file(token_path)
    consumed = token_path.with_name(f".{token_path.name}.consumed-{secrets.token_hex(8)}")
    os.replace(token_path, consumed)
    try:
        if profile is not None and profile.get("enrollment_token_file") == str(token_path):
            profile["enrollment_token_file"] = ""
            payload = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
            temporary = profile_path.with_name(f".{profile_path.name}.{os.getpid()}.tmp")
            _write_restricted_new_file(temporary, payload)
            os.replace(temporary, profile_path)
        consumed.unlink()
    except BaseException:
        if consumed.exists() and not token_path.exists():
            os.replace(consumed, token_path)
        raise


def _load_rss_profile() -> dict[str, Any] | None:
    path = rss_client_profile_path()
    if not path.exists():
        return None
    try:
        value = json.loads(_read_restricted_file(path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RSSAuthenticationError("RSS client profile is invalid") from exc
    if not isinstance(value, dict) or value.get("version") != 1:
        raise RSSAuthenticationError("RSS client profile version is invalid")
    return value


__all__ = [
    "RSS_AUTH_CONTROL_PROTOCOL",
    "RSS_AUTH_STREAM_PROTOCOL",
    "RSS_ENROLLMENT_PROOF_PROTOCOL",
    "RSS_IDENTITY_TRANSFER_PROTOCOL",
    "RSS_SESSION_AUTH_PROTOCOL",
    "RSS_SESSION_READY_PROTOCOL",
    "RSSAuthenticationChallenge",
    "RSSAuthenticationError",
    "RSSRelayClientCredentials",
    "build_rss_enrollment_proof",
    "build_rss_session_proof",
    "configure_rss_client",
    "clear_consumed_rss_enrollment_token",
    "create_rss_authentication_key_file",
    "encode_rss_auth_frame",
    "export_rss_authentication_identity",
    "import_rss_authentication_identity",
    "load_rss_relay_credentials_from_environment",
    "load_rss_relay_peers_from_profile",
    "parse_rss_auth_response",
    "perform_rss_https_enrollment",
    "rss_auth_control_request",
    "rss_client_profile_path",
    "store_rss_enrollment_token_file",
]
