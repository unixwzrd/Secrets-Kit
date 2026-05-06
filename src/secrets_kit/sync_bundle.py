"""Signed + encrypted peer bundle format (PyNaCl only; no network)."""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple

import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils

from secrets_kit.identity import HostIdentity, fingerprint_from_verify_key
from secrets_kit.models import now_utc_iso

BUNDLE_FORMAT = "seckit.peer_bundle"
BUNDLE_VERSION = 1

# Manifest: unknown keys are rejected unless they begin with "x_" (experimental / forward-compat
# annotations that MUST NOT alter crypto or trust — see docs/PEER_SYNC.md).
#
# Security-sensitive keys are the required v1 fields below plus anything that would change
# algorithms or signed-object shape; new algorithm IDs or alternate payload layouts MUST bump
# bundle version or use a new `format` — never accept unknown values for algorithm fields.
REQUIRED_MANIFEST_KEYS = frozenset(
    {
        "box_public",
        "bundle_version",
        "created_at",
        "entry_count",
        "signer_host_id",
        "signer_fingerprint",
        "signing_public",
        "inner_aead",
        "inner_encoding",
        "wrap",
    }
)

INNER_AEAD_V1 = "nacl-secretbox-xsalsa20-poly1305"
INNER_ENCODING_V1 = "json-utf8"
WRAP_V1 = "nacl-box-xsalsa20-poly1305"


class SyncBundleError(RuntimeError):
    """Bundle build, verify, or decrypt failed."""


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _b64e(raw: bytes) -> str:
    return base64.standard_b64encode(raw).decode("ascii")


def _b64d(label: str, value: str) -> bytes:
    try:
        return base64.standard_b64decode(value.encode("ascii"))
    except binascii.Error as exc:
        raise SyncBundleError(f"invalid base64 ({label})") from exc


def _validate_manifest_keys(manifest: Mapping[str, Any]) -> None:
    missing = REQUIRED_MANIFEST_KEYS - manifest.keys()
    if missing:
        raise SyncBundleError(f"bundle manifest missing keys: {sorted(missing)}")
    for key in manifest:
        if key in REQUIRED_MANIFEST_KEYS:
            continue
        if str(key).startswith("x_"):
            continue
        raise SyncBundleError(f"unsupported manifest key {key!r} (unknown keys must use x_ prefix)")


def _normalize_manifest_v1(manifest: MutableMapping[str, Any]) -> None:
    """Validate required v1 manifest fields; reject unknown algorithm/layout values."""
    if int(manifest["bundle_version"]) != BUNDLE_VERSION:
        raise SyncBundleError("unsupported bundle_version")
    if manifest.get("inner_aead") != INNER_AEAD_V1:
        raise SyncBundleError(f"unsupported inner_aead: {manifest.get('inner_aead')!r}")
    if manifest.get("inner_encoding") != INNER_ENCODING_V1:
        raise SyncBundleError(f"unsupported inner_encoding: {manifest.get('inner_encoding')!r}")
    if manifest.get("wrap") != WRAP_V1:
        raise SyncBundleError(f"unsupported wrap: {manifest.get('wrap')!r}")
    sp = _b64d("signing_public", str(manifest["signing_public"]))
    bp = _b64d("box_public", str(manifest["box_public"]))
    if len(sp) != 32 or len(bp) != 32:
        raise SyncBundleError("invalid public key length in manifest")
    try:
        uuid.UUID(str(manifest["signer_host_id"]))
    except ValueError as exc:
        raise SyncBundleError("invalid signer_host_id") from exc
    fp = str(manifest["signer_fingerprint"])
    vk = nacl.signing.VerifyKey(sp)
    if fingerprint_from_verify_key(vk) != fp:
        raise SyncBundleError("signer_fingerprint does not match signing_public")


def signing_input_bytes(*, manifest: Mapping[str, Any], wrapped_cek: Mapping[str, str], inner_ciphertext: str) -> bytes:
    """Deterministic payload bytes covered by the detached Ed25519 signature."""
    obj = {
        "inner_ciphertext": inner_ciphertext,
        "manifest": dict(manifest),
        "wrapped_cek": dict(wrapped_cek),
    }
    return _canon_json(obj).encode("utf-8")


def build_bundle(
    *,
    identity: HostIdentity,
    recipient_records: List[Tuple[str, nacl.public.PublicKey]],
    entries: List[Dict[str, Any]],
    domain_filter: Optional[List[str]] = None,
    manifest_extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a signed encrypted bundle.

    Args:
        identity: Local host identity (signer and box sender).
        recipient_records: ``(signing_fingerprint_hex, box_public_key)`` per recipient.
        entries: List of ``{"metadata": dict, "value": str, "origin_host": str}``.
        domain_filter: Domains used when selecting entries (recorded in inner plaintext).
        manifest_extras: Optional ``x_*`` manifest keys merged before signing.

    Returns:
        Complete bundle dict suitable for ``json.dumps``.
    """
    export_id = str(uuid.uuid4())
    created = now_utc_iso()
    inner_obj: Dict[str, Any] = {
        "created_at": created,
        "domain_filter": domain_filter or [],
        "entries": entries,
        "export_id": export_id,
        "origin_host": identity.host_id,
    }
    inner_plain = _canon_json(inner_obj).encode("utf-8")
    cek = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box_inner = nacl.secret.SecretBox(cek)
    inner_cipher = box_inner.encrypt(inner_plain)
    inner_b64 = _b64e(inner_cipher)

    wrapped: Dict[str, str] = {}
    for fp_hex, peer_box_pk in recipient_records:
        if fp_hex in wrapped:
            raise SyncBundleError(f"duplicate recipient fingerprint: {fp_hex}")
        shared = nacl.public.Box(identity.box_private, peer_box_pk)
        wrapped_blob = shared.encrypt(cek)
        wrapped[fp_hex] = _b64e(wrapped_blob)

    manifest: Dict[str, Any] = {
        "box_public": _b64e(bytes(identity.box_public)),
        "bundle_version": BUNDLE_VERSION,
        "created_at": created,
        "entry_count": len(entries),
        "inner_aead": INNER_AEAD_V1,
        "inner_encoding": INNER_ENCODING_V1,
        "signer_fingerprint": identity.signing_fingerprint_hex(),
        "signer_host_id": identity.host_id,
        "signing_public": _b64e(bytes(identity.verify_key)),
        "wrap": WRAP_V1,
    }
    if manifest_extras:
        for k, v in manifest_extras.items():
            if not str(k).startswith("x_"):
                raise SyncBundleError("manifest_extras keys must start with x_")
            manifest[k] = v
    _validate_manifest_keys(manifest)
    _normalize_manifest_v1(manifest)

    sig_msg = signing_input_bytes(manifest=manifest, wrapped_cek=wrapped, inner_ciphertext=inner_b64)
    sig = identity.signing_key.sign(sig_msg).signature

    return {
        "format": BUNDLE_FORMAT,
        "inner_ciphertext": inner_b64,
        "manifest": manifest,
        "signature": _b64e(sig),
        "version": BUNDLE_VERSION,
        "wrapped_cek": wrapped,
    }


def parse_bundle_file(text: str) -> Dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SyncBundleError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SyncBundleError("bundle top-level must be an object")
    if payload.get("format") != BUNDLE_FORMAT:
        raise SyncBundleError(f"unsupported bundle format: {payload.get('format')!r}")
    if int(payload.get("version", 0)) != BUNDLE_VERSION:
        raise SyncBundleError("unsupported bundle version")
    for key in ("manifest", "wrapped_cek", "inner_ciphertext", "signature"):
        if key not in payload:
            raise SyncBundleError(f"missing bundle field: {key}")
    return payload


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of structure + signature verification."""

    ok: bool
    signer_host_id: str
    signer_fingerprint: str
    entry_count: int
    message: str


def verify_bundle_structure(*, payload: Mapping[str, Any]) -> VerifyResult:
    """Validate manifest, signature, and ciphertext shape (no decryption)."""
    try:
        manifest_raw = payload["manifest"]
        if not isinstance(manifest_raw, dict):
            raise SyncBundleError("manifest must be object")
        manifest = dict(manifest_raw)
        _validate_manifest_keys(manifest)
        _normalize_manifest_v1(manifest)

        wrapped = payload["wrapped_cek"]
        if not isinstance(wrapped, dict):
            raise SyncBundleError("wrapped_cek must be object")
        inner_ciphertext = str(payload["inner_ciphertext"])
        sig = _b64d("signature", str(payload["signature"]))

        msg = signing_input_bytes(manifest=manifest, wrapped_cek=wrapped, inner_ciphertext=inner_ciphertext)
        vk = nacl.signing.VerifyKey(_b64d("signing_public", str(manifest["signing_public"])))
        vk.verify(msg, sig)
        return VerifyResult(
            ok=True,
            signer_host_id=str(manifest["signer_host_id"]),
            signer_fingerprint=str(manifest["signer_fingerprint"]),
            entry_count=int(manifest["entry_count"]),
            message="signature ok",
        )
    except (SyncBundleError, nacl.exceptions.BadSignatureError, KeyError, TypeError, ValueError) as exc:
        err = str(exc)
        if isinstance(exc, nacl.exceptions.BadSignatureError):
            err = "invalid signature"
        return VerifyResult(
            ok=False,
            signer_host_id="",
            signer_fingerprint="",
            entry_count=0,
            message=err,
        )


def inspect_bundle(*, payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Non-decrypting inspection: manifest summary + wrapped recipient fingerprints."""
    vr = verify_bundle_structure(payload=payload)
    wrapped = payload.get("wrapped_cek")
    keys = sorted(wrapped.keys()) if isinstance(wrapped, dict) else []
    return {
        "entry_count_manifest": vr.entry_count if vr.ok else None,
        "recipient_fingerprints": keys,
        "signature_ok": vr.ok,
        "signer_fingerprint": vr.signer_fingerprint,
        "signer_host_id": vr.signer_host_id,
        "verify_message": vr.message,
    }


def decrypt_bundle_for_recipient(
    *,
    payload: Mapping[str, Any],
    identity: HostIdentity,
    trusted_signer: nacl.signing.VerifyKey,
) -> Dict[str, Any]:
    """Verify signature and decrypt inner JSON for this recipient.

    Sender X25519 public key is read from the signed manifest. ``trusted_signer`` must match
    the manifest signing key (from the peer registry).
    """
    vr = verify_bundle_structure(payload=payload)
    if not vr.ok:
        raise SyncBundleError(vr.message)
    manifest = dict(payload["manifest"])
    vk = nacl.signing.VerifyKey(_b64d("signing_public", str(manifest["signing_public"])))
    if bytes(vk) != bytes(trusted_signer):
        raise SyncBundleError("signer public key does not match trusted peer record")

    sender_box = nacl.public.PublicKey(_b64d("box_public", str(manifest["box_public"])))

    fp_me = identity.signing_fingerprint_hex()
    wrapped = payload["wrapped_cek"]
    if not isinstance(wrapped, dict) or fp_me not in wrapped:
        raise SyncBundleError("bundle is not encrypted for this host (missing wrapped_cek slot)")

    box_rx = nacl.public.Box(identity.box_private, sender_box)
    cek = box_rx.decrypt(_b64d("wrapped_cek", wrapped[fp_me]))

    inner_cipher = _b64d("inner_ciphertext", str(payload["inner_ciphertext"]))
    plain = nacl.secret.SecretBox(cek).decrypt(inner_cipher)
    try:
        inner = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncBundleError(f"inner plaintext is not JSON: {exc}") from exc
    if not isinstance(inner, dict):
        raise SyncBundleError("inner payload must be object")
    return inner
