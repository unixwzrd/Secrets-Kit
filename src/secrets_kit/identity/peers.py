"""Trusted peer registry (public keys per alias)."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import nacl.public
import nacl.signing

from secrets_kit.identity.core import fingerprint_from_verify_key, load_identity_public_file
from secrets_kit.models.core import now_utc_iso
from secrets_kit.registry.core import RegistryError, registry_dir

PEERS_FILE_VERSION = 1


@dataclass(frozen=True)
class PeerRecord:
    """One trusted peer."""

    alias: str
    host_id: str
    signing_public_b64: str
    box_public_b64: str
    fingerprint: str
    trusted_at: str

    def verify_key(self) -> nacl.signing.VerifyKey:
        raw = _decode_b64(self.signing_public_b64, "signing_public")
        return nacl.signing.VerifyKey(raw)

    def box_public(self) -> nacl.public.PublicKey:
        raw = _decode_b64(self.box_public_b64, "box_public")
        return nacl.public.PublicKey(raw)


def _decode_b64(value: str, field: str) -> bytes:
    try:
        return base64.standard_b64decode(value.encode("ascii"))
    except Exception as exc:  # pragma: no cover - defensive
        raise RegistryError(f"invalid base64 for {field}: {exc}") from exc


def peers_path(*, home: Optional[Path] = None) -> Path:
    return registry_dir(home=home) / "peers.json"


def _atomic_write_peers(*, path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="peers-", suffix=".json", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _load_peers_db(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"version": PEERS_FILE_VERSION, "peers": []}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if int(payload.get("version", 0)) != PEERS_FILE_VERSION:
        raise RegistryError("unsupported peers.json version")
    peers = payload.get("peers")
    if not isinstance(peers, list):
        raise RegistryError("peers.json missing peers[]")
    return payload


def _persist_peers(path: Path, peers: List[Dict[str, Any]]) -> None:
    body = {"version": PEERS_FILE_VERSION, "peers": peers}
    _atomic_write_peers(path=path, payload=body)
    os.chmod(path, 0o600)


def list_peers(*, home: Optional[Path] = None) -> List[PeerRecord]:
    path = peers_path(home=home)
    payload = _load_peers_db(path)
    out: List[PeerRecord] = []
    for row in payload["peers"]:
        out.append(
            PeerRecord(
                alias=str(row["alias"]),
                host_id=str(row["host_id"]),
                signing_public_b64=str(row["signing_public"]),
                box_public_b64=str(row["box_public"]),
                fingerprint=str(row["fingerprint"]),
                trusted_at=str(row["trusted_at"]),
            )
        )
    return sorted(out, key=lambda p: p.alias.lower())


def get_peer(*, alias: str, home: Optional[Path] = None) -> PeerRecord:
    for peer in list_peers(home=home):
        if peer.alias == alias:
            return peer
    raise RegistryError(f"unknown peer alias: {alias}")


def add_peer_from_file(*, alias: str, path: Path, home: Optional[Path] = None) -> PeerRecord:
    """Add or replace peer trust from `seckit identity export` JSON."""
    _validate_alias(alias)
    host_id, vk, bk = load_identity_public_file(path)
    try:
        uuid.UUID(host_id)
    except ValueError as exc:
        raise RegistryError(f"invalid host_id in export: {host_id}") from exc
    sp_b64 = _encode_b64(bytes(vk))
    bp_b64 = _encode_b64(bytes(bk))
    fp = fingerprint_from_verify_key(vk)
    trusted_at = now_utc_iso()
    ppath = peers_path(home=home)
    if ppath.exists():
        mode = ppath.stat().st_mode & 0o777
        if mode > 0o600:
            raise RegistryError(f"unsafe permissions on {ppath}: {oct(mode)}")
    db = _load_peers_db(ppath)
    peers_raw: List[Dict[str, Any]] = list(db["peers"])
    new_row = {
        "alias": alias,
        "host_id": host_id,
        "signing_public": sp_b64,
        "box_public": bp_b64,
        "fingerprint": fp,
        "trusted_at": trusted_at,
    }
    replaced = False
    for idx, row in enumerate(peers_raw):
        if str(row["alias"]) == alias:
            peers_raw[idx] = new_row
            replaced = True
            break
    if not replaced:
        for row in peers_raw:
            if str(row["fingerprint"]) == fp and str(row["alias"]) != alias:
                raise RegistryError(
                    f"fingerprint already registered as {row['alias']!r}; remove it before re-adding"
                )
        peers_raw.append(new_row)
    _persist_peers(ppath, peers_raw)
    return PeerRecord(
        alias=alias,
        host_id=host_id,
        signing_public_b64=sp_b64,
        box_public_b64=bp_b64,
        fingerprint=fp,
        trusted_at=trusted_at,
    )


def _encode_b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def _validate_alias(alias: str) -> None:
    if not alias or "/" in alias or "\\" in alias or alias.strip() != alias:
        raise RegistryError("invalid peer alias (non-empty, no slashes, no surrounding whitespace)")
    if len(alias) > 128:
        raise RegistryError("peer alias too long")


def remove_peer(*, alias: str, home: Optional[Path] = None) -> bool:
    ppath = peers_path(home=home)
    if not ppath.exists():
        return False
    db = _load_peers_db(ppath)
    peers_raw: List[Dict[str, Any]] = list(db["peers"])
    new_list = [r for r in peers_raw if str(r["alias"]) != alias]
    if len(new_list) == len(peers_raw):
        return False
    _persist_peers(ppath, new_list)
    return True
