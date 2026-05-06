"""Local host identity: Ed25519 (signing) + X25519 (Box) key material storage."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import nacl.public
import nacl.signing

from secrets_kit.registry import registry_dir

IDENTITY_PUBLIC_FORMAT = "seckit.identity_public"
IDENTITY_SECRET_VERSION = 1


class IdentityError(RuntimeError):
    """Identity storage or crypto operation failed."""


def identity_dir(*, home: Optional[Path] = None) -> Path:
    """Directory for host identity files."""
    return registry_dir(home=home) / "identity"


def identity_secret_path(*, home: Optional[Path] = None) -> Path:
    """Path to host secret key file (0600)."""
    return identity_dir(home=home) / "secret.json"


def _check_dir_perms(path: Path) -> None:
    if path.exists():
        mode = path.stat().st_mode & 0o777
        if mode > 0o700:
            raise IdentityError(f"unsafe permissions on {path}: {oct(mode)} (expected <= 0o700)")


def _atomic_write_json(*, path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="identity-", suffix=".json", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@dataclass(frozen=True)
class HostIdentity:
    """Loaded host identity (secret material in memory — do not log)."""

    host_id: str
    signing_key: nacl.signing.SigningKey
    box_private: nacl.public.PrivateKey

    @property
    def verify_key(self) -> nacl.signing.VerifyKey:
        return self.signing_key.verify_key

    @property
    def box_public(self) -> nacl.public.PublicKey:
        return self.box_private.public_key

    def signing_fingerprint_hex(self) -> str:
        """SHA256(raw Ed25519 verify key bytes), lowercase hex."""
        raw = bytes(self.verify_key)
        return hashlib.sha256(raw).hexdigest()

    def export_public_payload(self) -> Dict[str, Any]:
        """Public bundle for `seckit peer add` / transport."""
        return {
            "format": IDENTITY_PUBLIC_FORMAT,
            "version": 1,
            "host_id": self.host_id,
            "signing_public": base64.standard_b64encode(bytes(self.verify_key)).decode("ascii"),
            "box_public": base64.standard_b64encode(bytes(self.box_public)).decode("ascii"),
        }


def parse_identity_public(payload: Dict[str, Any]) -> tuple[str, nacl.signing.VerifyKey, nacl.public.PublicKey]:
    """Parse exported public identity JSON; return (host_id, verify_key, box_public)."""
    fmt = str(payload.get("format", ""))
    if fmt != IDENTITY_PUBLIC_FORMAT:
        raise IdentityError(f"unsupported identity public format: {fmt!r}")
    if int(payload.get("version", 0)) != 1:
        raise IdentityError("unsupported identity public version")
    host_id = str(payload["host_id"])
    sp = base64.standard_b64decode(str(payload["signing_public"]).encode("ascii"))
    bp = base64.standard_b64decode(str(payload["box_public"]).encode("ascii"))
    if len(sp) != 32 or len(bp) != 32:
        raise IdentityError("invalid public key length")
    vk = nacl.signing.VerifyKey(sp)
    bk = nacl.public.PublicKey(bp)
    return host_id, vk, bk


def load_identity_public_file(path: Path) -> tuple[str, nacl.signing.VerifyKey, nacl.public.PublicKey]:
    """Load `seckit identity export` JSON from disk."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise IdentityError("identity export must be a JSON object")
    return parse_identity_public(payload)


def fingerprint_from_verify_key(verify_key: nacl.signing.VerifyKey) -> str:
    """Hex fingerprint for peer registry keys (same as HostIdentity.signing_fingerprint_hex)."""
    raw = bytes(verify_key)
    return hashlib.sha256(raw).hexdigest()


def init_identity(*, force: bool = False, home: Optional[Path] = None) -> HostIdentity:
    """Create a new host identity on disk. Fails if exists unless force=True."""
    d = identity_dir(home=home)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    _check_dir_perms(d)
    path = identity_secret_path(home=home)
    if path.exists() and not force:
        raise IdentityError(f"identity already exists: {path} (use --force to replace)")
    host_id = str(uuid.uuid4())
    sk = nacl.signing.SigningKey.generate()
    bk = nacl.public.PrivateKey.generate()
    secret_payload = {
        "version": IDENTITY_SECRET_VERSION,
        "host_id": host_id,
        "signing_seed": base64.standard_b64encode(bytes(sk.encode())).decode("ascii"),
        "box_secret": base64.standard_b64encode(bytes(bk.encode())).decode("ascii"),
    }
    _atomic_write_json(path=path, payload=secret_payload)
    os.chmod(path, 0o600)
    return load_identity(home=home)


def load_identity(*, home: Optional[Path] = None) -> HostIdentity:
    """Load host identity from disk."""
    path = identity_secret_path(home=home)
    if not path.exists():
        raise IdentityError(f"no host identity; run: seckit identity init ({path})")
    mode = path.stat().st_mode & 0o777
    if mode > 0o600:
        raise IdentityError(f"unsafe permissions on {path}: {oct(mode)}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if int(payload.get("version", 0)) != IDENTITY_SECRET_VERSION:
        raise IdentityError("unsupported identity secret version")
    host_id = str(payload["host_id"])
    seed = base64.standard_b64decode(str(payload["signing_seed"]).encode("ascii"))
    bsec = base64.standard_b64decode(str(payload["box_secret"]).encode("ascii"))
    if len(seed) != 32 or len(bsec) != 32:
        raise IdentityError("corrupt identity secret key material")
    return HostIdentity(
        host_id=host_id,
        signing_key=nacl.signing.SigningKey(seed),
        box_private=nacl.public.PrivateKey(bsec),
    )


def export_public_identity(*, out: Optional[Path] = None, home: Optional[Path] = None) -> Dict[str, Any]:
    """Return public payload; optionally write to path."""
    ident = load_identity(home=home)
    pub = ident.export_public_payload()
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(pub, indent=2, sort_keys=True) + "\n"
        out.write_text(text, encoding="utf-8")
        os.chmod(out, 0o644)
    return pub
