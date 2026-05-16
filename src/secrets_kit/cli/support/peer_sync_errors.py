"""
secrets_kit.cli.support.peer_sync_errors

User-facing errors for peer sync and bundle workflows (no secret values).
"""

from __future__ import annotations

from secrets_kit.backends.security import BackendError
from secrets_kit.identity.core import IdentityError
from secrets_kit.registry.core import RegistryError
from secrets_kit.sync.bundle import SyncBundleError


def _peer_sync_cli_error(exc: BaseException) -> str:
    """User-facing hints for peer sync / bundle workflows (no secret values)."""
    if isinstance(exc, IdentityError):
        return "Peer sync: no host identity. Run: seckit identity init"
    if isinstance(exc, RegistryError):
        text = str(exc)
        if "unknown peer" in text.lower():
            return f"Peer sync: {text}. Run: seckit peer add <alias> <export.json>"
        return f"Peer sync: {text}"
    if isinstance(exc, SyncBundleError):
        msg = str(exc)
        if "missing wrapped_cek slot" in msg:
            return (
                "Peer sync: this bundle was not encrypted for this host (no wrapped CEK for your signing fingerprint). "
                "Ask the sender to run `seckit sync export` with `--peer` listing your machine's peer alias. "
                f"Detail: {msg}"
            )
        if "does not match trusted peer" in msg:
            return (
                "Peer sync: bundle signing key does not match `seckit peer show` for `--signer`. "
                "Fix the alias or re-add the sender from a fresh `seckit identity export`. "
                f"Detail: {msg}"
            )
        if msg == "invalid signature":
            return (
                "Peer sync: bundle signature invalid (tampered file, truncated transfer, or wrong document). "
                f"Detail: {msg}"
            )
        if (
            "not valid JSON" in msg
            or "top-level must be an object" in msg
            or "unsupported bundle format" in msg
            or "unsupported bundle version" in msg
            or "missing bundle field" in msg
        ):
            return f"Peer sync: file is not a valid peer bundle. Detail: {msg}"
        return f"Peer sync: bundle error. Detail: {msg}"
    if isinstance(exc, BackendError):
        return (
            f"Peer sync: secret backend error — {exc} "
            "(for SQLite: check --backend sqlite, --db, SECKIT_SQLITE_PASSPHRASE, SECKIT_SQLITE_UNLOCK)."
        )
    return str(exc)
