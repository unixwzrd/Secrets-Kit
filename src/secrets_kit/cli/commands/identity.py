"""
secrets_kit.cli.commands.identity

Host identity subcommands.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.interaction import _fatal
from secrets_kit.identity.core import (
    IdentityError,
    export_public_identity,
    identity_dir,
    identity_secret_path,
    init_identity,
    load_identity,
)


def cmd_identity_init(*, args: argparse.Namespace) -> int:
    """Generate host Ed25519/X25519 key material if it does not already exist.

    With ``--force``, existing keys are overwritten. Prints the host id and
    the path to the secret key file (never the secret itself).
    """
    try:
        ident = init_identity(force=args.force)
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {"host_id": ident.host_id, "secret_path": str(identity_secret_path())},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print("Host identity initialized.")
            print(f"host_id: {ident.host_id}")
            print(f"secret: {identity_secret_path()}")
        return 0
    except IdentityError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_identity_show(*, args: argparse.Namespace) -> int:
    """Display the local host identity (public keys and fingerprints only)."""
    try:
        ident = load_identity()
        payload = {
            "box_public_hex": bytes(ident.box_public).hex(),
            "host_id": ident.host_id,
            "identity_dir": str(identity_dir()),
            "signing_fingerprint": ident.signing_fingerprint_hex(),
        }
        if getattr(args, "json", False):
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"host_id: {payload['host_id']}")
            print(f"signing_fingerprint: {payload['signing_fingerprint']}")
            print(f"box_public_hex: {payload['box_public_hex']}")
            print(f"identity_dir: {payload['identity_dir']}")
        return 0
    except IdentityError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_identity_export(*, args: argparse.Namespace) -> int:
    """Write the host public identity JSON for sharing with peers.

    The output is safe to distribute; it contains only public keys and
    the host id. When ``--out`` is omitted the JSON is printed to stdout.
    """
    try:
        out = Path(args.out).expanduser() if getattr(args, "out", None) else None
        pub = export_public_identity(out=out)
        if getattr(args, "json", False) or out is None:
            print(json.dumps(pub, indent=2, sort_keys=True))
        else:
            print(f"wrote {out}")
        return 0
    except IdentityError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])
