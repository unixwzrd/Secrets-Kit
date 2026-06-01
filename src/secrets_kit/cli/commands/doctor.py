"""
secrets_kit.cli.commands.doctor

Doctor command implementation.
"""

from __future__ import annotations

import argparse
import json

from secrets_kit.backends.dispatch import secret_exists_for_backend, sqlite_store
from secrets_kit.backends.keychain import BackendError, check_security_cli, doctor_roundtrip
from secrets_kit.backends.sqlite import SQLiteBackendError, is_sqlite_backend
from secrets_kit.cli.install_acceptance import run_acceptance_test
from secrets_kit.cli.install_check import run_install_check
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.locale import msg
from secrets_kit.models import EntryMetadata
from secrets_kit.registry import (
    RegistryError,
    ensure_defaults_storage,
    ensure_registry_storage,
    load_registry,
)
from secrets_kit.registry.resolve import read_metadata, resolve_status


def cmd_doctor(*, args: argparse.Namespace) -> int:
    if getattr(args, "install_check", False):
        result = run_install_check()
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result.get("ok"):
            return _fatal(message=msg("errors.install_check_failed"), code=1)
        return 0

    if getattr(args, "acceptance_test", False):
        result = run_acceptance_test()
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result.get("ok"):
            return _fatal(message=msg("errors.acceptance_test_failed"), code=1)
        return 0

    status = {
        "security_cli": False,
        "registry": False,
        "defaults": False,
        "keychain_roundtrip": False,
        "sqlite_roundtrip": False,
        "registry_path": None,
        "defaults_path": None,
        "metadata_keychain_drift": [],
        "entries_using_registry_fallback": [],
        "rotation_warnings": [],
    }
    backend = _backend_arg(args)
    sqlite_backend = is_sqlite_backend(backend=backend)
    if sqlite_backend:
        status["security_cli"] = None
    elif check_security_cli():
        status["security_cli"] = True
    else:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=msg("errors.security_cli_not_found"), code=1)

    try:
        path = ensure_registry_storage()
        status["registry"] = True
        status["registry_path"] = str(path)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        dpath = ensure_defaults_storage()
        status["defaults"] = True
        status["defaults_path"] = str(dpath)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        if sqlite_backend:
            sqlite_store(sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False)).doctor_roundtrip()
            status["sqlite_roundtrip"] = True
        else:
            doctor_roundtrip(path=_keychain_arg(args), backend=backend)
            status["keychain_roundtrip"] = True
    except (BackendError, SQLiteBackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        entries = load_registry()
        drift = []
        fallback = []
        warnings = []
        for meta in sorted(
            entries.values(), key=lambda item: (item.service, item.account, item.name)
        ):
            exists = secret_exists_for_backend(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                backend=backend,
                keychain_path=_keychain_arg(args),
                sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
            )
            if not exists:
                if _keychain_arg(args) is not None:
                    continue
                drift.append(
                    {
                        "name": meta.name,
                        "service": meta.service,
                        "account": meta.account,
                    }
                )
                continue
            resolved = read_metadata(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                registry=entries,
                path=_keychain_arg(args),
                backend=backend,
                sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
            )
            if resolved and resolved["metadata_source"] == "registry-fallback":
                fallback.append(
                    {
                        "name": meta.name,
                        "service": meta.service,
                        "account": meta.account,
                    }
                )
            if resolved and isinstance(resolved["metadata"], EntryMetadata):
                entry_status = resolve_status(metadata=resolved["metadata"])
                if entry_status:
                    warnings.append(
                        {
                            "name": meta.name,
                            "service": meta.service,
                            "account": meta.account,
                            "status": entry_status,
                        }
                    )
        status["metadata_keychain_drift"] = drift
        status["entries_using_registry_fallback"] = fallback
        status["rotation_warnings"] = warnings
    except (RegistryError, BackendError, SQLiteBackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    print(json.dumps(status, indent=2, sort_keys=True))
    if status["metadata_keychain_drift"] or status["entries_using_registry_fallback"]:
        return _fatal(message=msg("errors.metadata_keychain_drift"), code=1)
    return 0


__all__ = ["cmd_doctor"]
