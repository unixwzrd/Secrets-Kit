"""
secrets_kit.cli.commands.doctor

Doctor command implementation.
"""

from __future__ import annotations

import argparse
import json

from secrets_kit.backends.dispatch import list_secret_metadata, sqlite_store
from secrets_kit.backends.keychain import BackendError, check_security_cli, doctor_roundtrip
from secrets_kit.backends.sqlite import SQLiteBackendError, is_sqlite_backend
from secrets_kit.cli.install_check import run_install_check
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.locale import msg
from secrets_kit.metadata.catalog_validation import (
    MetadataValidationReport,
    validate_metadata_against_catalog,
)
from secrets_kit.models import ValidationError
from secrets_kit.registry import (
    RegistryError,
    ensure_defaults_storage,
    registry_path,
)
from secrets_kit.registry.resolve import read_metadata, resolve_status
from secrets_kit.schemas.registry_store import load_schema_registry


def cmd_doctor(*, args: argparse.Namespace) -> int:
    if getattr(args, "install_check", False):
        result = run_install_check()
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result.get("ok"):
            return _fatal(message=msg("errors.install_check_failed"), code=1)
        return 0

    status = {
        "security_cli": False,
        "registry": False,
        "defaults": False,
        "keychain_roundtrip": False,
        "sqlite_roundtrip": False,
        "registry_path": None,
        "defaults_path": None,
        "missing_required_fields": [],
        "unknown_fields": [],
        "invalid_field_types": [],
        "normalization_candidates": [],
        "enumeration_limitations": [],
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
        path = registry_path()
        if not path.is_file():
            raise RegistryError(f"schema registry not found: {path}; run seckit init")
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
            sqlite_store().doctor_roundtrip()
            status["sqlite_roundtrip"] = True
        else:
            doctor_roundtrip(path=_keychain_arg(args), backend=backend)
            status["keychain_roundtrip"] = True
    except (BackendError, SQLiteBackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        catalog = load_schema_registry(backend=backend, keychain_path=_keychain_arg(args))
        validation = MetadataValidationReport()
        warnings = []
        entries = list_secret_metadata(backend=backend, keychain_path=_keychain_arg(args))
        for meta in sorted(entries, key=lambda item: (item.service, item.account, item.name)):
            resolved = read_metadata(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                path=_keychain_arg(args),
                backend=backend,
            )
            validation.extend(
                validate_metadata_against_catalog(metadata=meta, catalog=catalog)
            )
            if resolved:
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
        status.update(validation.to_status_dict())
        status["rotation_warnings"] = warnings
    except (RegistryError, ValidationError, BackendError, SQLiteBackendError) as exc:
        status["enumeration_limitations"] = [str(exc)]

    print(json.dumps(status, indent=2, sort_keys=True))
    if status["missing_required_fields"] or status["unknown_fields"] or status["invalid_field_types"]:
        return _fatal(message=msg("errors.metadata_keychain_drift"), code=1)
    return 0


__all__ = ["cmd_doctor"]
