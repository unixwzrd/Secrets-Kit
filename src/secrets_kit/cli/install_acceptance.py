"""
secrets_kit.cli.install_acceptance

Post-install acceptance test: ephemeral secret CRUD in a dedicated namespace.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from secrets_kit.backends.common import (
    BACKEND_KEYCHAIN,
    BACKEND_SQLITE,
    BackendError,
    normalize_backend,
)
from secrets_kit.backends.sqlite import (
    SQLiteBackendError,
    is_sqlite_backend,
    require_sqlite_developer_mode,
)
from secrets_kit.backends.dispatch import (
    delete_secret_entry,
    list_secret_metadata,
    read_secret_value,
    secret_exists_for_backend,
    write_secret,
)
from secrets_kit.backends.keychain import check_security_cli
from secrets_kit.cli.defaults import _load_defaults
from secrets_kit.models import EntryMetadata
from secrets_kit.registry import delete_metadata, upsert_metadata

ACCEPTANCE_SERVICE = "__seckit_test__"
ACCEPTANCE_ACCOUNT = "__seckit_test__"
ACCEPTANCE_NAME = "ACCEPTANCE_PROBE"
_INITIAL_VALUE = "seckit_acceptance_v1"
_UPDATED_VALUE = "seckit_acceptance_v2"


def _resolve_backend() -> tuple[str, bool, list[str]]:
    issues: list[str] = []
    defaults = _load_defaults()
    raw = defaults.get("backend")
    backend = normalize_backend(str(raw)) if raw else (
        BACKEND_KEYCHAIN if sys.platform == "darwin" else BACKEND_SQLITE
    )
    sqlite_dev_mode = False
    if is_sqlite_backend(backend=backend):
        sqlite_dev_mode = True
        try:
            require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
        except BackendError as exc:
            issues.append(str(exc))
    elif platform.system().lower() == "darwin" and not check_security_cli():
        issues.append("macOS keychain backend requires the security CLI")
    return backend, sqlite_dev_mode, issues


def _cleanup_test_secret(
    *,
    backend: str,
    sqlite_dev_mode: bool,
) -> None:
    meta = EntryMetadata(
        name=ACCEPTANCE_NAME,
        service=ACCEPTANCE_SERVICE,
        account=ACCEPTANCE_ACCOUNT,
        source="acceptance-test",
    )
    try:
        if secret_exists_for_backend(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        ):
            delete_secret_entry(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=ACCEPTANCE_NAME,
                metadata=meta,
                backend=backend,
                sqlite_dev_mode=sqlite_dev_mode,
            )
    except (BackendError, SQLiteBackendError):
        pass
    try:
        delete_metadata(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
        )
    except Exception:
        pass


def run_acceptance_test() -> dict[str, Any]:
    """
    Run ephemeral secret CRUD in ``__seckit_test__``; always removes test artifacts.

    Returns:
        Dict with ok, steps, issues, backend, and namespace fields.
    """
    steps: list[str] = []
    issues: list[str] = []
    backend, sqlite_dev_mode, preflight_issues = _resolve_backend()
    issues.extend(preflight_issues)
    if issues:
        return {
            "ok": False,
            "steps": steps,
            "issues": issues,
            "backend": backend,
            "namespace": {
                "service": ACCEPTANCE_SERVICE,
                "account": ACCEPTANCE_ACCOUNT,
                "name": ACCEPTANCE_NAME,
            },
        }

    meta = EntryMetadata(
        name=ACCEPTANCE_NAME,
        service=ACCEPTANCE_SERVICE,
        account=ACCEPTANCE_ACCOUNT,
        entry_type="secret",
        entry_kind="generic",
        source="acceptance-test",
    )

    try:
        _cleanup_test_secret(backend=backend, sqlite_dev_mode=sqlite_dev_mode)

        write_secret(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
            value=_INITIAL_VALUE,
            metadata=meta,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        upsert_metadata(metadata=meta)
        steps.append("create")

        value = read_secret_value(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        if value != _INITIAL_VALUE:
            issues.append("read after create: value mismatch")
        else:
            steps.append("read")

        write_secret(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
            value=_UPDATED_VALUE,
            metadata=meta,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        upsert_metadata(metadata=meta)
        steps.append("update")

        value = read_secret_value(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        if value != _UPDATED_VALUE:
            issues.append("read after update: value mismatch")
        else:
            steps.append("verify_update")

        listed = list_secret_metadata(
            backend=backend,
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        if not any(item.name == ACCEPTANCE_NAME for item in listed):
            issues.append("list: test secret not found")
        else:
            steps.append("list")

        delete_secret_entry(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
            metadata=meta,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        delete_metadata(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
        )
        steps.append("delete")

        if secret_exists_for_backend(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=ACCEPTANCE_NAME,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        ):
            issues.append("verify_delete: secret still present")
        else:
            steps.append("verify_delete")
    except (BackendError, SQLiteBackendError) as exc:
        issues.append(str(exc))
    finally:
        _cleanup_test_secret(backend=backend, sqlite_dev_mode=sqlite_dev_mode)

    return {
        "ok": not issues,
        "steps": steps,
        "issues": issues,
        "backend": backend,
        "namespace": {
            "service": ACCEPTANCE_SERVICE,
            "account": ACCEPTANCE_ACCOUNT,
            "name": ACCEPTANCE_NAME,
        },
    }


__all__ = [
    "ACCEPTANCE_ACCOUNT",
    "ACCEPTANCE_NAME",
    "ACCEPTANCE_SERVICE",
    "run_acceptance_test",
]
