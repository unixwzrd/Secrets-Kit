"""
secrets_kit.cli.install_acceptance

Post-install acceptance test: ephemeral secret CRUD per platform backends.

- macOS: keychain + sqlite
- Linux: sqlite only
"""

from __future__ import annotations

import platform as platform_mod
import shutil
import sys
from pathlib import Path
from typing import Any, Optional

from secrets_kit.backends.common import BACKEND_KEYCHAIN, BACKEND_SQLITE, BackendError
from secrets_kit.backends.dispatch import (
    delete_secret_entry,
    list_secret_metadata,
    read_secret_value,
    secret_exists_for_backend,
    write_secret,
)
from secrets_kit.backends.keychain import (
    check_security_cli,
    delete_keychain,
    keychain_accessible,
    keychain_path as resolve_keychain_path,
    make_temp_keychain,
)
from secrets_kit.backends.sqlite import SQLiteBackendError, require_sqlite_developer_mode
from secrets_kit.models import EntryMetadata
from secrets_kit.registry import delete_metadata, upsert_metadata

ACCEPTANCE_SERVICE = "__seckit_test__"
ACCEPTANCE_ACCOUNT = "__seckit_test__"
ACCEPTANCE_NAME = "ACCEPTANCE_PROBE"
_ACCEPTANCE_KEYCHAIN_PASSWORD = "seckit-acceptance-test"
_SQLITE_DEV_MODE = True
_ACCEPTANCE_FIXTURES = """
ACCEPTANCE_PROBE|seckit_acceptance_v1|seckit_acceptance_v2
ACCEPTANCE_TOKEN|token_v1_123|token_v2_456
ACCEPTANCE_CONFIG|config_v1_enabled|config_v2_enabled
"""


def _acceptance_meta() -> EntryMetadata:
    return EntryMetadata(
        name=ACCEPTANCE_NAME,
        service=ACCEPTANCE_SERVICE,
        account=ACCEPTANCE_ACCOUNT,
        entry_type="secret",
        entry_kind="generic",
        source="acceptance-test",
    )

def _fixture_rows() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for raw in _ACCEPTANCE_FIXTURES.strip().splitlines():
        name, initial, updated = (part.strip() for part in raw.split("|", 2))
        rows.append((name, initial, updated))
    return rows


def _platform_backends() -> list[str]:
    if sys.platform == "darwin":
        return [BACKEND_KEYCHAIN, BACKEND_SQLITE]
    return [BACKEND_SQLITE]


def _preflight_issues() -> list[str]:
    issues: list[str] = []
    backends = _platform_backends()
    if BACKEND_SQLITE in backends:
        try:
            require_sqlite_developer_mode(sqlite_dev_mode=_SQLITE_DEV_MODE)
        except BackendError as exc:
            issues.append(f"sqlite: {exc}")
    if BACKEND_KEYCHAIN in backends:
        if not check_security_cli():
            issues.append("keychain: macOS keychain backend requires the security CLI")
    return issues


def _ensure_keychain_for_acceptance() -> tuple[Optional[str], Optional[dict[str, str]]]:
    """Use login/default keychain when usable; else create an isolated temp keychain."""
    target = resolve_keychain_path()
    if Path(target).is_file() and keychain_accessible(path=target):
        return None, None
    fixture = make_temp_keychain(password=_ACCEPTANCE_KEYCHAIN_PASSWORD)
    return fixture["path"], fixture


def _cleanup_temp_keychain(fixture: Optional[dict[str, str]]) -> None:
    if not fixture:
        return
    try:
        delete_keychain(path=fixture["path"])
    except BackendError:
        pass
    try:
        shutil.rmtree(fixture["directory"], ignore_errors=True)
    except OSError:
        pass


def _cleanup_test_secret(
    *,
    backend: str,
    name: str = ACCEPTANCE_NAME,
    keychain_path: Optional[str] = None,
) -> None:
    meta = _acceptance_meta()
    meta.name = name
    sqlite_dev_mode = backend == BACKEND_SQLITE
    try:
        if secret_exists_for_backend(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=name,
            backend=backend,
            keychain_path=keychain_path,
            sqlite_dev_mode=sqlite_dev_mode,
        ):
            delete_secret_entry(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=name,
                metadata=meta,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
    except (BackendError, SQLiteBackendError):
        pass
    try:
        delete_metadata(
            service=ACCEPTANCE_SERVICE,
            account=ACCEPTANCE_ACCOUNT,
            name=name,
        )
    except Exception:
        pass


def _run_backend_crud_acceptance(
    *,
    backend: str,
    keychain_path: Optional[str] = None,
) -> dict[str, Any]:
    """Run CRUD acceptance for one backend; always cleanup test artifacts."""
    label = backend
    steps: list[str] = []
    issues: list[str] = []
    sqlite_dev_mode = backend == BACKEND_SQLITE
    meta = _acceptance_meta()

    def step(name: str) -> None:
        steps.append(f"{label}:{name}")

    def issue(message: str) -> None:
        issues.append(f"{label}: {message}")

    try:
        for fixture_name, initial_value, updated_value in _fixture_rows():
            meta.name = fixture_name
            _cleanup_test_secret(
                backend=backend,
                name=fixture_name,
                keychain_path=keychain_path,
            )

            write_secret(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=fixture_name,
                value=initial_value,
                metadata=meta,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            upsert_metadata(metadata=meta)
            step(f"{fixture_name}:create")

            value = read_secret_value(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=fixture_name,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            if value != initial_value:
                issue(f"{fixture_name}: read after create mismatch")
            else:
                step(f"{fixture_name}:read")

            write_secret(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=fixture_name,
                value=updated_value,
                metadata=meta,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            upsert_metadata(metadata=meta)
            step(f"{fixture_name}:update")

            value = read_secret_value(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=fixture_name,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            if value != updated_value:
                issue(f"{fixture_name}: read after update mismatch")
            else:
                step(f"{fixture_name}:verify_update")

            listed = list_secret_metadata(
                backend=backend,
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            if not any(item.name == fixture_name for item in listed):
                issue(f"{fixture_name}: list did not include secret")
            else:
                step(f"{fixture_name}:list")

            delete_secret_entry(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=fixture_name,
                metadata=meta,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            delete_metadata(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=fixture_name,
            )
            step(f"{fixture_name}:delete")

            if secret_exists_for_backend(
                service=ACCEPTANCE_SERVICE,
                account=ACCEPTANCE_ACCOUNT,
                name=fixture_name,
                backend=backend,
                keychain_path=keychain_path,
                sqlite_dev_mode=sqlite_dev_mode,
            ):
                issue(f"{fixture_name}: verify_delete failed")
            else:
                step(f"{fixture_name}:verify_delete")
    except (BackendError, SQLiteBackendError) as exc:
        issue(str(exc))
    finally:
        for fixture_name, _, _ in _fixture_rows():
            _cleanup_test_secret(
                backend=backend,
                name=fixture_name,
                keychain_path=keychain_path,
            )

    result: dict[str, Any] = {
        "ok": not issues,
        "steps": steps,
        "issues": issues,
    }
    if backend == BACKEND_KEYCHAIN and keychain_path:
        result["keychain_path"] = keychain_path
    return result


def run_acceptance_test() -> dict[str, Any]:
    """
    Run platform acceptance suites (keychain on macOS, sqlite everywhere).

    Returns:
        Aggregate JSON result with per-backend outcomes.
    """
    platform_name = platform_mod.system().lower()
    backends = _platform_backends()
    steps: list[str] = []
    issues: list[str] = []
    backend_results: dict[str, Any] = {}

    preflight = _preflight_issues()
    if preflight:
        return {
            "ok": False,
            "platform": platform_name,
            "backends": backends,
            "steps": steps,
            "issues": preflight,
            "backend_results": backend_results,
            "namespace": {
                "service": ACCEPTANCE_SERVICE,
                "account": ACCEPTANCE_ACCOUNT,
                "name": ACCEPTANCE_NAME,
            },
        }

    for backend in backends:
        keychain_path: Optional[str] = None
        temp_keychain_fixture: Optional[dict[str, str]] = None
        try:
            if backend == BACKEND_KEYCHAIN:
                keychain_path, temp_keychain_fixture = _ensure_keychain_for_acceptance()
                if temp_keychain_fixture is not None:
                    steps.append("keychain:fixture")
            suite = _run_backend_crud_acceptance(
                backend=backend,
                keychain_path=keychain_path,
            )
            backend_results[backend] = suite
            steps.extend(suite.get("steps", []))
            issues.extend(suite.get("issues", []))
        except BackendError as exc:
            issues.append(f"{backend}: {exc}")
            backend_results[backend] = {"ok": False, "steps": [], "issues": [str(exc)]}
        finally:
            if backend == BACKEND_KEYCHAIN:
                _cleanup_temp_keychain(temp_keychain_fixture)

    return {
        "ok": not issues,
        "platform": platform_name,
        "backends": backends,
        "steps": steps,
        "issues": issues,
        "backend_results": backend_results,
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
