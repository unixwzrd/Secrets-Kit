"""Tests for post-install acceptance verification."""

from __future__ import annotations

import json
import sys
import unittest
from unittest import mock

from secrets_kit.backends.common import BACKEND_KEYCHAIN, BACKEND_SQLITE
from secrets_kit.cli.commands.doctor import cmd_doctor
from secrets_kit.cli.install_acceptance import (
    ACCEPTANCE_ACCOUNT,
    ACCEPTANCE_NAME,
    ACCEPTANCE_SERVICE,
    _platform_backends,
    _run_backend_crud_acceptance,
    run_acceptance_test,
)


class InstallAcceptanceTest(unittest.TestCase):
    def test_platform_backends_linux(self) -> None:
        with mock.patch.object(sys, "platform", "linux"):
            self.assertEqual(_platform_backends(), [BACKEND_SQLITE])

    def test_platform_backends_darwin(self) -> None:
        with mock.patch.object(sys, "platform", "darwin"):
            self.assertEqual(_platform_backends(), [BACKEND_KEYCHAIN, BACKEND_SQLITE])

    def test_run_acceptance_test_preflight_failure(self) -> None:
        with mock.patch(
            "secrets_kit.cli.install_acceptance._preflight_issues",
            return_value=["sqlite: blocked"],
        ):
            result = run_acceptance_test()
        self.assertFalse(result["ok"])
        self.assertIn("sqlite: blocked", result["issues"])

    def test_run_acceptance_test_runs_all_platform_backends(self) -> None:
        suite_ok = {"ok": True, "steps": ["sqlite:create"], "issues": []}
        with (
            mock.patch(
                "secrets_kit.cli.install_acceptance._platform_backends",
                return_value=[BACKEND_KEYCHAIN, BACKEND_SQLITE],
            ),
            mock.patch("secrets_kit.cli.install_acceptance._preflight_issues", return_value=[]),
            mock.patch(
                "secrets_kit.cli.install_acceptance._ensure_keychain_for_acceptance",
                return_value=(None, None),
            ),
            mock.patch(
                "secrets_kit.cli.install_acceptance._run_backend_crud_acceptance",
                return_value=suite_ok,
            ) as run_suite,
            mock.patch("secrets_kit.cli.install_acceptance._cleanup_temp_keychain"),
        ):
            result = run_acceptance_test()
        self.assertTrue(result["ok"])
        self.assertEqual(run_suite.call_count, 2)
        self.assertIn(BACKEND_KEYCHAIN, result["backend_results"])
        self.assertIn(BACKEND_SQLITE, result["backend_results"])

    def test_run_backend_crud_acceptance_happy_path(self) -> None:
        state = {"value": "", "exists": False}

        def fake_write_secret(*, value: str, **kwargs: object) -> None:
            state["value"] = value
            state["exists"] = True

        def fake_read_secret_value(**kwargs: object) -> str:
            return state["value"]

        def fake_list_secret_metadata(**kwargs: object) -> list[object]:
            from secrets_kit.models import EntryMetadata

            if not state["exists"]:
                return []
            return [
                EntryMetadata(
                    name=ACCEPTANCE_NAME,
                    service=ACCEPTANCE_SERVICE,
                    account=ACCEPTANCE_ACCOUNT,
                )
            ]

        def fake_delete_secret_entry(**kwargs: object) -> None:
            state["exists"] = False

        def fake_secret_exists(**kwargs: object) -> bool:
            return state["exists"]

        with (
            mock.patch(
                "secrets_kit.cli.install_acceptance._fixture_rows",
                return_value=[(ACCEPTANCE_NAME, "v1", "v2")],
            ),
            mock.patch(
                "secrets_kit.cli.install_acceptance.write_secret",
                side_effect=fake_write_secret,
            ),
            mock.patch(
                "secrets_kit.cli.install_acceptance.read_secret_value",
                side_effect=fake_read_secret_value,
            ),
            mock.patch(
                "secrets_kit.cli.install_acceptance.list_secret_metadata",
                side_effect=fake_list_secret_metadata,
            ),
            mock.patch(
                "secrets_kit.cli.install_acceptance.secret_exists_for_backend",
                side_effect=fake_secret_exists,
            ),
            mock.patch("secrets_kit.cli.install_acceptance.upsert_metadata"),
            mock.patch(
                "secrets_kit.cli.install_acceptance.delete_secret_entry",
                side_effect=fake_delete_secret_entry,
            ),
            mock.patch("secrets_kit.cli.install_acceptance.delete_metadata"),
            mock.patch("secrets_kit.cli.install_acceptance._cleanup_test_secret"),
        ):
            result = _run_backend_crud_acceptance(backend=BACKEND_SQLITE)

        self.assertTrue(result["ok"])
        self.assertTrue(any(step.endswith(":verify_delete") for step in result["steps"]))

    def test_doctor_acceptance_test_flag(self) -> None:
        import argparse
        import io
        from contextlib import redirect_stderr, redirect_stdout

        args = argparse.Namespace(
            install_check=False,
            acceptance_test=True,
            backend=None,
            keychain=None,
            sqlite_dev_mode=False,
        )
        stdout = io.StringIO()
        with (
            mock.patch(
                "secrets_kit.cli.commands.doctor.run_acceptance_test",
                return_value={"ok": True, "steps": ["sqlite:create"], "issues": []},
            ),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            code = cmd_doctor(args=args)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
