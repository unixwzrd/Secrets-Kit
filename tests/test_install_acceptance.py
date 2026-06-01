"""Tests for post-install acceptance verification."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from secrets_kit.cli.commands.doctor import cmd_doctor
from secrets_kit.cli.install_acceptance import (
    ACCEPTANCE_NAME,
    ACCEPTANCE_SERVICE,
    run_acceptance_test,
)


class InstallAcceptanceTest(unittest.TestCase):
    def test_run_acceptance_test_structure(self) -> None:
        with mock.patch(
            "secrets_kit.cli.install_acceptance._resolve_backend",
            return_value=("sqlite", True, ["blocked for unit test"]),
        ):
            result = run_acceptance_test()
        self.assertFalse(result["ok"])
        self.assertEqual(result["namespace"]["service"], ACCEPTANCE_SERVICE)
        self.assertEqual(result["namespace"]["name"], ACCEPTANCE_NAME)

    def test_run_acceptance_test_happy_path(self) -> None:
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
                    account=ACCEPTANCE_SERVICE,
                )
            ]

        def fake_delete_secret_entry(**kwargs: object) -> None:
            state["exists"] = False

        def fake_secret_exists(**kwargs: object) -> bool:
            return state["exists"]

        with (
            mock.patch(
                "secrets_kit.cli.install_acceptance._resolve_backend",
                return_value=("sqlite", True, []),
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
            result = run_acceptance_test()

        self.assertTrue(result["ok"])
        self.assertIn("verify_delete", result["steps"])

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
                return_value={"ok": True, "steps": ["create"], "issues": []},
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
