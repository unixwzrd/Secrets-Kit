"""Shared code activation never restores or rewrites per-user stores."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from secrets_kit.shared_runtime import SharedRuntimeError, activate_shared_generation


class SharedRuntimeTest(unittest.TestCase):
    def _runtime(self, root: Path) -> tuple[Path, Path]:
        prefix = root / "shared"
        (prefix / "config").mkdir(parents=True)
        runtime = prefix / "runtime"
        runtime.mkdir(parents=True)
        old = runtime / "runtime-old"
        new = runtime / "runtime-new"
        old.mkdir()
        new.mkdir()
        (runtime / "current").symlink_to(old)
        return prefix, new

    def test_failed_user_restart_restores_previous_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix, candidate = self._runtime(Path(tmp))
            old = (prefix / "runtime/current").resolve()
            calls: list[tuple[str, tuple[str, ...]]] = []

            def user_command(username: str, command: list[str]) -> str:
                calls.append((username, tuple(command[-2:])))
                if username == "bob" and command[-2:] == ["daemon", "restart"] and len(calls) < 5:
                    raise SharedRuntimeError("simulated restart failure")
                if command[-1] == "--version":
                    return "seckit 2.0.1b14"
                return ""

            with (
                mock.patch("secrets_kit.shared_runtime._require_admin_prefix"),
                mock.patch("secrets_kit.shared_runtime._locked_config", return_value=nullcontext()),
                mock.patch("secrets_kit.shared_runtime._generation_path", side_effect=lambda _p, name: prefix / "runtime" / name),
                mock.patch("secrets_kit.shared_runtime._registered_users", return_value=["alice", "bob"]),
                mock.patch("secrets_kit.shared_runtime._user_membership"),
                mock.patch("secrets_kit.shared_runtime._service_uses_shared_launcher"),
                mock.patch("secrets_kit.shared_runtime._user_command", side_effect=user_command),
                mock.patch("secrets_kit.shared_runtime.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="seckit 2.0.1b14\n")),
            ):
                with self.assertRaisesRegex(SharedRuntimeError, "previous code restored"):
                    activate_shared_generation(prefix=prefix, generation_name=candidate.name)
            self.assertEqual((prefix / "runtime/current").resolve(), old)
            self.assertIn(("alice", ("daemon", "restart")), calls)

    def test_success_switches_once_and_checks_each_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix, candidate = self._runtime(Path(tmp))
            with (
                mock.patch("secrets_kit.shared_runtime._require_admin_prefix"),
                mock.patch("secrets_kit.shared_runtime._locked_config", return_value=nullcontext()),
                mock.patch("secrets_kit.shared_runtime._generation_path", side_effect=lambda _p, name: prefix / "runtime" / name),
                mock.patch("secrets_kit.shared_runtime._registered_users", return_value=["alice"]),
                mock.patch("secrets_kit.shared_runtime._user_membership"),
                mock.patch("secrets_kit.shared_runtime._service_uses_shared_launcher"),
                mock.patch("secrets_kit.shared_runtime._user_command", side_effect=lambda _u, command: "seckit 2.0.1b14" if command[-1] == "--version" else ""),
                mock.patch("secrets_kit.shared_runtime.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="seckit 2.0.1b14\n")),
            ):
                result = activate_shared_generation(prefix=prefix, generation_name=candidate.name)
            self.assertEqual((prefix / "runtime/current").resolve(), candidate.resolve())
            self.assertEqual(result["users"], ["alice"])


if __name__ == "__main__":
    unittest.main()
