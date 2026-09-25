from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.status import cmd_status
from secrets_kit.cli.commands.upgrade import cmd_upgrade
from secrets_kit.cli.parser import build_parser
from secrets_kit.cli.update_check import (
    cached_update_available,
    check_for_update,
    download_release_installer,
)
from secrets_kit.cli.update_service import (
    _linux_definitions,
    _mac_definition,
    manage_update_service,
)


class _Response:
    def __init__(self, payload: object) -> None:
        self.payload = json.dumps(payload).encode()

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self.payload


def _release(tag: str, *, prerelease: bool) -> dict[str, object]:
    return {
        "draft": False,
        "prerelease": prerelease,
        "tag_name": tag,
        "assets": [{
            "name": "install.sh",
            "url": "https://api.github.com/repos/example/repo/releases/assets/7",
            "digest": "sha256:" + "1" * 64,
        }],
    }


class UpgradeTests(unittest.TestCase):
    def test_missing_receipt_does_not_guess_public_repository(self) -> None:
        with tempfile.TemporaryDirectory() as raw, mock.patch.dict(os.environ, {"SECKIT_GITHUB_REPO": ""}):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["reason"], "unknown_install_repository")

    def test_generated_installer_size_allowed_but_still_bounded(self) -> None:
        payload = b"#!/bin/bash\n#" + b"x" * (2 * 1024 * 1024) + b"\n"
        response = _Response({})
        response.payload = payload
        with mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen", return_value=response):
            path = download_release_installer(url="https://api.github.com/repos/example/private/releases/assets/7",
                                              digest="sha256:" + hashlib.sha256(payload).hexdigest())
        self.addCleanup(path.unlink, missing_ok=True)
        self.assertEqual(path.read_bytes(), payload)
        with mock.patch("secrets_kit.cli.update_check.MAX_INSTALLER_BYTES", 1024), mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen", return_value=response
        ), self.assertRaises(ValueError):
            download_release_installer(url="https://api.github.com/repos/example/private/releases/assets/7",
                                       digest="sha256:" + hashlib.sha256(payload).hexdigest())

    def setUp(self) -> None:
        """Keep upgrade scenarios independent of the checkout release version."""
        for module in ("commands.upgrade", "update_check"):
            patcher = mock.patch(f"secrets_kit.cli.{module}.__version__", "2.0.1a9")
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_unknown_launchd_state_preserves_checker_definition(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            launcher = home / ".local/bin/seckit"
            with mock.patch("pathlib.Path.home", return_value=home), mock.patch("secrets_kit.cli.update_service.sys.platform", "darwin"), mock.patch("secrets_kit.cli.update_service._launcher", return_value=launcher), mock.patch("secrets_kit.cli.update_service._run", return_value=125):
                path, content = _mac_definition(launcher=launcher)
                path.parent.mkdir(parents=True)
                path.write_bytes(content)
                self.assertEqual(manage_update_service(action="uninstall"), 1)
                self.assertEqual(path.read_bytes(), content)

    def test_parser_exposes_upgrade(self) -> None:
        args = build_parser().parse_args(["upgrade", "--check", "--refresh"])
        self.assertTrue(args.check)
        self.assertTrue(args.refresh)

    def test_parser_exposes_service_lifecycle(self) -> None:
        args = build_parser().parse_args(["upgrade", "service", "install"])
        self.assertEqual(args.upgrade_command, "service")
        self.assertEqual(args.service_action, "install")

    def test_upgrade_delegates_to_existing_installer(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            installer = Path(raw) / "install.sh"
            installer.write_text("#!/bin/bash\n")
            args = build_parser().parse_args(["upgrade", "--ref", "v2.0.1a9", "--dry-run"])
            output = io.StringIO()
            with mock.patch("secrets_kit.cli.commands.upgrade.update_context", return_value=("example/private", "prerelease")), mock.patch("secrets_kit.cli.commands.upgrade.release_installer_asset", return_value=("https://api.github.com/repos/example/private/releases/assets/7", "sha256:" + "1" * 64)), mock.patch("secrets_kit.cli.commands.upgrade.download_release_installer", return_value=installer), redirect_stdout(output):
                self.assertEqual(cmd_upgrade(args=args), 0)
            self.assertIn("install.sh", output.getvalue())
            self.assertIn("--upgrade", output.getvalue())
            self.assertIn("--no-init", output.getvalue())

    def test_upgrade_rejects_downgrade_and_non_version_ref(self) -> None:
        for ref in ("v2.0.1a8", "dev", "https://example.invalid/wheel"):
            args = build_parser().parse_args(["upgrade", "--ref", ref, "--dry-run"])
            with mock.patch("secrets_kit.cli.commands.upgrade.cmd_install") as install:
                self.assertEqual(cmd_upgrade(args=args), 2)
                install.assert_not_called()

    def test_noninteractive_confirmation_refusal_downloads_nothing(self) -> None:
        args = build_parser().parse_args(["upgrade", "--ref", "v2.0.1a9"])
        with mock.patch("secrets_kit.cli.commands.upgrade.update_context", return_value=("example/private", "prerelease")), mock.patch("sys.stdin.isatty", return_value=False), mock.patch("secrets_kit.cli.commands.upgrade.download_release_installer") as download:
            self.assertEqual(cmd_upgrade(args=args), 64)
        download.assert_not_called()

    def test_check_uses_receipt_repository_and_caches_newer_release(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            config = home / ".config" / "seckit"
            config.mkdir(parents=True)
            (config / "install.json").write_text(json.dumps({
                "github_repo": "example/private", "release_channel": "prerelease"
            }))
            (config / "install.json").chmod(0o600)
            releases = [{"draft": False, "prerelease": True, "tag_name": "v2.0.1a10", "assets": [{"name": "install.sh", "url": "https://api.github.com/repos/example/private/releases/assets/7", "digest": "sha256:" + "1" * 64}]}]
            with mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen", return_value=_Response(releases)), mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False):
                result = check_for_update(refresh=True, home=home)
                self.assertEqual(result["status"], "available")
                self.assertEqual(result["repository"], "example/private")
                self.assertEqual(cached_update_available(home=home), "v2.0.1a10")

    def test_alpha_update_ignores_mixed_beta_and_stable_releases(self) -> None:
        releases = [
            _release("v2.0.2b1", prerelease=True),
            _release("v2.0.2", prerelease=False),
            _release("v2.0.1a10", prerelease=True),
        ]
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen",
            return_value=_Response(releases),
        ), mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "prerelease",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["latest"], "v2.0.1a10")

    def test_future_alpha_does_not_hide_beta_update(self) -> None:
        releases = [
            _release("v9.0.0a1", prerelease=True),
            _release("v2.0.1b10", prerelease=True),
        ]
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.__version__", "2.0.1b9"
        ), mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen",
            return_value=_Response(releases),
        ), mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "prerelease",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["latest"], "v2.0.1b10")

    def test_malformed_tag_does_not_hide_valid_same_stage_update(self) -> None:
        releases = [
            _release("v2.0.1a", prerelease=True),
            _release("v2.0.1a10", prerelease=True),
        ]
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen",
            return_value=_Response(releases),
        ), mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "prerelease",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["latest"], "v2.0.1a10")

    def test_alpha_cannot_receive_beta_or_rc_release(self) -> None:
        releases = [
            _release("v2.0.1b10", prerelease=True),
            _release("v2.0.1rc1", prerelease=True),
            _release("v2.0.2", prerelease=False),
        ]
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen",
            return_value=_Response(releases),
        ), mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "prerelease",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["status"], "unavailable")

    def test_rc_update_ignores_alpha_and_beta_releases(self) -> None:
        releases = [
            _release("v9.0.0b1", prerelease=True),
            _release("v2.0.1a99", prerelease=True),
            _release("v2.0.1rc2", prerelease=True),
        ]
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.__version__", "2.0.1rc1"
        ), mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen",
            return_value=_Response(releases),
        ), mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "prerelease",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["latest"], "v2.0.1rc2")

    def test_installed_family_wins_over_mismatched_receipt_channel(self) -> None:
        releases = [_release("v2.0.2", prerelease=False)]
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen",
            return_value=_Response(releases),
        ), mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "release",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["status"], "unavailable")

    def test_wrong_stage_cached_result_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            cache = home / ".cache" / "seckit" / "update-check.json"
            cache.parent.mkdir(parents=True)
            cache.write_text(json.dumps({
                "status": "available",
                "current": "v2.0.1a9",
                "latest": "v9.0.0b1",
                "repository": "example/repo",
                "channel": "prerelease",
                "checked_at": 999,
            }))
            cache.chmod(0o600)
            request = mock.Mock(return_value=_Response([
                _release("v2.0.1a10", prerelease=True),
            ]))
            with mock.patch(
                "secrets_kit.cli.update_check.urllib.request.urlopen", request
            ), mock.patch(
                "secrets_kit.cli.update_check.time.time", return_value=1000
            ), mock.patch.dict(os.environ, {
                "HOME": raw,
                "SECKIT_GITHUB_REPO": "example/repo",
                "SECKIT_RELEASE_CHANNEL": "prerelease",
            }, clear=False):
                self.assertIsNone(cached_update_available(home=home))
                result = check_for_update(home=home)
            request.assert_called_once()
            self.assertEqual(result["latest"], "v2.0.1a10")

    def test_stable_update_selection_is_unchanged(self) -> None:
        releases = [
            _release("v9.0.0rc1", prerelease=True),
            _release("v2.0.2", prerelease=False),
        ]
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.__version__", "2.0.1"
        ), mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen",
            return_value=_Response(releases),
        ), mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "release",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["latest"], "v2.0.2")

    def test_unknown_installed_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "secrets_kit.cli.update_check.__version__", "development"
        ), mock.patch(
            "secrets_kit.cli.update_check.urllib.request.urlopen"
        ) as request, mock.patch.dict(os.environ, {
            "HOME": raw,
            "SECKIT_GITHUB_REPO": "example/repo",
            "SECKIT_RELEASE_CHANNEL": "prerelease",
        }, clear=False):
            result = check_for_update(refresh=True, home=Path(raw))
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "invalid_release_tag")
        request.assert_not_called()

    def test_older_release_is_not_reported_available(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            releases = [{"draft": False, "prerelease": True, "tag_name": "v2.0.1a8", "assets": [{"name": "install.sh", "url": "https://api.github.com/repos/example/repo/releases/assets/7", "digest": "sha256:" + "1" * 64}]}]
            with mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen", return_value=_Response(releases)), mock.patch.dict(os.environ, {"HOME": str(home), "SECKIT_GITHUB_REPO": "example/repo", "SECKIT_RELEASE_CHANNEL": "prerelease"}, clear=False):
                self.assertEqual(check_for_update(refresh=True, home=home)["status"], "current")

    def test_unknown_legacy_repository_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            config = home / ".config" / "seckit"
            config.mkdir(parents=True)
            (config / "install.json").write_text('{"package_source":"release"}')
            (config / "install.json").chmod(0o600)
            with mock.patch.dict(os.environ, {"HOME": str(home), "SECKIT_GITHUB_REPO": "", "SECKIT_RELEASE_CHANNEL": ""}, clear=False):
                result = check_for_update(refresh=True, home=home)
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["reason"], "unknown_install_repository")

    def test_unsafe_install_receipt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            config = home / ".config" / "seckit"
            config.mkdir(parents=True)
            state = config / "install.json"
            state.write_text('{"github_repo":"attacker/repo","release_channel":"release"}')
            state.chmod(0o644)
            with mock.patch.dict(os.environ, {"HOME": str(home), "SECKIT_GITHUB_REPO": ""}, clear=False):
                result = check_for_update(refresh=True, home=home)
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["reason"], "unsafe_install_repository_state")

    def test_invalid_install_receipt_never_falls_back_to_public(self) -> None:
        for payload in ("{", "[]"):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as raw:
                home = Path(raw)
                state = home / ".config" / "seckit" / "install.json"
                state.parent.mkdir(parents=True)
                state.write_text(payload)
                state.chmod(0o600)
                with mock.patch.dict(os.environ, {"HOME": str(home), "SECKIT_GITHUB_REPO": ""}, clear=False), mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen") as request:
                    result = check_for_update(refresh=True, home=home)
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["reason"], "invalid_install_repository_state")
                request.assert_not_called()

    def test_linux_timer_contains_no_credentials(self) -> None:
        service, service_text, timer, timer_text = _linux_definitions(launcher=Path("/home/test/.local/bin/seckit"))
        self.assertEqual(service.name, "secrets-kit-update-check.service")
        self.assertEqual(timer.name, "secrets-kit-update-check.timer")
        text = service_text + timer_text
        self.assertIn("upgrade --check --refresh", text)
        self.assertNotIn("TOKEN", text)
        self.assertNotIn("Authorization", text)

    def test_installer_download_requires_matching_digest_and_shell_syntax(self) -> None:
        payload = b"#!/bin/bash\nset -eu\n"
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        with mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen", return_value=_Response({})):
            response = _Response({})
            response.payload = payload
            with mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen", return_value=response):
                path = download_release_installer(
                    url="https://api.github.com/repos/example/private/releases/assets/7",
                    digest=digest,
                )
        try:
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        finally:
            path.unlink(missing_ok=True)
        response = _Response({})
        response.payload = payload
        with mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen", return_value=response):
            with self.assertRaises(ValueError):
                download_release_installer(
                    url="https://api.github.com/repos/example/private/releases/assets/7",
                    digest="sha256:" + "0" * 64,
                )
        response = _Response({})
        response.payload = payload
        with mock.patch("secrets_kit.cli.update_check.urllib.request.urlopen", return_value=response), mock.patch("secrets_kit.cli.update_check.subprocess.run", side_effect=subprocess.TimeoutExpired("bash", 10)):
            with self.assertRaises(ValueError):
                download_release_installer(
                    url="https://api.github.com/repos/example/private/releases/assets/7",
                    digest=digest,
                )

    def test_service_refuses_foreign_definition(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            launcher = home / ".local" / "bin" / "seckit"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("#!/bin/sh\n")
            launcher.chmod(0o700)
            unit = home / ".config" / "systemd" / "user" / "secrets-kit-update-check.service"
            unit.parent.mkdir(parents=True)
            unit.write_text("foreign\n")
            with mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False), mock.patch("sys.platform", "linux"):
                self.assertEqual(manage_update_service(action="install"), 2)
            self.assertEqual(unit.read_text(), "foreign\n")

    def test_service_refuses_symlinked_or_writable_parent(self) -> None:
        for unsafe_kind in ("symlink", "writable"):
            with self.subTest(unsafe_kind=unsafe_kind), tempfile.TemporaryDirectory() as raw:
                home = Path(raw) / "home"
                home.mkdir()
                launcher = home / ".local" / "bin" / "seckit"
                launcher.parent.mkdir(parents=True)
                launcher.write_text("#!/bin/sh\n")
                launcher.chmod(0o700)
                config = home / ".config"
                if unsafe_kind == "symlink":
                    external = Path(raw) / "external"
                    external.mkdir()
                    config.symlink_to(external, target_is_directory=True)
                else:
                    config.mkdir(mode=0o777)
                    config.chmod(0o777)
                with mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False), mock.patch("sys.platform", "linux"):
                    self.assertEqual(manage_update_service(action="install"), 2)

    def test_cached_notice_discards_unsafe_cache(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            cache = home / ".cache" / "seckit" / "update-check.json"
            cache.parent.mkdir(parents=True)
            cache.write_text('{"status":"available","latest":"v99.0.0"}')
            cache.chmod(0o644)
            self.assertIsNone(cached_update_available(home=home))

    def test_status_does_not_show_wrong_stage_cached_hint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            cache = home / ".cache" / "seckit" / "update-check.json"
            cache.parent.mkdir(parents=True)
            cache.write_text(json.dumps({
                "status": "available",
                "current": "v2.0.1a9",
                "latest": "v2.0.1b1",
                "repository": "example/repo",
                "channel": "prerelease",
                "checked_at": 1,
            }))
            cache.chmod(0o600)
            output = io.StringIO()
            args = build_parser().parse_args(["status"])
            with mock.patch(
                "pathlib.Path.home", return_value=home
            ), mock.patch(
                "secrets_kit.cli.commands.status.request_daemon_status",
                return_value={"overall": "OK", "daemon": {"running": True}},
            ), redirect_stdout(output):
                self.assertEqual(cmd_status(args=args), 0)
        self.assertNotIn("v2.0.1b1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
