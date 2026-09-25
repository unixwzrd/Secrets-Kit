"""Managed same-user daemon service tests."""

from __future__ import annotations

import argparse
import io
import os
import plistlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.daemon import (
    cmd_daemon_restart,
    cmd_daemon_service_install,
    cmd_daemon_service_status,
)
from secrets_kit.cli.parser import build_parser
from secrets_kit.daemon.service import DaemonServiceError, install_service


class DaemonServiceDefinitionTest(unittest.TestCase):
    """Validate deterministic launchd and systemd user definitions."""

    @unittest.skipUnless(Path("/usr/bin/plutil").is_file(), "macOS plist tool required")
    def test_administrator_helper_render_matches_customer_validator(self) -> None:
        from secrets_kit.daemon import service
        from tests.test_boot_service_helper import HELPER_PATH

        source = HELPER_PATH.read_text()
        # Execute only the fixed plist-construction section, never privileged
        # installation/removal, launchctl or customer runtime commands.
        body = source[source.index("/usr/bin/plutil -create"):source.index("# Compare canonical")]
        prefix = "set -eu\nstaged=$1\nlabel=$2\naccount=$3\nlauncher=$4\nhome=$5\n"
        for home in ("/Users/fixture", "/Users/fixture with spaces & punctuation"):
            with self.subTest(home=home), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "job.plist"
                launcher = Path(home) / ".local/bin/seckit"
                label = f"{service.LAUNCHD_LABEL}.508"
                subprocess.run(["bash", "-c", prefix + body, "render", str(path), label, "fixture", str(launcher), home], check=True, capture_output=True, timeout=10)
                expected = plistlib.loads(service._launchd_payload(launcher, home=Path(home)))
                expected.pop("LimitLoadToSessionType")
                expected.update(Label=label, UserName="fixture")
                self.assertEqual(plistlib.loads(path.read_bytes()), expected)
                self.assertEqual(expected["StandardOutPath"], "/dev/null")
                self.assertEqual(expected["StandardErrorPath"], "/dev/null")
                with mock.patch.object(service.os, "getuid", return_value=508), mock.patch("pwd.getpwuid", return_value=mock.Mock(pw_name="fixture")), mock.patch.object(service, "_launcher_path", return_value=launcher), mock.patch.object(service.Path, "home", return_value=Path(home)), mock.patch.object(service.Path, "lstat", return_value=mock.Mock(st_uid=0, st_mode=0o100644)):
                    service._validate_boot_definition(path)

    def test_boot_definition_blocks_unprivileged_lifecycle_before_changes(self) -> None:
        from secrets_kit.daemon import service

        with (
            mock.patch.object(service, "_system", return_value="Darwin"),
            mock.patch.object(service, "service_definition_path", return_value=service._boot_definition_path()),
            mock.patch.object(service, "_run") as run,
            mock.patch.object(service, "_atomic_write") as write,
            mock.patch.object(service, "_stop_unmanaged_daemon") as stop,
        ):
            for operation in (service.install_service, service.start_service, service.stop_service, service.restart_service, service.uninstall_service):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaisesRegex(DaemonServiceError, "administrator"):
                        operation()
            run.assert_not_called()
            write.assert_not_called()
            stop.assert_not_called()

    def test_system_job_is_detected_and_duplicate_domains_rejected(self) -> None:
        from secrets_kit.daemon import service

        target = f"system/{service.LAUNCHD_LABEL}.{os.getuid()}"
        with mock.patch.object(service, "_run", side_effect=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0 if argv[-1] == target else 113)):
            self.assertEqual(service._launchd_target(), target)
        with mock.patch.object(service, "_run", return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaisesRegex(DaemonServiceError, "duplicate"):
                service._launchd_target()

    def test_loaded_boot_job_without_definition_prevents_detached_start(self) -> None:
        from secrets_kit.daemon import service

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(service, "_system", return_value="Darwin"),
            mock.patch.object(service, "service_definition_path", return_value=Path(directory) / "missing.plist"),
            mock.patch.object(service, "_launchd_target", return_value=f"system/{service.LAUNCHD_LABEL}.{os.getuid()}"),
        ):
            self.assertTrue(service.service_installed())
            with self.assertRaisesRegex(DaemonServiceError, "administrator"):
                service.install_service()

    def test_boot_definition_accepts_only_exact_unprivileged_payload(self) -> None:
        from secrets_kit.daemon import service

        payload = plistlib.loads(service._launchd_payload(service._launcher_path(), home=Path.home()))
        payload.pop("LimitLoadToSessionType")
        payload.update(Label=f"{service.LAUNCHD_LABEL}.508", UserName="fixtureuser")
        path = mock.Mock(spec=Path)
        path.lstat.return_value = mock.Mock(st_uid=0, st_mode=0o100644)
        with mock.patch.object(service.os, "getuid", return_value=508), mock.patch("pwd.getpwuid", return_value=mock.Mock(pw_name="fixtureuser")):
            path.read_bytes.return_value = plistlib.dumps(payload)
            service._validate_boot_definition(path)
            for changes in ({"UserName": "root"}, {"Program": "/bin/sh"}, {"GroupName": "wheel"}, {"Label": "other"}):
                with self.subTest(changes=changes):
                    path.read_bytes.return_value = plistlib.dumps({**payload, **changes})
                    with self.assertRaisesRegex(DaemonServiceError, "unsafe or mismatched"):
                        service._validate_boot_definition(path)

    def test_boot_definition_rejects_symlinks_and_non_root_ownership(self) -> None:
        from secrets_kit.daemon import service

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "job.plist"
            target.write_bytes(plistlib.dumps({"UserName": "root"}))
            link = Path(directory) / "link.plist"
            link.symlink_to(target)
            for path in (target, link):
                with self.subTest(path=path.name):
                    with self.assertRaisesRegex(DaemonServiceError, "unsafe or mismatched"):
                        service._validate_boot_definition(path)

    def test_start_does_not_kill_run_at_load_process(self) -> None:
        from secrets_kit.daemon.service import start_service

        with tempfile.TemporaryDirectory() as directory:
            definition = Path(directory) / "service.plist"
            definition.write_bytes(b"fixture")
            with (
                mock.patch("secrets_kit.daemon.service._system", return_value="Darwin"),
                mock.patch("secrets_kit.daemon.service.service_definition_path", return_value=definition),
                mock.patch("secrets_kit.daemon.service._launchd_loaded", return_value=False),
                mock.patch("secrets_kit.daemon.service.wait_until_running", return_value=True),
                mock.patch("secrets_kit.daemon.service._run") as run,
            ):
                start_service()
            kickstarts = [call.args[0] for call in run.call_args_list if call.args[0][:2] == ["launchctl", "kickstart"]]
            self.assertEqual(kickstarts, [["launchctl", "kickstart", f"user/{os.getuid()}/net.unixwzrd.secrets-kit.daemon"]])

    def test_launchd_ssh_user_domain_and_legacy_job_detection(self) -> None:
        from secrets_kit.daemon.service import _launchd_domain, _launchd_target

        self.assertEqual(_launchd_domain(), f"user/{os.getuid()}")
        legacy = f"gui/{os.getuid()}/net.unixwzrd.secrets-kit.daemon"
        with mock.patch("secrets_kit.daemon.service._run", side_effect=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0 if argv[-1] == legacy else 113)):
            self.assertEqual(_launchd_target(), legacy)
        with mock.patch("secrets_kit.daemon.service._run", return_value=subprocess.CompletedProcess([], 113)):
            self.assertEqual(_launchd_target(), f"user/{os.getuid()}/net.unixwzrd.secrets-kit.daemon")
        with mock.patch("secrets_kit.daemon.service._run", return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaisesRegex(DaemonServiceError, "duplicate"):
                _launchd_target()

    def test_private_service_parents_and_metadata_with_permissive_umask(self) -> None:
        from secrets_kit.daemon.server import _write_metadata
        from secrets_kit.daemon.service import _atomic_write

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = os.umask(0o002)
            try:
                target = root / "systemd/user/test.service"
                _atomic_write(target, b"service")
                self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(target.parent.parent.stat().st_mode & 0o777, 0o700)
                metadata = root / "seckitd.json"
                with mock.patch("secrets_kit.daemon.server.metadata_path", return_value=metadata):
                    _write_metadata(tcp_port=0)
                    self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)
                    _write_metadata(tcp_port=1)
                    self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)
            finally:
                os.umask(previous)

    def _launcher(self, root: Path) -> Path:
        launcher = root / "bin/seckit"
        launcher.parent.mkdir()
        launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        launcher.chmod(0o700)
        return launcher

    def test_launchd_install_is_idempotent_and_uses_stable_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = self._launcher(root)
            definition = root / "LaunchAgents/seckit.plist"
            with (
                mock.patch("secrets_kit.daemon.service._system", return_value="Darwin"),
                mock.patch("secrets_kit.daemon.service._launcher_path", return_value=launcher),
                mock.patch(
                    "secrets_kit.daemon.service.service_definition_path",
                    return_value=definition,
                ),
                mock.patch("secrets_kit.daemon.service._launchd_loaded", return_value=False),
                mock.patch(
                    "secrets_kit.daemon.service._launchd_domain_available",
                    return_value=True,
                ),
                mock.patch("secrets_kit.daemon.service._stop_unmanaged_daemon"),
                mock.patch("secrets_kit.daemon.service.wait_until_running", return_value=True),
                mock.patch("secrets_kit.daemon.service._run") as run,
            ):
                self.assertTrue(install_service())
                self.assertFalse(install_service())
            payload = plistlib.loads(definition.read_bytes())
            self.assertEqual(
                payload["ProgramArguments"], [str(launcher.resolve()), "daemon", "run"]
            )
            self.assertTrue(payload["RunAtLoad"])
            self.assertEqual(payload["LimitLoadToSessionType"], "Background")
            self.assertEqual(payload["ProcessType"], "Standard")
            self.assertEqual(payload["KeepAlive"], {"SuccessfulExit": False})
            self.assertEqual(payload["EnvironmentVariables"], {"HOME": str(Path.home())})
            self.assertEqual(definition.stat().st_mode & 0o777, 0o644)
            self.assertGreaterEqual(run.call_count, 4)

    def test_unchanged_launchd_install_does_not_unload_job(self) -> None:
        """Repeated installation starts the existing job without IPC shutdown."""
        from secrets_kit.daemon import service

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = self._launcher(root)
            definition = root / "seckit.plist"
            definition.write_bytes(service._launchd_payload(launcher.resolve(), home=Path.home()))
            with (
                mock.patch.object(service, "_system", return_value="Darwin"),
                mock.patch.object(service, "_launcher_path", return_value=launcher),
                mock.patch.object(service, "service_definition_path", return_value=definition),
                mock.patch.object(service, "_launchd_domain_available", return_value=True),
                mock.patch.object(service, "_launchd_loaded", return_value=True),
                mock.patch.object(service, "_launchd_target", return_value=f"user/{os.getuid()}/{service.LAUNCHD_LABEL}"),
                mock.patch.object(service, "start_service") as start,
                mock.patch.object(service, "restart_service") as restart,
                mock.patch.object(service, "_stop_unmanaged_daemon") as stop,
                mock.patch.object(service, "_run") as run,
            ):
                self.assertFalse(install_service())
                start.assert_called_once_with(timeout=30.0)
                stop.assert_not_called()
                run.assert_not_called()
                restart.assert_not_called()
                self.assertFalse(install_service(reload_runtime=True))
                restart.assert_called_once_with(timeout=30.0)
                start.assert_called_once_with(timeout=30.0)
                stop.assert_not_called()
                run.assert_not_called()

    def test_failed_launchd_install_removes_new_definition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = self._launcher(root)
            definition = root / "LaunchAgents/seckit.plist"
            with (
                mock.patch("secrets_kit.daemon.service._system", return_value="Darwin"),
                mock.patch("secrets_kit.daemon.service._launcher_path", return_value=launcher),
                mock.patch(
                    "secrets_kit.daemon.service.service_definition_path",
                    return_value=definition,
                ),
                mock.patch(
                    "secrets_kit.daemon.service._launchd_loaded",
                    side_effect=[False, True],
                ),
                mock.patch(
                    "secrets_kit.daemon.service._launchd_domain_available",
                    return_value=True,
                ),
                mock.patch("secrets_kit.daemon.service._stop_unmanaged_daemon"),
                mock.patch("secrets_kit.daemon.service.wait_until_running", return_value=False),
                mock.patch("secrets_kit.daemon.service._run") as run,
            ):
                with self.assertRaisesRegex(DaemonServiceError, "did not become reachable"):
                    install_service(timeout=0.01)
            self.assertFalse(definition.exists())
            run.assert_any_call(
                [
                    "launchctl",
                    "bootout",
                    f"user/{os.getuid()}/net.unixwzrd.secrets-kit.daemon",
                ],
                check=False,
            )

    def test_launchd_install_requires_available_user_domain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = self._launcher(root)
            definition = root / "LaunchAgents/seckit.plist"
            with (
                mock.patch("secrets_kit.daemon.service._system", return_value="Darwin"),
                mock.patch("secrets_kit.daemon.service._launcher_path", return_value=launcher),
                mock.patch(
                    "secrets_kit.daemon.service.service_definition_path",
                    return_value=definition,
                ),
                mock.patch(
                    "secrets_kit.daemon.service._launchd_domain_available",
                    return_value=False,
                ),
            ):
                with self.assertRaisesRegex(DaemonServiceError, "available macOS user domain"):
                    install_service()
            self.assertFalse(definition.exists())

    def test_systemd_install_enables_restart_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = self._launcher(root)
            definition = root / "systemd/user/seckit.service"
            with (
                mock.patch("secrets_kit.daemon.service._system", return_value="Linux"),
                mock.patch("secrets_kit.daemon.service._launcher_path", return_value=launcher),
                mock.patch(
                    "secrets_kit.daemon.service.service_definition_path",
                    return_value=definition,
                ),
                mock.patch("secrets_kit.daemon.service._stop_unmanaged_daemon"),
                mock.patch("secrets_kit.daemon.service.wait_until_running", return_value=True),
                mock.patch("secrets_kit.daemon.service._run") as run,
            ):
                self.assertTrue(install_service())
            value = definition.read_text(encoding="utf-8")
            self.assertIn(f"ExecStart={launcher.resolve()} daemon run", value)
            self.assertIn("Restart=on-failure", value)
            self.assertIn("NoNewPrivileges=true", value)
            run.assert_any_call(
                ["systemctl", "--user", "enable", "--now", "secrets-kit-daemon.service"]
            )

    def test_systemd_reinstall_stops_unit_before_enable(self) -> None:
        """Wait for systemd exit rather than racing an IPC-only shutdown."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = self._launcher(root)
            definition = root / "service"
            definition.write_text("previous definition")
            with (
                mock.patch("secrets_kit.daemon.service._system", return_value="Linux"),
                mock.patch("secrets_kit.daemon.service._launcher_path", return_value=launcher),
                mock.patch("secrets_kit.daemon.service.service_definition_path", return_value=definition),
                mock.patch("secrets_kit.daemon.service._stop_unmanaged_daemon"),
                mock.patch("secrets_kit.daemon.service.wait_until_running", return_value=True),
                mock.patch("secrets_kit.daemon.service._run") as run,
            ):
                self.assertFalse(install_service())
            self.assertEqual(run.call_args_list[0], mock.call(["systemctl", "--user", "stop", "secrets-kit-daemon.service"]))


class DaemonServiceCLITest(unittest.TestCase):
    """Validate managed-service CLI topology and dispatch."""

    def test_parser_exposes_service_and_restart_commands(self) -> None:
        parser = build_parser()
        install = parser.parse_args(["daemon", "service", "install"])
        restart = parser.parse_args(["daemon", "restart"])
        self.assertIs(install.func, cmd_daemon_service_install)
        self.assertIs(restart.func, cmd_daemon_restart)

    def test_service_status_fails_when_daemon_is_not_reachable(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch(
                "secrets_kit.cli.commands.daemon.service_status",
                return_value={
                    "manager": "systemd-user",
                    "installed": True,
                    "active": True,
                    "daemon_reachable": False,
                    "definition": "/tmp/seckit.service",
                    "linger": False,
                },
            ),
            redirect_stdout(stdout),
        ):
            code = cmd_daemon_service_status(args=argparse.Namespace())
        self.assertEqual(code, 1)
        self.assertIn("daemon_reachable: false", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
