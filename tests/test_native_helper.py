from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.native_helper import (
    NativeHelperError,
    bundled_helper_path,
    helper_has_icloud_entitlements,
    helper_status,
    icloud_backend_available,
    icloud_helper_binary_path,
    run_helper_request,
)


class NativeHelperTest(unittest.TestCase):
    def test_helper_status_reports_missing_helper(self) -> None:
        with mock.patch("secrets_kit.native_helper.icloud_helper_binary_path", return_value=None), \
            mock.patch("secrets_kit.native_helper.bundled_helper_path", return_value=None):
            status = helper_status()
        self.assertFalse(status["helper"]["installed"])
        self.assertIsNone(status["helper"]["bundled_path"])
        self.assertTrue(status["backend_availability"]["secure"])
        self.assertFalse(status["backend_availability"]["icloud-helper"])
        self.assertFalse(status["backend_availability"]["icloud"])
        self.assertTrue(status["backend_availability"]["local"])

    def test_bundled_helper_path_is_none_off_darwin(self) -> None:
        with mock.patch("sys.platform", "linux"):
            self.assertIsNone(bundled_helper_path())

    def test_icloud_resolution_prefers_bundled_over_venv_bin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            install = Path(tmp) / "bin" / "seckit-keychain-helper"
            bundled = Path(tmp) / "bundled" / "seckit-keychain-helper"
            install.parent.mkdir(parents=True)
            bundled.parent.mkdir(parents=True)
            install.write_bytes(b"\n")
            bundled.write_bytes(b"\n")
            install.chmod(0o755)
            bundled.chmod(0o755)
            with mock.patch("secrets_kit.native_helper.helper_install_path", return_value=install), \
                mock.patch("secrets_kit.native_helper.bundled_helper_path", return_value=bundled), \
                mock.patch("secrets_kit.native_helper.helper_has_icloud_entitlements", return_value=True), \
                mock.patch("secrets_kit.native_helper.shutil.which", return_value=None):
                resolved = icloud_helper_binary_path()
        self.assertEqual(resolved, bundled)

    def test_helper_status_includes_bundled_path_when_present(self) -> None:
        fake = Path("/tmp/bundled/seckit-keychain-helper")
        with mock.patch("secrets_kit.native_helper.bundled_helper_path", return_value=fake), \
            mock.patch("secrets_kit.native_helper.icloud_helper_binary_path", return_value=fake):
            status = helper_status()
        self.assertEqual(status["helper"]["bundled_path"], str(fake))
        self.assertTrue(status["helper"]["installed"])
        self.assertEqual(status["helper"]["path"], str(fake))

    def test_icloud_backend_available_false_without_helper(self) -> None:
        with mock.patch("secrets_kit.native_helper.icloud_helper_binary_path", return_value=None):
            self.assertFalse(icloud_backend_available())

    def test_icloud_backend_available_true_with_entitled_helper(self) -> None:
        with mock.patch(
            "secrets_kit.native_helper.icloud_helper_binary_path",
            return_value=Path("/tmp/seckit-keychain-helper"),
        ):
            self.assertTrue(icloud_backend_available())

    def test_helper_has_icloud_entitlements_requires_keychain_group(self) -> None:
        with mock.patch(
            "secrets_kit.native_helper.helper_entitlements",
            return_value={
                "com.apple.application-identifier": "TEAMID.com.unixwzrd.seckit.keychain-helper",
                "com.apple.developer.team-identifier": "TEAMID",
                "keychain-access-groups": ["TEAMID.com.unixwzrd.seckit.keychain-helper"],
            },
        ):
            self.assertTrue(helper_has_icloud_entitlements(path=Path("/tmp/helper")))

    def test_helper_entitlement_inspection_uses_non_deprecated_codesign_output_path(self) -> None:
        proc = mock.Mock(
            returncode=0,
            stdout=b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict></dict></plist>',
        )
        with mock.patch("secrets_kit.native_helper.shutil.which", return_value="/usr/bin/codesign"), \
            mock.patch("subprocess.run", return_value=proc) as run_mock:
            from secrets_kit.native_helper import helper_entitlements

            helper_entitlements(path=Path("/tmp/helper"))
        self.assertEqual(run_mock.call_args.args[0], ["/usr/bin/codesign", "-d", "--entitlements", "-", "/tmp/helper"])

    def test_helper_entitlement_inspection_parses_codesign_text_output(self) -> None:
        proc = mock.Mock(
            returncode=0,
            stdout=(
                b"[Dict]\n"
                b"        [Key] com.apple.application-identifier\n"
                b"        [Value]\n"
                b"                [String] SECKITSELF.com.unixwzrd.seckit.keychain-helper\n"
                b"        [Key] com.apple.developer.team-identifier\n"
                b"        [Value]\n"
                b"                [String] SECKITSELF\n"
                b"        [Key] keychain-access-groups\n"
                b"        [Value]\n"
                b"                [Array]\n"
                b"                        [String] SECKITSELF.com.unixwzrd.seckit.keychain-helper\n"
            ),
        )
        with mock.patch("secrets_kit.native_helper.shutil.which", return_value="/usr/bin/codesign"), \
            mock.patch("subprocess.run", return_value=proc):
            from secrets_kit.native_helper import helper_entitlements

            entitlements = helper_entitlements(path=Path("/tmp/helper"))
        self.assertEqual(entitlements["com.apple.developer.team-identifier"], "SECKITSELF")
        self.assertEqual(entitlements["keychain-access-groups"], ["SECKITSELF.com.unixwzrd.seckit.keychain-helper"])

    def test_run_helper_request_requires_installed_helper(self) -> None:
        with mock.patch("secrets_kit.native_helper.icloud_helper_binary_path", return_value=None):
            with self.assertRaisesRegex(NativeHelperError, "iCloud backend requires"):
                run_helper_request(payload={"command": "exists", "backend": "icloud"})

    def test_run_helper_request_rejects_local_backend_payload(self) -> None:
        with self.assertRaisesRegex(NativeHelperError, "security CLI only"):
            run_helper_request(payload={"command": "exists", "backend": "local"})

    def test_run_helper_request_reports_json_error_on_nonzero_exit(self) -> None:
        proc = mock.Mock(
            returncode=1,
            stdout='{"ok":false,"error":"set failed: Missing entitlement (-34018)"}\n',
            stderr="",
        )
        with mock.patch("secrets_kit.native_helper.icloud_helper_binary_path", return_value=Path("/tmp/helper")), \
            mock.patch("subprocess.run", return_value=proc):
            with self.assertRaisesRegex(NativeHelperError, "Missing entitlement"):
                run_helper_request(payload={"command": "set", "backend": "icloud"})

    def test_run_helper_request_reports_stderr_on_nonzero_without_json(self) -> None:
        proc = mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch("secrets_kit.native_helper.icloud_helper_binary_path", return_value=Path("/tmp/helper")), \
            mock.patch("subprocess.run", return_value=proc):
            with self.assertRaisesRegex(NativeHelperError, "boom"):
                run_helper_request(payload={"command": "set", "backend": "icloud"})

    def test_run_helper_request_reports_signal_termination(self) -> None:
        proc = mock.Mock(returncode=-9, stdout="", stderr="")
        with mock.patch("secrets_kit.native_helper.icloud_helper_binary_path", return_value=Path("/tmp/helper")), \
            mock.patch("subprocess.run", return_value=proc):
            with self.assertRaisesRegex(NativeHelperError, "SIGKILL"):
                run_helper_request(payload={"command": "set", "backend": "icloud"})


if __name__ == "__main__":
    unittest.main()
