from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.native_helper import (
    NativeHelperError,
    build_and_install_helper,
    helper_status,
    icloud_backend_available,
    run_helper_request,
)


class NativeHelperTest(unittest.TestCase):
    def test_helper_status_reports_missing_helper(self) -> None:
        with mock.patch("secrets_kit.native_helper.local_helper_binary_path", return_value=None), \
            mock.patch("secrets_kit.native_helper.swift_binary_path", return_value=None):
            status = helper_status()
        self.assertFalse(status["helper"]["helper_installed"])
        self.assertFalse(status["backend_availability"]["icloud"])
        self.assertFalse(status["swift_available"])

    def test_icloud_backend_available_false_without_helper(self) -> None:
        with mock.patch("secrets_kit.native_helper.local_helper_binary_path", return_value=None):
            self.assertFalse(icloud_backend_available())

    def test_icloud_backend_available_true_with_helper(self) -> None:
        with mock.patch("secrets_kit.native_helper.local_helper_binary_path", return_value=Path("/tmp/seckit-keychain-helper")):
            self.assertTrue(icloud_backend_available())

    def test_run_helper_request_requires_installed_helper(self) -> None:
        with mock.patch("secrets_kit.native_helper.local_helper_binary_path", return_value=None):
            with self.assertRaisesRegex(NativeHelperError, "install-local"):
                run_helper_request(payload={"command": "exists"})

    def test_build_and_install_helper_copies_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_dir = root / "src"
            arm64_dir = source_dir / ".build" / "arm64-apple-macosx" / "release"
            x86_dir = source_dir / ".build" / "x86_64-apple-macosx" / "release"
            arm64_dir.mkdir(parents=True, exist_ok=True)
            x86_dir.mkdir(parents=True, exist_ok=True)
            (arm64_dir / "seckit-keychain-helper").write_text("arm64-binary", encoding="utf-8")
            (x86_dir / "seckit-keychain-helper").write_text("x86-binary", encoding="utf-8")
            universal_binary = source_dir / ".build" / "seckit-keychain-helper-universal"
            install_dir = root / "bin"
            install_dir.mkdir(parents=True, exist_ok=True)
            with mock.patch("sys.platform", "darwin"), \
                mock.patch("secrets_kit.native_helper.helper_source_dir", return_value=source_dir), \
                mock.patch("secrets_kit.native_helper.swift_binary_path", return_value="/usr/bin/swift"), \
                mock.patch("secrets_kit.native_helper.lipo_binary_path", return_value="/usr/bin/lipo"), \
                mock.patch("secrets_kit.native_helper.helper_install_path", return_value=install_dir / "seckit-keychain-helper"), \
                mock.patch("subprocess.run") as run_mock:
                def fake_run(cmd, capture_output=True, text=True, check=False):
                    if cmd[:2] == ["/usr/bin/swift", "build"]:
                        return mock.Mock(returncode=0, stderr="", stdout="")
                    if cmd[:2] == ["/usr/bin/lipo", "-create"]:
                        universal_binary.write_text("universal-binary", encoding="utf-8")
                        return mock.Mock(returncode=0, stderr="", stdout="")
                    return mock.Mock(returncode=0, stderr="", stdout="")

                run_mock.side_effect = fake_run
                target = build_and_install_helper()
            self.assertTrue(target.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "universal-binary")


if __name__ == "__main__":
    unittest.main()
