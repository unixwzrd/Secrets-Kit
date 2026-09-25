"""Tests for deterministic installed transport dependency validation."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.install_transport_validation import (
    TransportDependencyError,
    installed_versions,
    verify_linux_linkage,
    verify_macos_linkage,
)


class InstallTransportValidationTests(unittest.TestCase):
    """Verify that validation accepts known layouts and fails closed otherwise."""

    def test_exact_versions_are_required(self) -> None:
        versions = {
            "cryptography": "50.0.1",
            "libp2p": "0.7.0+seckit.4",
            "fastecdsa": "3.0.1",
        }
        with mock.patch(
            "secrets_kit.install_transport_validation.importlib.metadata.version",
            side_effect=lambda name: versions[name],
        ):
            self.assertEqual(installed_versions(), versions)

        versions["fastecdsa"] = "2.3.2"
        with mock.patch(
            "secrets_kit.install_transport_validation.importlib.metadata.version",
            side_effect=lambda name: versions[name],
        ):
            with self.assertRaisesRegex(TransportDependencyError, "unapproved fastecdsa"):
                installed_versions()

    def test_affected_cryptography_version_is_rejected(self) -> None:
        versions = {"cryptography": "48.0.1", "libp2p": "0.7.0+seckit.4", "fastecdsa": "3.0.1"}
        with mock.patch(
            "secrets_kit.install_transport_validation.importlib.metadata.version",
            side_effect=lambda name: versions[name],
        ):
            with self.assertRaisesRegex(TransportDependencyError, "unapproved cryptography"):
                installed_versions()

    def test_macos_requires_loader_relative_wheel_owned_gmp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "fastecdsa"
            dylibs = package / ".dylibs"
            dylibs.mkdir(parents=True)
            extension = package / "_ecdsa.cpython-312-darwin.so"
            extension.touch()
            (dylibs / "libgmp.10.dylib").touch()
            output = (
                f"{extension}:\n"
                "\t@loader_path/.dylibs/libgmp.10.dylib "
                "(compatibility version 16.0.0)\n"
            )
            with mock.patch(
                "secrets_kit.install_transport_validation._run",
                return_value=subprocess.CompletedProcess([], 0, output, ""),
            ):
                observed = verify_macos_linkage(extensions=(extension,))
            self.assertEqual(
                observed[str(extension)],
                "@loader_path/.dylibs/libgmp.10.dylib",
            )

    def test_macos_rejects_absolute_gmp_reference(self) -> None:
        extension = Path("/runtime/fastecdsa/_ecdsa.cpython-312-darwin.so")
        output = f"{extension}:\n\t/opt/homebrew/opt/gmp/lib/libgmp.10.dylib\n"
        with mock.patch(
            "secrets_kit.install_transport_validation._run",
            return_value=subprocess.CompletedProcess([], 0, output, ""),
        ):
            with self.assertRaisesRegex(TransportDependencyError, "not loader-relative"):
                verify_macos_linkage(extensions=(extension,))

    def test_linux_rejects_unresolved_dependency(self) -> None:
        extension = Path("/runtime/fastecdsa/_ecdsa.cpython-312-linux.so")
        output = "libgmp.so.10 => not found\n"
        with mock.patch(
            "secrets_kit.install_transport_validation._run",
            return_value=subprocess.CompletedProcess([], 0, output, ""),
        ):
            with self.assertRaisesRegex(TransportDependencyError, "unresolved dependency"):
                verify_linux_linkage(extensions=(extension,))

    def test_linux_accepts_one_resolved_gmp_dependency(self) -> None:
        extension = Path("/runtime/fastecdsa/_ecdsa.cpython-312-linux.so")
        output = "libgmp-abc.so.10 => /runtime/fastecdsa.libs/libgmp-abc.so.10\n"
        with mock.patch(
            "secrets_kit.install_transport_validation._run",
            return_value=subprocess.CompletedProcess([], 0, output, ""),
        ):
            observed = verify_linux_linkage(extensions=(extension,))
        self.assertEqual(observed[str(extension)], output.strip())


if __name__ == "__main__":
    unittest.main()
