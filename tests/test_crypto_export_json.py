from __future__ import annotations

import argparse
import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.export import cmd_export
from secrets_kit.crypto.cli.export_json import (
    build_plain_export,
    decrypt_payload,
    encrypt_payload,
    ensure_crypto_available,
)
from secrets_kit.exporters import write_protected_export


class CryptoExportJsonTest(unittest.TestCase):
    def test_roundtrip_encrypt_decrypt(self) -> None:
        ensure_crypto_available()
        plain = build_plain_export(
            entries=[
                {
                    "metadata": {"name": "DEMO", "service": "svc", "account": "acct"},
                    "value": "secret",
                }
            ]
        )
        encrypted = encrypt_payload(payload=plain, password="test-pass")
        decrypted = decrypt_payload(payload=encrypted.__dict__, password="test-pass")
        self.assertEqual(decrypted["format"], "seckit.export")
        self.assertEqual(decrypted["entries"], plain["entries"])


class ProtectedExportTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.target = self.root / "backup"

    def test_owner_only_and_no_overwrite(self) -> None:
        write_protected_export(destination=self.target, payload=b"synthetic")
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            write_protected_export(destination=self.target, payload=b"replacement")
        self.assertEqual(self.target.read_bytes(), b"synthetic")
        self.assertEqual(list(self.root.iterdir()), [self.target])

    def test_link_and_unsafe_parent_rejected(self) -> None:
        self.target.symlink_to(self.root / "missing")
        with self.assertRaises(FileExistsError):
            write_protected_export(destination=self.target, payload=b"synthetic")
        self.assertFalse((self.root / "missing").exists())
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "unsafe_directory"):
            write_protected_export(destination=self.root / "other", payload=b"synthetic")
        self.root.chmod(0o700)

    def test_failed_write_leaves_no_destination_or_temporary(self) -> None:
        with mock.patch("secrets_kit.exporters.os.fsync", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                write_protected_export(destination=self.target, payload=b"synthetic")
        self.assertEqual(list(self.root.iterdir()), [])

    def _export(self, *, executable, result=None):
        args = argparse.Namespace(format="age", out=str(self.target), recipient="age1synthetic")
        output = io.StringIO()
        with (
            mock.patch("secrets_kit.cli.commands.export._select_entries", return_value=[object()]),
            mock.patch(
                "secrets_kit.cli.commands.export._build_env_map",
                return_value={"TOKEN": "synthetic-secret"},
            ),
            mock.patch("secrets_kit.cli.commands.export.shutil.which", return_value=executable),
            mock.patch(
                "secrets_kit.cli.commands.export.subprocess.run", return_value=result
            ) as run,
            redirect_stdout(output),
            redirect_stderr(output),
        ):
            code = cmd_export(args=args)
        self.assertNotIn("synthetic-secret", output.getvalue())
        return code, run

    def test_age_missing_fails_without_output(self) -> None:
        code, run = self._export(executable=None)
        self.assertEqual(code, 1)
        run.assert_not_called()
        self.assertFalse(self.target.exists())

    def test_age_failure_never_falls_back(self) -> None:
        code, _ = self._export(
            executable="/test/age", result=subprocess.CompletedProcess([], 1, b"")
        )
        self.assertEqual(code, 1)
        self.assertFalse(self.target.exists())

    def test_age_uses_stdin_and_publishes_only_ciphertext(self) -> None:
        code, run = self._export(
            executable="/test/age", result=subprocess.CompletedProcess([], 0, b"ciphertext")
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.target.read_bytes(), b"ciphertext")
        self.assertNotIn("synthetic-secret", str(run.call_args.args))
        self.assertIn(b"synthetic-secret", run.call_args.kwargs["input"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)


if __name__ == "__main__":
    unittest.main()
