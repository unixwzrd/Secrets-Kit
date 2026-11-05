from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite.secrets_api import get_sqlite_secret, set_sqlite_secret
from secrets_kit.cli.commands.export import cmd_export
from secrets_kit.cli.commands.import_cmd import cmd_import_encrypted
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.crypto.cli.export_json import (
    build_plain_export,
    decrypt_payload,
    encrypt_payload,
    ensure_crypto_available,
)
from secrets_kit.exporters import write_protected_export
from secrets_kit.models import EntryMetadata


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

    def test_malicious_kdf_parameters_are_rejected_before_derivation(self) -> None:
        encrypted = encrypt_payload(payload=build_plain_export(entries=[]), password="test-pass")
        for field, value in (("n", 2**40), ("r", 2**20), ("p", 2**20), ("n", True)):
            with self.subTest(field=field, value=value):
                malformed = {**encrypted.__dict__, "kdf": {**encrypted.kdf, field: value}}
                with mock.patch(
                    "secrets_kit.crypto.cli.export_json._derive_key",
                    side_effect=AssertionError("derivation must not run"),
                ):
                    with self.assertRaisesRegex(ValueError, "unsupported scrypt work factors"):
                        decrypt_payload(payload=malformed, password="test-pass")

    def test_malformed_backup_structure_is_rejected_before_derivation(self) -> None:
        encrypted = encrypt_payload(payload=build_plain_export(entries=[]), password="test-pass")
        for change in (
            {"version": 2},
            {"cipher": "unknown"},
            {"kdf": {**encrypted.kdf, "salt": "bad!"}},
            {"data": "bad!"},
        ):
            with self.subTest(change=change):
                with mock.patch(
                    "secrets_kit.crypto.cli.export_json._derive_key",
                    side_effect=AssertionError("derivation must not run"),
                ):
                    with self.assertRaises(ValueError):
                        decrypt_payload(
                            payload={**encrypted.__dict__, **change}, password="test-pass"
                        )

    def test_encrypted_import_rejects_oversize_file_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "backup.json"
            backup.write_bytes(b"x" * 17)
            args = argparse.Namespace(file=str(backup), password="synthetic", password_stdin=False)
            with (
                mock.patch("secrets_kit.cli.commands.import_cmd.MAX_ENCRYPTED_BACKUP_BYTES", 16),
                mock.patch("secrets_kit.cli.commands.import_cmd.decrypt_payload") as decrypt,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(cmd_import_encrypted(args=args), 1)
            self.assertIn("exceeds maximum size", stderr.getvalue())
            decrypt.assert_not_called()

    def test_encrypted_import_preserves_exact_value_and_explicit_size_override(self) -> None:
        original = "  αβ\nline two\n"
        metadata = EntryMetadata(name="DEMO", service="svc", account="acct")
        encrypted = encrypt_payload(
            payload=build_plain_export(entries=[{"metadata": metadata.to_dict(), "value": original}]),
            password="synthetic",
        )
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "backup.json"
            backup.write_text(json.dumps(encrypted.__dict__), encoding="utf-8")
            captured = {}

            def inspect(*, args, load_candidates):
                captured["value"] = next(iter(load_candidates().values())).value
                return 0

            args = argparse.Namespace(
                file=str(backup), password="synthetic", password_stdin=False,
                max_backup_bytes=backup.stat().st_size,
            )
            with mock.patch("secrets_kit.cli.commands.import_cmd._run_import", side_effect=inspect):
                self.assertEqual(cmd_import_encrypted(args=args), 0)
            self.assertEqual(captured["value"], original)
            args.max_backup_bytes = backup.stat().st_size - 1
            with redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(cmd_import_encrypted(args=args), 1)
            self.assertIn("exceeds maximum size", stderr.getvalue())

    def test_encrypted_export_obeys_matching_size_limit(self) -> None:
        metadata = EntryMetadata(name="DEMO", service="svc", account="acct")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory).resolve() / "backup.json"
            args = argparse.Namespace(
                format="encrypted-json", out=str(destination), password="synthetic",
                password_stdin=False, backend="sqlite", keychain=None, max_backup_bytes=32,
            )
            with (
                mock.patch("secrets_kit.cli.commands.export._select_entries", return_value=[metadata]),
                mock.patch("secrets_kit.cli.commands.export.read_secret_value", return_value="synthetic"),
                redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(cmd_export(args=args), 1)
            self.assertIn("exceeds maximum size", stderr.getvalue())
            self.assertFalse(destination.exists())
            args.max_backup_bytes = 4096
            with (
                mock.patch("secrets_kit.cli.commands.export._select_entries", return_value=[metadata]),
                mock.patch("secrets_kit.cli.commands.export.read_secret_value", return_value="synthetic"),
            ):
                self.assertEqual(cmd_export(args=args), 0)
            self.assertLessEqual(destination.stat().st_size, args.max_backup_bytes)

    def test_encrypted_backup_restores_exact_and_preserves_existing_store(self) -> None:
        original = "  αβ\nline two\n"
        with tempfile.TemporaryDirectory(prefix="seckit-backup-") as raw:
            root = Path(raw).resolve()
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            backup = root / "backup.json"
            with mock.patch.dict(os.environ, {}, clear=False):
                for key in (
                    "SECKIT_SQLITE_PATH", "SECKIT_SQLITE_STORAGE_KEY",
                    "SECKIT_SQLITE_NODE_IDENTITY_KEY",
                ):
                    os.environ.pop(key, None)
                for home in (source, target):
                    with mock.patch("pathlib.Path.home", return_value=home), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(cmd_init_operator(args=argparse.Namespace(
                            yes=True, home=str(home), init_target=None, backend="sqlite"
                        )), 0)
                with mock.patch("pathlib.Path.home", return_value=source), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    for name, value in (("ALPHA", original), ("EMPTY", "")):
                        set_sqlite_secret(
                            service="svc", account="acct", name=name, value=value,
                            metadata=EntryMetadata(name=name, service="svc", account="acct"),
                        )
                    self.assertEqual(cmd_export(args=argparse.Namespace(
                        format="encrypted-json", out=str(backup), password="synthetic",
                        password_stdin=False, names="ALPHA,EMPTY", service="svc",
                        account="acct", backend="sqlite", keychain=None, max_backup_bytes=None,
                    )), 0)
                with mock.patch("pathlib.Path.home", return_value=target), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    set_sqlite_secret(
                        service="svc", account="acct", name="EXISTING", value="untouched",
                        metadata=EntryMetadata(name="EXISTING", service="svc", account="acct"),
                    )
                    self.assertEqual(cmd_import_encrypted(args=argparse.Namespace(
                        file=str(backup), password="synthetic", password_stdin=False,
                        backend="sqlite", keychain=None, max_backup_bytes=None,
                        dry_run=False, yes=True, allow_overwrite=False, allow_empty=False,
                    )), 0)
                    for name, expected in (("ALPHA", original), ("EMPTY", ""), ("EXISTING", "untouched")):
                        self.assertEqual(get_sqlite_secret(service="svc", account="acct", name=name), expected)

    def test_encrypted_import_rejects_malformed_decrypted_entries_without_writes(self) -> None:
        for malformed in (
            {"format": "seckit.export", "version": 1},
            {"format": "seckit.export", "version": 1, "entries": {}},
            {"format": "seckit.export", "version": 1, "entries": [42]},
            {"format": "seckit.export", "version": 1, "entries": [{"metadata": {}, "value": 42}]},
        ):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory:
                encrypted = encrypt_payload(payload=malformed, password="synthetic")
                backup = Path(directory) / "backup.json"
                backup.write_text(json.dumps(encrypted.__dict__), encoding="utf-8")
                args = argparse.Namespace(
                    file=str(backup), password="synthetic", password_stdin=False
                )
                with (
                    mock.patch("secrets_kit.cli.commands.import_cmd._apply_candidates") as write,
                    redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(cmd_import_encrypted(args=args), 1)
                write.assert_not_called()


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
